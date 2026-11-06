//! Message signing where every private-key operation happens in hardware.
//!
//! No session key exists in memory. A [`RootSigner`] is the identity key held
//! by a TPM (the machine's own, or a provider's reached over the network) or
//! a secure element; it signs one statement per batch, with both legs
//! (Ed25519 and ML-DSA-65). A [`Batcher`] collects messages and asks the
//! signer for one signature over the Merkle root of the batch. Each message
//! then travels with a [`BatchProof`] (32 bytes per tree level) and the one
//! [`RootSignature`] the batch shares.
//!
//! Batch size and flush interval are governed parameters ([`BatchParams`]).
//! The latency a message sees is at most the flush interval plus one hardware
//! signing time; a batch that fills flushes at once. Hardware signing time
//! is measured, not assumed: about 6 s on a hardware TPM, so the flush
//! interval is chosen above the signing time or batches queue behind it.

use ed25519_dalek::VerifyingKey;
use sha2::{Digest, Sha256};
use tenzro_crypto::pq::{ML_DSA_65_SIG_LEN, ML_DSA_65_VK_LEN, context};

use crate::compact::{BatchProof, batch_members};
use crate::delegation::{
    DelegationError, DelegationResult, IssuerResolver, Reader, VerifyParams, put_lp,
};

/// Domain of the statement the identity key signs over a batch root.
pub const HARDWARE_BATCH_DOMAIN: &[u8] = b"tenzro/hardware-batch/v1";
const FORMAT_VERSION: u8 = 1;
const MAX_IDENTITY_LEN: usize = 256;

/// The identity key, in hardware. Implemented over a TPM, a provider's TPM
/// or a secure element; never over a key held in this process.
pub trait RootSigner: Send + Sync {
    /// Signs the batch `root` of `count` messages with both legs and returns
    /// the whole [`RootSignature`]: the signer names the identity, the key
    /// version in force and (for a remote provider) its own time. `now_ms` is
    /// the caller's time, used by a signer that has no clock of its own.
    fn sign_root(
        &self,
        root: &[u8; 32],
        count: u32,
        now_ms: u64,
    ) -> DelegationResult<RootSignature>;
}

/// Governed, not constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BatchParams {
    /// A batch of this many messages is signed at once.
    pub max_batch: usize,
    /// A non-empty batch is signed when its oldest message is this old.
    pub flush_interval_ms: u64,
}

/// One hardware signature over a batch root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootSignature {
    pub identity: String,
    pub issuer_version: u64,
    pub issuer_ed25519: [u8; 32],
    pub issuer_ml_dsa: Vec<u8>,
    pub signed_at_ms: u64,
    pub count: u32,
    pub root: [u8; 32],
    pub ed_signature: [u8; 64],
    pub ml_dsa_signature: Vec<u8>,
}

impl RootSignature {
    fn body(&self) -> Vec<u8> {
        let mut out = vec![FORMAT_VERSION];
        put_lp(&mut out, self.identity.as_bytes());
        out.extend_from_slice(&self.issuer_version.to_be_bytes());
        out.extend_from_slice(&self.signed_at_ms.to_be_bytes());
        out.extend_from_slice(&self.count.to_be_bytes());
        out.extend_from_slice(&self.root);
        out
    }

    /// The signature's identifier: the hash of its statement. A chain that
    /// revokes it names this.
    pub fn id(&self) -> [u8; 32] {
        Sha256::digest(self.statement()).into()
    }

    /// The bytes both legs sign.
    pub fn statement(&self) -> Vec<u8> {
        let mut out = HARDWARE_BATCH_DOMAIN.to_vec();
        out.extend_from_slice(&self.body());
        out
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.body();
        out.extend_from_slice(&self.issuer_ed25519);
        put_lp(&mut out, &self.issuer_ml_dsa);
        out.extend_from_slice(&self.ed_signature);
        put_lp(&mut out, &self.ml_dsa_signature);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> DelegationResult<Self> {
        let mut r = Reader(bytes);
        if r.u8()? != FORMAT_VERSION {
            return Err(DelegationError::Malformed(
                "unknown batch signature version",
            ));
        }
        let identity = std::str::from_utf8(r.lp(MAX_IDENTITY_LEN)?)
            .map_err(|_| DelegationError::Malformed("identity is not UTF-8"))?
            .to_string();
        let issuer_version = r.u64()?;
        let signed_at_ms = r.u64()?;
        let count = u32::from_be_bytes(r.arr::<4>()?);
        let root = r.arr::<32>()?;
        let issuer_ed25519 = r.arr::<32>()?;
        let issuer_ml_dsa = r.lp(ML_DSA_65_VK_LEN)?.to_vec();
        let ed_signature = r.arr::<64>()?;
        let ml_dsa_signature = r.lp(ML_DSA_65_SIG_LEN)?.to_vec();
        r.done()?;
        Ok(Self {
            identity,
            issuer_version,
            issuer_ed25519,
            issuer_ml_dsa,
            signed_at_ms,
            count,
            root,
            ed_signature,
            ml_dsa_signature,
        })
    }

    /// Both legs verify under the keys the signature carries.
    pub fn verify_signatures(&self) -> DelegationResult<()> {
        let statement = self.statement();
        let vk = VerifyingKey::from_bytes(&self.issuer_ed25519)
            .map_err(|_| DelegationError::BadSignature("issuer Ed25519 key"))?;
        vk.verify_strict(
            &statement,
            &ed25519_dalek::Signature::from_bytes(&self.ed_signature),
        )
        .map_err(|_| DelegationError::BadSignature("Ed25519 leg"))?;
        tenzro_crypto::pq::ml_dsa_verify(
            &self.issuer_ml_dsa,
            context::BATCH_ROOT,
            &statement,
            &self.ml_dsa_signature,
        )
        .map_err(|_| DelegationError::BadSignature("ML-DSA-65 leg"))
    }

    /// The identity's chain-recorded key stood behind this signature when it
    /// was made and still does (rotation overlap, compromise as the resolver
    /// decides), and both legs verify.
    pub fn verify(
        &self,
        resolver: &dyn IssuerResolver,
        now_ms: u64,
        params: VerifyParams,
    ) -> DelegationResult<()> {
        if self.signed_at_ms > now_ms.saturating_add(params.skew_ms) {
            return Err(DelegationError::NotYetValid);
        }
        let rec = resolver.resolve_issuing(
            &self.identity,
            self.issuer_version,
            self.signed_at_ms,
            now_ms,
        )?;
        if rec.version != self.issuer_version
            || rec.ed25519 != self.issuer_ed25519
            || rec.ml_dsa != self.issuer_ml_dsa
        {
            return Err(DelegationError::WrongIssuer(
                "not the keys the chain records for that version".into(),
            ));
        }
        if resolver.is_revoked(&self.id()) {
            return Err(DelegationError::Revoked);
        }
        self.verify_signatures()
    }
}

/// A message's proof of membership in a signed batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub proof: BatchProof,
    pub signature: RootSignature,
}

impl Member {
    /// `message` is in the signed batch, and the signature stands.
    pub fn verify(
        &self,
        message: &[u8],
        resolver: &dyn IssuerResolver,
        now_ms: u64,
        params: VerifyParams,
    ) -> DelegationResult<()> {
        let root = self
            .proof
            .root_for(message)
            .ok_or(DelegationError::BadSignature("batch proof"))?;
        if root != self.signature.root || self.proof.count != self.signature.count {
            return Err(DelegationError::BadSignature("batch proof"));
        }
        self.signature.verify(resolver, now_ms, params)
    }
}

/// Signs through whichever provider's hardware answers: the providers are
/// tried starting from the last one that worked, and none is pinned. A
/// standby provider's key signs for the identity only once the chain records
/// that key (a rotation to the key the identity committed to in advance, see
/// `issuer_chain::commitment_of`); until then a verifier refuses its
/// signatures, so failing over early is safe but useless.
pub struct FailoverRootSigner {
    providers: Vec<Box<dyn RootSigner>>,
    last_good: std::sync::atomic::AtomicUsize,
}

impl FailoverRootSigner {
    pub fn new(providers: Vec<Box<dyn RootSigner>>) -> DelegationResult<Self> {
        if providers.is_empty() {
            return Err(DelegationError::Malformed("no providers"));
        }
        Ok(Self {
            providers,
            last_good: 0.into(),
        })
    }
}

impl RootSigner for FailoverRootSigner {
    fn sign_root(
        &self,
        root: &[u8; 32],
        count: u32,
        now_ms: u64,
    ) -> DelegationResult<RootSignature> {
        use std::sync::atomic::Ordering;
        let n = self.providers.len();
        let start = self.last_good.load(Ordering::Relaxed) % n;
        let mut why = Vec::new();
        for k in 0..n {
            let i = (start + k) % n;
            match self.providers[i].sign_root(root, count, now_ms) {
                Ok(sig) => {
                    self.last_good.store(i, Ordering::Relaxed);
                    return Ok(sig);
                }
                Err(e) => why.push(format!("provider {i}: {e}")),
            }
        }
        Err(DelegationError::Provider(format!(
            "no provider could sign: {}",
            why.join("; ")
        )))
    }
}

/// Collects messages and has the hardware sign them a batch at a time.
pub struct Batcher<S: RootSigner> {
    signer: S,
    params: BatchParams,
    pending: Vec<Vec<u8>>,
    oldest_ms: Option<u64>,
}

/// What a flush produced: a member for each message, in submission order.
pub struct Flushed {
    pub members: Vec<Member>,
}

impl<S: RootSigner> Batcher<S> {
    pub fn new(signer: S, params: BatchParams) -> DelegationResult<Self> {
        if params.max_batch == 0 || params.max_batch > u32::MAX as usize {
            return Err(DelegationError::Malformed("batch size out of range"));
        }
        Ok(Self {
            signer,
            params,
            pending: Vec::new(),
            oldest_ms: None,
        })
    }

    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Adds a message. Flushes (one hardware signature) when the batch is
    /// full. A failed hardware signature keeps the messages pending.
    pub fn submit(&mut self, message: Vec<u8>, now_ms: u64) -> DelegationResult<Option<Flushed>> {
        self.oldest_ms.get_or_insert(now_ms);
        self.pending.push(message);
        if self.pending.len() >= self.params.max_batch {
            return self.flush(now_ms).map(Some);
        }
        Ok(None)
    }

    /// Flushes when the oldest pending message has waited the interval.
    pub fn tick(&mut self, now_ms: u64) -> DelegationResult<Option<Flushed>> {
        match self.oldest_ms {
            Some(t) if now_ms.saturating_sub(t) >= self.params.flush_interval_ms => {
                self.flush(now_ms).map(Some)
            }
            _ => Ok(None),
        }
    }

    /// Signs everything pending now.
    pub fn flush(&mut self, now_ms: u64) -> DelegationResult<Flushed> {
        if self.pending.is_empty() {
            return Err(DelegationError::Malformed("nothing to sign"));
        }
        let refs: Vec<&[u8]> = self.pending.iter().map(|m| m.as_slice()).collect();
        let (root, proofs) = batch_members(&refs);
        let signature = self.signer.sign_root(&root, refs.len() as u32, now_ms)?;
        if signature.root != root || signature.count as usize != refs.len() {
            return Err(DelegationError::BadSignature("signer signed another batch"));
        }
        signature.verify_signatures()?;
        self.pending.clear();
        self.oldest_ms = None;
        Ok(Flushed {
            members: proofs
                .into_iter()
                .map(|proof| Member {
                    proof,
                    signature: signature.clone(),
                })
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::tests::{Chain, VERIFY};
    use crate::derive::RemoteDerive;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Stands in for the TPM: signs with the test chain's per-version keys.
    struct Hw {
        chain: Arc<Chain>,
        calls: AtomicU64,
        fail: std::sync::atomic::AtomicBool,
    }
    impl RootSigner for Hw {
        fn sign_root(
            &self,
            root: &[u8; 32],
            count: u32,
            now_ms: u64,
        ) -> DelegationResult<RootSignature> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if self.fail.load(Ordering::SeqCst) {
                return Err(DelegationError::Provider("hardware busy".into()));
            }
            let v = self.chain.version();
            let hw = crate::delegation::tests::ChainRoot(self.chain.clone());
            let label = format!("tenzro/test/identity/v{v}");
            let mut sig = RootSignature {
                identity: crate::delegation::tests::IDENTITY.to_string(),
                issuer_version: v,
                issuer_ed25519: hw.ed25519_public(&label).unwrap(),
                issuer_ml_dsa: hw.ml_dsa65_public(&label).unwrap(),
                signed_at_ms: now_ms,
                count,
                root: *root,
                ed_signature: [0; 64],
                ml_dsa_signature: Vec::new(),
            };
            let st = sig.statement();
            sig.ed_signature = hw.ed25519_sign(&label, &st).unwrap();
            sig.ml_dsa_signature = hw.ml_dsa65_sign(&label, context::BATCH_ROOT, &st).unwrap();
            Ok(sig)
        }
    }

    const P: BatchParams = BatchParams {
        max_batch: 4,
        flush_interval_ms: 1_000,
    };

    fn rig() -> (Arc<Chain>, Batcher<Hw>) {
        let chain = Chain::new();
        let hw = Hw {
            chain: chain.clone(),
            calls: AtomicU64::new(0),
            fail: Default::default(),
        };
        (chain, Batcher::new(hw, P).unwrap())
    }

    #[test]
    fn a_full_batch_costs_one_hardware_signature_and_every_member_verifies() {
        let (chain, mut b) = rig();
        for i in 0..3u8 {
            assert!(b.submit(vec![i], 100).unwrap().is_none());
        }
        let f = b.submit(vec![3], 100).unwrap().expect("full batch flushes");
        assert_eq!(b.signer.calls.load(Ordering::SeqCst), 1);
        for (i, m) in f.members.iter().enumerate() {
            let again = Member {
                proof: BatchProof::from_bytes(&m.proof.to_bytes()).unwrap(),
                signature: RootSignature::from_bytes(&m.signature.to_bytes()).unwrap(),
            };
            again
                .verify(&[i as u8], chain.as_ref(), 200, VERIFY)
                .unwrap();
            assert!(again.verify(b"x", chain.as_ref(), 200, VERIFY).is_err());
        }
    }

    #[test]
    fn a_partial_batch_flushes_at_the_interval_and_not_before() {
        let (chain, mut b) = rig();
        b.submit(b"a".to_vec(), 1_000).unwrap();
        assert!(b.tick(1_999).unwrap().is_none());
        let f = b.tick(2_000).unwrap().expect("interval elapsed");
        assert_eq!(f.members.len(), 1);
        f.members[0]
            .verify(b"a", chain.as_ref(), 2_000, VERIFY)
            .unwrap();
        assert!(b.tick(9_999).unwrap().is_none());
        assert_eq!(b.pending(), 0);
    }

    #[test]
    fn a_failed_hardware_signature_keeps_the_messages_pending() {
        let (_c, mut b) = rig();
        b.signer.fail.store(true, Ordering::SeqCst);
        b.submit(b"a".to_vec(), 0).unwrap();
        assert!(b.flush(5).is_err());
        assert_eq!(b.pending(), 1);
        b.signer.fail.store(false, Ordering::SeqCst);
        assert_eq!(b.flush(6).unwrap().members.len(), 1);
    }

    #[test]
    fn a_tampered_or_rotated_signature_is_refused() {
        let (chain, mut b) = rig();
        b.submit(b"a".to_vec(), 0).unwrap();
        let f = b.flush(10).unwrap();
        let mut m = f.members[0].clone();
        m.signature.count += 1;
        assert!(m.verify(b"a", chain.as_ref(), 20, VERIFY).is_err());
        let mut m = f.members[0].clone();
        m.signature.signed_at_ms += 1;
        assert!(m.verify(b"a", chain.as_ref(), 20, VERIFY).is_err());
        chain.rotate();
        assert!(
            f.members[0]
                .verify(b"a", chain.as_ref(), 20, VERIFY)
                .is_err()
        );
        assert!(
            Batcher::new(
                Hw {
                    chain: chain.clone(),
                    calls: 0.into(),
                    fail: Default::default()
                },
                BatchParams {
                    max_batch: 0,
                    flush_interval_ms: 1
                }
            )
            .is_err()
        );
    }

    #[test]
    fn failover_uses_the_next_provider_and_remembers_the_one_that_worked() {
        let chain = Chain::new();
        let mk = |fail: bool| {
            let hw = Hw {
                chain: chain.clone(),
                calls: AtomicU64::new(0),
                fail: Default::default(),
            };
            hw.fail.store(fail, Ordering::SeqCst);
            hw
        };
        let f = FailoverRootSigner::new(vec![Box::new(mk(true)), Box::new(mk(false))]).unwrap();
        let sig = f.sign_root(&[7; 32], 1, 5).unwrap();
        sig.verify_signatures().unwrap();
        assert_eq!(f.last_good.load(Ordering::SeqCst), 1);
        assert!(FailoverRootSigner::new(vec![]).is_err());
        let all_down =
            FailoverRootSigner::new(vec![Box::new(mk(true)), Box::new(mk(true))]).unwrap();
        let err = all_down.sign_root(&[7; 32], 1, 5).unwrap_err().to_string();
        assert!(
            err.contains("provider 0") && err.contains("provider 1"),
            "{err}"
        );
    }
}
