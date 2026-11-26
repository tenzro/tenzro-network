//! Session keys for provider heartbeats.
//!
//! A heartbeat is signed every few seconds, and a hardware signature costs
//! the chip about a second. A serving node therefore makes one Ed25519 key
//! from the OS random source at start, keeps it only in this process's memory
//! (wiped when dropped), and has its machine identity certify it once: the
//! certificate is a batch-signed record under [`CERTIFICATE_DOMAIN`] naming
//! the identity key, the session key, a boot nonce, the time it was issued
//! and the time it stops being valid, at most [`SessionLimits::max_lifetime_ms`] later. The
//! session key then signs heartbeats and nothing else, under
//! [`SIGNATURE_DOMAIN`]; the signer replaces it once half the lifetime has
//! passed. The identity key is captured when the signer is made: a machine
//! whose registered identity key is rotated restarts to certify under the new
//! one, and until then its session heartbeats fail verification.
//!
//! A session-signed heartbeat carries its certificate, so a receiver that
//! knows the machine's registered key checks the certificate once (it
//! remembers the certificates that verified) and the session signature on
//! each heartbeat, and never has to have seen the session key before. The
//! form travels inside the signature field of the heartbeat, led by a tag no
//! other signature begins with ([`SessionForm::to_record_signature`]), so the
//! heartbeat message itself is unchanged.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, RwLock};

use ed25519_dalek::{Signature as DalekSignature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::batch::{BatchProof, BatchedSignature, RecordSignature, RecordSigner, RootSignature};
use crate::composite::{ClassicalProof, CompositePublicKey, CompositeSignature};
use crate::error::{CryptoError, Result};
use crate::rng::fill_random_bytes;
use crate::session::now_ms;

/// Domain of the certificate a machine identity signs over a session key.
pub const CERTIFICATE_DOMAIN: &[u8] = b"tenzro/heartbeat-session/certificate/v1";

/// Domain of a session key's signature over a heartbeat.
pub const SIGNATURE_DOMAIN: &[u8] = b"tenzro/heartbeat-session/signature/v1";

/// The tag a session form leads with inside the signature field.
const FORM_TAG: &[u8] = b"tenzro/heartbeat-session/form/v1\0";

/// What a verifier holds a session certificate to. The node reads both
/// values from the governed parameters `heartbeat.session_max_lifetime_ms`
/// and `heartbeat.session_issue_skew_ms`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionLimits {
    /// The longest a certificate may be valid, from the moment it was issued.
    pub max_lifetime_ms: u64,
    /// How far past the verifier's clock a certificate's issue time may be.
    pub issue_skew_ms: u64,
}

/// Most certificates a verifier remembers; past it the memory starts empty.
const CACHE_CAPACITY: usize = 8192;

fn bad(why: impl Into<String>) -> CryptoError {
    CryptoError::InvalidSignature(why.into())
}

fn put(m: &mut Vec<u8>, bytes: &[u8]) {
    m.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    m.extend_from_slice(bytes);
}

/// What a machine identity signs to certify `session_key`.
fn certificate_message(
    identity: &CompositePublicKey,
    session_key: &[u8; 32],
    boot_nonce: &[u8; 16],
    issued_at_ms: u64,
    not_after_ms: u64,
) -> Vec<u8> {
    let mut m = CERTIFICATE_DOMAIN.to_vec();
    put(&mut m, &identity.p256);
    match &identity.pq {
        Some(pq) => {
            m.push(1);
            put(&mut m, pq);
        }
        None => m.push(0),
    }
    m.extend_from_slice(session_key);
    m.extend_from_slice(boot_nonce);
    m.extend_from_slice(&issued_at_ms.to_le_bytes());
    m.extend_from_slice(&not_after_ms.to_le_bytes());
    m
}

/// What a session key signs: the heartbeat's own signing preimage under
/// [`SIGNATURE_DOMAIN`].
fn signed_message(message: &[u8]) -> Vec<u8> {
    let mut m = SIGNATURE_DOMAIN.to_vec();
    m.extend_from_slice(message);
    m
}

/// A machine identity's statement that a session key may sign heartbeats for
/// it until `not_after_ms`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCertificate {
    pub session_key: [u8; 32],
    /// Random per boot, so two boots never share a certificate.
    pub boot_nonce: [u8; 16],
    pub issued_at_ms: u64,
    pub not_after_ms: u64,
    /// The identity's batch signature over the certificate message.
    pub signature: RecordSignature,
}

static VERIFIED: LazyLock<RwLock<HashSet<[u8; 32]>>> = LazyLock::new(RwLock::default);
static CACHE_HITS: AtomicU64 = AtomicU64::new(0);

/// How many certificate checks the memory has answered.
pub fn cache_hits() -> u64 {
    CACHE_HITS.load(Ordering::Relaxed)
}

impl SessionCertificate {
    fn message(&self, identity: &CompositePublicKey) -> Vec<u8> {
        certificate_message(
            identity,
            &self.session_key,
            &self.boot_nonce,
            self.issued_at_ms,
            self.not_after_ms,
        )
    }

    /// Checks that `identity` certified the session key and that the
    /// certificate is valid at `at_ms`. The identity's signature is checked
    /// once per certificate; the validity window on every call.
    pub fn verify(
        &self,
        identity: &CompositePublicKey,
        at_ms: u64,
        limits: &SessionLimits,
    ) -> Result<()> {
        if self.not_after_ms <= self.issued_at_ms
            || self.not_after_ms - self.issued_at_ms > limits.max_lifetime_ms
        {
            return Err(bad(format!(
                "a heartbeat session certificate is valid for at most {} ms",
                limits.max_lifetime_ms
            )));
        }
        if self.issued_at_ms > at_ms.saturating_add(limits.issue_skew_ms) {
            return Err(bad("the heartbeat session certificate is dated ahead"));
        }
        if at_ms > self.not_after_ms {
            return Err(bad(format!(
                "the heartbeat session certificate expired at {} ms, before {at_ms} ms",
                self.not_after_ms
            )));
        }
        let message = self.message(identity);
        let entry: [u8; 32] = Sha256::new()
            .chain_update((message.len() as u64).to_le_bytes())
            .chain_update(&message)
            .chain_update(encode_record_signature(&self.signature)?)
            .finalize()
            .into();
        if VERIFIED
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&entry)
        {
            CACHE_HITS.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        self.signature
            .verify(identity, &message, self.issued_at_ms)?;
        let mut verified = VERIFIED.write().unwrap_or_else(|e| e.into_inner());
        if verified.len() >= CACHE_CAPACITY {
            verified.clear();
        }
        verified.insert(entry);
        Ok(())
    }
}

/// A heartbeat signature by a session key, with the certificate that binds
/// the key to the machine identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionForm {
    pub certificate: SessionCertificate,
    pub signature: [u8; 64],
}

impl SessionForm {
    /// Checks that `identity` certified the session key, that the
    /// certificate was valid at `at_ms`, and that the key signed `message`.
    pub fn verify(
        &self,
        identity: &CompositePublicKey,
        message: &[u8],
        at_ms: u64,
        limits: &SessionLimits,
    ) -> Result<()> {
        self.certificate.verify(identity, at_ms, limits)?;
        let key = VerifyingKey::from_bytes(&self.certificate.session_key)
            .map_err(|e| bad(format!("session key: {e}")))?;
        key.verify_strict(
            &signed_message(message),
            &DalekSignature::from_bytes(&self.signature),
        )
        .map_err(|_| bad("the session key did not sign this heartbeat"))
    }

    /// The form as the signature field of a heartbeat. Its tag leads the
    /// ML-DSA bytes of the root signature, which a batch signature's never
    /// do (an ML-DSA-65 signature is 3309 bytes of no fixed lead), so the
    /// two forms cannot be taken for one another.
    pub fn to_record_signature(&self) -> Result<RecordSignature> {
        let mut body = FORM_TAG.to_vec();
        let c = &self.certificate;
        body.extend_from_slice(&c.session_key);
        body.extend_from_slice(&c.boot_nonce);
        body.extend_from_slice(&c.issued_at_ms.to_le_bytes());
        body.extend_from_slice(&c.not_after_ms.to_le_bytes());
        put(&mut body, &encode_record_signature(&c.signature)?);
        body.extend_from_slice(&self.signature);
        Ok(RecordSignature::batched(BatchedSignature {
            proof: BatchProof {
                index: 0,
                count: 0,
                path: Vec::new(),
            },
            root: RootSignature {
                signed_at_ms: c.issued_at_ms,
                count: 0,
                root: [0u8; 32],
                signature: CompositeSignature {
                    classical: ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                    pq: Some(body),
                },
            },
        }))
    }

    /// `None` when `signature` is not a session form (a batch signature);
    /// otherwise the form it carries, or why it does not parse.
    pub fn from_record_signature(signature: &RecordSignature) -> Option<Result<Self>> {
        let body = signature.batched.root.signature.pq.as_deref()?;
        let rest = body.strip_prefix(FORM_TAG)?;
        Some(parse_form(rest))
    }
}

fn parse_form(rest: &[u8]) -> Result<SessionForm> {
    struct Reader<'a>(&'a [u8]);
    impl<'a> Reader<'a> {
        fn take(&mut self, n: usize) -> Result<&'a [u8]> {
            if self.0.len() < n {
                return Err(bad("a heartbeat session form is cut short"));
            }
            let (head, tail) = self.0.split_at(n);
            self.0 = tail;
            Ok(head)
        }
        fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
            Ok(self.take(N)?.try_into().expect("length taken"))
        }
        fn u64(&mut self) -> Result<u64> {
            Ok(u64::from_le_bytes(self.array::<8>()?))
        }
    }
    let mut r = Reader(rest);
    let session_key = r.array::<32>()?;
    let boot_nonce = r.array::<16>()?;
    let issued_at_ms = r.u64()?;
    let not_after_ms = r.u64()?;
    let len = u32::from_le_bytes(r.array::<4>()?) as usize;
    let signature = decode_record_signature(r.take(len)?)?;
    let session_signature = r.array::<64>()?;
    if !r.0.is_empty() {
        return Err(bad("a heartbeat session form has trailing bytes"));
    }
    Ok(SessionForm {
        certificate: SessionCertificate {
            session_key,
            boot_nonce,
            issued_at_ms,
            not_after_ms,
            signature,
        },
        signature: session_signature,
    })
}

/// A batch signature as bytes: the proof, the root signature's fields and
/// both legs, each variable part length-prefixed. A machine identity's
/// signature has a raw P-256 leg; any other form is refused.
fn encode_record_signature(s: &RecordSignature) -> Result<Vec<u8>> {
    let b = &s.batched;
    let ClassicalProof::Raw { signature } = &b.root.signature.classical else {
        return Err(bad(
            "a machine identity signs with a raw P-256 signature, not a passkey assertion",
        ));
    };
    let mut m = Vec::new();
    m.extend_from_slice(&b.proof.index.to_le_bytes());
    m.extend_from_slice(&b.proof.count.to_le_bytes());
    m.extend_from_slice(&(b.proof.path.len() as u32).to_le_bytes());
    for node in &b.proof.path {
        m.extend_from_slice(node);
    }
    m.extend_from_slice(&b.root.signed_at_ms.to_le_bytes());
    m.extend_from_slice(&b.root.count.to_le_bytes());
    m.extend_from_slice(&b.root.root);
    put(&mut m, signature);
    match &b.root.signature.pq {
        Some(pq) => {
            m.push(1);
            put(&mut m, pq);
        }
        None => m.push(0),
    }
    Ok(m)
}

fn decode_record_signature(bytes: &[u8]) -> Result<RecordSignature> {
    struct Reader<'a>(&'a [u8]);
    impl<'a> Reader<'a> {
        fn take(&mut self, n: usize) -> Result<&'a [u8]> {
            if self.0.len() < n {
                return Err(bad("a certificate signature is cut short"));
            }
            let (head, tail) = self.0.split_at(n);
            self.0 = tail;
            Ok(head)
        }
        fn u32(&mut self) -> Result<u32> {
            Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("4")))
        }
        fn u64(&mut self) -> Result<u64> {
            Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("8")))
        }
        fn bytes(&mut self) -> Result<Vec<u8>> {
            let n = self.u32()? as usize;
            Ok(self.take(n)?.to_vec())
        }
    }
    let mut r = Reader(bytes);
    let index = r.u32()?;
    let count = r.u32()?;
    let nodes = r.u32()? as usize;
    // A batch holds at most 2^32 records, so a path is at most 32 nodes.
    if nodes > 32 {
        return Err(bad("a certificate signature's proof path is too long"));
    }
    let mut path = Vec::with_capacity(nodes);
    for _ in 0..nodes {
        path.push(r.take(32)?.try_into().expect("32"));
    }
    let signed_at_ms = r.u64()?;
    let root_count = r.u32()?;
    let root: [u8; 32] = r.take(32)?.try_into().expect("32");
    let classical = r.bytes()?;
    let pq = match r.take(1)?[0] {
        0 => None,
        1 => Some(r.bytes()?),
        _ => return Err(bad("a certificate signature's ML-DSA flag is not 0 or 1")),
    };
    if !r.0.is_empty() {
        return Err(bad("a certificate signature has trailing bytes"));
    }
    Ok(RecordSignature::batched(BatchedSignature {
        proof: BatchProof { index, count, path },
        root: RootSignature {
            signed_at_ms,
            count: root_count,
            root,
            signature: CompositeSignature {
                classical: ClassicalProof::Raw {
                    signature: classical,
                },
                pq,
            },
        },
    }))
}

/// One certified session key. The key is wiped when the value is dropped.
struct Live {
    key: SigningKey,
    certificate: SessionCertificate,
    renew_at_ms: u64,
}

/// Signs heartbeats with a session key certified by the machine identity,
/// replacing the key once half its lifetime has passed. The key is made at
/// random for this process, held only in memory, and never stored.
pub struct HeartbeatSessionSigner {
    identity: Arc<dyn RecordSigner>,
    lifetime_ms: u64,
    current: RwLock<Arc<Live>>,
}

impl HeartbeatSessionSigner {
    /// Makes the first session key and has the identity certify it: one
    /// hardware signature. `lifetime_ms` is how long each certificate is valid:
    /// the caller passes at most the governed maximum.
    pub fn new(identity: Arc<dyn RecordSigner>, lifetime_ms: u64) -> Result<Self> {
        let lifetime_ms = lifetime_ms.max(2);
        let first = Self::certify(identity.as_ref(), lifetime_ms)?;
        Ok(Self {
            identity,
            lifetime_ms,
            current: RwLock::new(Arc::new(first)),
        })
    }

    /// The machine identity the session keys sign for.
    pub fn identity(&self) -> &CompositePublicKey {
        self.identity.identity()
    }

    fn certify(identity: &dyn RecordSigner, lifetime_ms: u64) -> Result<Live> {
        let mut seed = Zeroizing::new([0u8; 32]);
        fill_random_bytes(seed.as_mut());
        let key = SigningKey::from_bytes(&seed);
        let mut boot_nonce = [0u8; 16];
        fill_random_bytes(&mut boot_nonce);
        let issued_at_ms = now_ms();
        let not_after_ms = issued_at_ms.saturating_add(lifetime_ms);
        let session_key = key.verifying_key().to_bytes();
        let message = certificate_message(
            identity.identity(),
            &session_key,
            &boot_nonce,
            issued_at_ms,
            not_after_ms,
        );
        let signature = identity.sign_record(&message)?;
        Ok(Live {
            key,
            certificate: SessionCertificate {
                session_key,
                boot_nonce,
                issued_at_ms,
                not_after_ms,
                signature,
            },
            renew_at_ms: issued_at_ms.saturating_add(lifetime_ms / 2),
        })
    }

    /// The session key to sign with at `now`, replaced first when it is due.
    /// A failed replacement keeps the current key while it is still valid,
    /// and the next signature tries again.
    fn live(&self, now: u64) -> Result<Arc<Live>> {
        let current = self
            .current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if now < current.renew_at_ms {
            return Ok(current);
        }
        let mut slot = self.current.write().unwrap_or_else(|e| e.into_inner());
        if now >= slot.renew_at_ms {
            match Self::certify(self.identity.as_ref(), self.lifetime_ms) {
                Ok(next) => *slot = Arc::new(next),
                Err(e) if now > slot.certificate.not_after_ms => return Err(e),
                Err(_) => {}
            }
        }
        Ok(slot.clone())
    }

    /// Signs `message`, a heartbeat's signing preimage, as a session form.
    /// The signature is under [`SIGNATURE_DOMAIN`], which nothing but a
    /// heartbeat verifier accepts, so this is no signing oracle for any
    /// other statement.
    pub fn sign_heartbeat(&self, message: &[u8]) -> Result<RecordSignature> {
        let now = now_ms();
        let live = self.live(now)?;
        if now > live.certificate.not_after_ms {
            return Err(bad(
                "the heartbeat session key has expired and could not be replaced",
            ));
        }
        let signature = live.key.sign(&signed_message(message)).to_bytes();
        SessionForm {
            certificate: live.certificate.clone(),
            signature,
        }
        .to_record_signature()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: SessionLimits = SessionLimits {
        max_lifetime_ms: 60 * 60 * 1000,
        issue_skew_ms: 60_000,
    };
    use crate::batch::ImmediateRecordSigner;
    use crate::composite::testing::TestHybridSigner;

    fn identity() -> Arc<ImmediateRecordSigner> {
        Arc::new(ImmediateRecordSigner::new(Arc::new(
            TestHybridSigner::random(),
        )))
    }

    #[test]
    fn a_session_signed_heartbeat_verifies_under_the_identity_that_certified_it() {
        let id = identity();
        let signer = HeartbeatSessionSigner::new(id.clone(), LIMITS.max_lifetime_ms).unwrap();
        let sig = signer.sign_heartbeat(b"beat").unwrap();
        let form = SessionForm::from_record_signature(&sig)
            .expect("a session form")
            .unwrap();
        form.verify(id.identity(), b"beat", now_ms(), &LIMITS)
            .unwrap();
        assert!(
            form.verify(id.identity(), b"other", now_ms(), &LIMITS)
                .is_err()
        );
        let other = identity();
        assert!(
            form.verify(other.identity(), b"beat", now_ms(), &LIMITS)
                .is_err()
        );
    }

    #[test]
    fn a_batch_signature_is_not_a_session_form() {
        let id = identity();
        let batch = id.sign_record(b"beat").unwrap();
        assert!(SessionForm::from_record_signature(&batch).is_none());
    }

    #[test]
    fn a_certificate_lives_at_most_an_hour_and_expires() {
        let id = identity();
        let signer = HeartbeatSessionSigner::new(id.clone(), 10 * 60 * 1000).unwrap();
        let sig = signer.sign_heartbeat(b"beat").unwrap();
        let form = SessionForm::from_record_signature(&sig).unwrap().unwrap();
        let after = form.certificate.not_after_ms;
        form.verify(id.identity(), b"beat", after, &LIMITS).unwrap();
        assert!(
            form.verify(id.identity(), b"beat", after + 1, &LIMITS)
                .is_err()
        );

        // A certificate valid for longer than an hour is refused whoever
        // signed it.
        let mut long = form.certificate.clone();
        long.not_after_ms = long.issued_at_ms + LIMITS.max_lifetime_ms + 1;
        assert!(
            long.verify(id.identity(), long.issued_at_ms, &LIMITS)
                .is_err()
        );
    }

    #[test]
    fn a_certificate_dated_ahead_of_the_verifier_is_refused() {
        let id = identity();
        let signer = HeartbeatSessionSigner::new(id.clone(), LIMITS.max_lifetime_ms).unwrap();
        let sig = signer.sign_heartbeat(b"beat").unwrap();
        let form = SessionForm::from_record_signature(&sig).unwrap().unwrap();
        let issued = form.certificate.issued_at_ms;
        assert!(
            form.verify(
                id.identity(),
                b"beat",
                issued - LIMITS.issue_skew_ms - 1,
                &LIMITS
            )
            .is_err()
        );
    }

    #[test]
    fn a_session_signer_renews_its_key_at_half_the_lifetime() {
        let id = identity();
        let signer = HeartbeatSessionSigner::new(id.clone(), 40).unwrap();
        let first = SessionForm::from_record_signature(&signer.sign_heartbeat(b"a").unwrap())
            .unwrap()
            .unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        let second = SessionForm::from_record_signature(&signer.sign_heartbeat(b"b").unwrap())
            .unwrap()
            .unwrap();
        assert_ne!(
            first.certificate.session_key, second.certificate.session_key,
            "a new key after half the lifetime"
        );
        second
            .verify(id.identity(), b"b", now_ms(), &LIMITS)
            .unwrap();
    }

    #[test]
    fn a_form_that_is_cut_short_or_padded_is_refused() {
        let id = identity();
        let signer = HeartbeatSessionSigner::new(id, LIMITS.max_lifetime_ms).unwrap();
        let mut sig = signer.sign_heartbeat(b"beat").unwrap();
        sig.batched.root.signature.pq.as_mut().unwrap().pop();
        assert!(SessionForm::from_record_signature(&sig).unwrap().is_err());
        let mut sig = signer.sign_heartbeat(b"beat").unwrap();
        sig.batched.root.signature.pq.as_mut().unwrap().push(0);
        assert!(SessionForm::from_record_signature(&sig).unwrap().is_err());
    }

    #[test]
    fn a_certificate_is_checked_once_and_remembered() {
        let id = identity();
        let signer = HeartbeatSessionSigner::new(id.clone(), LIMITS.max_lifetime_ms).unwrap();
        let form = SessionForm::from_record_signature(&signer.sign_heartbeat(b"beat").unwrap())
            .unwrap()
            .unwrap();
        form.verify(id.identity(), b"beat", now_ms(), &LIMITS)
            .unwrap();
        let before = cache_hits();
        form.verify(id.identity(), b"beat", now_ms(), &LIMITS)
            .unwrap();
        assert!(cache_hits() > before);
    }
}
