//! What a verifier needs to know about an identity key: the key the chain
//! currently names for an identity ([`IssuerResolver`]), the version a
//! provider signs under ([`IssuerVersions`]), the errors, the clock, and the
//! small length-prefixed encoding the batch signature formats use.
//!
//! The identity key signs in hardware, in batches (see
//! [`crate::batch_signer`]). Nothing here holds a private key.

use crate::derive::RemoteDerive;

/// Why a delegation or a session signature was refused or could not be made.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum DelegationError {
    /// The session has no live delegation. The caller does not sign.
    #[error("no live delegation: {0}")]
    NoSession(String),
    #[error("the delegation has expired")]
    Expired,
    #[error("the delegation is not valid yet")]
    NotYetValid,
    #[error("the delegation has been revoked")]
    Revoked,
    #[error(
        "the identity key has rotated: the delegation names version {delegation}, the identity is at version {current}"
    )]
    IssuerRotated { delegation: u64, current: u64 },
    #[error("the delegation was not issued by the identity's current key: {0}")]
    WrongIssuer(String),
    #[error("a signature does not verify: {0}")]
    BadSignature(&'static str),
    #[error("malformed: {0}")]
    Malformed(&'static str),
    /// The provider could not be reached or refused, and there is no earlier
    /// delegation to keep running on.
    #[error("the first delegation could not be obtained: {0}")]
    ColdStartRefused(String),
    #[error("the provider could not issue a delegation: {0}")]
    Provider(String),
    #[error("the identity is unknown to the resolver: {0}")]
    UnknownIdentity(String),
}

pub type DelegationResult<T> = std::result::Result<T, DelegationError>;

/// What a verifier tolerates. Governed, not constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifyParams {
    /// How far a delegation's start may be ahead of this verifier's clock.
    pub skew_ms: u64,
}

// ---------------------------------------------------------------------------
// The identity as the chain names it
// ---------------------------------------------------------------------------

/// The identity key as the chain currently records it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerRecord {
    /// The key version: the identity's rotation sequence. It rises with each
    /// on-chain identity key update.
    pub version: u64,
    pub ed25519: [u8; 32],
    pub ml_dsa: Vec<u8>,
}

/// Where a verifier learns which identity key is current, and which
/// delegations were revoked. The chain implements it.
pub trait IssuerResolver: Send + Sync {
    fn resolve(&self, identity: &str) -> DelegationResult<IssuerRecord>;
    fn is_revoked(&self, delegation_id: &[u8; 32]) -> bool;

    /// The identity key that may have issued a delegation made at
    /// `issued_at_ms` under key version `issuer_version`, as seen at
    /// `now_ms`. The default is the current key only; a resolver that keeps
    /// the identity's key history can accept the key a delegation was made
    /// under for a bounded time after a rotation.
    fn resolve_issuing(
        &self,
        identity: &str,
        _issuer_version: u64,
        _issued_at_ms: u64,
        _now_ms: u64,
    ) -> DelegationResult<IssuerRecord> {
        self.resolve(identity)
    }
}

/// Where a provider learns which TPM key label is the identity's current key
/// and at which version. The label is whatever the identity's key update
/// registered; nothing here names a handle or a key id.
pub trait IssuerVersions: Send + Sync {
    /// The current key version and the sub-label (under the client's grant
    /// label) its key is derived under.
    fn current(&self, identity: &str) -> DelegationResult<(u64, String)>;
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

pub(crate) fn put_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

pub(crate) struct Reader<'a>(pub(crate) &'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn take(&mut self, n: usize) -> DelegationResult<&'a [u8]> {
        if self.0.len() < n {
            return Err(DelegationError::Malformed("short"));
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    pub(crate) fn u8(&mut self) -> DelegationResult<u8> {
        Ok(self.take(1)?[0])
    }
    pub(crate) fn u64(&mut self) -> DelegationResult<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().expect("eight")))
    }
    pub(crate) fn arr<const N: usize>(&mut self) -> DelegationResult<[u8; N]> {
        Ok(self.take(N)?.try_into().expect("exact"))
    }
    pub(crate) fn lp(&mut self, max: usize) -> DelegationResult<&'a [u8]> {
        let n = u32::from_be_bytes(self.take(4)?.try_into().expect("four")) as usize;
        if n > max {
            return Err(DelegationError::Malformed("field too long"));
        }
        self.take(n)
    }
    /// A length-prefixed field of at most `max` bytes, the length a big-endian u32.
    pub(crate) fn lp_raw(&mut self, max: usize) -> DelegationResult<&'a [u8]> {
        self.lp(max)
    }
    pub(crate) fn done(&self) -> DelegationResult<()> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(DelegationError::Malformed("trailing bytes"))
        }
    }
}

/// The public keys of the identity key derived under `label`.
pub fn issuer_publics(root: &dyn RemoteDerive, label: &str) -> crate::Result<([u8; 32], Vec<u8>)> {
    Ok((root.ed25519_public(label)?, root.ml_dsa65_public(label)?))
}

/// Milliseconds since the Unix epoch.
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> u64;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};
    use tenzro_crypto::pq::{MlDsaSigningKey, context};

    pub(crate) struct ManualClock(pub AtomicU64);
    impl Clock for ManualClock {
        fn now_ms(&self) -> u64 {
            self.0.load(Ordering::SeqCst)
        }
    }

    /// An identity as a chain records it: one key per version.
    pub(crate) struct Chain {
        pub(crate) keys: Mutex<Vec<(MlDsaSigningKey, SigningKey)>>,
        pub(crate) revoked: Mutex<Vec<[u8; 32]>>,
    }

    impl Chain {
        pub(crate) fn new() -> Arc<Self> {
            let c = Arc::new(Self {
                keys: Mutex::new(Vec::new()),
                revoked: Mutex::new(Vec::new()),
            });
            c.rotate();
            c
        }
        /// The identity's key update: a new key at the next version.
        pub(crate) fn rotate(&self) {
            self.keys.lock().unwrap().push((
                MlDsaSigningKey::generate(),
                SigningKey::generate(&mut rand::rngs::OsRng),
            ));
        }
        pub(crate) fn version(&self) -> u64 {
            self.keys.lock().unwrap().len() as u64
        }
        fn sub_label(version: u64) -> String {
            format!("tenzro/test/identity/v{version}")
        }
    }

    impl IssuerResolver for Chain {
        fn resolve(&self, _identity: &str) -> DelegationResult<IssuerRecord> {
            let keys = self.keys.lock().unwrap();
            let (ml, ed) = keys.last().unwrap();
            Ok(IssuerRecord {
                version: keys.len() as u64,
                ed25519: ed.verifying_key().to_bytes(),
                ml_dsa: ml.verifying_key_bytes().to_vec(),
            })
        }
        fn is_revoked(&self, id: &[u8; 32]) -> bool {
            self.revoked.lock().unwrap().contains(id)
        }
    }

    impl IssuerVersions for Chain {
        fn current(&self, _identity: &str) -> DelegationResult<(u64, String)> {
            let v = self.version();
            Ok((v, Self::sub_label(v)))
        }
    }

    /// A derivation root whose per-label keys are the chain's, standing in
    /// for the TPM.
    pub(crate) struct ChainRoot(pub Arc<Chain>);
    impl ChainRoot {
        fn at(&self, label: &str) -> (usize,) {
            let v: usize = label.rsplit('v').next().unwrap().parse().unwrap();
            (v - 1,)
        }
    }
    impl RemoteDerive for ChainRoot {
        fn ed25519_public(&self, label: &str) -> crate::Result<[u8; 32]> {
            let (i,) = self.at(label);
            Ok(self.0.keys.lock().unwrap()[i].1.verifying_key().to_bytes())
        }
        fn ed25519_sign(&self, label: &str, m: &[u8]) -> crate::Result<[u8; 64]> {
            let (i,) = self.at(label);
            Ok(self.0.keys.lock().unwrap()[i].1.sign(m).to_bytes())
        }
        fn vrf_prove(&self, _: &str, _: &[u8]) -> crate::Result<tenzro_crypto::vrf::VrfProof> {
            unimplemented!()
        }
        fn x25519_public(&self, _: &str) -> crate::Result<[u8; 32]> {
            unimplemented!()
        }
        fn x25519_agree(
            &self,
            _: &str,
            _: &[u8; 32],
        ) -> crate::Result<zeroize::Zeroizing<[u8; 32]>> {
            unimplemented!()
        }
        fn ml_dsa65_public(&self, label: &str) -> crate::Result<Vec<u8>> {
            let (i,) = self.at(label);
            Ok(self.0.keys.lock().unwrap()[i]
                .0
                .verifying_key_bytes()
                .to_vec())
        }
        fn ml_dsa65_sign(&self, label: &str, ctx: &[u8], m: &[u8]) -> crate::Result<Vec<u8>> {
            assert!(ctx == context::SESSION_DELEGATION || ctx == context::BATCH_ROOT);
            let (i,) = self.at(label);
            Ok(self.0.keys.lock().unwrap()[i].0.sign(
                if ctx == context::BATCH_ROOT {
                    context::BATCH_ROOT
                } else {
                    context::SESSION_DELEGATION
                },
                m,
            ))
        }
        fn p256_public(&self, _: &str) -> crate::Result<[u8; 64]> {
            unimplemented!()
        }
        fn ml_kem768_public(&self, _: &str) -> crate::Result<Vec<u8>> {
            unimplemented!()
        }
        fn ml_kem768_decapsulate(
            &self,
            _: &str,
            _: &[u8],
        ) -> crate::Result<zeroize::Zeroizing<[u8; 32]>> {
            unimplemented!()
        }
        fn p256_sign_prehash(&self, _: &str, _: &[u8; 32]) -> crate::Result<[u8; 64]> {
            unimplemented!()
        }
    }

    pub(crate) const IDENTITY: &str = "did:tenzro:test:pi";

    pub(crate) const VERIFY: VerifyParams = VerifyParams { skew_ms: 5_000 };
}
