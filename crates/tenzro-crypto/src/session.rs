//! Session keys for signatures made on a hot path.
//!
//! The node's long-lived identity is a hardware key (P-256, plus ML-DSA-65
//! where the hardware holds one), and every hardware signature costs a round
//! trip. A process that signs per request instead makes an
//! Ed25519 session key from the OS random source, keeps it only in memory
//! (it is wiped on drop), and has the long-lived key sign one
//! [`SessionCertificate`] naming the session key and when it stops being
//! valid, signed under [`SignatureContext::SessionCertificate`]. Every
//! signature carries that certificate ([`SessionSignature`]), so
//! a verifier that knows the long-lived key checks the certificate first and
//! the signature second, and never needs to have seen the session key before.
//!
//! [`SessionSigner`] replaces its session key once half the lifetime has
//! passed, so a process that runs for weeks costs one long-lived signature
//! per half lifetime.
//!
//! A signer made with [`SessionSigner::new_hybrid`] holds an ML-DSA-65
//! session key beside the Ed25519 one ([`KeyType::Ed25519MlDsa65`]): every
//! signature carries both legs and verifies only if both do, so it holds
//! when Ed25519 is broken. Each signature then costs an ML-DSA-65 signature
//! and 3309 more bytes; a node that receives one must know the key type.
//!
//! Records that are stored and checked again later (receipts, billing, SLA
//! answers, availability attestations) are signed by a signer made with
//! [`SessionSigner::for_records`]. It signs with an Ed25519 session key until
//! hybrid records are in force ([`set_hybrid_records_from_ms`], set by the
//! node from chain state), and with a hybrid key from then on. A verifier of
//! such a record calls [`SessionSignature::verify_record`], which refuses a
//! record dated at or after that moment unless its session key is hybrid, so
//! a session key recovered later cannot mint records dated after it.
//!
//! A certificate is checked once: [`CertificateCache`] remembers the
//! certificates whose identity signature verified, so a verifier that sees
//! the same session key again pays only for the session signature and the
//! certificate's validity window.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(any(test, feature = "test-keys"))]
use crate::composite::HybridSigner;
use crate::composite::{
    CompositePublicKey, CompositeSignature, PqPolicy, SignatureContext, verify_composite,
};
use crate::error::{CryptoError, Result};
use crate::keys::{KeyType, PublicKey};
#[cfg(any(test, feature = "test-keys"))]
use crate::pq::MlDsaSigningKey;
use crate::pq::{ML_DSA_65_VK_LEN, ml_dsa_verify};
#[cfg(any(test, feature = "test-keys"))]
use crate::signatures::{Ed25519SignerImpl, Signer};
use crate::signatures::{Signature, verify};

/// FIPS 204 context of the ML-DSA-65 leg of a hybrid session signature.
pub const HYBRID_SESSION_CONTEXT: &[u8] = b"tenzro/session/ml-dsa-65";

const ED25519_KEY_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;

/// Verifies a [`KeyType::Ed25519MlDsa65`] signature: both legs, each over
/// the whole message.
pub fn verify_hybrid(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<()> {
    if public_key.len() != ED25519_KEY_LEN + ML_DSA_65_VK_LEN || signature.len() <= ED25519_SIG_LEN
    {
        return Err(CryptoError::InvalidSignature(
            "a hybrid session signature needs both legs".to_string(),
        ));
    }
    let (ed_key, pq_key) = public_key.split_at(ED25519_KEY_LEN);
    let (ed_sig, pq_sig) = signature.split_at(ED25519_SIG_LEN);
    verify(
        &PublicKey::new(KeyType::Ed25519, ed_key.to_vec()),
        message,
        &Signature::new(KeyType::Ed25519, ed_sig.to_vec()),
    )?;
    ml_dsa_verify(pq_key, HYBRID_SESSION_CONTEXT, message, pq_sig)
}

/// A session key: Ed25519 alone, or Ed25519 with ML-DSA-65.
#[cfg(any(test, feature = "test-keys"))]
enum SessionKey {
    Ed25519(Ed25519SignerImpl),
    Hybrid(Ed25519SignerImpl, MlDsaSigningKey),
}

#[cfg(any(test, feature = "test-keys"))]
impl SessionKey {
    fn generate(hybrid: bool) -> Result<Self> {
        let ed = Ed25519SignerImpl::generate()?;
        Ok(if hybrid {
            Self::Hybrid(ed, MlDsaSigningKey::generate())
        } else {
            Self::Ed25519(ed)
        })
    }

    fn public_key(&self) -> PublicKey {
        match self {
            Self::Ed25519(ed) => ed.public_key().clone(),
            Self::Hybrid(ed, pq) => {
                let mut bytes = ed.public_key().as_bytes().to_vec();
                bytes.extend_from_slice(pq.verifying_key_bytes());
                PublicKey::new(KeyType::Ed25519MlDsa65, bytes)
            }
        }
    }

    fn sign(&self, message: &[u8]) -> Result<Signature> {
        match self {
            Self::Ed25519(ed) => ed.sign(message),
            Self::Hybrid(ed, pq) => {
                let mut bytes = ed.sign(message)?.as_bytes().to_vec();
                bytes.extend_from_slice(&pq.sign(HYBRID_SESSION_CONTEXT, message));
                Ok(Signature::new(KeyType::Ed25519MlDsa65, bytes))
            }
        }
    }
}

/// How long a session key is valid after it is certified.
pub const SESSION_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// A long-lived key's statement that `session_key` may sign for it until
/// `not_after_ms`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionCertificate {
    /// The session key: Ed25519, or Ed25519 with ML-DSA-65.
    pub session_key: PublicKey,
    /// The last millisecond since the Unix epoch at which the session key's
    /// signatures are valid.
    pub not_after_ms: u64,
    /// The hardware identity's signature over [`SessionCertificate::message`]
    /// under [`SignatureContext::SessionCertificate`].
    pub signature: CompositeSignature,
}

impl SessionCertificate {
    /// The bytes the long-lived key `identity` signs.
    pub fn message(
        identity: &CompositePublicKey,
        session_key: &PublicKey,
        not_after_ms: u64,
    ) -> Vec<u8> {
        fn put(m: &mut Vec<u8>, bytes: &[u8]) {
            m.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            m.extend_from_slice(bytes);
        }
        let mut m = Vec::new();
        put(&mut m, &identity.p256);
        match &identity.pq {
            Some(pq) => {
                m.push(1);
                put(&mut m, pq);
            }
            None => m.push(0),
        }
        m.push(session_key.key_type() as u8);
        put(&mut m, session_key.as_bytes());
        m.extend_from_slice(&not_after_ms.to_le_bytes());
        m
    }

    /// Check that `identity` certified this session key and that the
    /// certificate was valid at `at_ms`.
    pub fn verify(&self, identity: &CompositePublicKey, at_ms: u64) -> Result<()> {
        if !matches!(
            self.session_key.key_type(),
            KeyType::Ed25519 | KeyType::Ed25519MlDsa65
        ) {
            return Err(CryptoError::InvalidSignature(
                "a session key must be an Ed25519 or hybrid Ed25519 / ML-DSA-65 key".to_string(),
            ));
        }
        if at_ms > self.not_after_ms {
            return Err(CryptoError::InvalidSignature(format!(
                "the session certificate expired at {} ms, before {at_ms} ms",
                self.not_after_ms
            )));
        }
        let message = Self::message(identity, &self.session_key, self.not_after_ms);
        CERTIFICATES.check(&message, &self.signature, || {
            verify_composite(
                identity,
                SignatureContext::SessionCertificate,
                &message,
                &self.signature,
                PqPolicy::WhenPresent,
            )
            .map(|_| ())
        })
    }
}

/// Most certificates a [`CertificateCache`] remembers. Past it the cache
/// starts again empty, so a flood of distinct certificates costs only the
/// checks it would have cost without a cache.
pub const CERTIFICATE_CACHE_CAPACITY: usize = 8192;

/// The certificates whose identity signature verified, by the hash of what
/// was signed and the signature itself. Only that check is remembered: the
/// validity window is checked on every use, so a remembered certificate
/// still expires.
#[derive(Debug, Default)]
pub struct CertificateCache {
    verified: RwLock<HashSet<[u8; 32]>>,
    hits: AtomicU64,
}

static CERTIFICATES: LazyLock<CertificateCache> = LazyLock::new(CertificateCache::default);

impl CertificateCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// The process-wide cache that [`SessionCertificate::verify`] uses.
    pub fn global() -> &'static CertificateCache {
        &CERTIFICATES
    }

    fn entry(message: &[u8], signature: &CompositeSignature) -> [u8; 32] {
        let encoded = serde_json::to_vec(signature).unwrap_or_default();
        Sha256::new()
            .chain_update((message.len() as u64).to_le_bytes())
            .chain_update(message)
            .chain_update(&encoded)
            .finalize()
            .into()
    }

    /// Runs `check` for the identity signature `signature` over `message`
    /// unless the same pair verified before, and remembers it when it does.
    pub fn check(
        &self,
        message: &[u8],
        signature: &CompositeSignature,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let entry = Self::entry(message, signature);
        if self
            .verified
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&entry)
        {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return Ok(());
        }
        check()?;
        let mut verified = self.verified.write().unwrap_or_else(|e| e.into_inner());
        if verified.len() >= CERTIFICATE_CACHE_CAPACITY {
            verified.clear();
        }
        verified.insert(entry);
        Ok(())
    }

    /// How many checks the cache answered.
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// How many certificates it holds.
    pub fn len(&self) -> usize {
        self.verified
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Whether it holds none.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// The moment from which stored records must carry hybrid session
/// signatures, ms since the Unix epoch; `u64::MAX` while they need not.
static HYBRID_RECORDS_FROM_MS: LazyLock<Arc<AtomicU64>> =
    LazyLock::new(|| Arc::new(AtomicU64::new(u64::MAX)));

/// Puts hybrid records in force from `from_ms` (`u64::MAX`: not in force).
/// The node sets it from chain state.
pub fn set_hybrid_records_from_ms(from_ms: u64) {
    HYBRID_RECORDS_FROM_MS.store(from_ms, Ordering::Relaxed);
}

/// The moment hybrid records are in force from, `u64::MAX` while they are
/// not.
pub fn hybrid_records_from_ms() -> u64 {
    HYBRID_RECORDS_FROM_MS.load(Ordering::Relaxed)
}

/// A signature by a session key, with the certificate that binds the session
/// key to a long-lived key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSignature {
    pub certificate: SessionCertificate,
    /// The session key's signature over the message: Ed25519, or both legs
    /// of a hybrid key.
    pub signature: Signature,
}

impl SessionSignature {
    /// Check that `identity` certified the session key, that the certificate
    /// was valid at `at_ms`, and that the session key signed `message`.
    ///
    /// A verifier that checks the signature as it arrives passes the current
    /// time ([`SessionSignature::verify_now`]); one that re-checks a stored
    /// record passes the time the record says it was made.
    pub fn verify(&self, identity: &CompositePublicKey, message: &[u8], at_ms: u64) -> Result<()> {
        self.certificate.verify(identity, at_ms)?;
        verify(&self.certificate.session_key, message, &self.signature)
    }

    /// [`SessionSignature::verify`] at the current time.
    pub fn verify_now(&self, identity: &CompositePublicKey, message: &[u8]) -> Result<()> {
        self.verify(identity, message, now_ms())
    }

    /// Whether the session key carries an ML-DSA-65 leg, for a verifier
    /// that accepts only hybrid session signatures for a statement.
    pub fn is_hybrid(&self) -> bool {
        self.certificate.session_key.key_type() == KeyType::Ed25519MlDsa65
    }

    /// [`SessionSignature::verify`] for a stored record made at `at_ms`: a
    /// record dated at or after the moment hybrid records are in force
    /// ([`hybrid_records_from_ms`]) must carry a hybrid session signature.
    pub fn verify_record(
        &self,
        identity: &CompositePublicKey,
        message: &[u8],
        at_ms: u64,
    ) -> Result<()> {
        self.verify_record_under(identity, message, at_ms, hybrid_records_from_ms())
    }

    /// [`SessionSignature::verify_record`] at the current time.
    pub fn verify_record_now(&self, identity: &CompositePublicKey, message: &[u8]) -> Result<()> {
        self.verify_record(identity, message, now_ms())
    }

    /// Refuses an Ed25519 session signature on a record made at `made_at_ms`
    /// once hybrid records are in force by then, for a verifier that checks
    /// the signature itself some other way.
    pub fn require_hybrid_record(&self, made_at_ms: u64) -> Result<()> {
        let from = hybrid_records_from_ms();
        if made_at_ms >= from && !self.is_hybrid() {
            return Err(CryptoError::InvalidSignature(format!(
                "a record made at {made_at_ms} ms needs a hybrid session signature (in force \
                 from {from} ms)"
            )));
        }
        Ok(())
    }

    /// [`SessionSignature::verify_record`] with hybrid records in force from
    /// `hybrid_from_ms`.
    pub fn verify_record_under(
        &self,
        identity: &CompositePublicKey,
        message: &[u8],
        at_ms: u64,
        hybrid_from_ms: u64,
    ) -> Result<()> {
        if at_ms >= hybrid_from_ms && !self.is_hybrid() {
            return Err(CryptoError::InvalidSignature(format!(
                "a record made at {at_ms} ms needs a hybrid session signature (in force from \
                 {hybrid_from_ms} ms)"
            )));
        }
        self.verify(identity, message, at_ms)
    }
}

/// Which session keys a [`SessionSigner`] makes.
#[derive(Debug, Clone)]
#[cfg(any(test, feature = "test-keys"))]
enum Kind {
    /// Ed25519 alone.
    Ed25519,
    /// Ed25519 with ML-DSA-65.
    Hybrid,
    /// Ed25519 until the moment the cell holds, hybrid from then on.
    Records(Arc<AtomicU64>),
}

#[cfg(any(test, feature = "test-keys"))]
impl Kind {
    fn hybrid_at(&self, now: u64) -> bool {
        match self {
            Self::Ed25519 => false,
            Self::Hybrid => true,
            Self::Records(from) => now >= from.load(Ordering::Relaxed),
        }
    }
}

/// One certified session key. The key is wiped when the value is dropped.
#[cfg(any(test, feature = "test-keys"))]
struct Session {
    key: SessionKey,
    certificate: SessionCertificate,
    renew_at_ms: u64,
}

#[cfg(any(test, feature = "test-keys"))]
impl Session {
    fn is_hybrid(&self) -> bool {
        matches!(self.key, SessionKey::Hybrid(..))
    }
}

/// Signs with a session key certified by the hardware identity, replacing the
/// session key once half its lifetime has passed.
#[cfg(any(test, feature = "test-keys"))]
pub struct SessionSigner {
    identity: Arc<dyn HybridSigner>,
    lifetime_ms: u64,
    kind: Kind,
    current: RwLock<Arc<Session>>,
}

#[cfg(any(test, feature = "test-keys"))]
impl SessionSigner {
    /// Make the first session key and have `identity` certify it: one
    /// hardware signature.
    pub fn new(identity: Arc<dyn HybridSigner>, lifetime: Duration) -> Result<Self> {
        Self::with_kind(identity, lifetime, Kind::Ed25519)
    }

    /// [`SessionSigner::new`] with hybrid Ed25519 / ML-DSA-65 session keys.
    pub fn new_hybrid(identity: Arc<dyn HybridSigner>, lifetime: Duration) -> Result<Self> {
        Self::with_kind(identity, lifetime, Kind::Hybrid)
    }

    /// The signer of stored records: Ed25519 session keys until hybrid
    /// records are in force ([`set_hybrid_records_from_ms`]), hybrid ones
    /// from then on. The first signature after that moment certifies a
    /// hybrid key.
    pub fn for_records(identity: Arc<dyn HybridSigner>, lifetime: Duration) -> Result<Self> {
        Self::for_records_from(identity, lifetime, HYBRID_RECORDS_FROM_MS.clone())
    }

    /// [`SessionSigner::for_records`] with hybrid records in force from the
    /// moment `from_ms` holds.
    pub fn for_records_from(
        identity: Arc<dyn HybridSigner>,
        lifetime: Duration,
        from_ms: Arc<AtomicU64>,
    ) -> Result<Self> {
        Self::with_kind(identity, lifetime, Kind::Records(from_ms))
    }

    fn with_kind(identity: Arc<dyn HybridSigner>, lifetime: Duration, kind: Kind) -> Result<Self> {
        let lifetime_ms = lifetime.as_millis() as u64;
        let first = Self::certify(identity.as_ref(), lifetime_ms, kind.hybrid_at(now_ms()))?;
        Ok(Self {
            identity,
            lifetime_ms,
            kind,
            current: RwLock::new(Arc::new(first)),
        })
    }

    /// The long-lived key the session keys sign for.
    pub fn identity(&self) -> &CompositePublicKey {
        self.identity.public_key()
    }

    fn certify(identity: &dyn HybridSigner, lifetime_ms: u64, hybrid: bool) -> Result<Session> {
        let key = SessionKey::generate(hybrid)?;
        let now = now_ms();
        let not_after_ms = now.saturating_add(lifetime_ms);
        let session_key = key.public_key();
        let signature = identity.sign(
            SignatureContext::SessionCertificate,
            &SessionCertificate::message(identity.public_key(), &session_key, not_after_ms),
        )?;
        Ok(Session {
            key,
            certificate: SessionCertificate {
                session_key,
                not_after_ms,
                signature,
            },
            renew_at_ms: now.saturating_add(lifetime_ms / 2),
        })
    }

    /// The session key to sign with at `now`, replacing it first when it is
    /// due. A failed replacement keeps the current key while it is still
    /// valid, and the next signature tries again.
    fn session(&self, now: u64) -> Result<Arc<Session>> {
        let current = self
            .current
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let hybrid = self.kind.hybrid_at(now);
        if now < current.renew_at_ms && current.is_hybrid() == hybrid {
            return Ok(current);
        }
        let mut slot = self.current.write().unwrap_or_else(|e| e.into_inner());
        if slot.is_hybrid() != hybrid {
            // Hybrid records came into force: an Ed25519 key cannot sign
            // past this moment, so a failed certification is an error.
            *slot = Arc::new(Self::certify(
                self.identity.as_ref(),
                self.lifetime_ms,
                hybrid,
            )?);
        } else if now >= slot.renew_at_ms {
            match Self::certify(self.identity.as_ref(), self.lifetime_ms, hybrid) {
                Ok(next) => *slot = Arc::new(next),
                Err(e) if now > slot.certificate.not_after_ms => return Err(e),
                Err(_) => {}
            }
        }
        Ok(slot.clone())
    }

    /// Sign `message` with the current session key.
    pub fn sign(&self, message: &[u8]) -> Result<SessionSignature> {
        let now = now_ms();
        let session = self.session(now)?;
        if now > session.certificate.not_after_ms {
            return Err(CryptoError::InvalidSignature(
                "the session key has expired and could not be replaced".to_string(),
            ));
        }
        Ok(SessionSignature {
            certificate: session.certificate.clone(),
            signature: session.key.sign(message)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composite::testing::TestHybridSigner;
    use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

    /// A hardware identity stand-in that counts its signatures.
    struct Counted(TestHybridSigner, AtomicUsize);

    impl HybridSigner for Counted {
        fn sign(&self, context: SignatureContext, msg: &[u8]) -> Result<CompositeSignature> {
            self.1.fetch_add(1, Ordering::SeqCst);
            self.0.sign(context, msg)
        }
        fn public_key(&self) -> &CompositePublicKey {
            self.0.public_key()
        }
        fn sign_external(&self, data: &[u8]) -> Result<Vec<u8>> {
            self.0.sign_external(data)
        }
    }

    fn identity() -> Arc<Counted> {
        static SEED: AtomicU8 = AtomicU8::new(1);
        let seed = SEED.fetch_add(1, Ordering::SeqCst);
        Arc::new(Counted(
            TestHybridSigner::p256_only(seed),
            AtomicUsize::new(0),
        ))
    }

    #[test]
    fn a_hybrid_identity_certifies_with_both_legs() {
        let id = Arc::new(Counted(TestHybridSigner::hybrid(200), AtomicUsize::new(0)));
        let signer = SessionSigner::new(id.clone(), SESSION_LIFETIME).unwrap();
        let sig = signer.sign(b"m").unwrap();
        assert!(sig.certificate.signature.pq.is_some());
        sig.verify_now(id.public_key(), b"m").unwrap();
        let mut stripped = sig.clone();
        stripped.certificate.signature.pq = None;
        assert!(stripped.verify_now(id.public_key(), b"m").is_err());
    }

    #[test]
    fn many_signatures_cost_one_long_lived_signature() {
        let id = identity();
        let signer = SessionSigner::new(id.clone(), SESSION_LIFETIME).unwrap();
        for i in 0..100u32 {
            let msg = i.to_le_bytes();
            let sig = signer.sign(&msg).unwrap();
            sig.verify_now(id.public_key(), &msg).unwrap();
        }
        assert_eq!(id.1.load(Ordering::SeqCst), 1);
        assert_eq!(signer.identity(), id.public_key());
    }

    #[test]
    fn a_signature_does_not_verify_under_another_identity_or_message() {
        let id = identity();
        let signer = SessionSigner::new(id.clone(), SESSION_LIFETIME).unwrap();
        let sig = signer.sign(b"m").unwrap();
        assert!(sig.verify_now(identity().public_key(), b"m").is_err());
        assert!(sig.verify_now(id.public_key(), b"other").is_err());
    }

    #[test]
    fn a_forged_or_extended_certificate_is_refused() {
        let id = identity();
        let signer = SessionSigner::new(id.clone(), SESSION_LIFETIME).unwrap();
        let sig = signer.sign(b"m").unwrap();

        let mut later = sig.clone();
        later.certificate.not_after_ms += 1;
        assert!(later.verify_now(id.public_key(), b"m").is_err());

        // A session key the identity never certified, with the old certificate.
        let rogue = Ed25519SignerImpl::generate().unwrap();
        let mut swapped = sig.clone();
        swapped.certificate.session_key = rogue.public_key().clone();
        swapped.signature = rogue.sign(b"m").unwrap();
        assert!(swapped.verify_now(id.public_key(), b"m").is_err());
    }

    #[test]
    fn an_expired_certificate_is_refused() {
        let id = identity();
        let signer = SessionSigner::new(id.clone(), SESSION_LIFETIME).unwrap();
        let sig = signer.sign(b"m").unwrap();
        let expiry = sig.certificate.not_after_ms;
        assert!(sig.verify(id.public_key(), b"m", expiry).is_ok());
        assert!(sig.verify(id.public_key(), b"m", expiry + 1).is_err());
    }

    #[test]
    fn the_session_key_is_replaced_after_half_its_lifetime() {
        let id = identity();
        let signer = SessionSigner::new(id.clone(), Duration::from_millis(40)).unwrap();
        let first = signer.sign(b"m").unwrap();
        std::thread::sleep(Duration::from_millis(25));
        let second = signer.sign(b"m").unwrap();
        assert_ne!(
            first.certificate.session_key,
            second.certificate.session_key
        );
        assert_eq!(id.1.load(Ordering::SeqCst), 2);
        second.verify_now(id.public_key(), b"m").unwrap();
    }

    #[test]
    fn session_keys_are_wiped_on_drop() {
        fn wipes<T: zeroize::ZeroizeOnDrop>() {}
        // The signer's key pair holds its secret as a `SecretKey`.
        wipes::<crate::keys::SecretKey>();
        wipes::<ed25519_dalek::SigningKey>();
    }
}

/// What each signature on a hot path costs, for choosing which statements
/// can carry an ML-DSA-65 leg. Run with
/// `cargo test --release -p tenzro-crypto session::costs -- --ignored --nocapture`.
#[cfg(test)]
mod costs {
    use super::*;
    use crate::composite::testing::TestHybridSigner;
    use crate::pq::{MlDsaSigningKey, ml_dsa_verify};
    use crate::vrf::{VrfSecretKey, prove as vrf_prove, verify as vrf_verify};
    use std::time::Instant;

    fn per_op_us(n: u32, mut f: impl FnMut()) -> f64 {
        for _ in 0..(n / 10).max(1) {
            f();
        }
        let start = Instant::now();
        for _ in 0..n {
            f();
        }
        start.elapsed().as_secs_f64() * 1e6 / f64::from(n)
    }

    #[test]
    #[ignore = "timing, run by hand in release"]
    fn hot_path_signature_costs() {
        let msg = [0x5au8; 256];
        let ed = Ed25519SignerImpl::generate().unwrap();
        let ed_sig = ed.sign(&msg).unwrap();
        let ed_pk = ed.public_key().clone();
        let ed_sign = per_op_us(2000, || {
            ed.sign(&msg).unwrap();
        });
        let ed_verify = per_op_us(2000, || {
            verify(&ed_pk, &msg, &ed_sig).unwrap();
        });

        let pq = MlDsaSigningKey::generate();
        let pq_sig = pq.sign(b"tenzro/session", &msg);
        let pq_sign = per_op_us(300, || {
            pq.sign(b"tenzro/session", &msg);
        });
        let pq_verify = per_op_us(1000, || {
            ml_dsa_verify(pq.verifying_key_bytes(), b"tenzro/session", &msg, &pq_sig).unwrap();
        });

        let vrf = VrfSecretKey([7u8; 32]);
        let vrf_pk = vrf.public_key();
        let pi = vrf_prove(&vrf, &msg).unwrap();
        let vrf_p = per_op_us(1000, || {
            vrf_prove(&vrf, &msg).unwrap();
        });
        let vrf_v = per_op_us(1000, || {
            vrf_verify(&vrf_pk, &msg, &pi).unwrap();
        });

        let identity: Arc<dyn HybridSigner> = Arc::new(TestHybridSigner::hybrid(3));
        let signer = SessionSigner::new(identity.clone(), SESSION_LIFETIME).unwrap();
        let s = signer.sign(&msg).unwrap();
        let session_verify = per_op_us(500, || {
            s.verify_now(identity.public_key(), &msg).unwrap();
        });
        let cert_bytes = serde_json::to_vec(&s.certificate).unwrap().len();
        let hybrid = SessionSigner::new_hybrid(identity.clone(), SESSION_LIFETIME).unwrap();
        let hs = hybrid.sign(&msg).unwrap();
        let hybrid_sign = per_op_us(300, || {
            hybrid.sign(&msg).unwrap();
        });
        let hybrid_verify = per_op_us(500, || {
            hs.verify_now(identity.public_key(), &msg).unwrap();
        });
        println!(
            "hybrid session signature sign {hybrid_sign:.1} us, verify (certificate + both legs) \
             {hybrid_verify:.1} us, signature {} B",
            hs.signature.as_bytes().len()
        );

        println!("ed25519 sign {ed_sign:.1} us, verify {ed_verify:.1} us, signature 64 B");
        println!(
            "ml-dsa-65 sign {pq_sign:.1} us, verify {pq_verify:.1} us, signature {} B",
            pq_sig.len()
        );
        println!("ecvrf-edwards25519 prove {vrf_p:.1} us, verify {vrf_v:.1} us, proof 80 B");
        println!(
            "session signature verify (hybrid certificate + ed25519) {session_verify:.1} us \
             with the certificate cached, certificate as JSON {cert_bytes} B"
        );
        let uncached = per_op_us(300, || {
            let fresh = CertificateCache::new();
            let m = SessionCertificate::message(
                identity.public_key(),
                &s.certificate.session_key,
                s.certificate.not_after_ms,
            );
            fresh
                .check(&m, &s.certificate.signature, || {
                    verify_composite(
                        identity.public_key(),
                        SignatureContext::SessionCertificate,
                        &m,
                        &s.certificate.signature,
                        PqPolicy::WhenPresent,
                    )
                    .map(|_| ())
                })
                .unwrap();
            verify(&s.certificate.session_key, &msg, &s.signature).unwrap();
        });
        println!("session signature verify with the certificate checked afresh {uncached:.1} us");
    }
}

#[cfg(test)]
mod hybrid_tests {
    use super::*;
    use crate::composite::testing::TestHybridSigner;
    use crate::keys::KeyPair;

    /// A hybrid session signature verifies only with both legs, over the
    /// message, under the key the certificate names: the Ed25519 leg alone,
    /// either leg altered, or a certificate rewritten to name the Ed25519 key
    /// alone is refused.
    #[test]
    fn a_hybrid_session_key_signs_with_both_legs_and_neither_alone_verifies() {
        let identity: Arc<dyn HybridSigner> = Arc::new(TestHybridSigner::hybrid(5));
        let id = identity.public_key().clone();
        let signer = SessionSigner::new_hybrid(identity.clone(), SESSION_LIFETIME).unwrap();
        let s = signer.sign(b"receipt").unwrap();
        assert!(s.is_hybrid());
        s.verify_now(&id, b"receipt").unwrap();
        assert!(s.verify_now(&id, b"another receipt").is_err());

        let bytes = s.signature.as_bytes().to_vec();
        for key_type in [KeyType::Ed25519, KeyType::Ed25519MlDsa65] {
            let mut ed_only = s.clone();
            ed_only.signature = Signature::new(key_type, bytes[..ED25519_SIG_LEN].to_vec());
            assert!(ed_only.verify_now(&id, b"receipt").is_err());
        }
        for i in [0, ED25519_SIG_LEN + 10, bytes.len() - 1] {
            let mut altered = s.clone();
            let mut b = bytes.clone();
            b[i] ^= 1;
            altered.signature = Signature::new(KeyType::Ed25519MlDsa65, b);
            assert!(altered.verify_now(&id, b"receipt").is_err());
        }
        let mut downgraded = s.clone();
        downgraded.certificate.session_key = PublicKey::new(
            KeyType::Ed25519,
            s.certificate.session_key.as_bytes()[..ED25519_KEY_LEN].to_vec(),
        );
        downgraded.signature = Signature::new(KeyType::Ed25519, bytes[..ED25519_SIG_LEN].to_vec());
        assert!(downgraded.verify_now(&id, b"receipt").is_err());

        let back: SessionSignature =
            serde_json::from_slice(&serde_json::to_vec(&s).unwrap()).unwrap();
        back.verify_now(&id, b"receipt").unwrap();

        // An Ed25519 session signer is unchanged.
        let plain = SessionSigner::new(identity, SESSION_LIFETIME)
            .unwrap()
            .sign(b"receipt")
            .unwrap();
        assert!(!plain.is_hybrid());
        assert_eq!(plain.signature.as_bytes().len(), ED25519_SIG_LEN);
        plain.verify_now(&id, b"receipt").unwrap();
    }

    /// A record signer signs with Ed25519 session keys until hybrid records
    /// come into force and with a hybrid key from then on, at the cost of
    /// one more identity signature; a verifier refuses an Ed25519 record
    /// dated at or after that moment and accepts one dated before it.
    #[test]
    fn a_record_signer_turns_hybrid_when_hybrid_records_come_into_force() {
        struct Counted(TestHybridSigner, std::sync::atomic::AtomicUsize);
        impl Counted {
            fn signatures(&self) -> usize {
                self.1.load(Ordering::SeqCst)
            }
        }
        impl HybridSigner for Counted {
            fn sign(&self, context: SignatureContext, msg: &[u8]) -> Result<CompositeSignature> {
                self.1.fetch_add(1, Ordering::SeqCst);
                self.0.sign(context, msg)
            }
            fn public_key(&self) -> &CompositePublicKey {
                self.0.public_key()
            }
            fn sign_external(&self, data: &[u8]) -> Result<Vec<u8>> {
                self.0.sign_external(data)
            }
        }
        let counted = Arc::new(Counted(TestHybridSigner::hybrid(7), Default::default()));
        let identity: Arc<dyn HybridSigner> = counted.clone();
        let id = identity.public_key().clone();
        let from = Arc::new(AtomicU64::new(u64::MAX));
        let signer =
            SessionSigner::for_records_from(identity, SESSION_LIFETIME, from.clone()).unwrap();
        let before = signer.sign(b"receipt").unwrap();
        assert!(!before.is_hybrid());
        let t = now_ms();
        before
            .verify_record_under(&id, b"receipt", t, u64::MAX)
            .unwrap();
        before
            .verify_record_under(&id, b"receipt", t, t + 1)
            .unwrap();
        assert!(before.verify_record_under(&id, b"receipt", t, t).is_err());
        assert_eq!(counted.signatures(), 1);

        from.store(t, Ordering::Relaxed);
        let after = signer.sign(b"receipt").unwrap();
        assert!(after.is_hybrid());
        after
            .verify_record_under(&id, b"receipt", now_ms(), t)
            .unwrap();
        assert!(
            after
                .verify_record_under(&id, b"another", now_ms(), t)
                .is_err()
        );
        assert_eq!(counted.signatures(), 2);
        signer.sign(b"again").unwrap();
        assert_eq!(counted.signatures(), 2);
    }

    /// A certificate's identity signature is checked once per process: the
    /// second check of the same certificate is answered from the cache, a
    /// certificate that does not verify is never remembered, and a
    /// remembered certificate still expires.
    #[test]
    fn a_certificate_is_checked_once_and_still_expires() {
        let identity: Arc<dyn HybridSigner> = Arc::new(TestHybridSigner::hybrid(9));
        let id = identity.public_key().clone();
        let s = SessionSigner::new(identity, SESSION_LIFETIME)
            .unwrap()
            .sign(b"m")
            .unwrap();
        let cache = CertificateCache::global();
        s.verify_now(&id, b"m").unwrap();
        let hits = cache.hits();
        s.verify_now(&id, b"m").unwrap();
        assert!(
            cache.hits() > hits,
            "the second check was not answered by the cache"
        );

        let mut forged = s.clone();
        forged.certificate.not_after_ms += 1;
        assert!(forged.verify_now(&id, b"m").is_err());
        assert!(forged.verify_now(&id, b"m").is_err());

        assert!(
            s.verify(&id, b"m", s.certificate.not_after_ms + 1).is_err(),
            "a cached certificate outlived its validity"
        );

        let local = CertificateCache::new();
        let mut runs = 0;
        for _ in 0..3 {
            local
                .check(b"msg", &s.certificate.signature, || {
                    runs += 1;
                    Ok(())
                })
                .unwrap();
        }
        assert_eq!(runs, 1);
        assert_eq!(local.hits(), 2);
    }

    #[test]
    fn a_hybrid_key_is_never_a_key_pair() {
        assert!(KeyPair::generate(KeyType::Ed25519MlDsa65).is_err());
    }
}
