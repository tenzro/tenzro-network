//! A registry of the passkey credentials this node will accept assertions from.
//!
//! # What this replaces
//!
//! The share-escrow path used to obtain a credential's verifying key by
//! *deriving* it:
//!
//! ```ignore
//! hasher.update(CREDENTIAL_KEY_DOMAIN_TAG);
//! hasher.update(credential_id.as_bytes());   // a public identifier
//! let signing_key = EdSigningKey::from_bytes(&seed);
//! ```
//!
//! A credential ID is not a secret. It is chosen by the authenticator, sent to
//! the server at registration, echoed back in every assertion, and stored in
//! the clear at both ends. Deriving the *signing* key from it means anyone who
//! has ever seen one can reconstruct the private half and mint assertions that
//! verify — so the passkey leg contributed nothing at all, while looking like
//! WebAuthn from the outside. The module was honest that it was a testnet stub;
//! the routes were wired to production handlers regardless.
//!
//! This stores the real public key the authenticator produced at registration
//! and verifies against that, so a signature can only come from the device
//! holding the credential.
//!
//! # What is checked, and why each one matters
//!
//! WebAuthn's guarantees come from several checks, and dropping any of them
//! removes a distinct protection:
//!
//! - **Signature over the stored public key** — without it, nothing is
//!   authenticated at all.
//! - **RP ID hash** ([`verify_authenticator_data`]) — an assertion is bound to
//!   the relying party it was created for. Without it, a credential registered
//!   at an attacker's site is accepted here: the user taps their key on
//!   `evil.example`, and that assertion unlocks their share on this node.
//! - **Origin** ([`verify_client_data_origin`]) — the same protection one layer
//!   up, against a page that can reach a permitted RP ID from an unexpected
//!   place.
//! - **User Presence, and User Verification when required** — UP says a human
//!   touched the authenticator; UV says the human proved it was *them* (PIN or
//!   biometric). A wallet share is exactly the thing that should require UV,
//!   since without it a stolen unlocked device is enough.
//! - **Signature counter monotonicity** ([`PasskeyRegistry::verify_and_bump`])
//!   — an authenticator that reports a counter must report an increasing one.
//!   A replayed or cloned authenticator shows up as a counter that stalls or
//!   goes backwards. Counters are optional in the spec (many platform
//!   authenticators always report zero), so a stored zero disables the check
//!   rather than locking the credential out.
//!
//! # Persistence
//!
//! Credentials live in `CF_CREDENTIALS` keyed `passkey:<credential_id>`, and
//! the in-memory map is hydrated at construction. A registry that forgot its
//! credentials on restart would be its own kind of stub: every wallet would be
//! locked out of its share by a node restart, and the tempting fix would be to
//! fall back to accepting unregistered credentials.

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_storage::kv::{CF_CREDENTIALS, KvStore};
use tracing::{info, warn};

/// Key prefix for credential records inside `CF_CREDENTIALS`.
///
/// The column family is shared with the identity registry's replay-protection
/// set, so this namespace keeps the two from colliding on a common ID.
const CREDENTIAL_KEY_PREFIX: &str = "passkey:";

/// COSE algorithm identifiers this node will verify.
///
/// Deliberately a closed set rather than an integer carried from the wire: an
/// unknown algorithm must be a rejection, not a lookup that silently picks a
/// weaker verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoseAlgorithm {
    /// COSE `-8`, Ed25519 (EdDSA over Curve25519).
    Ed25519,
    /// COSE `-7`, ECDSA over NIST P-256 with SHA-256.
    Es256,
}

impl CoseAlgorithm {
    /// Map a COSE algorithm identifier, rejecting anything else.
    pub fn from_cose(alg: i64) -> Option<Self> {
        match alg {
            -8 => Some(CoseAlgorithm::Ed25519),
            -7 => Some(CoseAlgorithm::Es256),
            _ => None,
        }
    }

    /// The COSE identifier, for round-tripping to the wire.
    pub fn as_cose(&self) -> i64 {
        match self {
            CoseAlgorithm::Ed25519 => -8,
            CoseAlgorithm::Es256 => -7,
        }
    }

    /// Expected public-key length in bytes.
    ///
    /// Ed25519 is a 32-byte compressed point. P-256 here is the uncompressed
    /// `(x, y)` pair without the SEC1 `0x04` tag, matching what the WebAuthn
    /// COSE key exposes as its two 32-byte coordinates.
    fn public_key_len(&self) -> usize {
        match self {
            CoseAlgorithm::Ed25519 => 32,
            CoseAlgorithm::Es256 => 64,
        }
    }

    /// Expected raw signature length in bytes.
    fn signature_len(&self) -> usize {
        64
    }
}

/// Why a credential or assertion was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PasskeyError {
    /// No credential registered under this ID.
    #[error("no passkey credential registered for id {0}")]
    UnknownCredential(String),

    /// A credential ID may be registered once.
    #[error("credential {0} is already registered")]
    DuplicateCredential(String),

    /// The stored or supplied key is the wrong size for its algorithm.
    #[error("{alg:?} public key must be {expected} bytes, got {actual}")]
    BadKeyLength {
        /// The algorithm the key claims.
        alg: CoseAlgorithm,
        /// Bytes the algorithm requires.
        expected: usize,
        /// Bytes supplied.
        actual: usize,
    },

    /// `authenticatorData` was shorter than the fixed 37-byte prefix.
    #[error("authenticatorData must be at least 37 bytes, got {0}")]
    AuthenticatorDataTooShort(usize),

    /// The assertion was produced for a different relying party.
    #[error("assertion is for a different relying party than {expected}")]
    RpIdMismatch {
        /// The RP ID this credential is registered against.
        expected: String,
    },

    /// The calling page was not one this credential is registered for.
    #[error("origin {actual} is not permitted; expected {expected}")]
    OriginMismatch {
        /// The origin registered for this credential.
        expected: String,
        /// The origin the assertion carried.
        actual: String,
    },

    /// The authenticator did not report a present user.
    #[error("authenticator did not assert user presence")]
    UserNotPresent,

    /// The authenticator did not verify the user, and this credential requires it.
    #[error("authenticator did not verify the user, which this credential requires")]
    UserNotVerified,

    /// The counter did not advance — a replay or a cloned authenticator.
    #[error("signature counter went backwards: stored {stored}, presented {presented}")]
    CounterReplay {
        /// Counter value last seen.
        stored: u32,
        /// Counter value now presented.
        presented: u32,
    },

    /// The signature did not verify against the registered key.
    #[error("assertion signature does not verify against the registered credential")]
    BadSignature,

    /// Storage refused a write.
    #[error("persisting credential: {0}")]
    Storage(String),
}

/// A registered passkey credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyCredential {
    /// Authenticator-chosen credential ID, base64url, no padding.
    pub credential_id: String,
    /// Raw public key bytes, shaped per [`CoseAlgorithm::public_key_len`].
    pub public_key: Vec<u8>,
    /// Which signature algorithm the credential uses.
    pub algorithm: CoseAlgorithm,
    /// Relying-party ID the credential was created for, e.g. `wallet.tenzro.net`.
    pub rp_id: String,
    /// Exact origin permitted to present this credential.
    pub origin: String,
    /// Highest signature counter seen. Zero means the authenticator does not
    /// keep one, which disables the replay check for this credential.
    pub sign_count: u32,
    /// Whether an assertion must carry the User Verified flag.
    pub require_user_verification: bool,
    /// Unix seconds at registration.
    pub created_at: u64,
}

impl PasskeyCredential {
    /// Reject a credential whose key cannot possibly verify.
    fn validate(&self) -> Result<(), PasskeyError> {
        let expected = self.algorithm.public_key_len();
        if self.public_key.len() != expected {
            return Err(PasskeyError::BadKeyLength {
                alg: self.algorithm,
                expected,
                actual: self.public_key.len(),
            });
        }
        Ok(())
    }
}

/// The set of credentials this node accepts assertions from.
pub struct PasskeyRegistry {
    credentials: DashMap<String, PasskeyCredential>,
    storage: Option<Arc<dyn KvStore>>,
}

impl PasskeyRegistry {
    /// An empty in-memory registry. For tests and for nodes with no store.
    pub fn new() -> Self {
        Self {
            credentials: DashMap::new(),
            storage: None,
        }
    }

    /// A registry backed by `storage`, hydrated from `CF_CREDENTIALS`.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        let credentials = DashMap::new();
        match storage.scan_prefix(CF_CREDENTIALS, CREDENTIAL_KEY_PREFIX.as_bytes()) {
            Ok(rows) => {
                for (_, blob) in rows {
                    match serde_json::from_slice::<PasskeyCredential>(&blob) {
                        Ok(cred) => {
                            credentials.insert(cred.credential_id.clone(), cred);
                        }
                        // A record we cannot parse is skipped rather than
                        // fatal: one corrupt row must not stop every other
                        // credential from loading and lock out every wallet.
                        Err(e) => warn!("skipping unparseable passkey credential: {e}"),
                    }
                }
                info!(
                    count = credentials.len(),
                    "hydrated passkey credentials from storage"
                );
            }
            Err(e) => warn!("could not hydrate passkey credentials: {e}"),
        }
        Self {
            credentials,
            storage: Some(storage),
        }
    }

    fn storage_key(credential_id: &str) -> Vec<u8> {
        format!("{CREDENTIAL_KEY_PREFIX}{credential_id}").into_bytes()
    }

    /// Register a credential, refusing a duplicate ID.
    ///
    /// Duplicates are refused rather than overwritten: re-registering an ID
    /// that already exists would let a caller replace the key a share is
    /// escrowed against, which is the whole attack this registry prevents.
    pub fn register(&self, credential: PasskeyCredential) -> Result<(), PasskeyError> {
        credential.validate()?;
        if self.credentials.contains_key(&credential.credential_id) {
            return Err(PasskeyError::DuplicateCredential(
                credential.credential_id.clone(),
            ));
        }
        self.persist(&credential)?;
        self.credentials
            .insert(credential.credential_id.clone(), credential);
        Ok(())
    }

    fn persist(&self, credential: &PasskeyCredential) -> Result<(), PasskeyError> {
        let Some(storage) = self.storage.as_ref() else {
            return Ok(());
        };
        let blob = serde_json::to_vec(credential)
            .map_err(|e| PasskeyError::Storage(format!("encoding credential: {e}")))?;
        storage
            .put(
                CF_CREDENTIALS,
                &Self::storage_key(&credential.credential_id),
                &blob,
            )
            .map_err(|e| PasskeyError::Storage(e.to_string()))
    }

    /// The credential registered under `credential_id`, if any.
    pub fn get(&self, credential_id: &str) -> Option<PasskeyCredential> {
        self.credentials.get(credential_id).map(|e| e.value().clone())
    }

    /// Whether anything is registered under this ID.
    pub fn contains(&self, credential_id: &str) -> bool {
        self.credentials.contains_key(credential_id)
    }

    /// How many credentials are registered.
    pub fn len(&self) -> usize {
        self.credentials.len()
    }

    /// Whether the registry holds no credentials.
    pub fn is_empty(&self) -> bool {
        self.credentials.is_empty()
    }

    /// Verify a full assertion and advance the stored counter on success.
    ///
    /// `signed_payload` is `authenticatorData || SHA-256(clientDataJSON)` per
    /// WebAuthn L3 §7.2 step 19 — the caller assembles it because it already
    /// holds both halves.
    ///
    /// The counter is only advanced once everything else has passed, so a
    /// failed attempt cannot burn a counter value and lock out the real device.
    pub fn verify_and_bump(
        &self,
        credential_id: &str,
        authenticator_data: &[u8],
        client_data_json: &[u8],
        signed_payload: &[u8],
        signature: &[u8],
    ) -> Result<(), PasskeyError> {
        let credential = self
            .get(credential_id)
            .ok_or_else(|| PasskeyError::UnknownCredential(credential_id.to_string()))?;

        let presented_count = verify_authenticator_data(
            authenticator_data,
            &credential.rp_id,
            credential.require_user_verification,
        )?;
        verify_client_data_origin(client_data_json, &credential.origin)?;

        if !verify_signature(&credential, signed_payload, signature) {
            return Err(PasskeyError::BadSignature);
        }

        // A stored counter of zero means this authenticator does not keep one.
        // Enforcing monotonicity against it would reject every assertion from
        // the many platform authenticators that always report zero.
        if credential.sign_count != 0 || presented_count != 0 {
            if presented_count <= credential.sign_count {
                return Err(PasskeyError::CounterReplay {
                    stored: credential.sign_count,
                    presented: presented_count,
                });
            }
            let mut advanced = credential.clone();
            advanced.sign_count = presented_count;
            self.persist(&advanced)?;
            self.credentials
                .insert(advanced.credential_id.clone(), advanced);
        }

        Ok(())
    }
}

impl Default for PasskeyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Check `authenticatorData` and return the signature counter it carries.
///
/// Layout per WebAuthn L3 §6.1: `rpIdHash(32) || flags(1) || signCount(4)`,
/// optionally followed by attested credential data and extensions, which this
/// does not need.
pub fn verify_authenticator_data(
    auth_data: &[u8],
    expected_rp_id: &str,
    require_user_verification: bool,
) -> Result<u32, PasskeyError> {
    if auth_data.len() < 37 {
        return Err(PasskeyError::AuthenticatorDataTooShort(auth_data.len()));
    }

    let expected_hash = Sha256::digest(expected_rp_id.as_bytes());
    // Constant-time compare: this is a public value, but a timing oracle on it
    // would still leak which RP a credential belongs to across a shared node.
    let matches = auth_data[..32]
        .iter()
        .zip(expected_hash.iter())
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0;
    if !matches {
        return Err(PasskeyError::RpIdMismatch {
            expected: expected_rp_id.to_string(),
        });
    }

    let flags = auth_data[32];
    // Bit 0 — User Present.
    if flags & 0x01 == 0 {
        return Err(PasskeyError::UserNotPresent);
    }
    // Bit 2 — User Verified.
    if require_user_verification && flags & 0x04 == 0 {
        return Err(PasskeyError::UserNotVerified);
    }

    let mut counter = [0u8; 4];
    counter.copy_from_slice(&auth_data[33..37]);
    Ok(u32::from_be_bytes(counter))
}

/// Minimal `clientDataJSON` shape needed for the origin check.
#[derive(Debug, Deserialize)]
struct ClientDataOrigin {
    origin: String,
}

/// Check that the assertion was produced by the origin this credential permits.
pub fn verify_client_data_origin(
    client_data_json: &[u8],
    expected_origin: &str,
) -> Result<(), PasskeyError> {
    let parsed: ClientDataOrigin =
        serde_json::from_slice(client_data_json).map_err(|_| PasskeyError::OriginMismatch {
            expected: expected_origin.to_string(),
            actual: "<unparseable clientDataJSON>".to_string(),
        })?;
    if parsed.origin != expected_origin {
        return Err(PasskeyError::OriginMismatch {
            expected: expected_origin.to_string(),
            actual: parsed.origin,
        });
    }
    Ok(())
}

/// Verify the raw signature against the credential's registered key.
fn verify_signature(credential: &PasskeyCredential, payload: &[u8], signature: &[u8]) -> bool {
    if signature.len() != credential.algorithm.signature_len() {
        return false;
    }
    match credential.algorithm {
        CoseAlgorithm::Ed25519 => {
            use ed25519_dalek::{Signature, Verifier, VerifyingKey};
            let Ok(key_bytes): Result<[u8; 32], _> = credential.public_key[..].try_into() else {
                return false;
            };
            let Ok(vk) = VerifyingKey::from_bytes(&key_bytes) else {
                return false;
            };
            let Ok(sig_bytes): Result<[u8; 64], _> = signature.try_into() else {
                return false;
            };
            vk.verify(payload, &Signature::from_bytes(&sig_bytes)).is_ok()
        }
        CoseAlgorithm::Es256 => {
            use tenzro_crypto::p256::{P256Signature, P256Verifier};
            // The credential stores the raw 64-byte (x, y) pair, which is what
            // the COSE key exposes and what this verifier takes directly.
            let Ok(verifier) = P256Verifier::from_public_key_bytes(&credential.public_key) else {
                return false;
            };
            let Ok(sig_bytes): Result<[u8; 64], _> = signature.try_into() else {
                return false;
            };
            // WebAuthn signs SHA-256 of the payload; ES256 is ECDSA-SHA256.
            verifier
                .verify_sha256(payload, &P256Signature::from_bytes(sig_bytes))
                .is_ok()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const RP_ID: &str = "wallet.tenzro.net";
    const ORIGIN: &str = "https://wallet.tenzro.net";

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn credential(id: &str, sk: &SigningKey, uv: bool, count: u32) -> PasskeyCredential {
        PasskeyCredential {
            credential_id: id.to_string(),
            public_key: sk.verifying_key().as_bytes().to_vec(),
            algorithm: CoseAlgorithm::Ed25519,
            rp_id: RP_ID.to_string(),
            origin: ORIGIN.to_string(),
            sign_count: count,
            require_user_verification: uv,
            created_at: 1_700_000_000,
        }
    }

    /// `rpIdHash(32) || flags(1) || signCount(4)`.
    fn auth_data(rp_id: &str, flags: u8, count: u32) -> Vec<u8> {
        let mut out = Sha256::digest(rp_id.as_bytes()).to_vec();
        out.push(flags);
        out.extend_from_slice(&count.to_be_bytes());
        out
    }

    fn client_data(origin: &str) -> Vec<u8> {
        format!(
            r#"{{"type":"webauthn.get","challenge":"abc","origin":"{origin}"}}"#
        )
        .into_bytes()
    }

    fn signed_payload(auth: &[u8], client: &[u8]) -> Vec<u8> {
        let mut p = auth.to_vec();
        p.extend_from_slice(&Sha256::digest(client));
        p
    }

    /// UP + UV set.
    const FLAGS_UP_UV: u8 = 0x05;
    /// UP only.
    const FLAGS_UP: u8 = 0x01;

    #[test]
    fn a_genuine_assertion_verifies() {
        let reg = PasskeyRegistry::new();
        let sk = signing_key(3);
        reg.register(credential("cred-a", &sk, true, 0)).unwrap();

        let auth = auth_data(RP_ID, FLAGS_UP_UV, 1);
        let client = client_data(ORIGIN);
        let payload = signed_payload(&auth, &client);
        let sig = sk.sign(&payload).to_bytes().to_vec();

        reg.verify_and_bump("cred-a", &auth, &client, &payload, &sig)
            .expect("a genuine assertion must verify");
    }

    /// The bug this module exists to fix.
    ///
    /// The old code derived the signing key from the credential ID, so anyone
    /// holding that public identifier could mint assertions. Here a key that is
    /// not the registered one fails, however well-formed the assertion is.
    #[test]
    fn a_key_derived_from_the_credential_id_no_longer_works() {
        let reg = PasskeyRegistry::new();
        let real = signing_key(3);
        reg.register(credential("cred-a", &real, true, 0)).unwrap();

        // Exactly the old derivation: seed = H(domain || credential_id).
        let mut hasher = Sha256::new();
        hasher.update(b"tenzro/wallet/share/credential-key");
        hasher.update(b"cred-a");
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&hasher.finalize());
        let forged = SigningKey::from_bytes(&seed);

        let auth = auth_data(RP_ID, FLAGS_UP_UV, 1);
        let client = client_data(ORIGIN);
        let payload = signed_payload(&auth, &client);
        let sig = forged.sign(&payload).to_bytes().to_vec();

        assert_eq!(
            reg.verify_and_bump("cred-a", &auth, &client, &payload, &sig),
            Err(PasskeyError::BadSignature),
            "a key derived from the public credential id must not authenticate"
        );
    }

    /// An assertion made for another relying party must not be accepted.
    #[test]
    fn an_assertion_for_a_different_relying_party_is_refused() {
        let reg = PasskeyRegistry::new();
        let sk = signing_key(3);
        reg.register(credential("cred-a", &sk, true, 0)).unwrap();

        let auth = auth_data("evil.example", FLAGS_UP_UV, 1);
        let client = client_data(ORIGIN);
        let payload = signed_payload(&auth, &client);
        let sig = sk.sign(&payload).to_bytes().to_vec();

        assert!(matches!(
            reg.verify_and_bump("cred-a", &auth, &client, &payload, &sig),
            Err(PasskeyError::RpIdMismatch { .. })
        ));
    }

    #[test]
    fn an_assertion_from_an_unexpected_origin_is_refused() {
        let reg = PasskeyRegistry::new();
        let sk = signing_key(3);
        reg.register(credential("cred-a", &sk, true, 0)).unwrap();

        let auth = auth_data(RP_ID, FLAGS_UP_UV, 1);
        let client = client_data("https://evil.example");
        let payload = signed_payload(&auth, &client);
        let sig = sk.sign(&payload).to_bytes().to_vec();

        assert!(matches!(
            reg.verify_and_bump("cred-a", &auth, &client, &payload, &sig),
            Err(PasskeyError::OriginMismatch { .. })
        ));
    }

    /// A wallet share should need the user proven, not merely present.
    #[test]
    fn user_verification_is_enforced_when_the_credential_requires_it() {
        let reg = PasskeyRegistry::new();
        let sk = signing_key(3);
        reg.register(credential("cred-a", &sk, true, 0)).unwrap();

        let auth = auth_data(RP_ID, FLAGS_UP, 1); // present, not verified
        let client = client_data(ORIGIN);
        let payload = signed_payload(&auth, &client);
        let sig = sk.sign(&payload).to_bytes().to_vec();

        assert_eq!(
            reg.verify_and_bump("cred-a", &auth, &client, &payload, &sig),
            Err(PasskeyError::UserNotVerified)
        );
    }

    #[test]
    fn an_absent_user_is_refused_even_without_uv() {
        let reg = PasskeyRegistry::new();
        let sk = signing_key(3);
        reg.register(credential("cred-a", &sk, false, 0)).unwrap();

        let auth = auth_data(RP_ID, 0x00, 1);
        let client = client_data(ORIGIN);
        let payload = signed_payload(&auth, &client);
        let sig = sk.sign(&payload).to_bytes().to_vec();

        assert_eq!(
            reg.verify_and_bump("cred-a", &auth, &client, &payload, &sig),
            Err(PasskeyError::UserNotPresent)
        );
    }

    /// Replaying an assertion re-presents a counter that has already been used.
    #[test]
    fn a_replayed_assertion_is_refused_by_the_counter() {
        let reg = PasskeyRegistry::new();
        let sk = signing_key(3);
        reg.register(credential("cred-a", &sk, true, 0)).unwrap();

        let auth = auth_data(RP_ID, FLAGS_UP_UV, 5);
        let client = client_data(ORIGIN);
        let payload = signed_payload(&auth, &client);
        let sig = sk.sign(&payload).to_bytes().to_vec();

        reg.verify_and_bump("cred-a", &auth, &client, &payload, &sig)
            .unwrap();
        assert_eq!(
            reg.verify_and_bump("cred-a", &auth, &client, &payload, &sig),
            Err(PasskeyError::CounterReplay {
                stored: 5,
                presented: 5
            }),
            "the same assertion must not verify twice"
        );
    }

    /// Authenticators that never keep a counter must still work.
    #[test]
    fn an_authenticator_that_always_reports_zero_is_not_locked_out() {
        let reg = PasskeyRegistry::new();
        let sk = signing_key(3);
        reg.register(credential("cred-a", &sk, true, 0)).unwrap();

        let auth = auth_data(RP_ID, FLAGS_UP_UV, 0);
        let client = client_data(ORIGIN);
        let payload = signed_payload(&auth, &client);
        let sig = sk.sign(&payload).to_bytes().to_vec();

        for _ in 0..3 {
            reg.verify_and_bump("cred-a", &auth, &client, &payload, &sig)
                .expect("a zero-counter authenticator must keep working");
        }
    }

    /// A failed attempt must not advance the counter and lock out the device.
    #[test]
    fn a_failed_assertion_does_not_burn_the_counter() {
        let reg = PasskeyRegistry::new();
        let sk = signing_key(3);
        let stranger = signing_key(9);
        reg.register(credential("cred-a", &sk, true, 0)).unwrap();

        let auth = auth_data(RP_ID, FLAGS_UP_UV, 7);
        let client = client_data(ORIGIN);
        let payload = signed_payload(&auth, &client);

        let bad = stranger.sign(&payload).to_bytes().to_vec();
        assert!(reg.verify_and_bump("cred-a", &auth, &client, &payload, &bad).is_err());
        assert_eq!(reg.get("cred-a").unwrap().sign_count, 0);

        let good = sk.sign(&payload).to_bytes().to_vec();
        reg.verify_and_bump("cred-a", &auth, &client, &payload, &good)
            .expect("the real device must still work after a failed attempt");
    }

    #[test]
    fn an_unregistered_credential_is_refused() {
        let reg = PasskeyRegistry::new();
        let err = reg.verify_and_bump("nobody", &auth_data(RP_ID, FLAGS_UP_UV, 1), &client_data(ORIGIN), b"x", &[0u8; 64]);
        assert!(matches!(err, Err(PasskeyError::UnknownCredential(_))));
    }

    /// Re-registering an ID would let a caller swap the key a share is bound to.
    #[test]
    fn a_credential_id_cannot_be_registered_twice() {
        let reg = PasskeyRegistry::new();
        reg.register(credential("cred-a", &signing_key(3), true, 0))
            .unwrap();
        assert!(matches!(
            reg.register(credential("cred-a", &signing_key(9), true, 0)),
            Err(PasskeyError::DuplicateCredential(_))
        ));
        // The original key still governs.
        assert_eq!(
            reg.get("cred-a").unwrap().public_key,
            signing_key(3).verifying_key().as_bytes().to_vec()
        );
    }

    #[test]
    fn a_wrong_length_key_is_refused_at_registration() {
        let reg = PasskeyRegistry::new();
        let mut cred = credential("cred-a", &signing_key(3), true, 0);
        cred.public_key = vec![0u8; 31];
        assert!(matches!(
            reg.register(cred),
            Err(PasskeyError::BadKeyLength { .. })
        ));
    }

    #[test]
    fn truncated_authenticator_data_is_refused() {
        assert!(matches!(
            verify_authenticator_data(&[0u8; 36], RP_ID, false),
            Err(PasskeyError::AuthenticatorDataTooShort(36))
        ));
    }

    #[test]
    fn unknown_cose_algorithms_are_rejected() {
        assert_eq!(CoseAlgorithm::from_cose(-8), Some(CoseAlgorithm::Ed25519));
        assert_eq!(CoseAlgorithm::from_cose(-7), Some(CoseAlgorithm::Es256));
        assert_eq!(CoseAlgorithm::from_cose(-257), None, "RS256 is not accepted");
        assert_eq!(CoseAlgorithm::from_cose(0), None);
    }
}
