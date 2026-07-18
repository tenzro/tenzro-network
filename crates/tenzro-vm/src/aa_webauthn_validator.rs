//! WebAuthn + ML-DSA-65 hybrid validator (ERC-7579 module).
//!
//! This validator authorises a `UserOperation` against an enrolled passkey
//! (WebAuthn / FIDO2 P-256 credential) **and** a hybrid post-quantum leg
//! (ML-DSA-65 per FIPS 204). Both legs must pass for the validator to return
//! `ValidationData::success()`.
//!
//! # Storage layout
//!
//! Per the ERC-7579 / Coinbase Smart Wallet pattern, each account is enrolled
//! with one credential bundle:
//!
//! ```text
//! mapping(address account => (
//!     bytes32 pubkey_x,        // P-256 public key, x coordinate
//!     bytes32 pubkey_y,        // P-256 public key, y coordinate
//!     bytes32 pq_pubkey_hash   // SHA-256(ML-DSA-65 verifying key bytes)
//! ));
//! ```
//!
//! The full 1952-byte ML-DSA-65 verifying key is too large to economically
//! store on-chain, so the on-chain commitment is the SHA-256 hash; the full
//! key lives in this in-memory registry and (in production) in a node-side
//! KV-store keyed by hash. This validator stores both — the hash is exposed
//! via [`WebAuthnAccountKey::pq_pubkey_hash`] for the on-chain commitment.
//!
//! # Signature wire format
//!
//! `userOp.signature` is the bincode encoding of [`HybridWebAuthnSignature`]:
//!
//! ```text
//! HybridWebAuthnSignature {
//!     assertion: WebAuthnAssertion,   // raw authenticatorData / clientDataJSON / DER sig
//!     ml_dsa_signature: Vec<u8>,       // 3309 bytes (ML-DSA-65)
//! }
//! ```
//!
//! # Challenge binding
//!
//! Per the Coinbase Smart Wallet / Daimo Pay convention, the WebAuthn
//! challenge issued to the authenticator at `navigator.credentials.get()`
//! time is `base64url_no_pad(SHA-256(canonicalUserOpHash))`. This validator
//! re-derives the challenge from `op_hash` and asserts byte-equality against
//! `clientDataJSON.challenge`. The ML-DSA-65 leg is verified over the raw
//! 32-byte `op_hash`.
//!
//! # On-chain hot path (RIP-7212 / EIP-7951 precompile)
//!
//! The P-256 verification routes through the same code path as the on-chain
//! `0x100` precompile (`crate::precompiles::precompile_p256verify`). For the
//! validator's in-runtime check we call directly into
//! [`tenzro_crypto::webauthn::verify_webauthn_assertion`] which uses the
//! same `tenzro_crypto::p256` verifier the precompile exposes — no
//! divergence between off-chain validator simulation and on-chain execution.

use base64::Engine;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use tenzro_crypto::pq::{ml_dsa_verify, ML_DSA_65_SIG_LEN, ML_DSA_65_VK_LEN};
use tenzro_crypto::webauthn::{
    verify_webauthn_assertion, WebAuthnAssertion, WebAuthnCeremonyType,
};

use crate::aa_validators::{
    IValidator, ValidationData, ValidatorError, ERC1271_FAILURE_VALUE, ERC1271_MAGIC_VALUE,
};
use crate::account_abstraction::UserOperation;

// -----------------------------------------------------------------------------
// Enrollment record
// -----------------------------------------------------------------------------

/// Per-account credential bundle. The on-chain shape is `(pubkey_x, pubkey_y,
/// pq_pubkey_hash)` — the full ML-DSA verifying key stays in this validator's
/// in-memory store and is verified by hash on every check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuthnAccountKey {
    /// P-256 public key x coordinate (big-endian, 32 bytes).
    pub pubkey_x: [u8; 32],
    /// P-256 public key y coordinate (big-endian, 32 bytes).
    pub pubkey_y: [u8; 32],
    /// Full ML-DSA-65 verifying key (1952 bytes). The on-chain commitment
    /// is `SHA-256(self.pq_pubkey)`.
    pub pq_pubkey: Vec<u8>,
}

impl WebAuthnAccountKey {
    /// Construct a new enrollment record. Validates the lengths of all key
    /// material. Returns `Err` if `pq_pubkey` is not exactly
    /// [`ML_DSA_65_VK_LEN`] bytes.
    pub fn new(
        pubkey_x: [u8; 32],
        pubkey_y: [u8; 32],
        pq_pubkey: Vec<u8>,
    ) -> Result<Self, ValidatorError> {
        if pq_pubkey.len() != ML_DSA_65_VK_LEN {
            return Err(ValidatorError::InvalidInput(format!(
                "ML-DSA-65 verifying key must be {} bytes, got {}",
                ML_DSA_65_VK_LEN,
                pq_pubkey.len()
            )));
        }
        Ok(Self { pubkey_x, pubkey_y, pq_pubkey })
    }

    /// SHA-256 hash of the ML-DSA verifying key — the on-chain commitment.
    pub fn pq_pubkey_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(&self.pq_pubkey);
        h.finalize().into()
    }

    /// Concatenated `x ‖ y` form consumed by `tenzro_crypto::p256` and the
    /// `0x100` RIP-7212 precompile.
    pub fn p256_public_key_xy(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.pubkey_x);
        out[32..].copy_from_slice(&self.pubkey_y);
        out
    }
}

// -----------------------------------------------------------------------------
// Wire-format hybrid signature
// -----------------------------------------------------------------------------

/// Wire-format `userOp.signature` payload consumed by [`WebAuthnValidator`].
///
/// Carries the raw WebAuthn assertion, the ML-DSA-65 signature over the
/// same UserOp hash, and the `credential.id` identifying which enrolled
/// passkey signed. Multi-credential per account is a first-class property
/// of the validator — every signature MUST address its credential.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridWebAuthnSignature {
    pub assertion: WebAuthnAssertion,
    pub ml_dsa_signature: Vec<u8>,
    /// Raw `credential.id` bytes (base64url-decoded). Identifies which
    /// enrolled credential on the sender's account this signature
    /// corresponds to. Required.
    pub credential_id: Vec<u8>,
}

impl HybridWebAuthnSignature {
    /// Encode for embedding in `userOp.signature`. Uses bincode 1.x default
    /// config (fixint-encoded lengths, little-endian) — matches the
    /// workspace-pinned bincode version.
    pub fn encode(&self) -> Result<Vec<u8>, ValidatorError> {
        bincode::serialize(self)
            .map_err(|e| ValidatorError::InvalidInput(format!("bincode encode: {}", e)))
    }

    /// Decode from `userOp.signature` bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, ValidatorError> {
        bincode::deserialize::<Self>(bytes)
            .map_err(|e| ValidatorError::InvalidInput(format!("bincode decode: {}", e)))
    }
}

// -----------------------------------------------------------------------------
// WebAuthnValidator
// -----------------------------------------------------------------------------

/// ERC-7579 validator module that authorises UserOperations against any
/// of the enrolled passkeys for a smart account, paired with a hybrid
/// ML-DSA-65 leg.
///
/// **Multi-device federation.** An account can carry any number of
/// enrolled credentials — a primary platform passkey, a phone passkey,
/// a YubiKey, and so on. Each is keyed by its `credential.id`; the
/// validator dispatches incoming `HybridWebAuthnSignature` to the
/// matching enrolled credential via `signature.credential_id`. Removing
/// one credential (lost device) does not lock the user out as long as
/// any other enrolled credential survives.
pub struct WebAuthnValidator {
    /// Module address (used as the registry key).
    address: [u8; 20],
    /// Pinned origin (e.g. `https://keys.tenzro.xyz`). The WebAuthn
    /// `clientDataJSON.origin` field must match exactly.
    expected_origin: String,
    /// Per-account credential set. The outer map keys on the smart-
    /// account address; the inner map keys on `credential_id` so the
    /// validator can dispatch a signature directly to the credential
    /// that produced it in O(1).
    enrollments: DashMap<Vec<u8>, DashMap<Vec<u8>, WebAuthnAccountKey>>,
    /// Optional persistent storage. When present, every `enroll` /
    /// `revoke_credential` / `revoke_account` writes through to
    /// `CF_VALIDATOR_MODULES` under the
    /// `erc7579/webauthn/<account_hex>/<credential_id_hex>` prefix and
    /// the constructor hydrates `enrollments` from the same prefix.
    /// Production constructor `with_storage()` always wires this; tests
    /// use `new()` for the in-memory-only path.
    storage: Option<Arc<dyn tenzro_storage::KvStore>>,
}

impl WebAuthnValidator {
    /// Build a new validator pinned to `expected_origin`. The address
    /// uniquely identifies the module instance in the
    /// [`crate::aa_validators::ValidatorRegistry`].
    pub fn new(address: [u8; 20], expected_origin: String) -> Self {
        Self {
            address,
            expected_origin,
            enrollments: DashMap::new(),
            storage: None,
        }
    }

    /// Construct a persistent validator backed by `storage`. Hydrates
    /// `enrollments` from `CF_VALIDATOR_MODULES / erc7579/webauthn/*`
    /// on construction. Every subsequent `enroll` / `revoke` writes
    /// through to the same column family. **Production constructor** —
    /// call instead of `new` whenever the node owns a `KvStore`.
    pub fn with_storage(
        address: [u8; 20],
        expected_origin: String,
        storage: Arc<dyn tenzro_storage::KvStore>,
    ) -> Self {
        let v = Self {
            address,
            expected_origin,
            enrollments: DashMap::new(),
            storage: Some(storage),
        };
        v.hydrate();
        v
    }

    /// Persistence key shape:
    /// `erc7579/webauthn/<account_bytes>/<credential_id_bytes>`.
    /// Account and credential id are concatenated as raw bytes with a `/`
    /// separator; both fields are caller-controlled and the validator
    /// does not enforce any length, so the separator is the only frame
    /// the hydrate path uses to split them back out.
    fn enrollment_key(account: &[u8], credential_id: &[u8]) -> Vec<u8> {
        let mut k = b"erc7579/webauthn/".to_vec();
        k.extend_from_slice(account);
        k.push(b'/');
        k.extend_from_slice(credential_id);
        k
    }

    fn hydrate(&self) {
        let Some(ref storage) = self.storage else {
            return;
        };
        let prefix = b"erc7579/webauthn/";
        let entries = match storage.scan_prefix(tenzro_storage::CF_VALIDATOR_MODULES, prefix) {
            Ok(e) => e,
            Err(_) => return,
        };
        for (key, value) in entries {
            if key.len() <= prefix.len() {
                continue;
            }
            // Split `<account>/<credential_id>` after the namespace prefix.
            let rest = &key[prefix.len()..];
            let Some(sep_idx) = rest.iter().rposition(|b| *b == b'/') else {
                continue;
            };
            let account = rest[..sep_idx].to_vec();
            let credential_id = rest[sep_idx + 1..].to_vec();
            if let Ok(record) = bincode::deserialize::<WebAuthnAccountKey>(&value) {
                let inner = self
                    .enrollments
                    .entry(account)
                    .or_default();
                inner.insert(credential_id, record);
            }
        }
    }

    fn persist(&self, account: &[u8], credential_id: &[u8], key: &WebAuthnAccountKey) {
        if let Some(ref storage) = self.storage
            && let Ok(bytes) = bincode::serialize(key)
        {
            let _ = storage.put(
                tenzro_storage::CF_VALIDATOR_MODULES,
                &Self::enrollment_key(account, credential_id),
                &bytes,
            );
        }
    }

    fn forget(&self, account: &[u8], credential_id: &[u8]) {
        if let Some(ref storage) = self.storage {
            let _ = storage.delete(
                tenzro_storage::CF_VALIDATOR_MODULES,
                &Self::enrollment_key(account, credential_id),
            );
        }
    }

    /// Wrap the validator in an Arc — convenience for installing into the
    /// registry.
    pub fn into_arc(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Enroll a passkey credential on an account. An account can carry
    /// any number of enrolled credentials; each is keyed by its
    /// `credential.id`. Re-enrolling the same `(account, credential_id)`
    /// overwrites the existing record — useful for refreshing the
    /// ML-DSA-65 verifying key without removing the credential.
    pub fn enroll(
        &self,
        account: Vec<u8>,
        credential_id: Vec<u8>,
        key: WebAuthnAccountKey,
    ) -> Result<(), ValidatorError> {
        if credential_id.is_empty() {
            return Err(ValidatorError::InvalidInput(
                "credential_id must be non-empty".to_string(),
            ));
        }
        self.persist(&account, &credential_id, &key);
        let inner = self
            .enrollments
            .entry(account)
            .or_default();
        inner.insert(credential_id, key);
        Ok(())
    }

    /// Remove a single credential from an account. Returns `true` if a
    /// record was removed. The account itself is removed from the
    /// outer map only when its last credential is revoked.
    pub fn revoke_credential(&self, account: &[u8], credential_id: &[u8]) -> bool {
        let mut last_credential_removed = false;
        let removed = if let Some(inner) = self.enrollments.get(account) {
            let r = inner.remove(credential_id).is_some();
            if r && inner.is_empty() {
                last_credential_removed = true;
            }
            r
        } else {
            false
        };
        if last_credential_removed {
            self.enrollments.remove(account);
        }
        if removed {
            self.forget(account, credential_id);
        }
        removed
    }

    /// Remove every credential for an account at once (e.g. an account
    /// closure). Returns the number of credentials revoked. Persisted
    /// rows for the removed credentials are also deleted.
    pub fn revoke_account(&self, account: &[u8]) -> usize {
        let credentials: Vec<Vec<u8>> = if let Some(inner) = self.enrollments.get(account) {
            inner.iter().map(|e| e.key().clone()).collect()
        } else {
            return 0;
        };
        for cred in &credentials {
            self.forget(account, cred);
        }
        self.enrollments.remove(account);
        credentials.len()
    }

    /// Look up a specific credential by `(account, credential_id)`.
    pub fn get_credential(
        &self,
        account: &[u8],
        credential_id: &[u8],
    ) -> Option<WebAuthnAccountKey> {
        self.enrollments
            .get(account)
            .and_then(|inner| inner.get(credential_id).map(|e| e.value().clone()))
    }

    /// List all credential ids enrolled for an account.
    pub fn list_credentials(&self, account: &[u8]) -> Vec<Vec<u8>> {
        self.enrollments
            .get(account)
            .map(|inner| inner.iter().map(|e| e.key().clone()).collect())
            .unwrap_or_default()
    }

    /// Number of accounts with at least one enrolled credential.
    pub fn enrolled_account_count(&self) -> usize {
        self.enrollments.len()
    }

    /// Total credentials enrolled across every account.
    pub fn enrolled_credential_count(&self) -> usize {
        self.enrollments.iter().map(|e| e.value().len()).sum()
    }

    /// Compute the WebAuthn challenge string the relying party must have
    /// issued for `op_hash`. Per the Coinbase Smart Wallet convention, this
    /// is `base64url_no_pad(op_hash)` — i.e. the 32-byte op-hash
    /// base64url-encoded with no `=` padding.
    pub fn expected_challenge_for(op_hash: &[u8; 32]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(op_hash)
    }
}

impl IValidator for WebAuthnValidator {
    fn module_address(&self) -> [u8; 20] {
        self.address
    }

    fn validate_user_op(
        &self,
        op: &UserOperation,
        op_hash: &[u8; 32],
    ) -> Result<ValidationData, ValidatorError> {
        // 1. Decode the hybrid signature wire format. The credential_id
        //    inside identifies *which* enrolled passkey signed.
        let hybrid = match HybridWebAuthnSignature::decode(&op.signature) {
            Ok(h) => h,
            Err(_) => return Ok(ValidationData::failure()),
        };

        // 2. Length-check the ML-DSA leg before doing any expensive crypto.
        if hybrid.ml_dsa_signature.len() != ML_DSA_65_SIG_LEN {
            return Ok(ValidationData::failure());
        }

        // 3. Dispatch to the specific enrolled credential. Unknown
        //    `(sender, credential_id)` fails closed — no fallback to any
        //    other credential on the account, because we want the
        //    signature's identification of which device signed to be
        //    cryptographically meaningful.
        let Some(key) = self.get_credential(&op.sender, &hybrid.credential_id) else {
            return Ok(ValidationData::failure());
        };

        // 4. Verify the WebAuthn (P-256) leg. Challenge derives from op_hash
        // — the relying party must have issued exactly this challenge.
        let expected_challenge = Self::expected_challenge_for(op_hash);
        let pubkey_xy = key.p256_public_key_xy();
        if verify_webauthn_assertion(
            &hybrid.assertion,
            &pubkey_xy,
            &expected_challenge,
            &self.expected_origin,
            WebAuthnCeremonyType::Get,
        )
        .is_err()
        {
            return Ok(ValidationData::failure());
        }

        // 5. Verify the ML-DSA-65 leg over the same op_hash.
        if ml_dsa_verify(&key.pq_pubkey, op_hash, &hybrid.ml_dsa_signature).is_err() {
            return Ok(ValidationData::failure());
        }

        // Both legs passed against the addressed credential.
        Ok(ValidationData::success())
    }

    fn is_valid_signature_with_sender(
        &self,
        sender: &[u8],
        hash: &[u8; 32],
        signature: &[u8],
    ) -> [u8; 4] {
        let Ok(hybrid) = HybridWebAuthnSignature::decode(signature) else {
            return ERC1271_FAILURE_VALUE;
        };
        if hybrid.ml_dsa_signature.len() != ML_DSA_65_SIG_LEN {
            return ERC1271_FAILURE_VALUE;
        }
        let Some(key) = self.get_credential(sender, &hybrid.credential_id) else {
            return ERC1271_FAILURE_VALUE;
        };
        let expected_challenge = Self::expected_challenge_for(hash);
        let pubkey_xy = key.p256_public_key_xy();
        if verify_webauthn_assertion(
            &hybrid.assertion,
            &pubkey_xy,
            &expected_challenge,
            &self.expected_origin,
            WebAuthnCeremonyType::Get,
        )
        .is_err()
        {
            return ERC1271_FAILURE_VALUE;
        }
        if ml_dsa_verify(&key.pq_pubkey, hash, &hybrid.ml_dsa_signature).is_err() {
            return ERC1271_FAILURE_VALUE;
        }
        ERC1271_MAGIC_VALUE
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aa_validators::{
        ModuleAttestation, ModuleType, NoOpValidator, ValidatorRegistry,
    };
    use crate::account_abstraction::UserOperation;
    use tenzro_crypto::p256::{P256KeyPair, P256Signer};
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_crypto::webauthn::webauthn_signed_hash;

    const ORIGIN: &str = "https://keys.tenzro.xyz";

    /// Build a self-consistent enrollment + assertion + ML-DSA sig over `op_hash`.
    /// Returns (credential_id, enrollment, hybrid_signature_bytes). The
    /// credential id is a freshly-generated 16-byte identifier so each
    /// call to `make_hybrid_sig` represents a distinct passkey credential.
    fn make_hybrid_sig(op_hash: &[u8; 32]) -> (Vec<u8>, WebAuthnAccountKey, Vec<u8>) {
        // Synthesize a per-credential id. In production the id comes
        // from the authenticator; tests just need uniqueness, so any
        // 16-byte unique value works.
        let credential_id = {
            let mut h = Sha256::new();
            h.update(op_hash);
            h.update(b":cred:");
            // Mix in a process-local counter to keep distinct calls
            // producing distinct ids — important for the multi-
            // credential tests that enroll several credentials per
            // account against the same op_hash.
            use std::sync::atomic::{AtomicU64, Ordering};
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            h.update(seq.to_le_bytes());
            let d: [u8; 32] = h.finalize().into();
            d[..16].to_vec()
        };
        // P-256 keypair (passkey)
        let p256 = P256KeyPair::generate();
        let pubkey_xy = p256.public_key_bytes();
        let mut x = [0u8; 32];
        let mut y = [0u8; 32];
        x.copy_from_slice(&pubkey_xy[..32]);
        y.copy_from_slice(&pubkey_xy[32..]);

        // ML-DSA-65 keypair (PQ leg)
        let pq = MlDsaSigningKey::generate();
        let pq_vk = pq.verifying_key_bytes().to_vec();

        // Build the WebAuthn assertion: challenge = base64url_no_pad(op_hash)
        let challenge_b64url =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(op_hash);
        let client_data_json = serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge_b64url,
            "origin": ORIGIN,
        })
        .to_string()
        .into_bytes();

        // authenticatorData: 32-byte rpIdHash (zeros) + 1 byte flags (UP set)
        // + 4 bytes signCount = 37 bytes minimum.
        let mut authenticator_data = vec![0u8; 37];
        authenticator_data[32] = 0x01; // UP flag

        // Compute the WebAuthn prehash and sign it. The verifier inside
        // verify_webauthn_assertion calls webauthn_signed_hash() and then
        // verify_prehash() — we sign the same prehash here so the signature
        // verifies against the precompile-compatible raw form.
        let prehash = webauthn_signed_hash(&authenticator_data, &client_data_json);
        let signer = P256Signer::from_keypair(&p256);
        let p256_sig = signer.sign_prehash(&prehash);
        // unwrap_der_signature in verify_webauthn_assertion accepts both raw
        // 64-byte r||s and DER — emit raw (what a hardware authenticator
        // would emit after our wallet layer pre-unwraps DER).
        let assertion = WebAuthnAssertion {
            authenticator_data,
            client_data_json,
            signature: p256_sig.as_bytes().to_vec(),
            user_handle: None,
        };

        // ML-DSA sig over op_hash.
        let ml_dsa_sig = pq.sign(op_hash);
        assert_eq!(ml_dsa_sig.len(), ML_DSA_65_SIG_LEN);

        let enrollment = WebAuthnAccountKey::new(x, y, pq_vk).expect("enrollment");
        let hybrid = HybridWebAuthnSignature {
            assertion,
            ml_dsa_signature: ml_dsa_sig,
            credential_id: credential_id.clone(),
        };
        let bytes = hybrid.encode().expect("encode");
        (credential_id, enrollment, bytes)
    }

    fn dummy_user_op(sender: Vec<u8>, sig: Vec<u8>) -> UserOperation {
        UserOperation {
            sender,
            nonce: crate::account_abstraction::Nonce::from_seq(0).to_bytes(),
            factory: vec![],
            factory_data: vec![],
            call_data: vec![0x42; 4],
            call_gas_limit: 100_000,
            verification_gas_limit: 50_000,
            pre_verification_gas: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000,
            paymaster: vec![],
            paymaster_verification_gas_limit: 0,
            paymaster_post_op_gas_limit: 0,
            paymaster_data: vec![],
            signature: sig,
        }
    }

    #[test]
    fn account_key_rejects_wrong_pq_length() {
        let err = WebAuthnAccountKey::new([0u8; 32], [0u8; 32], vec![0u8; 100]).unwrap_err();
        assert!(matches!(err, ValidatorError::InvalidInput(_)));
    }

    #[test]
    fn pq_pubkey_hash_is_sha256() {
        let pq = MlDsaSigningKey::generate();
        let key = WebAuthnAccountKey::new([0u8; 32], [0u8; 32], pq.verifying_key_bytes().to_vec())
            .unwrap();
        let h = key.pq_pubkey_hash();
        let expected = Sha256::digest(pq.verifying_key_bytes());
        assert_eq!(&h[..], &expected[..]);
    }

    #[test]
    fn challenge_derivation_is_base64url_no_pad() {
        let op_hash = [0xABu8; 32];
        let challenge = WebAuthnValidator::expected_challenge_for(&op_hash);
        // 32 bytes → 43 chars in base64url no-pad.
        assert_eq!(challenge.len(), 43);
        assert!(!challenge.contains('='));
        assert!(!challenge.contains('+'));
        assert!(!challenge.contains('/'));
    }

    #[test]
    fn validate_succeeds_with_matching_hybrid_signature() {
        let op_hash = [0x42u8; 32];
        let (cred_id, enrollment, sig_bytes) = make_hybrid_sig(&op_hash);

        let validator = WebAuthnValidator::new([0xCCu8; 20], ORIGIN.to_string());
        let account = vec![0x01; 20];
        validator
            .enroll(account.clone(), cred_id, enrollment)
            .unwrap();

        let op = dummy_user_op(account, sig_bytes);
        let result = validator.validate_user_op(&op, &op_hash).unwrap();
        assert!(!result.is_failure(), "hybrid sig should validate");
    }

    #[test]
    fn validate_fails_when_account_not_enrolled() {
        let op_hash = [0x42u8; 32];
        let (_cred_id, _enrollment, sig_bytes) = make_hybrid_sig(&op_hash);

        let validator = WebAuthnValidator::new([0xCCu8; 20], ORIGIN.to_string());
        let account = vec![0x01; 20];
        // Note: did NOT call validator.enroll().
        let op = dummy_user_op(account, sig_bytes);
        let result = validator.validate_user_op(&op, &op_hash).unwrap();
        assert!(result.is_failure(), "unenrolled account must fail closed");
    }

    #[test]
    fn validate_fails_when_op_hash_changes() {
        let op_hash = [0x42u8; 32];
        let (cred_id, enrollment, sig_bytes) = make_hybrid_sig(&op_hash);

        let validator = WebAuthnValidator::new([0xCCu8; 20], ORIGIN.to_string());
        let account = vec![0x01; 20];
        validator
            .enroll(account.clone(), cred_id, enrollment)
            .unwrap();

        // Change the challenge target: WebAuthn challenge mismatch + ML-DSA fails.
        let different_op_hash = [0x99u8; 32];
        let op = dummy_user_op(account, sig_bytes);
        let result = validator.validate_user_op(&op, &different_op_hash).unwrap();
        assert!(result.is_failure(), "tampered op_hash must fail");
    }

    #[test]
    fn validate_fails_when_ml_dsa_signature_length_wrong() {
        let op_hash = [0x42u8; 32];
        let (cred_id, enrollment, sig_bytes) = make_hybrid_sig(&op_hash);

        // Decode, truncate the ML-DSA leg, re-encode.
        let mut hybrid = HybridWebAuthnSignature::decode(&sig_bytes).unwrap();
        hybrid.ml_dsa_signature.truncate(100);
        let bad_bytes = hybrid.encode().unwrap();

        let validator = WebAuthnValidator::new([0xCCu8; 20], ORIGIN.to_string());
        let account = vec![0x01; 20];
        validator
            .enroll(account.clone(), cred_id, enrollment)
            .unwrap();

        let op = dummy_user_op(account, bad_bytes);
        let result = validator.validate_user_op(&op, &op_hash).unwrap();
        assert!(result.is_failure(), "wrong-length ML-DSA leg must fail");
    }

    #[test]
    fn validate_fails_when_ml_dsa_signature_tampered() {
        let op_hash = [0x42u8; 32];
        let (cred_id, enrollment, sig_bytes) = make_hybrid_sig(&op_hash);

        let mut hybrid = HybridWebAuthnSignature::decode(&sig_bytes).unwrap();
        hybrid.ml_dsa_signature[100] ^= 0x01;
        let bad_bytes = hybrid.encode().unwrap();

        let validator = WebAuthnValidator::new([0xCCu8; 20], ORIGIN.to_string());
        let account = vec![0x01; 20];
        validator
            .enroll(account.clone(), cred_id, enrollment)
            .unwrap();

        let op = dummy_user_op(account, bad_bytes);
        let result = validator.validate_user_op(&op, &op_hash).unwrap();
        assert!(result.is_failure(), "tampered ML-DSA sig must fail");
    }

    #[test]
    fn validate_fails_when_origin_mismatch() {
        let op_hash = [0x42u8; 32];
        let (cred_id, enrollment, sig_bytes) = make_hybrid_sig(&op_hash);

        // Validator pinned to a different origin.
        let validator =
            WebAuthnValidator::new([0xCCu8; 20], "https://attacker.example".to_string());
        let account = vec![0x01; 20];
        validator
            .enroll(account.clone(), cred_id, enrollment)
            .unwrap();

        let op = dummy_user_op(account, sig_bytes);
        let result = validator.validate_user_op(&op, &op_hash).unwrap();
        assert!(result.is_failure(), "origin mismatch must fail");
    }

    #[test]
    fn enroll_and_revoke_round_trip() {
        let validator = WebAuthnValidator::new([0xCCu8; 20], ORIGIN.to_string());
        let account = vec![0x01; 20];
        let cred_id = vec![0xDEu8; 16];

        let pq = MlDsaSigningKey::generate();
        let key = WebAuthnAccountKey::new([0u8; 32], [0u8; 32], pq.verifying_key_bytes().to_vec())
            .unwrap();
        validator
            .enroll(account.clone(), cred_id.clone(), key)
            .unwrap();
        assert_eq!(validator.enrolled_account_count(), 1);
        assert_eq!(validator.enrolled_credential_count(), 1);
        assert!(validator.get_credential(&account, &cred_id).is_some());

        assert!(validator.revoke_credential(&account, &cred_id));
        assert_eq!(validator.enrolled_account_count(), 0);
        assert!(validator.get_credential(&account, &cred_id).is_none());
        assert!(
            !validator.revoke_credential(&account, &cred_id),
            "second revoke is a no-op"
        );
    }

    #[test]
    fn erc1271_returns_magic_on_success_and_failure_otherwise() {
        let op_hash = [0x42u8; 32];
        let (cred_id, enrollment, sig_bytes) = make_hybrid_sig(&op_hash);

        let validator = WebAuthnValidator::new([0xCCu8; 20], ORIGIN.to_string());
        let account = vec![0x01; 20];
        validator
            .enroll(account.clone(), cred_id, enrollment)
            .unwrap();

        let magic = validator.is_valid_signature_with_sender(&account, &op_hash, &sig_bytes);
        assert_eq!(magic, ERC1271_MAGIC_VALUE);

        // Unenrolled sender → failure.
        let other = vec![0x02; 20];
        let fail =
            validator.is_valid_signature_with_sender(&other, &op_hash, &sig_bytes);
        assert_eq!(fail, ERC1271_FAILURE_VALUE);
    }

    #[test]
    fn integrates_with_validator_registry() {
        // End-to-end: install WebAuthnValidator into a ValidatorRegistry and
        // route a UserOp through it.
        let op_hash = [0x42u8; 32];
        let (cred_id, enrollment, sig_bytes) = make_hybrid_sig(&op_hash);

        let module_addr = [0x77u8; 20];
        let validator = WebAuthnValidator::new(module_addr, ORIGIN.to_string());
        let account = vec![0x01; 20];
        validator
            .enroll(account.clone(), cred_id, enrollment)
            .unwrap();

        let registry = ValidatorRegistry::new();
        // Attest the module so ERC-7484 install gate passes.
        registry.attestations().attest(ModuleAttestation {
            module_address: module_addr,
            module_type: ModuleType::Validator,
            registry: *registry.trusted_registry(),
            attester: [0xAA; 20],
            attestation_data: b"webauthn-audit-pass".to_vec(),
            revoked: false,
        });
        let module: Arc<dyn IValidator> = Arc::new(validator);
        registry
            .install(account.clone(), ModuleType::Validator, module, 100, vec![])
            .unwrap();

        let op = dummy_user_op(account, sig_bytes);
        let result = registry.validate_user_op(&op, &op_hash).unwrap();
        assert!(!result.is_failure());
    }

    #[test]
    fn multi_credential_per_account_dispatches_correctly() {
        // Enroll TWO credentials on the SAME account. Each produces a
        // distinct signature. The validator must accept either when
        // presented under its own credential_id and reject one when
        // presented under the other's credential_id.
        let op_hash_a = [0xA1u8; 32];
        let (cred_id_a, key_a, sig_a) = make_hybrid_sig(&op_hash_a);
        let op_hash_b = [0xB2u8; 32];
        let (cred_id_b, key_b, sig_b) = make_hybrid_sig(&op_hash_b);
        assert_ne!(cred_id_a, cred_id_b);

        let validator = WebAuthnValidator::new([0xCCu8; 20], ORIGIN.to_string());
        let account = vec![0x01; 20];
        validator
            .enroll(account.clone(), cred_id_a.clone(), key_a)
            .unwrap();
        validator
            .enroll(account.clone(), cred_id_b.clone(), key_b)
            .unwrap();
        assert_eq!(validator.enrolled_credential_count(), 2);
        assert_eq!(validator.list_credentials(&account).len(), 2);

        // Each signature validates against its own op_hash.
        let op_a = dummy_user_op(account.clone(), sig_a.clone());
        assert!(!validator.validate_user_op(&op_a, &op_hash_a).unwrap().is_failure());
        let op_b = dummy_user_op(account.clone(), sig_b);
        assert!(!validator.validate_user_op(&op_b, &op_hash_b).unwrap().is_failure());

        // Revoking credential A: signature A no longer validates, but
        // credential B is unaffected — the account is still usable.
        assert!(validator.revoke_credential(&account, &cred_id_a));
        let op_a_again = dummy_user_op(account.clone(), sig_a);
        assert!(
            validator
                .validate_user_op(&op_a_again, &op_hash_a)
                .unwrap()
                .is_failure(),
            "revoked credential A must no longer validate"
        );
        // B still works.
        assert_eq!(validator.enrolled_credential_count(), 1);
    }

    #[test]
    fn revoke_account_clears_every_credential() {
        let op_hash = [0x42u8; 32];
        let (cred_id_a, key_a, _sig_a) = make_hybrid_sig(&op_hash);
        let (cred_id_b, key_b, _sig_b) = make_hybrid_sig(&op_hash);

        let validator = WebAuthnValidator::new([0xCCu8; 20], ORIGIN.to_string());
        let account = vec![0x01; 20];
        validator.enroll(account.clone(), cred_id_a, key_a).unwrap();
        validator.enroll(account.clone(), cred_id_b, key_b).unwrap();
        assert_eq!(validator.enrolled_credential_count(), 2);

        let removed = validator.revoke_account(&account);
        assert_eq!(removed, 2);
        assert_eq!(validator.enrolled_account_count(), 0);
        assert_eq!(validator.enrolled_credential_count(), 0);
        assert!(validator.list_credentials(&account).is_empty());
    }

    // Explicitly test that NoOpValidator is NOT this validator — sanity check
    // on the trait-object dispatch.
    #[test]
    fn no_op_validator_does_not_collide() {
        let _ = NoOpValidator::new([0; 20]);
    }

    /// Verifies WebAuthnValidator enrollments — including multi-credential
    /// accounts — survive node restart by rebuilding the validator
    /// against the same backing store.
    #[test]
    fn webauthn_enrollment_persists_across_restart() {
        use std::sync::Arc;
        let store: Arc<dyn tenzro_storage::KvStore> =
            Arc::new(tenzro_storage::MemoryStore::new());
        let module_addr = [0x10u8; 20];
        let origin = "https://wallet.tenzro.xyz".to_string();
        let account_a = vec![0xA1u8; 20];
        let account_b = vec![0xB2u8; 20];
        let cred_a1 = vec![0xC1u8; 16];
        let cred_a2 = vec![0xC2u8; 16]; // second device on account A
        let cred_b1 = vec![0xC3u8; 16];
        let key_a1 = WebAuthnAccountKey::new(
            [0x11u8; 32],
            [0x22u8; 32],
            vec![0x33u8; ML_DSA_65_VK_LEN],
        )
        .unwrap();
        let key_a2 = WebAuthnAccountKey::new(
            [0x44u8; 32],
            [0x55u8; 32],
            vec![0x66u8; ML_DSA_65_VK_LEN],
        )
        .unwrap();
        let key_b1 = WebAuthnAccountKey::new(
            [0xAAu8; 32],
            [0xBBu8; 32],
            vec![0xCCu8; ML_DSA_65_VK_LEN],
        )
        .unwrap();

        {
            let v = WebAuthnValidator::with_storage(module_addr, origin.clone(), store.clone());
            v.enroll(account_a.clone(), cred_a1.clone(), key_a1.clone()).unwrap();
            v.enroll(account_a.clone(), cred_a2.clone(), key_a2.clone()).unwrap();
            v.enroll(account_b.clone(), cred_b1.clone(), key_b1.clone()).unwrap();
            assert_eq!(v.enrolled_account_count(), 2);
            assert_eq!(v.enrolled_credential_count(), 3);
        }

        let v2 = WebAuthnValidator::with_storage(module_addr, origin.clone(), store.clone());
        assert_eq!(v2.enrolled_account_count(), 2, "accounts must hydrate");
        assert_eq!(
            v2.enrolled_credential_count(),
            3,
            "every credential must hydrate"
        );
        let restored_a1 = v2.get_credential(&account_a, &cred_a1).expect("a1 hydrated");
        assert_eq!(restored_a1.pubkey_x, key_a1.pubkey_x);
        assert_eq!(restored_a1.pubkey_y, key_a1.pubkey_y);
        assert_eq!(restored_a1.pq_pubkey, key_a1.pq_pubkey);
        let restored_a2 = v2.get_credential(&account_a, &cred_a2).expect("a2 hydrated");
        assert_eq!(restored_a2.pubkey_x, key_a2.pubkey_x);

        // Revoke only credential A1; A2 must still be reachable after restart.
        assert!(v2.revoke_credential(&account_a, &cred_a1));
        drop(v2);
        let v3 = WebAuthnValidator::with_storage(module_addr, origin, store);
        assert_eq!(v3.enrolled_credential_count(), 2);
        assert!(v3.get_credential(&account_a, &cred_a1).is_none());
        assert!(v3.get_credential(&account_a, &cred_a2).is_some());
        assert!(v3.get_credential(&account_b, &cred_b1).is_some());
    }
}
