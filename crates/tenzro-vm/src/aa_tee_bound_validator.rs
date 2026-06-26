//! TEE-bound validator (ERC-7579 module) for autonomous-agent custody.
//!
//! # Threat model
//!
//! Autonomous machine identities (`did:tenzro:machine:{uuid}`) act without a
//! human in the loop. Their signing key cannot live on a phone (no biometric
//! gate) and cannot live on a server in plaintext (single-host compromise =
//! drained agent). The accepted answer is to seal the key inside a remote
//! attestable enclave (Intel TDX, AMD SEV-SNP, AWS Nitro, NVIDIA H100/H200/
//! Blackwell CC) and require every signed `UserOperation` to be accompanied by
//! a fresh attestation that:
//!
//! 1. comes from the **same enclave class** the account was enrolled with
//!    (vendor + measurement match),
//! 2. proves the enclave saw **this specific** `op_hash` (binding via the
//!    attestation report's `user_data` slot — prevents replay across ops),
//! 3. is **fresh** (within `max_age_secs` — prevents replay across windows),
//!    and
//! 4. is **cryptographically signed** by the enclave's enrolled key.
//!
//! Composing this with [`crate::aa_delegation_validator::DelegationScopeValidator`]
//! at install time yields the autonomous-agent profile from `SPECIFICATION.md`:
//! the enclave is the only signer, the scope is the only spending policy, and
//! the validator is the **single point of enforcement** seen by the EntryPoint.
//!
//! # Wire format
//!
//! `op.signature` is bincode (1.x) of [`EnclaveSignedOp`]:
//!
//! ```text
//! struct EnclaveSignedOp {
//!     attestation_report: AttestationReport,
//!     enclave_signature: Vec<u8>,   // Ed25519 over op_hash
//! }
//! ```
//!
//! # Why not async
//!
//! [`tenzro_tee::AttestationVerifier::verify_report`] is **synchronous** — it
//! does not call out to the network. NVIDIA's NRAS path is the only vendor
//! that needs HTTP, and that crate caches the result before producing the
//! report. So this validator can implement [`crate::aa_validators::IValidator`]
//! (a sync trait) without any runtime gymnastics.

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use tenzro_crypto::keys::{KeyType, PublicKey};
use tenzro_crypto::signatures::{self, Signature as CryptoSignature};
use tenzro_tee::AttestationVerifier;
use tenzro_types::tee::{AttestationReport, TeeVendor};

use crate::aa_validators::{
    ERC1271_FAILURE_VALUE, ERC1271_MAGIC_VALUE, IValidator, ValidationData, ValidatorError,
};
use crate::account_abstraction::UserOperation;

/// Default maximum attestation report age, in seconds.
///
/// 5 minutes is long enough to absorb network jitter and bundler queueing,
/// short enough that a stolen quote cannot be reused across many windows.
pub const DEFAULT_MAX_ATTESTATION_AGE_SECS: u64 = 300;

/// Per-account enrollment binding: which enclave class + which signing key the
/// account trusts.
///
/// `measurement_hash` is `SHA-256(report.measurement)` — we hash here to
/// normalize across vendor measurement sizes (TDX RTMR is 48 B, SEV-SNP
/// measurement is 48 B, Nitro PCR0 is 48 B). Storing the hash also means
/// account state is fixed-size regardless of vendor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TeeBoundAccountKey {
    /// Required attestation vendor (e.g. `IntelTdx`, `AmdSevSnp`, `AwsNitro`).
    pub vendor: TeeVendor,
    /// `SHA-256(measurement)` of the enrolled enclave image.
    pub measurement_hash: [u8; 32],
    /// Ed25519 public key the enclave uses to sign each `op_hash`.
    pub enclave_pubkey: [u8; 32],
}

impl TeeBoundAccountKey {
    pub fn new(vendor: TeeVendor, measurement: &[u8], enclave_pubkey: [u8; 32]) -> Self {
        Self {
            vendor,
            measurement_hash: sha256(measurement),
            enclave_pubkey,
        }
    }
}

/// What the enclave actually puts in the `UserOperation.signature` field.
///
/// `attestation_report.user_data` MUST equal the 32-byte `op_hash` —
/// this is how we prevent a quote captured for one op from being replayed
/// against another op produced inside the same enclave.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnclaveSignedOp {
    /// Fresh attestation produced inside the enclave for this UserOp.
    pub attestation_report: AttestationReport,
    /// Ed25519 signature over `op_hash` produced by the enrolled enclave key.
    pub enclave_signature: Vec<u8>,
}

impl EnclaveSignedOp {
    pub fn encode(&self) -> Result<Vec<u8>, ValidatorError> {
        bincode::serialize(self)
            .map_err(|e| ValidatorError::InvalidInput(format!("bincode encode: {}", e)))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ValidatorError> {
        bincode::deserialize::<Self>(bytes)
            .map_err(|e| ValidatorError::InvalidInput(format!("bincode decode: {}", e)))
    }
}

/// Resolves the enrolled `TeeBoundAccountKey` for a given account.
///
/// Implemented at the node layer so the on-disk source of truth can be
/// RocksDB / the AA registry / etc. without dragging tenzro-storage into
/// tenzro-vm.
pub trait TeeKeyOracle: Send + Sync {
    fn lookup(&self, account: &[u8]) -> Option<TeeBoundAccountKey>;
}

/// In-memory `TeeKeyOracle` for tests + bootstrap.
pub struct InMemoryTeeKeyOracle {
    keys: DashMap<Vec<u8>, TeeBoundAccountKey>,
}

impl InMemoryTeeKeyOracle {
    pub fn new() -> Self {
        Self {
            keys: DashMap::new(),
        }
    }

    pub fn enroll(&self, account: Vec<u8>, key: TeeBoundAccountKey) {
        self.keys.insert(account, key);
    }

    pub fn revoke(&self, account: &[u8]) {
        self.keys.remove(account);
    }
}

impl Default for InMemoryTeeKeyOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl TeeKeyOracle for InMemoryTeeKeyOracle {
    fn lookup(&self, account: &[u8]) -> Option<TeeBoundAccountKey> {
        self.keys.get(account).map(|v| v.clone())
    }
}

/// ERC-7579 validator that gates a `UserOperation` on a fresh, key-bound TEE
/// attestation.
pub struct TeeBoundValidator {
    address: [u8; 20],
    oracle: Arc<dyn TeeKeyOracle>,
    verifier: Arc<AttestationVerifier>,
    max_age_secs: u64,
}

impl TeeBoundValidator {
    /// Construct a validator with the default `300s` max attestation age.
    pub fn new(
        address: [u8; 20],
        oracle: Arc<dyn TeeKeyOracle>,
        verifier: Arc<AttestationVerifier>,
    ) -> Self {
        Self {
            address,
            oracle,
            verifier,
            max_age_secs: DEFAULT_MAX_ATTESTATION_AGE_SECS,
        }
    }

    /// Override the maximum allowed attestation report age (seconds).
    pub fn with_max_age_secs(mut self, secs: u64) -> Self {
        self.max_age_secs = secs;
        self
    }
}

impl IValidator for TeeBoundValidator {
    fn module_address(&self) -> [u8; 20] {
        self.address
    }

    fn validate_user_op(
        &self,
        op: &UserOperation,
        op_hash: &[u8; 32],
    ) -> Result<ValidationData, ValidatorError> {
        // 1. Enrollment must exist for this account.
        let enrollment = match self.oracle.lookup(op.sender.as_slice()) {
            Some(e) => e,
            None => return Ok(ValidationData::failure()),
        };

        // 2. Decode the signature envelope.
        let envelope = match EnclaveSignedOp::decode(&op.signature) {
            Ok(e) => e,
            Err(_) => return Ok(ValidationData::failure()),
        };
        let report = &envelope.attestation_report;

        // 3. Vendor must match enrolled vendor.
        if report.vendor != enrollment.vendor {
            return Ok(ValidationData::failure());
        }

        // 4. Measurement hash must match enrolled measurement hash.
        if sha256(&report.measurement) != enrollment.measurement_hash {
            return Ok(ValidationData::failure());
        }

        // 5. Report must be bound to *this* op_hash via user_data.
        if report.user_data.as_slice() != op_hash.as_slice() {
            return Ok(ValidationData::failure());
        }

        // 6. Report must be fresh.
        let now_ms = chrono::Utc::now().timestamp_millis();
        let report_ms = report.timestamp.as_millis();
        let age_ms = now_ms.saturating_sub(report_ms);
        if age_ms < 0 || (age_ms as u64) > self.max_age_secs * 1_000 {
            return Ok(ValidationData::failure());
        }

        // 7. Attestation must verify against the pinned vendor root CA chain.
        match self.verifier.verify_report(report) {
            Ok(result) if result.valid => {}
            _ => return Ok(ValidationData::failure()),
        }

        // 8. The op_hash must be signed by the enrolled enclave Ed25519 key.
        let pubkey = PublicKey::new(KeyType::Ed25519, enrollment.enclave_pubkey.to_vec());
        let sig = CryptoSignature::new(KeyType::Ed25519, envelope.enclave_signature.clone());
        if signatures::verify(&pubkey, op_hash, &sig).is_err() {
            return Ok(ValidationData::failure());
        }

        Ok(ValidationData::success())
    }

    fn is_valid_signature_with_sender(
        &self,
        sender: &[u8],
        hash: &[u8; 32],
        signature: &[u8],
    ) -> [u8; 4] {
        let enrollment = match self.oracle.lookup(sender) {
            Some(e) => e,
            None => return ERC1271_FAILURE_VALUE,
        };

        let envelope = match EnclaveSignedOp::decode(signature) {
            Ok(e) => e,
            Err(_) => return ERC1271_FAILURE_VALUE,
        };
        let report = &envelope.attestation_report;

        if report.vendor != enrollment.vendor {
            return ERC1271_FAILURE_VALUE;
        }
        if sha256(&report.measurement) != enrollment.measurement_hash {
            return ERC1271_FAILURE_VALUE;
        }
        if report.user_data.as_slice() != hash.as_slice() {
            return ERC1271_FAILURE_VALUE;
        }

        let now_ms = chrono::Utc::now().timestamp_millis();
        let age_ms = now_ms.saturating_sub(report.timestamp.as_millis());
        if age_ms < 0 || (age_ms as u64) > self.max_age_secs * 1_000 {
            return ERC1271_FAILURE_VALUE;
        }

        match self.verifier.verify_report(report) {
            Ok(result) if result.valid => {}
            _ => return ERC1271_FAILURE_VALUE,
        }

        let pubkey = PublicKey::new(KeyType::Ed25519, enrollment.enclave_pubkey.to_vec());
        let sig = CryptoSignature::new(KeyType::Ed25519, envelope.enclave_signature.clone());
        if signatures::verify(&pubkey, hash, &sig).is_err() {
            return ERC1271_FAILURE_VALUE;
        }

        ERC1271_MAGIC_VALUE
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
    use tenzro_types::Timestamp;

    use crate::account_abstraction::UserOperation;

    /// Makes a simulated AmdSevSnp report. The simulator metadata flag tells
    /// `AttestationVerifier` to accept the dummy cert chain — exactly the
    /// path that runs on a developer machine.
    fn make_simulated_report(
        vendor: TeeVendor,
        measurement: Vec<u8>,
        user_data: Vec<u8>,
        timestamp: Timestamp,
    ) -> AttestationReport {
        let attestation_data = match vendor {
            TeeVendor::AmdSevSnp => serde_json::to_vec(&serde_json::json!({
                "reported_tcb": {"boot_loader": 3, "tee": 0, "snp": 12},
                "measurement": hex::encode(&measurement),
            }))
            .unwrap(),
            TeeVendor::IntelTdx => serde_json::to_vec(&serde_json::json!({
                "tdx_tcb_svn": "03000600000000000000000000000000",
            }))
            .unwrap(),
            _ => vec![0xAB; 32],
        };

        let mut metadata = HashMap::new();
        metadata.insert("simulated".to_string(), "true".to_string());

        AttestationReport {
            id: Default::default(),
            vendor,
            user_data,
            attestation_data,
            certificates: vec![],
            timestamp,
            metadata,
            quote: vec![0x01; 32],
            measurement,
            signature: vec![],
            vendor_data: vec![],
        }
    }

    fn make_user_op(sender: Vec<u8>, signature: Vec<u8>) -> UserOperation {
        UserOperation {
            sender,
            nonce: tenzro_vm::account_abstraction::Nonce::from_seq(0).to_bytes(),
            factory: vec![],
            factory_data: vec![],
            call_data: vec![],
            call_gas_limit: 100_000,
            verification_gas_limit: 100_000,
            pre_verification_gas: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            paymaster: vec![],
            paymaster_verification_gas_limit: 0,
            paymaster_post_op_gas_limit: 0,
            paymaster_data: vec![],
            signature,
        }
    }

    /// Lenient verifier — accepts simulated reports.
    fn lenient_verifier() -> Arc<AttestationVerifier> {
        let mut v = AttestationVerifier::new();
        v.set_strict_cert_validation(false);
        Arc::new(v)
    }

    fn enrolled_account(
        sender: Vec<u8>,
        vendor: TeeVendor,
        measurement: &[u8],
    ) -> (
        InMemoryTeeKeyOracle,
        Ed25519SignerImpl,
        TeeBoundAccountKey,
    ) {
        let signer = Ed25519SignerImpl::generate().unwrap();
        let pk_bytes: [u8; 32] = signer.public_key().as_bytes().try_into().unwrap();
        let key = TeeBoundAccountKey::new(vendor, measurement, pk_bytes);

        let oracle = InMemoryTeeKeyOracle::new();
        oracle.enroll(sender, key.clone());
        (oracle, signer, key)
    }

    fn make_envelope(
        vendor: TeeVendor,
        measurement: Vec<u8>,
        op_hash: &[u8; 32],
        signer: &Ed25519SignerImpl,
        timestamp: Timestamp,
    ) -> EnclaveSignedOp {
        let report = make_simulated_report(vendor, measurement, op_hash.to_vec(), timestamp);
        let sig = signer.sign(op_hash).unwrap();
        EnclaveSignedOp {
            attestation_report: report,
            enclave_signature: sig.as_bytes().to_vec(),
        }
    }

    #[test]
    fn validates_well_formed_op() {
        let sender = vec![0x11; 20];
        let measurement = vec![0xAA; 48];
        let (oracle, signer, _) =
            enrolled_account(sender.clone(), TeeVendor::AmdSevSnp, &measurement);

        let validator = TeeBoundValidator::new(
            [0x42; 20],
            Arc::new(oracle),
            lenient_verifier(),
        );

        let op_hash = [0xCD; 32];
        let envelope = make_envelope(
            TeeVendor::AmdSevSnp,
            measurement,
            &op_hash,
            &signer,
            Timestamp::now(),
        );
        let op = make_user_op(sender, envelope.encode().unwrap());

        let result = validator.validate_user_op(&op, &op_hash).unwrap();
        assert!(!result.is_failure(), "well-formed op should validate");
    }

    #[test]
    fn rejects_unenrolled_account() {
        let oracle = InMemoryTeeKeyOracle::new();
        let validator = TeeBoundValidator::new([0x42; 20], Arc::new(oracle), lenient_verifier());

        let op = make_user_op(vec![0x11; 20], vec![0u8; 32]);
        let result = validator.validate_user_op(&op, &[0u8; 32]).unwrap();
        assert!(result.is_failure());
    }

    #[test]
    fn rejects_malformed_signature_envelope() {
        let sender = vec![0x11; 20];
        let measurement = vec![0xAA; 48];
        let (oracle, _, _) =
            enrolled_account(sender.clone(), TeeVendor::AmdSevSnp, &measurement);

        let validator = TeeBoundValidator::new(
            [0x42; 20],
            Arc::new(oracle),
            lenient_verifier(),
        );

        let op = make_user_op(sender, vec![0xFF; 5]); // not bincode
        let result = validator.validate_user_op(&op, &[0u8; 32]).unwrap();
        assert!(result.is_failure());
    }

    #[test]
    fn rejects_vendor_mismatch() {
        let sender = vec![0x11; 20];
        let measurement = vec![0xAA; 48];
        let (oracle, signer, _) =
            enrolled_account(sender.clone(), TeeVendor::AmdSevSnp, &measurement);

        let validator = TeeBoundValidator::new(
            [0x42; 20],
            Arc::new(oracle),
            lenient_verifier(),
        );

        let op_hash = [0xCD; 32];
        // Envelope vendor = IntelTdx, enrollment vendor = AmdSevSnp.
        let envelope = make_envelope(
            TeeVendor::IntelTdx,
            measurement,
            &op_hash,
            &signer,
            Timestamp::now(),
        );
        let op = make_user_op(sender, envelope.encode().unwrap());

        let result = validator.validate_user_op(&op, &op_hash).unwrap();
        assert!(result.is_failure());
    }

    #[test]
    fn rejects_measurement_mismatch() {
        let sender = vec![0x11; 20];
        let enrolled_measurement = vec![0xAA; 48];
        let (oracle, signer, _) =
            enrolled_account(sender.clone(), TeeVendor::AmdSevSnp, &enrolled_measurement);

        let validator = TeeBoundValidator::new(
            [0x42; 20],
            Arc::new(oracle),
            lenient_verifier(),
        );

        let op_hash = [0xCD; 32];
        let other_measurement = vec![0xBB; 48];
        let envelope = make_envelope(
            TeeVendor::AmdSevSnp,
            other_measurement,
            &op_hash,
            &signer,
            Timestamp::now(),
        );
        let op = make_user_op(sender, envelope.encode().unwrap());

        let result = validator.validate_user_op(&op, &op_hash).unwrap();
        assert!(result.is_failure());
    }

    #[test]
    fn rejects_user_data_not_bound_to_op_hash() {
        let sender = vec![0x11; 20];
        let measurement = vec![0xAA; 48];
        let (oracle, signer, _) =
            enrolled_account(sender.clone(), TeeVendor::AmdSevSnp, &measurement);

        let validator = TeeBoundValidator::new(
            [0x42; 20],
            Arc::new(oracle),
            lenient_verifier(),
        );

        let real_op_hash = [0xCD; 32];
        let stale_op_hash = [0xEF; 32]; // attestation captured for a different op
        let envelope = make_envelope(
            TeeVendor::AmdSevSnp,
            measurement,
            &stale_op_hash,
            &signer,
            Timestamp::now(),
        );
        let op = make_user_op(sender, envelope.encode().unwrap());

        let result = validator.validate_user_op(&op, &real_op_hash).unwrap();
        assert!(result.is_failure(), "stale-quote replay must be rejected");
    }

    #[test]
    fn rejects_expired_attestation() {
        let sender = vec![0x11; 20];
        let measurement = vec![0xAA; 48];
        let (oracle, signer, _) =
            enrolled_account(sender.clone(), TeeVendor::AmdSevSnp, &measurement);

        let validator = TeeBoundValidator::new(
            [0x42; 20],
            Arc::new(oracle),
            lenient_verifier(),
        )
        .with_max_age_secs(60);

        let op_hash = [0xCD; 32];
        // Report is 10 minutes old.
        let stale_ts = Timestamp::new(Timestamp::now().as_millis() - 600_000);
        let envelope = make_envelope(
            TeeVendor::AmdSevSnp,
            measurement,
            &op_hash,
            &signer,
            stale_ts,
        );
        let op = make_user_op(sender, envelope.encode().unwrap());

        let result = validator.validate_user_op(&op, &op_hash).unwrap();
        assert!(result.is_failure());
    }

    #[test]
    fn rejects_wrong_enclave_signature() {
        let sender = vec![0x11; 20];
        let measurement = vec![0xAA; 48];
        let (oracle, _enrolled_signer, _) =
            enrolled_account(sender.clone(), TeeVendor::AmdSevSnp, &measurement);

        let validator = TeeBoundValidator::new(
            [0x42; 20],
            Arc::new(oracle),
            lenient_verifier(),
        );

        let op_hash = [0xCD; 32];
        // Build the envelope with a *different* signer (attacker key).
        let attacker = Ed25519SignerImpl::generate().unwrap();
        let envelope = make_envelope(
            TeeVendor::AmdSevSnp,
            measurement,
            &op_hash,
            &attacker,
            Timestamp::now(),
        );
        let op = make_user_op(sender, envelope.encode().unwrap());

        let result = validator.validate_user_op(&op, &op_hash).unwrap();
        assert!(result.is_failure());
    }

    #[test]
    fn rejects_attestation_when_verifier_rejects() {
        // Strict-mode verifier with an empty cert chain → rejects.
        let strict = Arc::new(AttestationVerifier::new());

        let sender = vec![0x11; 20];
        let measurement = vec![0xAA; 48];
        let (oracle, signer, _) =
            enrolled_account(sender.clone(), TeeVendor::AmdSevSnp, &measurement);

        let validator = TeeBoundValidator::new([0x42; 20], Arc::new(oracle), strict);

        let op_hash = [0xCD; 32];
        let envelope = make_envelope(
            TeeVendor::AmdSevSnp,
            measurement,
            &op_hash,
            &signer,
            Timestamp::now(),
        );
        // The simulated report's `simulated=true` metadata makes the verifier
        // skip cert chain checks; remove it so strict mode actually rejects.
        let mut envelope = envelope;
        envelope.attestation_report.metadata.clear();
        let op = make_user_op(sender, envelope.encode().unwrap());

        let result = validator.validate_user_op(&op, &op_hash).unwrap();
        assert!(result.is_failure());
    }

    #[test]
    fn revocation_invalidates_subsequent_ops() {
        let sender = vec![0x11; 20];
        let measurement = vec![0xAA; 48];
        let oracle = InMemoryTeeKeyOracle::new();
        let signer = Ed25519SignerImpl::generate().unwrap();
        let pk: [u8; 32] = signer.public_key().as_bytes().try_into().unwrap();
        oracle.enroll(
            sender.clone(),
            TeeBoundAccountKey::new(TeeVendor::AmdSevSnp, &measurement, pk),
        );
        let oracle = Arc::new(oracle);

        let validator = TeeBoundValidator::new([0x42; 20], oracle.clone(), lenient_verifier());

        let op_hash = [0xCD; 32];
        let envelope = make_envelope(
            TeeVendor::AmdSevSnp,
            measurement,
            &op_hash,
            &signer,
            Timestamp::now(),
        );
        let op = make_user_op(sender.clone(), envelope.encode().unwrap());

        assert!(!validator
            .validate_user_op(&op, &op_hash)
            .unwrap()
            .is_failure());

        // Revoke and try again.
        oracle.revoke(&sender);
        assert!(validator
            .validate_user_op(&op, &op_hash)
            .unwrap()
            .is_failure());
    }

    #[test]
    fn erc1271_returns_magic_on_success() {
        let sender = vec![0x11; 20];
        let measurement = vec![0xAA; 48];
        let (oracle, signer, _) =
            enrolled_account(sender.clone(), TeeVendor::AmdSevSnp, &measurement);

        let validator = TeeBoundValidator::new(
            [0x42; 20],
            Arc::new(oracle),
            lenient_verifier(),
        );

        let hash = [0xCD; 32];
        let envelope = make_envelope(
            TeeVendor::AmdSevSnp,
            measurement,
            &hash,
            &signer,
            Timestamp::now(),
        );
        let result =
            validator.is_valid_signature_with_sender(&sender, &hash, &envelope.encode().unwrap());
        assert_eq!(result, ERC1271_MAGIC_VALUE);
    }

    #[test]
    fn erc1271_returns_failure_on_unenrolled() {
        let oracle = InMemoryTeeKeyOracle::new();
        let validator = TeeBoundValidator::new([0x42; 20], Arc::new(oracle), lenient_verifier());

        let result = validator.is_valid_signature_with_sender(&[0x11; 20], &[0u8; 32], &[]);
        assert_eq!(result, ERC1271_FAILURE_VALUE);
    }

    #[test]
    fn module_address_round_trips() {
        let oracle = InMemoryTeeKeyOracle::new();
        let v = TeeBoundValidator::new([0x77; 20], Arc::new(oracle), lenient_verifier());
        assert_eq!(v.module_address(), [0x77; 20]);
    }

    #[test]
    fn envelope_round_trips_through_bincode() {
        let signer = Ed25519SignerImpl::generate().unwrap();
        let sig = signer.sign(&[0u8; 32]).unwrap();
        let envelope = EnclaveSignedOp {
            attestation_report: make_simulated_report(
                TeeVendor::AmdSevSnp,
                vec![0xAA; 48],
                vec![0u8; 32],
                Timestamp::now(),
            ),
            enclave_signature: sig.as_bytes().to_vec(),
        };
        let encoded = envelope.encode().unwrap();
        let decoded = EnclaveSignedOp::decode(&encoded).unwrap();
        assert_eq!(decoded.enclave_signature, envelope.enclave_signature);
        assert_eq!(
            decoded.attestation_report.user_data,
            envelope.attestation_report.user_data
        );
    }
}
