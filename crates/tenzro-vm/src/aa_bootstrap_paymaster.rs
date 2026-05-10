//! TNZO bootstrap paymaster — sponsors the **first** transaction of a newly-
//! spawned autonomous machine so it can install a smart-account validator
//! without prefunding.
//!
//! # Why a special paymaster
//!
//! A general 4337 paymaster (`account_abstraction::Paymaster`) sponsors any
//! `UserOperation` it has the balance for. That is the right primitive for
//! application-level UX (an app paying for its own users' txs), but it is not
//! the right primitive for the **autonomous-agent bootstrap** path described
//! in `SPECIFICATION.md` §15.5:
//!
//! 1. A new agent is spawned inside a TEE; the enclave generates a hybrid
//!    Ed25519+ML-DSA-65 keypair sealed to hardware.
//! 2. The agent's TEE attestation is registered as the agent's identity in
//!    the on-chain ERC-8004 registry (sequential `tokenId`, not
//!    `keccak256(did)`).
//! 3. The agent submits a single EIP-7702 transaction whose authorization
//!    delegates the agent's EOA to a `TenzroSmartAccount` template that
//!    already has a `TeeBoundValidator` installed.
//! 4. The TNZO paymaster sponsors **only** that bootstrap transaction, and
//!    only if the attestation that produced the EOA's key resolves to a
//!    registered ERC-8004 agent in good standing.
//!
//! Crucially: the paymaster MUST refuse to sponsor an arbitrary UserOp from
//! an arbitrary sender. The whole point of the gating is to keep the
//! sponsorship pool from being drained by attackers replaying random
//! authorizations. Bootstrap is one-shot, on-attestation, on-registration.
//!
//! # Trait surface
//!
//! - [`AgentRegistryLookup`] — minimal lookup interface this crate needs from
//!   the on-chain ERC-8004 registry. The full transport lives in
//!   `tenzro-identity::erc8004`; the node layer adapts it to this trait so
//!   `tenzro-vm` does not depend on `tenzro-identity`.
//! - [`TnzoBootstrapPaymaster`] — the paymaster itself. Holds a reference to
//!   the `TeeKeyOracle`, the `AgentRegistryLookup`, the `AttestationVerifier`,
//!   and the per-bootstrap-attempt nonce ledger that prevents the same
//!   authorization from being sponsored twice.
//!
//! # What this module does NOT do
//!
//! - It does not move TNZO. The paymaster's balance is a `u128` field that
//!   the EntryPoint debits via the standard 4337 prefund/postOp flow. Wiring
//!   the debit into the actual TNZO ledger lives in the bundler / node
//!   integration that owns the paymaster instance.
//! - It does not install the validator on the smart account. That is the
//!   job of the SmartAccount factory invoked by the bootstrap UserOp's
//!   `factory` + `factory_data` fields.
//! - It does not verify the EIP-7702 authorization tuple. That lives in
//!   [`crate::account_abstraction::process_7702_authorizations`].

use std::sync::Arc;

use dashmap::DashSet;
use sha2::{Digest, Sha256};

use tenzro_tee::AttestationVerifier;
use tenzro_types::tee::AttestationReport;

use crate::aa_tee_bound_validator::{TeeBoundAccountKey, TeeKeyOracle};
use crate::account_abstraction::{AccountAbstractionError, Paymaster, UserOperation};

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Minimal lookup interface this paymaster needs from an ERC-8004 registry.
///
/// The full ERC-8004 transport (encode / decode / `eth_call` shim) lives in
/// `tenzro-identity::erc8004`; the node layer adapts that transport to this
/// trait so `tenzro-vm` does not have to depend on `tenzro-identity`.
pub trait AgentRegistryLookup: Send + Sync {
    /// Returns true iff `agent_address` is registered in the ERC-8004 registry
    /// and is currently in good standing (not paused, not slashed-out).
    fn is_registered(&self, agent_address: &[u8]) -> bool;
}

/// Errors specific to the bootstrap-paymaster gating logic. These are surfaced
/// as `AccountAbstractionError::PaymasterError(reason.to_string())` so the
/// EntryPoint sees a single error type.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapPaymasterError {
    #[error("sender is not enrolled with a TEE-bound key")]
    SenderNotTeeBound,
    #[error("sender is not registered in the ERC-8004 agent registry")]
    SenderNotErc8004Registered,
    #[error("attestation verification failed: {0}")]
    AttestationInvalid(String),
    #[error("attestation does not bind the sender's enclave key")]
    AttestationKeyMismatch,
    #[error("attestation measurement does not match enrolled measurement")]
    AttestationMeasurementMismatch,
    #[error("bootstrap already sponsored for this sender — first-tx only")]
    BootstrapAlreadyConsumed,
    #[error("UserOp is not a bootstrap op — `factory` field must be non-empty")]
    NotABootstrapOp,
}

impl From<BootstrapPaymasterError> for AccountAbstractionError {
    fn from(e: BootstrapPaymasterError) -> Self {
        AccountAbstractionError::PaymasterError(e.to_string())
    }
}

/// TNZO bootstrap paymaster.
///
/// Owns:
/// - the underlying [`Paymaster`] balance + sponsored-ops counter,
/// - a [`TeeKeyOracle`] resolving `sender → TeeBoundAccountKey`,
/// - an [`AgentRegistryLookup`] resolving `sender → ERC-8004 registered?`,
/// - an [`AttestationVerifier`] that checks the attestation chain,
/// - a `consumed` set of senders that have already been bootstrapped (one-shot
///   per agent — the `TeeBoundValidator` takes over after the first tx).
pub struct TnzoBootstrapPaymaster {
    inner: Paymaster,
    oracle: Arc<dyn TeeKeyOracle>,
    registry: Arc<dyn AgentRegistryLookup>,
    verifier: Arc<AttestationVerifier>,
    consumed: DashSet<Vec<u8>>,
}

impl TnzoBootstrapPaymaster {
    pub fn new(
        address: Vec<u8>,
        initial_balance: u128,
        oracle: Arc<dyn TeeKeyOracle>,
        registry: Arc<dyn AgentRegistryLookup>,
        verifier: Arc<AttestationVerifier>,
    ) -> Self {
        Self {
            inner: Paymaster::new(address, initial_balance),
            oracle,
            registry,
            verifier,
            consumed: DashSet::new(),
        }
    }

    /// Paymaster address (20-byte EVM address).
    pub fn address(&self) -> &[u8] {
        &self.inner.address
    }

    /// Remaining sponsorship balance, in wei-equivalent TNZO base units.
    pub fn balance(&self) -> u128 {
        self.inner.balance
    }

    /// Number of bootstrap UserOps sponsored to date.
    pub fn sponsored_ops(&self) -> u64 {
        self.inner.sponsored_ops
    }

    /// Whether `sender` has already consumed their one-shot bootstrap
    /// sponsorship.
    pub fn has_consumed(&self, sender: &[u8]) -> bool {
        self.consumed.contains(sender)
    }

    /// Top up the paymaster from the TNZO treasury. The actual ledger debit
    /// happens at the integration layer; this method just credits the local
    /// counter.
    pub fn add_funds(&mut self, amount: u128) {
        self.inner.add_funds(amount);
    }

    /// Apply the four bootstrap-gating rules. Pure: no state mutation. Returns
    /// the per-op gas cost the paymaster will sponsor on success.
    ///
    /// Gating rules (must all pass):
    ///   R1. The UserOp's `factory` field is non-empty (this is the bootstrap
    ///       call that creates the smart account; subsequent ops use the same
    ///       account so `factory` is empty and they are NOT eligible).
    ///   R2. The sender is enrolled in the [`TeeKeyOracle`] — i.e. has a
    ///       `TeeBoundAccountKey` recorded — meaning the agent's key was
    ///       generated inside an enclave whose vendor and measurement we
    ///       know.
    ///   R3. The sender is registered in the ERC-8004 agent registry.
    ///   R4. The attestation supplied in `paymaster_data` verifies under
    ///       [`AttestationVerifier`], its vendor + measurement match the
    ///       enrolled key, and its `user_data` field carries the sender's
    ///       enclave public key (preventing replay of an attestation
    ///       captured for a different op).
    ///   R5. The sender has not already consumed their one-shot bootstrap
    ///       (checked but not mutated here; mutation happens in `sponsor`).
    ///
    /// On success, returns `op.max_gas_cost()` so the caller can also verify
    /// the inner `Paymaster` has the balance to cover it.
    pub fn check(&self, op: &UserOperation) -> Result<u128, AccountAbstractionError> {
        // R1: must be a bootstrap op (factory call to create the account).
        if op.factory.is_empty() {
            return Err(BootstrapPaymasterError::NotABootstrapOp.into());
        }

        // R2: TEE enrollment exists for this sender.
        let enrolled: TeeBoundAccountKey = self
            .oracle
            .lookup(&op.sender)
            .ok_or(BootstrapPaymasterError::SenderNotTeeBound)?;

        // R3: sender is in the ERC-8004 registry.
        if !self.registry.is_registered(&op.sender) {
            return Err(BootstrapPaymasterError::SenderNotErc8004Registered.into());
        }

        // R4: paymaster_data carries an AttestationReport that binds the
        // sender's enclave key.
        let attestation = decode_attestation(&op.paymaster_data)
            .map_err(BootstrapPaymasterError::AttestationInvalid)?;

        if attestation.vendor != enrolled.vendor {
            return Err(BootstrapPaymasterError::AttestationKeyMismatch.into());
        }

        // Measurement parity with TeeBoundValidator: enrolled key was bound to
        // a specific enclave image (by `sha256(measurement)`); the attestation
        // must come from that same image.
        if sha256(&attestation.measurement) != enrolled.measurement_hash {
            return Err(BootstrapPaymasterError::AttestationMeasurementMismatch.into());
        }

        // The user_data field of the attestation MUST carry the enrolled
        // enclave's public key. This prevents a quote captured for one
        // enclave from being used to sponsor a bootstrap for a different
        // enclave that happens to be enrolled under the same sender.
        //
        // Note: TeeBoundValidator binds `user_data == op_hash` for replay
        // protection across ops. Bootstrap binds `user_data == enclave_pubkey`
        // because there is no signed op yet — this is an enrollment proof,
        // not an operation proof.
        if attestation.user_data.as_slice() != enrolled.enclave_pubkey.as_slice() {
            return Err(BootstrapPaymasterError::AttestationKeyMismatch.into());
        }

        self.verifier
            .verify_report(&attestation)
            .map_err(|e| BootstrapPaymasterError::AttestationInvalid(e.to_string()))?;

        // R5: not already consumed.
        if self.consumed.contains(&op.sender) {
            return Err(BootstrapPaymasterError::BootstrapAlreadyConsumed.into());
        }

        // Standard 4337 paymaster precondition: enough balance to cover the
        // worst-case gas this op might burn.
        self.inner.validate_paymaster_op(op)?;

        Ok(op.max_gas_cost())
    }

    /// Sponsor the bootstrap UserOp atomically: re-runs `check`, debits the
    /// inner balance, and records the sender as consumed so the same agent
    /// cannot drain a second sponsorship.
    pub fn sponsor(&mut self, op: &UserOperation) -> Result<(), AccountAbstractionError> {
        let gas_cost = self.check(op)?;
        self.inner.sponsor_gas(gas_cost)?;
        self.consumed.insert(op.sender.clone());
        Ok(())
    }
}

/// Decode the attestation report the bundler packed into `paymaster_data`.
///
/// Wire format is bincode 1.x of [`AttestationReport`] — same encoding used by
/// `aa_tee_bound_validator::EnclaveSignedOp.attestation_report`. Keeping the
/// encodings aligned means the same in-enclave assembly can produce both
/// payloads.
fn decode_attestation(bytes: &[u8]) -> Result<AttestationReport, String> {
    bincode::deserialize::<AttestationReport>(bytes)
        .map_err(|e| format!("bincode decode AttestationReport: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::HashMap;

    use crate::aa_tee_bound_validator::InMemoryTeeKeyOracle;
    use crate::account_abstraction::UserOperation;
    use tenzro_types::Timestamp;
    use tenzro_types::tee::TeeVendor;

    /// Permissive registry where every queried address is "registered".
    struct PermissiveRegistry;
    impl AgentRegistryLookup for PermissiveRegistry {
        fn is_registered(&self, _: &[u8]) -> bool {
            true
        }
    }

    /// Strict registry where nothing is ever registered.
    struct EmptyRegistry;
    impl AgentRegistryLookup for EmptyRegistry {
        fn is_registered(&self, _: &[u8]) -> bool {
            false
        }
    }

    fn lenient_verifier() -> Arc<AttestationVerifier> {
        // Tests use simulated attestations with dummy certs, so disable strict
        // chain validation. Real-world bundlers ship the live verifier.
        let mut v = AttestationVerifier::new();
        v.set_strict_cert_validation(false);
        Arc::new(v)
    }

    /// Build a UserOp shaped like a real bootstrap op: non-empty `factory`
    /// field (so R1 passes), sender pinned to the supplied address.
    fn bootstrap_op(sender: Vec<u8>, paymaster_data: Vec<u8>) -> UserOperation {
        UserOperation {
            sender,
            nonce: 0,
            factory: vec![0xFA; 20],
            factory_data: vec![],
            call_data: vec![],
            call_gas_limit: 200_000,
            verification_gas_limit: 100_000,
            pre_verification_gas: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 100_000_000,
            paymaster: vec![0xAA; 20],
            paymaster_verification_gas_limit: 50_000,
            paymaster_post_op_gas_limit: 30_000,
            paymaster_data,
            signature: vec![],
        }
    }

    /// AttestationReport shaped like the on-device simulator path:
    /// non-empty `attestation_data`, `simulated=true` metadata, and
    /// `user_data` bound to the enrolled enclave public key.
    ///
    /// This is the exact pattern `aa_tee_bound_validator::tests::make_simulated_report`
    /// uses — keeping it aligned ensures the same simulated quotes work for
    /// both bootstrap (here) and per-op validation (TeeBoundValidator).
    fn attestation_for(
        vendor: TeeVendor,
        measurement: Vec<u8>,
        enclave_pubkey: &[u8; 32],
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
            user_data: enclave_pubkey.to_vec(),
            attestation_data,
            certificates: vec![],
            timestamp: Timestamp::now(),
            metadata,
            quote: vec![0x01; 32],
            measurement,
            signature: vec![],
            vendor_data: vec![],
        }
    }

    fn build_paymaster(
        oracle: Arc<dyn TeeKeyOracle>,
        registry: Arc<dyn AgentRegistryLookup>,
    ) -> TnzoBootstrapPaymaster {
        TnzoBootstrapPaymaster::new(
            vec![0xAA; 20],
            10u128.pow(20), // 100 TNZO seed
            oracle,
            registry,
            lenient_verifier(),
        )
    }

    #[test]
    fn rejects_op_without_factory() {
        let oracle = Arc::new(InMemoryTeeKeyOracle::new());
        let pm = build_paymaster(oracle, Arc::new(PermissiveRegistry));
        let mut op = bootstrap_op(vec![0x01; 20], vec![]);
        op.factory = vec![]; // no factory — not a bootstrap op
        let err = pm.check(&op).unwrap_err();
        assert!(err.to_string().contains("not a bootstrap op"));
    }

    #[test]
    fn rejects_sender_not_tee_bound() {
        let oracle = Arc::new(InMemoryTeeKeyOracle::new());
        let pm = build_paymaster(oracle, Arc::new(PermissiveRegistry));
        let op = bootstrap_op(vec![0x01; 20], vec![]);
        let err = pm.check(&op).unwrap_err();
        assert!(err.to_string().contains("not enrolled with a TEE-bound key"));
    }

    #[test]
    fn rejects_sender_not_registered() {
        let sender = vec![0x02; 20];
        let pubkey = [0x33; 32];
        let measurement = b"enclave-image-v1".to_vec();
        let oracle = Arc::new(InMemoryTeeKeyOracle::new());
        oracle.enroll(
            sender.clone(),
            TeeBoundAccountKey::new(TeeVendor::IntelTdx, &measurement, pubkey),
        );
        let pm = build_paymaster(oracle, Arc::new(EmptyRegistry));
        let attestation = attestation_for(TeeVendor::IntelTdx, measurement, &pubkey);
        let payload = bincode::serialize(&attestation).unwrap();
        let op = bootstrap_op(sender, payload);
        let err = pm.check(&op).unwrap_err();
        assert!(err.to_string().contains("ERC-8004"));
    }

    #[test]
    fn rejects_attestation_with_wrong_pubkey() {
        let sender = vec![0x03; 20];
        let real_pubkey = [0x44; 32];
        let attacker_pubkey = [0x55; 32];
        let measurement = b"enclave-image-v1".to_vec();
        let oracle = Arc::new(InMemoryTeeKeyOracle::new());
        oracle.enroll(
            sender.clone(),
            TeeBoundAccountKey::new(TeeVendor::IntelTdx, &measurement, real_pubkey),
        );
        let pm = build_paymaster(oracle, Arc::new(PermissiveRegistry));
        // user_data carries the wrong pubkey
        let attestation = attestation_for(TeeVendor::IntelTdx, measurement, &attacker_pubkey);
        let payload = bincode::serialize(&attestation).unwrap();
        let op = bootstrap_op(sender, payload);
        let err = pm.check(&op).unwrap_err();
        assert!(err.to_string().contains("does not bind"));
    }

    #[test]
    fn rejects_vendor_mismatch() {
        let sender = vec![0x04; 20];
        let pubkey = [0x66; 32];
        let measurement = b"enclave-image-v1".to_vec();
        let oracle = Arc::new(InMemoryTeeKeyOracle::new());
        oracle.enroll(
            sender.clone(),
            TeeBoundAccountKey::new(TeeVendor::IntelTdx, &measurement, pubkey),
        );
        let pm = build_paymaster(oracle, Arc::new(PermissiveRegistry));
        // attestation comes from a different vendor than the enrolled key
        let attestation = attestation_for(TeeVendor::AmdSevSnp, measurement, &pubkey);
        let payload = bincode::serialize(&attestation).unwrap();
        let op = bootstrap_op(sender, payload);
        let err = pm.check(&op).unwrap_err();
        assert!(err.to_string().contains("does not bind"));
    }

    #[test]
    fn rejects_measurement_mismatch() {
        let sender = vec![0x06; 20];
        let pubkey = [0x88; 32];
        let enrolled_meas = b"enclave-image-v1".to_vec();
        let attacker_meas = b"enclave-image-v2-tampered".to_vec();
        let oracle = Arc::new(InMemoryTeeKeyOracle::new());
        oracle.enroll(
            sender.clone(),
            TeeBoundAccountKey::new(TeeVendor::IntelTdx, &enrolled_meas, pubkey),
        );
        let pm = build_paymaster(oracle, Arc::new(PermissiveRegistry));
        let attestation = attestation_for(TeeVendor::IntelTdx, attacker_meas, &pubkey);
        let payload = bincode::serialize(&attestation).unwrap();
        let op = bootstrap_op(sender, payload);
        let err = pm.check(&op).unwrap_err();
        assert!(err.to_string().contains("measurement does not match"));
    }

    #[test]
    fn happy_path_sponsors_bootstrap_once() {
        let sender = vec![0x05; 20];
        let pubkey = [0x77; 32];
        let measurement = b"enclave-image-v1".to_vec();
        let oracle = Arc::new(InMemoryTeeKeyOracle::new());
        oracle.enroll(
            sender.clone(),
            TeeBoundAccountKey::new(TeeVendor::IntelTdx, &measurement, pubkey),
        );
        let mut pm = build_paymaster(oracle, Arc::new(PermissiveRegistry));
        let attestation = attestation_for(TeeVendor::IntelTdx, measurement, &pubkey);
        let payload = bincode::serialize(&attestation).unwrap();
        let op = bootstrap_op(sender.clone(), payload);

        let bal_before = pm.balance();
        let cost = pm.check(&op).expect("check passes");
        assert!(cost > 0);
        pm.sponsor(&op).expect("sponsor succeeds");
        assert_eq!(pm.balance(), bal_before - cost);
        assert_eq!(pm.sponsored_ops(), 1);
        assert!(pm.has_consumed(&sender));

        // Second attempt for the same sender must be rejected.
        let err = pm.sponsor(&op).unwrap_err();
        assert!(err.to_string().contains("already sponsored"));
        assert_eq!(pm.sponsored_ops(), 1, "balance must not move on rejection");
    }
}
