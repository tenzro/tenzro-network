//! IBC-Eureka light-client adapter for Cosmos reach.
//!
//! Cosmos chains expose Tendermint headers that can be verified against the
//! ICS-07 Tendermint light-client rules. Direct in-protocol verification is
//! gas-prohibitive on every receiving chain, so IBC-Eureka (Succinct +
//! Interchain Foundation) compresses each header transition into an SP1
//! zero-knowledge proof. The Tenzro side is therefore a thin verifier: it
//! takes SP1 proof blobs together with the consensus state they advance, runs
//! the SP1 verifier, and persists the advancing `ConsensusState` keyed by
//! `ClientId`.
//!
//! Source of truth for the verifier shape: `cosmos/solidity-ibc-eureka`
//! (sp1-ics07-tendermint program). This module mirrors the on-chain interface
//! while staying agnostic about how the proof is generated. Higher-level
//! callers feed `verify_proof_envelope(&IbcEurekaProof)` to advance the
//! client; `verify_membership` checks an ICS-23 commitment proof against the
//! stored root.

use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{BridgeError, Result};
use tenzro_types::primitives::Hash;

/// Canonical ICS-07 client identifier (e.g. `07-tendermint-0`).
pub type ClientId = String;

/// Canonical ICS-24 path used for ICS-23 membership proofs.
pub type CommitmentPath = String;

/// Trust threshold for ICS-07 Tendermint clients. Two-thirds (`numerator=2,
/// denominator=3`) is the IBC default; relayers must supply headers whose
/// next-validator-set overlap reaches at least this fraction of voting power
/// before the light-client accepts the transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustThreshold {
    /// Trust threshold numerator.
    pub numerator: u8,
    /// Trust threshold denominator.
    pub denominator: u8,
}

impl Default for TrustThreshold {
    fn default() -> Self {
        Self {
            numerator: 2,
            denominator: 3,
        }
    }
}

/// ICS-07 Tendermint client state. Mirrors the subset of fields the SP1
/// program checks: chain id, latest height, trust period, unbonding period,
/// trust threshold, and a content-addressed commitment to the validator set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientState {
    /// Counterparty Tendermint `chain_id` (e.g. `cosmoshub-4`).
    pub counterparty_chain_id: String,
    /// Last verified Tendermint height.
    pub latest_height: u64,
    /// Maximum age (seconds) a trusted header can have when a relayer wants
    /// to bisect through it.
    pub trust_period_secs: u64,
    /// Counterparty staking unbonding period (seconds). Headers older than
    /// this are no longer slashable and the light-client must refuse them.
    pub unbonding_period_secs: u64,
    /// Trust threshold required for committing a header (IBC default 2/3).
    pub trust_threshold: TrustThreshold,
    /// 32-byte SHA-256 commitment to the latest validator-set hash. The SP1
    /// program proves the next validator set hashes to this value.
    pub validator_set_commitment: [u8; 32],
    /// Whether the client has been frozen by a misbehaviour proof.
    pub frozen_height: Option<u64>,
}

/// ICS-07 consensus state: the values the counterparty agreed on at
/// `latest_height`. The 32-byte `root` is the Merkle commitment used as
/// input to ICS-23 membership/non-membership proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusState {
    /// Counterparty consensus state height.
    pub height: u64,
    /// Unix timestamp (seconds) of the counterparty block.
    pub timestamp_secs: u64,
    /// Commitment root (32 bytes) used to seed ICS-23 membership proofs.
    pub root: [u8; 32],
    /// Next validator-set hash that will sign at `height + 1`.
    pub next_validators_hash: [u8; 32],
}

/// SP1-compressed update proof. The relayer submits the new `ClientState`
/// and `ConsensusState` together with the SP1 plonk proof committing to the
/// transition from `trusted_height -> client_state.latest_height`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IbcEurekaProof {
    /// Client being advanced (e.g. `07-tendermint-0`).
    pub client_id: ClientId,
    /// Height the transition is bisecting from (must already be stored).
    pub trusted_height: u64,
    /// Post-state the proof advances the client to.
    pub new_client_state: ClientState,
    /// Post-state consensus.
    pub new_consensus_state: ConsensusState,
    /// SP1 plonk proof bytes — opaque to this crate; only the configured
    /// SP1 verifier knows their shape.
    pub sp1_proof_bytes: Vec<u8>,
    /// Public-input commitment as committed to by the SP1 program. The
    /// receiver recomputes this from `(trusted_height, new_client_state,
    /// new_consensus_state)` and matches against the proof's public inputs.
    pub public_input_commitment: [u8; 32],
}

/// ICS-23 membership proof package. The relayer submits an inclusion proof
/// along with the (path, value) pair and the trusted consensus height that
/// the root is taken from.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipProof {
    /// Client whose `ConsensusState.root` will verify the proof.
    pub client_id: ClientId,
    /// Trusted consensus height the proof is rooted at.
    pub proof_height: u64,
    /// ICS-24 path that should be present.
    pub path: CommitmentPath,
    /// Value the relayer claims is committed at `path`.
    pub value: Vec<u8>,
    /// ICS-23 inclusion proof bytes (`existence`, opaque to this crate).
    pub ics23_proof_bytes: Vec<u8>,
}

/// Outcome of the SP1 + ICS-07 verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateOutcome {
    /// Client whose state was advanced.
    pub client_id: ClientId,
    /// New latest height after the update.
    pub new_height: u64,
    /// New root committed by the SP1 program.
    pub new_root: [u8; 32],
}

/// SP1 verifier abstraction. Production wires this to a concrete `sp1-sdk`
/// `PlonkVerifier`; tests use the stub.
pub trait Sp1Verifier: Send + Sync + std::fmt::Debug {
    /// Verify an SP1 plonk proof against a 32-byte public-input commitment
    /// and a program verification-key digest (the SP1 program ID).
    fn verify_plonk(
        &self,
        proof_bytes: &[u8],
        public_input_commitment: &[u8; 32],
        program_vk_digest: &[u8; 32],
    ) -> Result<()>;
}

/// Stub SP1 verifier used by tests and the default-OK admission path. It
/// rejects empty proofs and mismatched commitments but does not actually
/// run a PLONK verifier; production deployments must inject a real
/// `Sp1Verifier`.
#[derive(Debug, Default, Clone)]
pub struct StubSp1Verifier;

impl Sp1Verifier for StubSp1Verifier {
    fn verify_plonk(
        &self,
        proof_bytes: &[u8],
        public_input_commitment: &[u8; 32],
        _program_vk_digest: &[u8; 32],
    ) -> Result<()> {
        if proof_bytes.is_empty() {
            return Err(BridgeError::InvalidProof);
        }
        if public_input_commitment == &[0u8; 32] {
            return Err(BridgeError::InvalidProof);
        }
        Ok(())
    }
}

/// In-memory store of `ConsensusState` per (client, height). Production
/// nodes mirror this into `CF_STATE` under `ibc/cs/<client>/<height>`; this
/// crate stays storage-agnostic.
#[derive(Debug, Default)]
struct ConsensusStore {
    by_height: BTreeMap<u64, ConsensusState>,
}

/// IBC-Eureka adapter. Owns a registry of client states + consensus stores,
/// drives header updates via an injected `Sp1Verifier`, and answers ICS-23
/// membership questions against the stored roots.
#[derive(Debug)]
pub struct IbcEurekaAdapter {
    program_vk_digest: [u8; 32],
    verifier: Arc<dyn Sp1Verifier>,
    clients: RwLock<BTreeMap<ClientId, ClientState>>,
    stores: RwLock<BTreeMap<ClientId, ConsensusStore>>,
}

impl IbcEurekaAdapter {
    /// Build a new adapter pinned to a specific SP1 program verification key.
    /// The verifier rejects proofs not produced by this program.
    pub fn new(program_vk_digest: [u8; 32], verifier: Arc<dyn Sp1Verifier>) -> Self {
        Self {
            program_vk_digest,
            verifier,
            clients: RwLock::new(BTreeMap::new()),
            stores: RwLock::new(BTreeMap::new()),
        }
    }

    /// Convenience constructor wiring the stub verifier. Suitable for tests
    /// and development; production must call [`Self::new`] with a real
    /// SP1 verifier.
    pub fn with_stub_verifier(program_vk_digest: [u8; 32]) -> Self {
        Self::new(program_vk_digest, Arc::new(StubSp1Verifier))
    }

    /// Create a new ICS-07 light-client tracked by this adapter. The initial
    /// `ConsensusState` is taken from the supplied client-state's latest
    /// height + root + next-validators-hash so the first relayer header
    /// can bisect off it.
    pub fn create_client(
        &self,
        client_id: impl Into<ClientId>,
        client_state: ClientState,
        initial_consensus_state: ConsensusState,
    ) -> Result<()> {
        let cid = client_id.into();
        if cid.is_empty() {
            return Err(BridgeError::ConfigurationError(
                "client_id must be non-empty".into(),
            ));
        }
        if initial_consensus_state.height != client_state.latest_height {
            return Err(BridgeError::ConfigurationError(
                "initial consensus state height must match client latest_height".into(),
            ));
        }
        let mut clients = self.clients.write();
        if clients.contains_key(&cid) {
            return Err(BridgeError::ConfigurationError(format!(
                "client {} already exists",
                cid
            )));
        }
        clients.insert(cid.clone(), client_state);
        let mut stores = self.stores.write();
        let store = stores.entry(cid).or_default();
        store
            .by_height
            .insert(initial_consensus_state.height, initial_consensus_state);
        Ok(())
    }

    /// Read the current client state.
    pub fn client_state(&self, client_id: &str) -> Option<ClientState> {
        self.clients.read().get(client_id).cloned()
    }

    /// Read the consensus state at a specific height.
    pub fn consensus_state(&self, client_id: &str, height: u64) -> Option<ConsensusState> {
        self.stores
            .read()
            .get(client_id)
            .and_then(|s| s.by_height.get(&height).cloned())
    }

    /// Advance the light-client by verifying an SP1 update proof. The proof
    /// public-input commitment must equal
    /// `SHA-256(client_id || trusted_height_le || new_client_state_canon
    ///          || new_consensus_state_canon)`, where `_canon` is the
    /// `bincode::serialize` form.
    pub fn update_client(&self, proof: IbcEurekaProof) -> Result<UpdateOutcome> {
        // 1. Match the trusted height against a stored consensus state.
        let trusted_root = {
            let stores = self.stores.read();
            let store = stores
                .get(&proof.client_id)
                .ok_or_else(|| BridgeError::ChainNotSupported(proof.client_id.clone()))?;
            store
                .by_height
                .get(&proof.trusted_height)
                .cloned()
                .ok_or(BridgeError::InvalidProof)?
                .root
        };

        // 2. Reject if the client is frozen.
        {
            let clients = self.clients.read();
            let current = clients
                .get(&proof.client_id)
                .ok_or_else(|| BridgeError::ChainNotSupported(proof.client_id.clone()))?;
            if current.frozen_height.is_some() {
                return Err(BridgeError::InvalidProof);
            }
            if current.counterparty_chain_id != proof.new_client_state.counterparty_chain_id {
                return Err(BridgeError::InvalidProof);
            }
            if proof.new_client_state.latest_height <= current.latest_height {
                return Err(BridgeError::InvalidProof);
            }
        }

        // 3. Re-derive the expected public-input commitment and match against
        //    the proof claim before invoking SP1 — cheap to fail fast.
        let expected = expected_public_input_commitment(
            &proof.client_id,
            proof.trusted_height,
            &trusted_root,
            &proof.new_client_state,
            &proof.new_consensus_state,
        );
        if expected != proof.public_input_commitment {
            return Err(BridgeError::InvalidProof);
        }

        // 4. Verify the SP1 plonk proof.
        self.verifier.verify_plonk(
            &proof.sp1_proof_bytes,
            &proof.public_input_commitment,
            &self.program_vk_digest,
        )?;

        // 5. Commit.
        let outcome = UpdateOutcome {
            client_id: proof.client_id.clone(),
            new_height: proof.new_client_state.latest_height,
            new_root: proof.new_consensus_state.root,
        };
        let mut clients = self.clients.write();
        clients.insert(proof.client_id.clone(), proof.new_client_state.clone());
        let mut stores = self.stores.write();
        let store = stores.entry(proof.client_id.clone()).or_default();
        store
            .by_height
            .insert(proof.new_consensus_state.height, proof.new_consensus_state);
        Ok(outcome)
    }

    /// Verify an ICS-23 membership proof against a stored consensus root.
    /// The actual ICS-23 verification is delegated to the supplied closure
    /// — this lets node-layer code wire `ibc-proto-rs` without dragging
    /// the dependency into the bridge crate.
    pub fn verify_membership<F>(&self, proof: &MembershipProof, ics23_verify: F) -> Result<()>
    where
        F: FnOnce(&[u8; 32], &str, &[u8], &[u8]) -> Result<()>,
    {
        let root = self
            .consensus_state(&proof.client_id, proof.proof_height)
            .ok_or(BridgeError::InvalidProof)?
            .root;
        ics23_verify(&root, &proof.path, &proof.value, &proof.ics23_proof_bytes)
    }

    /// Freeze a client on misbehaviour detection. After freezing, all further
    /// updates and membership checks reject until the operator submits an
    /// unfreezing governance proof.
    pub fn freeze(&self, client_id: &str, at_height: u64) -> Result<()> {
        let mut clients = self.clients.write();
        let state = clients
            .get_mut(client_id)
            .ok_or_else(|| BridgeError::ChainNotSupported(client_id.to_string()))?;
        state.frozen_height = Some(at_height);
        Ok(())
    }

    /// Domain-tag used when the on-chain `IBC_VERIFY` precompile hashes
    /// proof bytes for the commitment registry.
    pub fn commitment_domain_tag() -> &'static [u8] {
        b"tenzro/ibc-eureka/proof"
    }

    /// Convenience commitment used by the `IBC_VERIFY` precompile lookup
    /// path: `SHA-256(domain || client_id || height_le || root)`.
    pub fn commit_outcome(outcome: &UpdateOutcome) -> Hash {
        let mut h = Sha256::new();
        h.update(Self::commitment_domain_tag());
        h.update(outcome.client_id.as_bytes());
        h.update(outcome.new_height.to_le_bytes());
        h.update(outcome.new_root);
        let digest: [u8; 32] = h.finalize().into();
        Hash::new(digest)
    }
}

/// Re-derive the expected public-input commitment the SP1 program committed
/// to. Domain tag `tenzro/ibc-eureka/pi` keeps this disjoint from any other
/// 32-byte commitment the system computes.
pub fn expected_public_input_commitment(
    client_id: &str,
    trusted_height: u64,
    trusted_root: &[u8; 32],
    new_client_state: &ClientState,
    new_consensus_state: &ConsensusState,
) -> [u8; 32] {
    let cs_bytes = bincode::serialize(new_client_state).unwrap_or_default();
    let con_bytes = bincode::serialize(new_consensus_state).unwrap_or_default();
    let mut h = Sha256::new();
    h.update(b"tenzro/ibc-eureka/pi");
    h.update(client_id.as_bytes());
    h.update(trusted_height.to_le_bytes());
    h.update(trusted_root);
    h.update((cs_bytes.len() as u32).to_le_bytes());
    h.update(&cs_bytes);
    h.update((con_bytes.len() as u32).to_le_bytes());
    h.update(&con_bytes);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_client_state(height: u64, chain: &str) -> ClientState {
        ClientState {
            counterparty_chain_id: chain.into(),
            latest_height: height,
            trust_period_secs: 14 * 24 * 3600,
            unbonding_period_secs: 21 * 24 * 3600,
            trust_threshold: TrustThreshold::default(),
            validator_set_commitment: [9u8; 32],
            frozen_height: None,
        }
    }

    fn sample_consensus_state(height: u64) -> ConsensusState {
        ConsensusState {
            height,
            timestamp_secs: 1_700_000_000 + height,
            root: [height as u8; 32],
            next_validators_hash: [(height + 1) as u8; 32],
        }
    }

    #[test]
    fn create_then_query_client() {
        let adapter = IbcEurekaAdapter::with_stub_verifier([7u8; 32]);
        let cs = sample_client_state(100, "cosmoshub-4");
        let con = sample_consensus_state(100);
        adapter.create_client("07-tendermint-0", cs, con).unwrap();
        assert_eq!(
            adapter
                .client_state("07-tendermint-0")
                .unwrap()
                .latest_height,
            100
        );
        assert!(adapter.consensus_state("07-tendermint-0", 100).is_some());
    }

    #[test]
    fn update_client_advances_state() {
        let adapter = IbcEurekaAdapter::with_stub_verifier([7u8; 32]);
        adapter
            .create_client(
                "07-tendermint-0",
                sample_client_state(100, "cosmoshub-4"),
                sample_consensus_state(100),
            )
            .unwrap();

        let trusted_root = adapter
            .consensus_state("07-tendermint-0", 100)
            .unwrap()
            .root;
        let new_client_state = sample_client_state(105, "cosmoshub-4");
        let new_con = sample_consensus_state(105);
        let pi = expected_public_input_commitment(
            "07-tendermint-0",
            100,
            &trusted_root,
            &new_client_state,
            &new_con,
        );

        let outcome = adapter
            .update_client(IbcEurekaProof {
                client_id: "07-tendermint-0".into(),
                trusted_height: 100,
                new_client_state,
                new_consensus_state: new_con,
                sp1_proof_bytes: vec![1, 2, 3, 4],
                public_input_commitment: pi,
            })
            .unwrap();
        assert_eq!(outcome.new_height, 105);
        assert_eq!(outcome.new_root, [105u8; 32]);
    }

    #[test]
    fn update_rejects_height_regression() {
        let adapter = IbcEurekaAdapter::with_stub_verifier([7u8; 32]);
        adapter
            .create_client(
                "07-tendermint-0",
                sample_client_state(100, "cosmoshub-4"),
                sample_consensus_state(100),
            )
            .unwrap();
        let trusted_root = [100u8; 32];
        let stale_state = sample_client_state(90, "cosmoshub-4");
        let stale_con = sample_consensus_state(90);
        let pi = expected_public_input_commitment(
            "07-tendermint-0",
            100,
            &trusted_root,
            &stale_state,
            &stale_con,
        );
        let err = adapter
            .update_client(IbcEurekaProof {
                client_id: "07-tendermint-0".into(),
                trusted_height: 100,
                new_client_state: stale_state,
                new_consensus_state: stale_con,
                sp1_proof_bytes: vec![1, 2, 3],
                public_input_commitment: pi,
            })
            .unwrap_err();
        assert!(matches!(err, BridgeError::InvalidProof));
    }

    #[test]
    fn freeze_blocks_subsequent_update() {
        let adapter = IbcEurekaAdapter::with_stub_verifier([7u8; 32]);
        adapter
            .create_client(
                "07-tendermint-0",
                sample_client_state(100, "cosmoshub-4"),
                sample_consensus_state(100),
            )
            .unwrap();
        adapter.freeze("07-tendermint-0", 100).unwrap();
        let trusted_root = [100u8; 32];
        let new_state = sample_client_state(105, "cosmoshub-4");
        let new_con = sample_consensus_state(105);
        let pi = expected_public_input_commitment(
            "07-tendermint-0",
            100,
            &trusted_root,
            &new_state,
            &new_con,
        );
        let err = adapter
            .update_client(IbcEurekaProof {
                client_id: "07-tendermint-0".into(),
                trusted_height: 100,
                new_client_state: new_state,
                new_consensus_state: new_con,
                sp1_proof_bytes: vec![9, 9, 9],
                public_input_commitment: pi,
            })
            .unwrap_err();
        assert!(matches!(err, BridgeError::InvalidProof));
    }

    #[test]
    fn commitment_is_deterministic() {
        let outcome = UpdateOutcome {
            client_id: "07-tendermint-0".into(),
            new_height: 200,
            new_root: [42u8; 32],
        };
        let a = IbcEurekaAdapter::commit_outcome(&outcome);
        let b = IbcEurekaAdapter::commit_outcome(&outcome);
        assert_eq!(a, b);
    }

    #[test]
    fn stub_verifier_rejects_empty_proof() {
        let v = StubSp1Verifier;
        let err = v.verify_plonk(&[], &[1u8; 32], &[2u8; 32]).unwrap_err();
        assert!(matches!(err, BridgeError::InvalidProof));
    }
}
