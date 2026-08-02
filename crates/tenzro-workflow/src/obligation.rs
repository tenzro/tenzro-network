//! Obligations — discrete promises tied to a workflow.
//!
//! An obligation is owed by an `obligor` to an `obligee`. Discharge happens by
//! supplying a typed proof (payment receipt, settlement receipt, credential,
//! TEE attestation, ZK proof, or a mirrored DAML choice exercise).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_types::primitives::Hash;

use crate::workflow::WorkflowId;

pub type ObligationId = Hash;

/// Lifecycle states of an obligation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ObligationStatus {
    Pending,
    InProgress {
        since: i64,
    },
    Discharged {
        receipt: Hash,
        at: i64,
    },
    Defaulted {
        reason: String,
        at: i64,
    },
    /// Forgiven by the obligee — discharges the obligation without proof.
    Forgiven {
        by: String,
        at: i64,
    },
}

impl ObligationStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            ObligationStatus::Discharged { .. }
                | ObligationStatus::Defaulted { .. }
                | ObligationStatus::Forgiven { .. }
        )
    }
}

/// Reference to an asset on Tenzro or another chain (CAIP-19-like).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssetRef {
    pub chain: String,  // "tenzro" | "ethereum" | "canton:mainnet" | ...
    pub symbol: String, // "TNZO" | "USDC" | ...
    pub token_address: Option<Vec<u8>>,
}

/// What is owed.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ObligationKind {
    Pay {
        amount_wei: u128,
        asset: AssetRef,
    },
    Deliver {
        resource_did: String,
        qty: u64,
    },
    Attest {
        credential_type: String,
        subject: String,
    },
    Settle {
        settlement_id: Hash,
    },
    Custom {
        tag: String,
        payload: Vec<u8>,
    },
}

/// What kind of proof is required to discharge.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DischargeProofKind {
    PaymentReceipt,
    SettlementReceipt,
    Credential,
    TeeAttestation,
    ZkProof {
        circuit_id: String,
    },
    /// A choice exercise on a mirrored DAML contract (CantonAdapter populates
    /// this when it consumes the inbound event).
    CantonExercise {
        template_id: String,
        choice: String,
    },
}

/// A discharge proof artifact submitted with `WorkflowManager::discharge`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DischargeProof {
    pub kind: DischargeProofKind,
    /// Receipt / credential / proof hash that the verifier can resolve.
    pub artifact_hash: Hash,
    /// Optional inline payload for clients that want to embed (preferred:
    /// resolve via the relevant registry by `artifact_hash`).
    pub artifact_inline: Option<Vec<u8>>,
}

/// An obligation between two DIDs in a workflow.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Obligation {
    pub obligation_id: ObligationId,
    pub workflow_id: WorkflowId,
    pub obligor: String,
    pub obligee: String,
    pub kind: ObligationKind,
    pub due_by: Option<i64>,
    pub status: ObligationStatus,
    pub discharge_proof_required: DischargeProofKind,
    /// AgentBond record id if the obligor has bond at risk on default.
    pub bond_anchor: Option<Hash>,
}

impl Obligation {
    /// Deterministic id derived from workflow + obligor + obligee + kind hash.
    pub fn derive_id(workflow_id: &WorkflowId, obligor: &str, obligee: &str, nonce: u64) -> Hash {
        let mut h = Sha256::new();
        h.update(b"tenzro/workflow/obligation/id");
        h.update(workflow_id.as_bytes());
        h.update((obligor.len() as u32).to_le_bytes());
        h.update(obligor.as_bytes());
        h.update((obligee.len() as u32).to_le_bytes());
        h.update(obligee.as_bytes());
        h.update(nonce.to_le_bytes());
        Hash::from(<[u8; 32]>::from(h.finalize()))
    }
}
