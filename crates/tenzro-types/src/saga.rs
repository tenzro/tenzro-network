//! Multi-agent saga workflow coordination types.
//!
//! Implements the Tier-3 (chain-anchored) saga primitives from
//! `docs/architecture/multi-agent-workflow-coordination.md`: a workflow is a
//! sequence of steps, each with an Execute → Verify → Compensate lifecycle and
//! an optional per-step escrow allocation. Tenzro records that each transition
//! occurred (durably persisted) and moves real funds per step; it does **not**
//! define what a step or its compensation means semantically — that is the
//! orchestrating framework's concern (LangGraph / CrewAI / AutoGen Magentic-One
//! / …).
//!
//! This is the lightweight, framework-portable coordinator. The richer
//! multi-party signed container (participant signatures over a canonical hash,
//! approval gates, obligations, kill-switch) lives in the `tenzro-workflow`
//! crate's `WorkflowManager` and is the right surface when the workflow needs
//! the full on-chain governance lifecycle.

use serde::{Deserialize, Serialize};

/// Lifecycle of a single saga step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SagaStepStatus {
    /// Declared at `workflowOpen`, not yet executed.
    Pending,
    /// `workflowStepExecute` called — work is in flight; escrow (if any) locked.
    Executing,
    /// `workflowStepVerify` accepted — escrow (if any) released to the payee.
    Verified,
    /// `workflowStepCompensate` fired — the inverse action ran; escrow (if any)
    /// refunded to the payer.
    Compensated,
    /// Execution or verification failed terminally.
    Failed,
}

/// One step in a saga workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SagaStep {
    /// Caller-defined step id (e.g. "pay", "receipt").
    pub id: String,
    /// DID of the agent expected to execute this step (optional).
    #[serde(default)]
    pub executor_did: Option<String>,
    /// Compensation handler tag the orchestrator registered (e.g. "none",
    /// "refund_payment", "void_receipt"). Tenzro records it; the framework
    /// decides what it means.
    #[serde(default)]
    pub compensation: String,
    /// Current status.
    pub status: SagaStepStatus,
    /// Per-step escrow id once `Execute` funds one (None if no escrow).
    #[serde(default)]
    pub escrow_id: Option<String>,
    /// Amount locked in the per-step escrow (0 if none).
    #[serde(default)]
    pub escrow_amount: u128,
    /// Opaque execution-proof reference recorded at `Execute`.
    #[serde(default)]
    pub execute_proof: Option<String>,
    /// Witness signatures / references recorded at `Verify`.
    #[serde(default)]
    pub verify_witnesses: Vec<String>,
    /// Last-updated unix-seconds timestamp.
    pub updated_at: i64,
    /// Optional TEE-attested deadline. When set, the saga
    /// orchestrator MUST refuse to advance the step past `Executing`
    /// after `attested_deadline.wall_ms` and SHOULD compensate
    /// instead. The monotonic counter binds the deadline to a
    /// specific enclave instance so a relayer cannot backdate it
    /// through wall-clock manipulation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attested_deadline: Option<AttestedDeadline>,
}

/// Tenzro-types projection of the workflow-crate `AttestedTimestamp`.
/// Mirrors the wire shape exactly. Defined here so any caller using
/// `SagaStep` (RPC, SDK, agent runtime) doesn't pull tenzro-workflow
/// just to set a deadline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestedDeadline {
    pub wall_ms: u64,
    pub monotonic_ns: u64,
    pub tee_vendor: Option<String>,
    pub enclave_id_hex: Option<String>,
    pub attestation_hash_hex: Option<String>,
    pub signature_hex: Option<String>,
}

impl AttestedDeadline {
    /// `true` if `wall_ms` lies before the relying party's wall-clock
    /// less the tolerance window. Default tolerance is 30s
    /// (Canton 3.5 timestamp drift guidance).
    pub fn is_expired(&self, now_wall_ms: u64, tolerance_ms: u64) -> bool {
        // Expired when deadline + tolerance ≤ now.
        self.wall_ms.saturating_add(tolerance_ms) <= now_wall_ms
    }
}

impl SagaStep {
    pub fn new(id: String, executor_did: Option<String>, compensation: String, at: i64) -> Self {
        Self {
            id,
            executor_did,
            compensation,
            status: SagaStepStatus::Pending,
            escrow_id: None,
            escrow_amount: 0,
            execute_proof: None,
            verify_witnesses: Vec::new(),
            updated_at: at,
            attested_deadline: None,
        }
    }
}

/// Overall saga workflow status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SagaStatus {
    /// Opened, steps declared, none verified yet.
    Open,
    /// At least one step executed/verified, not all terminal.
    Running,
    /// All steps Verified — finalized.
    Completed,
    /// One or more steps Failed and could not be compensated cleanly.
    Failed,
    /// A compensation cascade is in progress (rolling back prior steps).
    Compensating,
}

/// A multi-agent saga workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SagaWorkflow {
    /// Caller-supplied workflow id (e.g. "wf_abc123").
    pub workflow_id: String,
    /// DID of the orchestrator that opened the workflow.
    pub orchestrator_did: String,
    /// Participant DIDs (orchestrator + step executors).
    pub participants: Vec<String>,
    /// Ordered steps.
    pub steps: Vec<SagaStep>,
    /// Overall status.
    pub status: SagaStatus,
    /// Final receipt hash once finalized (hex), if any.
    #[serde(default)]
    pub receipt: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl SagaWorkflow {
    /// Returns true when every step has reached `Verified`.
    pub fn all_verified(&self) -> bool {
        !self.steps.is_empty()
            && self.steps.iter().all(|s| s.status == SagaStepStatus::Verified)
    }
}
