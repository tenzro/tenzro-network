//! Approval gates — typed escalation points inside a workflow.
//!
//! When a `PolicyExpr` returns `RequireApproval`, an `ApprovalRequest` is
//! opened against the matching `ApprovalGate`. Approvers sign decisions; the
//! gate's `m_of_n` rule decides when the request is finalized.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_identity::DelegationScope;
use tenzro_types::primitives::Hash;

use crate::policy_dsl::PolicyExpr;
use crate::workflow::WorkflowId;

pub type ApprovalRequestId = Hash;
pub type ApprovalGateId = Hash;

/// A configured escalation point.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalGate {
    pub gate_id: ApprovalGateId,
    pub workflow_id: WorkflowId,
    /// Predicate that, when true, opens a request against this gate.
    pub triggers: PolicyExpr,
    pub approvers: ApproverSet,
    /// Unix seconds after which the gate auto-resolves per `on_timeout`.
    pub timeout: Option<i64>,
    pub on_timeout: TimeoutBehavior,
}

impl ApprovalGate {
    pub fn derive_id(workflow_id: &WorkflowId, label: &str) -> Hash {
        let mut h = Sha256::new();
        h.update(b"tenzro/workflow/gate/id");
        h.update(workflow_id.as_bytes());
        h.update((label.len() as u32).to_le_bytes());
        h.update(label.as_bytes());
        Hash::from(<[u8; 32]>::from(h.finalize()))
    }
}

/// Resolved approver set. Threshold is the canonical multi-sig pattern;
/// `Role` resolves at evaluation time against the workflow's participants;
/// `Delegated` lets a controller authorize a machine to approve on its behalf.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ApproverSet {
    Single {
        did: String,
    },
    Threshold {
        dids: Vec<String>,
        m: u8,
        n: u8,
    },
    Role {
        role: String,
        m: u8,
    },
    Delegated {
        from: String,
        scope: DelegationScopeShim,
    },
}

/// Local mirror of `tenzro-identity::DelegationScope` so we can keep the type
/// `Eq` for tests. (DelegationScope itself doesn't derive `Eq` because of
/// `f64`-equivalent fields; we don't need full equality of nested scope here,
/// just structural equality of the DID.) We carry an opaque hash of the scope
/// to avoid drift between the two representations.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DelegationScopeShim {
    pub scope_hash: Hash,
}

impl DelegationScopeShim {
    pub fn from_scope(s: &DelegationScope) -> Self {
        let bytes = serde_json::to_vec(s).unwrap_or_default();
        let h: [u8; 32] = Sha256::digest(&bytes).into();
        Self {
            scope_hash: Hash::from(h),
        }
    }
}

/// What to do when the timeout fires before reaching threshold.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TimeoutBehavior {
    AutoApprove,
    AutoReject,
    EscalateTo { did: String },
}

/// Open / closed state of a request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ApprovalStatus {
    Open,
    Approved { at: i64 },
    Rejected { at: i64 },
    TimedOut { at: i64, behavior: TimeoutBehavior },
}

impl ApprovalStatus {
    pub fn is_finalized(&self) -> bool {
        !matches!(self, ApprovalStatus::Open)
    }
}

/// A decision a single approver has registered.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalDecision {
    pub by: String,
    pub decision: Decision,
    pub at: i64,
    pub justification: Option<String>,
    /// Ed25519 over canonical preimage (request_id || decision_byte || at_le).
    pub signature: Vec<u8>,
    pub signed_by_pubkey: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Decision {
    Approve,
    Reject,
}

impl Decision {
    pub fn as_byte(self) -> u8 {
        match self {
            Decision::Approve => 1,
            Decision::Reject => 0,
        }
    }
}

/// An open or finalized request against a gate.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalRequest {
    pub request_id: ApprovalRequestId,
    pub gate_id: ApprovalGateId,
    pub workflow_id: WorkflowId,
    /// Free-form context that tripped the gate (amount, counterparty, etc.).
    pub trigger_context: serde_json::Value,
    pub created_at: i64,
    pub decisions: Vec<ApprovalDecision>,
    pub status: ApprovalStatus,
}

impl ApprovalRequest {
    pub fn derive_id(gate_id: &ApprovalGateId, ctx_hash: &Hash, created_at: i64) -> Hash {
        let mut h = Sha256::new();
        h.update(b"tenzro/workflow/approval/id");
        h.update(gate_id.as_bytes());
        h.update(ctx_hash.as_bytes());
        h.update(created_at.to_le_bytes());
        Hash::from(<[u8; 32]>::from(h.finalize()))
    }

    /// Canonical preimage that approvers sign.
    pub fn decision_preimage(&self, decision: Decision, at: i64) -> Vec<u8> {
        let mut buf = Vec::with_capacity(32 + 1 + 8);
        buf.extend_from_slice(self.request_id.as_bytes());
        buf.push(decision.as_byte());
        buf.extend_from_slice(&at.to_le_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn approval_status_finalization() {
        assert!(!ApprovalStatus::Open.is_finalized());
        assert!(ApprovalStatus::Approved { at: 1 }.is_finalized());
        assert!(ApprovalStatus::Rejected { at: 1 }.is_finalized());
        assert!(
            ApprovalStatus::TimedOut {
                at: 1,
                behavior: TimeoutBehavior::AutoReject
            }
            .is_finalized()
        );
    }

    #[test]
    fn decision_preimage_includes_request_and_decision_bytes() {
        let req = ApprovalRequest {
            request_id: Hash::from([7u8; 32]),
            gate_id: Hash::from([0u8; 32]),
            workflow_id: Hash::from([0u8; 32]),
            trigger_context: serde_json::Value::Null,
            created_at: 100,
            decisions: vec![],
            status: ApprovalStatus::Open,
        };
        let pre = req.decision_preimage(Decision::Approve, 200);
        assert_eq!(pre.len(), 32 + 1 + 8);
        assert_eq!(pre[32], 1);
    }
}
