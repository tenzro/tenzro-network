//! Lifecycle transitions and kill-switch scopes.
//!
//! Every state transition on a workflow appends a `LifecycleTransition` to
//! the workflow's lifecycle history. The history is the source of truth for
//! audit/compliance.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_types::primitives::Hash;

use crate::workflow::{WorkflowId, WorkflowStatus};

/// What caused a state transition.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransitionTrigger {
    /// Standard creator/participant action.
    Participant { did: String },
    /// Approval gate finalized.
    ApprovalFinalized { request_id: Hash },
    /// All required signatures collected — Draft/AwaitingSignatures → Active.
    SignaturesComplete,
    /// Obligation discharge advanced the workflow.
    ObligationDischarged { obligation_id: Hash },
    /// Obligation defaulted past failure threshold.
    ObligationDefaulted { obligation_id: Hash },
    /// Kill-switch invoked by a controller / governance / TDIP scope holder.
    KillSwitch {
        invoker: String,
        scope: KillSwitchScope,
        reason: String,
    },
    /// Governance proposal forced a transition.
    Governance { proposal_id: Hash },
    /// Timeout fired (approval gate timeout, obligation deadline, etc.).
    Timeout,
    /// Canton mirror reported a state change inbound.
    CantonInbound { contract_id: String },
}

/// Scope of a kill-switch invocation. Affects who is authorized to invoke
/// and what the reachable target states are.
///
/// `Suspend` is the only reversible scope; the others lead to terminal
/// failure / cancellation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum KillSwitchScope {
    /// Halt the workflow but keep state intact (Active → Suspended).
    Suspend,
    /// Force-fail (Suspended → Failed).
    Fail,
    /// Cancel before activation (Draft/AwaitingSignatures/Suspended → Cancelled).
    Cancel,
}

/// One row in the lifecycle history.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LifecycleTransition {
    pub workflow_id: WorkflowId,
    pub from: WorkflowStatus,
    pub to: WorkflowStatus,
    pub trigger: TransitionTrigger,
    pub at: i64,
    /// Hash binding `(workflow_id, from, to, trigger, at)` for receipt
    /// chaining and replay verification.
    pub transition_hash: Hash,
}

impl LifecycleTransition {
    pub fn new(
        workflow_id: WorkflowId,
        from: WorkflowStatus,
        to: WorkflowStatus,
        trigger: TransitionTrigger,
        at: i64,
    ) -> Self {
        let transition_hash = Self::compute_hash(&workflow_id, from, to, &trigger, at);
        Self {
            workflow_id,
            from,
            to,
            trigger,
            at,
            transition_hash,
        }
    }

    fn compute_hash(
        workflow_id: &WorkflowId,
        from: WorkflowStatus,
        to: WorkflowStatus,
        trigger: &TransitionTrigger,
        at: i64,
    ) -> Hash {
        let mut h = Sha256::new();
        h.update(b"tenzro/workflow/lifecycle");
        h.update(workflow_id.as_bytes());
        h.update([from as u8]);
        h.update([to as u8]);
        let trig = serde_json::to_vec(trigger).unwrap_or_default();
        h.update((trig.len() as u32).to_le_bytes());
        h.update(&trig);
        h.update(at.to_le_bytes());
        Hash::from(<[u8; 32]>::from(h.finalize()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transition_hash_is_deterministic() {
        let wf = Hash::from([7u8; 32]);
        let a = LifecycleTransition::new(
            wf,
            WorkflowStatus::Draft,
            WorkflowStatus::AwaitingSignatures,
            TransitionTrigger::Participant {
                did: "alice".into(),
            },
            100,
        );
        let b = LifecycleTransition::new(
            wf,
            WorkflowStatus::Draft,
            WorkflowStatus::AwaitingSignatures,
            TransitionTrigger::Participant {
                did: "alice".into(),
            },
            100,
        );
        assert_eq!(a.transition_hash, b.transition_hash);
    }

    #[test]
    fn transition_hash_changes_with_inputs() {
        let wf = Hash::from([1u8; 32]);
        let a = LifecycleTransition::new(
            wf,
            WorkflowStatus::Active,
            WorkflowStatus::Suspended,
            TransitionTrigger::KillSwitch {
                invoker: "alice".into(),
                scope: KillSwitchScope::Suspend,
                reason: "ops".into(),
            },
            100,
        );
        let b = LifecycleTransition::new(
            wf,
            WorkflowStatus::Active,
            WorkflowStatus::Suspended,
            TransitionTrigger::KillSwitch {
                invoker: "alice".into(),
                scope: KillSwitchScope::Suspend,
                reason: "different reason".into(),
            },
            100,
        );
        assert_ne!(a.transition_hash, b.transition_hash);
    }
}
