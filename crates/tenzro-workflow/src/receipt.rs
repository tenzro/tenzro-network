//! Workflow receipts.
//!
//! Every consensus-visible workflow event (creation, signature, lifecycle
//! transition, obligation discharge, approval finalization, kill-switch)
//! emits a `WorkflowReceipt` that projects to a `tenzro_storage::da::ReceiptEnvelope`
//! for inline storage or DA offload — same chain-of-custody envelope used by
//! settlement, lifecycle, and governance receipts.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_storage::da::{ReceiptEnvelope, ReceiptKind, ReceiptSummary};
use tenzro_types::primitives::{Hash, Timestamp};

use crate::approval::ApprovalRequestId;
use crate::lifecycle::LifecycleTransition;
use crate::obligation::ObligationId;
use crate::workflow::WorkflowId;

pub type WorkflowReceiptId = Hash;

/// What happened.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum WorkflowEventKind {
    /// New workflow created (Draft).
    Created,
    /// A participant signed.
    Signed { by: String },
    /// All signatures collected → Active.
    Activated,
    /// A lifecycle transition was applied.
    LifecycleTransitioned { transition: LifecycleTransition },
    /// An obligation moved to a new status (InProgress / Discharged / Defaulted).
    ObligationStatusChanged {
        obligation_id: ObligationId,
        new_status_tag: String,
    },
    /// An approval request was opened against a gate.
    ApprovalOpened { request_id: ApprovalRequestId },
    /// An approval request finalized (Approved / Rejected / TimedOut).
    ApprovalFinalized {
        request_id: ApprovalRequestId,
        outcome: String,
    },
    /// Kill-switch invoked.
    KillSwitchInvoked { invoker: String, scope: String },
    /// Workflow reached a terminal state.
    Terminated { final_status: String },
}

/// Typed workflow receipt. Persisted under `wf_receipt:<receipt_id>` and
/// projected to a `ReceiptEnvelope` for indexing / DA offload.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkflowReceipt {
    pub receipt_id: WorkflowReceiptId,
    pub workflow_id: WorkflowId,
    pub event: WorkflowEventKind,
    pub at: Timestamp,
    /// Chain back to the previous receipt for the same workflow, building a
    /// per-workflow hash chain. `Hash::default()` for the first receipt.
    pub prev_receipt: Hash,
}

impl WorkflowReceipt {
    pub fn new(
        workflow_id: WorkflowId,
        event: WorkflowEventKind,
        at: Timestamp,
        prev_receipt: Hash,
    ) -> Self {
        let receipt_id = Self::derive_id(&workflow_id, &event, at, &prev_receipt);
        Self {
            receipt_id,
            workflow_id,
            event,
            at,
            prev_receipt,
        }
    }

    fn derive_id(
        workflow_id: &WorkflowId,
        event: &WorkflowEventKind,
        at: Timestamp,
        prev_receipt: &Hash,
    ) -> Hash {
        let mut h = Sha256::new();
        h.update(b"tenzro/workflow/receipt/id");
        h.update(workflow_id.as_bytes());
        let evt = serde_json::to_vec(event).unwrap_or_default();
        h.update((evt.len() as u32).to_le_bytes());
        h.update(&evt);
        h.update(at.0.to_le_bytes());
        h.update(prev_receipt.as_bytes());
        Hash::from(<[u8; 32]>::from(h.finalize()))
    }

    /// SHA-256 over the canonical (bincode) payload — used as the
    /// `ReceiptEnvelope::commitment` value.
    pub fn commitment(&self) -> Hash {
        let bytes = bincode::serialize(self).unwrap_or_default();
        let h: [u8; 32] = Sha256::digest(&bytes).into();
        Hash::from(h)
    }

    /// Project to an inline `ReceiptEnvelope` under the lifecycle kind.
    /// Workflow events are audit-critical; default to inline storage.
    pub fn to_envelope(&self) -> ReceiptEnvelope {
        let payload = bincode::serialize(self).unwrap_or_default();
        let summary = ReceiptSummary {
            receipt_id: self.receipt_id,
            payer: None,
            payee: None,
            amount_wei: None,
            timestamp: self.at,
            principal_chain_summary: None,
        };
        ReceiptEnvelope::inline(ReceiptKind::Lifecycle, summary, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn receipt_id_chain() {
        let wf = Hash::from([5u8; 32]);
        let r1 = WorkflowReceipt::new(
            wf,
            WorkflowEventKind::Created,
            Timestamp(100),
            Hash::default(),
        );
        let r2 = WorkflowReceipt::new(
            wf,
            WorkflowEventKind::Activated,
            Timestamp(200),
            r1.receipt_id,
        );
        assert_ne!(r1.receipt_id, r2.receipt_id);
        assert_eq!(r2.prev_receipt, r1.receipt_id);
    }

    #[test]
    fn projects_to_inline_envelope() {
        let wf = Hash::from([1u8; 32]);
        let r = WorkflowReceipt::new(
            wf,
            WorkflowEventKind::Created,
            Timestamp(1),
            Hash::default(),
        );
        let env = r.to_envelope();
        assert!(matches!(env.kind, ReceiptKind::Lifecycle));
        assert!(env.inline_payload.is_some());
        assert!(env.validate().is_ok());
    }
}
