//! Top-level workflow type — the multi-party container that owns
//! participants, obligations, approval gates, lifecycle history, and an
//! optional Canton synchronizer mirror.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_types::primitives::Hash;

use crate::approval::ApprovalGate;
use crate::obligation::ObligationId;
use crate::participant::Participant;
use crate::policy_dsl::PolicyExpr;

pub type WorkflowId = Hash;
pub type FeeRouteId = Hash;
pub type TemplateId = Hash;
pub type PrivacyDomainId = Hash;

/// State machine of a workflow.
///
/// Transitions:
/// `Draft → AwaitingSignatures → Active → (Suspended ↔ Active) →
///   Settling → Completed | Failed | Disputed | Cancelled`.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum WorkflowStatus {
    /// Creator is still composing — participants may join, obligations may
    /// change, no signatures collected yet.
    Draft,
    /// Composition is frozen; awaiting all participant signatures over the
    /// workflow's canonical hash.
    AwaitingSignatures,
    /// All participants signed; obligations are open for discharge.
    Active,
    /// Halted by kill-switch / governance / approval-on-pause; resumable.
    Suspended,
    /// All obligations terminal; final settlement is being computed and
    /// receipts emitted.
    Settling,
    /// All obligations discharged successfully.
    Completed,
    /// One or more obligations defaulted past the failure threshold.
    Failed,
    /// Open dispute on an obligation discharge / approval finalization.
    Disputed,
    /// Cancelled before activation.
    Cancelled,
}

impl WorkflowStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            WorkflowStatus::Completed
                | WorkflowStatus::Failed
                | WorkflowStatus::Cancelled
        )
    }

    /// Permitted next-state set. The manager enforces these on every
    /// transition; rejections come back as `WorkflowError::InvalidTransition`.
    pub fn can_transition_to(&self, next: WorkflowStatus) -> bool {
        use WorkflowStatus::*;
        matches!(
            (*self, next),
            (Draft, AwaitingSignatures)
                | (Draft, Cancelled)
                | (AwaitingSignatures, Active)
                | (AwaitingSignatures, Cancelled)
                | (Active, Suspended)
                | (Active, Settling)
                | (Active, Disputed)
                | (Suspended, Active)
                | (Suspended, Failed)
                | (Suspended, Cancelled)
                | (Settling, Completed)
                | (Settling, Failed)
                | (Settling, Disputed)
                | (Disputed, Active)
                | (Disputed, Failed)
                | (Disputed, Completed)
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            WorkflowStatus::Draft => "draft",
            WorkflowStatus::AwaitingSignatures => "awaiting_signatures",
            WorkflowStatus::Active => "active",
            WorkflowStatus::Suspended => "suspended",
            WorkflowStatus::Settling => "settling",
            WorkflowStatus::Completed => "completed",
            WorkflowStatus::Failed => "failed",
            WorkflowStatus::Disputed => "disputed",
            WorkflowStatus::Cancelled => "cancelled",
        }
    }
}

/// Pointer back to a Canton synchronizer mirror, populated when the workflow
/// is replicated via `CantonAdapter::mirror_workflow`. When `None`, the
/// workflow is Tenzro-native only.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CantonMirror {
    pub synchronizer_id: String,
    /// `tenzro::1220abcd…` — the party allocated for this workflow on the
    /// synchronizer.
    pub party: String,
    /// Active DAML contract id (the wrapper template that anchors the
    /// workflow). Updated as choice exercises advance the contract.
    pub contract_id: String,
}

/// Signature collected during `AwaitingSignatures`. Verified at the
/// `WorkflowManager::sign` entry point against `Workflow::canonical_hash()`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParticipantSignature {
    pub did: String,
    /// Ed25519 signature over `canonical_hash()`.
    pub signature: Vec<u8>,
    pub signed_by_pubkey: Vec<u8>,
    pub at: i64,
}

/// The workflow itself.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Workflow {
    pub workflow_id: WorkflowId,
    /// Optional pointer to the on-chain template that produced this workflow.
    pub template_id: Option<TemplateId>,
    /// DID of the creator. Always present in `participants` as `Initiator`.
    pub creator: String,
    pub title: String,
    /// Free-form description; not part of the canonical hash.
    pub description: Option<String>,
    pub participants: Vec<Participant>,
    /// Obligation ids — full obligation records live in the obligation index.
    pub obligations: Vec<ObligationId>,
    pub approval_gates: Vec<ApprovalGate>,
    /// Catch-all policy applied at the workflow boundary (in addition to any
    /// per-gate `triggers`). Empty `Allow` = no catch-all.
    pub root_policy: PolicyExpr,
    /// Optional privacy-domain envelope for receipts emitted by this
    /// workflow.
    pub privacy_domain: Option<PrivacyDomainId>,
    /// Optional fee-route applied to settlements emitted by this workflow.
    pub fee_route: Option<FeeRouteId>,
    /// Collected signatures; gates `AwaitingSignatures → Active`.
    pub signatures: Vec<ParticipantSignature>,
    pub status: WorkflowStatus,
    pub canton_mirror: Option<CantonMirror>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl Workflow {
    /// Deterministic id derived from creator + title + creation timestamp.
    /// The same `(creator, title, created_at)` tuple is required to be unique
    /// per creator — enforced at the manager.
    pub fn derive_id(creator: &str, title: &str, created_at: i64) -> WorkflowId {
        let mut h = Sha256::new();
        h.update(b"tenzro/workflow/id");
        h.update((creator.len() as u32).to_le_bytes());
        h.update(creator.as_bytes());
        h.update((title.len() as u32).to_le_bytes());
        h.update(title.as_bytes());
        h.update(created_at.to_le_bytes());
        Hash::from(<[u8; 32]>::from(h.finalize()))
    }

    /// Canonical hash that participants sign. Excludes mutable fields
    /// (`signatures`, `status`, `canton_mirror`, `updated_at`) so the same
    /// composition produces the same preimage regardless of who's signed yet.
    pub fn canonical_hash(&self) -> Hash {
        let mut h = Sha256::new();
        h.update(b"tenzro/workflow/canonical");
        h.update(self.workflow_id.as_bytes());
        if let Some(t) = &self.template_id {
            h.update(b"tpl");
            h.update(t.as_bytes());
        }
        h.update((self.creator.len() as u32).to_le_bytes());
        h.update(self.creator.as_bytes());
        h.update((self.title.len() as u32).to_le_bytes());
        h.update(self.title.as_bytes());
        h.update((self.participants.len() as u32).to_le_bytes());
        for p in &self.participants {
            h.update((p.did.len() as u32).to_le_bytes());
            h.update(p.did.as_bytes());
        }
        h.update((self.obligations.len() as u32).to_le_bytes());
        for o in &self.obligations {
            h.update(o.as_bytes());
        }
        h.update((self.approval_gates.len() as u32).to_le_bytes());
        for g in &self.approval_gates {
            h.update(g.gate_id.as_bytes());
        }
        // root_policy: hash its serialized form.
        let policy_bytes = serde_json::to_vec(&self.root_policy).unwrap_or_default();
        h.update((policy_bytes.len() as u32).to_le_bytes());
        h.update(&policy_bytes);
        if let Some(d) = &self.privacy_domain {
            h.update(b"pd");
            h.update(d.as_bytes());
        }
        if let Some(f) = &self.fee_route {
            h.update(b"fr");
            h.update(f.as_bytes());
        }
        h.update(self.created_at.to_le_bytes());
        Hash::from(<[u8; 32]>::from(h.finalize()))
    }

    /// `true` once every participant DID has at least one matching signature.
    pub fn has_all_signatures(&self) -> bool {
        self.participants.iter().all(|p| {
            self.signatures.iter().any(|s| s.did == p.did)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::participant::ParticipantRole;

    fn mk(creator: &str, title: &str, created_at: i64) -> Workflow {
        let id = Workflow::derive_id(creator, title, created_at);
        Workflow {
            workflow_id: id,
            template_id: None,
            creator: creator.into(),
            title: title.into(),
            description: None,
            participants: vec![
                Participant::new(creator, vec![ParticipantRole::Initiator]),
                Participant::new("did:tenzro:human:bob:1", vec![ParticipantRole::Counterparty]),
            ],
            obligations: vec![],
            approval_gates: vec![],
            root_policy: PolicyExpr::Allow,
            privacy_domain: None,
            fee_route: None,
            signatures: vec![],
            status: WorkflowStatus::Draft,
            canton_mirror: None,
            created_at,
            updated_at: created_at,
        }
    }

    #[test]
    fn derive_id_deterministic() {
        let a = Workflow::derive_id("alice", "swap", 100);
        let b = Workflow::derive_id("alice", "swap", 100);
        assert_eq!(a, b);
        let c = Workflow::derive_id("alice", "swap", 101);
        assert_ne!(a, c);
    }

    #[test]
    fn canonical_hash_excludes_signatures_and_status() {
        let mut wf = mk("did:tenzro:human:alice:1", "swap", 100);
        let h1 = wf.canonical_hash();
        wf.status = WorkflowStatus::Active;
        wf.updated_at = 999;
        wf.signatures.push(ParticipantSignature {
            did: "did:tenzro:human:alice:1".into(),
            signature: vec![1; 64],
            signed_by_pubkey: vec![2; 32],
            at: 200,
        });
        let h2 = wf.canonical_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn transition_table() {
        use WorkflowStatus::*;
        assert!(Draft.can_transition_to(AwaitingSignatures));
        assert!(AwaitingSignatures.can_transition_to(Active));
        assert!(Active.can_transition_to(Settling));
        assert!(Settling.can_transition_to(Completed));
        assert!(!Completed.can_transition_to(Active));
        assert!(!Cancelled.can_transition_to(Active));
        assert!(Disputed.can_transition_to(Active));
    }

    #[test]
    fn signatures_completion() {
        let mut wf = mk("did:tenzro:human:alice:1", "swap", 100);
        assert!(!wf.has_all_signatures());
        wf.signatures.push(ParticipantSignature {
            did: "did:tenzro:human:alice:1".into(),
            signature: vec![],
            signed_by_pubkey: vec![],
            at: 0,
        });
        assert!(!wf.has_all_signatures());
        wf.signatures.push(ParticipantSignature {
            did: "did:tenzro:human:bob:1".into(),
            signature: vec![],
            signed_by_pubkey: vec![],
            at: 0,
        });
        assert!(wf.has_all_signatures());
    }
}
