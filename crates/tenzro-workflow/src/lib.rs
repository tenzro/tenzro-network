//! `tenzro-workflow` — multi-party workflow primitive.
//!
//! A `Workflow` is a typed container that owns:
//!
//! - `Participant`s with `ParticipantRole`s,
//! - `Obligation`s tied to typed `DischargeProofKind`s,
//! - `ApprovalGate`s wired to a composite `PolicyExpr` and `ApproverSet`,
//! - a `WorkflowStatus` lifecycle with full `LifecycleTransition` history,
//! - optional `CantonMirror` pointer for replication to a Canton synchronizer,
//! - optional `PrivacyDomainId` and `FeeRouteId` references.
//!
//! `WorkflowManager` owns the in-memory indices (`DashMap` per surface)
//! and writes through to RocksDB (`CF_SETTLEMENTS` and `CF_APPROVALS`) via
//! `write_batch_sync` for fsync durability — same path used by the rest of
//! the settlement subsystem.
//!
//! ### Module map
//!
//! - [`workflow`] — `Workflow`, `WorkflowStatus`, `CantonMirror`, `ParticipantSignature`
//! - [`participant`] — `Participant`, `ParticipantRole`
//! - [`obligation`] — `Obligation`, `ObligationStatus`, `ObligationKind`, `DischargeProof`
//! - [`approval`] — `ApprovalGate`, `ApprovalRequest`, `ApprovalDecision`, `ApproverSet`
//! - [`policy_dsl`] — composite `PolicyExpr`, pure `evaluate(expr, ctx)` evaluator
//! - [`lifecycle`] — `LifecycleTransition`, `TransitionTrigger`, `KillSwitchScope`
//! - [`receipt`] — `WorkflowReceipt` projecting to `tenzro_storage::da::ReceiptEnvelope`
//! - [`manager`] — `WorkflowManager` with persistence + indices
//! - [`error`] — `WorkflowError`, `Result`

pub mod approval;
pub mod attested_clock;
pub mod codegen;
pub mod error;
pub mod fee_route;
pub mod idempotency;
pub mod lifecycle;
pub mod manager;
pub mod metrics;
pub mod obligation;
pub mod participant;
pub mod policy_dsl;
pub mod privacy;
pub mod receipt;
pub mod workflow;

pub use approval::{
    ApprovalDecision, ApprovalGate, ApprovalGateId, ApprovalRequest, ApprovalRequestId,
    ApprovalStatus, ApproverSet, Decision, DelegationScopeShim, TimeoutBehavior,
};
pub use codegen::{DamlArgField, DamlMap, ObligationChoiceMap, WorkflowDamlCodegen};
pub use error::{Result, WorkflowError};
pub use fee_route::{FeeRoute, FeeRouteRegistry, FeeSplit};
pub use lifecycle::{KillSwitchScope, LifecycleTransition, TransitionTrigger};
pub use manager::WorkflowManager;
pub use metrics::OperationalMetrics;
pub use obligation::{
    AssetRef, DischargeProof, DischargeProofKind, Obligation, ObligationId, ObligationKind,
    ObligationStatus,
};
pub use participant::{Participant, ParticipantRole};
pub use policy_dsl::{
    ApproverSpec, IdentityLookup, NullLookup, PolicyContext, PolicyExpr, PolicyVerdict, evaluate,
};
pub use privacy::{
    AclDecision, AddressedEnvelope, EncryptedReceipt, PrivacyDomain, PrivacyDomainRegistry,
    PrivacyRecipient, acl_check,
};
pub use receipt::{WorkflowEventKind, WorkflowReceipt, WorkflowReceiptId};
pub use workflow::{
    CantonMirror, FeeRouteId, ParticipantSignature, PrivacyDomainId, TemplateId, Workflow,
    WorkflowId, WorkflowStatus,
};
