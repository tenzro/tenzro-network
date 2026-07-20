//! Persistent state shapes for `tenzro-auth`.
//!
//! `tenzro-auth` writes through to two RocksDB column families
//! ([`tenzro_storage::CF_AUDIT`] and [`tenzro_storage::CF_APPROVALS`])
//! via [`tenzro_storage::KvStore::write_batch_sync`] for durability —
//! the same write-through pattern as `EscrowManager::with_storage` and
//! the rest of the settlement subsystem.
//!
//! ## Design rationale
//!
//! - **Audit is append-only.** We never delete an audit row. Even
//!   revocations are recorded as new events (`AuditEventKind::Revoked`),
//!   not as in-place mutations of the issuance row. This makes the log
//!   safe to share with regulators and lets us implement
//!   "explain why this token was rejected" by walking the chain.
//!
//! - **Approvals have a status field but never lose history.** When a
//!   human approves or denies a pending request, we update the
//!   [`ApprovalRecord::status`] field — but the engine *also* writes a
//!   new [`AuditEvent`] for the decision, so the immutable record of
//!   "X approved Y at T" survives in the audit log.
//!
//! - **ULIDs as event ids.** ULIDs sort lexicographically by time, so
//!   `prefix_iterator_cf("audit:")` returns events in chronological
//!   order without an explicit timestamp index.
//!
//! - **Secondary indices live in CF_AUDIT.** `audit_did:<did>:<ulid>`
//!   gives "all events for this DID"; `audit_jti:<jti>` gives "issuance
//!   ULID for this JWT id". Both have empty values — they exist only as
//!   prefix-iteration anchors.

use crate::rar::AuthorizationDetails;
use serde::{Deserialize, Serialize};

/// One row in `CF_AUDIT`. Stored under the key `audit:<ulid>`; the same
/// row is referenced by `audit_did:<did>:<ulid>` and (for issuance
/// events) `audit_jti:<jti>` index entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    /// ULID of this event (also the primary key suffix). Encoded as
    /// the standard 26-character Crockford-base32 string.
    pub event_id: String,

    /// Unix timestamp in milliseconds. Redundant with the ULID but
    /// exposed explicitly so consumers don't need to decode.
    pub timestamp_ms: u64,

    /// Bearer DID — the `sub` of the affected JWT (or, for
    /// approval events, the requesting DID).
    pub bearer_did: String,

    /// Authorizing DID — the `controller_did` of the affected JWT.
    /// Equal to `bearer_did` for autonomous-agent tokens.
    pub controller_did: String,

    /// JWT id, when applicable.
    pub jti: Option<String>,

    /// Discriminated event payload.
    pub kind: AuditEventKind,
}

/// Discriminated payload of an [`AuditEvent`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuditEventKind {
    /// A new JWT was issued.
    #[serde(rename = "issued")]
    Issued {
        /// The full RAR envelope embedded in the issued token (so the
        /// audit log captures *what* was authorized, not just *who*).
        authorization_details: AuthorizationDetails,
        /// JWT expiration (Unix seconds).
        expires_at: u64,
    },

    /// A JWT was successfully validated against an incoming request.
    /// We log validations sparingly — see [`crate::AuthEngineConfig`]
    /// for the sampling knob — but every *failed* validation is logged.
    #[serde(rename = "validated")]
    Validated {
        /// The DPoP `htm` of the validated request (e.g., "POST").
        method: String,
        /// The DPoP `htu` of the validated request (URI without query).
        uri: String,
    },

    /// A JWT validation failed. Captured for security monitoring.
    #[serde(rename = "validation_failed")]
    ValidationFailed {
        /// Free-text reason — surface of the underlying [`crate::AuthError`].
        reason: String,
    },

    /// A JWT was explicitly revoked. The cascading-revocation algorithm
    /// reads this row to decide which downstream tokens to also revoke.
    #[serde(rename = "revoked")]
    Revoked {
        /// Whether this revocation was direct (revoke-by-jti) or
        /// cascaded from a parent revocation.
        cascaded: bool,
        /// If `cascaded`, the upstream `event_id` that triggered this.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent_event_id: Option<String>,
        /// Reason recorded by the caller (free-form).
        reason: String,
    },

    /// A signing decision was made on the bearer's behalf. Either the
    /// VM-mediated transfer / escrow create / etc. went through, or
    /// (for HITL flows) the engine deferred to an [`ApprovalRecord`].
    #[serde(rename = "signed")]
    Signed {
        /// Hash of the canonical signed transaction bytes (hex-encoded).
        tx_hash: String,
        /// Asset and amount, free-form ("TNZO/1000000000000000000" =
        /// "1 TNZO"), captured for audit summaries.
        summary: String,
    },

    /// A HITL approval was recorded (created, approved, denied, or
    /// expired). The `event_id` of this audit row lives independently
    /// of the [`ApprovalRecord`] in `CF_APPROVALS`; the two together
    /// form the immutable history.
    #[serde(rename = "approval")]
    Approval {
        /// Approval id.
        approval_id: String,
        /// New status of the approval after this event.
        new_status: ApprovalStatus,
    },
}

/// One row in `CF_APPROVALS`, stored under `approval:<approval_id>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalRecord {
    /// UUIDv4 string identifying the approval.
    pub approval_id: String,

    /// Bearer DID — the agent or human that *requested* the action.
    pub requester_did: String,

    /// Approver DID — the human (or upstream agent) whose approval is
    /// required. Indexed in `approval_pending:<approver_did>:<approval_id>`.
    pub approver_did: String,

    /// Unix timestamp in milliseconds when the request was created.
    pub created_at_ms: u64,

    /// Unix timestamp in milliseconds after which the request is
    /// considered expired (regardless of approver action).
    pub expires_at_ms: u64,

    /// The RAR detail describing the action that needs approval.
    /// Captured verbatim so the approver sees exactly what they're
    /// signing off on.
    pub action: crate::rar::AuthorizationDetail,

    /// Free-form caller-supplied summary ("Pay 50 TNZO to acme.eth for
    /// invoice #1234"). Surfaced verbatim to the approver UI.
    pub summary: String,

    /// Current status. Updated in place when the approver acts; the
    /// transition itself is also recorded as an [`AuditEvent`] for
    /// immutability.
    pub status: ApprovalStatus,

    /// Set once the approver acts (or on expiry).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at_ms: Option<u64>,
}

/// Lifecycle of a [`ApprovalRecord`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalStatus {
    /// Request is open and awaiting an approver decision.
    Pending,
    /// Approver explicitly approved. The engine will permit the
    /// underlying action exactly once (the approval is single-use).
    Approved,
    /// Approver explicitly denied.
    Denied,
    /// `expires_at_ms` passed before the approver acted.
    Expired,
    /// The action was carried out after approval — the approval has
    /// been "spent" and may not be reused.
    Consumed,
}

/// One row representing an opaque refresh token, stored in `CF_AUDIT`
/// under the key `auth_refresh:<token>`. Refresh tokens are UUIDs, not
/// JWTs — they exchange at the `/token` endpoint (or the
/// `tenzro_refreshToken` RPC) for a fresh access JWT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshTokenEntry {
    /// The opaque refresh-token value (UUIDv4, also the storage key
    /// suffix).
    pub token: String,
    /// Bearer DID — what the new access JWT's `sub` will be.
    pub bearer_did: String,
    /// Authorizing DID — what the new access JWT's `controller_did`
    /// will be. Equal to `bearer_did` for autonomous-agent tokens.
    pub controller_did: String,
    /// DPoP key thumbprint that the refreshed access JWT must be
    /// pinned to. `None` only on flows where DPoP is not yet enforced.
    pub dpop_jkt: Option<String>,
    /// The full RAR envelope to embed in every access JWT minted from
    /// this refresh token. Persisted verbatim so the original
    /// authorization grant is preserved across refreshes.
    pub authorization_details: AuthorizationDetails,
    /// Unix seconds when this refresh token expires. After this point
    /// the engine returns `AuthError::TokenExpired` on exchange.
    pub expires_at: u64,
}

/// Helper: storage key for a refresh token.
pub fn refresh_token_key(token: &str) -> String {
    format!("auth_refresh:{}", token)
}

/// Helper: storage key for a DPoP replay-window entry. The value is
/// the entry's expiry as 8 little-endian bytes (Unix seconds).
pub fn dpop_replay_key(jti: &str) -> String {
    format!("auth_dpop_jti:{}", jti)
}

/// Prefix for [`dpop_replay_key`] rows — used by the hydrate scan.
pub const DPOP_REPLAY_PREFIX: &[u8] = b"auth_dpop_jti:";

/// Helper: storage key for an audit event by its primary id.
pub fn audit_key(event_id: &str) -> String {
    format!("audit:{}", event_id)
}

/// Helper: storage key for the per-DID secondary index.
pub fn audit_did_key(did: &str, event_id: &str) -> String {
    format!("audit_did:{}:{}", did, event_id)
}

/// Helper: storage key for the per-JTI secondary index.
pub fn audit_jti_key(jti: &str) -> String {
    format!("audit_jti:{}", jti)
}

/// Helper: storage key for an approval record.
pub fn approval_key(approval_id: &str) -> String {
    format!("approval:{}", approval_id)
}

/// Helper: storage key for the per-approver secondary index.
pub fn approval_pending_key(approver_did: &str, approval_id: &str) -> String {
    format!("approval_pending:{}:{}", approver_did, approval_id)
}
