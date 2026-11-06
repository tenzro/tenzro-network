//! Persistent state shapes for `tenzro-auth`.
//!
//! `tenzro-auth` writes through to the RocksDB column family
//! [`tenzro_storage::CF_AUDIT`]
//! via [`tenzro_storage::KvStore::write_batch_sync`] for durability —
//! the same write-through pattern as
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

    /// Bearer DID — the `sub` of the affected JWT.
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

    /// One access token was withdrawn by the node operator. Unlike
    /// [`Self::Revoked`] it says nothing about the bearer: the DID may sign
    /// in again.
    #[serde(rename = "token_revoked")]
    TokenRevoked {
        /// Reason recorded by the operator (free-form).
        reason: String,
    },

    /// A signing decision was made on the bearer's behalf: the
    /// VM-mediated transfer, escrow create or similar went through.
    #[serde(rename = "signed")]
    Signed {
        /// Hash of the canonical signed transaction bytes (hex-encoded).
        tx_hash: String,
        /// Asset and amount, free-form ("TNZO/1000000000000000000" =
        /// "1 TNZO"), captured for audit summaries.
        summary: String,
    },
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
