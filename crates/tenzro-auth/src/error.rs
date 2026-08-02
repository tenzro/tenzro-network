//! Error types for `tenzro-auth`.
//!
//! All public methods of [`crate::AuthEngine`] return `Result<T, AuthError>`.
//! `AuthError` is the typed replacement for the previous
//! `NodeError::AuthError(String)` opaque variant: each variant identifies a
//! distinct failure class so that the RPC layer can map it to the correct
//! JSON-RPC error code, and so that callers can match on the variant
//! programmatically (e.g., `ApprovalRequired { approval_id }` is *not* a
//! terminal failure — it tells the caller to surface the approval flow to
//! the human).

use thiserror::Error;

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, AuthError>;

/// All errors produced by the `tenzro-auth` engine.
#[derive(Debug, Error)]
pub enum AuthError {
    /// The presented JWT is structurally malformed, fails signature
    /// validation against the node-instance issuer secret, or carries
    /// claims that this validator rejects (wrong `iss`, wrong `aud`, etc.).
    #[error("invalid token: {0}")]
    InvalidToken(String),

    /// The token validates cryptographically but its lifetime is over —
    /// `exp` is in the past or `nbf` is in the future.
    #[error("token expired or not yet valid")]
    TokenExpired,

    /// The token has been explicitly revoked, either directly (revoke by
    /// JTI) or transitively (revoke by `controller_did` cascaded down the
    /// act-chain).
    #[error("token revoked: {0}")]
    TokenRevoked(String),

    /// A `DPoP` proof header is missing, malformed, or fails verification
    /// (wrong `htm`/`htu`, replayed `jti`, signature mismatch against the
    /// `cnf.jkt` thumbprint).
    #[error("invalid DPoP proof: {0}")]
    InvalidDpop(String),

    /// The token validates and the DPoP proof verifies, but the requested
    /// action falls outside the token's `authorization_details` (RAR)
    /// envelope. Carries a human-readable description of the gap.
    #[error("insufficient authorization: {0}")]
    InsufficientAuthorization(String),

    /// The requested action is permitted by the token's RAR envelope and
    /// by the controller's delegation scope, but the engine policy
    /// requires explicit human approval before signing. The caller should
    /// surface `approval_id` to the human approver and retry once
    /// approved.
    #[error("approval required: {approval_id}")]
    ApprovalRequired {
        /// Identifier of the pending [`crate::ApprovalRecord`] in
        /// `CF_APPROVALS`. The human approver acts on this id.
        approval_id: String,
    },

    /// The requested action references a DID that does not exist in the
    /// local identity registry, or whose controller chain cannot be
    /// resolved all the way back to a root controller.
    #[error("unknown DID: {0}")]
    UnknownDid(String),

    /// The bearer's DID is known but is not authorized to act for the
    /// target DID — i.e., the controller chain does not transitively
    /// reach the target, or a delegation envelope along the chain has
    /// been revoked.
    #[error("not authorized for DID: bearer={bearer}, target={target}")]
    NotAuthorizedForDid {
        /// DID extracted from the JWT's `sub` claim.
        bearer: String,
        /// DID the bearer attempted to act on behalf of.
        target: String,
    },

    /// The action is permitted by the RAR envelope but exceeds the
    /// controller-attested [`tenzro_identity`] `DelegationScope`
    /// (e.g., daily-spend cap, max-transaction value, allowed-operation
    /// list). Carries the specific violation reason.
    #[error("delegation scope violation: {0}")]
    DelegationViolation(String),

    /// The caller is recognized but does not have authority to perform
    /// this specific operation — e.g., a DID other than the named
    /// `approver_did` attempting to decide an HITL approval, or a caller
    /// trying to consume an approval that is not in `Approved` state.
    /// Distinct from `NotAuthorizedForDid` (which is about act-chain
    /// reach) and `InsufficientAuthorization` (which is about the RAR
    /// envelope shape).
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// A storage backend operation failed (RocksDB read/write error,
    /// serialization failure, etc.). These are retryable but indicate
    /// node-local trouble, not caller error.
    #[error("storage error: {0}")]
    Storage(String),

    /// A token issuance call carried a malformed scope shape — e.g.,
    /// an AAP capability with an action name that doesn't satisfy the
    /// ABNF, or an `aap_context.time_window.exp` past `claims.exp`.
    /// Distinct from `InsufficientAuthorization` (runtime adjudication
    /// failure) — `InvalidScope` is a *construction* failure.
    #[error("invalid scope: {0}")]
    InvalidScope(String),

    /// JWT encoding or decoding (the lower-level `jsonwebtoken` crate)
    /// returned an error before claim validation could even begin.
    #[error("JWT codec error: {0}")]
    Codec(String),

    /// Internal invariant violation — should never happen in practice.
    /// If you see one of these, file a bug.
    #[error("internal auth error: {0}")]
    Internal(String),
}

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(e: jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;
        match e.kind() {
            ErrorKind::ExpiredSignature => AuthError::TokenExpired,
            ErrorKind::InvalidSignature
            | ErrorKind::InvalidToken
            | ErrorKind::InvalidAlgorithm
            | ErrorKind::InvalidAudience
            | ErrorKind::InvalidIssuer
            | ErrorKind::InvalidSubject => AuthError::InvalidToken(e.to_string()),
            _ => AuthError::Codec(e.to_string()),
        }
    }
}

impl From<serde_json::Error> for AuthError {
    fn from(e: serde_json::Error) -> Self {
        AuthError::Codec(format!("serde_json: {}", e))
    }
}
