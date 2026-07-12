//! JWT claim shapes for `tenzro-auth`.
//!
//! [`AuthClaims`] is the typed body of every JWT we issue. It extends the
//! standard OAuth/JWT claim set with three Tenzro-specific additions:
//!
//! - **`cnf`** ([`Cnf`]) — RFC 7800 confirmation claim binding the token
//!   to a public key by SHA-256 thumbprint. Every protected request must
//!   carry a fresh DPoP proof signed by that key.
//! - **`controller_did`** — the *authorizing* DID. For autonomous-agent
//!   tokens this is the agent itself (controller_did == sub); for
//!   delegated-agent tokens this is the human or parent agent that
//!   spawned the bearer. The cascading-revocation index in `CF_AUDIT` is
//!   keyed by this field.
//! - **`authorization_details`** — an embedded RFC 9396 RAR envelope
//!   ([`crate::AuthorizationDetails`]) — the *only* source of truth for
//!   what the bearer may do. There is no `scope` field.
//!
//! ## Why no `scope`
//!
//! Plain OAuth `scope` is a flat space-separated string ("read write
//! admin"). It cannot carry per-grant constraints ("transfer up to 1
//! TNZO to address X but not Y"). Mixing `scope` and `authorization_details`
//! is a known footgun (see RFC 9396 §13). We pick one — the typed one —
//! and reject any token carrying a legacy `scope` field.

use crate::aap::{
    AapAgentClaim, AapAuditClaim, AapCapabilityClaim, AapContextClaim, AapDelegationClaim,
    AapOversightClaim, AapTaskClaim,
};
use crate::rar::AuthorizationDetails;
use serde::{Deserialize, Serialize};

/// The full body of a Tenzro auth JWT.
///
/// Field order is fixed (sub → iss → aud → iat → nbf → exp → jti → cnf →
/// controller_did → authorization_details) so that JSON serialization is
/// stable across nodes — important for `audit:<ulid>` hashing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthClaims {
    /// Subject — the bearer DID. The bearer is the entity that holds
    /// the DPoP private key matching `cnf.jkt`.
    pub sub: String,

    /// Issuer — always the local node's DID (or, equivalently, the
    /// node-instance issuer identifier configured in
    /// [`crate::AuthEngineConfig`]). V1 does not support cross-node
    /// validation: a token issued by node A is rejected by node B.
    pub iss: String,

    /// Audience — typically the resource server URL (e.g.,
    /// `"https://rpc.tenzro.xyz"`). Used in conjunction with the
    /// DPoP `htu` field to bind a token to a specific deployment.
    pub aud: String,

    /// Issued-at, Unix seconds.
    pub iat: u64,

    /// Not-before, Unix seconds. Usually equal to `iat`.
    pub nbf: u64,

    /// Expires-at, Unix seconds. Tokens are short-lived (default 1h);
    /// long-running agents refresh via [`crate::AuthEngine::issue_jwt`].
    pub exp: u64,

    /// JWT id — UUIDv4 hex. Doubles as the revocation key
    /// (`audit_jti:<jti>` → ULID of the issuance event).
    pub jti: String,

    /// RFC 7800 confirmation claim binding the token to a public key.
    /// Omitted entirely when the token is **not** DPoP-bound — per RFC
    /// 9449 §6 a missing `cnf` claim means "bearer-only token, no proof
    /// of possession required". Callers receive a non-DPoP token when
    /// they onboard without supplying a `dpop_jkt` thumbprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cnf: Option<Cnf>,

    /// The DID that authorized this token. For an autonomous-agent
    /// token, `controller_did == sub`. For a delegated-agent token,
    /// `controller_did` is the parent (human or upstream agent) that
    /// spawned the bearer.
    ///
    /// The cascading-revocation index uses this field: revoking
    /// `controller_did = X` revokes every token whose `controller_did`
    /// (transitively) reaches X.
    pub controller_did: String,

    /// RFC 9396 typed scope envelope — the only source of authorization
    /// truth. See [`crate::AuthorizationDetails`].
    pub authorization_details: AuthorizationDetails,

    /// AAP `aap_agent` claim — bearer agent identity and runtime
    /// metadata. Optional; absent on plain RAR tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aap_agent: Option<AapAgentClaim>,

    /// AAP `aap_task` claim — purpose binding. Optional but
    /// recommended for production agent tokens; the RS uses it to
    /// reject requests that don't match the declared task.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aap_task: Option<AapTaskClaim>,

    /// AAP `aap_capabilities` claim — typed action grants with
    /// per-action constraints. Layered on top of
    /// `authorization_details`: a request must satisfy *both* the
    /// RAR envelope and the AAP capability set when both are
    /// present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aap_capabilities: Option<Vec<AapCapabilityClaim>>,

    /// AAP `aap_oversight` claim — actions that require human
    /// approval. Triggers
    /// [`crate::AuthorityDecision::RequireApproval`] when an
    /// inbound request's action is on the list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aap_oversight: Option<AapOversightClaim>,

    /// AAP `aap_delegation` claim — position in the act-chain.
    /// Token Exchange (RFC 8693) increments `depth` and appends to
    /// `chain` when minting a child token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aap_delegation: Option<AapDelegationClaim>,

    /// AAP `aap_context` claim — operational context (network zone,
    /// inner time window, geo restriction).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aap_context: Option<AapContextClaim>,

    /// AAP `aap_audit` claim — observability hooks (trace_id,
    /// session_id, log_level). Forwarded to `tracing::span` for
    /// cross-system correlation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aap_audit: Option<AapAuditClaim>,
}

/// RFC 7800 §3.1 confirmation method — public-key thumbprint binding.
///
/// We support exactly one mechanism: `jkt` (JWK SHA-256 thumbprint per
/// RFC 7638). Other variants from RFC 7800 (`jwk`, `kid`, `x5t#S256`)
/// are deliberately excluded — `jkt` is the unambiguously correct
/// choice for DPoP per RFC 9449 §6.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cnf {
    /// Base64url(SHA-256(JWK canonical JSON)) of the holder's DPoP
    /// public key. Computed via [`crate::DpopProof::compute_jkt`] when
    /// the holder generates the key, and stored verbatim in the token.
    pub jkt: String,
}
