//! # Tenzro authentication & authorization
//!
//! **OAuth 2.1 + DPoP + RAR** authentication for the Tenzro node. Every
//! issued token is bound to (a) a TDIP DID, (b) a holder-of-key proof
//! (RFC 9449), and (c) an explicit, narrowly-scoped authorization request
//! (RFC 9396).
//!
//! ## Design principles
//!
//! 1. **Proof-of-possession, not bearer.** Every JWT carries a `cnf` claim
//!    with the SHA-256 (RFC 7638) thumbprint of the holder's public key.
//!    Every protected request must carry a fresh `DPoP` header signed by
//!    that key. A token presented without a matching DPoP proof is
//!    rejected even if the JWT signature validates — possession of the
//!    JWT alone grants nothing.
//! 2. **Narrow, additive scopes.** Authorization is expressed as RAR
//!    `authorization_details` entries — typed envelopes such as
//!    `{type: "transfer", asset: "TNZO", max_amount: 1_000_000_000_000_000_000}`.
//!    A request is permitted only if some grant strictly covers it.
//!    There is no implicit fallback, no `"all"` shorthand, no string
//!    scope.
//! 3. **No private keys on the wire.** Onboarding RPCs return a JWT bound
//!    to a key the caller already controls (the DPoP key). Signing flows
//!    consume that JWT plus a per-request DPoP proof; the node never sees
//!    or stores user signing material.
//!
//! ## Public API surface
//!
//! | Type / fn                          | Role                                            |
//! |------------------------------------|-------------------------------------------------|
//! | [`AuthEngine`]                     | Singleton owned by `TenzroNode`; issues, validates, and revokes JWTs |
//! | [`AuthEngine::issue_jwt`]          | Mints a DPoP-bound JWT for an onboarded identity |
//! | [`AuthEngine::validate_jwt`]       | Validates a JWT + DPoP proof against scope and binding |
//! | [`AuthEngine::revoke`]             | Revokes a single JWT, cascading through the act-chain (see §Revocation) |
//! | [`AuthEngine::resolve_authority`]  | Walks DID → controller chain; returns the signing DID + delegation envelope |
//! | [`AuthEngine::record_audit`]       | Append-only audit log in `CF_AUDIT`             |
//! | [`AuthEngine::record_approval`]    | HITL approval cache in `CF_APPROVALS`           |
//! | [`AuthClaims`]                     | JWT body: `cnf`, `authorization_details`, `controller_did`, `act` |
//! | [`AuthorizationDetails`] (RAR)     | Typed scope envelopes per RFC 9396              |
//! | [`DpopProof`]                      | RFC 9449 DPoP-Proof header parser               |
//! | [`AuthError`]                      | Typed errors over `NodeError::AuthError`        |
//!
//! ### What this crate does NOT do
//!
//! - **Does not provision identities or wallets.** Onboarding RPCs
//!   (`tenzro_onboardHuman` / `tenzro_onboardDelegatedAgent` /
//!   `tenzro_onboardAutonomousAgent`, subtask #52) live in
//!   `tenzro-node::rpc` and call into [`AuthEngine::issue_jwt`] *after*
//!   identity + wallet provisioning. This crate is auth, not identity.
//! - **Does not perform signing.** The new ambient-auth signing path
//!   (subtask #51) lives in `tenzro-node::rpc`; it asks this crate
//!   "is the bearer of this JWT authorized to sign for DID X up to amount
//!   Y?" and gets back a yes/no plus a wallet handle.
//! - **Does not implement the OAuth /authorize HTML flow.** The MCP
//!   server's HTTP endpoints stay in `mcp/oauth.rs`; they will be slimmed
//!   to thin shims that delegate to this crate. The /token endpoint
//!   forwards the DPoP proof to [`AuthEngine::validate_dpop`] and the
//!   client_id+code to [`AuthEngine::issue_jwt`].
//!
//! ## Trust model & invariants
//!
//! 1. **Issuer is the node.** Every JWT is HS256-signed with a
//!    per-node-instance secret derived from its identity keypair. We do
//!    *not* support cross-node JWT validation in V1 — a token issued by
//!    node A must be presented to node A. (Cross-node trust is a future
//!    workstream that needs validator-quorum signing; we don't do it
//!    half-way.)
//! 2. **DPoP binds the token to a key.** Every issued JWT carries a `cnf`
//!    (confirmation) claim with the SHA-256 thumbprint of the holder's
//!    public key. Every protected request must carry a fresh `DPoP`
//!    header signed by that key over `(htm, htu, iat, jti, ath)`. A
//!    bearer-only request is rejected even if the JWT validates.
//! 3. **RAR scopes are *additive*, not declarative.** A token's
//!    `authorization_details` is a list of explicit grants
//!    (`{type: "transfer", asset: "TNZO", max_amount: 1_000_000_000_000_000_000}`).
//!    The auth engine answers "is action X permitted?" by searching for a
//!    grant that strictly *covers* X. Anything unmatched is denied. There
//!    is no implicit fallback, no string scope, no `"all"` shorthand.
//! 4. **Cascading revocation by act-chain.** Revoking a JWT also revokes
//!    every JWT whose `controller_did` points back at the revoked DID,
//!    transitively. (Subtask #54 implements the recursion; this crate's
//!    storage layout supports it via the `controller_did:<did>`
//!    secondary index in `CF_AUDIT`.)
//! 5. **HITL approvals are append-only.** When a request requires human
//!    approval (e.g., spend > delegation_scope max), the engine records
//!    the request in `CF_APPROVALS` and returns
//!    `AuthError::ApprovalRequired { approval_id }`. The human approves
//!    or denies via a separate RPC; the approval record is never mutated
//!    after creation, only marked `Approved` / `Denied` / `Expired` via
//!    a status field that itself appends a new history entry.
//!
//! ## Storage layout (CF_AUDIT, CF_APPROVALS)
//!
//! Both column families are added in subtask #49.
//!
//! ### `CF_AUDIT` — append-only event log
//!
//! - `audit:<ulid>` → JSON-encoded [`AuditEvent`]. ULIDs sort
//!   lexicographically by time, so prefix scans return events in order
//!   without an explicit timestamp index.
//! - `audit_did:<did>:<ulid>` → empty value, secondary index for
//!   "all events for this DID."
//! - `audit_jti:<jti>` → ULID of the issuance event for the JWT with
//!   this JTI. Used by revocation: revoke-by-JTI looks up the issuance
//!   record to find the bound DID, then writes a new revocation event.
//!
//! ### `CF_APPROVALS` — HITL approval state
//!
//! - `approval:<approval_id>` → JSON [`ApprovalRecord`].
//! - `approval_pending:<approver_did>:<approval_id>` → empty, secondary
//!   index for "what's in my approval queue."
//!
//! ## Threading
//!
//! `AuthEngine` is `Send + Sync` and all methods take `&self`. Internal
//! state uses `dashmap` for hot caches (recent JWTs, recent DPoP nonces
//! for replay protection) and writes through to RocksDB via
//! [`tenzro_storage::KvStore::write_batch_sync`] for durability — the
//! same write-through pattern as `EscrowManager::with_storage`,
//! `ModelRegistry::with_storage`, etc.
//!
//! ## Testing strategy
//!
//! Each public method has a unit test. The combined onboarding +
//! signing + revocation flows are covered by an integration test in
//! `crates/tenzro-node/tests/auth_integration.rs` (subtask #56).

#![deny(missing_docs)]
#![deny(unsafe_code)]

mod aap;
mod admission;
mod claims;
mod dpop;
mod engine;
mod error;
mod exchange;
mod introspect;
mod rar;
mod storage;
mod util;

pub use aap::{
    AapAgentClaim, AapAuditClaim, AapCapabilityClaim, AapConstraints, AapContextClaim,
    AapDelegationClaim, AapOversightClaim, AapTaskClaim, AapTimeWindow, authority_action_to_aap,
    is_valid_action_name, rar_to_aap_action,
};
pub use admission::{
    Admission, AdmissionPolicy, NEVER_GATED_PATHS, ServiceKeyGrant, ServiceKeyHash, ServiceSurface, admit,
    is_never_gated,
};
pub use claims::{AuthClaims, Cnf};
pub use dpop::{DpopProof, DpopVerification};
pub use engine::{
    AapOverrides, AuthEngine, AuthEngineConfig, AuthorityAction, AuthorityDecision,
    AuthorityRequest, DpopValidation,
};
pub use error::{AuthError, Result};
pub use exchange::{
    TokenExchangeOutcome, TokenExchangeRequest, aap_capabilities_is_subset, detail_covers,
    rar_is_subset,
};
pub use introspect::IntrospectionResponse;
pub use rar::{AuthorizationDetail, AuthorizationDetails, ResourceConstraint};
pub use storage::{ApprovalRecord, ApprovalStatus, AuditEvent, AuditEventKind, RefreshTokenEntry};
pub use util::peek_unverified_jti;
