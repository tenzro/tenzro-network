//! AuthIssuer trait — the seam between `tenzro-agent-kit` and the node's
//! `tenzro-auth` engine.
//!
//! # Why a trait
//!
//! `tenzro-agent-kit` is the registry-driven runtime. It must not pull in
//! `tenzro-auth` directly — that would couple the kit to one specific
//! authentication implementation, and it would force every embedder
//! (mobile, embedded, off-node tooling) to carry the full RAR/AAP/DPoP
//! engine even when they would rather plug in a different signer
//! (passkey, HSM, KMS, third-party token service).
//!
//! Instead the kit declares the surface it needs — "mint me a
//! sender-constrained access token for this newly-spawned agent" — and
//! lets the embedder satisfy it. `tenzro-node` ships
//! [`NodeAuthIssuer`](../../tenzro-node/src/agent_kit_auth.rs) which
//! delegates to `AuthEngine::issue_jwt_with_aap`.
//!
//! # What the kit needs back
//!
//! Per RFC 9449 (DPoP), the issued credential has *two* pieces:
//!
//! 1. **Access token** (long-lived, hours): a JWT carrying the bearer's
//!    DID, the controller DID, the RAR scope envelope, and `cnf.jkt` —
//!    the SHA-256 thumbprint of the DPoP key. Sent verbatim on every
//!    request as `Authorization: DPoP <jwt>`.
//!
//! 2. **DPoP private key** (per-request use): held by the agent. For
//!    each protected RPC the agent constructs a fresh one-shot JWS
//!    (`htm`, `htu`, `iat`, `jti`, `ath`) signed by this key and
//!    attaches it in the `DPoP:` header. The verifier hashes the
//!    embedded JWK and matches it against the token's `cnf.jkt`,
//!    confirming the bearer holds the key.
//!
//! The kit therefore stores both: the JWT for the bearer header, and a
//! `DpopSigner` for per-request proof signing. Both are owned by
//! [`SpawnedAgent::credentials`](crate::SpawnedAgent::credentials) and
//! consumed by [`RegistryClient::call_raw_with_auth`](crate::RegistryClient::call_raw_with_auth).
//!
//! # Scope projection (DelegationSpec → AgentAuthRequest)
//!
//! The kit projects the template's `DelegationSpec` into a structured
//! [`AgentAuthRequest`] so the issuer can render it into whatever
//! authorization envelope it uses (RFC 9396 RAR for the node issuer,
//! plain scope strings for simpler issuers). This keeps the trait
//! agnostic of the wire format.

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::AgentKitError;

/// A request to mint a sender-constrained access token for an agent.
///
/// Constructed by `AgentSpawner::spawn` from the template's
/// `DelegationSpec` and handed to the [`AuthIssuer`].
#[derive(Debug, Clone)]
pub struct AgentAuthRequest {
    /// Bearer DID — the agent's machine DID (`did:tenzro:machine:...`).
    /// This is the `sub` of the issued token.
    pub bearer_did: String,

    /// Controller DID — the human or parent machine that minted this
    /// agent. Used for cascading revocation: revoking the controller
    /// transitively revokes every child token.
    pub controller_did: String,

    /// Per-operation value ceiling, in base units (TNZO smallest unit
    /// or asset-denominated). Projected from `DelegationSpec::max_transaction_value`.
    pub max_transaction_value: u128,

    /// Rolling-24h value ceiling, in base units. Projected from
    /// `DelegationSpec::max_daily_spend`.
    pub max_daily_spend: u128,

    /// Allowed operation names from the template's `DelegationSpec`.
    /// The issuer maps these to the appropriate RAR detail variants
    /// (e.g. `"transfer"` → `Transfer { … }`, `"stake"` → `Stake { … }`,
    /// `"bridge"` / `"deposit"` / `"swap"` → `Transfer { … }` against
    /// the default asset).
    pub allowed_operations: Vec<String>,

    /// Allowed chain ids from the template's `DelegationSpec`. The
    /// issuer encodes these as the `network` field of the relevant
    /// RAR details, or — if its envelope has no chain field — declines
    /// to issue when the requested operation set crosses chains the
    /// caller cannot prove authority on.
    pub allowed_chains: Vec<String>,

    /// Token lifetime cap, in seconds. The issuer clamps to its own
    /// `max_ttl_secs`. Spawner default: `7 * 24 * 3600` (one week) —
    /// long enough for a multi-step yield rebalance or settlement loop
    /// to complete without re-spawning, short enough that a stolen
    /// token decays before the controller realises.
    pub ttl_secs: u64,
}

/// Sender-constrained credentials returned by [`AuthIssuer::issue`].
///
/// `Clone` is deliberate — the credential bundle gets copied into
/// `SpawnedAgent` so it can be serialized to disk for crash recovery
/// (the JWT is opaque to disk and the DPoP private key bytes are
/// already AES-GCM-sealed by the keystore at rest).
#[derive(Debug, Clone)]
pub struct AgentCredentials {
    /// The access token, ready to be sent as `Authorization: DPoP <jwt>`.
    pub jwt: String,

    /// SHA-256 JWK thumbprint (RFC 7638), base64url-encoded. This is
    /// the value the token's `cnf.jkt` claim already carries; we keep
    /// a copy on the credentials for audit/debug without re-parsing
    /// the JWT.
    pub jkt: String,

    /// DPoP signer for per-request proof construction. The bearer
    /// holds this for the entire token lifetime; one signer per
    /// agent. `Arc` so the executor and any in-flight RPCs can share
    /// it cheaply.
    pub dpop: Arc<dyn DpopSigner>,

    /// Token expiry, Unix seconds. Stored explicitly so consumers can
    /// re-issue *before* expiry rather than after — saves one
    /// failed-then-retried RPC per expiry boundary.
    pub expires_at_unix: u64,
}

/// One-shot DPoP proof constructor.
///
/// Per RFC 9449 §4, a DPoP proof is a compact JWS over
/// `{htm, htu, iat, jti, ath}`, signed by the holder's private key,
/// with the matching public key embedded as a JWK in the JWS header.
/// The verifier extracts the JWK, hashes it (RFC 7638), and compares
/// the digest against the access token's `cnf.jkt`.
///
/// Implementations MUST:
/// - generate a fresh random `jti` per call (used by the verifier's
///   replay cache);
/// - use the current Unix time for `iat`;
/// - emit `htm` in uppercase ("POST", "GET");
/// - emit `htu` as origin + path, query string stripped;
/// - compute `ath = base64url-no-pad(SHA-256(access_token))` and embed
///   it in the payload when `access_token` is supplied (every request
///   from the agent kit does).
#[async_trait]
pub trait DpopSigner: Send + Sync + std::fmt::Debug {
    /// Construct a DPoP proof for a request.
    ///
    /// Returns the compact JWS string ready to be sent as the value of
    /// the `DPoP:` HTTP header.
    async fn sign_proof(
        &self,
        http_method: &str,
        http_url: &str,
        access_token: &str,
    ) -> Result<String, AgentKitError>;
}

/// The seam: mints sender-constrained access tokens for newly-spawned
/// agents.
///
/// Implementations live outside this crate (the canonical one is
/// `tenzro-node`'s `NodeAuthIssuer`). The spawner accepts
/// `Option<Arc<dyn AuthIssuer>>` — when `None`, spawn still works but
/// the returned `SpawnedAgent.credentials` is `None` and any execution
/// step that needs DPoP-bound RPC will fail loudly (per
/// `feedback_implement_dont_delete` — we never silently fall back to
/// an unauthenticated path).
#[async_trait]
pub trait AuthIssuer: Send + Sync + std::fmt::Debug {
    /// Mint a credential bundle (JWT + DPoP signer) for `request`.
    ///
    /// The issuer is responsible for:
    /// - generating the DPoP keypair (or selecting one from its
    ///   keystore);
    /// - computing the JWK thumbprint;
    /// - projecting the request into its native authorization envelope;
    /// - issuing the JWT with `cnf.jkt = <thumbprint>`;
    /// - returning both halves wrapped in [`AgentCredentials`].
    async fn issue(&self, request: AgentAuthRequest) -> Result<AgentCredentials, AgentKitError>;
}
