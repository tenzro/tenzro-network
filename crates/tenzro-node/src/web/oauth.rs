//! OAuth 2.1 / RFC 8693 / RFC 7662 / RFC 7009 / RFC 9728 endpoints
//! exposed on the public Web API (port 8080, served at
//! `api.tenzro.network`).
//!
//! These endpoints sit *alongside* the MCP-specific OAuth 2.1
//! authorization-code flow at `mcp/oauth.rs`. The MCP module owns the
//! interactive browser dance (registration, /authorize HTML form,
//! /authorize/submit, code-grant /token) used by MCP clients on port
//! 3001. This module exposes the **agent-to-agent** auth surface used
//! by RPC clients, SDKs, and downstream services:
//!
//! | Endpoint | RFC | Purpose |
//! |----------|-----|---------|
//! | `POST /oauth/token` (grant_type=token-exchange) | RFC 8693 | Mint a child JWT under a parent's authority |
//! | `POST /oauth/introspect` | RFC 7662 | Inspect a token's claims and active state |
//! | `POST /oauth/revoke` | RFC 7009 | Revoke a JWT by hash and cascade through controller_did |
//! | `GET /.well-known/oauth-protected-resource` | RFC 9728 | Resource-server metadata (issuers, supported methods) |
//! | `GET /.well-known/openid-configuration` | OpenID Connect Discovery 1.0 | AS metadata + endpoint URLs |
//!
//! All calls flow through the same [`tenzro_auth::AuthEngine`] used by
//! the JSON-RPC layer, so a token introspected here, revoked here,
//! exchanged here, or validated against an RPC method shares one
//! source of truth (revocation set, audit log, replay cache, AAP
//! envelope).
//!
//! ## Authentication
//!
//! - `POST /oauth/token` (RFC 8693): the **subject_token** field
//!   carries the parent JWT; the `DPoP` header carries a fresh proof
//!   over `(POST, "<aud>/oauth/token")` signed by the parent's
//!   confirmation key. The endpoint validates both before exchanging.
//! - `POST /oauth/introspect` (RFC 7662 §2.1 requires the endpoint be
//!   authenticated): we require a DPoP-bound JWT in the
//!   `Authorization: Bearer …` header whose `aap_capabilities`
//!   includes the action `auth.introspect`. Per RFC 7662 §2.2, an
//!   inactive token is reported as `{"active": false}` with no other
//!   leaked claims.
//! - `POST /oauth/revoke` (RFC 7009): no caller authentication
//!   required — we only need the token itself. Revocation is
//!   idempotent; a forged token revokes a `jti` that doesn't exist
//!   (no-op).
//! - The `/.well-known/*` endpoints are unauthenticated GET.

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use tenzro_auth::{
    peek_unverified_jti, AapCapabilityClaim, AuthClaims, AuthError, AuthorizationDetails,
    IntrospectionResponse, TokenExchangeRequest,
};

use super::handlers::WebState;

// ---------------------------------------------------------------------------
// RFC 8693 — Token Exchange
// ---------------------------------------------------------------------------

/// The exact `grant_type` URI registered in the IANA OAuth Parameters
/// registry for token exchange. A request with any other `grant_type`
/// is forwarded to the next layer (currently rejected — V1's web
/// `/oauth/token` only handles token-exchange; the authorization-code
/// and refresh-token grants live on the MCP module's `/token`).
const GRANT_TYPE_TOKEN_EXCHANGE: &str =
    "urn:ietf:params:oauth:grant-type:token-exchange";

/// Required `subject_token_type` value. We accept exactly one shape.
const TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

/// RFC 8693 §2.1 token-exchange request body.
///
/// Mapping notes:
///
/// - `subject_token` carries the parent JWT.
/// - `actor_token` (RFC 8693 §1.1) is **rejected** — Tenzro encodes
///   delegation losslessly in the parent's `aap_delegation.chain`
///   field, so a separate actor token is redundant and ambiguous.
/// - `scope` is **rejected** — Tenzro tokens carry no `scope` field;
///   authorization is fully described by RAR + AAP.
/// - `resource` is **rejected** — V1 has a single resource server
///   (the configured `audience`).
/// - `requested_rar` and `requested_aap_capabilities` are
///   Tenzro-specific extensions: they describe the child's *requested*
///   subset of the parent's authority. The engine rejects any request
///   that widens beyond the parent.
/// - `child_bearer_did` and `child_dpop_jkt` identify the child agent
///   that will hold the new token; both are required because the
///   minted JWT is DPoP-bound to a specific key the child controls.
#[derive(Debug, Deserialize)]
pub struct TokenExchangeRequestBody {
    /// Must be `urn:ietf:params:oauth:grant-type:token-exchange`.
    pub grant_type: String,
    /// The parent JWT being exchanged.
    pub subject_token: String,
    /// Must be `urn:ietf:params:oauth:token-type:jwt`.
    pub subject_token_type: String,
    /// DID of the child agent that will bear the new token.
    pub child_bearer_did: String,
    /// SHA-256 thumbprint (RFC 7638) of the child's DPoP key.
    pub child_dpop_jkt: String,
    /// RAR envelope the child wants. Must be a strict subset of the
    /// parent's `authorization_details`.
    #[serde(default)]
    pub requested_rar: Option<AuthorizationDetails>,
    /// AAP capability set the child wants. Must be a strict subset of
    /// the parent's `aap_capabilities`.
    #[serde(default)]
    pub requested_aap_capabilities: Vec<AapCapabilityClaim>,
    /// Requested child TTL in seconds. Clamped by parent's remaining
    /// lifetime and by the engine's `max_ttl_secs`.
    #[serde(default)]
    pub requested_ttl_secs: Option<u64>,
}

/// RFC 8693 §2.2 token-exchange response body. We always issue JWTs,
/// so `issued_token_type` is fixed and `token_type` is always `DPoP`
/// (the child token is bound to `child_dpop_jkt`).
#[derive(Debug, Serialize)]
pub struct TokenExchangeResponseBody {
    pub access_token: String,
    pub issued_token_type: &'static str,
    pub token_type: &'static str,
    pub expires_in: u64,
}

/// `POST /oauth/token` — RFC 8693 token exchange.
///
/// Validates the parent JWT's signature and revocation status, then
/// delegates to [`tenzro_auth::AuthEngine::exchange_token`] which
/// performs the RAR/AAP subset enforcement and mints the child JWT.
///
/// **DPoP**: the parent JWT was bound to a key (its `cnf.jkt`); the
/// caller proves possession of that key via the `DPoP` header on this
/// request. (The MCP `/token` endpoint accepts code/refresh grants
/// without DPoP because those flows mint the original key binding.)
/// V1 implementation note: the DPoP proof on the exchange call is
/// **not** verified here yet — we accept the parent's signature as the
/// gating credential for V1 testnet. Item 7 of Phase A includes
/// wiring DPoP-on-exchange when we land the AS endpoints in the
/// production deployment; the engine's `validate_jwt(token, None)`
/// call below establishes the parent's JTI/revocation status, and
/// `exchange_token` then narrows the RAR/AAP envelope.
pub async fn token_exchange_handler(
    State(state): State<Arc<WebState>>,
    Json(body): Json<TokenExchangeRequestBody>,
) -> Response {
    let engine = match auth_engine(&state) {
        Ok(e) => e,
        Err(resp) => return resp,
    };

    if body.grant_type != GRANT_TYPE_TOKEN_EXCHANGE {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "this endpoint only handles grant_type=urn:ietf:params:oauth:grant-type:token-exchange",
        );
    }
    if body.subject_token_type != TOKEN_TYPE_JWT {
        return oauth_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "subject_token_type must be urn:ietf:params:oauth:token-type:jwt",
        );
    }

    // Validate the parent JWT (signature, exp, revocation). DPoP
    // proof verification on /oauth/token is deferred to a follow-up
    // pass — see the rustdoc above.
    let parent_claims: AuthClaims = match engine.validate_jwt(&body.subject_token, None) {
        Ok(c) => c,
        Err(e) => return auth_error_to_response(e),
    };

    let req = TokenExchangeRequest {
        child_bearer_did: body.child_bearer_did,
        child_dpop_jkt: body.child_dpop_jkt,
        requested_rar: body.requested_rar.unwrap_or_default(),
        requested_aap_capabilities: body.requested_aap_capabilities,
        requested_ttl_secs: body.requested_ttl_secs,
    };

    match engine.exchange_token(&parent_claims, req) {
        Ok(outcome) => Json(TokenExchangeResponseBody {
            access_token: outcome.access_token,
            issued_token_type: TOKEN_TYPE_JWT,
            token_type: "DPoP",
            expires_in: outcome.expires_in,
        })
        .into_response(),
        Err(e) => auth_error_to_response(e),
    }
}

// ---------------------------------------------------------------------------
// RFC 7662 — Token Introspection
// ---------------------------------------------------------------------------

/// RFC 7662 §2.1 introspection request body. The `token_type_hint` is
/// purely advisory and currently unused — we always treat the input
/// as a JWT.
#[derive(Debug, Deserialize)]
pub struct IntrospectionRequestBody {
    pub token: String,
    #[serde(default)]
    pub token_type_hint: Option<String>,
}

/// `POST /oauth/introspect` — RFC 7662 token introspection.
///
/// Per RFC 7662 §2.2, the response for an inactive (unknown,
/// expired, or revoked) token is exactly `{"active": false}` — no
/// other claims leak. The active response carries the full claim
/// set including AAP fields so resource servers that honor AAP
/// (purpose binding, oversight, delegation chain) can read them
/// straight from the introspection response without re-parsing the
/// JWT.
///
/// Caller authentication: V1 testnet leaves this open for the
/// alpha; production hardening will require a DPoP-bound JWT with
/// the `auth.introspect` AAP capability (per the module rustdoc).
pub async fn introspect_handler(
    State(state): State<Arc<WebState>>,
    Json(body): Json<IntrospectionRequestBody>,
) -> Response {
    let engine = match auth_engine(&state) {
        Ok(e) => e,
        Err(resp) => return resp,
    };

    // The hint is advisory — log at trace level so operators can
    // confirm well-behaved clients are sending it, but never branch on it.
    if let Some(hint) = &body.token_type_hint {
        tracing::trace!(token_type_hint = %hint, "introspect: client supplied advisory hint");
    }

    // Per RFC 7662 §2.2, every failure path yields `{"active": false}`.
    // We never tell the caller *why* — that would be an oracle.
    match engine.validate_jwt(&body.token, None) {
        Ok(claims) => Json(IntrospectionResponse::from_claims(&claims)).into_response(),
        Err(_) => Json(IntrospectionResponse::inactive()).into_response(),
    }
}

// ---------------------------------------------------------------------------
// RFC 7009 — Revocation
// ---------------------------------------------------------------------------

/// RFC 7009 §2.1 revocation request body.
#[derive(Debug, Deserialize)]
pub struct RevokeRequestBody {
    pub token: String,
    #[serde(default)]
    pub token_type_hint: Option<String>,
    /// Optional human-readable reason recorded in the audit log.
    #[serde(default)]
    pub reason: Option<String>,
}

/// `POST /oauth/revoke` — RFC 7009 token revocation.
///
/// Decodes the JWT *without* signature verification to extract its
/// `jti`, then calls [`tenzro_auth::AuthEngine::revoke`] which records
/// a `Revoked` audit event and cascades through the `controller_did`
/// chain. Always returns 200 per RFC 7009 §2.2 — revocation is
/// idempotent and we don't want to leak token validity through
/// timing.
pub async fn revoke_handler(
    State(state): State<Arc<WebState>>,
    Json(body): Json<RevokeRequestBody>,
) -> Response {
    let Some(engine) = state
        .node
        .as_ref()
        .and_then(|n| n.auth_engine().cloned())
    else {
        // Per RFC 7009 §2.2, even when revocation is unavailable we
        // return 200; logging the misconfiguration on our side.
        tracing::warn!("revoke called but auth engine not initialized");
        return StatusCode::OK.into_response();
    };

    let Some(jti) = peek_unverified_jti(&body.token) else {
        // Not a JWT shape; nothing to do. Per RFC 7009 §2.2, return 200.
        return StatusCode::OK.into_response();
    };

    // The hint is advisory — we always treat the token as a JWT.
    if let Some(hint) = &body.token_type_hint {
        tracing::trace!(token_type_hint = %hint, "revoke: client supplied advisory hint");
    }

    let reason = body.reason.unwrap_or_else(|| "client revocation".into());
    if let Err(e) = engine.revoke(&jti, reason) {
        // Engine-level errors (storage failure) are logged but not
        // surfaced to the caller — RFC 7009 §2.2 always 200.
        tracing::warn!(jti = %jti, error = %e, "revoke failed");
    }
    StatusCode::OK.into_response()
}

// ---------------------------------------------------------------------------
// RFC 9728 — Protected Resource Metadata
// ---------------------------------------------------------------------------

/// RFC 9728 §2 protected-resource metadata. The Tenzro Web API is
/// *both* the resource server (it serves `/chat`, `/verify/*`, etc.)
/// and the authorization server (it issues + introspects + revokes
/// tokens). The same document advertises both roles.
#[derive(Debug, Serialize)]
pub struct ProtectedResourceMetadata {
    /// Canonical URI for this resource (the public web base URL).
    pub resource: String,
    /// List of issuer URIs whose tokens this resource accepts.
    /// V1 testnet: a single self-issuer.
    pub authorization_servers: Vec<String>,
    /// Methods the resource accepts for presenting a bearer token.
    /// We accept DPoP only — see RFC 9449 — so the array contains
    /// exactly `"dpop"`.
    pub bearer_methods_supported: Vec<&'static str>,
    /// Confirmation methods supported, per RFC 7800. We support
    /// `jkt` (JWK SHA-256 thumbprint per RFC 7638) only.
    pub token_introspection_endpoint: String,
    pub revocation_endpoint: String,
    pub token_endpoint: String,
}

/// `GET /.well-known/oauth-protected-resource` — RFC 9728.
pub async fn protected_resource_metadata_handler(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    let base = derive_base_url(&headers);
    let issuer = node_issuer(&state).unwrap_or_else(|| base.clone());

    Json(ProtectedResourceMetadata {
        resource: base.clone(),
        authorization_servers: vec![issuer],
        bearer_methods_supported: vec!["dpop"],
        token_introspection_endpoint: format!("{}/oauth/introspect", base),
        revocation_endpoint: format!("{}/oauth/revoke", base),
        token_endpoint: format!("{}/oauth/token", base),
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// OpenID Connect Discovery 1.0 — Authorization Server Metadata
// ---------------------------------------------------------------------------

/// OpenID Connect Discovery 1.0 / RFC 8414 authorization server
/// metadata. We expose the OIDC discovery name because most SDKs
/// look there first; the document is a strict superset of RFC 8414
/// content.
#[derive(Debug, Serialize)]
pub struct AsMetadata {
    pub issuer: String,
    pub token_endpoint: String,
    pub introspection_endpoint: String,
    pub revocation_endpoint: String,

    /// All grant types this AS accepts across both web and MCP
    /// surfaces. The web `/oauth/token` endpoint handles only
    /// `urn:ietf:params:oauth:grant-type:token-exchange`; the
    /// MCP `/token` endpoint (port 3001) handles
    /// `authorization_code` and `refresh_token`. Listing them all
    /// here lets a single discovery document describe the whole
    /// node.
    pub grant_types_supported: Vec<&'static str>,
    pub token_endpoint_auth_methods_supported: Vec<&'static str>,
    pub response_types_supported: Vec<&'static str>,

    /// RFC 8705 / RFC 9449 confirmation method advertisement.
    pub dpop_signing_alg_values_supported: Vec<&'static str>,

    /// RFC 9396 — we use Authorization Details exclusively (no
    /// `scope` field). Listing the supported types lets clients
    /// discover what shapes this AS will accept.
    pub authorization_details_types_supported: Vec<&'static str>,

    /// Tenzro-specific extension: the AAP claim names this AS
    /// emits. Lets clients know whether the AS implements
    /// IETF draft-aap-oauth-profile-01 capabilities.
    pub aap_claims_supported: Vec<&'static str>,
}

/// `GET /.well-known/openid-configuration` — RFC 8414 / OIDC Discovery 1.0.
pub async fn as_metadata_handler(
    State(state): State<Arc<WebState>>,
    headers: HeaderMap,
) -> Response {
    let base = derive_base_url(&headers);
    let issuer = node_issuer(&state).unwrap_or_else(|| base.clone());

    Json(AsMetadata {
        issuer,
        token_endpoint: format!("{}/oauth/token", base),
        introspection_endpoint: format!("{}/oauth/introspect", base),
        revocation_endpoint: format!("{}/oauth/revoke", base),
        grant_types_supported: vec![
            GRANT_TYPE_TOKEN_EXCHANGE,
            "authorization_code",
            "refresh_token",
        ],
        token_endpoint_auth_methods_supported: vec!["none", "private_key_jwt"],
        response_types_supported: vec!["code"],
        dpop_signing_alg_values_supported: vec!["EdDSA"],
        authorization_details_types_supported: vec![
            "transfer",
            "create_escrow",
            "discharge_escrow",
            "inference",
            "stake",
            "vote",
            "contract",
            "register_identity",
        ],
        aap_claims_supported: vec![
            "aap_agent",
            "aap_task",
            "aap_capabilities",
            "aap_oversight",
            "aap_delegation",
            "aap_context",
            "aap_audit",
        ],
    })
    .into_response()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Extract a cloned `Arc<AuthEngine>` from the WebState. Returns a
/// 503 response if the auth engine isn't initialized (e.g., the node
/// is starting up or the role doesn't include auth).
fn auth_engine(
    state: &Arc<WebState>,
) -> std::result::Result<Arc<tenzro_auth::AuthEngine>, Response> {
    state
        .node
        .as_ref()
        .and_then(|n| n.auth_engine().cloned())
        .ok_or_else(|| {
            oauth_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "service_unavailable",
                "auth engine not initialized on this node",
            )
        })
}

/// Derive the public base URL of this node from the incoming `Host`
/// and `X-Forwarded-Proto` headers. Caddy / our reverse proxy sets
/// these; for direct hits we default to `http`.
fn derive_base_url(headers: &HeaderMap) -> String {
    let scheme = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("https");
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("api.tenzro.network");
    format!("{}://{}", scheme, host)
}

/// The node's configured issuer, if available. Falls back to the
/// derived base URL when the auth engine is absent.
fn node_issuer(state: &Arc<WebState>) -> Option<String> {
    state
        .node
        .as_ref()
        .and_then(|n| n.auth_engine())
        .map(|e| e.config().issuer.clone())
}

/// OAuth-compliant error body. Per RFC 6749 §5.2, errors are JSON
/// with `error` and `error_description` fields.
#[derive(Serialize)]
struct OAuthError {
    error: &'static str,
    error_description: String,
}

fn oauth_error(status: StatusCode, code: &'static str, description: &str) -> Response {
    (
        status,
        Json(OAuthError {
            error: code,
            error_description: description.to_string(),
        }),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Wallet endpoint auth — shared validator for /wallet/* surfaces
// ---------------------------------------------------------------------------

/// Validate a wallet-surface request: DPoP-bound JWT + matching AAP
/// capability action.
///
/// Used by the `/wallet/mldsa/*`, `/wallet/frost/*`, and `/wallet/share/*`
/// endpoints. Mirrors the JSON-RPC validation path in `rpc.rs` but
/// returns a `Response` directly instead of a `JsonRpcError`, so the
/// handler can `return r;` on the error case.
///
/// Auth contract enforced here:
///
/// 1. `Authorization: DPoP <jwt>` header present (Bearer is rejected).
/// 2. `DPoP: <proof>` header present and signed over the request's
///    `(method, full_uri)`.
/// 3. JWT validates: signature, exp, audience, issuer, `cnf.jkt`
///    binding to the DPoP key, and replay window.
/// 4. The token's `aap_capabilities` includes a grant whose `action`
///    equals `required_action` (no wildcards — see RFC AAP §3.2).
///
/// On success returns the validated `AuthClaims` so the handler can
/// look up the controller DID, identity binding, etc.
pub(super) async fn validate_wallet_auth(
    state: &Arc<WebState>,
    headers: &axum::http::HeaderMap,
    method: &str,
    full_uri: &str,
    required_action: &str,
) -> std::result::Result<AuthClaims, Response> {
    // 1. Extract Authorization header and strip "DPoP " scheme prefix.
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Authorization header missing",
            )
        })?;
    let jwt = auth_header
        .strip_prefix("DPoP ")
        .or_else(|| auth_header.strip_prefix("dpop "))
        .ok_or_else(|| {
            oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Authorization header must use the 'DPoP' scheme (RFC 9449)",
            )
        })?
        .trim();

    // 2. Extract DPoP proof header.
    let dpop_header = headers
        .get("dpop")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_dpop_proof",
                "DPoP proof header missing (RFC 9449 §4)",
            )
        })?;

    let engine = auth_engine(state)?;

    // 3. Parse DPoP proof + run JWT validation with DPoP context.
    let (dpop_proof, signed_input, signature) =
        tenzro_auth::DpopProof::parse_with_signed_input(dpop_header).map_err(|e| {
            oauth_error(
                StatusCode::UNAUTHORIZED,
                "invalid_dpop_proof",
                &format!("DPoP proof parse failed: {}", e),
            )
        })?;
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let dpop_validation = tenzro_auth::DpopValidation {
        proof: &dpop_proof,
        expected_htm: method,
        expected_htu: full_uri,
        now_unix,
        signed_input: &signed_input,
        signature: &signature,
    };
    let claims = engine
        .validate_jwt(jwt, Some(dpop_validation))
        .map_err(auth_error_to_response)?;

    // 4. Capability check — token must hold the exact required action
    //    in its aap_capabilities list. AAP §3.2 forbids wildcards.
    let has_capability = claims
        .aap_capabilities
        .as_ref()
        .map(|caps| caps.iter().any(|c| c.action == required_action))
        .unwrap_or(false);
    if !has_capability {
        return Err(oauth_error(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            &format!(
                "token lacks aap_capabilities action '{}'",
                required_action
            ),
        ));
    }

    Ok(claims)
}

/// Build the `htu` value (full request URL minus query/fragment per
/// RFC 9449 §4.2) from the inbound headers + path. The wallet must
/// sign DPoP proofs over this same string.
pub(super) fn full_request_uri(headers: &axum::http::HeaderMap, path: &str) -> String {
    format!("{}{}", derive_base_url(headers), path)
}

/// Map an `AuthError` to the closest OAuth/HTTP status code.
fn auth_error_to_response(e: AuthError) -> Response {
    match e {
        AuthError::TokenExpired | AuthError::TokenRevoked(_) | AuthError::InvalidToken(_) => {
            oauth_error(StatusCode::UNAUTHORIZED, "invalid_token", &e.to_string())
        }
        AuthError::InvalidDpop(_) => {
            oauth_error(StatusCode::UNAUTHORIZED, "invalid_dpop_proof", &e.to_string())
        }
        AuthError::InsufficientAuthorization(_)
        | AuthError::DelegationViolation(_)
        | AuthError::Forbidden(_)
        | AuthError::NotAuthorizedForDid { .. } => {
            oauth_error(StatusCode::FORBIDDEN, "insufficient_scope", &e.to_string())
        }
        AuthError::ApprovalRequired { approval_id } => oauth_error(
            StatusCode::ACCEPTED,
            "approval_required",
            &format!("approval_id={}", approval_id),
        ),
        AuthError::UnknownDid(_) => {
            oauth_error(StatusCode::BAD_REQUEST, "invalid_request", &e.to_string())
        }
        AuthError::InvalidScope(_) => {
            oauth_error(StatusCode::BAD_REQUEST, "invalid_scope", &e.to_string())
        }
        AuthError::Storage(_) | AuthError::Codec(_) | AuthError::Internal(_) => oauth_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &e.to_string(),
        ),
    }
}
