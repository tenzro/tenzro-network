//! MCP OAuth 2.1 + JWT bearer middleware.
//!
//! Implements the OAuth 2.1 surface required by the MCP specification
//! (2025-11-25):
//! - RFC 8414 Authorization Server Metadata
//! - RFC 9728 Protected Resource Metadata
//! - RFC 7591 Dynamic Client Registration
//! - PKCE S256 (mandatory)
//! - JWT (HS256) access tokens with TDIP DID claims
//! - Automatic identity + wallet provisioning on first authentication
//!
//! ## Token model
//!
//! All access tokens are issued by [`tenzro_auth::AuthEngine::issue_jwt`]
//! and validated by [`tenzro_auth::AuthEngine::validate_jwt`]:
//!
//! - Bearer auth on `/mcp` paths accepts only JWTs minted by the node's
//!   `AuthEngine`.
//! - The JWT carries an RFC 9396 RAR envelope. The MCP `/authorize` flow
//!   issues a coarse developer envelope; the onboarding RPCs
//!   (`tenzro_onboardHuman` / `tenzro_onboardDelegatedAgent` /
//!   `tenzro_onboardAutonomousAgent`) issue per-identity envelopes
//!   matched to the caller's KYC tier and delegation scope.
//! - DPoP (RFC 9449) is **not** enforced at this MCP middleware layer —
//!   the JWT alone is sufficient to invoke MCP tools. DPoP IS enforced
//!   in the per-handler signing path: the `tenzro_signTransaction`
//!   family of RPCs require a DPoP proof bound to the JWT's `cnf.jkt`.
//!
//! Why this split: the MCP transport does not carry DPoP headers
//! across every transport adapter, but the *consequential*
//! actions (signing, transferring, escrowing) funnel through the JSON-RPC
//! layer where the per-handler `AuthContext` enforces DPoP-bound proof.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::NodeError;

use axum::{
    extract::{Form, Query, State},
    http::{Request, StatusCode, header},
    middleware::Next,
    response::{Html, IntoResponse, Json, Redirect, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use tenzro_auth::{AuthClaims, AuthorizationDetail, AuthorizationDetails};
use tenzro_storage::KvStore;
use tenzro_types::AssetId;

use super::auth_page;
use crate::node::TenzroNode;
use crate::web::handlers::WebState;

// ─── Configuration ───────────────────────────────────────────────────────────

/// Configuration for OAuth endpoints. The signing key is owned by
/// [`tenzro_auth::AuthEngine`]; this config only carries the public-facing
/// issuer URL and refresh-token lifetimes.
pub struct OAuthConfig {
    /// Public issuer URL embedded in OAuth metadata (RFC 8414). Must
    /// match the `iss` claim of every JWT this node issues — i.e., must
    /// match the `AuthEngineConfig.issuer` value.
    pub issuer: String,
    /// Refresh-token lifetime. Refresh tokens are *not* JWTs; they are
    /// opaque UUIDs persisted to RocksDB and exchanged for new JWTs at
    /// the /token endpoint.
    pub refresh_token_ttl: Duration,
}

impl OAuthConfig {
    pub fn new(issuer: String) -> Self {
        Self {
            issuer,
            refresh_token_ttl: Duration::from_secs(30 * 86400), // 30 days
        }
    }
}

// ─── Data Structures ─────────────────────────────────────────────────────────

/// An in-flight OAuth authorization session, keyed by authorization code.
#[derive(Debug, Clone)]
pub struct OAuthSession {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub scope: String,
    pub created_at: Instant,
    pub approved: bool,
    /// Optional DPoP key thumbprint (RFC 9449 §10.1) — when supplied by
    /// the client at /authorize time, the issued JWT's `cnf.jkt` is
    /// pinned to this value, enabling DPoP-bound use of the token in
    /// the signing path.
    pub dpop_jkt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredClient {
    pub client_id: String,
    pub client_name: String,
    pub redirect_uris: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenEntry {
    pub token: String,
    pub client_id: String,
    pub did: String,
    pub address: String,
    pub scope: String,
    pub dpop_jkt: Option<String>,
    pub expires_at: u64,
}

/// Authenticated user info extracted from a validated JWT, injected
/// into request extensions for downstream handlers.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub did: String,
    pub address: String,
    pub scope: String,
}

/// Shared OAuth state accessible by all handlers.
pub struct OAuthState {
    /// Authorization code -> session
    pub sessions: DashMap<String, OAuthSession>,
    /// Session token (authorize page CSRF) -> authorization code
    pub session_tokens: DashMap<String, String>,
    /// client_id -> registered client
    pub clients: DashMap<String, RegisteredClient>,
    /// refresh_token -> metadata
    pub refresh_tokens: DashMap<String, RefreshTokenEntry>,
    /// Node reference for identity provisioning + auth-engine access
    pub node: Arc<TenzroNode>,
    /// Web state for node version and metrics access
    pub web_state: Arc<WebState>,
    pub config: OAuthConfig,
}

impl OAuthState {
    pub fn new(node: Arc<TenzroNode>, web_state: Arc<WebState>) -> Self {
        let config = OAuthConfig::new("https://mcp.tenzro.xyz".to_string());
        Self {
            sessions: DashMap::new(),
            session_tokens: DashMap::new(),
            clients: DashMap::new(),
            refresh_tokens: DashMap::new(),
            node,
            web_state,
            config,
        }
    }
}

// ─── Request / Response Types ────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct AuthorizeQuery {
    pub client_id: String,
    pub redirect_uri: String,
    pub response_type: String,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: String,
    pub code_challenge_method: String,
    /// Optional DPoP key thumbprint per RFC 9449 §10.1. When supplied,
    /// the resulting JWT is pinned to this key and may be used for
    /// DPoP-protected endpoints (e.g. `tenzro_signTransaction`).
    pub dpop_jkt: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AuthorizeSubmit {
    pub session_token: String,
    pub action: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    /// Optional DPoP thumbprint, used when /authorize did not carry one.
    /// The JWT's `cnf.jkt` is set from this value if present.
    pub dpop_jkt: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub client_name: String,
    pub redirect_uris: Vec<String>,
    pub grant_types: Option<Vec<String>>,
    pub response_types: Option<Vec<String>>,
    pub token_endpoint_auth_method: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/// RFC 8414 — OAuth Authorization Server Metadata discovery.
pub async fn metadata_handler(State(state): State<Arc<OAuthState>>) -> Json<serde_json::Value> {
    let iss = &state.config.issuer;
    let node_version = &state.web_state.node_version;
    Json(serde_json::json!({
        "issuer": iss,
        "authorization_endpoint": format!("{}/authorize", iss),
        "token_endpoint": format!("{}/token", iss),
        "registration_endpoint": format!("{}/register", iss),
        "revocation_endpoint": format!("{}/revoke", iss),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["read", "write"],
        "dpop_signing_alg_values_supported": ["EdDSA", "ES256"],
        "service_documentation": "https://docs.tenzro.com/mcp",
        "server_version": node_version
    }))
}

/// RFC 9728 — OAuth 2.0 Protected Resource Metadata.
///
/// Returns the metadata document advertising this MCP server as a protected
/// resource, listing its trusted authorization server(s), supported bearer
/// transport, supported scopes, and the DPoP / RAR (RFC 9396) requirements
/// that auth-sensitive RPCs (signing, escrow, settlement) impose on access
/// tokens. MCP clients fetch this at `/.well-known/oauth-protected-resource`
/// (advertised in `WWW-Authenticate: Bearer resource_metadata="..."` on
/// 401 responses) before they begin the OAuth dance.
pub async fn resource_metadata_handler(
    State(state): State<Arc<OAuthState>>,
) -> Json<serde_json::Value> {
    let iss = &state.config.issuer;
    Json(serde_json::json!({
        // RFC 9728 §2: required.
        "resource": format!("{}/mcp", iss),
        "authorization_servers": [iss],

        // RFC 9728 §2: recommended/optional.
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["read", "write"],
        "resource_name": "Tenzro MCP",
        "resource_documentation": "https://docs.tenzro.com/mcp",
        "resource_policy_uri": "https://tenzro.com/policy",
        "resource_tos_uri": "https://tenzro.com/tos",

        // RFC 9449 — DPoP is mandatory for auth-sensitive RPCs (signing,
        // escrow, settlement). Public reads (balance/status/block) accept
        // unauthenticated requests, so DPoP is *advertised* as supported
        // rather than required at the resource level; the per-tool auth
        // policy decides per request.
        "dpop_signing_alg_values_supported": ["EdDSA", "ES256"],
        "dpop_bound_access_tokens_required": true,

        // RFC 9396 — Rich Authorization Requests are how clients ask for
        // signing / escrow / spend authority bound to a specific wallet
        // and scope. These types are interpreted by this server's RAR
        // validator (see crate `tenzro-auth`).
        "authorization_details_types_supported": [
            "transfer",
            "create_escrow",
            "discharge_escrow",
            "inference",
            "stake",
            "vote",
            "contract",
            "register_identity",
            "resource_invocation",
        ],

        // Token signing algorithms accepted by the protected resource for
        // JWT bearer validation (matches the AS metadata).
        "resource_signing_alg_values_supported": ["EdDSA"],

        // Supplemental version pin so clients can detect upgrades.
        "tenzro_server_version": &state.web_state.node_version,
    }))
}

/// RFC 7591 — Dynamic Client Registration.
pub async fn register_handler(
    State(state): State<Arc<OAuthState>>,
    Json(req): Json<RegisterRequest>,
) -> impl IntoResponse {
    let supported_grant_types = ["authorization_code", "refresh_token"];
    if let Some(ref requested_grants) = req.grant_types {
        for gt in requested_grants {
            if !supported_grant_types.contains(&gt.as_str()) {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_client_metadata",
                        "error_description": format!("Unsupported grant_type: {}. Supported: authorization_code, refresh_token", gt)
                    })),
                )
                    .into_response();
            }
        }
    }

    if let Some(ref requested_responses) = req.response_types {
        for rt in requested_responses {
            if rt != "code" {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid_client_metadata",
                        "error_description": format!("Unsupported response_type: {}. Only 'code' is supported", rt)
                    })),
                )
                    .into_response();
            }
        }
    }

    if let Some(ref auth_method) = req.token_endpoint_auth_method
        && auth_method != "none"
    {
        return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_client_metadata",
                    "error_description": format!("Unsupported token_endpoint_auth_method: {}. Only 'none' is supported (public client)", auth_method)
                })),
            )
                .into_response();
    }

    let client_id = format!("client_{}", Uuid::new_v4().simple());

    let client = RegisteredClient {
        client_id: client_id.clone(),
        client_name: req.client_name.clone(),
        redirect_uris: req.redirect_uris.clone(),
    };
    state.clients.insert(client_id.clone(), client);

    let grant_types = req.grant_types.unwrap_or_else(|| {
        vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ]
    });
    let response_types = req
        .response_types
        .unwrap_or_else(|| vec!["code".to_string()]);
    let auth_method = req
        .token_endpoint_auth_method
        .unwrap_or_else(|| "none".to_string());

    tracing::info!(
        client_id = %client_id,
        name = %req.client_name,
        grant_types = ?grant_types,
        response_types = ?response_types,
        auth_method = %auth_method,
        "Registered OAuth client"
    );

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "client_id": client_id,
            "client_name": req.client_name,
            "redirect_uris": req.redirect_uris,
            "grant_types": grant_types,
            "response_types": response_types,
            "token_endpoint_auth_method": auth_method
        })),
    )
        .into_response()
}

/// GET /authorize — Render the browser authorization page.
pub async fn authorize_handler(
    State(state): State<Arc<OAuthState>>,
    Query(params): Query<AuthorizeQuery>,
) -> impl IntoResponse {
    if params.response_type != "code" {
        return (
            StatusCode::BAD_REQUEST,
            Html("Unsupported response_type. Only 'code' is supported.".to_string()),
        )
            .into_response();
    }

    if params.code_challenge_method != "S256" {
        return (
            StatusCode::BAD_REQUEST,
            Html("Only S256 code_challenge_method is supported (per MCP spec).".to_string()),
        )
            .into_response();
    }

    let client_name = if let Some(client) = state.clients.get(&params.client_id) {
        client.client_name.clone()
    } else {
        let client = RegisteredClient {
            client_id: params.client_id.clone(),
            client_name: params.client_id.clone(),
            redirect_uris: vec![params.redirect_uri.clone()],
        };
        state.clients.insert(params.client_id.clone(), client);
        params.client_id.clone()
    };

    let scope = params.scope.as_deref().unwrap_or("read write");

    let code = Uuid::new_v4().to_string();
    let session_token = Uuid::new_v4().to_string();

    state.sessions.insert(
        code.clone(),
        OAuthSession {
            code: code.clone(),
            client_id: params.client_id.clone(),
            redirect_uri: params.redirect_uri.clone(),
            code_challenge: params.code_challenge.clone(),
            scope: scope.to_string(),
            created_at: Instant::now(),
            approved: false,
            dpop_jkt: params.dpop_jkt.clone(),
        },
    );
    state.session_tokens.insert(session_token.clone(), code);

    if let Some(ref s) = params.state {
        state
            .session_tokens
            .insert(format!("state:{}", session_token), s.clone());
    }

    let html = auth_page::render_authorize_page(
        &client_name,
        scope,
        &session_token,
        state.web_state.faucet_amount,
    );
    Html(html).into_response()
}

/// POST /authorize — Handle user approval / denial from the browser form.
pub async fn authorize_submit_handler(
    State(state): State<Arc<OAuthState>>,
    Form(form): Form<AuthorizeSubmit>,
) -> impl IntoResponse {
    let code = match state.session_tokens.remove(&form.session_token) {
        Some((_, code)) => code,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Html("Invalid or expired session.".to_string()),
            )
                .into_response();
        }
    };

    let client_state = state
        .session_tokens
        .remove(&format!("state:{}", form.session_token))
        .map(|(_, v)| v);

    let redirect_uri = match state.sessions.get(&code) {
        Some(session) => {
            if session.created_at.elapsed() > Duration::from_secs(120) {
                state.sessions.remove(&code);
                return (
                    StatusCode::BAD_REQUEST,
                    Html("Authorization session expired. Please try again.".to_string()),
                )
                    .into_response();
            }
            session.redirect_uri.clone()
        }
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Html("Session not found.".to_string()),
            )
                .into_response();
        }
    };

    if form.action == "approve" {
        if let Some(mut session) = state.sessions.get_mut(&code) {
            session.approved = true;
        }

        let mut url = redirect_uri;
        url.push_str(&format!("?code={}", code));
        if let Some(s) = client_state {
            url.push_str(&format!("&state={}", s));
        }
        Redirect::to(&url).into_response()
    } else {
        state.sessions.remove(&code);

        let mut url = redirect_uri;
        url.push_str("?error=access_denied&error_description=User+denied+the+request");
        if let Some(s) = client_state {
            url.push_str(&format!("&state={}", s));
        }
        Redirect::to(&url).into_response()
    }
}

/// POST /token — Exchange authorization code (or refresh token) for access token.
pub async fn token_handler(
    State(state): State<Arc<OAuthState>>,
    Form(req): Form<TokenRequest>,
) -> impl IntoResponse {
    match req.grant_type.as_str() {
        "authorization_code" => handle_auth_code_grant(state, req).await,
        "refresh_token" => handle_refresh_grant(state, req).await,
        _ => oauth_error(
            "unsupported_grant_type",
            "Only authorization_code and refresh_token are supported",
        ),
    }
}

/// POST /revoke — Token revocation (RFC 7009).
///
/// Refresh tokens are removed from the local store. Access tokens (JWTs)
/// are revoked through the [`tenzro_auth::AuthEngine`] which records a
/// `Revoked` audit event and (per subtask #54) cascades through the
/// controller_did chain.
pub async fn revoke_handler(
    State(state): State<Arc<OAuthState>>,
    Form(req): Form<RevokeRequest>,
) -> impl IntoResponse {
    let hint = req.token_type_hint.as_deref();

    match hint {
        Some("refresh_token") => {
            if state.refresh_tokens.remove(&req.token).is_some() {
                if let Some(storage) = state.node.storage() {
                    let key = format!("oauth_refresh:{}", req.token);
                    let _ = storage.delete("metadata", key.as_bytes());
                }
                tracing::debug!(hint = "refresh_token", "Revoked refresh token");
            } else {
                revoke_jwt_via_engine(&state, &req.token);
            }
        }
        Some("access_token") => {
            revoke_jwt_via_engine(&state, &req.token);
        }
        _ => {
            // No hint: try refresh first, then access (engine).
            if state.refresh_tokens.remove(&req.token).is_some() {
                if let Some(storage) = state.node.storage() {
                    let key = format!("oauth_refresh:{}", req.token);
                    let _ = storage.delete("metadata", key.as_bytes());
                }
                tracing::debug!("Revoked refresh token (no hint)");
            } else {
                revoke_jwt_via_engine(&state, &req.token);
            }
        }
    }
    StatusCode::OK
}

/// Decode the JWT *without* signature verification just to extract the
/// `jti`, then ask the auth engine to revoke that jti. We don't need
/// signature verification here because revocation is idempotent and the
/// worst case of an attacker submitting a forged JWT is that they
/// "revoke" a `jti` that doesn't exist — a no-op.
fn revoke_jwt_via_engine(state: &OAuthState, token: &str) {
    let Some(engine) = state.node.auth_engine() else {
        tracing::warn!("Cannot revoke JWT: auth engine not initialized");
        return;
    };
    // Split the JWT and base64url-decode the payload (middle segment).
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        tracing::debug!("Revoke called with non-JWT token shape");
        return;
    }
    let Ok(payload_bytes) = URL_SAFE_NO_PAD.decode(parts[1]) else {
        tracing::debug!("Revoke: failed to base64-decode JWT payload");
        return;
    };
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&payload_bytes) else {
        tracing::debug!("Revoke: failed to parse JWT payload as JSON");
        return;
    };
    let Some(jti) = claims.get("jti").and_then(|v| v.as_str()) else {
        tracing::debug!("Revoke: JWT payload missing jti");
        return;
    };
    match engine.revoke(jti, "client revocation request") {
        Ok(()) => tracing::info!(jti = %jti, "Revoked JWT via auth engine"),
        Err(e) => tracing::warn!(jti = %jti, error = %e, "Auth engine revoke failed"),
    }
}

// ─── Grant Handlers ──────────────────────────────────────────────────────────

async fn handle_auth_code_grant(state: Arc<OAuthState>, req: TokenRequest) -> Response {
    let code = match req.code {
        Some(ref c) => c.clone(),
        None => return oauth_error("invalid_request", "Missing 'code' parameter"),
    };
    let code_verifier = match req.code_verifier {
        Some(ref v) => v.clone(),
        None => return oauth_error("invalid_request", "Missing 'code_verifier' parameter"),
    };

    let session = match state.sessions.remove(&code) {
        Some((_, s)) => s,
        None => return oauth_error("invalid_grant", "Invalid or expired authorization code"),
    };

    if session.code != code {
        tracing::warn!(expected = %session.code, got = %code, "Authorization code cross-reference mismatch");
        return oauth_error("invalid_grant", "Authorization code mismatch");
    }

    if let Some(ref redirect_uri) = req.redirect_uri
        && *redirect_uri != session.redirect_uri
    {
        tracing::warn!(
            expected = %session.redirect_uri,
            got = %redirect_uri,
            "redirect_uri mismatch in token request"
        );
        return oauth_error(
            "invalid_grant",
            "redirect_uri does not match authorization request",
        );
    }

    if let Some(ref client_id) = req.client_id
        && *client_id != session.client_id
    {
        tracing::warn!(
            expected = %session.client_id,
            got = %client_id,
            "client_id mismatch in token request"
        );
        return oauth_error(
            "invalid_grant",
            "client_id does not match authorization request",
        );
    }

    if !session.approved {
        return oauth_error("invalid_grant", "Authorization was not approved");
    }
    if session.created_at.elapsed() > Duration::from_secs(300) {
        return oauth_error("invalid_grant", "Authorization code has expired");
    }

    // PKCE S256 verification
    let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    if computed != session.code_challenge {
        return oauth_error("invalid_grant", "PKCE verification failed");
    }

    let (did, address) = match provision_or_retrieve_identity(
        &state.node,
        &session.client_id,
        state.web_state.faucet_amount,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "Identity provisioning failed");
            return oauth_error(
                "server_error",
                &format!("Identity provisioning failed: {}", e),
            );
        }
    };

    let dpop_jkt = req.dpop_jkt.clone().or(session.dpop_jkt.clone());
    let access_token = match mint_jwt(&state, &did, dpop_jkt.as_deref(), &session.scope) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    // Issue refresh token (opaque UUID, NOT a JWT).
    let refresh_token = Uuid::new_v4().to_string();
    let now = unix_now();
    let refresh_expires = now + state.config.refresh_token_ttl.as_secs();
    let entry = RefreshTokenEntry {
        token: refresh_token.clone(),
        client_id: session.client_id.clone(),
        did: did.clone(),
        address: address.clone(),
        scope: session.scope.clone(),
        dpop_jkt,
        expires_at: refresh_expires,
    };
    state
        .refresh_tokens
        .insert(refresh_token.clone(), entry.clone());

    if let Some(storage) = state.node.storage() {
        let key = format!("oauth_refresh:{}", refresh_token);
        if let Ok(data) = serde_json::to_vec(&entry) {
            let _ = storage.put("metadata", key.as_bytes(), &data);
        }
    }

    tracing::info!(did = %did, address = %address, client = %session.client_id, "Issued OAuth access token");

    let access_ttl = state
        .node
        .auth_engine()
        .map(|e| e.config().default_ttl_secs)
        .unwrap_or(3600);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": access_ttl,
            "refresh_token": refresh_token,
            "scope": session.scope
        })),
    )
        .into_response()
}

async fn handle_refresh_grant(state: Arc<OAuthState>, req: TokenRequest) -> Response {
    let rt = match req.refresh_token {
        Some(ref t) => t.clone(),
        None => return oauth_error("invalid_request", "Missing 'refresh_token' parameter"),
    };

    let entry = if let Some(e) = state.refresh_tokens.get(&rt) {
        e.value().clone()
    } else if let Some(storage) = state.node.storage() {
        let key = format!("oauth_refresh:{}", rt);
        match storage.get("metadata", key.as_bytes()) {
            Ok(Some(data)) => match serde_json::from_slice::<RefreshTokenEntry>(&data) {
                Ok(e) => e,
                Err(_) => return oauth_error("invalid_grant", "Invalid refresh token"),
            },
            _ => return oauth_error("invalid_grant", "Invalid refresh token"),
        }
    } else {
        return oauth_error("invalid_grant", "Invalid refresh token");
    };

    let now = unix_now();
    if now > entry.expires_at {
        state.refresh_tokens.remove(&rt);
        return oauth_error("invalid_grant", "Refresh token has expired");
    }

    let dpop_jkt = req.dpop_jkt.clone().or(entry.dpop_jkt.clone());
    let access_token = match mint_jwt(&state, &entry.did, dpop_jkt.as_deref(), &entry.scope) {
        Ok(t) => t,
        Err(e) => return e.into_response(),
    };

    tracing::info!(did = %entry.did, "Refreshed OAuth access token");

    let access_ttl = state
        .node
        .auth_engine()
        .map(|e| e.config().default_ttl_secs)
        .unwrap_or(3600);

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": access_ttl,
            "refresh_token": rt,
            "scope": entry.scope
        })),
    )
        .into_response()
}

// ─── Bearer Auth Middleware ──────────────────────────────────────────────────

/// Read-only MCP tools that do not require authentication.
const PUBLIC_MCP_TOOLS: &[&str] = &[
    // Network & status
    "get_node_status",
    "get_block",
    "get_block_range",
    "get_transaction",
    // Read-only queries
    "get_balance",
    "token_balance",
    "total_supply",
    "get_token_info",
    "list_tokens",
    "get_token_balance",
    // Model discovery
    "list_models",
    "list_model_endpoints",
    "get_download_progress",
    // Provenance & training status (read-only)
    "get_provenance",
    "get_trainer_daemon_status",
    // Bridge info
    "get_bridge_routes",
    "list_bridge_adapters",
    // deBridge read-only
    "debridge_search_tokens",
    "debridge_get_chains",
    "debridge_get_instructions",
    // Staking & governance queries
    "get_provider_stats",
    "get_provider_schedule",
    "get_provider_pricing",
    "list_proposals",
    "get_voting_power",
    // Task & agent browsing
    "list_tasks",
    "get_task",
    "list_agent_templates",
    "get_agent_template",
    // Canton read-only
    "list_canton_domains",
    "list_daml_contracts",
    // Payment info
    "list_payment_protocols",
    // Verification
    "verify_zk_proof",
    "get_zk_attestation",
    // Identity resolution
    "resolve_did",
];

fn is_public_mcp_request(body: &[u8]) -> bool {
    let Ok(json) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    let method = json.get("method").and_then(|m| m.as_str()).unwrap_or("");
    match method {
        "initialize"
        | "notifications/initialized"
        | "tools/list"
        | "resources/list"
        | "prompts/list"
        | "ping" => true,
        "tools/call" => {
            let tool_name = json
                .get("params")
                .and_then(|p| p.get("name"))
                .and_then(|n| n.as_str())
                .unwrap_or("");
            PUBLIC_MCP_TOOLS.contains(&tool_name)
        }
        _ => false,
    }
}

/// Bearer token authentication middleware.
///
/// - Read-only tools (queries, discovery): public, no auth required
/// - Write tools: require Bearer JWT minted by [`tenzro_auth::AuthEngine`]
/// - `TENZRO_MCP_AUTH=tiered` (default) — public-read tools open, mutations require Bearer
/// - `TENZRO_MCP_AUTH=full` — every call requires Bearer
/// - Any other value (including the removed `false`/`0` bypass) falls back to `tiered`
///
/// Side-effect: while `next.run(req)` is awaited, the
/// [`crate::mcp::server::MCP_REQUEST_HEADERS`] task-local is set so that
/// MCP tool handlers (running in the same tokio task) can forward the
/// inbound `Authorization` and `DPoP` headers into auth-mediated JSON-RPC
/// calls. This is what lets MCP-originated `tenzro_signTransaction` etc.
/// see the bearer's identity instead of falling through to the rejected
/// "no auth" path.
pub async fn bearer_auth_check(
    oauth_state: Arc<OAuthState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if !req.uri().path().starts_with("/mcp") {
        return next.run(req).await;
    }

    // Snapshot the inbound auth-relevant headers + request line so MCP
    // tool handlers can rebuild the same `AuthContext` that direct RPC
    // clients get from `AuthContext::from_headers`.
    let mcp_headers = crate::mcp::server::McpRequestHeaders {
        authorization: req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        dpop: req
            .headers()
            .get("dpop")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        http_method: req.method().as_str().to_string(),
        http_uri: req.uri().to_string(),
        x_tenzro_api_key: req
            .headers()
            .get("x-tenzro-api-key")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        x_tenzro_admin_token: req
            .headers()
            .get("x-tenzro-admin-token")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
    };

    // Auth mode floor is `tiered`. Historical `false`/`0` bypass was removed —
    // a public-facing MCP endpoint must never be unauthenticated for mutation
    // tools. `tiered` (default) lets public-read tools through and requires
    // Bearer for everything else; `full` requires Bearer for every call.
    let auth_mode_raw = std::env::var("TENZRO_MCP_AUTH").unwrap_or_else(|_| "tiered".to_string());
    let auth_mode = match auth_mode_raw.as_str() {
        "full" => "full",
        "tiered" => "tiered",
        other => {
            tracing::warn!(
                "TENZRO_MCP_AUTH={:?} is not recognised (or is a removed bypass value); falling back to `tiered`",
                other
            );
            "tiered"
        }
    };

    if auth_mode == "tiered" {
        let (parts, body) = req.into_parts();
        let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
            Ok(b) => b,
            Err(_) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "body too large"})),
                )
                    .into_response();
            }
        };

        if is_public_mcp_request(&body_bytes) {
            let req = Request::from_parts(parts, axum::body::Body::from(body_bytes));
            return crate::mcp::server::MCP_REQUEST_HEADERS
                .scope(mcp_headers, next.run(req))
                .await;
        }

        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let req = Request::from_parts(parts, axum::body::Body::from(body_bytes));

        match auth_header {
            Some(ref h) if h.starts_with("Bearer ") => {
                let token = &h[7..];
                match validate_bearer_jwt(&oauth_state, token) {
                    Ok(user) => {
                        let mut req = req;
                        req.extensions_mut().insert(user);
                        crate::mcp::server::MCP_REQUEST_HEADERS
                            .scope(mcp_headers, next.run(req))
                            .await
                    }
                    Err(reason) => unauthorized_response(&oauth_state, &reason),
                }
            }
            _ => (
                StatusCode::UNAUTHORIZED,
                [(
                    header::WWW_AUTHENTICATE,
                    format!(
                        "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
                        oauth_state.config.issuer
                    ),
                )],
                Json(serde_json::json!({
                    "error": "unauthorized",
                    "error_description": "This tool requires authentication. Obtain a JWT via the OAuth flow at /authorize."
                })),
            )
                .into_response(),
        }
    } else {
        // Full auth mode: require Bearer for everything.
        let auth_header = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok());

        let token = match auth_header {
            Some(h) if h.starts_with("Bearer ") => &h[7..],
            _ => {
                return (
                    StatusCode::UNAUTHORIZED,
                    [(
                        header::WWW_AUTHENTICATE,
                        format!(
                            "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
                            oauth_state.config.issuer
                        ),
                    )],
                    Json(serde_json::json!({
                        "error": "unauthorized",
                        "error_description": "Bearer token required."
                    })),
                )
                    .into_response();
            }
        };

        match validate_bearer_jwt(&oauth_state, token) {
            Ok(user) => {
                tracing::info!(
                    did = %user.did,
                    address = %user.address,
                    scope = %user.scope,
                    method = %req.method(),
                    path = %req.uri().path(),
                    "Authenticated MCP request"
                );
                let mut req = req;
                req.extensions_mut().insert(user);
                crate::mcp::server::MCP_REQUEST_HEADERS
                    .scope(mcp_headers, next.run(req))
                    .await
            }
            Err(reason) => unauthorized_response(&oauth_state, &reason),
        }
    }
}

/// Validate a Bearer JWT against the node's [`tenzro_auth::AuthEngine`].
/// DPoP is **not** enforced here (see module docs); the per-handler
/// signing path enforces it for consequential RPCs.
fn validate_bearer_jwt(
    oauth_state: &OAuthState,
    token: &str,
) -> std::result::Result<AuthenticatedUser, String> {
    let engine = oauth_state
        .node
        .auth_engine()
        .ok_or_else(|| "auth engine not initialized on this node".to_string())?;

    let claims: AuthClaims = engine
        .validate_jwt(token, None)
        .map_err(|e| format!("Invalid token: {}", e))?;

    // Resolve the bearer DID -> wallet address for downstream handlers.
    let address = match oauth_state.node.identity_registry() {
        Some(registry) => registry
            .resolve(&claims.sub)
            .map(|id| format!("0x{}", hex::encode(id.wallet_address.as_bytes())))
            .unwrap_or_default(),
        None => String::new(),
    };

    // Render the RAR envelope as a coarse scope string for backward-compatible
    // logging; the engine itself enforces the typed envelope.
    let scope = render_scope(&claims.authorization_details);

    Ok(AuthenticatedUser {
        did: claims.sub,
        address,
        scope,
    })
}

/// Render a RAR envelope as a space-separated scope string for logs.
fn render_scope(details: &AuthorizationDetails) -> String {
    let mut parts: Vec<&'static str> = Vec::new();
    for d in &details.details {
        match d {
            AuthorizationDetail::Transfer { .. } => parts.push("transfer"),
            AuthorizationDetail::CreateEscrow { .. } => parts.push("create_escrow"),
            AuthorizationDetail::DischargeEscrow { .. } => parts.push("discharge_escrow"),
            AuthorizationDetail::Inference { .. } => parts.push("inference"),
            AuthorizationDetail::Stake { .. } => parts.push("stake"),
            AuthorizationDetail::Vote { .. } => parts.push("vote"),
            AuthorizationDetail::Contract { .. } => parts.push("contract"),
            AuthorizationDetail::RegisterIdentity { .. } => parts.push("register_identity"),
            AuthorizationDetail::ResourceInvocation { .. } => parts.push("resource_invocation"),
        }
    }
    parts.sort_unstable();
    parts.dedup();
    parts.join(" ")
}

// ─── Identity Provisioning ───────────────────────────────────────────────────

/// Provision (or look up) the TDIP identity behind an OAuth client, seeding a
/// fresh one with `seed_tnzo` whole TNZO from the genesis faucet account so the
/// user can pay gas on their first call. The seed tracks the node's configured
/// faucet grant rather than a figure of its own.
async fn provision_or_retrieve_identity(
    node: &TenzroNode,
    client_id: &str,
    seed_tnzo: u128,
) -> std::result::Result<(String, String), NodeError> {
    let storage = node
        .storage()
        .ok_or_else(|| NodeError::Internal("Storage not initialized".to_string()))?;

    let mapping_key = format!("oauth_user:{}", client_id);
    if let Ok(Some(did_bytes)) = storage.get("metadata", mapping_key.as_bytes()) {
        let did = String::from_utf8(did_bytes)
            .map_err(|e| NodeError::Internal(format!("Invalid DID encoding: {}", e)))?;

        if let Some(registry) = node.identity_registry()
            && let Ok(identity) = registry.resolve(&did)
        {
            let address = format!("0x{}", hex::encode(identity.wallet_address.as_bytes()));
            tracing::info!(did = %did, address = %address, "Retrieved existing OAuth identity");
            return Ok((did, address));
        }
        tracing::warn!(did = %did, "DID mapping exists but identity not found, re-provisioning");
    }

    let registry = node
        .identity_registry()
        .ok_or_else(|| NodeError::Internal("Identity registry not initialized".to_string()))?;

    let keypair = tenzro_crypto::KeyPair::generate(tenzro_crypto::KeyType::Ed25519)
        .map_err(|e| NodeError::Internal(format!("Key generation failed: {}", e)))?;

    let display_name = format!("MCP User {}", &client_id[..client_id.len().min(8)]);

    let identity = registry
        .register_human_with_fee(
            keypair.public_key().as_bytes().to_vec(),
            display_name,
            tenzro_types::identity::KycTier::Unverified,
        )
        .await
        .map_err(|e| NodeError::Internal(format!("Identity registration failed: {}", e)))?
        .identity;

    let did = identity.did_string();
    let address = format!("0x{}", hex::encode(identity.wallet_address.as_bytes()));

    let _ = storage.put("metadata", mapping_key.as_bytes(), did.as_bytes());

    tracing::info!(did = %did, address = %address, client = %client_id, "Provisioned new TDIP identity");

    if let Some(token) = node.token() {
        let faucet_key = b"genesis_faucet_address";
        if let Ok(Some(faucet_bytes)) = storage.get("metadata", faucet_key)
            && let Ok(faucet_hex) = String::from_utf8(faucet_bytes)
            && let Ok(faucet_addr) = tenzro_types::primitives::Address::from_hex(&faucet_hex)
        {
            let amount = seed_tnzo.saturating_mul(10u128.pow(18));
            match token.transfer(&faucet_addr, &identity.wallet_address, amount) {
                Ok(_) => tracing::info!(did = %did, tnzo = seed_tnzo, "Funded new OAuth user"),
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to fund new OAuth user from faucet")
                }
            }
        }
    }

    Ok((did, address))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Mint a JWT through the node's auth engine.
///
/// `cnf_jkt` is `None` when the OAuth client did not present a DPoP
/// thumbprint at /authorize or /token; in that case the token is
/// usable for MCP middleware (which does not enforce DPoP) but cannot
/// be used for DPoP-protected RPCs like `tenzro_signTransaction`.
///
/// The RAR envelope is currently a coarse "developer scope" — see
/// subtask #52 for proper per-identity envelopes issued at onboarding.
fn mint_jwt(
    state: &OAuthState,
    did: &str,
    cnf_jkt: Option<&str>,
    _scope: &str,
) -> std::result::Result<String, crate::web::error::WalletApiError> {
    let engine = state.node.auth_engine().ok_or_else(|| {
        crate::web::error::WalletApiError::new(
            StatusCode::BAD_REQUEST,
            "server_error",
            "Auth engine not initialized on this node",
        )
    })?;

    let details = developer_scope_envelope();
    // Empty cnf.jkt means the JWT is bearer-only; this is acceptable
    // for MCP read/write tools but DPoP-bound endpoints will reject it.
    let jkt = cnf_jkt.unwrap_or("");
    engine.issue_jwt(did, did, jkt, details, None).map_err(|e| {
        tracing::error!(error = %e, "AuthEngine::issue_jwt failed");
        crate::web::error::WalletApiError::new(
            StatusCode::BAD_REQUEST,
            "server_error",
            "Token generation failed",
        )
    })
}

/// Coarse RAR envelope granted to OAuth-flow tokens. Allows the bearer
/// to perform low-value transfers, escrows, inference calls, and
/// contract interactions. Strict per-identity envelopes are issued by
/// the onboarding RPCs (subtask #52).
fn developer_scope_envelope() -> AuthorizationDetails {
    // 1 TNZO base units (10^18)
    let one_tnzo: u128 = 1_000_000_000_000_000_000;
    AuthorizationDetails::default()
        .with(AuthorizationDetail::Transfer {
            asset: AssetId::tnzo(),
            max_amount: one_tnzo * 10,
            max_daily_amount: Some(one_tnzo * 100),
            allowed_counterparties: None,
        })
        .with(AuthorizationDetail::CreateEscrow {
            asset: AssetId::tnzo(),
            max_amount: one_tnzo * 10,
            allowed_payees: None,
        })
        .with(AuthorizationDetail::DischargeEscrow {
            allowed_escrow_ids: None,
        })
        .with(AuthorizationDetail::Inference {
            max_amount_per_call: one_tnzo,
            max_daily_amount: Some(one_tnzo * 50),
            allowed_model_ids: None,
        })
        .with(AuthorizationDetail::Contract {
            allowed_contracts: None,
            allow_deploy: false,
        })
        .with(AuthorizationDetail::ResourceInvocation {
            max_amount_per_call: one_tnzo,
            class: None,
            allowed_resource_ids: None,
        })
}

fn unauthorized_response(oauth_state: &OAuthState, reason: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            header::WWW_AUTHENTICATE,
            format!(
                "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
                oauth_state.config.issuer
            ),
        )],
        Json(serde_json::json!({
            "error": "unauthorized",
            "error_description": reason
        })),
    )
        .into_response()
}

fn oauth_error(error: &str, description: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "error": error,
            "error_description": description
        })),
    )
        .into_response()
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_s256_verification() {
        let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        let hash = Sha256::digest(code_verifier.as_bytes());
        let computed = URL_SAFE_NO_PAD.encode(hash);

        assert_eq!(computed, expected_challenge);
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(
            auth_page::html_escape("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"
        );
    }

    #[test]
    fn test_oauth_error_response() {
        let _resp = oauth_error("invalid_request", "Missing parameter");
    }

    #[test]
    fn test_developer_scope_includes_transfer_and_escrow() {
        let env = developer_scope_envelope();
        let kinds: Vec<&'static str> = env
            .details
            .iter()
            .map(|d| match d {
                AuthorizationDetail::Transfer { .. } => "transfer",
                AuthorizationDetail::CreateEscrow { .. } => "create_escrow",
                AuthorizationDetail::DischargeEscrow { .. } => "discharge_escrow",
                AuthorizationDetail::Inference { .. } => "inference",
                AuthorizationDetail::Stake { .. } => "stake",
                AuthorizationDetail::Vote { .. } => "vote",
                AuthorizationDetail::Contract { .. } => "contract",
                AuthorizationDetail::RegisterIdentity { .. } => "register_identity",
                AuthorizationDetail::ResourceInvocation { .. } => "resource_invocation",
            })
            .collect();
        assert!(kinds.contains(&"transfer"));
        assert!(kinds.contains(&"create_escrow"));
        assert!(kinds.contains(&"discharge_escrow"));
        assert!(kinds.contains(&"inference"));
        assert!(kinds.contains(&"contract"));
    }

    #[test]
    fn test_render_scope_is_sorted_and_unique() {
        let env = AuthorizationDetails::default()
            .with(AuthorizationDetail::Transfer {
                asset: AssetId::tnzo(),
                max_amount: 1,
                max_daily_amount: None,
                allowed_counterparties: None,
            })
            .with(AuthorizationDetail::Transfer {
                asset: AssetId::tnzo(),
                max_amount: 2,
                max_daily_amount: None,
                allowed_counterparties: None,
            })
            .with(AuthorizationDetail::Inference {
                max_amount_per_call: 1,
                max_daily_amount: None,
                allowed_model_ids: None,
            });
        assert_eq!(render_scope(&env), "inference transfer");
    }
}
