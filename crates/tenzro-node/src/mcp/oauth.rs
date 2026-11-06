//! MCP OAuth 2.1 authorization server and bearer middleware.
//!
//! Implements the authorization surface of MCP revision 2026-07-28:
//! - RFC 8414 Authorization Server Metadata
//! - RFC 9728 Protected Resource Metadata
//! - OAuth Client ID Metadata Documents for client identification (an
//!   `https://` URL as `client_id`; see [`super::client_metadata`]). There
//!   is no dynamic registration endpoint and no client table.
//! - PKCE S256 (mandatory)
//! - RFC 8707 resource indicators: the authorization and token requests
//!   name this server's `/mcp` resource, and `/mcp` accepts only tokens
//!   issued for it
//! - RFC 9207 `iss` on every authorization response
//!
//! ## Who is authorized
//!
//! `/authorize` issues nothing until the user proves control of a passkey
//! enrolled on a Tenzro account: a WebAuthn assertion, with user
//! verification, over a challenge minted for that one authorization
//! request. The user's identity is the DID derived from that passkey.
//! Every grant is keyed to that user: the client acts as a machine
//! identity delegated by the user, so two users of the same client hold
//! two distinct identities, and revoking the user cascades to the client.
//!
//! ## Token model
//!
//! Access tokens are JWTs minted by [`tenzro_auth::AuthEngine::issue_jwt`]
//! and validated by [`tenzro_auth::AuthEngine::validate_jwt`]. The server
//! records, per token id, the resource the token was issued for; the
//! `/mcp` middleware refuses any token not recorded for the `/mcp`
//! resource, so a token minted for another Tenzro surface is not accepted
//! here. DPoP is enforced in the per-handler signing path, where the
//! token's `cnf.jkt` must match the proof key.

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
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use tenzro_auth::{AuthClaims, AuthorizationDetail, AuthorizationDetails};
use tenzro_storage::KvStore;
use tenzro_types::AssetId;
use tenzro_types::admission::ExpiringMap;

use super::auth_page;
use super::client_metadata::{ClientMetadataFetcher, ClientResolver, HttpsFetcher};
use crate::node::TenzroNode;
use crate::web::handlers::WebState;

/// Lifetime of an authorization request between `GET /authorize` and the
/// user's passkey answer.
const PENDING_TTL: Duration = Duration::from_secs(300);

/// Most authorization requests held waiting for a passkey answer.
/// `GET /authorize` is open to anyone, so past this the oldest request is
/// dropped; a user whose request was dropped starts the sign-in again.
const MAX_PENDING_AUTHORIZATIONS: usize = 4096;

/// Lifetime of an issued authorization code.
const CODE_TTL: Duration = Duration::from_secs(120);

/// Storage column the server keeps its grant records in.
const METADATA_CF: &str = "metadata";

// ─── Configuration ───────────────────────────────────────────────────────────

/// Public-facing issuer and refresh-token lifetime. The signing key is
/// owned by [`tenzro_auth::AuthEngine`].
pub struct OAuthConfig {
    /// Issuer identifier advertised in metadata and returned as `iss` on
    /// authorization responses.
    pub issuer: String,
    /// Refresh-token lifetime. Refresh tokens are opaque UUIDs persisted
    /// to storage and exchanged for new JWTs at `/token`.
    pub refresh_token_ttl: Duration,
    /// Most authorization requests held waiting for a passkey answer.
    pub max_pending_authorizations: usize,
}

impl OAuthConfig {
    pub fn new(issuer: String) -> Self {
        Self {
            issuer,
            refresh_token_ttl: Duration::from_secs(30 * 86400),
            max_pending_authorizations: MAX_PENDING_AUTHORIZATIONS,
        }
    }

    /// The canonical RFC 8707 resource identifier of this MCP server.
    pub fn resource(&self) -> String {
        format!("{}/mcp", self.issuer)
    }
}

// ─── Data Structures ─────────────────────────────────────────────────────────

/// An authorization request waiting for the user's passkey, keyed by the
/// session token embedded in the consent page.
#[derive(Debug, Clone)]
pub struct PendingAuthorization {
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub scope: String,
    pub state: Option<String>,
    pub dpop_jkt: Option<String>,
    /// Random challenge the user's passkey must sign. Single use: the
    /// pending entry is removed when the form is submitted.
    pub challenge: [u8; 32],
}

/// An issued authorization code, keyed by the code.
#[derive(Debug, Clone)]
pub struct OAuthSession {
    pub code: String,
    pub client_id: String,
    pub redirect_uri: String,
    pub code_challenge: String,
    pub scope: String,
    pub created_at: Instant,
    /// DID derived from the passkey the user authenticated with.
    pub user_did: String,
    /// DPoP key thumbprint (RFC 9449 §10.1) supplied at `/authorize`; the
    /// issued JWT's `cnf.jkt` is pinned to it.
    pub dpop_jkt: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshTokenEntry {
    pub token: String,
    pub client_id: String,
    /// The client's machine identity acting for the user.
    pub did: String,
    /// The user who authorized the grant.
    pub user_did: String,
    pub address: String,
    pub scope: String,
    pub dpop_jkt: Option<String>,
    pub expires_at: u64,
}

/// Authenticated caller extracted from a validated JWT, injected into
/// request extensions for downstream handlers.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub did: String,
    pub address: String,
    pub scope: String,
}

/// Shared OAuth state accessible by all handlers.
pub struct OAuthState {
    /// Session token (consent page) -> pending authorization request,
    /// expiring after [`PENDING_TTL`] and bounded by
    /// [`OAuthConfig::max_pending_authorizations`].
    pub pending: parking_lot::Mutex<ExpiringMap<String, PendingAuthorization>>,
    /// Authorization code -> issued code.
    pub sessions: DashMap<String, OAuthSession>,
    /// refresh_token -> metadata
    pub refresh_tokens: DashMap<String, RefreshTokenEntry>,
    /// Resolves `client_id` URLs to their metadata documents.
    pub clients: ClientResolver,
    /// Node reference for identity provisioning + auth-engine access
    pub node: Arc<TenzroNode>,
    /// Web state for node version and metrics access
    pub web_state: Arc<WebState>,
    pub config: OAuthConfig,
}

impl OAuthState {
    pub fn new(node: Arc<TenzroNode>, web_state: Arc<WebState>) -> Self {
        Self::with_fetcher(node, web_state, Arc::new(HttpsFetcher::new()))
    }

    fn with_fetcher(
        node: Arc<TenzroNode>,
        web_state: Arc<WebState>,
        fetcher: Arc<dyn ClientMetadataFetcher>,
    ) -> Self {
        let issuer = crate::exposure::mcp_origin(node.config());
        let config = OAuthConfig::new(issuer);
        Self {
            pending: parking_lot::Mutex::new(ExpiringMap::new(
                PENDING_TTL,
                config.max_pending_authorizations,
            )),
            sessions: DashMap::new(),
            refresh_tokens: DashMap::new(),
            clients: ClientResolver::new(fetcher),
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
    /// RFC 8707 resource indicator; must name this server's `/mcp`.
    pub resource: Option<String>,
    /// Optional DPoP key thumbprint per RFC 9449 §10.1.
    pub dpop_jkt: Option<String>,
}

/// The consent form. On `approve` it carries the passkey assertion over
/// the pending request's challenge, every byte field base64url, and the
/// ML-DSA-65 leg over the same challenge, hex.
#[derive(Debug, Deserialize)]
pub struct AuthorizeSubmit {
    pub session_token: String,
    pub action: String,
    pub account_address: Option<String>,
    pub credential_id: Option<String>,
    pub authenticator_data: Option<String>,
    pub client_data_json: Option<String>,
    pub signature: Option<String>,
    #[serde(default)]
    pub ml_dsa_signature: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: String,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub client_id: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    /// RFC 8707 resource indicator; must name this server's `/mcp`.
    pub resource: Option<String>,
    /// DPoP thumbprint, used when `/authorize` did not carry one.
    pub dpop_jkt: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeRequest {
    pub token: String,
    pub token_type_hint: Option<String>,
}

// ─── Metadata ────────────────────────────────────────────────────────────────

fn authorization_server_metadata(issuer: &str, node_version: &str) -> serde_json::Value {
    serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{}/authorize", issuer),
        "token_endpoint": format!("{}/token", issuer),
        "revocation_endpoint": format!("{}/revoke", issuer),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["read", "write"],
        "client_id_metadata_document_supported": true,
        "authorization_response_iss_parameter_supported": true,
        "dpop_signing_alg_values_supported": ["EdDSA", "ES256"],
        "service_documentation": "https://docs.tenzro.com/mcp",
        "server_version": node_version
    })
}

/// RFC 8414 — OAuth Authorization Server Metadata discovery.
pub async fn metadata_handler(State(state): State<Arc<OAuthState>>) -> Json<serde_json::Value> {
    Json(authorization_server_metadata(
        &state.config.issuer,
        &state.web_state.node_version,
    ))
}

/// RFC 9728 — OAuth 2.0 Protected Resource Metadata for `/mcp`.
pub async fn resource_metadata_handler(
    State(state): State<Arc<OAuthState>>,
) -> Json<serde_json::Value> {
    let iss = &state.config.issuer;
    Json(serde_json::json!({
        "resource": state.config.resource(),
        "authorization_servers": [iss],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["read", "write"],
        "resource_name": "Tenzro MCP",
        "resource_documentation": "https://docs.tenzro.com/mcp",
        "resource_policy_uri": "https://tenzro.com/policy",
        "resource_tos_uri": "https://tenzro.com/tos",
        // DPoP proofs are checked by the signing, escrow and settlement
        // handlers against the token's `cnf.jkt`.
        "dpop_signing_alg_values_supported": ["EdDSA", "ES256"],
        "dpop_bound_access_tokens_required": true,
        // RFC 9396 authorization detail types interpreted by `tenzro-auth`.
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
        "tenzro_server_version": &state.web_state.node_version,
    }))
}

// ─── Authorization endpoint ──────────────────────────────────────────────────

/// Whether `requested` names the canonical resource. Scheme and host
/// compare case-insensitively (the URL parser lowercases them); a single
/// trailing slash is not significant.
fn resource_matches(requested: &str, canonical: &str) -> bool {
    let norm = |s: &str| -> Option<String> {
        let url = url::Url::parse(s).ok()?;
        if url.fragment().is_some() {
            return None;
        }
        Some(url.to_string().trim_end_matches('/').to_string())
    };
    matches!((norm(requested), norm(canonical)), (Some(a), Some(b)) if a == b)
}

/// Build the redirect back to the client with `params` and the RFC 9207
/// `iss` appended to whatever query the registered URI already carries.
fn authorization_redirect(
    redirect_uri: &str,
    issuer: &str,
    params: &[(&str, &str)],
) -> Result<String, String> {
    let mut url = url::Url::parse(redirect_uri).map_err(|e| e.to_string())?;
    {
        let mut q = url.query_pairs_mut();
        for (k, v) in params {
            q.append_pair(k, v);
        }
        q.append_pair("iss", issuer);
    }
    Ok(url.to_string())
}

fn bad_request_page(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Html(auth_page::html_escape(message)),
    )
        .into_response()
}

/// GET /authorize — validate the client and request, then render the
/// passkey consent page.
///
/// Every refusal here is a plain 400 page, never a redirect: until the
/// client document is fetched and the redirect URI found in it, the
/// redirect URI is not known to belong to the client.
pub async fn authorize_handler(
    State(state): State<Arc<OAuthState>>,
    Query(params): Query<AuthorizeQuery>,
) -> impl IntoResponse {
    let client = match state.clients.resolve(&params.client_id).await {
        Ok(c) => c,
        Err(e) => return bad_request_page(&format!("Unknown client: {e}")),
    };
    if !client.allows_redirect(&params.redirect_uri) {
        return bad_request_page(
            "redirect_uri is not one of the redirect URIs in the client's metadata document",
        );
    }
    if params.response_type != "code" {
        return bad_request_page("Unsupported response_type. Only 'code' is supported.");
    }
    if params.code_challenge_method != "S256" {
        return bad_request_page("Only the S256 code_challenge_method is supported.");
    }
    match params.resource.as_deref() {
        Some(r) if resource_matches(r, &state.config.resource()) => {}
        Some(r) => {
            return bad_request_page(&format!(
                "resource '{r}' is not served by this authorization server; expected {}",
                state.config.resource()
            ));
        }
        None => {
            return bad_request_page(&format!(
                "Missing resource parameter (RFC 8707); expected {}",
                state.config.resource()
            ));
        }
    }

    let scope = params.scope.as_deref().unwrap_or("read write").to_string();
    let mut challenge = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut challenge);
    let session_token = Uuid::new_v4().to_string();

    state.pending.lock().insert(
        session_token.clone(),
        PendingAuthorization {
            client_id: client.client_id.clone(),
            redirect_uri: params.redirect_uri.clone(),
            code_challenge: params.code_challenge.clone(),
            scope: scope.clone(),
            state: params.state.clone(),
            dpop_jkt: params.dpop_jkt.clone(),
            challenge,
        },
    );

    let rp_id = state
        .node
        .webauthn_validator()
        .map(|v| relying_party_id(v.relying_party()))
        .unwrap_or_default();

    Html(auth_page::render_authorize_page(&auth_page::ConsentPage {
        client_name: &client.client_name,
        client_id: &client.client_id,
        scope: &scope,
        session_token: &session_token,
        challenge_b64: &URL_SAFE_NO_PAD.encode(challenge),
        rp_id: &rp_id,
    }))
    .into_response()
}

/// The RP ID a browser passes to `navigator.credentials.get`.
fn relying_party_id(rp: &tenzro_crypto::webauthn::WebAuthnRelyingParty) -> String {
    match rp {
        tenzro_crypto::webauthn::WebAuthnRelyingParty::Origin(origin) => url::Url::parse(origin)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_default(),
        tenzro_crypto::webauthn::WebAuthnRelyingParty::RegistrableDomain { rp_id, .. } => {
            rp_id.clone()
        }
    }
}

/// The passkey answer to one pending authorization.
pub struct PasskeyLogin<'a> {
    pub account_address: &'a str,
    pub credential_id_b64: &'a str,
    pub authenticator_data_b64: &'a str,
    pub client_data_json_b64: &'a str,
    pub signature_b64: &'a str,
    /// The ML-DSA-65 signature over the challenge under the account-owner
    /// context, hex, made by the hardware key enrolled with the passkey.
    pub ml_dsa_signature_hex: Option<&'a str>,
}

/// The P-256 key (`x || y`) of the passkey an account with no keystore on
/// chain yet derives from, as the identity registered at enrolment names it.
/// Only a key that derives the account is ever used (see
/// `WebAuthnValidator::keystore_or_genesis`).
pub(crate) fn registered_genesis_key(
    registry: &tenzro_identity::IdentityRegistry,
    account: &[u8],
) -> Option<Vec<u8>> {
    let did = registry.find_did_by_wallet_id(&format!("0x{}", hex::encode(account)))?;
    let identity = registry.resolve(&did).ok()?;
    identity
        .public_keys
        .iter()
        .map(|k| match k.public_key.as_slice() {
            [0x04, xy @ ..] if xy.len() == 64 => xy.to_vec(),
            other => other.to_vec(),
        })
        .find(|k| k.len() == 64)
}

/// Verify a passkey login against `challenge` and return the user's DID.
///
/// The credential must be linked by the named account's keystore (for an
/// account with none on chain yet, be the first passkey the account derives
/// from, whose key `genesis_key` recalls), the assertion must be a
/// `webauthn.get` over exactly this challenge for this node's relying party
/// with user verification, and the account's owner must be a registered,
/// active human identity. Any linked passkey signs in as that owner.
///
/// The ML-DSA-65 leg is required: it must verify over the challenge under
/// the account-owner context against the ML-DSA-65 key enrolled for the
/// passkey on chain or, before that, the one the owner's identity recorded
/// at enrolment (`identity_pq_key`). A passkey with no ML-DSA-65 key cannot
/// sign in.
pub fn verify_passkey_login(
    validator: &tenzro_vm::WebAuthnValidator,
    challenge: &[u8; 32],
    login: &PasskeyLogin<'_>,
    is_active_human: impl Fn(&str) -> bool,
    genesis_key: impl Fn(&[u8]) -> Option<Vec<u8>>,
    identity_pq_key: impl Fn(&str) -> Option<Vec<u8>>,
) -> Result<String, String> {
    let b64 = |field: &str, v: &str| -> Result<Vec<u8>, String> {
        URL_SAFE_NO_PAD
            .decode(v.trim_end_matches('='))
            .map_err(|_| format!("{field} is not base64url"))
    };
    let account = hex::decode(login.account_address.trim().trim_start_matches("0x"))
        .map_err(|_| "account_address is not hex".to_string())?;
    let credential_id = b64("credential_id", login.credential_id_b64)?;
    // A login ceremony is hosted by this node, on its relying party: the
    // one an account with no keystore on chain yet enrolled through here.
    let node_rp_id = relying_party_id(validator.relying_party());
    let anchor = genesis_key(&account).map(|public_key| tenzro_types::keystore::KeystoreAnchor {
        rp_id: node_rp_id.clone(),
        credential_id: credential_id.clone(),
        public_key,
        aaguid: vec![0; 16],
        backup_eligible: false,
        backup_state: false,
        salt: 0,
    });
    let keystore = validator
        .keystore_or_genesis(&account, anchor.as_ref())
        .ok_or_else(|| "that account has no keystore linking this passkey".to_string())?;
    let key = keystore
        .credential_by_id(&credential_id)
        .ok_or_else(|| "this passkey is not linked to that account".to_string())?;
    let mut xy = [0u8; 64];
    xy.copy_from_slice(&key.public_key);

    let assertion = tenzro_crypto::webauthn::WebAuthnAssertion {
        authenticator_data: b64("authenticator_data", login.authenticator_data_b64)?,
        client_data_json: b64("client_data_json", login.client_data_json_b64)?,
        signature: b64("signature", login.signature_b64)?,
        user_handle: None,
    };
    tenzro_crypto::webauthn::verify_webauthn_assertion_require_uv(
        &assertion,
        &xy,
        &URL_SAFE_NO_PAD.encode(challenge),
        &tenzro_crypto::webauthn::WebAuthnRelyingParty::RegistrableDomain {
            rp_id: key.rp_id.clone(),
            related_origins: Vec::new(),
        },
        tenzro_crypto::webauthn::WebAuthnCeremonyType::Get,
    )
    .map_err(|e| format!("passkey assertion rejected: {e}"))?;

    // Every passkey linked to the account signs in as the account's owner.
    let did = keystore.owner_did.clone();
    let pq_key = validator
        .enrolled_pq_key(&key.public_key)
        .or_else(|| identity_pq_key(&did).filter(|k| !k.is_empty()))
        .ok_or_else(|| {
            "this passkey has no ML-DSA-65 key enrolled; enrol one with the passkey before signing in"
                .to_string()
        })?;
    let pq_sig = login
        .ml_dsa_signature_hex
        .ok_or_else(|| "sign-in requires the ML-DSA-65 signature over the challenge".to_string())?;
    let pq_sig = hex::decode(pq_sig.trim().trim_start_matches("0x"))
        .map_err(|_| "ml_dsa_signature is not hex".to_string())?;
    tenzro_crypto::composite::verify_pq_component(
        Some(&pq_key),
        tenzro_crypto::composite::SignatureContext::AccountOwner,
        challenge,
        Some(&pq_sig),
        tenzro_crypto::composite::PqPolicy::Required,
    )
    .map_err(|e| format!("ML-DSA-65 signature rejected: {e}"))?;
    if !is_active_human(&did) {
        return Err(format!(
            "{did} is not an active human identity on this node"
        ));
    }
    Ok(did)
}

/// POST /authorize — the user's decision. `approve` must carry a passkey
/// assertion; `deny` needs none.
pub async fn authorize_submit_handler(
    State(state): State<Arc<OAuthState>>,
    Form(form): Form<AuthorizeSubmit>,
) -> impl IntoResponse {
    let taken = state.pending.lock().take(&form.session_token);
    let Some(pending) = taken else {
        return bad_request_page("Invalid or expired authorization session.");
    };
    let issuer = state.config.issuer.clone();
    let with_state = |mut v: Vec<(&'static str, String)>| {
        if let Some(s) = &pending.state {
            v.push(("state", s.clone()));
        }
        v
    };
    let redirect = |params: Vec<(&'static str, String)>| -> Response {
        let refs: Vec<(&str, &str)> = params.iter().map(|(k, v)| (*k, v.as_str())).collect();
        match authorization_redirect(&pending.redirect_uri, &issuer, &refs) {
            Ok(url) => Redirect::to(&url).into_response(),
            Err(e) => bad_request_page(&format!("redirect_uri does not parse: {e}")),
        }
    };

    if form.action != "approve" {
        return redirect(with_state(vec![
            ("error", "access_denied".to_string()),
            ("error_description", "User denied the request".to_string()),
        ]));
    }

    let (Some(account), Some(cred), Some(ad), Some(cdj), Some(sig)) = (
        form.account_address.as_deref(),
        form.credential_id.as_deref(),
        form.authenticator_data.as_deref(),
        form.client_data_json.as_deref(),
        form.signature.as_deref(),
    ) else {
        return bad_request_page("Approval requires signing in with your passkey.");
    };
    let (Some(validator), Some(registry)) = (
        state.node.webauthn_validator(),
        state.node.identity_registry(),
    ) else {
        return bad_request_page("Passkey sign-in is not available on this node.");
    };
    let login = PasskeyLogin {
        account_address: account,
        credential_id_b64: cred,
        authenticator_data_b64: ad,
        client_data_json_b64: cdj,
        signature_b64: sig,
        ml_dsa_signature_hex: form.ml_dsa_signature.as_deref(),
    };
    let user_did = match verify_passkey_login(
        validator,
        &pending.challenge,
        &login,
        |did| {
            registry.resolve(did).is_ok_and(|id| {
                id.is_human() && id.status == tenzro_identity::IdentityStatus::Active
            })
        },
        |account| registered_genesis_key(registry, account),
        |did| registry.resolve(did).ok().map(|id| id.pq_verifying_key),
    ) {
        Ok(did) => did,
        Err(e) => {
            tracing::warn!(client = %pending.client_id, error = %e, "MCP authorization sign-in refused");
            return redirect(with_state(vec![
                ("error", "access_denied".to_string()),
                ("error_description", "Passkey sign-in failed".to_string()),
            ]));
        }
    };

    let code = Uuid::new_v4().to_string();
    state.sessions.insert(
        code.clone(),
        OAuthSession {
            code: code.clone(),
            client_id: pending.client_id.clone(),
            redirect_uri: pending.redirect_uri.clone(),
            code_challenge: pending.code_challenge.clone(),
            scope: pending.scope.clone(),
            created_at: Instant::now(),
            user_did,
            dpop_jkt: pending.dpop_jkt.clone(),
        },
    );
    redirect(with_state(vec![("code", code)]))
}

// ─── Token endpoint ──────────────────────────────────────────────────────────

/// POST /token — exchange an authorization code or refresh token.
pub async fn token_handler(
    State(state): State<Arc<OAuthState>>,
    headers: axum::http::HeaderMap,
    Form(req): Form<TokenRequest>,
) -> impl IntoResponse {
    match req.resource.as_deref() {
        Some(r) if resource_matches(r, &state.config.resource()) => {}
        Some(_) => {
            return oauth_error(
                "invalid_target",
                "resource is not served by this authorization server",
            );
        }
        None => return oauth_error("invalid_request", "Missing 'resource' parameter (RFC 8707)"),
    }
    match req.grant_type.as_str() {
        "authorization_code" => handle_auth_code_grant(state, &headers, req).await,
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
/// are revoked through the [`tenzro_auth::AuthEngine`], which cascades
/// through the controller_did chain.
pub async fn revoke_handler(
    State(state): State<Arc<OAuthState>>,
    Form(req): Form<RevokeRequest>,
) -> impl IntoResponse {
    let hint = req.token_type_hint.as_deref();

    match hint {
        Some("access_token") => revoke_jwt_via_engine(&state, &req.token),
        _ => {
            if state.refresh_tokens.remove(&req.token).is_some() {
                if let Some(storage) = state.node.storage() {
                    let key = format!("oauth_refresh:{}", req.token);
                    let _ = storage.delete(METADATA_CF, key.as_bytes());
                }
                tracing::debug!("Revoked refresh token");
            } else {
                revoke_jwt_via_engine(&state, &req.token);
            }
        }
    }
    StatusCode::OK
}

/// Extract the `jti` without verifying the signature and ask the auth
/// engine to revoke it. Revocation is idempotent: a forged token names a
/// `jti` that does not exist, which is a no-op.
fn revoke_jwt_via_engine(state: &OAuthState, token: &str) {
    let Some(engine) = state.node.auth_engine() else {
        tracing::warn!("Cannot revoke JWT: auth engine not initialized");
        return;
    };
    let Some(jti) = tenzro_auth::peek_unverified_jti(token) else {
        tracing::debug!("Revoke called with a token carrying no readable jti");
        return;
    };
    match engine.revoke(&jti, "client revocation request") {
        Ok(()) => tracing::info!(jti = %jti, "Revoked JWT via auth engine"),
        Err(e) => tracing::warn!(jti = %jti, error = %e, "Auth engine revoke failed"),
    }
}

async fn handle_auth_code_grant(
    state: Arc<OAuthState>,
    headers: &axum::http::HeaderMap,
    req: TokenRequest,
) -> Response {
    let Some(code) = req.code.as_deref() else {
        return oauth_error("invalid_request", "Missing 'code' parameter");
    };
    let Some(code_verifier) = req.code_verifier.as_deref() else {
        return oauth_error("invalid_request", "Missing 'code_verifier' parameter");
    };
    let Some(client_id) = req.client_id.as_deref() else {
        return oauth_error("invalid_request", "Missing 'client_id' parameter");
    };
    let Some(redirect_uri) = req.redirect_uri.as_deref() else {
        return oauth_error("invalid_request", "Missing 'redirect_uri' parameter");
    };

    // Single use: removed before any check, so a failed attempt burns it.
    let session = match state.sessions.remove(code) {
        Some((_, s)) => s,
        None => return oauth_error("invalid_grant", "Invalid or expired authorization code"),
    };
    if session.created_at.elapsed() > CODE_TTL {
        return oauth_error("invalid_grant", "Authorization code has expired");
    }
    if client_id != session.client_id {
        return oauth_error(
            "invalid_grant",
            "client_id does not match the authorization request",
        );
    }
    if redirect_uri != session.redirect_uri {
        return oauth_error(
            "invalid_grant",
            "redirect_uri does not match the authorization request",
        );
    }
    let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
    if computed != session.code_challenge {
        return oauth_error("invalid_grant", "PKCE verification failed");
    }

    // The client's DPoP key anchors its machine identity: the client holds
    // its own hardware P-256 key, so there is nothing for the node to mint.
    // The token request carries a DPoP proof (RFC 9449 section 5) by that
    // key; its JWK is the machine's public key and must match the thumbprint
    // bound at `/authorize`, when one was.
    let token_url = format!("{}/token", state.config.issuer);
    let (dpop_jkt, client_key) = match dpop_client_key(headers, &token_url) {
        Ok((jkt, key)) => {
            let bound = session.dpop_jkt.clone().or(req.dpop_jkt.clone());
            if bound.is_some_and(|b| b != jkt) {
                return oauth_error(
                    "invalid_dpop_proof",
                    "the DPoP key is not the one bound at /authorize",
                );
            }
            (Some(jkt), key)
        }
        Err(e) => return oauth_error("invalid_dpop_proof", &e),
    };

    let (did, address) = match provision_or_retrieve_identity(
        &state.node,
        &session.user_did,
        &session.client_id,
        client_key,
    )
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "Identity provisioning failed");
            return oauth_error(
                "server_error",
                &format!("Identity provisioning failed: {e}"),
            );
        }
    };

    let access_token = match issue_mcp_token(&state, &did, &session.user_did, dpop_jkt.as_deref()) {
        Ok(t) => t,
        Err(e) => return e,
    };

    let refresh_token = Uuid::new_v4().to_string();
    let entry = RefreshTokenEntry {
        token: refresh_token.clone(),
        client_id: session.client_id.clone(),
        did: did.clone(),
        user_did: session.user_did.clone(),
        address: address.clone(),
        scope: session.scope.clone(),
        dpop_jkt,
        expires_at: unix_now() + state.config.refresh_token_ttl.as_secs(),
    };
    state
        .refresh_tokens
        .insert(refresh_token.clone(), entry.clone());
    if let Some(storage) = state.node.storage()
        && let Ok(data) = serde_json::to_vec(&entry)
    {
        let key = format!("oauth_refresh:{}", refresh_token);
        let _ = storage.put(METADATA_CF, key.as_bytes(), &data);
    }

    tracing::info!(did = %did, user = %session.user_did, client = %session.client_id, "Issued MCP access token");
    token_response(&state, access_token, refresh_token, &session.scope)
}

async fn handle_refresh_grant(state: Arc<OAuthState>, req: TokenRequest) -> Response {
    let Some(rt) = req.refresh_token.as_deref() else {
        return oauth_error("invalid_request", "Missing 'refresh_token' parameter");
    };
    let Some(client_id) = req.client_id.as_deref() else {
        return oauth_error("invalid_request", "Missing 'client_id' parameter");
    };

    let entry = if let Some(e) = state.refresh_tokens.get(rt) {
        e.value().clone()
    } else if let Some(storage) = state.node.storage() {
        let key = format!("oauth_refresh:{}", rt);
        match storage.get(METADATA_CF, key.as_bytes()) {
            Ok(Some(data)) => match serde_json::from_slice::<RefreshTokenEntry>(&data) {
                Ok(e) => e,
                Err(_) => return oauth_error("invalid_grant", "Invalid refresh token"),
            },
            _ => return oauth_error("invalid_grant", "Invalid refresh token"),
        }
    } else {
        return oauth_error("invalid_grant", "Invalid refresh token");
    };

    if unix_now() > entry.expires_at {
        state.refresh_tokens.remove(rt);
        return oauth_error("invalid_grant", "Refresh token has expired");
    }
    if client_id != entry.client_id {
        return oauth_error(
            "invalid_grant",
            "refresh token was issued to a different client",
        );
    }
    // A refresh token cannot move the grant to a different key: a stolen
    // refresh token must not mint access tokens bound to the thief's key.
    if let Some(requested) = req.dpop_jkt.as_deref()
        && entry.dpop_jkt.as_deref() != Some(requested)
    {
        return oauth_error(
            "invalid_grant",
            "dpop_jkt differs from the key this grant is bound to",
        );
    }

    let access_token = match issue_mcp_token(
        &state,
        &entry.did,
        &entry.user_did,
        entry.dpop_jkt.as_deref(),
    ) {
        Ok(t) => t,
        Err(e) => return e,
    };
    tracing::info!(did = %entry.did, "Refreshed MCP access token");
    token_response(&state, access_token, rt.to_string(), &entry.scope)
}

fn token_response(
    state: &OAuthState,
    access_token: String,
    refresh_token: String,
    scope: &str,
) -> Response {
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
            "scope": scope
        })),
    )
        .into_response()
}

// ─── Token-resource binding ──────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct ResourceBinding {
    resource: String,
    expires_at: u64,
}

fn binding_key(jti: &str) -> String {
    format!("mcp_token_resource:{jti}")
}

/// Record that the token `jti` was issued for `resource`.
fn bind_token_resource(
    storage: &dyn KvStore,
    jti: &str,
    resource: &str,
    expires_at: u64,
) -> Result<(), String> {
    let row = serde_json::to_vec(&ResourceBinding {
        resource: resource.to_string(),
        expires_at,
    })
    .map_err(|e| e.to_string())?;
    storage
        .put(METADATA_CF, binding_key(jti).as_bytes(), &row)
        .map_err(|e| e.to_string())
}

/// Validate a bearer JWT for `resource`: a valid engine token whose id
/// this server recorded as issued for exactly that resource.
fn authenticate_bearer(
    engine: &tenzro_auth::AuthEngine,
    storage: &dyn KvStore,
    token: &str,
    resource: &str,
) -> Result<AuthClaims, String> {
    let claims = engine
        .validate_jwt(token, None)
        .map_err(|e| format!("Invalid token: {e}"))?;
    let row = storage
        .get(METADATA_CF, binding_key(&claims.jti).as_bytes())
        .map_err(|e| format!("token binding lookup failed: {e}"))?
        .ok_or_else(|| {
            format!(
                "this token was not issued for {resource}; obtain one from this server's /authorize"
            )
        })?;
    let binding: ResourceBinding =
        serde_json::from_slice(&row).map_err(|e| format!("token binding unreadable: {e}"))?;
    if binding.resource != resource {
        return Err(format!(
            "this token was issued for {}, not {resource}",
            binding.resource
        ));
    }
    Ok(claims)
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
    // Provenance (read-only)
    "get_provenance",
    // Bridge info
    "get_bridge_routes",
    "list_bridge_adapters",
    // deBridge read-only
    "debridge_search_tokens",
    "debridge_get_chains",
    "debridge_get_instructions",
    // Staking & governance queries
    "get_provider_stats",
    "get_model_stacks",
    "get_provider_pricing",
    "list_registry",
    "get_registry_entry",
    "get_price_card",
    "list_proposals",
    "get_voting_power",
    "get_sponsored_bond",
    "get_treasury_payouts",
    "get_guardian_state",
    "can_transfer",
    // Task & agent browsing
    "list_agent_templates",
    "get_agent_template",
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
        "server/discover" | "tools/list" | "resources/list" | "prompts/list" | "ping" => true,
        "tools/call" => {
            fn name(p: Option<&serde_json::Value>) -> &str {
                p.and_then(|p| p.get("name"))
                    .and_then(|n| n.as_str())
                    .unwrap_or("")
            }
            let params = json.get("params");
            match name(params) {
                // The compact listing (`/mcp/compact`): finding tools is
                // public, and a `call` is public exactly when the tool it
                // names is.
                "search" => true,
                "call" => PUBLIC_MCP_TOOLS.contains(&name(params.and_then(|p| p.get("arguments")))),
                tool => PUBLIC_MCP_TOOLS.contains(&tool),
            }
        }
        _ => false,
    }
}

/// Which `/mcp` calls require a Bearer JWT, from `TENZRO_MCP_AUTH`:
///
/// - `tiered` (the default when unset) — public-read tools open, every
///   other call requires a Bearer JWT issued for this `/mcp` resource
/// - `full` — every call requires one
///
/// Any other value is a configuration error and the MCP server does not start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum McpAuthMode {
    Tiered,
    Full,
}

impl McpAuthMode {
    pub fn parse(raw: Option<&str>) -> Result<Self, String> {
        match raw {
            None | Some("tiered") => Ok(Self::Tiered),
            Some("full") => Ok(Self::Full),
            Some(other) => Err(format!(
                "TENZRO_MCP_AUTH={other:?} is not recognised; expected `tiered` or `full`"
            )),
        }
    }

    pub fn from_env() -> Result<Self, String> {
        Self::parse(std::env::var("TENZRO_MCP_AUTH").ok().as_deref())
    }
}

/// Bearer token authentication middleware for `/mcp`, enforcing `auth_mode`.
///
/// While `next.run(req)` is awaited, the
/// [`crate::mcp::server::MCP_REQUEST_HEADERS`] task-local carries the
/// inbound `Authorization` and `DPoP` headers so tool
/// handlers can forward them into the JSON-RPC layer.
pub async fn bearer_auth_check(
    oauth_state: Arc<OAuthState>,
    auth_mode: McpAuthMode,
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    if !req.uri().path().starts_with("/mcp") {
        return next.run(req).await;
    }

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
        // The URL as the client dialled it, which a DPoP proof covers: the
        // same one the access gate checks the proof against.
        http_uri: crate::inference_admission::auth_context(&oauth_state.node, &req).http_uri,
    };

    let full = auth_mode == McpAuthMode::Full;

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
    if !full && is_public_mcp_request(&body_bytes) {
        let req = Request::from_parts(parts, axum::body::Body::from(body_bytes));
        return crate::mcp::server::MCP_REQUEST_HEADERS
            .scope(mcp_headers, next.run(req))
            .await;
    }

    let token = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(str::to_string);
    let Some(token) = token else {
        return unauthorized_response(
            &oauth_state,
            "This call requires authentication. Obtain a token through this server's \
             /authorize flow.",
        );
    };
    match validate_bearer_jwt(&oauth_state, &token) {
        Ok(user) => {
            let mut req = Request::from_parts(parts, axum::body::Body::from(body_bytes));
            req.extensions_mut().insert(user);
            crate::mcp::server::MCP_REQUEST_HEADERS
                .scope(mcp_headers, next.run(req))
                .await
        }
        Err(reason) => unauthorized_response(&oauth_state, &reason),
    }
}

/// Validate a Bearer JWT for this server's `/mcp` resource.
pub(crate) fn validate_bearer_jwt(
    oauth_state: &OAuthState,
    token: &str,
) -> std::result::Result<AuthenticatedUser, String> {
    let engine = oauth_state
        .node
        .auth_engine()
        .ok_or_else(|| "auth engine not initialized on this node".to_string())?;
    let storage = oauth_state
        .node
        .storage()
        .ok_or_else(|| "storage not initialized on this node".to_string())?;
    let claims = authenticate_bearer(engine, &**storage, token, &oauth_state.config.resource())?;

    let address = match oauth_state.node.identity_registry() {
        Some(registry) => registry
            .resolve(&claims.sub)
            .map(|id| format!("0x{}", hex::encode(id.wallet_address.as_bytes())))
            .unwrap_or_default(),
        None => String::new(),
    };
    Ok(AuthenticatedUser {
        did: claims.sub,
        address,
        scope: render_scope(&claims.authorization_details),
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

fn grant_key(user_did: &str, client_id: &str) -> String {
    format!("oauth_grant:{user_did}:{client_id}")
}

/// The client key a token request's `DPoP` proof is signed with: its JWK
/// thumbprint and its P-256 point `x || y`. The proof must be an ES256 proof
/// over `POST` to `token_url`, fresh, and verify under its own JWK.
fn dpop_client_key(
    headers: &axum::http::HeaderMap,
    token_url: &str,
) -> Result<(String, Vec<u8>), String> {
    let header = headers
        .get("dpop")
        .and_then(|v| v.to_str().ok())
        .ok_or("a DPoP proof by the client's own key is required: the node does not mint one")?;
    let (proof, signed_input, signature) = tenzro_auth::DpopProof::parse_with_signed_input(header)
        .map_err(|e| format!("DPoP proof: {e}"))?;
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let verified = proof
        .verify("POST", token_url, now_unix, &signed_input, &signature)
        .map_err(|e| format!("DPoP proof: {e}"))?;
    let jwk: serde_json::Value =
        serde_json::from_str(&proof.jwk_json).map_err(|e| format!("DPoP jwk: {e}"))?;
    if jwk.get("kty").and_then(|v| v.as_str()) != Some("EC")
        || jwk.get("crv").and_then(|v| v.as_str()) != Some("P-256")
    {
        return Err("the DPoP key must be a P-256 key".to_string());
    }
    let coord = |name: &str| {
        jwk.get(name)
            .and_then(|v| v.as_str())
            .and_then(|c| URL_SAFE_NO_PAD.decode(c).ok())
            .filter(|c| c.len() == 32)
            .ok_or_else(|| format!("DPoP jwk {name} is not a 32-byte coordinate"))
    };
    Ok((verified.jkt, [coord("x")?, coord("y")?].concat()))
}

/// Provision (or look up) the machine identity through which `client_id`
/// acts for `user_did`.
///
/// The identity is delegated by the user: its controller is the user's
/// passkey-derived DID, so each user of a client gets a separate identity
/// and revoking the user revokes every client acting for them. Its key is
/// the client's own DPoP key.
///
/// The stored `oauth_grant` row is only an index: a row whose identity is
/// not controlled by `user_did` is ignored and a fresh identity provisioned.
async fn provision_or_retrieve_identity(
    node: &TenzroNode,
    user_did: &str,
    client_id: &str,
    device_public_key: Vec<u8>,
) -> std::result::Result<(String, String), NodeError> {
    let storage = node
        .storage()
        .ok_or_else(|| NodeError::Internal("Storage not initialized".to_string()))?;
    let registry = node
        .identity_registry()
        .ok_or_else(|| NodeError::Internal("Identity registry not initialized".to_string()))?;

    let index_key = grant_key(user_did, client_id);
    if let Ok(Some(did_bytes)) = storage.get(METADATA_CF, index_key.as_bytes())
        && let Ok(did) = String::from_utf8(did_bytes)
        && let Ok(identity) = registry.resolve(&did)
        && identity.controller_did() == Some(user_did)
    {
        let address = format!("0x{}", hex::encode(identity.wallet_address.as_bytes()));
        return Ok((did, address));
    }

    let identity = registry
        .register_machine_via_binder(
            user_did,
            format!("oauth-client:{client_id}"),
            device_public_key,
            vec!["mcp".to_string()],
        )
        .await
        .map_err(|e| NodeError::Internal(format!("Identity registration failed: {}", e)))?
        .identity;

    let did = identity.did_string();
    let address = format!("0x{}", hex::encode(identity.wallet_address.as_bytes()));
    let _ = storage.put(METADATA_CF, index_key.as_bytes(), did.as_bytes());
    tracing::info!(did = %did, user = %user_did, client = %client_id, "Provisioned delegated MCP client identity");

    Ok((did, address))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Mint a JWT for `bearer_did` acting under `controller_did`, and record
/// it as issued for this server's `/mcp` resource.
fn issue_mcp_token(
    state: &OAuthState,
    bearer_did: &str,
    controller_did: &str,
    cnf_jkt: Option<&str>,
) -> std::result::Result<String, Response> {
    let engine = state
        .node
        .auth_engine()
        .ok_or_else(|| oauth_error("server_error", "Auth engine not initialized on this node"))?;
    let storage = state
        .node
        .storage()
        .ok_or_else(|| oauth_error("server_error", "Storage not initialized on this node"))?;
    mint_bound_token(
        engine,
        &**storage,
        bearer_did,
        controller_did,
        cnf_jkt,
        &state.config.resource(),
    )
    .map_err(|e| {
        tracing::error!(error = %e, "MCP token issuance failed");
        oauth_error("server_error", "Token generation failed")
    })
}

fn mint_bound_token(
    engine: &tenzro_auth::AuthEngine,
    storage: &dyn KvStore,
    bearer_did: &str,
    controller_did: &str,
    cnf_jkt: Option<&str>,
    resource: &str,
) -> Result<String, String> {
    let token = engine
        .issue_jwt(
            bearer_did,
            controller_did,
            cnf_jkt.unwrap_or(""),
            developer_scope_envelope(),
            None,
        )
        .map_err(|e| e.to_string())?;
    let jti = tenzro_auth::peek_unverified_jti(&token)
        .ok_or_else(|| "issued token carries no jti".to_string())?;
    let expires_at = unix_now() + engine.config().max_ttl_secs;
    bind_token_resource(storage, &jti, resource, expires_at)?;
    Ok(token)
}

/// RAR envelope granted to tokens from the MCP authorization flow:
/// low-value transfers, escrows, inference calls and contract
/// interactions. Per-identity envelopes come from the onboarding RPCs.
fn developer_scope_envelope() -> AuthorizationDetails {
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
    fn an_unknown_mcp_auth_mode_is_refused() {
        assert_eq!(McpAuthMode::parse(None), Ok(McpAuthMode::Tiered));
        assert_eq!(McpAuthMode::parse(Some("tiered")), Ok(McpAuthMode::Tiered));
        assert_eq!(McpAuthMode::parse(Some("full")), Ok(McpAuthMode::Full));
        let err = McpAuthMode::parse(Some("ful")).unwrap_err();
        assert!(err.contains("not recognised"), "{err}");
        assert!(McpAuthMode::parse(Some("")).is_err());
    }
    use tenzro_crypto::p256::{P256KeyPair, P256Signer};
    use tenzro_crypto::webauthn::{WebAuthnRelyingParty, webauthn_signed_hash};
    use tenzro_storage::MemoryStore;

    const RESOURCE: &str = "https://mcp.tenzro.com/mcp";

    /// A passkey the test holds, enrolled on `account` in `validator`.
    struct TestPasskey {
        keypair: P256KeyPair,
        credential_id: Vec<u8>,
        account: Vec<u8>,
        /// The hardware ML-DSA-65 key enrolled with the passkey.
        pq: tenzro_crypto::pq::MlDsaSigningKey,
    }

    impl TestPasskey {
        fn enroll(validator: &tenzro_vm::WebAuthnValidator, seed: u8) -> Self {
            let keypair = P256KeyPair::generate();
            let xy = keypair.public_key_bytes();
            let account = vec![seed; 20];
            let credential_id = vec![seed, 0xc0, 0xde];
            // Link the passkey the way a KeystoreUpdate leaves chain state.
            let record = tenzro_types::keystore::KeystoreRecord {
                account: account.clone(),
                owner_did: tenzro_identity::TenzroDid::from_passkey(&xy).to_string(),
                salt: 0,
                version: 1,
                credentials: vec![tenzro_types::keystore::KeystoreCredential {
                    rp_id: relying_party_id(validator.relying_party()),
                    credential_id: credential_id.clone(),
                    public_key: xy.to_vec(),
                    aaguid: vec![0; 16],
                    backup_eligible: true,
                    backup_state: true,
                    counts_as_root_from_ms: 0,
                    label: String::new(),
                    added_at_ms: 0,
                }],
                policy: Default::default(),
                recovery_signers: Vec::new(),
                recovery_threshold: 0,
                pending_recovery: None,
                recovery_code: None,
            };
            let mut state = validator.state();
            tenzro_vm::keystore::write_record(&mut state, None, &record, &mut Vec::new())
                .expect("link");
            state.commit().expect("commit");
            Self {
                keypair,
                credential_id,
                account,
                pq: tenzro_crypto::pq::MlDsaSigningKey::from_seed(&[seed; 32]).expect("pq key"),
            }
        }

        fn pq_key(&self) -> Option<Vec<u8>> {
            Some(self.pq.verifying_key_bytes().to_vec())
        }

        /// The ML-DSA-65 leg over `challenge` under the account-owner
        /// context, hex.
        fn pq_leg(&self, challenge: &[u8; 32]) -> String {
            use tenzro_crypto::composite::{
                LABEL_MLDSA65_P256, SignatureContext, message_representative,
            };
            hex::encode(self.pq.sign(
                LABEL_MLDSA65_P256,
                &message_representative(SignatureContext::AccountOwner, challenge),
            ))
        }

        fn did(&self) -> String {
            tenzro_identity::TenzroDid::from_passkey(&self.keypair.public_key_bytes()).to_string()
        }

        /// Assertion over `challenge` for `rp`, with the given authenticator
        /// flags (0x05 = user present + user verified).
        fn assert(
            &self,
            rp: &WebAuthnRelyingParty,
            challenge: &[u8; 32],
            flags: u8,
        ) -> (String, String, String, String) {
            let (origin, rp_id) = match rp {
                WebAuthnRelyingParty::Origin(o) => (o.clone(), relying_party_id(rp)),
                WebAuthnRelyingParty::RegistrableDomain { rp_id, .. } => {
                    (format!("https://{rp_id}"), rp_id.clone())
                }
            };
            let cdj = serde_json::json!({
                "type": "webauthn.get",
                "challenge": URL_SAFE_NO_PAD.encode(challenge),
                "origin": origin,
            })
            .to_string()
            .into_bytes();
            let mut ad = Sha256::digest(rp_id.as_bytes()).to_vec();
            ad.push(flags);
            ad.extend_from_slice(&[0, 0, 0, 1]);
            let sig = P256Signer::from_keypair(&self.keypair)
                .sign_prehash(&webauthn_signed_hash(&ad, &cdj));
            (
                URL_SAFE_NO_PAD.encode(&ad),
                URL_SAFE_NO_PAD.encode(&cdj),
                URL_SAFE_NO_PAD.encode(sig.as_bytes()),
                self.pq_leg(challenge),
            )
        }

        fn login<'a>(
            &'a self,
            parts: &'a (String, String, String, String),
            cred: &'a str,
            acct: &'a str,
        ) -> PasskeyLogin<'a> {
            PasskeyLogin {
                account_address: acct,
                credential_id_b64: cred,
                authenticator_data_b64: &parts.0,
                client_data_json_b64: &parts.1,
                signature_b64: &parts.2,
                ml_dsa_signature_hex: Some(&parts.3),
            }
        }
    }

    fn validator() -> tenzro_vm::WebAuthnValidator {
        tenzro_vm::WebAuthnValidator::new(
            [7u8; 20],
            WebAuthnRelyingParty::Origin("https://mcp.tenzro.com".to_string()),
        )
    }

    #[test]
    fn passkey_login_yields_the_passkey_derived_did() {
        let v = validator();
        let pk = TestPasskey::enroll(&v, 1);
        let challenge = [9u8; 32];
        let parts = pk.assert(v.relying_party(), &challenge, 0x05);
        let cred = URL_SAFE_NO_PAD.encode(&pk.credential_id);
        let acct = hex::encode(&pk.account);
        let did = verify_passkey_login(
            &v,
            &challenge,
            &pk.login(&parts, &cred, &acct),
            |_| true,
            |_| None,
            |_| pk.pq_key(),
        )
        .expect("login");
        assert_eq!(did, pk.did());
    }

    #[test]
    fn passkey_login_refuses_a_replayed_or_foreign_answer() {
        let v = validator();
        let pk = TestPasskey::enroll(&v, 2);
        let other = TestPasskey::enroll(&v, 3);
        let challenge = [1u8; 32];
        let cred = URL_SAFE_NO_PAD.encode(&pk.credential_id);
        let acct = hex::encode(&pk.account);

        // An assertion over a different request's challenge.
        let stale = pk.assert(v.relying_party(), &[2u8; 32], 0x05);
        assert!(
            verify_passkey_login(
                &v,
                &challenge,
                &pk.login(&stale, &cred, &acct),
                |_| true,
                |_| None,
                |_| pk.pq_key(),
            )
            .is_err()
        );

        // No user verification.
        let no_uv = pk.assert(v.relying_party(), &challenge, 0x01);
        assert!(
            verify_passkey_login(
                &v,
                &challenge,
                &pk.login(&no_uv, &cred, &acct),
                |_| true,
                |_| None,
                |_| pk.pq_key(),
            )
            .is_err()
        );

        // Someone else's passkey presented against this account.
        let foreign = other.assert(v.relying_party(), &challenge, 0x05);
        assert!(
            verify_passkey_login(
                &v,
                &challenge,
                &pk.login(&foreign, &cred, &acct),
                |_| true,
                |_| None,
                |_| pk.pq_key(),
            )
            .is_err()
        );

        // A credential not enrolled on the named account.
        let good = pk.assert(v.relying_party(), &challenge, 0x05);
        let wrong_acct = hex::encode(&other.account);
        assert!(
            verify_passkey_login(
                &v,
                &challenge,
                &pk.login(&good, &cred, &wrong_acct),
                |_| true,
                |_| None,
                |_| pk.pq_key(),
            )
            .is_err()
        );

        // A valid passkey whose DID is not a registered human.
        assert!(
            verify_passkey_login(
                &v,
                &challenge,
                &pk.login(&good, &cred, &acct),
                |_| false,
                |_| None,
                |_| pk.pq_key(),
            )
            .is_err()
        );
    }

    #[test]
    fn passkey_sign_in_without_the_ml_dsa_leg_is_refused() {
        let v = validator();
        let pk = TestPasskey::enroll(&v, 4);
        let other = TestPasskey::enroll(&v, 5);
        let challenge = [6u8; 32];
        let cred = URL_SAFE_NO_PAD.encode(&pk.credential_id);
        let acct = hex::encode(&pk.account);
        let parts = pk.assert(v.relying_party(), &challenge, 0x05);

        // The passkey assertion alone, with no ML-DSA-65 leg.
        let mut login = pk.login(&parts, &cred, &acct);
        login.ml_dsa_signature_hex = None;
        let err = verify_passkey_login(&v, &challenge, &login, |_| true, |_| None, |_| pk.pq_key())
            .unwrap_err();
        assert!(err.contains("ML-DSA-65"), "{err}");

        // A passkey whose owner never enrolled an ML-DSA-65 key.
        let err = verify_passkey_login(
            &v,
            &challenge,
            &pk.login(&parts, &cred, &acct),
            |_| true,
            |_| None,
            |_| None,
        )
        .unwrap_err();
        assert!(err.contains("no ML-DSA-65 key"), "{err}");

        // A leg over another challenge, and a leg by another key.
        let stale = pk.pq_leg(&[7u8; 32]);
        let mut login = pk.login(&parts, &cred, &acct);
        login.ml_dsa_signature_hex = Some(&stale);
        assert!(
            verify_passkey_login(&v, &challenge, &login, |_| true, |_| None, |_| pk.pq_key())
                .is_err()
        );
        let foreign = other.pq_leg(&challenge);
        let mut login = pk.login(&parts, &cred, &acct);
        login.ml_dsa_signature_hex = Some(&foreign);
        assert!(
            verify_passkey_login(&v, &challenge, &login, |_| true, |_| None, |_| pk.pq_key())
                .is_err()
        );

        // Both legs sign in.
        let did = verify_passkey_login(
            &v,
            &challenge,
            &pk.login(&parts, &cred, &acct),
            |_| true,
            |_| None,
            |_| pk.pq_key(),
        )
        .expect("sign-in with both legs");
        assert_eq!(did, pk.did());
    }

    #[test]
    fn resource_indicator_must_name_the_mcp_endpoint() {
        assert!(resource_matches(RESOURCE, RESOURCE));
        assert!(resource_matches("HTTPS://MCP.TENZRO.COM/mcp", RESOURCE));
        assert!(resource_matches("https://mcp.tenzro.com/mcp/", RESOURCE));
        for other in [
            "https://rpc.tenzro.com",
            "https://mcp.tenzro.com",
            "https://mcp.tenzro.com/mcp#x",
            "https://mcp.tenzro.com.evil.example/mcp",
            "mcp.tenzro.com/mcp",
        ] {
            assert!(!resource_matches(other, RESOURCE), "{other} must not match");
        }
    }

    #[test]
    fn authorization_redirect_carries_iss_and_keeps_the_registered_query() {
        let url = authorization_redirect(
            "http://127.0.0.1:3000/callback?app=1",
            "https://mcp.tenzro.com",
            &[("code", "abc"), ("state", "s&x")],
        )
        .unwrap();
        let parsed = url::Url::parse(&url).unwrap();
        let q: std::collections::HashMap<_, _> = parsed.query_pairs().into_owned().collect();
        assert_eq!(q["app"], "1");
        assert_eq!(q["code"], "abc");
        assert_eq!(q["state"], "s&x");
        assert_eq!(q["iss"], "https://mcp.tenzro.com");
    }

    #[test]
    fn metadata_advertises_cimd_and_iss_and_no_registration_endpoint() {
        let m = authorization_server_metadata("https://mcp.tenzro.com", "1.0");
        assert_eq!(m["client_id_metadata_document_supported"], true);
        assert_eq!(m["authorization_response_iss_parameter_supported"], true);
        assert!(m.get("registration_endpoint").is_none());
        assert_eq!(m["code_challenge_methods_supported"][0], "S256");
    }

    fn engine(storage: Arc<MemoryStore>) -> tenzro_auth::AuthEngine {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = crate::keygen::NodeKeys::open(dir.path()).expect("test keys");
        tenzro_auth::AuthEngine::new(
            tenzro_auth::AuthEngineConfig::new("did:tenzro:node:test", "https://rpc.tenzro.com"),
            storage,
            Arc::new(crate::access_signer::AccessTokenSigner::new(keys).expect("signer")),
        )
        .expect("engine")
    }

    #[test]
    fn mcp_accepts_only_tokens_issued_for_it() {
        let storage = Arc::new(MemoryStore::new());
        let engine = engine(storage.clone());

        let bound =
            mint_bound_token(&engine, storage.as_ref(), "did:a", "did:u", None, RESOURCE).unwrap();
        let claims = authenticate_bearer(&engine, storage.as_ref(), &bound, RESOURCE).unwrap();
        assert_eq!(claims.sub, "did:a");

        // A valid engine token from another surface (onboarding RPC, say)
        // carries no /mcp binding.
        let foreign = engine
            .issue_jwt("did:a", "did:u", "", developer_scope_envelope(), None)
            .unwrap();
        let err = authenticate_bearer(&engine, storage.as_ref(), &foreign, RESOURCE).unwrap_err();
        assert!(err.contains("not issued for"), "{err}");

        // A token bound to a different resource.
        let elsewhere = mint_bound_token(
            &engine,
            storage.as_ref(),
            "did:a",
            "did:u",
            None,
            "https://other.example.org/mcp",
        )
        .unwrap();
        assert!(authenticate_bearer(&engine, storage.as_ref(), &elsewhere, RESOURCE).is_err());
    }

    /// A started node on a private data directory, so grants run against
    /// the real identity registry, wallet binder, WebAuthn validator and
    /// auth engine.
    #[test]
    fn the_issuer_is_the_operators_own_published_origin() {
        let mut cfg = crate::NodeConfig {
            external_mcp_addr: Some("https://mcp.operator.example/".to_string()),
            ..Default::default()
        };
        assert_eq!(
            crate::exposure::mcp_origin(&cfg),
            "https://mcp.operator.example"
        );
        assert_eq!(
            OAuthConfig::new(crate::exposure::mcp_origin(&cfg)).resource(),
            "https://mcp.operator.example/mcp"
        );
        assert_eq!(
            crate::exposure::mcp_public_host(&cfg).as_deref(),
            Some("mcp.operator.example")
        );
        cfg.external_mcp_addr = None;
        assert_eq!(
            crate::exposure::mcp_origin(&cfg),
            format!("http://{}", cfg.mcp_addr)
        );
        assert_eq!(crate::exposure::mcp_public_host(&cfg), None);
    }

    async fn boot_node() -> (TenzroNode, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        // Not a validator: a validator needs a genesis committee.
        let cfg = crate::NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            roles: tenzro_types::RoleSet::client(),
            iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
            external_mcp_addr: Some(RESOURCE.trim_end_matches("/mcp").to_string()),
            ..Default::default()
        };
        let mut node = TenzroNode::new(cfg).await.expect("node");
        node.start().await.expect("start");
        (node, tmp)
    }

    /// Enrol a passkey on the node's validator and register its human
    /// identity, as passkey onboarding does.
    async fn onboard_user(node: &TenzroNode, seed: u8) -> TestPasskey {
        let validator = node.webauthn_validator().expect("validator");
        let pk = TestPasskey::enroll(validator, seed);
        assert!(
            validator
                .get_credential(&pk.account, &pk.credential_id)
                .is_some(),
            "linked"
        );
        let xy = pk.keypair.public_key_bytes();
        node.identity_registry()
            .expect("registry")
            .register_human_with_binding(
                tenzro_identity::TenzroDid::from_passkey(&xy),
                format!("user-{seed}"),
                tenzro_identity::WalletBinding {
                    wallet_id: format!("0x{}", hex::encode(&pk.account)),
                    address: tenzro_types::primitives::Address::new([seed; 32]),
                    public_key: xy.to_vec(),
                    pq_verifying_key: pk.pq_key().expect("ml-dsa key"),
                },
            )
            .await
            .expect("register human");
        pk
    }

    #[tokio::test]
    async fn two_users_of_one_client_get_distinct_identities() {
        let (node, _tmp) = boot_node().await;
        let registry = node.identity_registry().expect("registry").clone();
        let mut users = Vec::new();
        for seed in [11u8, 12u8] {
            users.push(onboard_user(&node, seed).await.did());
        }

        let client = "https://app.example.com/oauth/client.json";
        use tenzro_crypto::composite::HybridSigner as _;
        let key = tenzro_crypto::testing::TestHybridSigner::p256_only(5)
            .public_key()
            .p256
            .clone();
        let (a1, _) = provision_or_retrieve_identity(&node, &users[0], client, key.clone())
            .await
            .expect("user a");
        let (b1, _) = provision_or_retrieve_identity(&node, &users[1], client, key.clone())
            .await
            .expect("user b");
        assert_ne!(a1, b1, "one client, two users, must be two identities");
        assert_eq!(
            registry.resolve(&a1).unwrap().controller_did(),
            Some(users[0].as_str())
        );
        assert_eq!(
            registry.resolve(&b1).unwrap().controller_did(),
            Some(users[1].as_str())
        );

        // The same user and client resolve back to the same identity.
        let (a2, _) = provision_or_retrieve_identity(&node, &users[0], client, key)
            .await
            .expect("user a again");
        assert_eq!(a1, a2);

        // An index row pointing at another user's identity is not honoured.
        let storage = node.storage().expect("storage");
        storage
            .put(
                METADATA_CF,
                grant_key(&users[0], "https://x.example/c.json").as_bytes(),
                b1.as_bytes(),
            )
            .unwrap();
        let (a3, _) = provision_or_retrieve_identity(
            &node,
            &users[0],
            "https://x.example/c.json",
            tenzro_crypto::testing::TestHybridSigner::p256_only(6)
                .public_key()
                .p256
                .clone(),
        )
        .await
        .expect("fresh identity");
        assert_ne!(a3, b1);
    }

    fn location(resp: &Response) -> url::Url {
        let loc = resp
            .headers()
            .get(header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .expect("redirect location");
        url::Url::parse(loc).expect("location url")
    }

    fn query(url: &url::Url) -> std::collections::HashMap<String, String> {
        url.query_pairs().into_owned().collect()
    }

    async fn json_body(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }

    fn authorize_query(redirect_uri: &str, challenge: &str) -> AuthorizeQuery {
        AuthorizeQuery {
            client_id: super::super::client_metadata::tests::CLIENT.to_string(),
            redirect_uri: redirect_uri.to_string(),
            response_type: "code".to_string(),
            scope: None,
            state: Some("st-1".to_string()),
            code_challenge: challenge.to_string(),
            code_challenge_method: "S256".to_string(),
            resource: Some(RESOURCE.to_string()),
            dpop_jkt: Some(client_jkt()),
        }
    }

    /// The whole authorization-code flow through the HTTP handlers: client
    /// document resolution, exact redirect matching, passkey sign-in, `iss`
    /// on the response, code redemption, and a token `/mcp` accepts.
    /// The OAuth client's own key in these tests.
    fn client_key() -> tenzro_crypto::testing::TestHybridSigner {
        tenzro_crypto::testing::TestHybridSigner::p256_only(31)
    }

    /// The JWK of `key`'s P-256 point.
    fn client_jwk(key: &tenzro_crypto::testing::TestHybridSigner) -> String {
        use tenzro_crypto::composite::HybridSigner as _;
        let xy = &key.public_key().p256;
        format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            URL_SAFE_NO_PAD.encode(&xy[..32]),
            URL_SAFE_NO_PAD.encode(&xy[32..])
        )
    }

    /// The thumbprint `/authorize` binds: that of [`client_key`].
    fn client_jkt() -> String {
        tenzro_auth::DpopProof::compute_jkt(&client_jwk(&client_key())).unwrap()
    }

    /// A `DPoP` header for a token request to `token_url`, by `key`.
    fn dpop_headers(
        key: &tenzro_crypto::testing::TestHybridSigner,
        token_url: &str,
    ) -> axum::http::HeaderMap {
        use tenzro_crypto::composite::HybridSigner as _;
        let jwk = client_jwk(key);
        let header = format!(r#"{{"typ":"dpop+jwt","alg":"ES256","jwk":{jwk}}}"#);
        let iat = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let payload = format!(
            r#"{{"htm":"POST","htu":"{token_url}","iat":{iat},"jti":"{}"}}"#,
            Uuid::new_v4()
        );
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(payload)
        );
        let sig = key.sign_external(input.as_bytes()).unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "dpop",
            format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig))
                .parse()
                .unwrap(),
        );
        headers
    }

    #[tokio::test]
    async fn authorization_code_flow_requires_a_passkey_and_binds_the_token() {
        use super::super::client_metadata::tests::{CLIENT, FixtureFetcher, good_doc};
        let (node, _tmp) = boot_node().await;
        let node = Arc::new(node);
        let user = onboard_user(&node, 21).await;
        let web_state = Arc::new(WebState::new().with_node(node.clone()));
        let state = Arc::new(OAuthState::with_fetcher(
            node.clone(),
            web_state,
            FixtureFetcher::with(CLIENT, good_doc()),
        ));
        let redirect_uri = "http://127.0.0.1:3000/callback";
        let verifier = "x".repeat(43);
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));

        // A redirect URI the client's document does not list is refused
        // without redirecting anywhere.
        let resp = authorize_handler(
            State(state.clone()),
            Query(authorize_query("https://attacker.example/cb", &challenge)),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(state.pending.lock().is_empty());

        // An unknown client is refused.
        let mut q = authorize_query(redirect_uri, &challenge);
        q.client_id = "https://nowhere.example/client.json".to_string();
        let resp = authorize_handler(State(state.clone()), Query(q))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // A request for another resource is refused.
        let mut q = authorize_query(redirect_uri, &challenge);
        q.resource = Some("https://rpc.tenzro.com".to_string());
        let resp = authorize_handler(State(state.clone()), Query(q))
            .await
            .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // Approving without signing in issues nothing.
        let resp = authorize_handler(
            State(state.clone()),
            Query(authorize_query(redirect_uri, &challenge)),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let token = state
            .pending
            .lock()
            .iter()
            .next()
            .expect("pending")
            .0
            .clone();
        let resp = authorize_submit_handler(
            State(state.clone()),
            Form(AuthorizeSubmit {
                session_token: token,
                action: "approve".to_string(),
                account_address: None,
                credential_id: None,
                authenticator_data: None,
                client_data_json: None,
                signature: None,
                ml_dsa_signature: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        assert!(state.sessions.is_empty());

        // Signing in with the enrolled passkey issues a code, with `iss`.
        authorize_handler(
            State(state.clone()),
            Query(authorize_query(redirect_uri, &challenge)),
        )
        .await;
        let (token, pending) = {
            let pending = state.pending.lock();
            let e = pending.iter().next().expect("pending");
            (e.0.clone(), e.1.clone())
        };
        let rp = node.webauthn_validator().unwrap().relying_party().clone();
        let parts = user.assert(&rp, &pending.challenge, 0x05);
        let resp = authorize_submit_handler(
            State(state.clone()),
            Form(AuthorizeSubmit {
                session_token: token,
                action: "approve".to_string(),
                account_address: Some(hex::encode(&user.account)),
                credential_id: Some(URL_SAFE_NO_PAD.encode(&user.credential_id)),
                authenticator_data: Some(parts.0),
                client_data_json: Some(parts.1),
                signature: Some(parts.2),
                ml_dsa_signature: Some(parts.3),
            }),
        )
        .await
        .into_response();
        assert!(resp.status().is_redirection(), "{:?}", resp.status());
        let loc = location(&resp);
        assert!(loc.as_str().starts_with(redirect_uri));
        let q = query(&loc);
        assert_eq!(q["iss"], state.config.issuer);
        assert_eq!(q["state"], "st-1");
        let code = q["code"].clone();
        assert_eq!(state.sessions.get(&code).unwrap().user_did, user.did());

        // Redeeming with a different redirect URI fails, and burns the code.
        let token_req = |redirect: &str, code: &str| TokenRequest {
            grant_type: "authorization_code".to_string(),
            code: Some(code.to_string()),
            redirect_uri: Some(redirect.to_string()),
            client_id: Some(CLIENT.to_string()),
            code_verifier: Some(verifier.clone()),
            refresh_token: None,
            resource: Some(RESOURCE.to_string()),
            dpop_jkt: None,
        };
        let client_key = client_key();
        let token_url = format!("{}/token", state.config.issuer);
        let resp = token_handler(
            State(state.clone()),
            dpop_headers(&client_key, &token_url),
            Form(token_req("https://attacker.example/cb", &code)),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp = token_handler(
            State(state.clone()),
            dpop_headers(&client_key, &token_url),
            Form(token_req(redirect_uri, &code)),
        )
        .await
        .into_response();
        assert_eq!(
            resp.status(),
            StatusCode::BAD_REQUEST,
            "a burned code must not redeem"
        );

        // A fresh sign-in and a correct redemption yield a token for /mcp,
        // held by a machine identity the user controls.
        authorize_handler(
            State(state.clone()),
            Query(authorize_query(redirect_uri, &challenge)),
        )
        .await;
        let (token, pending) = {
            let pending = state.pending.lock();
            let e = pending.iter().next().expect("pending");
            (e.0.clone(), e.1.clone())
        };
        let parts = user.assert(&rp, &pending.challenge, 0x05);
        let resp = authorize_submit_handler(
            State(state.clone()),
            Form(AuthorizeSubmit {
                session_token: token,
                action: "approve".to_string(),
                account_address: Some(hex::encode(&user.account)),
                credential_id: Some(URL_SAFE_NO_PAD.encode(&user.credential_id)),
                authenticator_data: Some(parts.0),
                client_data_json: Some(parts.1),
                signature: Some(parts.2),
                ml_dsa_signature: Some(parts.3),
            }),
        )
        .await
        .into_response();
        let code = query(&location(&resp))["code"].clone();
        let resp = token_handler(
            State(state.clone()),
            dpop_headers(&client_key, &token_url),
            Form(token_req(redirect_uri, &code)),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = json_body(resp).await;
        let access = body["access_token"].as_str().expect("access token");
        let caller = validate_bearer_jwt(&state, access).expect("accepted at /mcp");
        let identity = node
            .identity_registry()
            .unwrap()
            .resolve(&caller.did)
            .unwrap();
        assert_eq!(identity.controller_did(), Some(user.did().as_str()));

        // The refresh token is bound to its client.
        let refresh = body["refresh_token"].as_str().unwrap().to_string();
        let resp = token_handler(
            State(state.clone()),
            dpop_headers(&client_key, &token_url),
            Form(TokenRequest {
                grant_type: "refresh_token".to_string(),
                code: None,
                redirect_uri: None,
                client_id: Some("https://other.example/client.json".to_string()),
                code_verifier: None,
                refresh_token: Some(refresh),
                resource: Some(RESOURCE.to_string()),
                dpop_jkt: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_pkce_s256_verification() {
        let code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let computed = URL_SAFE_NO_PAD.encode(Sha256::digest(code_verifier.as_bytes()));
        assert_eq!(computed, expected_challenge);
    }

    #[test]
    fn consent_page_escapes_client_supplied_text() {
        let html = auth_page::render_authorize_page(&auth_page::ConsentPage {
            client_name: "<img src=x onerror=alert(1)>",
            client_id: "https://app.example.com/c.json",
            scope: "read write",
            session_token: "tok",
            challenge_b64: "abc_DEF-123');alert(1);//",
            rp_id: "mcp.tenzro.com'",
        });
        assert!(!html.contains("<img src=x"));
        assert!(html.contains("unb64('abc_DEF-123alert1')"));
        assert!(html.contains("rpId: 'mcp.tenzro.com'"));
        assert!(html.contains("userVerification: 'required'"));
    }

    #[test]
    fn test_html_escape() {
        assert_eq!(
            auth_page::html_escape("<script>alert('xss')</script>"),
            "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"
        );
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

    /// `/authorize` is unauthenticated: a flood of requests cannot grow the
    /// pending sign-ins without bound.
    #[tokio::test]
    async fn unauthenticated_authorize_requests_cannot_grow_pending_without_bound() {
        use super::super::client_metadata::tests::{CLIENT, FixtureFetcher, good_doc};
        let (node, _tmp) = boot_node().await;
        let node = Arc::new(node);
        let web_state = Arc::new(WebState::new().with_node(node.clone()));
        let state = Arc::new(OAuthState::with_fetcher(
            node.clone(),
            web_state,
            FixtureFetcher::with(CLIENT, good_doc()),
        ));
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(b"verifier"));
        for _ in 0..10_000 {
            let mut q = authorize_query("http://127.0.0.1:3000/callback", &challenge);
            q.state = Some("s".repeat(4096));
            let resp = authorize_handler(State(state.clone()), Query(q))
                .await
                .into_response();
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let held = state.pending.lock().len();
        assert!(
            held <= state.config.max_pending_authorizations,
            "{held} pending authorizations held"
        );
    }
}
