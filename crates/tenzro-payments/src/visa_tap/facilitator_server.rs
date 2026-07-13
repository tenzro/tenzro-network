//! Visa TAP facilitator HTTP surface
//!
//! Serves the recognition role of the Visa Trusted Agent Protocol over HTTP:
//! `POST /verify` (RFC 9421 agent recognition), `GET /supported`. A resource
//! server that fronts a checkout or browse endpoint forwards the signed
//! request fields here; the facilitator runs the [`TapVerifier`] 8-stage
//! pipeline and returns the recognition result (verified flag, agent DID,
//! tag, stages passed).
//!
//! Settlement is not part of the recognition role — a recognized
//! `agent-payer-auth` request settles through the payment gateway
//! (`tenzro_payVisaTap`). This surface answers a single question: does this
//! signed request come from a recognized agent, and with what tag.

use std::sync::Arc;

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::rfc9421::{RequestParts, SignedHeaders};
use crate::visa_tap::types::AgentTag;
use crate::visa_tap::verifier::TapVerifier;

/// Shared state behind the facilitator router.
#[derive(Clone)]
pub struct TapFacilitatorState {
    verifier: Arc<TapVerifier>,
    domain: String,
}

impl TapFacilitatorState {
    /// Build facilitator state around a shared [`TapVerifier`]. `domain` is
    /// the authority this facilitator recognizes agents for (surfaced in
    /// `GET /supported` so callers can confirm they are talking to the right
    /// recognition endpoint).
    pub fn new(verifier: Arc<TapVerifier>, domain: impl Into<String>) -> Self {
        Self {
            verifier,
            domain: domain.into(),
        }
    }

    /// Borrow the underlying verifier.
    pub fn verifier(&self) -> &Arc<TapVerifier> {
        &self.verifier
    }
}

/// The signed HTTP request an agent presents, decomposed into the fields the
/// RFC 9421 verifier needs. A resource server forwards these verbatim from
/// the inbound request it received from the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TapVerifyRequest {
    /// HTTP method of the agent's request (e.g. `POST`).
    pub method: String,
    /// Authority (host[:port]) the agent addressed.
    pub authority: String,
    /// Request path (no query string).
    pub path: String,
    /// Raw query string without the leading `?` (empty if absent).
    #[serde(default)]
    pub query: String,
    /// URI scheme (`https` by default).
    #[serde(default = "default_scheme")]
    pub scheme: String,
    /// Selected request headers covered by the signature (lowercase keys).
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    /// Raw `Signature-Input` header value.
    pub signature_input: String,
    /// Base64-encoded signature bytes (`Signature` header value).
    pub signature: String,
}

fn default_scheme() -> String {
    "https".to_string()
}

/// Recognition result returned to the caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TapVerifyResponse {
    /// Whether every verification stage passed.
    pub verified: bool,
    /// The agent's `keyid` from the signature parameters.
    pub agent_key_id: String,
    /// The agent's DID, when the registry resolved one.
    pub agent_did: Option<String>,
    /// The recognized tag (`agent-browser-auth` / `agent-payer-auth`), if any.
    pub tag: Option<String>,
    /// Named stages the pipeline passed (diagnostic).
    pub stages_passed: Vec<String>,
    /// Error string when verification could not complete.
    pub error: Option<String>,
}

/// One recognition capability advertised by `GET /supported`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TapSupportedResponse {
    /// Signature format this facilitator recognizes.
    pub signature_format: String,
    /// Authority agents are recognized for.
    pub domain: String,
    /// Tag values the taxonomy accepts.
    pub tags: Vec<String>,
}

/// Build the Visa TAP facilitator router. Routes are `/verify` and
/// `/supported`; mount under a domain-namespaced prefix.
pub fn tap_facilitator_router(state: TapFacilitatorState) -> Router {
    Router::new()
        .route("/verify", post(handle_verify))
        .route("/supported", get(handle_supported))
        .with_state(state)
}

async fn handle_verify(
    State(state): State<TapFacilitatorState>,
    Json(request): Json<TapVerifyRequest>,
) -> Json<TapVerifyResponse> {
    let request_parts = RequestParts {
        method: request.method,
        authority: request.authority,
        path: request.path,
        query: request.query,
        scheme: request.scheme,
        status: None,
        headers: request
            .headers
            .into_iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v))
            .collect(),
    };

    let signature_bytes = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        &request.signature,
    ) {
        Ok(b) => b,
        Err(e) => {
            debug!("tap facilitator verify: bad signature base64: {}", e);
            return Json(TapVerifyResponse {
                verified: false,
                agent_key_id: String::new(),
                agent_did: None,
                tag: None,
                stages_passed: Vec::new(),
                error: Some(format!("invalid signature base64: {}", e)),
            });
        }
    };

    let parsed = match crate::rfc9421::signature::parse_signature_input(&request.signature_input) {
        Ok(p) => p,
        Err(e) => {
            debug!("tap facilitator verify: bad signature-input: {}", e);
            return Json(TapVerifyResponse {
                verified: false,
                agent_key_id: String::new(),
                agent_did: None,
                tag: None,
                stages_passed: Vec::new(),
                error: Some(format!("invalid signature-input: {}", e)),
            });
        }
    };

    let signed_headers = SignedHeaders {
        signature_input_raw: request.signature_input,
        signature_bytes,
        parsed,
    };

    match state.verifier.verify(&request_parts, &signed_headers).await {
        Ok(result) => Json(TapVerifyResponse {
            verified: result.verified,
            agent_key_id: result.agent_key_id,
            agent_did: result.agent_did,
            tag: result.verified_tag.map(|t| t.as_str().to_string()),
            stages_passed: result.stages_passed,
            error: None,
        }),
        Err(e) => {
            warn!("tap facilitator verify error: {}", e);
            Json(TapVerifyResponse {
                verified: false,
                agent_key_id: String::new(),
                agent_did: None,
                tag: None,
                stages_passed: Vec::new(),
                error: Some(e.to_string()),
            })
        }
    }
}

async fn handle_supported(State(state): State<TapFacilitatorState>) -> Json<TapSupportedResponse> {
    Json(TapSupportedResponse {
        signature_format: "rfc9421-http-message-signatures".to_string(),
        domain: state.domain.clone(),
        tags: vec![
            AgentTag::BrowserAuth.as_str().to_string(),
            AgentTag::PayerAuth.as_str().to_string(),
        ],
    })
}
