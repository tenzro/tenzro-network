//! Universal Resolver-compatible DID resolution endpoint.
//!
//! DIF's Universal Resolver exposes any DID method via a single HTTP API:
//! `GET /1.0/identifiers/{did}` returns a DID Resolution Result wrapping
//! the canonical DID Document. This handler implements that contract for
//! `did:tenzro:` identifiers using the local `IdentityRegistry`, and
//! returns the same JSON shape DIF's drivers produce so any standard
//! resolver client (the Vidos / Godiddy / Spruce SDKs and so on) can
//! consume it.
//!
//! Spec reference: <https://github.com/decentralized-identity/universal-resolver>
//! plus W3C DID Resolution 0.3 (`https://www.w3.org/TR/did-resolution/`).
//!
//! Path: `GET /1.0/identifiers/{did}`. The DID is URL-encoded by the
//! caller; axum's `Path<String>` handler decodes it before dispatch.

use std::sync::Arc;

use axum::{Json, extract::Path, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::web::handlers::WebState;

/// Resolver-level options accepted on resolveRepresentation.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct DidResolutionOptions {
    /// Requested DID document media type (default `application/did+ld+json`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept: Option<String>,
}

/// Resolution result wrapper — matches DIF's Universal Resolver JSON shape.
#[derive(Debug, Clone, Serialize)]
pub struct DidResolutionResult {
    /// Top-level `@context` (W3C DID Resolution).
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// Echo of the resolveRepresentation options.
    #[serde(rename = "didResolutionMetadata")]
    pub did_resolution_metadata: Value,
    /// The DID Document itself, or `null` when an error occurred.
    #[serde(rename = "didDocument")]
    pub did_document: Option<Value>,
    /// Document metadata (created / updated / deactivated).
    #[serde(rename = "didDocumentMetadata")]
    pub did_document_metadata: Value,
}

impl DidResolutionResult {
    /// Build a successful resolution result.
    pub fn ok(document: Value, content_type: &str) -> Self {
        Self {
            context: vec!["https://w3id.org/did-resolution/v1".into()],
            did_resolution_metadata: json!({ "contentType": content_type }),
            did_document: Some(document),
            did_document_metadata: json!({}),
        }
    }

    /// Build an error resolution result. `error` is one of the W3C
    /// resolution error codes (`notFound`, `invalidDid`, `methodNotSupported`,
    /// `representationNotSupported`, `internalError`).
    pub fn err(error: &str, message: &str) -> Self {
        Self {
            context: vec!["https://w3id.org/did-resolution/v1".into()],
            did_resolution_metadata: json!({
                "error": error,
                "errorMessage": message,
            }),
            did_document: None,
            did_document_metadata: json!({}),
        }
    }
}

/// `GET /1.0/identifiers/{did}` handler. Dispatches to the local identity
/// registry for `did:tenzro:` identifiers and returns the W3C resolution
/// result. Non-tenzro DIDs return `methodNotSupported`.
pub async fn resolve_identifier(
    state: axum::extract::State<Arc<WebState>>,
    Path(did): Path<String>,
) -> impl IntoResponse {
    let did_str = did.trim();
    if !did_str.starts_with("did:tenzro:") && !did_str.starts_with("did:pdis:") {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(DidResolutionResult::err(
                "methodNotSupported",
                "this Universal Resolver instance only serves did:tenzro and did:pdis",
            )),
        )
            .into_response();
    }

    let Some(node) = state.node.as_ref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(DidResolutionResult::err(
                "internalError",
                "node not attached to web state",
            )),
        )
            .into_response();
    };
    let Some(registry) = node.identity_registry() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(DidResolutionResult::err(
                "internalError",
                "identity registry not initialized",
            )),
        )
            .into_response();
    };

    match registry.resolve(did_str) {
        Ok(identity) => {
            let doc = json!({
                "@context": [
                    "https://www.w3.org/ns/did/v1",
                ],
                "id": did_str,
                "verificationMethod": identity.public_keys.iter().enumerate().map(|(i, k)| json!({
                    "id": format!("{}#key-{}", did_str, i + 1),
                    "type": k.key_type,
                    "controller": did_str,
                    "publicKeyMultibase": multibase_z(&k.public_key),
                })).collect::<Vec<_>>(),
                "authentication": (0..identity.public_keys.len()).map(|i| format!("{}#key-{}", did_str, i + 1)).collect::<Vec<_>>(),
                "service": identity.services.iter().map(|s| json!({
                    "id": s.id,
                    "type": s.service_type,
                    "serviceEndpoint": s.service_endpoint,
                })).collect::<Vec<_>>(),
            });
            (
                StatusCode::OK,
                Json(DidResolutionResult::ok(doc, "application/did+ld+json")),
            )
                .into_response()
        }
        Err(_) => (
            StatusCode::NOT_FOUND,
            Json(DidResolutionResult::err("notFound", "identity not found")),
        )
            .into_response(),
    }
}

/// `GET /1.0/methods` handler — minimum-viable DIF Universal Resolver
/// method-discovery endpoint. Returns the list of method names this
/// instance can resolve so federated resolvers know to route.
pub async fn list_methods() -> Json<Value> {
    Json(json!({
        "methods": ["tenzro", "pdis"],
    }))
}

/// Multibase `z` (base58btc) encoding of public key bytes — required for
/// `publicKeyMultibase` per DID Core.
fn multibase_z(bytes: &[u8]) -> String {
    let mut buf = String::with_capacity(bytes.len() * 2 + 1);
    buf.push('z');
    buf.push_str(&bs58::encode(bytes).into_string());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_result_contains_context_and_document() {
        let r = DidResolutionResult::ok(
            json!({"id": "did:tenzro:human:abc"}),
            "application/did+ld+json",
        );
        assert_eq!(r.context[0], "https://w3id.org/did-resolution/v1");
        assert!(r.did_document.is_some());
        assert_eq!(
            r.did_resolution_metadata
                .get("contentType")
                .and_then(|v| v.as_str()),
            Some("application/did+ld+json")
        );
    }

    #[test]
    fn err_result_has_error_field() {
        let r = DidResolutionResult::err("notFound", "no such DID");
        assert!(r.did_document.is_none());
        assert_eq!(
            r.did_resolution_metadata
                .get("error")
                .and_then(|v| v.as_str()),
            Some("notFound")
        );
    }

    #[test]
    fn multibase_z_uses_base58btc_prefix() {
        let enc = multibase_z(b"hello");
        assert!(enc.starts_with('z'));
    }
}
