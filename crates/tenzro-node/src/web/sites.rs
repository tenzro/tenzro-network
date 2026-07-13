//! Static site serving: `GET /sites/{site_id}` and `GET /sites/{site_id}/*path`.
//!
//! Resolution: manifest lookup → exact route match (falling back to the
//! manifest's `not_found_path`, then plain 404) → per-site x402 gate when the
//! manifest carries a price → LRU byte cache → iroh blob fetch. Content never
//! touches the filesystem; paths only ever index the manifest's route map.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use tenzro_iroh::IrohResolver as _;
use tenzro_payments::middleware::PaymentGateError;
use tenzro_payments::traits::PaymentGateway as _;
use tenzro_payments::types::PaymentCredential;
use tenzro_types::tenzro_uri::TenzroUri;
use tracing::{debug, warn};

use crate::sites::SiteManifest;
use crate::web::handlers::WebState;

pub async fn serve_site_index(
    State(state): State<Arc<WebState>>,
    Path(site_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    serve(state, site_id, None, headers).await
}

pub async fn serve_site_asset(
    State(state): State<Arc<WebState>>,
    Path((site_id, path)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    serve(state, site_id, Some(path), headers).await
}

async fn serve(
    state: Arc<WebState>,
    site_id: String,
    path: Option<String>,
    headers: HeaderMap,
) -> Response {
    let Some(node) = &state.node else {
        return (StatusCode::SERVICE_UNAVAILABLE, "node unavailable").into_response();
    };
    let registry = node.site_registry();
    let Some(manifest) = registry.get_site(&site_id) else {
        return (StatusCode::NOT_FOUND, "site not found").into_response();
    };

    // Axum's `*path` capture strips the leading slash; manifest keys keep it.
    let request_path = match &path {
        Some(p) => format!("/{p}"),
        None => manifest.index_path.clone(),
    };

    let (route_path, status) = if manifest.routes.contains_key(&request_path) {
        (request_path.clone(), StatusCode::OK)
    } else if let Some(nf) = manifest
        .not_found_path
        .as_ref()
        .filter(|nf| manifest.routes.contains_key(*nf))
    {
        (nf.clone(), StatusCode::NOT_FOUND)
    } else {
        return (StatusCode::NOT_FOUND, "no route for path").into_response();
    };

    if let Some(price) = manifest.price_per_request
        && let Err(resp) = enforce_payment(node, &manifest, &request_path, price, &headers).await
    {
        return resp;
    }

    let route = manifest
        .routes
        .get(&route_path)
        .expect("route_path checked above")
        .clone();

    let etag = format!("\"{}\"", route.blob_hash);
    if headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|inm| inm.split(',').any(|c| c.trim() == etag))
    {
        return ([(header::ETAG, etag)], StatusCode::NOT_MODIFIED).into_response();
    }

    let cache = registry.blob_cache();
    let body = if let Some(bytes) = cache.get(&route.blob_hash) {
        bytes
    } else {
        let Some(resolver) = node.iroh_resolver() else {
            return (StatusCode::SERVICE_UNAVAILABLE, "blob resolver unavailable").into_response();
        };
        let uri = TenzroUri::Blob {
            hash: route.blob_hash.clone(),
            provider_hint: None,
        };
        match resolver.fetch_bytes(&uri).await {
            Ok(bytes) => {
                cache.insert(&route.blob_hash, bytes.clone());
                bytes
            }
            Err(e) => {
                warn!("site {site_id} blob fetch failed for {route_path}: {e}");
                return (StatusCode::BAD_GATEWAY, "blob fetch failed").into_response();
            }
        }
    };

    (
        status,
        [
            (header::CONTENT_TYPE, route.content_type.clone()),
            (header::CACHE_CONTROL, "public,max-age=60".to_string()),
            (header::ETAG, etag),
        ],
        body,
    )
        .into_response()
}

/// Per-site x402 gate. `Ok(())` means the request may proceed (payment
/// verified and settled); `Err` carries the 402 challenge or a failure.
async fn enforce_payment(
    node: &Arc<crate::node::TenzroNode>,
    manifest: &SiteManifest,
    resource: &str,
    price: u128,
    headers: &HeaderMap,
) -> Result<(), Response> {
    let Some(gateway) = node.payment_gateway() else {
        return Err(
            (StatusCode::SERVICE_UNAVAILABLE, "payment gateway unavailable").into_response(),
        );
    };
    let payments = &node.config().payments;

    let credential_header = headers
        .get("Payment-Credential")
        .or_else(|| headers.get(header::AUTHORIZATION))
        .and_then(|v| v.to_str().ok());

    if let Some(header_value) = credential_header {
        let credential = parse_credential(header_value).map_err(|e| {
            PaymentGateError::InvalidCredential(e).into_response()
        })?;
        debug!(
            "site {} verifying credential {} for {}",
            manifest.site_id, credential.credential_id, resource
        );
        gateway
            .verify_and_settle(&credential)
            .await
            .map_err(|e| PaymentGateError::VerificationFailed(e.to_string()).into_response())?;
        Ok(())
    } else {
        let resource_path = format!("/sites/{}{}", manifest.site_id, resource);
        let challenge = gateway
            .create_challenge(
                &payments.default_protocol,
                &resource_path,
                price,
                &payments.default_asset,
                &payments.recipient,
            )
            .await
            .map_err(|e| {
                PaymentGateError::ChallengeCreationFailed(e.to_string()).into_response()
            })?;
        gateway.challenge_store().store(&challenge);
        Err(PaymentGateError::PaymentRequired(challenge).into_response())
    }
}

/// Header-credential decode matching the payment-gate middleware conventions:
/// `Payment ` prefix is base64url-nopad; protocol prefixes and the raw
/// `Payment-Credential` value are STANDARD base64 JSON.
fn parse_credential(header_value: &str) -> Result<PaymentCredential, String> {
    let (data, url_safe) = if let Some(rest) = header_value.strip_prefix("Payment ") {
        (rest, true)
    } else if let Some(rest) = header_value
        .strip_prefix("mpp ")
        .or_else(|| header_value.strip_prefix("x402 "))
        .or_else(|| header_value.strip_prefix("visa-tap "))
        .or_else(|| header_value.strip_prefix("mastercard-agent-pay "))
    {
        (rest, false)
    } else {
        (header_value, false)
    };
    let json_bytes = if url_safe {
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(data.trim())
            .map_err(|e| format!("base64url decode: {e}"))?
    } else {
        base64::engine::general_purpose::STANDARD
            .decode(data.trim())
            .map_err(|e| format!("base64 decode: {e}"))?
    };
    serde_json::from_slice(&json_bytes).map_err(|e| format!("credential JSON: {e}"))
}
