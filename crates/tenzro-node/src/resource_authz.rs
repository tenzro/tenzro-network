//! One enforcement path for the operator's per-resource serving mode, shared by
//! the Database (`/v1/databases`) and Storage (`/v1/files`) REST surfaces.
//!
//! Both surfaces used to carry the same hard-coded gate: *present the scoped API
//! key or be refused*. That is exactly one of the three modes an operator can
//! now choose per resource ([`ResourceAccess`]). This module folds all three
//! into a single [`authorize_resource`] so the two surfaces enforce identically
//! and a mode added later is classified in one place.
//!
//! # Precedence
//!
//! Mirrors `inference_admission::decide_creds`: a valid credential wins first,
//! then the resource's own mode decides.
//!
//! 1. A valid API key carrying `required_scope` → allow. This is the `Gated`
//!    path, and it doubles as the operator's per-caller override on a resource
//!    in *any* mode — an operator holding a scoped key always reaches their own
//!    resource, whatever its serving mode.
//! 2. Else the resource is `Open` → run the x402 payment check (the same
//!    `verify_and_settle` the priced-site edge and the `/chat` payment gate use)
//!    → paid allows, unpaid returns a 402.
//! 3. Else the resource is `Gated` (and no key was presented) → refuse; a
//!    credential is required.
//! 4. Else the resource is `Private` → refuse unless the request is
//!    loopback / on-node.
//!
//! Fail-closed throughout: an unset/`Private` mode with an off-box caller is
//! refused, and the payment path never allows without a settled credential.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::{
    Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;

use crate::api_key::ApiKeyScope;
use crate::node::TenzroNode;
use crate::web::sites::parse_credential;
use tenzro_types::resource_access::ResourceAccess;

/// The header a scoped tenant API key is presented in (both surfaces).
const API_KEY_HEADER: &str = "x-tenzro-api-key";

/// How a request cleared [`authorize_resource`]. The caller uses this to
/// attribute the request to a DID for the downstream engine/store, which each
/// mode supplies differently.
#[derive(Debug, Clone)]
pub enum Authorized {
    /// A valid scoped API key. Carries the raw key (so the caller can continue
    /// through the existing key-subject dispatch/adjudication path) and the
    /// key's subject DID, if it names one.
    Key {
        /// The raw API key as presented.
        key: String,
        /// The key's subject DID, if it names one.
        subject: Option<String>,
    },
    /// An `Open` resource, payment verified and settled. Carries the payer DID
    /// from the settled credential — the identity the request is attributed to.
    Payment {
        /// The payer DID from the settled x402 credential.
        payer_did: String,
    },
    /// A loopback / on-node caller reaching a `Private` (or otherwise
    /// loopback-only) resource.
    Loopback,
}

/// An error body in the shape both `/v1` surfaces already return.
fn error_response(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(json!({
            "error": { "message": message, "type": "invalid_request_error", "code": code }
        })),
    )
        .into_response()
}

/// The raw API key as presented, trimmed and non-empty, if any.
fn presented_key(headers: &HeaderMap) -> Option<String> {
    headers
        .get(API_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Whether the request originated on this node.
///
/// Fail-closed for the `Private` tier: on-node means the direct TCP peer is
/// loopback *and* the request was not forwarded (no `X-Forwarded-For` /
/// `Forwarded`). A reverse proxy makes every request appear to come from
/// loopback, so a forwarded request — even one relayed by a local proxy — is
/// treated as off-box and refused. This is the same peer-vs-XFF distinction
/// `ip_rate_limit` draws, resolved conservatively here because the cost of a
/// false positive is exposing a private resource.
fn is_on_node(peer: Option<SocketAddr>, headers: &HeaderMap) -> bool {
    let peer_is_loopback = peer.map(|p| p.ip().is_loopback()).unwrap_or(false);
    let forwarded = headers.contains_key("x-forwarded-for") || headers.contains_key("forwarded");
    peer_is_loopback && !forwarded
}

/// Verify and settle an x402 payment for one `Open` request, reusing the exact
/// credential parse + `verify_and_settle` the priced-site edge uses. Returns the
/// payer DID on success, or the HTTP refusal to return.
async fn verify_payment(
    node: &Arc<TenzroNode>,
    headers: &HeaderMap,
    price_per_request: u128,
) -> Result<String, Response> {
    use tenzro_payments::traits::PaymentGateway as _;

    let Some(gateway) = node.payment_gateway() else {
        return Err(error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "payment_unavailable",
            "This resource is Open (pay-per-request) but the node has no payment gateway \
             configured, so it cannot verify a payment.",
        ));
    };

    // Same header pair the priced-site / function / machine gates read.
    let credential_header = headers
        .get("payment-credential")
        .or_else(|| headers.get("authorization"))
        .and_then(|v| v.to_str().ok());

    let Some(header_value) = credential_header else {
        return Err(error_response(
            StatusCode::PAYMENT_REQUIRED,
            "payment_required",
            "This resource is Open. Settle an x402 payment and present it in the \
             Payment-Credential (or Authorization: Payment) header.",
        ));
    };

    let credential = parse_credential(header_value).map_err(|e| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_credential",
            &format!("The payment credential could not be parsed: {e}"),
        )
    })?;

    // The operator's per-request price is a floor: a credential that settles for
    // less than the quoted price does not pay for the request. `0` (free-public)
    // clears any credential. Settlement itself is the gateway's job.
    if price_per_request > 0 && credential.amount < price_per_request {
        return Err(error_response(
            StatusCode::PAYMENT_REQUIRED,
            "insufficient_payment",
            &format!(
                "This resource costs {price_per_request} per request; the presented credential \
                 settles only {}.",
                credential.amount
            ),
        ));
    }

    gateway.verify_and_settle(&credential).await.map_err(|e| {
        error_response(
            StatusCode::PAYMENT_REQUIRED,
            "payment_failed",
            &format!("Payment verification failed: {e}"),
        )
    })?;

    Ok(credential.payer_did)
}

/// Authorize one request against a resource's operator-set serving mode.
///
/// See the module docs for the precedence. `required_scope` is the API-key scope
/// that gates this surface ([`ApiKeyScope::Database`] / [`ApiKeyScope::Storage`]).
/// `access` is the resource's mode: a database's per-record
/// [`DatabaseDescriptor::access`], or the node-wide `storage_access` for the
/// files surface.
///
/// [`DatabaseDescriptor::access`]: tenzro_database::DatabaseDescriptor::access
pub async fn authorize_resource(
    node: &Arc<TenzroNode>,
    headers: &HeaderMap,
    peer: Option<SocketAddr>,
    access: ResourceAccess,
    required_scope: ApiKeyScope,
) -> Result<Authorized, Response> {
    // 1. A valid scoped API key wins in every mode — the operator's override.
    if let Some(key) = presented_key(headers) {
        if let Some(mgr) = node.api_key_manager()
            && let Some(record) = mgr.lookup(&key)
            && record.has_scope(required_scope)
        {
            return Ok(Authorized::Key {
                subject: record.subject.filter(|s| !s.trim().is_empty()),
                key,
            });
        }
        // A key was presented but is unknown, revoked, or lacks the scope. It is
        // not a valid credential, so it does not take the Gated path; fall
        // through to the resource's mode. For a Gated resource that lands on the
        // refusal below; for an Open one, payment can still authorize.
    }

    // 2..4. Decide by the resource's own mode.
    match access {
        ResourceAccess::Open { price_per_request } => {
            let payer_did = verify_payment(node, headers, price_per_request).await?;
            Ok(Authorized::Payment { payer_did })
        }
        ResourceAccess::Gated => {
            let (status, code, message) = if presented_key(headers).is_some() {
                (
                    StatusCode::FORBIDDEN,
                    "insufficient_scope",
                    format!(
                        "This resource is Gated and the presented API key does not carry the \
                         '{}' scope.",
                        required_scope.as_str()
                    ),
                )
            } else {
                (
                    StatusCode::UNAUTHORIZED,
                    "missing_api_key",
                    format!(
                        "This resource is Gated. Present a '{}'-scoped X-Tenzro-Api-Key.",
                        required_scope.as_str()
                    ),
                )
            };
            Err(error_response(status, code, &message))
        }
        ResourceAccess::Private => {
            if is_on_node(peer, headers) {
                Ok(Authorized::Loopback)
            } else {
                Err(error_response(
                    StatusCode::FORBIDDEN,
                    "resource_private",
                    "This resource is Private: it is served only to on-node (loopback) callers. \
                     Present a scoped API key, or ask the operator to set it Open or Gated.",
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback(port: u16) -> Option<SocketAddr> {
        Some(SocketAddr::from(([127, 0, 0, 1], port)))
    }

    fn external() -> Option<SocketAddr> {
        Some(SocketAddr::from(([203, 0, 113, 7], 4000)))
    }

    #[test]
    fn on_node_requires_loopback_and_no_forwarding() {
        let plain = HeaderMap::new();
        assert!(is_on_node(loopback(5000), &plain));
        // Off-box direct peer is never on-node.
        assert!(!is_on_node(external(), &plain));
        // Loopback but forwarded (behind a proxy) is treated as off-box.
        let mut proxied = HeaderMap::new();
        proxied.insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
        assert!(!is_on_node(loopback(5000), &proxied));
        // Unknown peer is fail-closed.
        assert!(!is_on_node(None, &plain));
    }
}
