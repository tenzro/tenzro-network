//! x402 facilitator HTTP surface: `POST /verify`, `POST /settle`,
//! `GET /supported`.
//!
//! Request bodies are `{x402Version, paymentPayload, paymentRequirements}`.
//! `/verify` answers `{isValid, invalidReason?, payer?}`, `/settle` answers a
//! settlement response and `/supported` lists the `(scheme, network)` kinds
//! this facilitator settles. Verification and settlement are the
//! [`X402Facilitator`]'s; this module only translates the HTTP shapes.

use crate::error::PaymentError;
use crate::x402::coinbase::{FacilitatorRequest, VerifyResponse};
use crate::x402::receipt::X402SettlementResponse;
use crate::x402::{X402_WIRE_VERSION, X402Facilitator};
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::debug;

/// Shared state behind the facilitator router.
#[derive(Clone)]
pub struct FacilitatorServerState {
    facilitator: Arc<X402Facilitator>,
}

impl FacilitatorServerState {
    /// State serving `facilitator`.
    pub fn new(facilitator: Arc<X402Facilitator>) -> Self {
        Self { facilitator }
    }
}

/// One `(scheme, network)` pair this facilitator settles.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SupportedKind {
    /// Protocol version.
    pub x402_version: u32,
    /// Scheme id.
    pub scheme: String,
    /// CAIP-2 network.
    pub network: String,
    /// Scheme-specific details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extra: Option<serde_json::Value>,
}

/// Body of `GET /supported`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedResponse {
    /// The kinds this facilitator settles.
    pub kinds: Vec<SupportedKind>,
    /// Protocol extensions supported.
    pub extensions: Vec<String>,
    /// Addresses this facilitator signs settlements with, by CAIP-2 family
    /// (`"eip155:*"`). Tenzro-scheme settlements are signed by the payer,
    /// so a facilitator that relays no EVM transaction lists none.
    #[serde(default)]
    pub signers: std::collections::BTreeMap<String, Vec<String>>,
}

/// The facilitator router: `/verify`, `/settle`, `/supported`.
pub fn facilitator_router(state: FacilitatorServerState) -> Router {
    Router::new()
        .route("/verify", post(handle_verify))
        .route("/settle", post(handle_settle))
        .route("/supported", get(handle_supported))
        .with_state(state)
}

fn invalid_reason(e: &PaymentError) -> &'static str {
    match e {
        PaymentError::InsufficientFunds(_) => "insufficient_funds",
        PaymentError::UnsupportedProtocol(_) => "unsupported_scheme",
        _ => "invalid_payload",
    }
}

fn version_ok(request: &FacilitatorRequest) -> bool {
    request.x402_version == X402_WIRE_VERSION
        && request.payment_payload.x402_version == X402_WIRE_VERSION
}

async fn handle_verify(
    State(state): State<FacilitatorServerState>,
    Json(request): Json<FacilitatorRequest>,
) -> Json<VerifyResponse> {
    if !version_ok(&request) {
        return Json(VerifyResponse {
            is_valid: false,
            invalid_reason: Some("invalid_x402_version".to_string()),
            payer: None,
        });
    }
    match state
        .facilitator
        .verify(&request.payment_requirements, &request.payment_payload)
        .await
    {
        Ok(verified) => Json(VerifyResponse {
            is_valid: true,
            invalid_reason: None,
            payer: Some(verified.payer),
        }),
        Err(e) => {
            debug!("x402 facilitator verify refused: {e}");
            Json(VerifyResponse {
                is_valid: false,
                invalid_reason: Some(invalid_reason(&e).to_string()),
                payer: None,
            })
        }
    }
}

async fn handle_settle(
    State(state): State<FacilitatorServerState>,
    Json(request): Json<FacilitatorRequest>,
) -> Json<X402SettlementResponse> {
    if !version_ok(&request) {
        return Json(X402SettlementResponse::failed(
            request.payment_requirements.network.clone(),
            "invalid_x402_version",
        ));
    }
    Json(
        state
            .facilitator
            .settle(&request.payment_requirements, &request.payment_payload)
            .await,
    )
}

async fn handle_supported(State(state): State<FacilitatorServerState>) -> Json<SupportedResponse> {
    let kinds = state
        .facilitator
        .supported_kinds()
        .into_iter()
        .map(|(scheme, network)| SupportedKind {
            x402_version: X402_WIRE_VERSION,
            scheme,
            network,
            extra: None,
        })
        .collect();
    Json(SupportedResponse {
        kinds,
        extensions: Vec::new(),
        signers: Default::default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::RailOutcome;
    use crate::test_support::RecordingRail;
    use crate::x402::{X402PaymentPayload, X402PaymentRequirement};

    fn state() -> FacilitatorServerState {
        let rail = RecordingRail::new(RailOutcome::Settled {
            reference: "0xledger".to_string(),
        });
        FacilitatorServerState::new(Arc::new(
            X402Facilitator::new(
                1337,
                vec!["eip155:8453".to_string()],
                Arc::new(crate::test_support::SeedKeys),
            )
            .with_ledger_rail(rail),
        ))
    }

    fn request(version: u32) -> FacilitatorRequest {
        let mut req = X402PaymentRequirement::new(
            "tenzro-hybrid",
            "tenzro:1337",
            "10",
            "09".repeat(20),
            "TNZO",
            60,
        );
        req.set_extra("challengeId", serde_json::json!("ch"));
        let mut r = FacilitatorRequest::new(
            &X402PaymentPayload::new(req.clone(), serde_json::json!({ "garbage": true })),
            &req,
        );
        r.x402_version = version;
        r
    }

    #[test]
    fn router_constructs_with_all_routes() {
        let _router = facilitator_router(state());
    }

    #[tokio::test]
    async fn an_unsigned_payload_is_invalid_and_does_not_settle() {
        let verify = handle_verify(State(state()), Json(request(2))).await;
        assert!(!verify.0.is_valid);
        assert_eq!(verify.0.invalid_reason.as_deref(), Some("invalid_payload"));

        let settle = handle_settle(State(state()), Json(request(2))).await;
        assert!(!settle.0.success);
        assert!(settle.0.transaction.is_empty());
    }

    /// Bodies written exactly as the x402 v2 specification gives them
    /// (`specs/x402-specification-v2.md`, facilitator interface).
    #[tokio::test]
    async fn the_routes_speak_the_x402_v2_wire_shapes() {
        use axum::body::Body;
        use tower::ServiceExt;

        let body = serde_json::json!({
            "x402Version": 2,
            "paymentPayload": {
                "x402Version": 2,
                "resource": { "url": "https://api.example.com/paid", "description": "d", "mimeType": "application/json" },
                "accepted": {
                    "scheme": "tenzro-hybrid", "network": "tenzro:1337", "amount": "10",
                    "asset": "TNZO", "payTo": "09".repeat(20), "maxTimeoutSeconds": 60,
                    "extra": { "challengeId": "ch" }
                },
                "payload": { "signature": "0xdeadbeef" }
            },
            "paymentRequirements": {
                "scheme": "tenzro-hybrid", "network": "tenzro:1337", "amount": "10",
                "asset": "TNZO", "payTo": "09".repeat(20), "maxTimeoutSeconds": 60,
                "extra": { "challengeId": "ch" }
            }
        });
        let call = |method: &str, path: &str, body: Option<serde_json::Value>| {
            let mut req = axum::http::Request::builder().method(method).uri(path);
            let body = match body {
                Some(b) => {
                    req = req.header("content-type", "application/json");
                    Body::from(b.to_string())
                }
                None => Body::empty(),
            };
            let router = facilitator_router(state());
            let req = req.body(body).unwrap();
            async move {
                let resp = router.oneshot(req).await.unwrap();
                assert_eq!(resp.status(), 200);
                let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
                    .await
                    .unwrap();
                serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()
            }
        };

        let verify = call("POST", "/verify", Some(body.clone())).await;
        assert_eq!(verify["isValid"], false);
        assert!(verify["invalidReason"].is_string());

        let settle = call("POST", "/settle", Some(body)).await;
        assert_eq!(settle["success"], false);
        assert_eq!(settle["transaction"], "");
        assert_eq!(settle["network"], "tenzro:1337");
        assert!(settle["errorReason"].is_string());

        let supported = call("GET", "/supported", None).await;
        assert!(supported["kinds"].is_array());
        assert!(supported["extensions"].is_array());
        assert!(supported["signers"].is_object());
        let kind = &supported["kinds"][0];
        assert_eq!(kind["x402Version"], 2);
        assert!(kind["scheme"].is_string() && kind["network"].is_string());
    }

    #[tokio::test]
    async fn another_protocol_version_is_refused() {
        let verify = handle_verify(State(state()), Json(request(1))).await;
        assert_eq!(
            verify.0.invalid_reason.as_deref(),
            Some("invalid_x402_version")
        );
    }

    #[tokio::test]
    async fn supported_lists_the_ledger_kinds_and_no_evm_kind_without_an_evm_rpc() {
        let kinds = handle_supported(State(state())).await.0.kinds;
        assert!(
            kinds
                .iter()
                .any(|k| k.scheme == "tenzro-hybrid" && k.network == "tenzro:1337")
        );
        assert!(
            !kinds.iter().any(|k| k.scheme == "exact-eip3009"),
            "EIP-3009 is offered only over the operator's own EVM RPC"
        );
        assert!(!kinds.iter().any(|k| k.scheme == "batch-settlement"));
    }
}
