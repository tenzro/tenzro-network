//! x402 facilitator HTTP surface
//!
//! Serves the facilitator role of the x402 protocol over HTTP:
//! `POST /verify`, `POST /settle`, `GET /supported`. Wire shapes are
//! byte-compatible with [`crate::x402::coinbase::CdpFacilitatorClient`] —
//! any x402 resource server that speaks to the hosted CDP facilitator can
//! point at this router unchanged.
//!
//! Verification and settlement are delegated to [`X402Facilitator`]; this
//! module only translates HTTP wire shapes.

use crate::x402::coinbase::{SettleRequest, SettleResponse, VerifyRequest, VerifyResponse};
use crate::x402::{X402_WIRE_VERSION, X402Facilitator, X402PaymentPayload, X402PaymentRequired};
use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, warn};

/// Shared state behind the facilitator router.
#[derive(Clone)]
pub struct FacilitatorServerState {
    facilitator: Arc<X402Facilitator>,
}

impl FacilitatorServerState {
    pub fn new(facilitator: Arc<X402Facilitator>) -> Self {
        Self { facilitator }
    }

    pub fn facilitator(&self) -> &Arc<X402Facilitator> {
        &self.facilitator
    }
}

/// One `(scheme, network)` pair this facilitator can verify and settle.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SupportedKind {
    #[serde(rename = "x402Version")]
    pub x402_version: u32,
    pub scheme: String,
    pub network: String,
}

/// Body of `GET /supported`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportedResponse {
    pub kinds: Vec<SupportedKind>,
}

/// Builds the facilitator router. Mount it directly or nest it under a
/// prefix; the routes are `/verify`, `/settle`, `/supported`.
pub fn facilitator_router(state: FacilitatorServerState) -> Router {
    Router::new()
        .route("/verify", post(handle_verify))
        .route("/settle", post(handle_settle))
        .route("/supported", get(handle_supported))
        .with_state(state)
}

fn decode_pair(
    payload_b64: &str,
    requirements_b64: &str,
) -> std::result::Result<(X402PaymentRequired, X402PaymentPayload), String> {
    let requirements = X402PaymentRequired::from_base64(requirements_b64)
        .map_err(|e| format!("invalid paymentRequirements: {}", e))?;

    let payload_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, payload_b64)
            .map_err(|e| format!("invalid payload base64: {}", e))?;
    let payload: X402PaymentPayload = serde_json::from_slice(&payload_bytes)
        .map_err(|e| format!("invalid payload JSON: {}", e))?;

    Ok((requirements, payload))
}

async fn handle_verify(
    State(state): State<FacilitatorServerState>,
    Json(request): Json<VerifyRequest>,
) -> Json<VerifyResponse> {
    let (requirements, payload) = match decode_pair(&request.payload, &request.payment_requirements)
    {
        Ok(pair) => pair,
        Err(e) => {
            debug!("x402 facilitator verify: malformed request: {}", e);
            return Json(VerifyResponse {
                is_valid: false,
                error: Some(e),
                invalidation_reason: Some("malformed_request".to_string()),
            });
        }
    };

    match state.facilitator.verify(&requirements, &payload).await {
        Ok(true) => Json(VerifyResponse {
            is_valid: true,
            error: None,
            invalidation_reason: None,
        }),
        Ok(false) => Json(VerifyResponse {
            is_valid: false,
            error: Some("payment payload failed verification".to_string()),
            invalidation_reason: Some("verification_failed".to_string()),
        }),
        Err(e) => {
            warn!("x402 facilitator verify error: {}", e);
            Json(VerifyResponse {
                is_valid: false,
                error: Some(e.to_string()),
                invalidation_reason: Some("facilitator_error".to_string()),
            })
        }
    }
}

async fn handle_settle(
    State(state): State<FacilitatorServerState>,
    Json(request): Json<SettleRequest>,
) -> Json<SettleResponse> {
    let (requirements, payload) = match decode_pair(&request.payload, &request.payment_requirements)
    {
        Ok(pair) => pair,
        Err(e) => {
            debug!("x402 facilitator settle: malformed request: {}", e);
            return Json(SettleResponse {
                success: false,
                tx_hash: String::new(),
                network: None,
                error: Some(e),
            });
        }
    };

    // Re-verify before settling — the settle endpoint must not trust that
    // the caller ran /verify first.
    match state.facilitator.verify(&requirements, &payload).await {
        Ok(true) => {}
        Ok(false) => {
            return Json(SettleResponse {
                success: false,
                tx_hash: String::new(),
                network: Some(payload.network.clone()),
                error: Some("payment payload failed verification".to_string()),
            });
        }
        Err(e) => {
            warn!("x402 facilitator settle: verify error: {}", e);
            return Json(SettleResponse {
                success: false,
                tx_hash: String::new(),
                network: Some(payload.network.clone()),
                error: Some(e.to_string()),
            });
        }
    }

    match state.facilitator.settle(&requirements, &payload).await {
        Ok(tx_hash) => Json(SettleResponse {
            success: true,
            tx_hash,
            network: Some(payload.network.clone()),
            error: None,
        }),
        Err(e) => {
            warn!("x402 facilitator settle error: {}", e);
            Json(SettleResponse {
                success: false,
                tx_hash: String::new(),
                network: Some(payload.network.clone()),
                error: Some(e.to_string()),
            })
        }
    }
}

async fn handle_supported(State(state): State<FacilitatorServerState>) -> Json<SupportedResponse> {
    let mut kinds = Vec::new();
    for scheme in state.facilitator.scheme_registry().ids() {
        for network in state.facilitator.supported_chains() {
            kinds.push(SupportedKind {
                x402_version: X402_WIRE_VERSION,
                scheme: scheme.clone(),
                network: network.clone(),
            });
        }
    }
    Json(SupportedResponse { kinds })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x402::X402PaymentRequirement;
    use crate::x402::payment_payload::{ExactAuthorization, ExactSchemePayload};

    fn encode_payload(payload: &X402PaymentPayload) -> String {
        base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            serde_json::to_vec(payload).unwrap(),
        )
    }

    fn sample_state() -> FacilitatorServerState {
        FacilitatorServerState::new(Arc::new(X402Facilitator::new(vec![
            "tenzro-mainnet".to_string(),
        ])))
    }

    fn sample_pair() -> (String, String) {
        let requirements = X402PaymentRequired::new(vec![X402PaymentRequirement::new(
            "tenzro-hybrid",
            "tenzro-mainnet",
            "1000",
            "0xrecipient",
            "USDC",
            "https://api.tenzro.xyz/paid/resource",
            "Test resource",
            "application/json",
            60,
        )]);
        let payload = X402PaymentPayload::new(
            "tenzro-hybrid",
            "tenzro-mainnet",
            ExactSchemePayload {
                signature: "00".to_string(),
                authorization: ExactAuthorization {
                    from: "0xpayer".to_string(),
                    to: "0xrecipient".to_string(),
                    value: "1000".to_string(),
                    valid_after: 0,
                    valid_before: u64::MAX,
                    nonce: "0x01".to_string(),
                },
            },
        );
        (encode_payload(&payload), requirements.to_base64().unwrap())
    }

    #[test]
    fn router_constructs_with_all_routes() {
        // Router construction panics on malformed route specs — building it
        // is the compile-and-shape check.
        let _router = facilitator_router(sample_state());
    }

    #[tokio::test]
    async fn verify_rejects_malformed_base64() {
        let response = handle_verify(
            State(sample_state()),
            Json(VerifyRequest {
                payload: "!!!not-base64!!!".to_string(),
                payment_requirements: "!!!also-not!!!".to_string(),
            }),
        )
        .await;

        assert!(!response.0.is_valid);
        assert_eq!(
            response.0.invalidation_reason.as_deref(),
            Some("malformed_request")
        );
    }

    #[tokio::test]
    async fn verify_returns_is_valid_false_for_unverifiable_payload() {
        // Well-formed wire pair, but the hybrid signature is garbage — the
        // facilitator pipeline must answer with isValid=false, not an error.
        let (payload_b64, requirements_b64) = sample_pair();
        let response = handle_verify(
            State(sample_state()),
            Json(VerifyRequest {
                payload: payload_b64,
                payment_requirements: requirements_b64,
            }),
        )
        .await;

        assert!(!response.0.is_valid);
        assert_eq!(
            response.0.invalidation_reason.as_deref(),
            Some("verification_failed")
        );
    }

    #[tokio::test]
    async fn settle_refuses_unverified_payload() {
        let (payload_b64, requirements_b64) = sample_pair();
        let response = handle_settle(
            State(sample_state()),
            Json(SettleRequest {
                payload: payload_b64,
                payment_requirements: requirements_b64,
            }),
        )
        .await;

        assert!(!response.0.success);
        assert!(response.0.tx_hash.is_empty());
        assert_eq!(response.0.network.as_deref(), Some("tenzro-mainnet"));
    }

    #[tokio::test]
    async fn supported_lists_scheme_network_cross_product() {
        let response = handle_supported(State(sample_state())).await;
        let kinds = &response.0.kinds;

        assert!(!kinds.is_empty());
        assert!(
            kinds
                .iter()
                .all(|k| k.network == "tenzro-mainnet" && k.x402_version == X402_WIRE_VERSION)
        );
        assert!(kinds.iter().any(|k| k.scheme == "tenzro-hybrid"));
        assert!(kinds.iter().any(|k| k.scheme == "erc7710"));
    }

    #[test]
    fn supported_response_serializes_x402_version_field() {
        let body = serde_json::to_string(&SupportedResponse {
            kinds: vec![SupportedKind {
                x402_version: X402_WIRE_VERSION,
                scheme: "erc7710".to_string(),
                network: "eip155:8453".to_string(),
            }],
        })
        .unwrap();
        assert!(body.contains("\"x402Version\":1"));
        assert!(body.contains("\"scheme\":\"erc7710\""));
    }
}
