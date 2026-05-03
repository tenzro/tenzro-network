//! Axum middleware for payment-gated endpoints
//!
//! Provides middleware that intercepts requests to payment-gated API endpoints,
//! returning HTTP 402 challenges and verifying payment credentials.

use crate::challenge_store::ChallengeStore;
use crate::identity_binding::IdentityPaymentBinder;
use crate::traits::PaymentGateway;
use crate::types::PaymentCredential;
use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tracing::{debug, warn};

/// Configuration for the payment gate middleware
#[derive(Debug, Clone)]
pub struct PaymentGateConfig {
    /// Default payment amount for gated endpoints
    pub default_amount: u128,
    /// Default asset for payment
    pub default_asset: String,
    /// Recipient address for payments
    pub recipient: String,
    /// Default protocol to use
    pub default_protocol: String,
}

impl Default for PaymentGateConfig {
    fn default() -> Self {
        Self {
            default_amount: 0,
            default_asset: "USDC".to_string(),
            recipient: String::new(),
            default_protocol: "mpp".to_string(),
        }
    }
}

/// Payment gate middleware state
///
/// Attach this to Axum router state to enable payment-gated endpoints.
#[derive(Clone)]
pub struct PaymentGateMiddleware {
    /// The payment gateway
    pub gateway: Arc<dyn PaymentGateway>,
    /// Configuration
    pub config: PaymentGateConfig,
    /// Challenge store for looking up challenges during verification
    pub challenge_store: ChallengeStore,
    /// Optional identity binder for payer validation (delegation scopes, active status)
    identity_binder: Option<Arc<IdentityPaymentBinder>>,
}

impl PaymentGateMiddleware {
    /// Creates a new payment gate middleware
    pub fn new(
        gateway: Arc<dyn PaymentGateway>,
        config: PaymentGateConfig,
        challenge_store: ChallengeStore,
    ) -> Self {
        Self {
            gateway,
            config,
            challenge_store,
            identity_binder: None,
        }
    }

    /// Attach an identity binder for payer validation
    ///
    /// When set, the middleware will validate that the payer DID is active and
    /// that the payment amount/protocol/chain are within the payer's delegation scope.
    pub fn with_identity_binder(mut self, binder: Arc<IdentityPaymentBinder>) -> Self {
        self.identity_binder = Some(binder);
        self
    }

    /// Creates a default middleware for testing
    pub fn default_with_gateway(gateway: Arc<dyn PaymentGateway>) -> Self {
        Self::new(gateway, PaymentGateConfig::default(), ChallengeStore::new())
    }
}

/// Axum middleware handler for payment verification
///
/// Checks for payment credentials in headers:
/// - `Payment-Credential` (base64-encoded JSON)
/// - `Authorization: mpp <base64>` (MPP protocol)
/// - `Authorization: x402 <base64>` (x402 protocol)
///
/// If no credential is found, returns HTTP 402 with a JSON challenge.
/// If credential is present, verifies it and forwards request on success.
pub async fn payment_gate_handler(
    State(middleware): State<PaymentGateMiddleware>,
    request: Request,
    next: Next,
) -> Result<Response, PaymentGateError> {
    let uri = request.uri().clone();
    let resource = uri.path();

    debug!("Payment gate checking resource: {}", resource);

    // Check for payment credential in headers
    let credential_header = request
        .headers()
        .get("Payment-Credential")
        .or_else(|| request.headers().get(header::AUTHORIZATION));

    if let Some(header_value) = credential_header {
        // Credential present — attempt to verify
        match parse_credential(header_value.to_str().unwrap_or("")) {
            Ok(credential) => {
                debug!(
                    "Verifying credential {} for challenge {}",
                    credential.credential_id, credential.challenge_id
                );

                // If identity binder is configured, validate the payer's identity
                // and delegation scope BEFORE verifying the payment itself.
                // This prevents suspended/revoked identities from making payments
                // and enforces delegation limits for machine identities.
                if let Some(ref binder) = middleware.identity_binder {
                    if !credential.payer_did.is_empty() {
                        if let Err(e) = binder.validate_payer_for_protocol(
                            &credential.payer_did,
                            credential.amount,
                            "payment",
                            Some(&credential.protocol),
                            credential.extra.get("chain").and_then(|v| v.as_str()),
                        ) {
                            warn!(
                                "Payer identity validation failed for {}: {}",
                                credential.payer_did, e
                            );
                            return Err(PaymentGateError::VerificationFailed(format!(
                                "payer identity rejected: {}",
                                e
                            )));
                        }
                        debug!("Payer identity {} validated", credential.payer_did);
                    }
                }

                match middleware.gateway.verify_and_settle(&credential).await {
                    Ok(receipt) => {
                        debug!(
                            "Payment verified and settled: receipt_id={}, amount={}",
                            receipt.receipt_id, receipt.amount
                        );
                        // Forward the request to the next handler
                        Ok(next.run(request).await)
                    }
                    Err(e) => {
                        warn!("Payment verification failed: {}", e);
                        Err(PaymentGateError::VerificationFailed(e.to_string()))
                    }
                }
            }
            Err(e) => {
                warn!("Failed to parse payment credential: {}", e);
                Err(PaymentGateError::InvalidCredential(e.to_string()))
            }
        }
    } else {
        // No credential — return HTTP 402 with challenge
        debug!("No payment credential found, issuing challenge");

        let challenge = middleware
            .gateway
            .create_challenge(
                &middleware.config.default_protocol,
                resource,
                middleware.config.default_amount,
                &middleware.config.default_asset,
                &middleware.config.recipient,
            )
            .await
            .map_err(|e| PaymentGateError::ChallengeCreationFailed(e.to_string()))?;

        // Store the challenge for later verification
        middleware.challenge_store.store(&challenge);

        debug!(
            "Created challenge {} for resource {} (amount={} {})",
            challenge.challenge_id, resource, challenge.amount, challenge.asset
        );

        Err(PaymentGateError::PaymentRequired(challenge))
    }
}

/// Parses a payment credential from a header value
///
/// Supports:
/// - `Payment-Credential: <base64-json>`
/// - `Authorization: mpp <base64-json>`
/// - `Authorization: x402 <base64-json>`
/// - `Authorization: visa-tap <base64-json>`
/// - `Authorization: mastercard-agent-pay <base64-json>`
fn parse_credential(header_value: &str) -> crate::error::Result<PaymentCredential> {
    use base64::{engine::general_purpose, Engine as _};

    // Check if it's an Authorization header with protocol prefix
    let base64_data = if header_value.starts_with("mpp ")
        || header_value.starts_with("x402 ")
        || header_value.starts_with("visa-tap ")
        || header_value.starts_with("mastercard-agent-pay ")
    {
        // Extract base64 part after protocol prefix
        header_value.split_whitespace().nth(1).ok_or_else(|| {
            crate::error::PaymentError::CredentialError(
                "Invalid Authorization header format, expected 'protocol base64-data'".to_string(),
            )
        })?
    } else {
        // Assume it's a raw base64 value from Payment-Credential
        header_value
    };

    // Decode base64
    let json_bytes = general_purpose::STANDARD
        .decode(base64_data)
        .map_err(|e| crate::error::PaymentError::CredentialError(format!("Failed to decode base64 credential: {}", e)))?;

    // Parse JSON
    let credential: PaymentCredential = serde_json::from_slice(&json_bytes)?;

    Ok(credential)
}

/// Errors that can occur during payment gate processing
#[derive(Debug)]
pub enum PaymentGateError {
    /// No payment credential provided — return HTTP 402
    PaymentRequired(crate::types::PaymentChallenge),
    /// Credential parsing failed
    InvalidCredential(String),
    /// Challenge creation failed
    ChallengeCreationFailed(String),
    /// Credential verification failed
    VerificationFailed(String),
}

impl IntoResponse for PaymentGateError {
    fn into_response(self) -> Response {
        match self {
            PaymentGateError::PaymentRequired(challenge) => {
                let body = serde_json::to_string(&challenge).unwrap_or_else(|_| "{}".to_string());

                Response::builder()
                    .status(StatusCode::PAYMENT_REQUIRED)
                    .header("Payment-Required", "true")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(body))
                    .unwrap()
            }
            PaymentGateError::InvalidCredential(msg) => Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from(format!(
                    "{{\"error\":\"invalid_credential\",\"message\":\"{}\"}}",
                    msg
                )))
                .unwrap(),
            PaymentGateError::ChallengeCreationFailed(msg) => Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Body::from(format!(
                    "{{\"error\":\"challenge_creation_failed\",\"message\":\"{}\"}}",
                    msg
                )))
                .unwrap(),
            PaymentGateError::VerificationFailed(msg) => Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from(format!(
                    "{{\"error\":\"verification_failed\",\"message\":\"{}\"}}",
                    msg
                )))
                .unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::PaymentProtocol;
    use crate::types::{PaymentChallenge, PaymentReceipt, PaymentVerification};
    use crate::gateway::TenzroPaymentGateway;
    use async_trait::async_trait;
    use axum::{routing::get, Router};
    use chrono::Utc;
    use std::collections::HashMap;
    use tower::ServiceExt;

    /// Minimal test protocol for middleware testing
    struct TestProtocol;

    #[async_trait]
    impl PaymentProtocol for TestProtocol {
        fn protocol_name(&self) -> &str {
            "test"
        }

        async fn create_challenge(
            &self,
            resource: &str,
            amount: u128,
            asset: &str,
            recipient: &str,
        ) -> crate::Result<PaymentChallenge> {
            Ok(PaymentChallenge {
                challenge_id: uuid::Uuid::new_v4().to_string(),
                protocol: "test".to_string(),
                resource: resource.to_string(),
                amount,
                asset: asset.to_string(),
                recipient: recipient.to_string(),
                chain: "tenzro".to_string(),
                expires_at: Utc::now() + chrono::Duration::minutes(5),
                extra: HashMap::new(),
            })
        }

        async fn verify_credential(
            &self,
            _challenge: &PaymentChallenge,
            credential: &PaymentCredential,
        ) -> crate::Result<PaymentVerification> {
            Ok(PaymentVerification {
                verified: true,
                credential_id: credential.credential_id.clone(),
                challenge_id: credential.challenge_id.clone(),
                payer_did: credential.payer_did.clone(),
                verified_at: Utc::now(),
                settlement_ref: Some("0xtest".to_string()),
            })
        }

        async fn settle(
            &self,
            verification: &PaymentVerification,
        ) -> crate::Result<PaymentReceipt> {
            Ok(PaymentReceipt {
                receipt_id: uuid::Uuid::new_v4().to_string(),
                protocol: "test".to_string(),
                challenge_id: verification.challenge_id.clone(),
                credential_id: verification.credential_id.clone(),
                amount: 1000,
                asset: "USDC".to_string(),
                settlement_tx: verification.settlement_ref.clone(),
                chain: "tenzro".to_string(),
                settled_at: Utc::now(),
                extra: HashMap::new(),
            })
        }

        async fn create_credential(
            &self,
            challenge: &PaymentChallenge,
            payer_did: &str,
            _wallet_id: &str,
        ) -> crate::Result<PaymentCredential> {
            Ok(PaymentCredential {
                credential_id: uuid::Uuid::new_v4().to_string(),
                challenge_id: challenge.challenge_id.clone(),
                protocol: "test".to_string(),
                payer_did: payer_did.to_string(),
                payer_address: "0xpayer".to_string(),
                amount: challenge.amount,
                asset: challenge.asset.clone(),
                signature: Vec::new(),
                pq_signature: Vec::new(),
                pq_public_key: Vec::new(),
                extra: HashMap::new(),
            })
        }
    }

    async fn test_handler() -> &'static str {
        "success"
    }

    #[tokio::test]
    async fn test_middleware_returns_402_without_credential() {
        let challenge_store = ChallengeStore::new();
        let gateway = Arc::new(TenzroPaymentGateway::new().with_challenge_store(challenge_store.clone()));
        gateway.register_protocol(Arc::new(TestProtocol));

        let middleware = PaymentGateMiddleware::new(
            gateway,
            PaymentGateConfig {
                default_amount: 1000,
                default_asset: "USDC".to_string(),
                recipient: "0xrecipient".to_string(),
                default_protocol: "test".to_string(),
            },
            challenge_store,
        );

        let app = Router::new()
            .route("/paid-resource", get(test_handler))
            .layer(axum::middleware::from_fn_with_state(
                middleware,
                payment_gate_handler,
            ));

        let request = Request::builder()
            .uri("/paid-resource")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(
            response.headers().get("Payment-Required").unwrap(),
            "true"
        );
    }

    #[tokio::test]
    async fn test_middleware_accepts_valid_credential() {
        use base64::{engine::general_purpose, Engine as _};

        let challenge_store = ChallengeStore::new();
        let gateway = Arc::new(TenzroPaymentGateway::new().with_challenge_store(challenge_store.clone()));
        gateway.register_protocol(Arc::new(TestProtocol));

        // Create a challenge and store it
        let challenge: crate::types::PaymentChallenge = gateway
            .create_challenge("test", "/paid-resource", 1000, "USDC", "0xrecipient")
            .await
            .unwrap();
        challenge_store.store(&challenge);

        let middleware = PaymentGateMiddleware::new(
            gateway,
            PaymentGateConfig::default(),
            challenge_store,
        );

        let app = Router::new()
            .route("/paid-resource", get(test_handler))
            .layer(axum::middleware::from_fn_with_state(
                middleware,
                payment_gate_handler,
            ));

        // Create a valid credential
        let credential = PaymentCredential {
            credential_id: "cred-1".to_string(),
            challenge_id: challenge.challenge_id.clone(),
            protocol: "test".to_string(),
            payer_did: "did:tenzro:human:alice".to_string(),
            payer_address: "0xpayer".to_string(),
            amount: 1000,
            asset: "USDC".to_string(),
            signature: Vec::new(),
            pq_signature: Vec::new(),
            pq_public_key: Vec::new(),
            extra: HashMap::new(),
        };

        let credential_json = serde_json::to_string(&credential).unwrap();
        let credential_b64 = general_purpose::STANDARD.encode(credential_json);

        let request = Request::builder()
            .uri("/paid-resource")
            .header("Payment-Credential", credential_b64)
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_parse_credential_from_x_payment_header() {
        use base64::{engine::general_purpose, Engine as _};

        let credential = PaymentCredential {
            credential_id: "cred-1".to_string(),
            challenge_id: "ch-1".to_string(),
            protocol: "mpp".to_string(),
            payer_did: "did:tenzro:human:alice".to_string(),
            payer_address: "0xpayer".to_string(),
            amount: 1000,
            asset: "USDC".to_string(),
            signature: Vec::new(),
            pq_signature: Vec::new(),
            pq_public_key: Vec::new(),
            extra: HashMap::new(),
        };

        let json = serde_json::to_string(&credential).unwrap();
        let b64 = general_purpose::STANDARD.encode(&json);

        let parsed = parse_credential(&b64).unwrap();
        assert_eq!(parsed.credential_id, "cred-1");
        assert_eq!(parsed.protocol, "mpp");
    }

    #[tokio::test]
    async fn test_parse_credential_from_authorization_header() {
        use base64::{engine::general_purpose, Engine as _};

        let credential = PaymentCredential {
            credential_id: "cred-2".to_string(),
            challenge_id: "ch-2".to_string(),
            protocol: "x402".to_string(),
            payer_did: "did:tenzro:human:bob".to_string(),
            payer_address: "0xbob".to_string(),
            amount: 500,
            asset: "USDT".to_string(),
            signature: Vec::new(),
            pq_signature: Vec::new(),
            pq_public_key: Vec::new(),
            extra: HashMap::new(),
        };

        let json = serde_json::to_string(&credential).unwrap();
        let b64 = general_purpose::STANDARD.encode(&json);
        let header = format!("x402 {}", b64);

        let parsed = parse_credential(&header).unwrap();
        assert_eq!(parsed.credential_id, "cred-2");
        assert_eq!(parsed.protocol, "x402");
    }
}
