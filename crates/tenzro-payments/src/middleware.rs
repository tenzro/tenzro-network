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
/// - `Authorization: Payment <base64url>` (IETF `draft-ryan-httpauth-payment-01`)
/// - `Authorization: mpp <base64>` (legacy MPP shape)
/// - `Authorization: x402 <base64>` (x402 protocol)
/// - `Authorization: visa-tap <base64>` (Visa TAP)
/// - `Authorization: mastercard-agent-pay <base64>` (Mastercard Agent Pay)
/// - `Payment-Credential: <base64>` (raw fallback)
///
/// If no credential is found, returns HTTP 402 with a `WWW-Authenticate: Payment` header
/// (per IETF draft) and a JSON challenge body for clients that need richer context.
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
                if let Some(ref binder) = middleware.identity_binder
                    && !credential.payer_did.is_empty()
                {
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

                match middleware.gateway.verify_and_settle(&credential).await {
                    Ok(receipt) => {
                        debug!(
                            "Payment verified and settled: receipt_id={}, amount={}",
                            receipt.receipt_id, receipt.amount
                        );

                        // x402 V2: emit the canonical settlement-receipt body
                        // as the `X-PAYMENT-RESPONSE` header (base64-encoded
                        // JSON) per the Coinbase upstream spec. The receipt
                        // body is stashed into `extra["x_payment_response"]`
                        // by the protocol implementation (see
                        // `X402PaymentServer::settle`). Other protocols leave
                        // it absent and the header is simply not emitted.
                        let x_payment_response = receipt
                            .extra
                            .get("x_payment_response")
                            .and_then(|v| serde_json::to_string(v).ok())
                            .map(|s| {
                                use base64::{engine::general_purpose, Engine as _};
                                general_purpose::STANDARD.encode(s.as_bytes())
                            });

                        // Forward the request to the next handler
                        let mut response = next.run(request).await;
                        if let Some(b64) = x_payment_response
                            && let Ok(val) = axum::http::HeaderValue::from_str(&b64)
                        {
                            response.headers_mut().insert("X-PAYMENT-RESPONSE", val);
                        }
                        Ok(response)
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

/// Escapes backslashes and double-quotes for inclusion inside an RFC 7230 quoted-string.
/// Used when building the `WWW-Authenticate: Payment ...` header per
/// `draft-ryan-httpauth-payment-01` ABNF: `auth-param = token BWS "=" BWS ( token / quoted-string )`.
fn escape_quoted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' | '"' => {
                out.push('\\');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

/// Parses a payment credential from a header value
///
/// Supports:
/// - `Authorization: Payment <base64url>` (IETF `draft-ryan-httpauth-payment-01`, MPP-canonical)
/// - `Authorization: mpp <base64-json>` (legacy MPP shape)
/// - `Authorization: x402 <base64-json>`
/// - `Authorization: visa-tap <base64-json>`
/// - `Authorization: mastercard-agent-pay <base64-json>`
/// - `Payment-Credential: <base64-json>` (raw fallback)
///
/// The `Payment` prefix triggers base64url-nopad decoding (per IETF draft);
/// other prefixes use legacy base64 STANDARD encoding.
fn parse_credential(header_value: &str) -> crate::error::Result<PaymentCredential> {
    use base64::{engine::general_purpose, Engine as _};

    // IETF Payment scheme uses base64url-nopad; everything else uses STANDARD
    let (base64_data, is_url_safe) = if let Some(rest) = header_value.strip_prefix("Payment ") {
        (rest, true)
    } else if let Some(rest) = header_value.strip_prefix("mpp ") {
        (rest, false)
    } else if let Some(rest) = header_value.strip_prefix("x402 ") {
        (rest, false)
    } else if let Some(rest) = header_value.strip_prefix("visa-tap ") {
        (rest, false)
    } else if let Some(rest) = header_value.strip_prefix("mastercard-agent-pay ") {
        (rest, false)
    } else {
        // Assume it's a raw base64 value from Payment-Credential
        (header_value, false)
    };

    // Decode base64 (IETF draft mandates base64url-nopad for Payment scheme)
    let json_bytes = if is_url_safe {
        general_purpose::URL_SAFE_NO_PAD
            .decode(base64_data.trim())
            .map_err(|e| {
                crate::error::PaymentError::CredentialError(format!(
                    "Failed to decode base64url credential: {}",
                    e
                ))
            })?
    } else {
        general_purpose::STANDARD.decode(base64_data).map_err(|e| {
            crate::error::PaymentError::CredentialError(format!(
                "Failed to decode base64 credential: {}",
                e
            ))
        })?
    };

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

                // Build IETF-compliant WWW-Authenticate per draft-ryan-httpauth-payment-01.
                // ABNF: challenge = "Payment" 1*SP auth-params
                // Required params: id, realm, method, intent, request
                // Optional: expires, digest, description, opaque
                let request_b64 = {
                    use base64::{engine::general_purpose, Engine as _};
                    // Embed the JSON challenge body as base64url-nopad-encoded request param
                    general_purpose::URL_SAFE_NO_PAD.encode(body.as_bytes())
                };
                let www_auth = format!(
                    "Payment id=\"{}\", realm=\"{}\", method=\"{}\", intent=\"charge\", \
                     request=\"{}\", expires=\"{}\"",
                    escape_quoted(&challenge.challenge_id),
                    escape_quoted(&challenge.resource),
                    escape_quoted(&challenge.protocol),
                    request_b64,
                    challenge.expires_at.to_rfc3339(),
                );

                Response::builder()
                    .status(StatusCode::PAYMENT_REQUIRED)
                    .header(header::WWW_AUTHENTICATE, www_auth)
                    .header(header::CONTENT_TYPE, "application/json")
                    // Simple boolean signal alongside the IETF WWW-Authenticate header.
                    // Lets clients that don't parse the auth-params still detect that
                    // the route is gated. Asserted by the web-server 402 unit tests.
                    .header("Payment-Required", "true")
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
                principal_chain: tenzro_types::principal_chain::anonymous_chain_for_did(
                    verification.payer_did.clone(),
                    tenzro_types::primitives::BlockHeight::new(0),
                ),
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
        let www_auth = response
            .headers()
            .get(axum::http::header::WWW_AUTHENTICATE)
            .expect("WWW-Authenticate header must be set on 402 response")
            .to_str()
            .unwrap();
        assert!(
            www_auth.starts_with("Payment "),
            "WWW-Authenticate must use Payment scheme (RFC 7235), got: {www_auth}"
        );
        assert!(www_auth.contains("realm="));
        assert!(www_auth.contains("method=\"test\""));
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
