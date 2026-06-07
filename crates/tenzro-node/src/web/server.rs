use axum::{Router, routing::{get, post}};
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::{CorsLayer, Any};
use tower_http::limit::RequestBodyLimitLayer;
use std::collections::HashSet;
use std::sync::Arc;

use tenzro_payments::middleware::{
    payment_gate_handler, PaymentGateConfig, PaymentGateMiddleware,
};

use crate::error::Result;
use super::handlers::{self, WebState};
use super::oauth;
use super::wallet_frost;
use super::wallet_mldsa;
use super::wallet_share;

/// Configuration for the HTTP 402 payment gate, plus the set of routes
/// that should be wrapped with the [`payment_gate_handler`] middleware.
///
/// Built by the node from `NodeConfig::payments` plus the live
/// `TenzroPaymentGateway` constructed in `init_payments()`.
pub struct PaymentGateSetup {
    /// Fully-built middleware (gateway + config + shared challenge store)
    pub middleware: PaymentGateMiddleware,
    /// Exact-match paths that should be gated, e.g. "/chat", "/execution/resolve"
    pub paid_routes: HashSet<String>,
}

impl PaymentGateSetup {
    pub fn new(middleware: PaymentGateMiddleware, paid_routes: Vec<String>) -> Self {
        Self {
            middleware,
            paid_routes: paid_routes.into_iter().collect(),
        }
    }

    /// Returns the gate's [`PaymentGateConfig`].
    ///
    /// Read by [`WebServer::start_with_shutdown`] when emitting the
    /// "payment gate enabled" startup log, so operators see the active
    /// default amount/asset/recipient/protocol without having to grep
    /// the running config. Also used in `PaymentGateSetup` test
    /// helpers.
    pub fn config(&self) -> &PaymentGateConfig {
        &self.middleware.config
    }
}

pub struct WebServer {
    listen_addr: String,
    state: Arc<WebState>,
    /// When `Some`, paid routes are wrapped with the payment gate middleware.
    /// When `None`, all routes are unprotected (legacy behaviour).
    payment_gate: Option<PaymentGateSetup>,
}

impl WebServer {
    pub fn new(listen_addr: String) -> Self {
        Self {
            listen_addr,
            state: Arc::new(WebState::new()),
            payment_gate: None,
        }
    }

    pub fn with_state_arc(mut self, state: Arc<WebState>) -> Self {
        self.state = state;
        self
    }

    /// Wire HTTP 402 payment gating into the Web API. Routes named in
    /// `setup.paid_routes` will return 402 + a payment challenge body when
    /// no valid `Payment-Credential`/`Authorization` header is present.
    pub fn with_payment_gate(mut self, setup: PaymentGateSetup) -> Self {
        self.payment_gate = Some(setup);
        self
    }

    /// Start the web server with graceful shutdown support
    pub async fn start_with_shutdown(
        self,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<()> {
        let cors = CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);

        let app = self.build_app().layer(cors)
            // Concurrency limit: max 100 in-flight requests
            .layer(ConcurrencyLimitLayer::new(100))
            // Request body size limit: 2 MB
            .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024));

        let listener = tokio::net::TcpListener::bind(&self.listen_addr).await?;
        if let Some(gate) = self.payment_gate.as_ref() {
            let cfg = gate.config();
            tracing::info!(
                addr = %self.listen_addr,
                default_amount = %cfg.default_amount,
                default_asset = %cfg.default_asset,
                default_protocol = %cfg.default_protocol,
                recipient = %cfg.recipient,
                paid_routes = ?gate.paid_routes,
                "Web API listening (HTTP 402 payment gate enabled)"
            );
        } else {
            tracing::info!(addr = %self.listen_addr, "Web API listening (includes /metrics)");
        }

        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.recv().await;
                tracing::info!("Web API server shutting down gracefully");
            })
            .await?;

        Ok(())
    }

    /// Build the axum router. Public routes are always mounted; paid routes
    /// are only wrapped with the payment gate middleware when one of two
    /// conditions holds:
    ///   1. `payment_gate` is `Some`, AND
    ///   2. The route's path is listed in `payment_gate.paid_routes`.
    ///
    /// All other routes are mounted unprotected.
    fn build_app(&self) -> Router {
        // Helper closure: should this route be gated?
        let is_paid = |path: &str| -> bool {
            self.payment_gate
                .as_ref()
                .map(|g| g.paid_routes.contains(path))
                .unwrap_or(false)
        };

        // HTTP endpoints are served at root paths — the public hostname
        // `api.tenzro.network` is itself the `/api` namespace, so doubling
        // the prefix on routes would produce `api.tenzro.network/api/...`.
        // `/metrics` stays at root to comply with the Prometheus scraper
        // convention.
        //
        // Paid routes (gated by HTTP 402 middleware) are matched against the
        // full mounted path (e.g. `/chat`). Config must list
        // `payments.paid_routes = ["/chat", "/execution/resolve", ...]`.
        let mut open = Router::new()
            .route("/verify/did-envelope", post(handlers::verify_did_envelope))
            .route("/verify/zk-proof", post(handlers::verify_zk_proof))
            .route("/verify/tee-attestation", post(handlers::verify_tee_attestation))
            .route("/verify/transaction", post(handlers::verify_transaction))
            .route("/verify/settlement", post(handlers::verify_settlement))
            .route("/verify/inference", post(handlers::verify_inference))
            .route("/verify/health", get(handlers::health))
            .route("/health", get(handlers::health))
            .route("/verify/ready", get(handlers::ready))
            .route("/ready", get(handlers::ready))
            .route("/status", get(handlers::status))
            .route("/faucet", post(handlers::faucet))
            // OAuth 2.1 / RFC 8693 / RFC 7662 / RFC 7009 / RFC 9728
            // — agent-to-agent token surface, distinct from the
            // MCP-specific authorization-code flow on port 3001.
            .route("/oauth/token", post(oauth::token_exchange_handler))
            .route("/oauth/introspect", post(oauth::introspect_handler))
            .route("/oauth/revoke", post(oauth::revoke_handler))
            .route(
                "/.well-known/oauth-protected-resource",
                get(oauth::protected_resource_metadata_handler),
            )
            .route(
                "/.well-known/openid-configuration",
                get(oauth::as_metadata_handler),
            )
            // RFC 7517 / RFC 7518 JWK Set — public signing keys for every
            // active Tenzro identity. External RFC 9421 verifiers (Visa
            // TAP, Mastercard Agent Pay, Stripe MPP, AP2 facilitators,
            // x402 settlement nodes) resolve `keyid` parameters here.
            .route("/.well-known/jwks.json", get(handlers::jwks))
            .route("/.well-known/jwks.json/:keyid", get(handlers::jwks_get))
            // ML-DSA-65 (FIPS 204) wallet signing surface — `tee-only`
            // mode for testnet. Threshold endpoints await NIST IR 8214B
            // and are intentionally unmounted (no dead routes).
            .route(
                "/wallet/mldsa/capabilities",
                get(wallet_mldsa::capabilities_handler),
            )
            .route("/wallet/mldsa/sign", post(wallet_mldsa::sign_handler))
            // FROST (RFC 9591) round-coordination — six endpoints,
            // two schemes (ed25519 + secp256k1), curve dispatched via
            // the `:scheme` path segment. Per-scheme behavior lives
            // in `wallet_frost::{ed25519_ops, secp256k1_ops}`.
            .route(
                "/wallet/frost/:scheme/start",
                post(wallet_frost::start_handler),
            )
            .route(
                "/wallet/frost/:scheme/commit",
                post(wallet_frost::commit_handler),
            )
            .route(
                "/wallet/frost/:scheme/await-challenge",
                post(wallet_frost::await_challenge_handler),
            )
            .route(
                "/wallet/frost/:scheme/respond",
                post(wallet_frost::respond_handler),
            )
            .route(
                "/wallet/frost/:scheme/finalize",
                post(wallet_frost::finalize_handler),
            )
            .route(
                "/wallet/frost/:scheme/abort",
                post(wallet_frost::abort_handler),
            )
            // Passkey share-unwrap surface — three endpoints. The
            // wrapped FROST share is fetched via `envelope`; unwrap
            // requires a fresh WebAuthn assertion bound to a
            // server-issued single-use nonce.
            .route(
                "/wallet/share/envelope",
                get(wallet_share::envelope_handler),
            )
            .route(
                "/wallet/share/escrow/challenge",
                post(wallet_share::challenge_handler),
            )
            .route(
                "/wallet/share/escrow/unwrap",
                post(wallet_share::unwrap_handler),
            )
            // Prometheus metrics endpoint (kept at root for standard scrapers)
            .route("/metrics", get(handlers::prometheus_metrics));

        // Routes that *may* be gated by HTTP 402 payment middleware. Add to
        // `open` when not gated; add to `gated` when gated. Paths are
        // matched against `config.payments.paid_routes`.
        let mut gated = Router::new();
        let mut any_gated = false;

        // Chat completion (OpenAI-compatible)
        if is_paid("/chat") {
            gated = gated.route("/chat", post(handlers::chat_completion));
            any_gated = true;
        } else {
            open = open.route("/chat", post(handlers::chat_completion));
        }

        // Adaptive execution resolve (RFC-0007)
        if is_paid("/execution/resolve") {
            gated = gated.route("/execution/resolve", post(handlers::resolve_execution));
            any_gated = true;
        } else {
            open = open.route("/execution/resolve", post(handlers::resolve_execution));
        }

        // Model artifact listing (parameterised — gating treats the template
        // as the path)
        if is_paid("/models/:model_id/artifacts") {
            gated = gated.route(
                "/models/:model_id/artifacts",
                get(handlers::list_model_artifacts),
            );
            any_gated = true;
        } else {
            open = open.route(
                "/models/:model_id/artifacts",
                get(handlers::list_model_artifacts),
            );
        }

        // Provider listing (RFC-0007)
        if is_paid("/providers") {
            gated = gated.route("/providers", get(handlers::list_providers_rfc));
            any_gated = true;
        } else {
            open = open.route("/providers", get(handlers::list_providers_rfc));
        }

        // Execution receipt lookup (parameterised)
        if is_paid("/execution/receipts/:receipt_id") {
            gated = gated.route(
                "/execution/receipts/:receipt_id",
                get(handlers::get_execution_receipt),
            );
            any_gated = true;
        } else {
            open = open.route(
                "/execution/receipts/:receipt_id",
                get(handlers::get_execution_receipt),
            );
        }

        // Apply state to the open router
        let open = open.with_state(self.state.clone());

        // If anything is gated, attach the middleware layer to the gated
        // sub-router and merge it back in. Each branch ends up with the
        // same final type (`Router`), which is what axum's merge expects.
        if any_gated {
            // Safe: any_gated implies payment_gate.is_some()
            let gate = self.payment_gate.as_ref().expect("payment_gate set when any_gated");
            let gated_with_state = gated.with_state(self.state.clone()).layer(
                axum::middleware::from_fn_with_state(
                    gate.middleware.clone(),
                    payment_gate_handler,
                ),
            );
            open.merge(gated_with_state)
        } else {
            open
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_payments::challenge_store::ChallengeStore;
    use tenzro_payments::gateway::TenzroPaymentGateway;
    use tenzro_payments::traits::PaymentProtocol;
    use tenzro_payments::types::{
        PaymentChallenge, PaymentCredential, PaymentReceipt, PaymentVerification,
    };
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chrono::Utc;
    use std::collections::HashMap;
    use tower::ServiceExt;

    /// Trivial protocol used to drive the gated-route smoke test.
    struct AlwaysOkProtocol;

    #[async_trait]
    impl PaymentProtocol for AlwaysOkProtocol {
        fn protocol_name(&self) -> &str {
            "test"
        }

        async fn create_challenge(
            &self,
            resource: &str,
            amount: u128,
            asset: &str,
            recipient: &str,
        ) -> tenzro_payments::Result<PaymentChallenge> {
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
        ) -> tenzro_payments::Result<PaymentVerification> {
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
        ) -> tenzro_payments::Result<PaymentReceipt> {
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
        ) -> tenzro_payments::Result<PaymentCredential> {
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

    fn build_setup() -> PaymentGateSetup {
        let store = ChallengeStore::new();
        let gateway = Arc::new(
            TenzroPaymentGateway::new().with_challenge_store(store.clone()),
        );
        gateway.register_protocol(Arc::new(AlwaysOkProtocol));

        let middleware = PaymentGateMiddleware::new(
            gateway,
            PaymentGateConfig {
                default_amount: 1000,
                default_asset: "USDC".to_string(),
                recipient: "0xrecipient".to_string(),
                default_protocol: "test".to_string(),
            },
            store,
        );

        PaymentGateSetup::new(middleware, vec!["/chat".to_string()])
    }

    #[tokio::test]
    async fn test_unprotected_routes_skip_middleware() {
        // /health is never gated; even when /chat is gated, /health
        // must continue to return 200 without a payment header.
        let server = WebServer::new("127.0.0.1:0".to_string())
            .with_payment_gate(build_setup());

        let app = server.build_app();
        let request = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_paid_route_returns_402_without_credential() {
        let server = WebServer::new("127.0.0.1:0".to_string())
            .with_payment_gate(build_setup());

        let app = server.build_app();
        let request = Request::builder()
            .method("POST")
            .uri("/chat")
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
    async fn test_paid_route_with_no_gate_returns_normal() {
        // When no payment gate is wired at all, /chat must NOT be gated.
        // It will hit the real chat handler which may itself error, but
        // the response status must not be 402.
        let server = WebServer::new("127.0.0.1:0".to_string());
        let app = server.build_app();
        let request = Request::builder()
            .method("POST")
            .uri("/chat")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_ne!(response.status(), StatusCode::PAYMENT_REQUIRED);
    }

    /// `/wallet/mldsa/sign` must reject any request lacking the
    /// `Authorization: DPoP <jwt>` header. This is the load-bearing
    /// invariant of the wallet auth surface — a missing header must
    /// produce a 401, not a key-derivation attempt against an
    /// attacker-supplied DID/surface_key.
    #[tokio::test]
    async fn test_wallet_mldsa_sign_rejects_unauthenticated() {
        let server = WebServer::new("127.0.0.1:0".to_string());
        let app = server.build_app();
        let request = Request::builder()
            .method("POST")
            .uri("/wallet/mldsa/sign")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"did":"did:tenzro:human:alice","surface_key":"vault.0","preimage_b64":""}"#,
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// `/wallet/mldsa/capabilities` is a discovery endpoint but is
    /// still capability-gated — the wallet treats `tee-only` vs a
    /// future `threshold` mode as authorization-relevant metadata
    /// that should not leak to unauthenticated callers.
    #[tokio::test]
    async fn test_wallet_mldsa_capabilities_rejects_unauthenticated() {
        let server = WebServer::new("127.0.0.1:0".to_string());
        let app = server.build_app();
        let request = Request::builder()
            .method("GET")
            .uri("/wallet/mldsa/capabilities")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// `/wallet/frost/{scheme}/start` must reject any request lacking
    /// the `Authorization: DPoP <jwt>` header. The auth check runs
    /// *before* the FROST coordinator is even consulted, so an
    /// unauthenticated client cannot allocate session state at all.
    #[tokio::test]
    async fn test_wallet_frost_start_rejects_unauthenticated() {
        let server = WebServer::new("127.0.0.1:0".to_string());
        let app = server.build_app();
        let request = Request::builder()
            .method("POST")
            .uri("/wallet/frost/ed25519/start")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"did":"did:tenzro:human:alice","surface_key":"vault.0","preimage_b64":""}"#,
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Same reject-before-allocate guarantee for the secp256k1 leg.
    #[tokio::test]
    async fn test_wallet_frost_secp256k1_start_rejects_unauthenticated() {
        let server = WebServer::new("127.0.0.1:0".to_string());
        let app = server.build_app();
        let request = Request::builder()
            .method("POST")
            .uri("/wallet/frost/secp256k1/start")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"did":"did:tenzro:human:alice","surface_key":"vault.0","preimage_b64":""}"#,
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Other FROST endpoints (`commit`, `respond`, `await-challenge`,
    /// `finalize`, `abort`) all share the same auth helper; one
    /// representative is enough to confirm they're wired the same way.
    #[tokio::test]
    async fn test_wallet_frost_respond_rejects_unauthenticated() {
        let server = WebServer::new("127.0.0.1:0".to_string());
        let app = server.build_app();
        let request = Request::builder()
            .method("POST")
            .uri("/wallet/frost/ed25519/respond")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"session_id":"frost-fake","device_signature_share_b64":""}"#,
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// `/wallet/share/envelope` must reject any request lacking the
    /// `Authorization: DPoP <jwt>` header. The auth check runs *before*
    /// the share-wrapping derivation, so an unauthenticated client
    /// cannot probe the wrapping construction.
    #[tokio::test]
    async fn test_wallet_share_envelope_rejects_unauthenticated() {
        let server = WebServer::new("127.0.0.1:0".to_string());
        let app = server.build_app();
        let request = Request::builder()
            .method("GET")
            .uri("/wallet/share/envelope?credential_id=cred-A&surface_key=vault.0")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// Same reject-before-allocate guarantee for the escrow challenge
    /// endpoint — an unauthenticated client must not be able to mint
    /// nonces and pollute the escrow store.
    #[tokio::test]
    async fn test_wallet_share_challenge_rejects_unauthenticated() {
        let server = WebServer::new("127.0.0.1:0".to_string());
        let app = server.build_app();
        let request = Request::builder()
            .method("POST")
            .uri("/wallet/share/escrow/challenge")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"credential_id":"cred-A","surface_key":"vault.0"}"#,
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    /// The unwrap endpoint must also reject before consulting the
    /// escrow map — no information leaks (nonce existence, etc.) from
    /// an unauthenticated probe.
    #[tokio::test]
    async fn test_wallet_share_unwrap_rejects_unauthenticated() {
        let server = WebServer::new("127.0.0.1:0".to_string());
        let app = server.build_app();
        let request = Request::builder()
            .method("POST")
            .uri("/wallet/share/escrow/unwrap")
            .header("content-type", "application/json")
            .body(Body::from(
                r#"{"credential_id":"cred-A","surface_key":"vault.0","nonce_b64":"","assertion":{"authenticator_data_b64":"","client_data_json_b64":"","signature_b64":""}}"#,
            ))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}
