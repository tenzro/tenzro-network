use axum::{
    Router,
    routing::{get, post},
};
use std::sync::Arc;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::limit::RequestBodyLimitLayer;

use tenzro_payments::middleware::{PaymentGateConfig, PaymentGateMiddleware, payment_gate_handler};

use super::handlers::{self, WebState};
use super::oauth;
use super::passkey_register;
use crate::error::Result;

/// Web routes a payment can be due on. Whether one is due, and at what price,
/// is the access policy's `paid` rule for the caller, decided per request.
pub const PAYABLE_ROUTES: &[&str] = &[
    "/execution/resolve",
    "/models/:model_id/artifacts",
    "/providers",
];

/// The price a request owes, by path: `Some((amount, asset))` when the access
/// policy asks the caller to pay.
pub type PriceFor = Arc<dyn Fn(&str) -> Option<(u128, String)> + Send + Sync>;

/// The HTTP 402 payment gate: the middleware that issues challenges and
/// settles credentials, and the price each request owes.
///
/// Built by the node from `NodeConfig::payments` plus the live
/// `TenzroPaymentGateway` constructed in `init_payments()`.
pub struct PaymentGateSetup {
    /// Fully-built middleware (gateway + config + shared challenge store)
    pub middleware: PaymentGateMiddleware,
    /// The price a request owes.
    pub price_for: PriceFor,
}

impl PaymentGateSetup {
    pub fn new(middleware: PaymentGateMiddleware, price_for: PriceFor) -> Self {
        Self {
            middleware,
            price_for,
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
    /// The gate that collects payments the access policy asks for.
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

    /// Wire HTTP 402 payment gating into the Web API. A payable route the
    /// access policy prices for the caller returns 402 + a payment challenge
    /// body when no valid `Payment-Credential`/`Authorization` header is
    /// present.
    pub fn with_payment_gate(mut self, setup: PaymentGateSetup) -> Self {
        self.payment_gate = Some(setup);
        self
    }

    /// Start the web server with graceful shutdown support
    pub async fn start_with_shutdown(
        self,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<()> {
        // Exactly the configured browser origins, or none.
        let origins = self
            .state
            .node
            .as_ref()
            .map(|n| n.config().cors_allowed_origins.clone())
            .unwrap_or_default();
        let cors = crate::http_surface::cors_layer(&origins);
        let surface = match self.state.node.as_ref() {
            Some(n) => n.http_surface().clone(),
            None => Arc::new(
                crate::http_surface::SurfacePolicy::from_config(
                    &crate::config::NodeConfig::default(),
                    None,
                )
                .map_err(crate::error::NodeError::Config)?,
            ),
        };

        let mut app = self.build_app();

        // The access policy for the web surface. Mounted only when the web
        // state carries a node handle — a `WebServer` built without one (the
        // unit tests) has no policy to consult. Inside CORS so a browser
        // preflight is answered before the gate sees it.
        if let Some(node) = self.state.node.clone() {
            app = app.layer(axum::middleware::from_fn_with_state(
                (node, tenzro_types::node_access::Surface::Web),
                crate::access::http_gate,
            ));
        }

        // Only this node's own names reach it.
        if let Some(node) = self.state.node.clone() {
            app = app.layer(axum::middleware::from_fn_with_state(
                node,
                crate::http_surface::require_known_web_host,
            ));
        }

        let app = match self.state.node.clone() {
            Some(node) => app.layer(axum::middleware::from_fn_with_state(
                node,
                crate::inference_admission::identify_caller,
            )),
            None => app,
        };
        let app = app
            .layer(cors)
            // Concurrency limit: max 100 in-flight requests
            .layer(ConcurrencyLimitLayer::new(100))
            // Under load a request of a shed class is refused with 503 and
            // Retry-After before it reaches the limit above.
            .layer(axum::middleware::from_fn_with_state(
                crate::load_shed::ShedGate::new(),
                crate::load_shed::load_shed,
            ))
            // Request body size limit: 2 MB
            .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024))
            // Per-IP GCRA gate, outermost so an abusive source is
            // rejected with 429 before consuming a concurrency slot.
            // 10 req/s sustained per IP with a burst of 50 — the Web API
            // fronts inference chat and verification, both heavier per
            // request than plain RPC reads.
            .layer(axum::middleware::from_fn_with_state(
                crate::ip_rate_limit::IpRateLimiter::new(
                    10,
                    50,
                    surface,
                    crate::ip_rate_limit::Answer::Http,
                ),
                crate::ip_rate_limit::ip_rate_limit,
            ));

        let listener = tokio::net::TcpListener::bind(&self.listen_addr).await?;
        if let Some(gate) = self.payment_gate.as_ref() {
            let cfg = gate.config();
            tracing::info!(
                addr = %self.listen_addr,
                default_amount = %cfg.default_amount,
                default_asset = %cfg.default_asset,
                default_protocol = %cfg.default_protocol,
                recipient = %cfg.recipient,
                "Web API listening (HTTP 402 payment gate enabled)"
            );
        } else {
            tracing::info!(addr = %self.listen_addr, "Web API listening (includes /metrics)");
        }

        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        )
        .with_graceful_shutdown(async move {
            let _ = shutdown_rx.recv().await;
            tracing::info!("Web API server shutting down gracefully");
        })
        .await?;

        Ok(())
    }

    /// Build the axum router. Payable routes run the paid matcher: the
    /// access policy decides per request whether a payment is due, and the
    /// payment gate collects it.
    fn build_app(&self) -> Router {
        // HTTP endpoints are served at root paths — the public hostname
        // `api.tenzro.com` is itself the `/api` namespace, so doubling
        // the prefix on routes would produce `api.tenzro.com/api/...`.
        // `/metrics` stays at root to comply with the Prometheus scraper
        // convention.
        let open = Router::new()
            .route("/verify/did-envelope", post(handlers::verify_did_envelope))
            .route("/verify/zk-proof", post(handlers::verify_zk_proof))
            .route(
                "/verify/tee-attestation",
                post(handlers::verify_tee_attestation),
            )
            .route("/verify/transaction", post(handlers::verify_transaction))
            .route("/verify/settlement", post(handlers::verify_settlement))
            .route("/verify/inference", post(handlers::verify_inference))
            // W3C DID resolution well-known path. Inside the access policy,
            // because a closed node's operator has said who may talk to it at
            // all, and addressing information is a service like any other. A
            // node that wants to be discoverable leaves `read` open.
            .route("/.well-known/did.json", get(handlers::node_did_document))
            .route("/verify/health", get(handlers::health))
            .route("/health", get(handlers::health))
            .route("/verify/ready", get(handlers::ready))
            .route("/ready", get(handlers::ready))
            .route("/status", get(handlers::status))
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
            // DIF Universal Resolver-compatible DID resolution. Path is
            // exactly what `decentralized-identity/universal-resolver`
            // serves so any compliant resolver driver can dispatch here.
            .route(
                "/1.0/identifiers/:did",
                get(crate::web::universal_resolver::resolve_identifier),
            )
            .route(
                "/1.0/methods",
                get(crate::web::universal_resolver::list_methods),
            )
            // Enrol a passkey credential. Assertions are checked against the
            // key the authenticator registered here; nothing is derived from
            // the credential id, which is public.
            .route(
                "/wallet/passkey/register",
                post(passkey_register::passkey_register_handler),
            )
            // Browser-launch passkey ceremony (gcloud-style CLI login).
            // The CLI creates a session over JSON-RPC, opens the page in a
            // browser, and polls `tenzro_getPasskeySession`; the page runs
            // the WebAuthn ceremony and posts the outcome back here.
            .route("/auth/passkey", get(crate::web::passkey_auth::passkey_page))
            .route(
                "/auth/passkey/session/:session_id",
                get(crate::web::passkey_auth::session_info),
            )
            .route(
                "/auth/passkey/session/:session_id/complete",
                post(crate::web::passkey_auth::session_complete),
            )
            // Prometheus metrics endpoint (kept at root for standard scrapers)
            .route("/metrics", get(handlers::prometheus_metrics));

        let payable = Router::new()
            .route(PAYABLE_ROUTES[0], post(handlers::resolve_execution))
            .route(PAYABLE_ROUTES[1], get(handlers::list_model_artifacts))
            .route(PAYABLE_ROUTES[2], get(handlers::list_providers_rfc));

        // Apply state to the open router
        let open = open.with_state(self.state.clone());

        // The x402 facilitator for resource servers that sell over x402:
        // `/facilitator/x402/verify`, `/facilitator/x402/settle` and
        // `/facilitator/x402/supported`.
        let open = match self
            .state
            .node
            .as_ref()
            .and_then(|n| n.x402_facilitator_service().cloned())
        {
            Some(facilitator) => open.nest(
                "/facilitator/x402",
                tenzro_payments::x402::facilitator_router(
                    tenzro_payments::x402::FacilitatorServerState::new(facilitator),
                ),
            ),
            None => open,
        };

        // ACP checkout for paid AI work, paid through the facilitator above:
        // `/acp/checkout_sessions` and its update, get, complete and cancel.
        // UCP checkout over the same sessions and seller: `/.well-known/ucp`
        // and `/checkout-sessions`, completed under the Tenzro handler with
        // AP2 mandates.
        let open = match self.state.node.as_ref() {
            Some(node) if node.x402_facilitator_service().is_some() => {
                let sessions = tenzro_payments::acp::AcpState::new(std::sync::Arc::new(
                    crate::acp_seller::NodeSeller::new(node.clone()),
                ));
                let open = open.nest("/acp", tenzro_payments::acp::acp_router(sessions.clone()));
                match crate::acp_seller::NodeMerchant::open() {
                    Ok(merchant) => open.merge(tenzro_payments::ucp::ucp_router(
                        sessions,
                        std::sync::Arc::new(merchant),
                        format!("http://{}", node.config().web_addr),
                    )),
                    Err(e) => {
                        tracing::warn!(error = %e, "UCP checkout not served: no business key");
                        open
                    }
                }
            }
            _ => open,
        };

        // Forward-auth for reverse proxies in front of a publisher's site:
        // the proxy asks with the original method, URI and headers and
        // serves the request only on a 2xx, after this node's gate settled
        // its payment.
        let open = match self.payment_gate.as_ref().map(|g| g.middleware.clone()) {
            Some(middleware) => open.route(
                "/payments/forward-auth",
                axum::routing::any(move |request: axum::extract::Request| {
                    tenzro_payments::middleware::forward_auth(middleware.clone(), request)
                }),
            ),
            None => open,
        };

        let price_for = match (&self.payment_gate, &self.state.node) {
            (Some(gate), _) => Some(gate.price_for.clone()),
            (None, Some(node)) => Some(crate::access::web_pricing(node.clone())),
            (None, None) => None,
        };
        let payable = payable.with_state(self.state.clone());
        let payable = match price_for {
            Some(price_for) => payable.layer(axum::middleware::from_fn_with_state(
                (
                    price_for,
                    self.payment_gate.as_ref().map(|g| g.middleware.clone()),
                ),
                paid_matcher,
            )),
            None => payable,
        };
        open.merge(payable)
    }
}

/// Collect the payment the access policy asks for on a payable route, at the
/// policy's price; pass the request through when none is due.
async fn paid_matcher(
    axum::extract::State((price_for, gate)): axum::extract::State<(
        PriceFor,
        Option<PaymentGateMiddleware>,
    )>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Some((amount, asset)) = price_for(request.uri().path()) else {
        return next.run(request).await;
    };
    let Some(mut middleware) = gate else {
        return (
            axum::http::StatusCode::PAYMENT_REQUIRED,
            axum::Json(serde_json::json!({ "error": tenzro_payments::middleware::PAYMENT_REQUIRED_NO_GATEWAY })),
        )
            .into_response();
    };
    middleware.config.default_amount = amount;
    middleware.config.default_asset = asset;
    payment_gate_handler(axum::extract::State(middleware), request, next)
        .await
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chrono::Utc;
    use std::collections::HashMap;
    use tenzro_payments::gateway::TenzroPaymentGateway;
    use tenzro_payments::traits::PaymentProtocol;
    use tenzro_payments::types::{
        PaymentChallenge, PaymentCredential, PaymentReceipt, PaymentVerification,
    };
    use tower::ServiceExt;

    /// Challenge-only protocol used to drive the gated-route smoke test;
    /// these tests never present a credential.
    struct ChallengeOnlyProtocol;

    #[async_trait]
    impl PaymentProtocol for ChallengeOnlyProtocol {
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
            _credential: &PaymentCredential,
        ) -> tenzro_payments::Result<PaymentVerification> {
            Err(tenzro_payments::PaymentError::VerificationFailed(
                "challenge-only protocol".to_string(),
            ))
        }

        async fn settle(
            &self,
            _challenge: &PaymentChallenge,
            _credential: &PaymentCredential,
            _verification: &PaymentVerification,
        ) -> tenzro_payments::Result<PaymentReceipt> {
            Err(tenzro_payments::PaymentError::SettlementError(
                "challenge-only protocol".to_string(),
            ))
        }

        async fn create_credential(
            &self,
            _challenge: &PaymentChallenge,
            _payer_did: &str,
            _signer: &dyn tenzro_crypto::composite::HybridSigner,
        ) -> tenzro_payments::Result<PaymentCredential> {
            Err(tenzro_payments::PaymentError::CredentialError(
                "challenge-only protocol".to_string(),
            ))
        }
    }

    fn build_setup() -> PaymentGateSetup {
        let gateway = Arc::new(TenzroPaymentGateway::new(
            1337,
            Arc::new(crate::payment_rails::LedgerEnrolledKeys::new(None)),
        ));
        gateway.register_protocol(Arc::new(ChallengeOnlyProtocol));
        let store = gateway.challenge_store();

        let middleware = PaymentGateMiddleware::new(
            gateway,
            PaymentGateConfig {
                default_amount: 1000,
                default_asset: "TNZO".to_string(),
                recipient: "0909090909090909090909090909090909090909".to_string(),
                default_protocol: "test".to_string(),
            },
            store,
        );

        PaymentGateSetup::new(
            middleware,
            Arc::new(|path: &str| {
                (path == "/execution/resolve").then(|| (1000, "TNZO".to_string()))
            }),
        )
    }

    #[tokio::test]
    async fn test_unprotected_routes_skip_middleware() {
        // /health is never gated; even when /execution/resolve is gated, /health
        // must continue to return 200 without a payment header.
        let server = WebServer::new("127.0.0.1:0".to_string()).with_payment_gate(build_setup());

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
        let server = WebServer::new("127.0.0.1:0".to_string()).with_payment_gate(build_setup());

        let app = server.build_app();
        let request = Request::builder()
            .method("POST")
            .uri("/execution/resolve")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
    }

    #[tokio::test]
    async fn test_paid_route_with_no_gate_returns_normal() {
        // With no payment gate and no access policy to price it,
        // /execution/resolve is not gated. It reaches the real handler, which
        // may itself error, but the response status must not be 402.
        let server = WebServer::new("127.0.0.1:0".to_string());
        let app = server.build_app();
        let request = Request::builder()
            .method("POST")
            .uri("/execution/resolve")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_ne!(response.status(), StatusCode::PAYMENT_REQUIRED);
    }

    /// The derived-key wallet cluster is gone: threshold signing
    /// (`/wallet/frost/*`), the DID-derived ML-DSA signing surface
    /// (`/wallet/mldsa/*`), the share-escrow surface (`/wallet/share/*`),
    /// and the derived-key provisioning path (`/wallet/new/*`) all rooted
    /// custody in keys the node could recompute, not in the holder's
    /// hardware. Every one of their routes must be unmounted, not merely
    /// unreachable — a surviving route would keep advertising a custody
    /// model the node can no longer honour.
    #[tokio::test]
    async fn test_derived_key_cluster_routes_are_unmounted() {
        let post_paths = [
            "/wallet/frost/ed25519/start",
            "/wallet/frost/ed25519/commit",
            "/wallet/frost/ed25519/await-challenge",
            "/wallet/frost/ed25519/respond",
            "/wallet/frost/ed25519/finalize",
            "/wallet/frost/ed25519/abort",
            "/wallet/frost/secp256k1/start",
            "/wallet/mldsa/sign",
            "/wallet/share/escrow/challenge",
            "/wallet/share/escrow/unwrap",
            "/wallet/new/start",
            "/wallet/new/finalize",
            "/wallet/new/confirm",
            "/wallet/new/cancel",
        ];
        for path in post_paths {
            let server = WebServer::new("127.0.0.1:0".to_string());
            let app = server.build_app();
            let request = Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from("{}"))
                .unwrap();
            let response = app.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "{path} is still mounted"
            );
        }

        let get_paths = [
            "/wallet/mldsa/capabilities",
            "/wallet/share/envelope?credential_id=c&surface_key=s",
        ];
        for path in get_paths {
            let server = WebServer::new("127.0.0.1:0".to_string());
            let app = server.build_app();
            let request = Request::builder()
                .method("GET")
                .uri(path)
                .body(Body::empty())
                .unwrap();
            let response = app.oneshot(request).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::NOT_FOUND,
                "{path} is still mounted"
            );
        }
    }
}
