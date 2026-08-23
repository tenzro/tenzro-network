use axum::{
    Router,
    routing::{get, post},
};
use std::collections::HashSet;
use std::sync::Arc;
use tower::limit::ConcurrencyLimitLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;

use tenzro_payments::middleware::{PaymentGateConfig, PaymentGateMiddleware, payment_gate_handler};

use super::handlers::{self, WebState};
use super::oauth;
use super::wallet_frost;
use super::wallet_mldsa;
use super::wallet_new;
use super::wallet_share;
use crate::error::Result;

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

/// Host-header dispatch. When an incoming request's `Host` maps to a registered
/// site alias or a verified custom domain, serve it from that site's manifest
/// (path `<path>` under `site_id`) so the static-site handler renders it. A
/// custom hostname (`myapp.apps.tenzro.xyz`) or an owner's own domain
/// (`shop.example.com`) thus lands on its site without the caller ever naming
/// the raw site id. Aliases are checked first; a verified custom domain is the
/// fallback. Unverified custom domains do not resolve, so an in-flight claim
/// never serves content.
///
/// The rewrite is skipped when the path already targets an API surface
/// (`/sites/`, `/facilitator/`, `/wallet/`, `/metrics`, `/health`, `/ready`,
/// `/status`, `/verify/`, `/faucet`, `/chat`, `/v1/`, `/models/`, `/providers`,
/// `/execution/`) so an aliased hostname cannot shadow the node's own routes —
/// aliases only ever add site paths, never intercept the control plane.
async fn host_alias_rewrite(
    axum::extract::State(state): axum::extract::State<Arc<WebState>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    if let Some(node) = state.node.as_ref() {
        let host = req
            .headers()
            .get(axum::http::header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let path = req.uri().path().to_string();

        // Node aliases resolve ahead of site aliases: `<name>.<suffix>` names
        // a node, not a deployment, and the two namespaces are disjoint.
        //
        // Deliberately NOT gated on `is_reserved_path`. That guard exists so a
        // site alias cannot shadow this node's control plane, but the point of
        // a public node name is that `alice.<suffix>/v1/chat/completions`
        // works. The equivalent protection for this path is the alias's own
        // `exposed_prefixes` allowlist, enforced fail-closed on the *serving*
        // node in `ingress::serve_node_alias` — putting it there means a buggy
        // or hostile edge cannot widen what the operator agreed to expose.
        if let Some(ref host) = host
            && let Some(registry) = node.node_alias_registry()
            && let Some(alias) = registry.resolve_host(host)
        {
            let bound_endpoint = alias.endpoint_id.clone();
            let local = node
                .iroh_resolver()
                .map(|resolver| resolver.endpoint_id().to_string());

            match (bound_endpoint, local) {
                // Resolves to this very node: serve locally.
                //
                // This branch is mandatory, not an optimisation. Without it
                // the node forwards to itself over iroh, the replayed request
                // still carries `Host: <name>.<suffix>` (the relay preserves
                // every caller header, correctly), this middleware matches the
                // alias table again, and the node forwards to itself forever.
                (Some(bound), Some(local)) if bound == local => {
                    return next.run(req).await;
                }
                (Some(bound), _) => match bound.parse::<tenzro_iroh::EndpointId>() {
                    Ok(endpoint) => {
                        return forward_to_alias_node(node.clone(), endpoint, req).await;
                    }
                    Err(e) => {
                        tracing::debug!(alias = %alias.name, "unparseable bound endpoint: {e}");
                    }
                },
                // Claimed but never bound — nothing to route to yet.
                (None, _) => {}
            }
        }

        if let Some(host) = host
            && !is_reserved_path(&path)
            && let Some(site_id) = node
                .site_registry()
                .resolve_alias(&host)
                .or_else(|| node.site_registry().resolve_domain(&host))
        {
            // Placement decides local-vs-remote. When the site is placed on a
            // remote serving node, forward the request over the `tenzro/http`
            // iroh ALPN and relay the response verbatim; the local static
            // handler is bypassed. An empty remote list means "serve locally".
            if let Some(resolver) = node.iroh_resolver() {
                let local = resolver.endpoint_id();
                let remotes = node.ingress_table().remote_serving_nodes(&site_id, &local);
                if !remotes.is_empty() {
                    return forward_to_serving_node(node.clone(), &site_id, remotes, req).await;
                }
            }

            // Dispatch straight to the site handler rather than mutating the URI
            // and re-entering the router. `Router::layer` in axum 0.7 wraps each
            // matched route *after* routing has already run against the original
            // path, so a rewritten URI would never re-route — the request would
            // fall through to the 404 fallback. Calling `serve` directly with the
            // resolved `site_id` skips routing entirely.
            let asset = path
                .strip_prefix('/')
                .filter(|p| !p.is_empty())
                .map(|p| p.to_string());
            let headers = req.headers().clone();
            return crate::web::sites::serve(state.clone(), site_id, asset, headers).await;
        }
    }
    next.run(req).await
}

/// Edge dispatch for a remotely-placed site: assemble the raw HTTP/1.1 request
/// from the axum request, open a `tenzro/http` bi-stream to the first reachable
/// serving node (the rest are failover), and relay the raw response back as an
/// axum response. On total failure across all candidates, return 502.
async fn forward_to_serving_node(
    node: Arc<crate::node::TenzroNode>,
    site_id: &str,
    remotes: Vec<tenzro_iroh::EndpointId>,
    req: axum::extract::Request,
) -> axum::response::Response {
    // Rewrite the forwarded path to the site-scoped form the serving node's
    // ingress handler resolves (`/sites/<id><suffix>`), so the serving node
    // does not depend on its own alias/domain tables to identify the site.
    let path = req.uri().path();
    let suffix = if path == "/" {
        String::new()
    } else {
        path.to_string()
    };
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    let forwarded_target = format!("/sites/{site_id}{suffix}{query}");
    forward_over_iroh(node, remotes, req, forwarded_target).await
}

/// Forward a request to a node alias's bound node, preserving the original
/// path verbatim.
///
/// Unlike the site path there is no target rewrite: the serving node resolves
/// the alias from the `Host` header the caller sent, and the request is for
/// that node's own surface rather than for a deployment it hosts.
async fn forward_to_alias_node(
    node: Arc<crate::node::TenzroNode>,
    endpoint: tenzro_iroh::EndpointId,
    req: axum::extract::Request,
) -> axum::response::Response {
    let path = req.uri().path().to_string();
    let query = req
        .uri()
        .query()
        .map(|q| format!("?{q}"))
        .unwrap_or_default();
    forward_over_iroh(node, vec![endpoint], req, format!("{path}{query}")).await
}

/// Shared raw-HTTP relay over the `tenzro/http` ALPN: assemble the request
/// head, read the body, and try each candidate in order (the rest are
/// failover). Extracted so the site and node-alias paths cannot drift in how
/// they preserve caller headers or bound the body.
async fn forward_over_iroh(
    node: Arc<crate::node::TenzroNode>,
    remotes: Vec<tenzro_iroh::EndpointId>,
    req: axum::extract::Request,
    forwarded_target: String,
) -> axum::response::Response {
    use axum::response::IntoResponse;

    let method = req.method().clone();

    // Build the raw HTTP/1.1 head. Preserve the caller's headers (Host,
    // payment credential, if-none-match, etc.) so the serving node renders and
    // meters identically to a local serve.
    let mut head = format!("{} {} HTTP/1.1\r\n", method.as_str(), forwarded_target);
    for (name, value) in req.headers() {
        if let Ok(v) = value.to_str() {
            head.push_str(&format!("{}: {}\r\n", name.as_str(), v));
        }
    }
    head.push_str("\r\n");

    let body =
        match axum::body::to_bytes(req.into_body(), crate::ingress::MAX_FORWARD_BODY_BYTES).await {
            Ok(b) => b,
            Err(_) => {
                return (
                    axum::http::StatusCode::PAYLOAD_TOO_LARGE,
                    "request body too large to forward",
                )
                    .into_response();
            }
        };

    for serving_node in remotes {
        match crate::ingress::forward_request(&node, serving_node, head.as_bytes(), &body).await {
            Ok(raw) => match crate::ingress::raw_http_to_response(&raw) {
                Some(resp) => return resp,
                None => continue,
            },
            Err(e) => {
                tracing::debug!("ingress: forward to {serving_node} failed: {e}");
                continue;
            }
        }
    }

    (
        axum::http::StatusCode::BAD_GATEWAY,
        "no serving node reachable for host",
    )
        .into_response()
}

/// Paths that belong to the node's own control plane and must never be
/// shadowed by a site alias.
fn is_reserved_path(path: &str) -> bool {
    const RESERVED: &[&str] = &[
        "/sites/",
        "/facilitator/",
        "/wallet/",
        "/verify/",
        "/execution/",
        "/models/",
        "/v1/",
    ];
    const RESERVED_EXACT: &[&str] = &[
        "/metrics",
        "/health",
        "/ready",
        "/status",
        "/faucet",
        "/chat",
        "/providers",
    ];
    RESERVED.iter().any(|p| path.starts_with(p)) || RESERVED_EXACT.contains(&path)
}

pub struct WebServer {
    listen_addr: String,
    state: Arc<WebState>,
    /// When `Some`, paid routes are wrapped with the payment gate middleware.
    /// When `None`, all routes are unprotected (legacy behaviour).
    payment_gate: Option<PaymentGateSetup>,
    /// When `Some`, an additional public HTTPS listener is bound that terminates
    /// TLS in-process (on-demand ACME) and serves the same axum app. Wired by
    /// `main.rs` for `edge`-role nodes with an ACME contact configured.
    #[cfg(feature = "edge-tls")]
    edge_tls: Option<super::edge_tls::EdgeTlsSettings>,
}

impl WebServer {
    pub fn new(listen_addr: String) -> Self {
        Self {
            listen_addr,
            state: Arc::new(WebState::new()),
            payment_gate: None,
            #[cfg(feature = "edge-tls")]
            edge_tls: None,
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

    /// Enable the in-node public HTTPS edge. When set (and the web state carries
    /// a node handle), `start_with_shutdown` additionally binds an HTTPS listener
    /// on `settings.https_addr` that terminates TLS with on-demand ACME and
    /// serves the same axum router as the plain-HTTP listener.
    #[cfg(feature = "edge-tls")]
    pub fn with_edge_tls(mut self, settings: super::edge_tls::EdgeTlsSettings) -> Self {
        self.edge_tls = Some(settings);
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

        let mut app = self.build_app();

        // Operator admission gate. Mounted only when the web state carries a
        // node handle — a `WebServer` built without one (the unit tests) has
        // no gate to consult and nothing to protect. Inner relative to CORS
        // so a browser preflight, which cannot carry the service-key header,
        // is answered before the gate sees it.
        if let Some(node) = self.state.node.clone() {
            app = app.layer(axum::middleware::from_fn_with_state(
                node.admission_gate().clone(),
                |state, req, next| {
                    crate::admission::gate_request(
                        tenzro_auth::ServiceSurface::WebApi,
                        state,
                        req,
                        next,
                    )
                },
            ));
        }

        let app = app
            // Host-header alias rewrite: an aliased custom hostname is
            // rewritten to its `/sites/<site_id>` path before routing. Inner
            // relative to CORS so preflight is untouched.
            .layer(axum::middleware::from_fn_with_state(
                self.state.clone(),
                host_alias_rewrite,
            ))
            .layer(cors)
            // Concurrency limit: max 100 in-flight requests
            .layer(ConcurrencyLimitLayer::new(100))
            // Request body size limit: 2 MB
            .layer(RequestBodyLimitLayer::new(2 * 1024 * 1024))
            // Per-IP GCRA gate, outermost so an abusive source is
            // rejected with 429 before consuming a concurrency slot.
            // 10 req/s sustained per IP with a burst of 50 — the Web API
            // fronts inference chat and verification, both heavier per
            // request than plain RPC reads.
            .layer(axum::middleware::from_fn_with_state(
                crate::ip_rate_limit::IpRateLimiter::new(10, 50),
                crate::ip_rate_limit::ip_rate_limit,
            ));

        // Public HTTPS edge: an additional TLS listener that serves the SAME
        // fully-layered `app` (host→site routing, overlay forward and all). The
        // plain-HTTP listener on `web_addr` below stays for internal callers and
        // overlay forwarding.
        #[cfg(feature = "edge-tls")]
        if let (Some(settings), Some(node)) =
            (self.edge_tls.clone(), self.state.node.clone())
        {
            let edge_app = app.clone();
            let edge_shutdown = shutdown_rx.resubscribe();
            tokio::spawn(async move {
                if let Err(e) =
                    super::edge_tls::serve(edge_app, node, settings, edge_shutdown).await
                {
                    tracing::error!("Edge HTTPS server error: {e}");
                }
            });
        }

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
        // `api.tenzro.xyz` is itself the `/api` namespace, so doubling
        // the prefix on routes would produce `api.tenzro.xyz/api/...`.
        // `/metrics` stays at root to comply with the Prometheus scraper
        // convention.
        //
        // Paid routes (gated by HTTP 402 middleware) are matched against the
        // full mounted path (e.g. `/chat`). Config must list
        // `payments.paid_routes = ["/chat", "/execution/resolve", ...]`.
        let mut open = Router::new()
            .route("/verify/did-envelope", post(handlers::verify_did_envelope))
            .route("/verify/zk-proof", post(handlers::verify_zk_proof))
            .route(
                "/verify/tee-attestation",
                post(handlers::verify_tee_attestation),
            )
            .route("/verify/transaction", post(handlers::verify_transaction))
            .route("/verify/settlement", post(handlers::verify_settlement))
            .route("/verify/inference", post(handlers::verify_inference))
            // W3C DID resolution well-known path. Open, and outside the
            // service-key gate would be wrong — but it is inside it, because
            // a gated node's operator has said who may talk to it at all, and
            // addressing information is a service like any other. A node that
            // wants to be discoverable simply does not gate.
            .route("/.well-known/did.json", get(handlers::node_did_document))
            .route("/verify/health", get(handlers::health))
            .route("/health", get(handlers::health))
            .route("/verify/ready", get(handlers::ready))
            .route("/ready", get(handlers::ready))
            .route("/status", get(handlers::status))
            // x402 Bazaar resource discovery — public, ungated. Buyers
            // browse a seller's paid resource listings, narrowed by
            // scheme/network/asset/sellerDid/tags query params.
            .route("/discovery/resources", get(handlers::discover_resources))
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
            .route(
                "/.well-known/http-message-signatures-directory",
                get(handlers::web_bot_auth_directory),
            )
            .route("/.well-known/jwks.json", get(handlers::jwks))
            .route("/.well-known/jwks.json/:keyid", get(handlers::jwks_get))
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
            // Enrol a passkey credential. Assertions are checked against the
            // key the authenticator registered here; nothing is derived from
            // the credential id, which is public.
            .route(
                "/wallet/passkey/register",
                post(wallet_share::passkey_register_handler),
            )
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
            // Passkey-quorum wallet provisioning. A Tenzro-aware wallet mints
            // a fresh TDIP identity whose signing key is split 2-of-2 between
            // the device passkey and this node's TEE leg — no seed phrase.
            // Consent for the new device is asserted by the WebAuthn
            // attestation in `finalize`, so these stay on the open router.
            .route("/wallet/new/start", post(wallet_new::start_handler))
            .route("/wallet/new/finalize", post(wallet_new::finalize_handler))
            .route("/wallet/new/confirm", post(wallet_new::confirm_handler))
            .route("/wallet/new/cancel", post(wallet_new::cancel_handler))
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
            // Static site serving — content-addressed blobs behind site
            // manifests. Per-site x402 gating happens inside the handler
            // (price is per-manifest, not per-route), so both routes stay
            // on the open router.
            // On-demand-TLS ask endpoint. Caddy calls this once per unseen
            // hostname during the TLS handshake; it returns 200 only for a
            // verified custom domain, so a certificate is issued only for a
            // domain whose owner has proved control. The static `tls-ask`
            // segment is matched ahead of the `:site_id` param route. It runs
            // no network I/O — a fast in-memory lookup on the handshake path.
            .route("/sites/tls-ask", get(crate::web::sites::tls_ask))
            .route("/sites/:site_id", get(crate::web::sites::serve_site_index))
            .route(
                "/sites/:site_id/*path",
                get(crate::web::sites::serve_site_asset),
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

        // Mount the Visa TAP recognition facilitator when the node has a
        // verifier bound. The facilitator carries its own state
        // (`TapFacilitatorState`), so it is built with its own `.with_state`
        // and merged into the fully-stated `open` router. Routes resolve as
        // `/facilitator/visa-tap/verify` and `/facilitator/visa-tap/supported`
        // — no `/api/` prefix (the hostname is the namespace).
        #[cfg(feature = "visa-tap")]
        let open = {
            let verifier = self
                .state
                .node
                .as_ref()
                .and_then(|n| n.visa_tap_verifier().cloned());
            if let Some(verifier) = verifier {
                let tap_state =
                    tenzro_payments::visa_tap::TapFacilitatorState::new(verifier, "api.tenzro.xyz");
                let tap_router = tenzro_payments::visa_tap::tap_facilitator_router(tap_state);
                open.nest("/facilitator/visa-tap", tap_router)
            } else {
                open
            }
        };

        // Mount the x402 facilitator (verify/settle) when the node has one
        // bound. Routes resolve as `/facilitator/x402/verify`,
        // `/facilitator/x402/settle`, `/facilitator/x402/supported`.
        let open = {
            let facilitator = self
                .state
                .node
                .as_ref()
                .and_then(|n| n.x402_facilitator().cloned());
            if let Some(facilitator) = facilitator {
                let x402_state = tenzro_payments::x402::FacilitatorServerState::new(facilitator);
                let x402_router = tenzro_payments::x402::facilitator_router(x402_state);
                open.nest("/facilitator/x402", x402_router)
            } else {
                open
            }
        };

        // If anything is gated, attach the middleware layer to the gated
        // sub-router and merge it back in. Each branch ends up with the
        // same final type (`Router`), which is what axum's merge expects.
        if any_gated {
            // Safe: any_gated implies payment_gate.is_some()
            let gate = self
                .payment_gate
                .as_ref()
                .expect("payment_gate set when any_gated");
            let gated_with_state =
                gated
                    .with_state(self.state.clone())
                    .layer(axum::middleware::from_fn_with_state(
                        gate.middleware.clone(),
                        payment_gate_handler,
                    ));
            open.merge(gated_with_state)
        } else {
            open
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chrono::Utc;
    use std::collections::HashMap;
    use tenzro_payments::challenge_store::ChallengeStore;
    use tenzro_payments::gateway::TenzroPaymentGateway;
    use tenzro_payments::traits::PaymentProtocol;
    use tenzro_payments::types::{
        PaymentChallenge, PaymentCredential, PaymentReceipt, PaymentVerification,
    };
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
        let gateway = Arc::new(TenzroPaymentGateway::new().with_challenge_store(store.clone()));
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
            .uri("/chat")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        assert_eq!(response.headers().get("Payment-Required").unwrap(), "true");
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
    /// `Authorization: DPoP <jwt>` header. This is the central
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
