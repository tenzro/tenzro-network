//! In-node public HTTPS edge.
//!
//! An `edge`-role node terminates public TLS itself (in-process `rustls`) and
//! mints Let's Encrypt certificates on demand via the ACME **TLS-ALPN-01**
//! challenge — no external Caddy/nginx and no HTTP-01 port coordination. The
//! same axum [`Router`](axum::Router) that serves the plain-HTTP Web API is
//! handed the decrypted requests, so host→site routing (`host_alias_rewrite`),
//! overlay forwarding (`forward_over_iroh`) and the site registry are all reused
//! unchanged; this module is purely the TLS front door.
//!
//! ## Why one `AcmeState` per hostname
//!
//! rustls-acme's high-level API manages a *fixed* set of domains as a single
//! multi-SAN certificate. Hosted sites are dynamic — new `*.<app_domain>`
//! subdomains and freshly DNS-verified custom domains appear at runtime — so a
//! boot-time domain list cannot express them. Instead [`OnDemandResolver`] keeps
//! one rustls-acme `AcmeState` **per hostname**, created lazily on the first
//! allowed TLS handshake for an unseen SNI. Each per-host
//! `ResolvesServerCertAcme` transparently serves both the TLS-ALPN-01 challenge
//! and, once issued, the live certificate for its own name.
//!
//! ## Issuance is gated — never issue for arbitrary hostnames
//!
//! Every handshake is filtered through [`sni_allowed`] *before* any ACME order is
//! created. That is the same decision `/sites/tls-ask` makes (it is the in-node
//! answer to Caddy's on-demand-TLS "ask"), extended with the operator-owned
//! `app_domain` rule. A disallowed SNI never spawns an order, so a flood of bogus
//! hostnames can never exhaust Let's Encrypt rate limits.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use futures::StreamExt;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use rustls_acme::acme::ACME_TLS_ALPN_NAME;
use rustls_acme::caches::DirCache;
use rustls_acme::{AcmeConfig, ResolvesServerCertAcme};

use crate::node::TenzroNode;

/// Settings the node hands the edge when it holds the `edge` role (or has
/// `hosting.edge_enabled = true`) and an ACME contact address is configured.
///
/// Built in `main.rs` from `NodeConfig::hosting`; kept independent of
/// [`TenzroNode`] internals so [`crate::web::WebServer`] can carry it without a
/// node handle.
#[derive(Clone)]
pub struct EdgeTlsSettings {
    /// Bind address for the HTTPS listener, e.g. `0.0.0.0:443`.
    pub https_addr: String,
    /// ACME account contact email (without the `mailto:` prefix).
    pub contact_email: String,
    /// Directory for the certificate + ACME account cache.
    pub cache_dir: PathBuf,
    /// Use the Let's Encrypt staging directory (untrusted certs, high limits).
    pub staging: bool,
    /// The operator's app domain, e.g. `apps.tenzro.xyz`. Subdomains of it are
    /// operator-owned and always allowed to obtain a certificate.
    pub app_domain: Option<String>,
}

/// Normalize a hostname for the gate: drop any `:port`, trim a trailing dot,
/// lowercase. Mirrors what `SiteRegistry::is_domain_verified` does internally so
/// the two decisions agree on the same key.
fn normalize(host: &str) -> String {
    let h = host.split(':').next().unwrap_or(host);
    h.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// The single "may this node obtain/serve a certificate for this SNI hostname?"
/// decision — identical to what `/sites/tls-ask` answers for Caddy, extended with
/// the operator-owned `app_domain` rule:
///
/// * a subdomain of (or exactly) the operator's `app_domain` is operator-owned →
///   allowed; and
/// * any other (custom) domain must carry a verified DNS-TXT ownership claim
///   (`SiteRegistry::is_domain_verified`, the exact check tls-ask uses).
pub fn sni_allowed(node: &TenzroNode, app_domain: Option<&str>, sni: &str) -> bool {
    let host = normalize(sni);
    if host.is_empty() {
        return false;
    }
    if let Some(app_domain) = app_domain {
        let app_domain = normalize(app_domain);
        if !app_domain.is_empty()
            && (host == app_domain || host.ends_with(&format!(".{app_domain}")))
        {
            return true;
        }
    }
    node.site_registry().is_domain_verified(&host)
}

/// A rustls certificate resolver that mints Let's Encrypt certificates on demand,
/// one per SNI hostname, gated by [`sni_allowed`].
struct OnDemandResolver {
    node: Arc<TenzroNode>,
    app_domain: Option<String>,
    contact: String,
    cache_dir: PathBuf,
    staging: bool,
    /// Handle to the runtime the edge runs on, used to spawn per-host ACME
    /// drivers from the synchronous `resolve` callback.
    rt: tokio::runtime::Handle,
    /// SNI hostname → its per-host ACME resolver. Populated lazily; the resolver
    /// exists immediately (returning `None` until its first cert lands) and the
    /// order runs in the background.
    per_host: Mutex<HashMap<String, Arc<ResolvesServerCertAcme>>>,
}

impl std::fmt::Debug for OnDemandResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnDemandResolver").finish_non_exhaustive()
    }
}

impl OnDemandResolver {
    /// Return the per-host ACME resolver for `host`, spawning its order/renewal
    /// driver the first time the host is seen. Caller must have already checked
    /// [`sni_allowed`]. Insertion happens under the lock before the driver is
    /// spawned, so concurrent handshakes for the same host share one order.
    fn ensure(&self, host: &str) -> Arc<ResolvesServerCertAcme> {
        let mut per_host = self.per_host.lock().unwrap();
        if let Some(resolver) = per_host.get(host) {
            return resolver.clone();
        }

        // `production = !staging`.
        let mut state = AcmeConfig::new([host])
            .contact_push(format!("mailto:{}", self.contact))
            .cache(DirCache::new(self.cache_dir.clone()))
            .directory_lets_encrypt(!self.staging)
            .state();
        let resolver = state.resolver();
        per_host.insert(host.to_string(), resolver.clone());
        drop(per_host);

        let host_owned = host.to_string();
        self.rt.spawn(async move {
            loop {
                match state.next().await {
                    Some(Ok(ok)) => {
                        tracing::info!(host = %host_owned, event = ?ok, "edge ACME")
                    }
                    Some(Err(err)) => {
                        tracing::warn!(host = %host_owned, error = %err, "edge ACME error")
                    }
                    None => break,
                }
            }
        });
        resolver
    }
}

impl ResolvesServerCert for OnDemandResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name()?;
        let host = normalize(sni);
        if !sni_allowed(&self.node, self.app_domain.as_deref(), &host) {
            tracing::warn!(
                sni = %host,
                "edge TLS: refusing certificate for unowned/unverified host"
            );
            return None;
        }
        // The per-host `ResolvesServerCertAcme` answers both branches: the
        // TLS-ALPN-01 validation handshake (via the negotiated `acme-tls/1`
        // protocol) and, once issued, the live certificate.
        self.ensure(&host).resolve(client_hello)
    }
}

/// Bind the public HTTPS edge on `settings.https_addr` and serve `app` over TLS,
/// terminating certificates in-process with on-demand ACME issuance. Runs until
/// `shutdown_rx` fires, then drains in-flight connections for up to 5s.
pub async fn serve(
    app: axum::Router,
    node: Arc<TenzroNode>,
    settings: EdgeTlsSettings,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) -> std::io::Result<()> {
    let addr: SocketAddr = settings.https_addr.parse().map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("invalid hosting.https_addr `{}`: {e}", settings.https_addr),
        )
    })?;

    if let Err(e) = std::fs::create_dir_all(&settings.cache_dir) {
        tracing::warn!(
            dir = %settings.cache_dir.display(),
            error = %e,
            "edge TLS: could not create ACME cache dir; issuance may re-order on every restart"
        );
    }

    let resolver = Arc::new(OnDemandResolver {
        node,
        app_domain: settings.app_domain.clone(),
        contact: settings.contact_email.clone(),
        cache_dir: settings.cache_dir.clone(),
        staging: settings.staging,
        rt: tokio::runtime::Handle::current(),
        per_host: Mutex::new(HashMap::new()),
    });

    // aws-lc-rs is the workspace-wide rustls provider (PQ-hybrid named group);
    // build the server config with it explicitly so the edge does not depend on
    // a process-wide default provider having been installed.
    let mut server_config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
            .with_safe_default_protocol_versions()
            .map_err(|e| std::io::Error::other(format!("edge TLS rustls config: {e}")))?
            .with_no_client_auth()
            .with_cert_resolver(resolver);
    // Advertise HTTP/2 and HTTP/1.1 for real traffic, plus `acme-tls/1` so an
    // incoming TLS-ALPN-01 validation handshake negotiates the challenge protocol
    // and the per-host resolver presents the challenge certificate.
    server_config.alpn_protocols = vec![
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
        ACME_TLS_ALPN_NAME.to_vec(),
    ];

    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(server_config));

    let handle = axum_server::Handle::new();
    {
        let handle = handle.clone();
        tokio::spawn(async move {
            let _ = shutdown_rx.recv().await;
            tracing::info!("Edge HTTPS server shutting down gracefully");
            handle.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
        });
    }

    tracing::info!(
        addr = %addr,
        staging = settings.staging,
        "Edge HTTPS listening (in-node rustls + on-demand ACME / Let's Encrypt)"
    );

    axum_server::bind_rustls(addr, rustls_config)
        .handle(handle)
        .serve(app.into_make_service_with_connect_info::<SocketAddr>())
        .await
}
