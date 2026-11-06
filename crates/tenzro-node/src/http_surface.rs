//! Request-level hygiene shared by the node's HTTP listeners: who the client
//! is, which `Host` names the node answers to, which browser origins may call
//! it, and how large a JSON-RPC batch may be.
//!
//! # Client address
//!
//! `X-Forwarded-For` is a header anyone can send. It is believed only when the
//! TCP peer is a proxy the operator listed in
//! [`HttpSurfaceConfig::trusted_proxies`], and then only the entries that proxy
//! chain appended: the address is the rightmost entry that is not itself a
//! trusted proxy. Without a trusted proxy the TCP peer is the client, loopback
//! included — a same-host bridge that relays public traffic onto the loopback
//! port would otherwise make every relayed caller look local.
//!
//! # Host
//!
//! A browser on a page at `evil.example` can have `evil.example` resolve to
//! `127.0.0.1` and then talk to the node's loopback listener as a same-origin
//! request. The request still carries `Host: evil.example`, so each listener
//! answers only to IP literals, `localhost`, the names the operator configured,
//! and (on the web listener) the hosts of registered sites.

use std::net::{IpAddr, SocketAddr};

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use tower_http::cors::{AllowHeaders, AllowMethods, AllowOrigin, CorsLayer};

use crate::egress_guard::Cidr;

/// Default cap on the number of calls in one JSON-RPC batch.
pub const DEFAULT_MAX_BATCH: usize = 64;

/// Operator configuration for the HTTP listeners.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HttpSurfaceConfig {
    /// Addresses or CIDR ranges of reverse proxies whose `X-Forwarded-For`
    /// is believed. Empty by default: no forwarding header is trusted.
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Host names the listeners answer to besides IP literals and
    /// `localhost`. An entry `*.example.com` admits every subdomain of
    /// `example.com` but not `example.com` itself. The advertised RPC host
    /// and the public node suffix are added automatically.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    /// Largest number of calls accepted in one JSON-RPC batch.
    #[serde(default = "default_max_batch")]
    pub max_batch: usize,
}

fn default_max_batch() -> usize {
    DEFAULT_MAX_BATCH
}

impl Default for HttpSurfaceConfig {
    fn default() -> Self {
        Self {
            trusted_proxies: Vec::new(),
            allowed_hosts: Vec::new(),
            max_batch: DEFAULT_MAX_BATCH,
        }
    }
}

/// The resolved policy, built once at startup.
#[derive(Debug, Clone)]
pub struct SurfacePolicy {
    trusted: Vec<Cidr>,
    hosts: Vec<String>,
    max_batch: usize,
    rp_id: String,
}

/// The host part of a `Host` header or URL authority, lower-cased, without
/// port or IPv6 brackets.
fn host_of(authority: &str) -> String {
    let a = authority.trim().trim_end_matches('.');
    let host = if let Some(rest) = a.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else if a.matches(':').count() > 1 {
        // A bare IPv6 literal has no port.
        a
    } else {
        a.split(':').next().unwrap_or("")
    };
    host.to_ascii_lowercase()
}

impl SurfacePolicy {
    /// Build from the node configuration. `rp_id_override` is the operator's
    /// WebAuthn RP ID, if set; see [`webauthn_rp_id`].
    pub fn from_config(
        config: &crate::config::NodeConfig,
        rp_id_override: Option<&str>,
    ) -> Result<Self, String> {
        let rp_id = webauthn_rp_id(rp_id_override);
        let surface = &config.http_surface;
        let trusted = surface
            .trusted_proxies
            .iter()
            .map(|s| Cidr::parse(s).map_err(|e| format!("trusted_proxies: {e}")))
            .collect::<Result<Vec<_>, _>>()?;
        let mut hosts: Vec<String> = surface
            .allowed_hosts
            .iter()
            .map(|h| h.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect();
        if let Some(advertised) = config.external_rpc_addr.as_deref() {
            let authority = advertised
                .split("://")
                .last()
                .unwrap_or(advertised)
                .split('/')
                .next()
                .unwrap_or("");
            let h = host_of(authority);
            if !h.is_empty() {
                hosts.push(h);
            }
        }
        Ok(Self {
            trusted,
            hosts,
            max_batch: surface.max_batch.max(1),
            rp_id,
        })
    }

    /// The WebAuthn relying-party ID passkey assertions are verified against.
    pub fn webauthn_rp_id(&self) -> &str {
        &self.rp_id
    }

    /// Largest accepted JSON-RPC batch.
    pub fn max_batch(&self) -> usize {
        self.max_batch
    }

    fn is_trusted_proxy(&self, ip: IpAddr) -> bool {
        self.trusted.iter().any(|c| c.contains(ip))
    }

    /// The client address for rate limiting and per-client accounting.
    pub fn client_ip(&self, peer: SocketAddr, headers: &HeaderMap) -> IpAddr {
        let peer_ip = peer.ip().to_canonical();
        if !self.is_trusted_proxy(peer_ip) {
            return peer_ip;
        }
        let chain: Vec<IpAddr> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .filter_map(|s| s.trim().parse::<IpAddr>().ok())
            .map(|ip| ip.to_canonical())
            .collect();
        chain
            .into_iter()
            .rev()
            .find(|ip| !self.is_trusted_proxy(*ip))
            .unwrap_or(peer_ip)
    }

    /// The `X-Forwarded-For` chain, as sent, when `peer` is a trusted proxy;
    /// `None` otherwise, since anyone else can write the header.
    pub fn forwarded_chain(&self, peer: SocketAddr, headers: &HeaderMap) -> Option<Vec<IpAddr>> {
        if !self.is_trusted_proxy(peer.ip().to_canonical()) {
            return None;
        }
        let chain: Vec<IpAddr> = headers
            .get_all("x-forwarded-for")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(','))
            .filter_map(|s| s.trim().parse::<IpAddr>().ok())
            .map(|ip| ip.to_canonical())
            .collect();
        (!chain.is_empty()).then_some(chain)
    }

    /// Whether a request carrying this `Host` header is for this node's own
    /// control plane.
    pub fn host_allowed(&self, host_header: &str) -> bool {
        let host = host_of(host_header);
        if host.is_empty() {
            return false;
        }
        if host.parse::<IpAddr>().is_ok() || host == "localhost" {
            return true;
        }
        self.hosts
            .iter()
            .any(|pattern| match pattern.strip_prefix("*.") {
                Some(suffix) => {
                    host.len() > suffix.len() + 1 && host.ends_with(&format!(".{suffix}"))
                }
                None => *pattern == host,
            })
    }
}

/// The WebAuthn relying-party ID this node verifies passkey assertions
/// against: `TENZRO_WEBAUTHN_RP_ID` when set, otherwise the network's
/// [`DEFAULT_WEBAUTHN_RP_ID`](crate::config::DEFAULT_WEBAUTHN_RP_ID).
///
/// Every origin at or under the RP ID can ask a browser for an assertion with
/// the user's passkey, and sites under the app domain are served by whoever
/// deployed them, so the RP ID must not cover that namespace.
pub fn webauthn_rp_id(configured: Option<&str>) -> String {
    configured
        .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| crate::config::DEFAULT_WEBAUTHN_RP_ID.to_string())
}

/// CORS for a listener: exactly the configured origins, or none.
///
/// With no origins configured a browser page on another origin cannot read
/// responses from the node at all; the node's own pages and non-browser
/// clients are unaffected.
pub fn cors_layer(origins: &[String]) -> CorsLayer {
    let origins: Vec<HeaderValue> = origins.iter().filter_map(|o| o.parse().ok()).collect();
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods(AllowMethods::mirror_request())
        .allow_headers(AllowHeaders::mirror_request())
}

/// Body ceilings for the JSON-RPC root: `(node, ordinary, operator)`.
pub type RpcBodyCeiling = (std::sync::Arc<crate::node::TenzroNode>, usize, usize);

/// Middleware for the JSON-RPC root: a request is held to the ordinary JSON
/// ceiling unless its caller administers this node, in which case the
/// larger ceiling applies. The large ceiling exists for operators sending
/// media inputs as base64 inside a JSON-RPC call, and an anonymous caller has
/// no call that needs tens of megabytes buffered on its behalf.
pub async fn rpc_body_ceiling(
    State((node, ordinary, operator)): State<RpcBodyCeiling>,
    request: Request,
    next: Next,
) -> Response {
    let privileged =
        crate::rpc::current_caller_did().is_some_and(|did| node.access().is_admin(&node, &did));
    let limit = if privileged { operator } else { ordinary };
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<u64>().ok());
    if declared.is_some_and(|len| len > limit as u64) {
        return (StatusCode::PAYLOAD_TOO_LARGE, "request body too large").into_response();
    }
    let (parts, body) = request.into_parts();
    let body = axum::body::Body::new(http_body_util::Limited::new(body, limit));
    next.run(Request::from_parts(parts, body)).await
}

fn misdirected() -> Response {
    (
        StatusCode::MISDIRECTED_REQUEST,
        "this node does not answer to that host name",
    )
        .into_response()
}

/// Middleware: refuse a request whose `Host` is not one of the node's own.
pub async fn require_known_host(
    State(policy): State<std::sync::Arc<SurfacePolicy>>,
    request: Request,
    next: Next,
) -> Response {
    let known = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|h| policy.host_allowed(h));
    if known {
        next.run(request).await
    } else {
        misdirected()
    }
}

/// Middleware for the web listener: only the node's own names reach it. A
/// name the node does not own is refused, so a hostname someone else
/// controls cannot be pointed at a loopback address and used from a browser
/// as a same-origin way into the node's routes.
pub async fn require_known_web_host(
    State(node): State<std::sync::Arc<crate::node::TenzroNode>>,
    request: Request,
    next: Next,
) -> Response {
    let Some(host) = request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(host_of)
    else {
        return misdirected();
    };
    if node.http_surface().host_allowed(&host) {
        next.run(request).await
    } else {
        misdirected()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(trusted: &[&str], hosts: &[&str]) -> SurfacePolicy {
        let config = crate::config::NodeConfig {
            http_surface: HttpSurfaceConfig {
                trusted_proxies: trusted.iter().map(|s| s.to_string()).collect(),
                allowed_hosts: hosts.iter().map(|s| s.to_string()).collect(),
                max_batch: 8,
            },
            external_rpc_addr: Some("https://rpc.example.org:8545/".into()),
            ..Default::default()
        };
        SurfacePolicy::from_config(&config, None).unwrap()
    }

    fn sock(ip: &str) -> SocketAddr {
        SocketAddr::new(ip.parse().unwrap(), 4000)
    }

    fn xff(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", v.parse().unwrap());
        h
    }

    #[test]
    fn forwarding_header_is_ignored_from_an_untrusted_peer() {
        let p = policy(&[], &[]);
        assert_eq!(
            p.client_ip(sock("203.0.113.9"), &xff("1.2.3.4")),
            "203.0.113.9".parse::<IpAddr>().unwrap()
        );
        // Loopback is not a trusted proxy unless configured, and is not exempt.
        assert_eq!(
            p.client_ip(sock("127.0.0.1"), &xff("1.2.3.4")),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn a_trusted_proxy_chain_yields_the_first_untrusted_hop_from_the_right() {
        let p = policy(&["127.0.0.1", "10.0.0.0/8"], &[]);
        // Client-supplied entry on the left is never reached.
        assert_eq!(
            p.client_ip(sock("127.0.0.1"), &xff("9.9.9.9, 198.51.100.7, 10.1.1.1")),
            "198.51.100.7".parse::<IpAddr>().unwrap()
        );
        // A trusted proxy with no header is itself the client.
        assert_eq!(
            p.client_ip(sock("127.0.0.1"), &HeaderMap::new()),
            "127.0.0.1".parse::<IpAddr>().unwrap()
        );
    }

    /// The startup path: a default node, with or without
    /// `TENZRO_WEBAUTHN_RP_ID=tenzro.com`, builds its surface policy.
    #[test]
    fn a_default_node_starts_with_the_network_rp_id() {
        let config = crate::config::NodeConfig::default();
        for rp in [None, Some("tenzro.com")] {
            let policy = SurfacePolicy::from_config(&config, rp).expect("starts");
            assert_eq!(policy.webauthn_rp_id(), "tenzro.com");
        }
    }

    #[test]
    fn host_names_outside_the_node_are_refused() {
        let p = policy(&[], &["*.apps.example.com", "node.example.com"]);
        assert!(p.host_allowed("127.0.0.1:8545"));
        assert!(p.host_allowed("[::1]:8545"));
        assert!(p.host_allowed("localhost:8080"));
        assert!(p.host_allowed("rpc.example.org"));
        assert!(p.host_allowed("node.example.com"));
        assert!(p.host_allowed("shop.apps.example.com"));
        assert!(!p.host_allowed("apps.example.com"));
        assert!(!p.host_allowed("evil.example"));
        assert!(!p.host_allowed("evilapps.example.com"));
        assert!(!p.host_allowed(""));
    }
}
