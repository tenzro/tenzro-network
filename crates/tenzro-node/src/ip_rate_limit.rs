//! Per-IP rate limiting for the public JSON-RPC and Web API servers.
//!
//! Both servers face the open internet (`rpc.tenzro.xyz`,
//! `api.tenzro.xyz`). The existing `ConcurrencyLimitLayer` +
//! `RequestBodyLimitLayer` bound aggregate load but let a single remote
//! address consume the entire budget. This module adds a GCRA gate keyed
//! on the client IP so one abusive source is throttled to its own budget
//! while everyone else keeps normal service.
//!
//! Client-IP resolution is proxy-aware without being spoofable: when the
//! direct TCP peer is loopback, the request came through a reverse proxy
//! on the same host (Caddy on the public fleet) and the *last*
//! `X-Forwarded-For` entry — the one appended by our own proxy — is
//! authoritative. Earlier entries are client-supplied and ignored. When
//! the direct peer is non-loopback, the socket address is used and
//! `X-Forwarded-For` is ignored entirely. Loopback traffic with no
//! forwarding header (local CLI, health probes, same-host services) is
//! exempt.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::bridge_analytics::{GcraConfig, GcraDecision, GcraLimiter};

/// When the per-IP map grows past this many tracked addresses, fully
/// replenished entries are evicted before admitting the next request.
/// Bounds memory under source-address spray.
const EVICT_THRESHOLD: usize = 100_000;

/// Per-IP GCRA gate shared across all connections of one HTTP server.
pub struct IpRateLimiter {
    limiter: GcraLimiter,
}

impl IpRateLimiter {
    /// `rate_per_sec` sustained requests per second per IP, with `burst`
    /// requests of extra credit for a fresh or long-idle address.
    pub fn new(rate_per_sec: u32, burst: u32) -> Arc<Self> {
        let period = Duration::from_micros(1_000_000 / u64::from(rate_per_sec.max(1)));
        Arc::new(Self {
            limiter: GcraLimiter::new(GcraConfig { period, burst }),
        })
    }

    fn check(&self, ip: IpAddr) -> GcraDecision {
        if self.limiter.active_keys() > EVICT_THRESHOLD {
            self.limiter.evict_replenished();
        }
        self.limiter.check(&ip.to_string())
    }
}

/// Resolve the address to rate-limit on. `None` means exempt (trusted
/// same-host traffic with no proxy header).
fn client_ip(peer: SocketAddr, headers: &HeaderMap) -> Option<IpAddr> {
    let peer_ip = peer.ip();
    if peer_ip.is_loopback() {
        headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|s| s.trim().parse::<IpAddr>().ok())
    } else {
        Some(peer_ip)
    }
}

/// axum middleware: admit or reject the request against the per-IP gate.
/// Rejections return HTTP 429 with a `Retry-After` header.
pub async fn ip_rate_limit(
    State(limiter): State<Arc<IpRateLimiter>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let Some(ip) = client_ip(peer, request.headers()) else {
        return next.run(request).await;
    };
    match limiter.check(ip) {
        GcraDecision::Admit { .. } => next.run(request).await,
        GcraDecision::Deny { retry_after } => {
            let secs = retry_after.as_secs().max(1);
            (
                StatusCode::TOO_MANY_REQUESTS,
                [("retry-after", secs.to_string())],
                axum::Json(serde_json::json!({
                    "error": "rate_limited",
                    "message": format!(
                        "per-IP request rate exceeded; retry after {}s",
                        secs
                    ),
                })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sock(ip: &str) -> SocketAddr {
        format!("{}:12345", ip).parse().unwrap()
    }

    #[test]
    fn direct_peer_ip_is_used_and_xff_ignored() {
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        assert_eq!(
            client_ip(sock("203.0.113.9"), &headers),
            Some("203.0.113.9".parse().unwrap())
        );
    }

    #[test]
    fn loopback_peer_trusts_last_xff_entry() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "10.0.0.1, 198.51.100.7".parse().unwrap(),
        );
        assert_eq!(
            client_ip(sock("127.0.0.1"), &headers),
            Some("198.51.100.7".parse().unwrap())
        );
    }

    #[test]
    fn loopback_without_xff_is_exempt() {
        assert_eq!(client_ip(sock("127.0.0.1"), &HeaderMap::new()), None);
    }

    #[test]
    fn gate_denies_after_burst_exhausted() {
        let limiter = IpRateLimiter::new(1, 3);
        let ip: IpAddr = "198.51.100.7".parse().unwrap();
        // burst=3 grants 3 immediate admits plus the steady-rate cell.
        let mut admitted = 0;
        for _ in 0..8 {
            if matches!(limiter.check(ip), GcraDecision::Admit { .. }) {
                admitted += 1;
            }
        }
        assert!((3..8).contains(&admitted));
        assert!(matches!(limiter.check(ip), GcraDecision::Deny { .. }));
        // A different IP is unaffected.
        let other: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(matches!(limiter.check(other), GcraDecision::Admit { .. }));
    }
}
