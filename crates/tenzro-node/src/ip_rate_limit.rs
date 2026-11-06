//! Per-IP rate limiting for the public JSON-RPC and Web API servers.
//!
//! Both servers face the open internet (`rpc.tenzro.com`,
//! `api.tenzro.com`). The existing `ConcurrencyLimitLayer` +
//! `RequestBodyLimitLayer` bound aggregate load but let a single remote
//! address consume the entire budget. This module adds a GCRA gate keyed
//! on the client IP so one abusive source is throttled to its own budget
//! while everyone else keeps normal service.
//!
//! The client IP comes from [`crate::http_surface::SurfacePolicy::client_ip`]:
//! `X-Forwarded-For` counts only when the TCP peer is a proxy the operator
//! listed as trusted, and no address is exempt. Loopback used to be, and a
//! same-host bridge relaying public traffic onto the loopback port then made
//! every relayed caller unlimited.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::gcra::{GcraConfig, GcraDecision, GcraLimiter};
use crate::http_surface::SurfacePolicy;

/// When the per-IP map grows past this many tracked addresses, fully
/// replenished entries are evicted before admitting the next request.
/// Bounds memory under source-address spray.
const EVICT_THRESHOLD: usize = 100_000;

/// JSON-RPC error code of a call refused for its address's request rate.
pub const RPC_ERR_RATE_LIMITED: i32 = -32005;

/// How a server answers a request it refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// A JSON-RPC 2.0 response whose `error` is a JSON-RPC error object.
    JsonRpc,
    /// A plain JSON body `{ "error": "rate_limited", "message": ... }`.
    Http,
}

/// The per-address limits in force: the request floor every caller gets
/// before anything else is known about it, and how many transaction
/// submissions per second beyond that floor are checked against their
/// sender's own admission quota (verified or delegated lane) instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressLimits {
    pub rate_per_sec: u32,
    pub burst: u32,
    pub identity_checks_per_sec: u32,
}

/// Where a governed limiter reads its limits from.
pub type LimitsSource = Arc<dyn Fn() -> AddressLimits + Send + Sync>;

/// How often a governed limiter reads its limits again.
const LIMITS_REFRESH: Duration = Duration::from_secs(10);

/// Largest body read from a request past the address floor: a transaction
/// submission fits well within it.
const MAX_SUBMISSION_BYTES: usize = 256 * 1024;

/// Methods that submit a signed transaction and so name a sender whose own
/// quota can stand in for the address floor.
const SUBMISSION_METHODS: [&str; 2] = ["tenzro_sendRawTransaction", "eth_sendRawTransaction"];

tokio::task_local! {
    static OVER_ADDRESS_FLOOR: bool;
}

/// Whether the request being handled arrived after its address spent its
/// floor. Its transaction is then admitted only from a sender in the
/// verified or delegated lane.
pub fn over_address_floor() -> bool {
    OVER_ADDRESS_FLOOR.try_with(|v| *v).unwrap_or(false)
}

struct Gates {
    limits: AddressLimits,
    floor: GcraLimiter,
    identity_checks: GcraLimiter,
    read_at: std::time::Instant,
}

fn gcra(rate_per_sec: u32, burst: u32) -> GcraLimiter {
    let period = Duration::from_micros(1_000_000 / u64::from(rate_per_sec.max(1)));
    GcraLimiter::new(GcraConfig { period, burst })
}

impl Gates {
    fn new(limits: AddressLimits) -> Self {
        Self {
            limits,
            floor: gcra(limits.rate_per_sec, limits.burst),
            identity_checks: gcra(
                limits.identity_checks_per_sec,
                limits.identity_checks_per_sec,
            ),
            read_at: std::time::Instant::now(),
        }
    }
}

/// Per-address GCRA gate shared across all connections of one HTTP server.
pub struct IpRateLimiter {
    gates: parking_lot::RwLock<Gates>,
    source: Option<LimitsSource>,
    surface: Arc<SurfacePolicy>,
    answer: Answer,
}

impl IpRateLimiter {
    /// `rate_per_sec` sustained requests per second per IP, with `burst`
    /// requests of extra credit for a fresh or long-idle address. `surface`
    /// decides which address a request is counted against, and `answer` the
    /// shape of a refusal. Nothing passes the floor.
    pub fn new(
        rate_per_sec: u32,
        burst: u32,
        surface: Arc<SurfacePolicy>,
        answer: Answer,
    ) -> Arc<Self> {
        Arc::new(Self {
            gates: parking_lot::RwLock::new(Gates::new(AddressLimits {
                rate_per_sec,
                burst,
                identity_checks_per_sec: 0,
            })),
            source: None,
            surface,
            answer,
        })
    }

    /// A gate whose limits are read from `source` (the governed values) and
    /// read again every [`LIMITS_REFRESH`].
    pub fn governed(
        source: LimitsSource,
        surface: Arc<SurfacePolicy>,
        answer: Answer,
    ) -> Arc<Self> {
        Arc::new(Self {
            gates: parking_lot::RwLock::new(Gates::new(source())),
            source: Some(source),
            surface,
            answer,
        })
    }

    fn refresh(&self) {
        let Some(source) = &self.source else { return };
        if self.gates.read().read_at.elapsed() < LIMITS_REFRESH {
            return;
        }
        let limits = source();
        let mut gates = self.gates.write();
        if gates.limits == limits {
            gates.read_at = std::time::Instant::now();
        } else {
            *gates = Gates::new(limits);
        }
    }

    /// The limits in force.
    pub fn limits(&self) -> AddressLimits {
        self.gates.read().limits
    }

    /// The body of a refusal that may be retried after `retry_after`.
    fn refusal(&self, retry_after: Duration) -> serde_json::Value {
        let secs = retry_after.as_secs().max(1);
        let limits = self.limits();
        let message = format!("per-IP request rate exceeded; retry after {secs}s");
        match self.answer {
            // The body is not parsed before the gate, so the request id is
            // unknown; JSON-RPC answers null for it then.
            Answer::JsonRpc => serde_json::json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": RPC_ERR_RATE_LIMITED,
                    "message": message,
                    "data": {
                        "retry_after_ms": u64::try_from(retry_after.as_millis()).unwrap_or(u64::MAX).max(1),
                        "rate_per_second": limits.rate_per_sec,
                        "burst": limits.burst,
                    },
                },
            }),
            Answer::Http => serde_json::json!({ "error": "rate_limited", "message": message }),
        }
    }

    fn check(&self, ip: IpAddr) -> GcraDecision {
        self.refresh();
        let gates = self.gates.read();
        if gates.floor.active_keys() > EVICT_THRESHOLD {
            gates.floor.evict_replenished();
        }
        gates.floor.check(&ip.to_string())
    }

    /// Whether `ip` may have one more submission past its floor checked
    /// against its sender's own quota.
    fn check_identity(&self, ip: IpAddr) -> bool {
        let gates = self.gates.read();
        if gates.limits.identity_checks_per_sec == 0 {
            return false;
        }
        if gates.identity_checks.active_keys() > EVICT_THRESHOLD {
            gates.identity_checks.evict_replenished();
        }
        matches!(
            gates.identity_checks.check(&ip.to_string()),
            GcraDecision::Admit { .. }
        )
    }

    fn refuse(&self, retry_after: Duration) -> Response {
        let secs = retry_after.as_secs().max(1);
        (
            StatusCode::TOO_MANY_REQUESTS,
            [("retry-after", secs.to_string())],
            axum::Json(self.refusal(retry_after)),
        )
            .into_response()
    }
}

/// Whether `body` is a single JSON-RPC call that submits a transaction.
fn is_submission(body: &[u8]) -> bool {
    #[derive(serde::Deserialize)]
    struct Call<'a> {
        #[serde(borrow)]
        method: std::borrow::Cow<'a, str>,
    }
    serde_json::from_slice::<Call<'_>>(body)
        .is_ok_and(|c| SUBMISSION_METHODS.contains(&c.method.as_ref()))
}

/// Where and when the request being served arrived, as the per-address gate
/// admitted it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Arrival {
    /// The client address the gate keyed on.
    pub ip: IpAddr,
    /// Unix milliseconds at admission.
    pub at_ms: u64,
}

tokio::task_local! {
    static ARRIVAL: Arrival;
}

/// The arrival of the request this task serves, when it came in over a
/// surface the per-address gate guards; `None` for an embedded call.
pub(crate) fn arrival() -> Option<Arrival> {
    ARRIVAL.try_with(|a| *a).ok()
}

/// axum middleware: admit or reject the request against the per-address
/// gate. Past the floor, a transaction submission may still go through,
/// within the address's identity-check budget, to be admitted only on its
/// sender's own quota. Rejections return HTTP 429 with a `Retry-After`
/// header and a body in the limiter's [`Answer`] shape.
pub async fn ip_rate_limit(
    State(limiter): State<Arc<IpRateLimiter>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request,
    next: Next,
) -> Response {
    let ip = limiter.surface.client_ip(peer, request.headers());
    let arrival = Arrival {
        ip,
        at_ms: crate::calendar::now_ms(),
    };
    let retry_after = match limiter.check(ip) {
        GcraDecision::Admit { .. } => return ARRIVAL.scope(arrival, next.run(request)).await,
        GcraDecision::Deny { retry_after } => retry_after,
    };
    if limiter.answer != Answer::JsonRpc || !limiter.check_identity(ip) {
        return limiter.refuse(retry_after);
    }
    let (parts, body) = request.into_parts();
    let Ok(bytes) = axum::body::to_bytes(body, MAX_SUBMISSION_BYTES).await else {
        return limiter.refuse(retry_after);
    };
    if !is_submission(&bytes) {
        return limiter.refuse(retry_after);
    }
    let request = Request::from_parts(parts, axum::body::Body::from(bytes));
    ARRIVAL
        .scope(arrival, OVER_ADDRESS_FLOOR.scope(true, next.run(request)))
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limiter(rate: u32, burst: u32) -> Arc<IpRateLimiter> {
        let surface =
            SurfacePolicy::from_config(&crate::config::NodeConfig::default(), None).unwrap();
        IpRateLimiter::new(rate, burst, Arc::new(surface), Answer::Http)
    }

    /// A JSON-RPC client decodes a refusal as an error object with the
    /// rate-limit code and the retry hint, not as a bare string.
    #[tokio::test]
    async fn json_rpc_refusal_is_an_error_object() {
        use axum::body::Body;
        use tower::ServiceExt;
        let surface =
            SurfacePolicy::from_config(&crate::config::NodeConfig::default(), None).unwrap();
        let gate = IpRateLimiter::new(1, 1, Arc::new(surface), Answer::JsonRpc);
        let app = axum::Router::new()
            .route("/", axum::routing::post(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(gate, ip_rate_limit));
        let mut refused = None;
        for _ in 0..10 {
            let mut req = Request::builder()
                .method("POST")
                .uri("/")
                .body(Body::from("{}"))
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(
                "198.51.100.9:4000".parse::<SocketAddr>().unwrap(),
            ));
            let res = app.clone().oneshot(req).await.unwrap();
            if res.status() == StatusCode::TOO_MANY_REQUESTS {
                refused = Some(res);
                break;
            }
        }
        let res = refused.expect("the gate never refused");
        let body = axum::body::to_bytes(res.into_body(), 1 << 16)
            .await
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert!(v["id"].is_null());
        assert_eq!(v["error"]["code"], RPC_ERR_RATE_LIMITED);
        assert!(v["error"]["message"].is_string());
        assert!(v["error"]["data"]["retry_after_ms"].as_u64().unwrap() >= 1);
        assert_eq!(v["error"]["data"]["rate_per_second"], 1);
    }

    /// Past its floor an address still gets transaction submissions through,
    /// marked so admission takes them only on the sender's own quota, up to
    /// its identity-check budget; any other request is refused.
    #[tokio::test]
    async fn past_the_floor_only_submissions_go_on_to_the_sender_quota() {
        use axum::body::Body;
        use tower::ServiceExt;
        let surface =
            SurfacePolicy::from_config(&crate::config::NodeConfig::default(), None).unwrap();
        let limits = AddressLimits {
            rate_per_sec: 1,
            burst: 1,
            identity_checks_per_sec: 3,
        };
        let gate =
            IpRateLimiter::governed(Arc::new(move || limits), Arc::new(surface), Answer::JsonRpc);
        let app = axum::Router::new()
            .route(
                "/",
                axum::routing::post(|| async {
                    if over_address_floor() {
                        "past"
                    } else {
                        "floor"
                    }
                }),
            )
            .layer(axum::middleware::from_fn_with_state(gate, ip_rate_limit));
        let call = |method: &str| {
            let mut req = Request::builder()
                .method("POST")
                .uri("/")
                .body(Body::from(format!(
                    r#"{{"jsonrpc":"2.0","id":1,"method":"{method}","params":{{}}}}"#
                )))
                .unwrap();
            req.extensions_mut().insert(ConnectInfo(
                "198.51.100.11:4000".parse::<SocketAddr>().unwrap(),
            ));
            let app = app.clone();
            async move {
                let res = app.oneshot(req).await.unwrap();
                let status = res.status();
                let body = axum::body::to_bytes(res.into_body(), 1 << 16)
                    .await
                    .unwrap();
                (status, String::from_utf8_lossy(&body).to_string())
            }
        };
        // Spend the floor.
        let mut spent = false;
        for _ in 0..5 {
            if call("eth_blockNumber").await.0 == StatusCode::TOO_MANY_REQUESTS {
                spent = true;
                break;
            }
        }
        assert!(spent, "the floor never ran out");
        assert_eq!(
            call("tenzro_getBalance").await.0,
            StatusCode::TOO_MANY_REQUESTS
        );
        let mut past = 0;
        for _ in 0..10 {
            let (status, body) = call("eth_sendRawTransaction").await;
            if status == StatusCode::OK {
                assert_eq!(body, "past");
                past += 1;
            }
        }
        assert!(
            (1..10).contains(&past),
            "identity checks are bounded per address, got {past}"
        );
    }

    #[test]
    fn gate_denies_after_burst_exhausted() {
        let limiter = limiter(1, 3);
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

    /// Loopback is counted like any other address. A bridge relaying public
    /// traffic onto the loopback port is limited, not waved through.
    #[test]
    fn loopback_is_not_exempt() {
        let limiter = limiter(1, 2);
        let peer: SocketAddr = "127.0.0.1:40000".parse().unwrap();
        let ip = limiter
            .surface
            .client_ip(peer, &axum::http::HeaderMap::new());
        let mut denied = false;
        for _ in 0..10 {
            if matches!(limiter.check(ip), GcraDecision::Deny { .. }) {
                denied = true;
            }
        }
        assert!(denied, "loopback traffic must be rate limited");
    }
}
