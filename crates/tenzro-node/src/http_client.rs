//! Shared outbound HTTP clients.
//!
//! Every outbound call the node makes to a third party — chain RPCs,
//! aggregator APIs, peer provider endpoints, MCP upstreams — goes through
//! one of the two clients here. A `reqwest::Client` owns its connection
//! pool, so building one per request discards keep-alive and pays a fresh
//! TCP + TLS handshake on every call. Cloning is cheap (the inner state is
//! refcounted) and clones share the pool, so a struct that wants to hold
//! one can clone from the accessor.
//!
//! Both clients bound how long a request may occupy a node request slot.
//! An upstream that accepts the connection and then never answers is the
//! failure mode these timeouts exist to prevent.
//!
//! A call site that needs a different total budget sets it per request
//! with [`reqwest::RequestBuilder::timeout`], which takes precedence over
//! the client default in either direction, and keeps the shared pool.

use std::sync::OnceLock;
use std::time::Duration;

/// Covers DNS + TCP + TLS only. Cross-region handshakes land well inside
/// this, so a blackholed address fails here rather than consuming the
/// whole request budget.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Total budget for a non-streaming request. Chain RPCs, aggregator quotes
/// and search upstreams answer in single-digit seconds; the headroom
/// absorbs a cold or rate-limited upstream without pinning a slot.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

const POOL_MAX_IDLE_PER_HOST: usize = 32;

fn build(request_timeout: Option<Duration>) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .pool_idle_timeout(POOL_IDLE_TIMEOUT)
        .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST);
    if let Some(timeout) = request_timeout {
        builder = builder.timeout(timeout);
    }
    builder
        .build()
        .expect("reqwest client construction is infallible with these options")
}

/// Pooled client for outbound calls whose response is read in full.
pub fn shared() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| build(Some(REQUEST_TIMEOUT)))
}

/// Pooled client for responses consumed as a byte stream. No total-request
/// timeout: a legitimate SSE completion runs for as long as the model
/// generates. The connect timeout still bounds an unreachable peer.
pub fn streaming() -> &'static reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| build(None))
}
