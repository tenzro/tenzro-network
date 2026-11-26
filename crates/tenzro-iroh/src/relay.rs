//! The relay role.
//!
//! Relaying is an ordinary operator role. A node that runs it serves, on one
//! HTTP listener:
//!
//! - `/relay`: the iroh relay protocol, which forwards end-to-end encrypted
//!   QUIC between endpoints that cannot reach each other directly.
//! - `/identity`: the relay operator's own signed [`EndpointRecord`], which
//!   announces this relay and names the operator's endpoint. It is the door
//!   a new node enters the Tenzro discovery network through: from it the
//!   node reaches the operator's endpoint and asks it for everyone else.
//! - `/ping`: the latency probe iroh uses to choose a home relay.
//! - `/generate_204`: the captive-portal check iroh runs on a new network.
//!
//! The relay's resources are bounded whatever its clients do: at most
//! [`RelayLimits::max_connections`] connections at once (a connection beyond
//! it is closed on accept), and each client read at most
//! [`RelayLimits::client_bytes_per_second`]. A committee that stalls and has
//! every validator retry through the relay cannot grow it without limit.
//!
//! Who may use the relay is [`RelayAdmission`]'s to say once the node installs
//! its identity gate: a registered machine, an app device signed in to this
//! node, or a machine inside its onboarding session (so joining keeps
//! working), judged by the gate as for any onboarding protocol and only logged
//! while the gate audits. Before the gate is installed every client is let in.
//!
//! The listener speaks plain HTTP on the address the operator binds it to.
//! Exposing it, and terminating TLS for the URL the operator publishes, is
//! the operator's choice outside the node; nodes that do not run the role
//! need no inbound port at all, since they reach relays outbound.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::Service;
use iroh::EndpointId;
use iroh_relay::KeyCache;
use iroh_relay::server::http_server::{
    BytesBody, Handlers, HyperError, RelayService, RelayServiceWithNotify,
};
use iroh_relay::server::streams::MaybeTlsStream;
use iroh_relay::server::{
    Access, AccessControl, ClientRateLimit, ClientRequest, ConnectionId, Metrics,
};
use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use url::Url;

use crate::discovery::DiscoveryStore;
use crate::error::{IrohError, IrohResult};
use crate::identity_gate::{Admit, IdentityGate};
use crate::identity_record::{EndpointRecord, RecordScope};

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn respond(status: StatusCode, body: impl Into<Bytes>) -> Response<BytesBody> {
    let body: BytesBody = Box::new(Full::new(body.into()));
    let mut r = Response::new(body);
    *r.status_mut() = status;
    r
}

/// The answer iroh's captive-portal check expects: `204 No Content`, echoing
/// a well-formed challenge header. A network that intercepts HTTP answers
/// something else, and the endpoint then knows it sits behind a portal.
fn no_content(req: &Request<Incoming>) -> Response<BytesBody> {
    let mut r = respond(StatusCode::NO_CONTENT, Bytes::new());
    let challenge = req
        .headers()
        .get("X-Iroh-Challenge")
        .and_then(|c| c.to_str().ok())
        .filter(|c| {
            !c.is_empty()
                && c.len() < 64
                && c.chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_')
        });
    if let Some(value) =
        challenge.and_then(|c| http::HeaderValue::from_str(&format!("response {c}")).ok())
    {
        r.headers_mut().insert("X-Iroh-Response", value);
    }
    r
}

/// One HTTP connection of the relay listener: `/relay` goes to the iroh
/// relay service; `/identity` and `/ping` are answered here.
#[derive(Clone)]
struct RelayHttp {
    relay: RelayServiceWithNotify,
    store: Arc<DiscoveryStore>,
    operator: String,
}

impl RelayHttp {
    fn answer(&self, req: &Request<Incoming>) -> Response<BytesBody> {
        match (req.method(), req.uri().path()) {
            (&Method::GET, "/ping") => respond(StatusCode::OK, Bytes::new()),
            (&Method::GET, "/generate_204") => no_content(req),
            (&Method::GET, "/identity") => match self
                .store
                .lookup(&self.operator)
                .filter(|r| r.scope == RecordScope::Network)
            {
                Some(r) => respond(StatusCode::OK, serde_json::to_vec(&r).unwrap_or_default()),
                None => respond(StatusCode::NOT_FOUND, "no relay record yet"),
            },
            _ => respond(StatusCode::NOT_FOUND, Bytes::new()),
        }
    }
}

impl Service<Request<Incoming>> for RelayHttp {
    type Response = Response<BytesBody>;
    type Error = HyperError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn call(&self, req: Request<Incoming>) -> Self::Future {
        if req.uri().path() == iroh_relay::http::RELAY_PATH {
            return Box::pin(self.relay.call(req));
        }
        let response = self.answer(&req);
        Box::pin(async move { Ok::<_, HyperError>(response) })
    }
}

/// The name a relay client is judged under by the identity gate: an
/// onboarding protocol, so a machine that is joining reaches the relay inside
/// its onboarding session.
pub const RELAY_CLIENT: &[u8] = b"tenzro/relay-client";

/// App devices signed in to this node, which the relay lets in on the
/// credential in their request.
pub trait RelayDevices: Send + Sync + 'static {
    /// The identity a signed-in device's request names, when it carries a
    /// valid credential of this node: an `Authorization: DPoP <token>` and a
    /// `DPoP` proof header, or `token` and `dpop` query parameters.
    fn signed_in(&self, uri: &http::Uri, headers: &http::HeaderMap) -> Option<String>;
}

struct Installed {
    gate: IdentityGate,
    discovery: Arc<DiscoveryStore>,
    devices: Option<(Arc<dyn RelayDevices>, u32)>,
}

#[derive(Default)]
struct AdmissionInner {
    installed: std::sync::OnceLock<Installed>,
    /// Devices' connections, to count each identity's.
    devices: Mutex<HashMap<ConnectionId, String>>,
    per_identity: Mutex<HashMap<String, u32>>,
}

/// Decides who may use the relay. Lets everyone in until [`Self::install`].
#[derive(Clone, Default)]
pub struct RelayAdmission {
    inner: Arc<AdmissionInner>,
}

impl std::fmt::Debug for RelayAdmission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RelayAdmission")
    }
}

impl RelayAdmission {
    /// Judges relay clients by `gate`, naming machines by the records
    /// `discovery` holds, and lets in the app devices `devices` vouches for,
    /// at most `per_identity` connections for one identity. Once only.
    pub fn install(
        &self,
        gate: IdentityGate,
        discovery: Arc<DiscoveryStore>,
        devices: Option<(Arc<dyn RelayDevices>, u32)>,
    ) {
        let _ = self.inner.installed.set(Installed {
            gate,
            discovery,
            devices,
        });
    }

    /// The decision for a client: pure of the relay, so it is tested with
    /// plain values.
    pub fn decide(
        &self,
        now_ms: u64,
        endpoint: EndpointId,
        connection: ConnectionId,
        uri: &http::Uri,
        headers: &http::HeaderMap,
    ) -> Access {
        let Some(installed) = self.inner.installed.get() else {
            return Access::Allow;
        };
        if let Some((devices, per_identity)) = &installed.devices
            && let Some(did) = devices.signed_in(uri, headers)
        {
            let mut counts = self.inner.per_identity.lock();
            let count = counts.entry(did.clone()).or_insert(0);
            if *count >= *per_identity {
                return Access::Deny {
                    reason: Some(format!("{did} holds as many relay connections as it may")),
                };
            }
            *count += 1;
            self.inner.devices.lock().insert(connection, did);
            return Access::Allow;
        }
        let did = installed
            .discovery
            .naming(endpoint)
            .map(|record| record.machine_did());
        match installed
            .gate
            .evaluate(now_ms, endpoint, did.as_deref(), None, RELAY_CLIENT)
        {
            Admit::Allow | Admit::Onboarding { .. } => Access::Allow,
            Admit::Refuse { reason, .. } => Access::Deny {
                reason: Some(reason),
            },
        }
    }

    fn left(&self, connection: ConnectionId) {
        let Some(did) = self.inner.devices.lock().remove(&connection) else {
            return;
        };
        let mut counts = self.inner.per_identity.lock();
        if let Some(count) = counts.get_mut(&did) {
            *count -= 1;
            if *count == 0 {
                counts.remove(&did);
            }
        }
    }
}

impl AccessControl for RelayAdmission {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        self.decide(
            now_ms(),
            request.endpoint_id(),
            request.connection_id(),
            request.uri(),
            request.headers(),
        )
    }

    fn on_disconnect(&self, _endpoint: EndpointId, connection: ConnectionId) {
        self.left(connection);
    }
}

/// A running relay: the listener task and the relay service it feeds.
pub struct RelayServer {
    local_addr: SocketAddr,
    service: RelayService,
    task: JoinHandle<()>,
    metrics: Arc<Metrics>,
}

/// What a relay may hold at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayLimits {
    /// Most client connections served at once.
    pub max_connections: usize,
    /// Bytes per second read from one client.
    pub client_bytes_per_second: u32,
    /// Bytes one client may send in a burst above that rate.
    pub client_burst_bytes: u32,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_connections: 4_096,
            client_bytes_per_second: 8 * 1024 * 1024,
            client_burst_bytes: 16 * 1024 * 1024,
        }
    }
}

impl RelayLimits {
    fn rate_limit(&self) -> Option<ClientRateLimit> {
        let mut limit =
            ClientRateLimit::new(std::num::NonZeroU32::new(self.client_bytes_per_second)?);
        limit.max_burst_bytes = std::num::NonZeroU32::new(self.client_burst_bytes);
        Some(limit)
    }
}

/// What a relay is carrying.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RelayLoad {
    /// Client connections open now.
    pub connections: u64,
    /// Bytes relayed since the relay started, both directions.
    pub bytes: u64,
}

impl RelayServer {
    /// Binds the relay listener on `bind_addr`, announcing the record
    /// `store` holds for `operator`, and serves it within `limits` until
    /// drop. The listener speaks plain HTTP and binds loopback only; any
    /// other address is refused. TLS is the operator's proxy's, outside the
    /// node.
    pub async fn spawn(
        bind_addr: SocketAddr,
        store: Arc<DiscoveryStore>,
        operator: String,
        limits: RelayLimits,
        admission: RelayAdmission,
    ) -> IrohResult<Self> {
        if !bind_addr.ip().is_loopback() {
            return Err(IrohError::Unauthorized(format!(
                "relay listener {bind_addr}: binds loopback only, behind the operator's own TLS proxy"
            )));
        }
        let listener = TcpListener::bind(bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let metrics = Arc::new(Metrics::default());
        let service = RelayService::new(
            Handlers::default(),
            http::HeaderMap::new(),
            limits.rate_limit(),
            KeyCache::new(4096),
            Arc::new(admission),
            metrics.clone(),
        );
        let accept_service = service.clone();
        let slots = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
        let task = tokio::spawn(async move {
            loop {
                let (stream, _peer) = match listener.accept().await {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::warn!(error = %e, "relay listener accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Ok(slot) = slots.clone().try_acquire_owned() else {
                    tracing::debug!("relay at its connection limit; closing a new connection");
                    drop(stream);
                    continue;
                };
                let conn = RelayHttp {
                    relay: RelayServiceWithNotify::new(
                        accept_service.clone(),
                        Arc::new(Notify::new()),
                    ),
                    store: store.clone(),
                    operator: operator.clone(),
                };
                tokio::spawn(async move {
                    let _slot = slot;
                    let io = hyper_util::rt::TokioIo::new(MaybeTlsStream::Plain(stream));
                    if let Err(e) = hyper::server::conn::http1::Builder::new()
                        .serve_connection(io, conn)
                        .with_upgrades()
                        .await
                    {
                        tracing::debug!(error = %e, "relay connection ended");
                    }
                });
            }
        });
        Ok(Self {
            local_addr,
            service,
            task,
            metrics,
        })
    }

    /// Connections and bytes the relay is carrying.
    pub fn load(&self) -> RelayLoad {
        let m = &self.metrics;
        RelayLoad {
            connections: m.accepts.get().saturating_sub(m.disconnects.get()),
            bytes: m.bytes_sent.get().saturating_add(m.bytes_recv.get()),
        }
    }

    /// The address the listener bound.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
}

impl Drop for RelayServer {
    fn drop(&mut self) {
        self.task.abort();
        let service = self.service.clone();
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move { service.shutdown().await });
        }
    }
}

/// Where the relay at `relay` serves its operator's record.
pub fn identity_url(relay: &Url) -> Url {
    let mut url = relay.clone();
    if let Ok(mut segments) = url.path_segments_mut() {
        segments.pop_if_empty().push("identity");
    }
    url
}

/// Where the relay at `relay` takes relay clients: the URL a signed-in
/// device's DPoP proof names.
pub fn client_url(relay: &Url) -> Url {
    let mut url = relay.clone();
    if let Ok(mut segments) = url.path_segments_mut() {
        segments
            .pop_if_empty()
            .push(iroh_relay::http::RELAY_PATH.trim_start_matches('/'));
    }
    url
}

/// The relay at `url` as its operator announces it: the operator's record,
/// signed, current, and announcing exactly this URL.
pub async fn fetch_relay_record(url: &Url) -> IrohResult<EndpointRecord> {
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .use_preconfigured_tls(crate::identity_transport::platform_tls()?)
        .build()
        .map_err(|e| IrohError::Backend(format!("http client: {e}")))?;
    let target = identity_url(url);
    let resp = http
        .get(target.clone())
        .send()
        .await
        .map_err(|e| IrohError::Backend(format!("GET {target}: {e}")))?;
    if !resp.status().is_success() {
        return Err(IrohError::NotFound(format!(
            "GET {target}: {}",
            resp.status()
        )));
    }
    let body = resp
        .bytes()
        .await
        .map_err(|e| IrohError::Backend(format!("GET {target}: {e}")))?;
    admit_relay_record(url, &body)
}

/// The record a relay at `url` served at [`identity_url`], admitted only if
/// it is its operator's, signed, current, and announces exactly `url`.
pub fn admit_relay_record(url: &Url, body: &[u8]) -> IrohResult<EndpointRecord> {
    let record: EndpointRecord = serde_json::from_slice(body)
        .map_err(|e| IrohError::Backend(format!("relay {url}: record: {e}")))?;
    record
        .check_current(now_ms())
        .map_err(|e| IrohError::Unauthorized(format!("relay {url}: {e}")))?;
    if record.serves_relay.as_ref() != Some(url) {
        return Err(IrohError::Unauthorized(format!(
            "relay {url}: its operator's record does not announce it"
        )));
    }
    Ok(record)
}

/// One check of a relay: whether it served its operator's current record,
/// announcing exactly its URL, and how long that took.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RelayCheck {
    /// The relay URL.
    pub url: String,
    /// The operator's machine identity, from its record.
    pub operator: Option<String>,
    /// Whether the relay answered with a valid record.
    pub healthy: bool,
    /// How long the answer took, in milliseconds.
    pub latency_ms: Option<u64>,
    /// When the check ran, in milliseconds since the Unix epoch.
    pub checked_ms: u64,
    /// Why the check failed.
    pub error: Option<String>,
}

/// Checks the relay at `url` the way a node admits one: its operator's
/// record, signed, current and announcing this URL.
pub async fn check_relay(url: &Url) -> RelayCheck {
    let started = std::time::Instant::now();
    let result = fetch_relay_record(url).await;
    let latency_ms = started.elapsed().as_millis() as u64;
    match result {
        Ok(record) => RelayCheck {
            url: url.to_string(),
            operator: Some(record.machine_did()),
            healthy: true,
            latency_ms: Some(latency_ms),
            checked_ms: now_ms(),
            error: None,
        },
        Err(e) => RelayCheck {
            url: url.to_string(),
            operator: None,
            healthy: false,
            latency_ms: None,
            checked_ms: now_ms(),
            error: Some(e.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_transport::RelayRoleConfig;

    /// The relay role's whole configuration is a loopback bind and a URL: no
    /// certificate, key, ACME or TLS setting exists to be set.
    #[test]
    fn the_relay_role_configures_nothing_but_a_bind_and_a_url() {
        let role = RelayRoleConfig {
            bind_addr: "127.0.0.1:3340".parse().unwrap(),
            public_url: "https://relay.example.org/".parse().unwrap(),
        };
        let fields = serde_json::to_value(&role).unwrap();
        let keys: Vec<&String> = fields.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["bind_addr", "public_url"]);
        for word in ["tls", "cert", "acme", "key"] {
            assert!(keys.iter().all(|k| !k.contains(word)), "no {word} setting");
        }
    }

    #[tokio::test]
    async fn the_relay_listener_binds_loopback_only() {
        let refused = RelayServer::spawn(
            "0.0.0.0:0".parse().unwrap(),
            Arc::new(DiscoveryStore::new()),
            String::new(),
            RelayLimits::default(),
            RelayAdmission::default(),
        )
        .await;
        assert!(refused.is_err(), "an off-loopback relay bind is refused");
        let server = RelayServer::spawn(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(DiscoveryStore::new()),
            String::new(),
            RelayLimits::default(),
            RelayAdmission::default(),
        )
        .await
        .unwrap();
        assert!(server.local_addr().ip().is_loopback());
    }

    /// The captive-portal check gets `204 No Content` and its challenge back,
    /// so an endpoint on an open network does not believe it is behind a
    /// portal.
    #[tokio::test]
    async fn the_relay_answers_the_captive_portal_check() {
        let server = RelayServer::spawn(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(DiscoveryStore::new()),
            String::new(),
            RelayLimits::default(),
            RelayAdmission::default(),
        )
        .await
        .unwrap();
        let url = format!("http://{}/generate_204", server.local_addr());
        let resp = reqwest::Client::new()
            .get(&url)
            .header("X-Iroh-Challenge", "abc-1.2_3")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers().get("X-Iroh-Response").unwrap(),
            "response abc-1.2_3"
        );
        let resp = reqwest::Client::new()
            .get(&url)
            .header("X-Iroh-Challenge", "bad value!")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), reqwest::StatusCode::NO_CONTENT);
        assert!(
            resp.headers().get("X-Iroh-Response").is_none(),
            "a malformed challenge is not echoed"
        );
    }

    /// Connections beyond the limit are closed on accept, and a slot frees
    /// when a connection ends: however many clients retry at once, the relay
    /// holds at most its limit.
    #[tokio::test]
    async fn the_relay_holds_at_most_its_connection_limit() {
        use tokio::io::AsyncReadExt;
        let limits = RelayLimits {
            max_connections: 2,
            ..RelayLimits::default()
        };
        let server = RelayServer::spawn(
            "127.0.0.1:0".parse().unwrap(),
            Arc::new(DiscoveryStore::new()),
            String::new(),
            limits,
            RelayAdmission::default(),
        )
        .await
        .unwrap();
        let addr = server.local_addr();
        let open = |_| tokio::net::TcpStream::connect(addr);
        // The listener takes connections in the order they arrived and gives
        // each its place as it takes it, so the first two hold both places.
        let first = open(0).await.unwrap();
        let mut second = open(1).await.unwrap();
        let mut third = open(2).await.unwrap();
        let mut buf = [0u8; 1];
        // The third is closed at once: a read sees the end of the stream.
        let read = tokio::time::timeout(Duration::from_secs(2), third.read(&mut buf)).await;
        assert!(
            matches!(read, Ok(Ok(0)) | Ok(Err(_))),
            "a connection over the limit is closed: {read:?}"
        );
        // The second stays open.
        assert!(
            tokio::time::timeout(Duration::from_millis(200), second.read(&mut buf))
                .await
                .is_err()
        );
        // Once one ends, a new one is served.
        // The place comes back once the relay has seen the end, so a new
        // connection is tried until one is served, for at most ten seconds.
        drop(first);
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        let served = loop {
            let mut fourth = open(3).await.unwrap();
            if tokio::time::timeout(Duration::from_millis(300), fourth.read(&mut buf))
                .await
                .is_err()
            {
                break true;
            }
            if tokio::time::Instant::now() >= deadline {
                break false;
            }
        };
        assert!(served, "a freed slot serves again");
        assert!(
            limits.rate_limit().is_some(),
            "every client is read at a bounded rate"
        );
    }

    // -- admission ---------------------------------------------------------

    const MIN: u64 = 60_000;

    /// A registry that knows nobody.
    struct Nobody;

    impl crate::identity_gate::RegistryView for Nobody {
        fn standing(&self, _did: &str) -> tenzro_onboarding_types::onboarding::Standing {
            tenzro_onboarding_types::onboarding::Standing::Unregistered
        }
    }

    /// Vouches for a request whose authorization is `DPoP good-<did>`.
    struct Tokens;

    impl RelayDevices for Tokens {
        fn signed_in(&self, _uri: &http::Uri, headers: &http::HeaderMap) -> Option<String> {
            let value = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
            value.strip_prefix("DPoP good-").map(str::to_string)
        }
    }

    fn endpoint(n: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[n; 32]).public()
    }

    fn connection(n: u8) -> (ConnectionId, http::Uri, http::HeaderMap) {
        let (parts, ()) = http::Request::new(()).into_parts();
        let request = ClientRequest::new(
            endpoint(n),
            iroh_relay::http::ProtocolVersion::default(),
            parts,
        );
        (
            request.connection_id(),
            request.uri().clone(),
            request.headers().clone(),
        )
    }

    fn installed(
        mode: tenzro_onboarding_types::onboarding::GateMode,
        per_identity: u32,
    ) -> (RelayAdmission, IdentityGate) {
        let gate = IdentityGate::new(
            tenzro_onboarding_types::onboarding::OnboardingPolicy {
                mode,
                ..Default::default()
            },
            None,
        );
        gate.install_registry(Arc::new(Nobody));
        let admission = RelayAdmission::default();
        admission.install(
            gate.clone(),
            Arc::new(DiscoveryStore::new()),
            Some((Arc::new(Tokens), per_identity)),
        );
        (admission, gate)
    }

    #[test]
    fn before_the_gate_is_installed_everyone_uses_the_relay() {
        let admission = RelayAdmission::default();
        let (id, uri, headers) = connection(1);
        assert_eq!(
            admission.decide(0, endpoint(1), id, &uri, &headers),
            Access::Allow
        );
    }

    #[test]
    fn a_joining_machine_uses_the_relay_for_its_onboarding_window_only_when_enforced() {
        let (admission, _gate) =
            installed(tenzro_onboarding_types::onboarding::GateMode::Enforce, 2);
        let (id, uri, headers) = connection(1);
        assert_eq!(
            admission.decide(0, endpoint(1), id, &uri, &headers),
            Access::Allow
        );
        let (id, uri, headers) = connection(1);
        assert!(matches!(
            admission.decide(31 * MIN, endpoint(1), id, &uri, &headers),
            Access::Deny { .. }
        ));
    }

    #[test]
    fn in_audit_the_relay_refuses_nobody_and_logs_what_it_would_have() {
        let (admission, gate) = installed(tenzro_onboarding_types::onboarding::GateMode::Audit, 2);
        let (id, uri, headers) = connection(1);
        assert_eq!(
            admission.decide(0, endpoint(1), id, &uri, &headers),
            Access::Allow
        );
        let (id, uri, headers) = connection(1);
        assert_eq!(
            admission.decide(31 * MIN, endpoint(1), id, &uri, &headers),
            Access::Allow
        );
        assert!(
            gate.recent_refusals()
                .iter()
                .any(|r| r.action == "audit" && r.alpn == "tenzro/relay-client"),
            "the refusal it would have made is logged"
        );
    }

    #[test]
    fn a_signed_in_device_holds_at_most_its_identitys_relay_connections() {
        let (admission, _gate) =
            installed(tenzro_onboarding_types::onboarding::GateMode::Enforce, 1);
        let device = |n: u8| {
            let (id, uri, mut headers) = connection(n);
            headers.insert(
                http::header::AUTHORIZATION,
                "DPoP good-did:tenzro:human:a".parse().unwrap(),
            );
            (id, uri, headers)
        };
        let (first, uri, headers) = device(1);
        // Long after any onboarding window: a device is let in on its token.
        assert_eq!(
            admission.decide(99 * MIN, endpoint(1), first, &uri, &headers),
            Access::Allow
        );
        let (second, uri, headers) = device(2);
        assert!(matches!(
            admission.decide(99 * MIN, endpoint(2), second, &uri, &headers),
            Access::Deny { .. }
        ));
        admission.left(first);
        let (third, uri, headers) = device(3);
        assert_eq!(
            admission.decide(99 * MIN, endpoint(3), third, &uri, &headers),
            Access::Allow
        );
    }
}
