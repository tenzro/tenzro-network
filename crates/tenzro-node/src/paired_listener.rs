//! The listener paired devices reach the node on.
//!
//! A phone or a television on the operator's network dials an address like
//! `192.168.1.20`, which no public authority certifies. This listener serves
//! TLS under the node's pinned certificates ([`crate::pinned_cert`]): the
//! pairing code carries their hashes, and the device accepts those
//! certificates and no other. It learns later certificates from the signed
//! list at `GET /certificates`, which it checks against the node key it was
//! given when it paired.
//!
//! The listener opens when the operator starts a pairing, or at start when a
//! device is already paired; a node no device was paired with has no such
//! socket. It answers peers on private, link-local and loopback addresses
//! only, and serves only the calls in [`SERVED_METHODS`].

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore, broadcast, watch};
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::node::TenzroNode;
use crate::pinned_cert::{PinnedCerts, PinnedHash, Publication};

/// The name this listener's certificates are published under.
pub const LISTENER: &str = "paired-devices";

/// The JSON-RPC methods served here: signing in, pairing, the reads a paired
/// device shows, and the administrative calls a paired device may make.
pub(crate) const SERVED_METHODS: &[&str] = &[
    "tenzro_accessChallenge",
    "tenzro_approveDeviceCode",
    "tenzro_getConnectivity",
    "tenzro_getNodeStatus",
    "tenzro_getRole",
    "tenzro_getRoleStakes",
    "tenzro_getUpdateNotice",
    "tenzro_installUpdate",
    "tenzro_issueAccessToken",
    "tenzro_listConditions",
    "tenzro_listPairedDevices",
    "tenzro_nodeProfile",
    "tenzro_pairDevice",
    "tenzro_pollDeviceCode",
    "tenzro_queryEvents",
    "tenzro_requestDeviceCode",
    "tenzro_restartNode",
    "tenzro_submitApproval",
    "tenzro_syncing",
    "tenzro_unpairDevice",
];

/// Most addresses a pairing code names, so the code stays easy to scan.
const MAX_ADDRESSES: usize = 3;
/// Most connections held at once.
const MAX_CONNECTIONS: usize = 64;
/// How long a peer has to finish the TLS handshake.
const HANDSHAKE_WAIT: Duration = Duration::from_secs(10);
/// How long a peer has to send a request's headers.
const REQUEST_WAIT: Duration = Duration::from_secs(60);
/// How long a caller waits for the listener to open.
const OPEN_WAIT: Duration = Duration::from_secs(5);
/// The pause after the socket refuses to accept.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

/// The listener while it serves.
#[derive(Debug, Clone)]
pub(crate) struct Serving {
    certs: Arc<PinnedCerts>,
    bound: SocketAddr,
    published: Arc<Mutex<Option<Publication>>>,
}

impl Serving {
    /// Where a device dials: the bound address, or for a listener on every
    /// interface this machine's addresses on private networks.
    pub(crate) fn addresses(&self) -> Vec<SocketAddr> {
        if !self.bound.ip().is_unspecified() {
            return vec![self.bound];
        }
        interface_addresses()
            .into_iter()
            .take(MAX_ADDRESSES)
            .map(|ip| SocketAddr::new(ip, self.bound.port()))
            .collect()
    }

    /// The certificates a device may pin: the one served now, then the next.
    pub(crate) fn pins(&self) -> Vec<PinnedHash> {
        self.certs.hashes()
    }

    /// The certificates signed by the node, signed again only when they
    /// change.
    fn publication(
        &self,
        signer: &dyn tenzro_auth::TokenSigner,
        issuer: &str,
    ) -> Result<Publication, String> {
        let mut held = self.published.lock();
        if let Some(publication) = held.as_ref()
            && publication.hashes == self.certs.hashes()
        {
            return Ok(publication.clone());
        }
        let publication = self.certs.publish(signer, issuer, LISTENER, unix_now())?;
        *held = Some(publication.clone());
        Ok(publication)
    }
}

#[derive(Debug, Clone)]
enum ListenerState {
    Closed,
    Serving(Serving),
    Failed(String),
}

/// What the rest of the node holds of the listener: a way to ask for it and
/// to learn where it serves.
#[derive(Debug)]
pub(crate) struct Door {
    wanted: Notify,
    /// Whether a listener task runs in this process.
    attended: AtomicBool,
    state: watch::Sender<ListenerState>,
}

impl Default for Door {
    fn default() -> Self {
        Self {
            wanted: Notify::new(),
            attended: AtomicBool::new(false),
            state: watch::channel(ListenerState::Closed).0,
        }
    }
}

impl Door {
    /// The listener, when it serves.
    pub(crate) fn serving(&self) -> Option<Serving> {
        match &*self.state.borrow() {
            ListenerState::Serving(serving) => Some(serving.clone()),
            ListenerState::Closed | ListenerState::Failed(_) => None,
        }
    }

    /// Opens the listener if it is not open and waits for it: where it
    /// serves, nothing when this process runs no listener, or why it did not
    /// open.
    pub(crate) async fn open(&self) -> Result<Option<Serving>, String> {
        if !self.attended.load(Ordering::Acquire) {
            return Ok(None);
        }
        if let Some(serving) = self.serving() {
            return Ok(Some(serving));
        }
        // A listener that failed to open is tried again.
        self.state.send_if_modified(|state| {
            let failed = matches!(state, ListenerState::Failed(_));
            if failed {
                *state = ListenerState::Closed;
            }
            failed
        });
        self.wanted.notify_one();
        let mut state = self.state.subscribe();
        let settled = tokio::time::timeout(
            OPEN_WAIT,
            state.wait_for(|state| !matches!(state, ListenerState::Closed)),
        )
        .await;
        match settled {
            Ok(Ok(state)) => match &*state {
                ListenerState::Serving(serving) => Ok(Some(serving.clone())),
                ListenerState::Failed(why) => Err(why.clone()),
                ListenerState::Closed => Err("the paired-device listener closed".to_string()),
            },
            Ok(Err(_)) | Err(_) => {
                Err("the paired-device listener did not open in time".to_string())
            }
        }
    }
}

/// Whether `ip` is on a private network: loopback, a private or link-local
/// range, or the shared range overlay networks hand out.
fn on_private_network(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || (a == 100 && (b & 0xc0) == 64)
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

/// This machine's IPv4 addresses on private networks, those of the interface
/// that carries the default route first.
fn interface_addresses() -> Vec<IpAddr> {
    let first: Vec<IpAddr> = netdev::get_default_interface()
        .map(|i| i.ipv4.iter().map(|n| IpAddr::V4(n.addr())).collect())
        .unwrap_or_default();
    let every = netdev::get_interfaces()
        .into_iter()
        .flat_map(|i| i.ipv4.into_iter().map(|n| IpAddr::V4(n.addr())));
    let mut out = Vec::new();
    for ip in first.into_iter().chain(every) {
        if on_private_network(ip) && !ip.is_loopback() && !out.contains(&ip) {
            out.push(ip);
        }
    }
    out
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Binds the socket and mints the certificates it serves under.
async fn bind(node: &Arc<TenzroNode>) -> Result<(TcpListener, TlsAcceptor, Serving), String> {
    let addr = &node.config().paired_device_addr;
    let listener = TcpListener::bind(addr)
        .await
        .map_err(|e| format!("paired devices cannot be served on {addr}: {e}"))?;
    let bound = listener
        .local_addr()
        .map_err(|e| format!("paired-device listener address: {e}"))?;
    let mut names: Vec<String> = if bound.ip().is_unspecified() {
        interface_addresses()
            .iter()
            .map(IpAddr::to_string)
            .collect()
    } else {
        vec![bound.ip().to_string()]
    };
    if names.is_empty() {
        names.push("localhost".to_string());
    }
    let certs = Arc::new(PinnedCerts::mint(names, unix_now())?);
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("paired-device listener TLS: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(certs.clone());
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let serving = Serving {
        certs,
        bound,
        published: Arc::new(Mutex::new(None)),
    };
    Ok((listener, TlsAcceptor::from(Arc::new(tls)), serving))
}

/// Serves paired devices from the first time the listener is wanted until
/// the node shuts down.
pub async fn run(node: Arc<TenzroNode>, mut shutdown: broadcast::Receiver<()>) {
    let door = node.access().paired_listener();
    door.attended.store(true, Ordering::Release);
    let mut wanted = crate::pairing_rpc::any_paired(&node);
    let (listener, acceptor, serving) = loop {
        if !wanted {
            tokio::select! {
                _ = door.wanted.notified() => {}
                _ = shutdown.recv() => return,
            }
        }
        wanted = false;
        match bind(&node).await {
            Ok(bound) => break bound,
            Err(why) => {
                warn!(error = %why, "the paired-device listener did not open");
                door.state.send_replace(ListenerState::Failed(why));
            }
        }
    };
    info!(addr = %serving.bound, "paired-device listener serving");
    let rotation = tokio::spawn(serving.certs.clone().run());
    door.state.send_replace(ListenerState::Serving(serving));

    let app = crate::rpc::paired_device_routes(&node);
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = shutdown.recv() => break,
        };
        let (tcp, peer) = match accepted {
            Ok(accepted) => accepted,
            Err(e) => {
                warn!(error = %e, "paired-device listener accept failed");
                tokio::time::sleep(ACCEPT_PAUSE).await;
                continue;
            }
        };
        if !on_private_network(peer.ip()) {
            continue;
        }
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let acceptor = acceptor.clone();
        let app = app.clone().layer(axum::Extension(ConnectInfo(peer)));
        tokio::spawn(async move {
            let _slot = slot;
            let Ok(Ok(tls)) = tokio::time::timeout(HANDSHAKE_WAIT, acceptor.accept(tcp)).await
            else {
                return;
            };
            let _ = hyper::server::conn::http1::Builder::new()
                .timer(TokioTimer::new())
                .header_read_timeout(REQUEST_WAIT)
                .serve_connection(TokioIo::new(tls), TowerToHyperService::new(app))
                .await;
        });
    }
    rotation.abort();
    door.state.send_replace(ListenerState::Closed);
}

/// `GET /certificates`: the listener's certificates, signed by the node.
pub(crate) async fn certificates(State(node): State<Arc<TenzroNode>>) -> Response {
    let Some(serving) = node.access().paired_listener().serving() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(engine) = node.auth_engine() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "this node signs nothing").into_response();
    };
    match serving.publication(engine.signer().as_ref(), &engine.config().issuer) {
        Ok(publication) => axum::Json(publication).into_response(),
        Err(why) => {
            warn!(error = %why, "the paired-device certificates were not signed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn the_served_methods_are_sorted_and_all_dispatched() {
        assert!(SERVED_METHODS.windows(2).all(|w| w[0] < w[1]));
        for method in SERVED_METHODS {
            assert!(
                crate::rpc_gates::ADMIN_METHODS.contains(method)
                    || crate::rpc_gates::OWNER_METHODS.contains(method)
                    || crate::rpc_gates::OPEN_METHODS.contains(method),
                "{method} is not a method this node dispatches"
            );
        }
    }

    #[test]
    fn every_call_a_paired_device_is_allowed_is_served() {
        for method in crate::pairing_rpc::PAIRED_DEVICE_METHODS {
            assert!(SERVED_METHODS.contains(method), "{method}");
        }
        assert!(SERVED_METHODS.contains(&crate::pairing_rpc::PAIR_METHOD));
        for method in ["tenzro_accessChallenge", "tenzro_issueAccessToken"] {
            assert!(SERVED_METHODS.contains(&method), "{method}");
        }
    }

    #[test]
    fn only_peers_on_private_networks_are_answered() {
        for near in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.9",
            "192.168.1.20",
            "100.64.0.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:192.168.1.20",
        ] {
            assert!(on_private_network(near.parse().unwrap()), "{near}");
        }
        // Spelled from parts: the last link-local address and the top of the shared range.
        for near in [
            Ipv4Addr::new(169, 254, 7, 7),
            Ipv4Addr::new(100, 127, 255, 254),
        ] {
            assert!(on_private_network(IpAddr::V4(near)), "{near}");
        }
        assert!(!on_private_network(IpAddr::V4(Ipv4Addr::new(
            100, 63, 255, 255
        ))));
        for far in [
            "8.8.8.8",
            "100.128.0.1",
            "172.32.0.1",
            "2001:db8::1",
            "::ffff:8.8.8.8",
        ] {
            assert!(!on_private_network(far.parse().unwrap()), "{far}");
        }
    }

    #[tokio::test]
    async fn a_process_with_no_listener_task_has_no_listener_to_open() {
        let door = Door::default();
        assert!(door.serving().is_none());
        assert_eq!(door.open().await.map(|s| s.is_some()), Ok(false));
    }

    #[tokio::test]
    async fn a_listener_that_did_not_open_says_why_and_is_tried_again() {
        let door = Door::default();
        door.attended.store(true, Ordering::Release);
        door.state
            .send_replace(ListenerState::Failed("address in use".to_string()));
        // Nobody answers the second try within the wait.
        tokio::time::pause();
        let again = door.open().await;
        assert_eq!(
            again.map(|s| s.is_some()),
            Err("the paired-device listener did not open in time".to_string())
        );
        assert!(matches!(&*door.state.borrow(), ListenerState::Closed));
    }
}
