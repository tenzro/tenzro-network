//! Paths between endpoints besides iroh's own IP and relay paths.
//!
//! This module is the one place the node adds a transport to iroh. It
//! implements iroh's custom transport interface; the rest of the node sees
//! only [`Paths`] (attach it to an endpoint, choose forwarders) and
//! [`PeerRelayService`] (serve forwarding). When iroh ships the same
//! capability itself, this module is replaced and deleted, and nothing else
//! changes.
//!
//! # Peer relays
//!
//! Two endpoints behind NATs that hole punching cannot cross (an
//! endpoint-dependent NAT on one side, a port-restricted one on the other)
//! still reach each other directly through a third endpoint both reach
//! directly: a forwarder. Each keeps an ordinary iroh connection to the
//! forwarder, opened outbound, and the forwarder passes QUIC packets
//! between them as QUIC datagrams on those connections. The packets stay
//! end-to-end encrypted between the two endpoints; the forwarder sees only
//! which endpoint ids exchange how many bytes.
//!
//! An endpoint offers each forwarder it is connected to as a custom address
//! `(forwarder, itself)`; its signed endpoint record names the forwarders, so
//! a peer dialing it tries that path beside the relay and iroh prefers it
//! (a custom path is primary, a relay path a backup).
//!
//! A forwarder holds at most [`PeerRelayLimits::max_clients`] connections and
//! forwards at most [`PeerRelayLimits::bytes_per_second`] from any one of
//! them, so no client can make it carry more than its share.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};
use iroh::endpoint::Connection;
use iroh::endpoint::transports::{
    CustomEndpoint, CustomSender, CustomTransport, RecvInfo, Transmit,
};
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr, EndpointId};
use iroh_base::CustomAddr;
use parking_lot::{Mutex, RwLock};
use tokio::sync::mpsc;

pub mod punch;
pub use punch::{ALPN_PUNCH, NatSide, PunchService, parse_punched_addr, punched_addr};

/// Transport id of every address this module hands iroh.
pub const PATHS_TRANSPORT_ID: u64 = 0x7465_6e7a_726f_0001;

/// ALPN of the peer relay protocol.
pub const ALPN_PEER_RELAY: &[u8] = b"tenzro/peer-relay/1";

/// Address kind: through a forwarder.
const KIND_PEER_RELAY: u8 = 1;

/// Packets waiting for iroh to read them.
const INBOX: usize = 1024;

/// The custom address of `target` through `forwarder`.
pub fn peer_relay_addr(forwarder: EndpointId, target: EndpointId) -> CustomAddr {
    let mut data = Vec::with_capacity(65);
    data.push(KIND_PEER_RELAY);
    data.extend_from_slice(forwarder.as_bytes());
    data.extend_from_slice(target.as_bytes());
    CustomAddr::from_parts(PATHS_TRANSPORT_ID, &data)
}

/// The `(forwarder, target)` of a peer relay address.
pub fn parse_peer_relay_addr(addr: &CustomAddr) -> Option<(EndpointId, EndpointId)> {
    let data = addr.data();
    if addr.id() != PATHS_TRANSPORT_ID || data.len() != 65 || data[0] != KIND_PEER_RELAY {
        return None;
    }
    let forwarder = EndpointId::from_bytes(data[1..33].try_into().ok()?).ok()?;
    let target = EndpointId::from_bytes(data[33..65].try_into().ok()?).ok()?;
    Some((forwarder, target))
}

/// Room every forwarder connection starts with: a QUIC packet of the inner
/// connection (at least 1,200 bytes) plus the forwarding header must fit in
/// one datagram from the start, before path MTU discovery has run.
const FORWARDER_INITIAL_MTU: u16 = 1_400;

fn forwarder_connect_options() -> iroh::endpoint::ConnectOptions {
    let config = iroh::endpoint::QuicTransportConfig::builder()
        .initial_mtu(FORWARDER_INITIAL_MTU)
        .build();
    iroh::endpoint::ConnectOptions::new().with_transport_config(config)
}

/// The round-trip time on the path a connection uses now.
fn selected_rtt(conn: &Connection) -> Duration {
    conn.paths()
        .iter()
        .find(|p| p.is_selected())
        .map(|p| p.rtt())
        .unwrap_or_default()
}

/// A packet framed for a forwarder: the other endpoint's id, then the packet.
fn frame(id: &EndpointId, packet: &[u8]) -> Bytes {
    let mut b = BytesMut::with_capacity(32 + packet.len());
    b.put_slice(id.as_bytes());
    b.put_slice(packet);
    b.freeze()
}

fn unframe(datagram: &Bytes) -> Option<(EndpointId, Bytes)> {
    if datagram.len() <= 32 {
        return None;
    }
    let id = EndpointId::from_bytes(datagram[..32].try_into().ok()?).ok()?;
    Some((id, datagram.slice(32..)))
}

/// Packet counts of a [`Paths`] transport or a [`PeerRelayService`].
#[derive(Debug, Default)]
pub struct PathStats {
    /// Packets sent or forwarded.
    pub sent: std::sync::atomic::AtomicU64,
    /// Packets received.
    pub received: std::sync::atomic::AtomicU64,
    /// Packets dropped: no connection, not direct, too large, over the rate,
    /// or for an endpoint not connected.
    pub dropped: std::sync::atomic::AtomicU64,
}

impl PathStats {
    fn add(counter: &std::sync::atomic::AtomicU64) {
        counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// `(sent, received, dropped)` now.
    pub fn snapshot(&self) -> (u64, u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        (
            self.sent.load(Relaxed),
            self.received.load(Relaxed),
            self.dropped.load(Relaxed),
        )
    }
}

#[derive(Debug)]
struct Inner {
    /// This endpoint's id, once attached.
    me: RwLock<Option<EndpointId>>,
    /// The endpoint, while attached, for connecting to forwarders. Holding
    /// it keeps the endpoint's sockets bound, so `detach` drops it.
    endpoint: RwLock<Option<Endpoint>>,
    /// Open connections to forwarders, by forwarder id.
    forwarders: RwLock<HashMap<EndpointId, Connection>>,
    /// Forwarders a connection is being opened to.
    connecting: Mutex<std::collections::HashSet<EndpointId>>,
    /// The addresses this endpoint offers: one per forwarder.
    local: n0_watcher::Watchable<Vec<CustomAddr>>,
    /// Where received packets go: the inbox of the endpoint now bound. Each
    /// bind opens a new one, so the transport serves a later endpoint after
    /// an earlier one closed.
    inbox_tx: RwLock<mpsc::Sender<(CustomAddr, Bytes)>>,
    /// The forwarders this endpoint offers: connected on a direct path and
    /// chosen by round-trip time. Other forwarder connections only carry
    /// packets this endpoint sends.
    offered: RwLock<std::collections::BTreeSet<EndpointId>>,
    stats: PathStats,
    /// Punched paths and the attempts that make them.
    punch: punch::PunchState,
}

/// The node's side of this module: the transport iroh uses, and the
/// forwarders it goes through.
#[derive(Debug, Clone)]
pub struct Paths {
    inner: Arc<Inner>,
}

impl Default for Paths {
    fn default() -> Self {
        Self::new()
    }
}

impl Paths {
    /// A transport with no forwarders yet.
    pub fn new() -> Self {
        let (inbox_tx, _) = mpsc::channel(INBOX);
        Self {
            inner: Arc::new(Inner {
                me: RwLock::new(None),
                endpoint: RwLock::new(None),
                forwarders: RwLock::new(HashMap::new()),
                connecting: Mutex::new(Default::default()),
                local: n0_watcher::Watchable::new(Vec::new()),
                inbox_tx: RwLock::new(inbox_tx),
                offered: RwLock::new(Default::default()),
                stats: PathStats::default(),
                punch: Default::default(),
            }),
        }
    }

    /// Hands the transport to the endpoint being built.
    pub fn install(&self, builder: iroh::endpoint::Builder) -> iroh::endpoint::Builder {
        builder.add_custom_transport(Arc::new(self.clone()))
    }

    /// Binds the transport to the endpoint it was installed in, once bound.
    pub fn attach(&self, endpoint: &Endpoint) {
        *self.inner.me.write() = Some(endpoint.id());
        *self.inner.endpoint.write() = Some(endpoint.clone());
    }

    /// Lets go of the endpoint [`attach`](Self::attach) bound the transport
    /// to, with the forwarder connections made through it, so that endpoint's
    /// sockets are released once its owner closes it. A later `attach` binds
    /// the transport to the next endpoint.
    pub fn detach(&self) {
        *self.inner.me.write() = None;
        *self.inner.endpoint.write() = None;
        self.inner.forwarders.write().clear();
        self.inner.connecting.lock().clear();
        self.inner.offered.write().clear();
    }

    /// The forwarders this endpoint offers paths through.
    pub fn forwarders(&self) -> Vec<EndpointId> {
        self.inner.offered.read().iter().copied().collect()
    }

    /// Offers paths through exactly `ids`, each of which must be connected.
    pub fn offer(&self, ids: &[EndpointId]) {
        let connected = self.inner.forwarders.read();
        *self.inner.offered.write() = ids
            .iter()
            .filter(|id| connected.contains_key(*id))
            .copied()
            .collect();
        drop(connected);
        self.publish_local();
    }

    /// Packet counts of this transport.
    pub fn stats(&self) -> (u64, u64, u64) {
        self.inner.stats.snapshot()
    }

    /// The round-trip time to each forwarder, on the path in use.
    pub fn forwarder_rtts(&self) -> Vec<(EndpointId, Duration)> {
        self.inner
            .forwarders
            .read()
            .iter()
            .map(|(id, c)| (*id, selected_rtt(c)))
            .collect()
    }

    /// Whether the connection to the forwarder `id` runs on a direct path.
    pub fn forwarder_is_direct(&self, id: &EndpointId) -> bool {
        self.inner
            .forwarders
            .read()
            .get(id)
            .is_some_and(|c| c.paths().iter().any(|p| p.is_selected() && p.is_ip()))
    }

    fn publish_local(&self) {
        let Some(me) = *self.inner.me.read() else {
            return;
        };
        let mut addrs: Vec<CustomAddr> = self
            .forwarders()
            .into_iter()
            .map(|f| peer_relay_addr(f, me))
            .collect();
        if !self.inner.punch.punched.lock().is_empty() {
            addrs.push(punched_addr(me));
        }
        let _ = self.inner.local.set(addrs);
    }

    /// Keeps a connection to the forwarder `addr` and offers the path
    /// through it. A forwarder already connected is kept as it is.
    pub async fn connect_forwarder(&self, addr: EndpointAddr) -> io::Result<Duration> {
        let id = addr.id;
        if let Some(c) = self.inner.forwarders.read().get(&id) {
            return Ok(selected_rtt(c));
        }
        let endpoint = self
            .inner
            .endpoint
            .read()
            .clone()
            .ok_or_else(|| io::Error::other("transport not attached"))?;
        let conn = endpoint
            .connect_with_opts(addr, ALPN_PEER_RELAY, forwarder_connect_options())
            .await
            .map_err(io::Error::other)?
            .await
            .map_err(io::Error::other)?;
        let rtt = selected_rtt(&conn);
        self.adopt(id, conn);
        Ok(rtt)
    }

    /// Drops the connection to the forwarder `id`.
    pub fn drop_forwarder(&self, id: &EndpointId) {
        if let Some(c) = self.inner.forwarders.write().remove(id) {
            c.close(0u32.into(), b"not chosen");
        }
        self.inner.offered.write().remove(id);
        self.publish_local();
    }

    /// The forwarders this endpoint holds a connection to.
    pub fn connected_forwarders(&self) -> Vec<EndpointId> {
        self.inner.forwarders.read().keys().copied().collect()
    }

    fn adopt(&self, id: EndpointId, conn: Connection) {
        self.inner.forwarders.write().insert(id, conn.clone());
        let this = self.clone();
        tokio::spawn(async move {
            while let Ok(datagram) = conn.read_datagram().await {
                let Some((from, packet)) = unframe(&datagram) else {
                    continue;
                };
                PathStats::add(&this.inner.stats.received);
                if this
                    .inner
                    .inbox_tx
                    .read()
                    .try_send((peer_relay_addr(id, from), packet))
                    .is_err()
                {
                    PathStats::add(&this.inner.stats.dropped);
                }
            }
            let mut held = this.inner.forwarders.write();
            if held
                .get(&id)
                .is_some_and(|c| c.stable_id() == conn.stable_id())
            {
                held.remove(&id);
                drop(held);
                this.inner.offered.write().remove(&id);
            }
            this.publish_local();
        });
    }

    /// Opens a connection to `forwarder` in the background, so a peer that
    /// offers a path through a forwarder this endpoint has no connection to
    /// becomes reachable on the next packet.
    fn connect_in_background(&self, forwarder: EndpointId) {
        if Some(forwarder) == *self.inner.me.read()
            || !self.inner.connecting.lock().insert(forwarder)
        {
            return;
        }
        let this = self.clone();
        tokio::spawn(async move {
            if let Err(e) = this.connect_forwarder(EndpointAddr::new(forwarder)).await {
                tracing::debug!(forwarder = %forwarder, error = %e, "peer relay unreachable");
            }
            this.inner.connecting.lock().remove(&forwarder);
        });
    }
}

impl CustomTransport for Paths {
    fn bind(&self) -> io::Result<Box<dyn CustomEndpoint>> {
        let (inbox_tx, inbox) = mpsc::channel(INBOX);
        *self.inner.inbox_tx.write() = inbox_tx;
        Ok(Box::new(PathsEndpoint {
            paths: self.clone(),
            inbox,
        }))
    }
}

#[derive(Debug)]
struct PathsEndpoint {
    paths: Paths,
    inbox: mpsc::Receiver<(CustomAddr, Bytes)>,
}

impl CustomEndpoint for PathsEndpoint {
    fn watch_local_addrs(&self) -> n0_watcher::Direct<Vec<CustomAddr>> {
        self.paths.inner.local.watch()
    }

    fn create_sender(&self) -> Arc<dyn CustomSender> {
        Arc::new(PathsSender {
            paths: self.paths.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        metas: &mut [noq_udp::RecvMeta],
        recv_infos: &mut [RecvInfo],
    ) -> Poll<io::Result<usize>> {
        let n = bufs.len().min(metas.len()).min(recv_infos.len());
        if n == 0 {
            return Poll::Ready(Ok(0));
        }
        let mut packets = Vec::with_capacity(n);
        match self.inbox.poll_recv_many(cx, &mut packets, n) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(0) => return Poll::Ready(Err(io::Error::other("paths inbox closed"))),
            Poll::Ready(_) => {}
        }
        let mut filled = 0;
        for (from, packet) in packets {
            if bufs[filled].len() < packet.len() {
                continue;
            }
            bufs[filled][..packet.len()].copy_from_slice(&packet);
            let local = match parse_peer_relay_addr(&from) {
                Some((f, _)) => (*self.paths.inner.me.read()).map(|me| peer_relay_addr(f, me)),
                None => (*self.paths.inner.me.read()).map(punched_addr),
            };
            recv_infos[filled] = RecvInfo::new(from, local);
            metas[filled].len = packet.len();
            metas[filled].stride = packet.len();
            filled += 1;
        }
        if filled == 0 {
            Poll::Pending
        } else {
            Poll::Ready(Ok(filled))
        }
    }
}

#[derive(Debug)]
struct PathsSender {
    paths: Paths,
}

impl CustomSender for PathsSender {
    fn is_valid_send_addr(&self, addr: &CustomAddr) -> bool {
        parse_peer_relay_addr(addr).is_some() || parse_punched_addr(addr).is_some()
    }

    fn poll_send(
        &self,
        _cx: &mut Context,
        dst: &CustomAddr,
        _src: Option<&CustomAddr>,
        transmit: &Transmit<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(peer) = parse_punched_addr(dst) {
            let path = self.paths.inner.punch.punched.lock().get(&peer).cloned();
            let stats = &self.paths.inner.stats;
            let segment = transmit
                .segment_size
                .unwrap_or(transmit.contents.len())
                .max(1);
            for packet in transmit.contents.chunks(segment) {
                match path.as_ref().map(|p| p.send(packet)) {
                    Some(true) => PathStats::add(&stats.sent),
                    _ => PathStats::add(&stats.dropped),
                }
            }
            return Poll::Ready(Ok(()));
        }
        let Some((forwarder, target)) = parse_peer_relay_addr(dst) else {
            return Poll::Ready(Err(io::Error::other("not a paths address")));
        };
        let conn = self.paths.inner.forwarders.read().get(&forwarder).cloned();
        let stats = &self.paths.inner.stats;
        let Some(conn) = conn else {
            // Lost, like any packet on a path not open yet; the connection
            // opens in the background and the next packet goes through.
            self.paths.connect_in_background(forwarder);
            PathStats::add(&stats.dropped);
            return Poll::Ready(Ok(()));
        };
        // A forwarder reached only through a relay adds a hop and nothing
        // else: such a path stays silent and iroh keeps the relay path.
        if !conn.paths().iter().any(|p| p.is_selected() && p.is_ip()) {
            PathStats::add(&stats.dropped);
            return Poll::Ready(Ok(()));
        }
        let segment = transmit
            .segment_size
            .unwrap_or(transmit.contents.len())
            .max(1);
        for packet in transmit.contents.chunks(segment) {
            // A datagram the connection cannot carry is lost like a packet
            // a network drops; QUIC on the inner connection recovers.
            match conn.send_datagram(frame(&target, packet)) {
                Ok(()) => PathStats::add(&stats.sent),
                Err(_) => PathStats::add(&stats.dropped),
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// What a forwarder holds at most.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerRelayLimits {
    /// Most client connections at once.
    pub max_clients: usize,
    /// Bytes per second forwarded from one client.
    pub bytes_per_second: u64,
    /// Bytes one client may send in a burst above that rate.
    pub burst_bytes: u64,
}

impl Default for PeerRelayLimits {
    fn default() -> Self {
        Self {
            max_clients: 4_096,
            bytes_per_second: 4 * 1024 * 1024,
            burst_bytes: 8 * 1024 * 1024,
        }
    }
}

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

impl Bucket {
    fn take(&mut self, limits: &PeerRelayLimits, bytes: usize) -> bool {
        let now = Instant::now();
        let refill = now.duration_since(self.at).as_secs_f64() * limits.bytes_per_second as f64;
        self.tokens = (self.tokens + refill).min(limits.burst_bytes as f64);
        self.at = now;
        if self.tokens >= bytes as f64 {
            self.tokens -= bytes as f64;
            true
        } else {
            false
        }
    }
}

/// The forwarder side: passes packets between the endpoints connected to it.
#[derive(Debug, Clone)]
pub struct PeerRelayService {
    clients: Arc<RwLock<HashMap<EndpointId, Connection>>>,
    limits: PeerRelayLimits,
    stats: Arc<PathStats>,
    /// The UDP socket that tells a punch socket its public address.
    observer: Arc<tokio::sync::OnceCell<punch::Observer>>,
}

impl PeerRelayService {
    /// A forwarder within `limits`.
    pub fn new(limits: PeerRelayLimits) -> Self {
        Self {
            clients: Arc::new(RwLock::new(HashMap::new())),
            limits,
            stats: Arc::new(PathStats::default()),
            observer: Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    /// `(forwarded, received, dropped)` packet counts.
    pub fn stats(&self) -> (u64, u64, u64) {
        self.stats.snapshot()
    }

    /// Endpoints connected now.
    pub fn clients(&self) -> usize {
        self.clients.read().len()
    }
}

impl ProtocolHandler for PeerRelayService {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let me = conn.remote_id();
        {
            let mut clients = self.clients.write();
            if clients.len() >= self.limits.max_clients && !clients.contains_key(&me) {
                conn.close(1u32.into(), b"forwarder full");
                return Ok(());
            }
            if let Some(old) = clients.insert(me, conn.clone()) {
                old.close(0u32.into(), b"replaced");
            }
        }
        // A client asks on a stream where to check its punch socket's
        // public address.
        let observer = self.observer.clone();
        let streams = conn.clone();
        tokio::spawn(async move {
            while let Ok((mut send, mut recv)) = streams.accept_bi().await {
                let Ok(ask) = recv.read_to_end(16).await else {
                    break;
                };
                if ask != b"observe" {
                    continue;
                }
                let Ok(o) = observer.get_or_try_init(punch::Observer::spawn).await else {
                    continue;
                };
                let _ = send.write_all(o.port().to_string().as_bytes()).await;
                let _ = send.finish();
            }
        });
        let mut bucket = Bucket {
            tokens: self.limits.burst_bytes as f64,
            at: Instant::now(),
        };
        while let Ok(datagram) = conn.read_datagram().await {
            PathStats::add(&self.stats.received);
            if !bucket.take(&self.limits, datagram.len()) {
                PathStats::add(&self.stats.dropped);
                continue;
            }
            let Some((to, packet)) = unframe(&datagram) else {
                continue;
            };
            // Addressed to itself, a datagram comes straight back: the
            // check that this forwarder forwards.
            let target = if to == me {
                Some(conn.clone())
            } else {
                self.clients.read().get(&to).cloned()
            };
            match target.map(|t| t.send_datagram(frame(&me, &packet))) {
                Some(Ok(())) => PathStats::add(&self.stats.sent),
                _ => PathStats::add(&self.stats.dropped),
            }
        }
        let mut clients = self.clients.write();
        if clients
            .get(&me)
            .is_some_and(|c| c.stable_id() == conn.stable_id())
        {
            clients.remove(&me);
        }
        Ok(())
    }
}

/// Whether the forwarder `forwarder` passes a datagram: one sent addressed to
/// the sender itself must come back within `wait`.
pub async fn forwarder_answers(
    endpoint: &Endpoint,
    forwarder: EndpointAddr,
    wait: Duration,
) -> bool {
    let probe = async {
        let conn = endpoint.connect(forwarder, ALPN_PEER_RELAY).await.ok()?;
        let nonce: [u8; 16] = rand::random();
        // A datagram may be lost on the way there or back, so it is sent
        // again until one comes back.
        let mut again = tokio::time::interval(Duration::from_millis(500));
        loop {
            tokio::select! {
                _ = again.tick() => {
                    conn.send_datagram(frame(&endpoint.id(), &nonce)).ok()?;
                }
                answer = conn.read_datagram() => {
                    let answer = answer.ok()?;
                    if unframe(&answer).is_some_and(|(_, echoed)| echoed.as_ref() == nonce) {
                        break;
                    }
                }
            }
        }
        conn.close(0u32.into(), b"checked");
        Some(true)
    };
    matches!(tokio::time::timeout(wait, probe).await, Ok(Some(true)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    #[test]
    fn a_peer_relay_address_round_trips_and_nothing_else_parses() {
        let a = peer_relay_addr(id(1), id(2));
        assert_eq!(parse_peer_relay_addr(&a), Some((id(1), id(2))));
        assert_eq!(
            parse_peer_relay_addr(&CustomAddr::from_parts(PATHS_TRANSPORT_ID + 1, &[0; 65])),
            None
        );
        assert_eq!(
            parse_peer_relay_addr(&CustomAddr::from_parts(PATHS_TRANSPORT_ID, &[1; 3])),
            None
        );
    }

    #[test]
    fn framing_round_trips_and_refuses_empty_packets() {
        let f = frame(&id(3), b"quic");
        assert_eq!(unframe(&f), Some((id(3), Bytes::from_static(b"quic"))));
        assert_eq!(unframe(&Bytes::copy_from_slice(&f[..32])), None);
    }

    #[test]
    fn one_client_cannot_exceed_its_rate() {
        let limits = PeerRelayLimits {
            max_clients: 1,
            bytes_per_second: 1_000,
            burst_bytes: 2_000,
        };
        let mut bucket = Bucket {
            tokens: 2_000.0,
            at: Instant::now(),
        };
        assert!(bucket.take(&limits, 1_500));
        assert!(!bucket.take(&limits, 1_500), "the burst is spent");
    }
}
