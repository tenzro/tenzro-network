//! How many connections the endpoint holds, and how much each may carry.
//!
//! [`ConnectionLimits`] is the `[iroh.connection]` table of the node config.
//! It sets the QUIC limits every connection of the endpoint runs under (idle
//! timeout, concurrent streams, connection-wide receive window) and the
//! number of connections the endpoint keeps open from peers it has not
//! vetted:
//!
//! - Two pools. Connections on the consensus protocol count against their
//!   own pool, so a flood on every other protocol cannot take their places
//!   and a flood on the consensus protocol cannot take the others'. Each
//!   pool has a bound overall and a bound per peer.
//! - [`ConnectionGate::incoming_filter`] runs before the handshake: once the
//!   two pools together are full, a new attempt is refused without a
//!   handshake being spent on it.
//! - [`GatedRouter`] counts each accepted connection against its pool until
//!   the connection closes and closes an excess one with
//!   [`REFUSED_CONNECTIONS`]. A connection already established is never
//!   closed to make room.
//!
//! The router is also the one place every accepted connection passes, so it
//! is where the time a connection takes to reach a direct path is measured
//! ([`crate::path_metrics::PathTimings`]).
//!
//! The per-peer bound keys on the peer's endpoint id. The overall bounds are
//! what hold when a flood arrives under many ids.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use iroh::EndpointId;
use iroh::endpoint::{
    Connection, IdleTimeout, Incoming, QuicTransportConfig, QuicTransportConfigBuilder, VarInt,
};
use iroh::protocol::{
    AcceptError, DynProtocolHandler, IncomingFilterOutcome, ProtocolHandler, Router, RouterBuilder,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::consensus::ALPN_CONSENSUS;
use crate::identity_gate::{Admit, IdentityGate};
use crate::path_metrics::PathTimings;

/// Application close code for a connection closed because its pool or its
/// peer is at its bound.
pub const REFUSED_CONNECTIONS: u32 = 4;

/// The `[iroh.connection]` table: connection counts and QUIC limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ConnectionLimits {
    /// Connections held open at once on every protocol except consensus.
    pub max_connections: usize,
    /// Connections held open at once from one peer on those protocols.
    pub max_connections_per_peer: usize,
    /// Connections held open at once on the consensus protocol.
    pub max_consensus_connections: usize,
    /// Connections held open at once from one peer on the consensus protocol.
    pub max_consensus_connections_per_peer: usize,
    /// Seconds without traffic after which a connection is closed. Every
    /// connection sends a keep-alive well inside it.
    pub idle_timeout_secs: u64,
    /// Bidirectional streams a peer may have open on one connection.
    pub max_concurrent_bidi_streams: u32,
    /// Unidirectional streams a peer may have open on one connection.
    pub max_concurrent_uni_streams: u32,
    /// Bytes a peer may have in flight to this endpoint on one connection,
    /// across all its streams.
    pub receive_window_bytes: u32,
    /// Bytes of datagrams a peer-relay connection holds until they are
    /// forwarded, held to 64 KiB..16 MiB. No other connection accepts
    /// datagrams, so no other connection holds any.
    pub peer_relay_datagram_buffer_bytes: usize,
    /// Bytes of datagrams all the endpoint's connections may hold between
    /// them: each connection's buffer is at most this divided by the number of
    /// connections the endpoint admits (both pools), so that a forwarder with
    /// every place taken stays within it. The floor of 64 KiB a connection
    /// keeps can lift the total above a very small budget.
    pub peer_relay_datagram_budget_bytes: usize,
}

impl Default for ConnectionLimits {
    fn default() -> Self {
        Self {
            max_connections: 1024,
            max_connections_per_peer: 8,
            max_consensus_connections: 512,
            max_consensus_connections_per_peer: 4,
            idle_timeout_secs: 30,
            max_concurrent_bidi_streams: 100,
            max_concurrent_uni_streams: 100,
            receive_window_bytes: 32 * 1024 * 1024,
            peer_relay_datagram_buffer_bytes: 1_250_000,
            peer_relay_datagram_budget_bytes: 192 * 1024 * 1024,
        }
    }
}

/// Bounds of [`ConnectionLimits::peer_relay_datagram_buffer_bytes`].
const PEER_RELAY_DATAGRAM_BUFFER: std::ops::RangeInclusive<usize> = 64 * 1024..=16 * 1024 * 1024;

/// Room every forwarder connection starts with: a QUIC packet of the inner
/// connection (at least 1,200 bytes) plus the forwarding header must fit in
/// one datagram from the start, before path MTU discovery has run.
const FORWARDER_INITIAL_MTU: u16 = 1_400;

impl ConnectionLimits {
    /// The QUIC transport config every connection of the endpoint runs
    /// under: BBRv3 in place of the default loss-based controller (cubic).
    /// Loss-based control reads random packet loss as congestion and
    /// collapses its window; BBR models the path's bottleneck bandwidth and
    /// round-trip time instead, so it holds throughput under the kind of
    /// uncorrelated loss a lossy link produces. The stream, window and idle
    /// limits are this table's.
    ///
    /// Only an endpoint that forwards for the peer relay accepts datagrams
    /// on the connections it accepts: the transport sets that per endpoint,
    /// before a connection's protocol is known. Every other endpoint offers
    /// peers no datagram buffer at all.
    pub fn transport_config(&self, serves_peer_relay: bool) -> QuicTransportConfig {
        self.builder()
            .datagram_receive_buffer_size(
                serves_peer_relay.then(|| self.peer_relay_datagram_buffer()),
            )
            .build()
    }

    /// The transport config of a connection this endpoint opens on the peer
    /// relay protocol: the endpoint's own, with a datagram buffer and an
    /// initial MTU that fits a forwarded packet.
    pub fn peer_relay_transport_config(&self) -> QuicTransportConfig {
        self.builder()
            .initial_mtu(FORWARDER_INITIAL_MTU)
            .datagram_receive_buffer_size(Some(self.peer_relay_datagram_buffer()))
            .build()
    }

    /// The datagram buffer of one connection: what the table asks for, within its share of the
    /// endpoint's budget and the bounds. It only has to hold the datagrams that arrive while the
    /// forwarder has not yet read them, not what is in flight on the path.
    fn peer_relay_datagram_buffer(&self) -> usize {
        let places = self
            .max_connections
            .saturating_add(self.max_consensus_connections)
            .max(1);
        self.peer_relay_datagram_buffer_bytes
            .min(self.peer_relay_datagram_budget_bytes / places)
            .clamp(
                *PEER_RELAY_DATAGRAM_BUFFER.start(),
                *PEER_RELAY_DATAGRAM_BUFFER.end(),
            )
    }

    fn builder(&self) -> QuicTransportConfigBuilder {
        let idle = IdleTimeout::try_from(Duration::from_secs(self.idle_timeout_secs.max(1)))
            .unwrap_or(IdleTimeout::from(VarInt::from_u32(30_000)));
        QuicTransportConfig::builder()
            .congestion_controller_factory(Arc::new(noq_proto::congestion::Bbr3Config::default()))
            .max_idle_timeout(Some(idle))
            // Every path of a connection, the direct one included, carries a
            // keep-alive, so the direct path stays open and a relay outage
            // finds it already there.
            .default_path_keep_alive_interval(Duration::from_secs(4))
            .max_concurrent_bidi_streams(VarInt::from_u32(self.max_concurrent_bidi_streams))
            .max_concurrent_uni_streams(VarInt::from_u32(self.max_concurrent_uni_streams))
            .receive_window(VarInt::from_u32(self.receive_window_bytes))
    }
}

#[derive(Debug, Default)]
struct Pool {
    total: usize,
    per_peer: HashMap<EndpointId, usize>,
}

/// Which pool a connection counts against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Consensus,
    General,
}

impl Class {
    fn of(alpn: &[u8]) -> Self {
        if alpn == ALPN_CONSENSUS {
            Self::Consensus
        } else {
            Self::General
        }
    }
}

#[derive(Debug)]
struct GateInner {
    limits: ConnectionLimits,
    consensus: Mutex<Pool>,
    general: Mutex<Pool>,
    /// Connections held in both pools, read without a lock by the filter.
    live: AtomicUsize,
    path_timings: Arc<PathTimings>,
}

/// The connections the endpoint holds, counted against
/// [`ConnectionLimits`].
#[derive(Debug, Clone)]
pub struct ConnectionGate {
    inner: Arc<GateInner>,
}

/// One admitted connection. Dropping it frees its place.
#[derive(Debug)]
pub struct ConnectionPermit {
    gate: Arc<GateInner>,
    class: Class,
    peer: EndpointId,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        let pool = match self.class {
            Class::Consensus => &self.gate.consensus,
            Class::General => &self.gate.general,
        };
        let mut pool = pool.lock();
        pool.total = pool.total.saturating_sub(1);
        if let Some(n) = pool.per_peer.get_mut(&self.peer) {
            *n -= 1;
            if *n == 0 {
                pool.per_peer.remove(&self.peer);
            }
        }
        self.gate.live.fetch_sub(1, Ordering::Relaxed);
    }
}

impl ConnectionGate {
    /// A gate holding connections up to `limits`.
    pub fn new(limits: ConnectionLimits) -> Self {
        Self {
            inner: Arc::new(GateInner {
                limits,
                consensus: Mutex::new(Pool::default()),
                general: Mutex::new(Pool::default()),
                live: AtomicUsize::new(0),
                path_timings: Arc::default(),
            }),
        }
    }

    /// How long the connections this gate admitted took to reach a direct
    /// path.
    pub fn path_timings(&self) -> Arc<PathTimings> {
        self.inner.path_timings.clone()
    }

    /// Connections held now, in both pools.
    pub fn live(&self) -> usize {
        self.inner.live.load(Ordering::Relaxed)
    }

    fn admit(&self, class: Class, peer: EndpointId) -> Option<ConnectionPermit> {
        let limits = &self.inner.limits;
        let (pool, max, max_per_peer) = match class {
            Class::Consensus => (
                &self.inner.consensus,
                limits.max_consensus_connections,
                limits.max_consensus_connections_per_peer,
            ),
            Class::General => (
                &self.inner.general,
                limits.max_connections,
                limits.max_connections_per_peer,
            ),
        };
        let mut pool = pool.lock();
        if pool.total >= max {
            return None;
        }
        let held = pool.per_peer.get(&peer).copied().unwrap_or(0);
        if held >= max_per_peer {
            return None;
        }
        pool.total += 1;
        pool.per_peer.insert(peer, held + 1);
        self.inner.live.fetch_add(1, Ordering::Relaxed);
        Some(ConnectionPermit {
            gate: self.inner.clone(),
            class,
            peer,
        })
    }

    /// The decision on a new attempt before its handshake: refused once both
    /// pools are full, so a flood past the bound costs no handshake.
    pub fn incoming_filter(&self, _incoming: &Incoming) -> IncomingFilterOutcome {
        if self.at_ceiling() {
            IncomingFilterOutcome::Reject
        } else {
            IncomingFilterOutcome::Accept
        }
    }

    fn at_ceiling(&self) -> bool {
        let limits = &self.inner.limits;
        self.live()
            >= limits
                .max_connections
                .saturating_add(limits.max_consensus_connections)
    }
}

/// A protocol handler that counts each connection it is given against the
/// gate and closes one that does not fit.
struct Gated<P> {
    inner: P,
    gate: ConnectionGate,
    class: Class,
    identity: Option<IdentityGate>,
}

impl<P> std::fmt::Debug for Gated<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Gated").field("class", &self.class).finish()
    }
}

impl<P: ProtocolHandler> ProtocolHandler for Gated<P> {
    async fn on_accepting(
        &self,
        accepting: iroh::endpoint::Accepting,
    ) -> Result<Connection, AcceptError> {
        self.inner.on_accepting(accepting).await
    }

    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        // Who may use this protocol at all comes first: a refused peer takes
        // no place in the pools.
        if let Some(identity) = &self.identity
            && let Admit::Refuse { code, reason } = identity.admit(&conn).await
        {
            conn.close(code.into(), reason.as_bytes());
            return Ok(());
        }
        let Some(permit) = self.gate.admit(self.class, conn.remote_id()) else {
            tracing::debug!(target: "tenzro_iroh::limits", "connection refused: at its bound");
            conn.close(REFUSED_CONNECTIONS.into(), b"connection limit");
            return Ok(());
        };
        // The place is held until the connection closes, whether or not the
        // handler returns first. The same task times its first direct path.
        let held = conn.clone();
        let timings = self.gate.path_timings();
        tokio::spawn(async move {
            timings.observe(&held).await;
            held.closed().await;
            drop(permit);
        });
        self.inner.accept(conn).await
    }

    async fn shutdown(&self) {
        self.inner.shutdown().await
    }
}

/// A [`RouterBuilder`] that gates every protocol registered on it.
pub struct GatedRouter {
    builder: RouterBuilder,
    gate: ConnectionGate,
    identity: Option<IdentityGate>,
}

impl GatedRouter {
    /// Gates the router `builder` builds with `gate`, and refuses attempts
    /// the gate has no room for before their handshake.
    pub fn new(builder: RouterBuilder, gate: ConnectionGate) -> Self {
        let filter = gate.clone();
        let builder =
            builder.incoming_filter(Arc::new(move |incoming| filter.incoming_filter(incoming)));
        Self {
            builder,
            gate,
            identity: None,
        }
    }

    /// Admits peers to each protocol by registered identity (see
    /// [`crate::identity_gate`]). Protocols registered after this call are
    /// gated; call it before [`Self::accept`].
    pub fn with_identity_gate(mut self, identity: IdentityGate) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Serves `alpn` with `handler`, under the pool the protocol counts in.
    pub fn accept<P: ProtocolHandler>(mut self, alpn: impl AsRef<[u8]>, handler: P) -> Self {
        let gated: Box<dyn DynProtocolHandler> = Box::new(Gated {
            inner: handler,
            gate: self.gate.clone(),
            class: Class::of(alpn.as_ref()),
            identity: self.identity.clone(),
        });
        self.builder = self.builder.accept(alpn, gated);
        self
    }

    /// Starts accepting.
    pub fn spawn(self) -> Router {
        self.builder.spawn()
    }
}

#[cfg(test)]
#[expect(
    clippy::disallowed_methods,
    reason = "the test runner bounds every wait in a test"
)]
mod tests {
    use super::*;
    use iroh::Endpoint;
    use iroh::endpoint::ConnectionError;

    const GENERAL_ALPN: &[u8] = b"tenzro/test/general";

    /// Holds every connection open until the peer closes it, answering one
    /// echo on the first stream.
    #[derive(Debug, Clone)]
    struct Hold;

    impl ProtocolHandler for Hold {
        async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
            while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                let msg = recv
                    .read_to_end(1024)
                    .await
                    .map_err(AcceptError::from_err)?;
                send.write_all(&msg).await.map_err(AcceptError::from_err)?;
                send.finish().map_err(AcceptError::from_err)?;
            }
            conn.closed().await;
            Ok(())
        }
    }

    fn limits(general: usize, per_peer: usize, consensus: usize) -> ConnectionLimits {
        ConnectionLimits {
            max_connections: general,
            max_connections_per_peer: per_peer,
            max_consensus_connections: consensus,
            max_consensus_connections_per_peer: 2,
            ..ConnectionLimits::default()
        }
    }

    async fn serve(limits: ConnectionLimits) -> (Endpoint, Router, ConnectionGate) {
        let endpoint = crate::identity_transport::on_loopback(
            crate::identity_transport::base_builder_with(&limits, false),
        )
        .bind()
        .await
        .unwrap();
        let gate = ConnectionGate::new(limits);
        let router = GatedRouter::new(Router::builder(endpoint.clone()), gate.clone())
            .accept(ALPN_CONSENSUS, Hold)
            .accept(GENERAL_ALPN, Hold)
            .spawn();
        (endpoint, router, gate)
    }

    async fn client() -> Endpoint {
        crate::identity_transport::on_loopback(crate::identity_transport::base_builder())
            .bind()
            .await
            .unwrap()
    }

    /// Whether the server closed `conn` as over its bound.
    async fn refused(conn: &Connection) -> bool {
        match tokio::time::timeout(Duration::from_millis(1500), conn.closed()).await {
            Ok(ConnectionError::ApplicationClosed(close)) => {
                close.error_code == VarInt::from_u32(REFUSED_CONNECTIONS)
            }
            _ => false,
        }
    }

    async fn echoes(conn: &Connection) -> bool {
        let Ok((mut send, mut recv)) = conn.open_bi().await else {
            return false;
        };
        if send.write_all(b"ping").await.is_err() || send.finish().is_err() {
            return false;
        }
        matches!(
            tokio::time::timeout(Duration::from_secs(5), recv.read_to_end(16)).await,
            Ok(Ok(reply)) if reply == b"ping"
        )
    }

    #[test]
    fn the_defaults_are_the_documented_values() {
        let l = ConnectionLimits::default();
        assert_eq!(l.max_connections, 1024);
        assert_eq!(l.max_connections_per_peer, 8);
        assert_eq!(l.max_consensus_connections, 512);
        assert_eq!(l.max_consensus_connections_per_peer, 4);
        assert_eq!(l.idle_timeout_secs, 30);
        assert_eq!(l.max_concurrent_bidi_streams, 100);
        assert_eq!(l.max_concurrent_uni_streams, 100);
        assert_eq!(l.receive_window_bytes, 32 * 1024 * 1024);
    }

    #[test]
    fn every_place_of_a_forwarder_taken_stays_within_the_datagram_budget() {
        let l = ConnectionLimits::default();
        let places = l.max_connections + l.max_consensus_connections;
        assert!(
            l.peer_relay_datagram_buffer() * places <= l.peer_relay_datagram_budget_bytes,
            "{} bytes a connection, {places} places, budget {}",
            l.peer_relay_datagram_buffer(),
            l.peer_relay_datagram_budget_bytes
        );
        // A larger request or a larger pool does not lift the total above the budget either,
        // while a connection's share stays above the least buffer a connection gets.
        let wide = ConnectionLimits {
            peer_relay_datagram_buffer_bytes: 16 * 1024 * 1024,
            max_connections: 2048,
            ..l
        };
        let places = wide.max_connections + wide.max_consensus_connections;
        assert!(
            wide.peer_relay_datagram_buffer() * places <= wide.peer_relay_datagram_budget_bytes
        );
        // A pool so large that its share is below that least buffer gives each connection the
        // least buffer, which is the one case above the budget: the budget is 192 MiB and the
        // least buffer 64 KiB, so it takes more than 3,072 places.
        let huge = ConnectionLimits {
            max_connections: 4096,
            ..ConnectionLimits::default()
        };
        assert_eq!(huge.peer_relay_datagram_buffer(), 64 * 1024);
    }

    #[test]
    fn one_value_can_be_set_without_restating_the_table() {
        let l: ConnectionLimits = serde_json::from_str(r#"{"max_connections": 64}"#).unwrap();
        assert_eq!(l.max_connections, 64);
        assert_eq!(l.max_connections_per_peer, 8);
    }

    #[test]
    fn pools_bound_each_peer_and_the_whole_and_free_a_place_on_drop() {
        let gate = ConnectionGate::new(limits(3, 2, 2));
        let id = |n: u8| iroh::SecretKey::from_bytes(&[n; 32]).public();
        let a1 = gate.admit(Class::General, id(1)).unwrap();
        let _a2 = gate.admit(Class::General, id(1)).unwrap();
        assert!(
            gate.admit(Class::General, id(1)).is_none(),
            "a third from one peer"
        );
        let _b = gate.admit(Class::General, id(2)).unwrap();
        assert!(
            gate.admit(Class::General, id(3)).is_none(),
            "a fourth overall"
        );
        let _c = gate
            .admit(Class::Consensus, id(3))
            .expect("the consensus pool is separate");
        assert_eq!(gate.live(), 4);
        drop(a1);
        assert!(gate.admit(Class::General, id(3)).is_some());
    }

    #[test]
    fn only_the_consensus_protocol_counts_in_the_consensus_pool() {
        assert_eq!(Class::of(ALPN_CONSENSUS), Class::Consensus);
        assert_eq!(Class::of(b"tenzro/gossip"), Class::General);
        assert_eq!(Class::of(b""), Class::General);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn one_peer_over_its_bound_is_refused_and_its_first_connections_stay() {
        let (server, router, _gate) = serve(limits(16, 2, 4)).await;
        let peer = client().await;
        let mut held = Vec::new();
        for _ in 0..2 {
            let conn = peer.connect(server.addr(), GENERAL_ALPN).await.unwrap();
            assert!(echoes(&conn).await);
            held.push(conn);
        }
        let excess = peer.connect(server.addr(), GENERAL_ALPN).await.unwrap();
        assert!(refused(&excess).await, "the third connection is refused");
        for conn in &held {
            assert!(echoes(conn).await, "an established connection survives");
        }
        router.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_flood_of_connections_is_refused_and_consensus_links_survive() {
        const GENERAL_BOUND: usize = 6;
        const FLOOD: usize = 20;
        let (server, router, gate) = serve(limits(GENERAL_BOUND, 2, 4)).await;

        // Two consensus links from distinct peers, established first.
        let mut consensus = Vec::new();
        let mut consensus_peers = Vec::new();
        for _ in 0..2 {
            let peer = client().await;
            let conn = peer.connect(server.addr(), ALPN_CONSENSUS).await.unwrap();
            assert!(echoes(&conn).await);
            consensus.push(conn);
            consensus_peers.push(peer);
        }

        // A flood from many fresh keys on another protocol.
        let mut flood = Vec::new();
        let mut flood_peers = Vec::new();
        for _ in 0..FLOOD {
            let peer = client().await;
            if let Ok(conn) = peer.connect(server.addr(), GENERAL_ALPN).await {
                flood.push(conn);
            }
            flood_peers.push(peer);
        }
        // An attempt is refused either before its handshake (the dial fails)
        // or after it (the server closes the connection).
        let mut kept = 0;
        for conn in &flood {
            if !refused(conn).await {
                kept += 1;
            }
        }
        assert!(kept >= 1, "the bound admits some of the flood");
        assert!(
            kept <= GENERAL_BOUND,
            "{kept} of {FLOOD} flood connections were kept, bound {GENERAL_BOUND}"
        );
        assert!(
            gate.live() <= GENERAL_BOUND + 2,
            "the server holds {} connections, bound {}",
            gate.live(),
            GENERAL_BOUND + 2
        );

        // The links established before the flood still carry traffic, and a
        // new consensus peer is still admitted.
        for conn in &consensus {
            assert!(echoes(conn).await, "a consensus link survived the flood");
        }
        let late = client().await;
        let conn = late.connect(server.addr(), ALPN_CONSENSUS).await.unwrap();
        assert!(
            echoes(&conn).await,
            "a new consensus peer is still admitted"
        );
        router.shutdown().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_transport_config_carries_the_configured_limits() {
        // A server whose streams are limited to one admits one open stream
        // and holds the second until the first ends.
        let limits = ConnectionLimits {
            max_concurrent_bidi_streams: 1,
            ..ConnectionLimits::default()
        };
        let (server, router, _gate) = serve(limits).await;
        let peer = client().await;
        let conn = peer.connect(server.addr(), GENERAL_ALPN).await.unwrap();
        let (_first_send, _first_recv) = conn.open_bi().await.unwrap();
        let second = tokio::time::timeout(Duration::from_millis(500), conn.open_bi()).await;
        assert!(second.is_err(), "a second stream waits behind the bound");
        router.shutdown().await.unwrap();
    }

    /// A connection the router admits is timed to its first direct path; one
    /// it refuses is not.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_admitted_connection_is_timed_to_its_first_direct_path() {
        let (server, router, gate) = serve(limits(16, 1, 4)).await;
        let peer = client().await;
        let conn = peer.connect(server.addr(), GENERAL_ALPN).await.unwrap();
        assert!(echoes(&conn).await);
        let timings = gate.path_timings();
        let counted = async {
            while timings.snapshot().count() < 1 {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        };
        assert!(
            tokio::time::timeout(Duration::from_secs(5), counted)
                .await
                .is_ok(),
            "two endpoints on one machine have a direct path"
        );
        let over = peer.connect(server.addr(), GENERAL_ALPN).await.unwrap();
        assert!(refused(&over).await);
        assert_eq!(timings.snapshot().count(), 1);
        router.shutdown().await.unwrap();
    }

    const DATAGRAM_ALPN: &[u8] = b"tenzro/test/datagram";

    /// Answers each datagram with a datagram holding its length, and accepts
    /// streams without ever reading them.
    #[derive(Debug, Clone)]
    struct DatagramLengths;

    impl ProtocolHandler for DatagramLengths {
        async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
            let mut held = Vec::new();
            loop {
                tokio::select! {
                    datagram = conn.read_datagram() => match datagram {
                        Ok(d) => {
                            let len = u32::try_from(d.len()).unwrap_or(u32::MAX);
                            let _ = conn.send_datagram(len.to_be_bytes().to_vec().into());
                        }
                        Err(_) => break,
                    },
                    stream = conn.accept_bi() => match stream {
                        Ok(stream) => held.push(stream),
                        Err(_) => break,
                    },
                }
            }
            Ok(())
        }
    }

    async fn serve_datagrams(serves_peer_relay: bool) -> (Endpoint, Router) {
        let limits = ConnectionLimits::default();
        let endpoint = crate::identity_transport::on_loopback(
            crate::identity_transport::base_builder_with(&limits, serves_peer_relay),
        )
        .bind()
        .await
        .unwrap();
        let router = GatedRouter::new(
            Router::builder(endpoint.clone()),
            ConnectionGate::new(limits),
        )
        .accept(DATAGRAM_ALPN, DatagramLengths)
        .spawn();
        (endpoint, router)
    }

    /// A connection opened as the peer relay opens one: it accepts datagrams.
    async fn dial_with_datagrams(peer: &Endpoint, server: &Endpoint) -> Connection {
        let options = iroh::endpoint::ConnectOptions::new()
            .with_transport_config(ConnectionLimits::default().peer_relay_transport_config());
        peer.connect_with_opts(server.addr(), DATAGRAM_ALPN, options)
            .await
            .unwrap()
            .await
            .unwrap()
    }

    async fn length_answer(conn: &Connection) -> Option<u32> {
        let answer = tokio::time::timeout(Duration::from_secs(2), conn.read_datagram())
            .await
            .ok()?
            .ok()?;
        Some(u32::from_be_bytes(answer[..].try_into().ok()?))
    }

    /// An endpoint that does not forward for the peer relay offers no
    /// datagram buffer: a peer cannot queue a single datagram on it.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_endpoint_that_reads_no_datagrams_lets_none_be_queued() {
        let (server, router) = serve_datagrams(false).await;
        let peer = client().await;
        let conn = dial_with_datagrams(&peer, &server).await;
        assert_eq!(conn.max_datagram_size(), None);
        assert!(matches!(
            conn.send_datagram(bytes::Bytes::from_static(b"queued?")),
            Err(iroh::endpoint::SendDatagramError::UnsupportedByPeer)
        ));
        router.shutdown().await.unwrap();
    }

    /// A datagram does not wait behind a stream that is stalled on flow
    /// control on the same connection.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_datagram_does_not_wait_behind_a_stalled_stream() {
        let (server, router) = serve_datagrams(true).await;
        let peer = client().await;
        let conn = dial_with_datagrams(&peer, &server).await;
        let (mut send, _recv) = conn.open_bi().await.unwrap();
        // The server never reads the stream, so writes stop once its windows
        // and this side's send buffer are full.
        let filler = vec![0u8; 64 * 1024];
        let fill = async {
            loop {
                send.write_all(&filler).await.unwrap();
            }
        };
        assert!(
            tokio::time::timeout(Duration::from_secs(3), fill)
                .await
                .is_err(),
            "the stream stalls"
        );
        conn.send_datagram(bytes::Bytes::from_static(b"real time"))
            .unwrap();
        assert_eq!(length_answer(&conn).await, Some(9));
        router.shutdown().await.unwrap();
    }

    /// A datagram up to the size the connection states arrives; one byte
    /// more is refused before it is sent.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_datagram_up_to_the_stated_size_arrives_and_a_larger_one_is_refused() {
        let (server, router) = serve_datagrams(true).await;
        let peer = client().await;
        let conn = dial_with_datagrams(&peer, &server).await;
        let max = conn
            .max_datagram_size()
            .expect("the forwarder accepts datagrams");
        assert!(max >= 1_000, "{max} bytes");
        assert!(matches!(
            conn.send_datagram(vec![1u8; max + 1].into()),
            Err(iroh::endpoint::SendDatagramError::TooLarge)
        ));
        conn.send_datagram(vec![2u8; max].into()).unwrap();
        assert_eq!(length_answer(&conn).await, Some(max as u32));
        router.shutdown().await.unwrap();
    }
}
