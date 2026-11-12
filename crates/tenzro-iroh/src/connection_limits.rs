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
//! The per-peer bound keys on the peer's endpoint id. The overall bounds are
//! what hold when a flood arrives under many ids.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use iroh::EndpointId;
use iroh::endpoint::{Connection, IdleTimeout, Incoming, QuicTransportConfig, VarInt};
use iroh::protocol::{
    AcceptError, DynProtocolHandler, IncomingFilterOutcome, ProtocolHandler, Router, RouterBuilder,
};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::consensus::ALPN_CONSENSUS;
use crate::identity_gate::{Admit, IdentityGate};

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
        }
    }
}

impl ConnectionLimits {
    /// The QUIC transport config every connection of the endpoint runs
    /// under: BBRv3 in place of the default loss-based controller (cubic).
    /// Loss-based control reads random packet loss as congestion and
    /// collapses its window; BBR models the path's bottleneck bandwidth and
    /// round-trip time instead, so it holds throughput under the kind of
    /// uncorrelated loss a lossy link produces. The stream, window and idle
    /// limits are this table's.
    pub fn transport_config(&self) -> QuicTransportConfig {
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
            .build()
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
            }),
        }
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
        // handler returns first.
        let held = conn.clone();
        tokio::spawn(async move {
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
        let endpoint = crate::identity_transport::base_builder_with(&limits)
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
        crate::identity_transport::base_builder()
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
}
