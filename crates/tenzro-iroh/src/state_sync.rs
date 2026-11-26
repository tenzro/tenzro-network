//! `tenzro/state-sync` ALPN — where a joining node learns which blob holds a
//! peer's snapshot manifest.
//!
//! The snapshot itself travels as ordinary BLAKE3-verified blobs over the
//! blobs ALPN, from any provider that has them. What a joining node needs
//! first is the hash of the manifest blob for a given height, and it asks a
//! peer it names by `EndpointId` over this ALPN. The connection is
//! authenticated to that key by the transport, and the answer is only a
//! pointer: the manifest it names is checked against a state root the joining
//! node already trusts before anything in it is used, so a peer that lies here
//! achieves nothing beyond a failed sync.
//!
//! Wire format, one bidirectional stream per request:
//!
//! ```text
//! request  := height:u64 (big-endian)
//! response := 0x00                      no snapshot at that height
//!           | 0x01 manifest_hash:[u8;32]
//! ```
//!
//! A joining node that holds no checkpoint of its own first asks a peer over
//! [`ALPN_STATE_SYNC_ANCHOR`] for the anchor of the newest snapshot it
//! serves: the block that commits the snapshot's state root, with the
//! certification of the checkpoint covering it. The bytes are opaque here;
//! the node verifies them from its genesis before it trusts the block.
//!
//! ```text
//! request  := (none: the stream is finished at once)
//! response := 0x00                      no certified snapshot anchor
//!           | 0x01 len:u32 (big-endian) anchor:[u8;len]
//!           | 0x02                      asked again too soon
//!           | 0x03                      busy building the anchor, ask again
//! ```
//!
//! Anyone may ask, and an answer can take the node a proof from genesis and
//! a checkpoint's blocks to build, so a remote endpoint is answered at most
//! once per [`ANCHOR_REQUEST_INTERVAL`], an address on the network at most
//! once per [`ANCHOR_ADDRESS_INTERVAL`] (endpoint ids cost nothing to make),
//! and no anchor over [`MAX_ANCHOR_BYTES`] is sent. A table that is full
//! forgets its oldest entry for a new one: a joining node is never refused
//! because other askers filled it.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointId};
use parking_lot::RwLock;
use tracing::{debug, trace, warn};

use crate::error::{IrohError, IrohResult};

/// ALPN for manifest discovery.
pub const ALPN_STATE_SYNC: &[u8] = b"tenzro/state-sync";

/// ALPN for the certified anchor of a peer's newest snapshot.
pub const ALPN_STATE_SYNC_ANCHOR: &[u8] = b"tenzro/state-sync/anchor";

/// Largest anchor a joining node reads: a certification from genesis
/// carries every epoch handover, and a chained one far fewer.
pub const MAX_ANCHOR_BYTES: usize = 16 << 20;

/// Shortest time between two anchors served to one remote endpoint. A
/// joining node asks once per start.
pub const ANCHOR_REQUEST_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);

/// Shortest time between two anchors served to one address on the network:
/// every endpoint id an asker makes still arrives from an address of its own,
/// and several joining nodes may share one.
pub const ANCHOR_ADDRESS_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Most remote endpoints, and most addresses, whose last request is
/// remembered. Past it the oldest entry is forgotten for a new one.
const MAX_PACED_REMOTES: usize = 4_096;

/// What a node serving the anchor has to say about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorAnswer {
    /// The encoded anchor of the newest snapshot.
    Anchor(Vec<u8>),
    /// No snapshot it can certify.
    None,
    /// Another build of the anchor is running and none is kept: ask again.
    Busy,
}

/// When each remote endpoint and each address was last answered.
#[derive(Debug, Default)]
struct Pacing {
    last: parking_lot::Mutex<std::collections::HashMap<EndpointId, tokio::time::Instant>>,
    addresses:
        parking_lot::Mutex<std::collections::HashMap<std::net::IpAddr, tokio::time::Instant>>,
}

/// Records `key` as answered at `now` unless it was answered less than
/// `interval` ago. A full table forgets its expired entries, then its oldest.
fn admit_key<K: Eq + std::hash::Hash + Copy>(
    table: &mut std::collections::HashMap<K, tokio::time::Instant>,
    key: K,
    now: tokio::time::Instant,
    interval: std::time::Duration,
) -> bool {
    if let Some(at) = table.get(&key)
        && now.duration_since(*at) < interval
    {
        return false;
    }
    if table.len() >= MAX_PACED_REMOTES && !table.contains_key(&key) {
        table.retain(|_, at| now.duration_since(*at) < interval);
        if table.len() >= MAX_PACED_REMOTES
            && let Some(oldest) = table.iter().min_by_key(|(_, at)| **at).map(|(k, _)| *k)
        {
            table.remove(&oldest);
        }
    }
    table.insert(key, now);
    true
}

impl Pacing {
    /// Whether `remote`, reaching this node from `address` when it is a
    /// direct path from an address off this machine, may be answered at
    /// `now`; if so, records it. An address that is refused records nothing
    /// for the endpoint, and the other way round.
    fn admit(
        &self,
        remote: EndpointId,
        address: Option<std::net::IpAddr>,
        now: tokio::time::Instant,
    ) -> bool {
        let mut last = self.last.lock();
        if let Some(at) = last.get(&remote)
            && now.duration_since(*at) < ANCHOR_REQUEST_INTERVAL
        {
            return false;
        }
        if let Some(ip) = address
            && !admit_key(&mut self.addresses.lock(), ip, now, ANCHOR_ADDRESS_INTERVAL)
        {
            return false;
        }
        admit_key(&mut last, remote, now, ANCHOR_REQUEST_INTERVAL)
    }
}

/// The address on the network `conn` reaches this node from, when it has a
/// direct path from one off this machine: a loopback address is this
/// machine's own, and a relayed connection shows none.
fn remote_address(conn: &Connection) -> Option<std::net::IpAddr> {
    let selected = conn
        .paths()
        .iter()
        .filter_map(|p| match p.remote_addr() {
            iroh::TransportAddr::Ip(addr) => Some((p.is_selected(), addr.ip())),
            _ => None,
        })
        .max_by_key(|(selected, _)| *selected)
        .map(|(_, ip)| ip)?;
    let ip = match selected {
        std::net::IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map_or(std::net::IpAddr::V6(v6), std::net::IpAddr::V4),
        v4 => v4,
    };
    (!ip.is_loopback() && !ip.is_unspecified()).then_some(ip)
}

/// A serving node's snapshot directory: the manifest blob for a height.
#[async_trait]
pub trait SnapshotDirectory: Send + Sync + fmt::Debug + 'static {
    /// BLAKE3 hash of the manifest blob for the snapshot at `height`, if this
    /// node holds one.
    async fn manifest_for(&self, height: u64) -> Option<[u8; 32]>;
}

/// A directory installed after the endpoint is bound. Until then every
/// request is answered "no snapshot".
#[derive(Debug, Clone, Default)]
pub struct DeferredSnapshotDirectory {
    inner: Arc<RwLock<Option<Arc<dyn SnapshotDirectory>>>>,
}

impl DeferredSnapshotDirectory {
    /// An empty directory.
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs the backing directory.
    pub fn set(&self, directory: Arc<dyn SnapshotDirectory>) {
        *self.inner.write() = Some(directory);
    }
}

#[async_trait]
impl SnapshotDirectory for DeferredSnapshotDirectory {
    async fn manifest_for(&self, height: u64) -> Option<[u8; 32]> {
        let backing = self.inner.read().clone();
        match backing {
            Some(d) => d.manifest_for(height).await,
            None => None,
        }
    }
}

/// A serving node's certified snapshot anchor.
#[async_trait]
pub trait AnchorSource: Send + Sync + fmt::Debug + 'static {
    /// The encoded anchor of the newest snapshot this node serves, if it
    /// can certify one.
    async fn newest_anchor(&self) -> AnchorAnswer;
}

/// An anchor source installed after the endpoint is bound. Until then
/// every request is answered "no anchor".
#[derive(Debug, Clone, Default)]
pub struct DeferredAnchorSource {
    inner: Arc<RwLock<Option<Arc<dyn AnchorSource>>>>,
}

impl DeferredAnchorSource {
    /// An empty source.
    pub fn new() -> Self {
        Self::default()
    }

    /// Installs the backing source.
    pub fn set(&self, source: Arc<dyn AnchorSource>) {
        *self.inner.write() = Some(source);
    }
}

#[async_trait]
impl AnchorSource for DeferredAnchorSource {
    async fn newest_anchor(&self) -> AnchorAnswer {
        let backing = self.inner.read().clone();
        match backing {
            Some(s) => s.newest_anchor().await,
            None => AnchorAnswer::None,
        }
    }
}

/// Protocol handler serving [`ALPN_STATE_SYNC_ANCHOR`].
#[derive(Debug, Clone)]
pub struct AnchorProtocol {
    source: Arc<dyn AnchorSource>,
    pacing: Arc<Pacing>,
}

impl AnchorProtocol {
    /// A handler answering from `source`.
    pub fn new(source: Arc<dyn AnchorSource>) -> Self {
        Self {
            source,
            pacing: Arc::default(),
        }
    }
}

impl ProtocolHandler for AnchorProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = conn.remote_id();
        loop {
            let (mut send, _recv) = match conn.accept_bi().await {
                Ok(pair) => pair,
                Err(e) => {
                    trace!(target: "tenzro_iroh::state_sync", %remote, error = %e, "anchor connection closed");
                    return Ok(());
                }
            };
            let address = remote_address(&conn);
            let answer = if !self
                .pacing
                .admit(remote, address, tokio::time::Instant::now())
            {
                vec![2u8]
            } else {
                match self.source.newest_anchor().await {
                    AnchorAnswer::Anchor(anchor) if anchor.len() <= MAX_ANCHOR_BYTES => {
                        let mut out = Vec::with_capacity(5 + anchor.len());
                        out.push(1u8);
                        out.extend_from_slice(&(anchor.len() as u32).to_be_bytes());
                        out.extend_from_slice(&anchor);
                        out
                    }
                    AnchorAnswer::Anchor(anchor) => {
                        warn!(target: "tenzro_iroh::state_sync", bytes = anchor.len(), "snapshot anchor over the size bound is not served");
                        vec![0u8]
                    }
                    AnchorAnswer::None => vec![0u8],
                    AnchorAnswer::Busy => vec![3u8],
                }
            };
            debug!(target: "tenzro_iroh::state_sync", %remote, found = answer[0] == 1, "served snapshot anchor");
            if send.write_all(&answer).await.is_err() || send.finish().is_err() {
                return Ok(());
            }
        }
    }
}

/// Asks `peer` for the certified anchor of its newest snapshot. A peer that
/// does not serve [`ALPN_STATE_SYNC_ANCHOR`] is an error, like one that
/// cannot be reached.
pub async fn request_anchor(
    endpoint: &Endpoint,
    peer: impl Into<iroh::EndpointAddr>,
) -> IrohResult<Option<Vec<u8>>> {
    let peer = peer.into();
    let id = peer.id;
    let conn = crate::bounded::connect(
        endpoint,
        peer,
        ALPN_STATE_SYNC_ANCHOR,
        crate::bounded::BACKSTOP,
    )
    .await
    .map_err(|e| IrohError::Backend(format!("anchor connect to {id}: {e}")))?;
    let (mut send, mut recv) = crate::bounded::open_bi(&conn, crate::bounded::BACKSTOP)
        .await
        .map_err(|e| IrohError::Backend(format!("anchor open stream: {e}")))?;
    send.finish()
        .map_err(|e| IrohError::Backend(format!("anchor finish: {e}")))?;
    let mut tag = [0u8; 1];
    recv.read_exact(&mut tag)
        .await
        .map_err(|e| IrohError::Backend(format!("anchor read: {e}")))?;
    match tag[0] {
        0 => Ok(None),
        1 => {
            let mut len = [0u8; 4];
            recv.read_exact(&mut len)
                .await
                .map_err(|e| IrohError::Backend(format!("anchor read length: {e}")))?;
            let len = u32::from_be_bytes(len) as usize;
            if len > MAX_ANCHOR_BYTES {
                return Err(IrohError::Backend(format!(
                    "anchor of {len} bytes is over {MAX_ANCHOR_BYTES}"
                )));
            }
            let mut anchor = vec![0u8; len];
            recv.read_exact(&mut anchor)
                .await
                .map_err(|e| IrohError::Backend(format!("anchor read body: {e}")))?;
            Ok(Some(anchor))
        }
        2 => Err(IrohError::Backend(format!(
            "{id} was asked for an anchor too soon; it answers once per {}s",
            ANCHOR_REQUEST_INTERVAL.as_secs()
        ))),
        3 => Err(IrohError::Backend(format!(
            "{id} is busy building its anchor; ask again shortly"
        ))),
        other => Err(IrohError::Backend(format!(
            "anchor: unexpected response tag {other}"
        ))),
    }
}

/// Protocol handler serving [`ALPN_STATE_SYNC`].
#[derive(Debug, Clone)]
pub struct StateSyncProtocol {
    directory: Arc<dyn SnapshotDirectory>,
}

impl StateSyncProtocol {
    /// A handler answering from `directory`.
    pub fn new(directory: Arc<dyn SnapshotDirectory>) -> Self {
        Self { directory }
    }
}

impl ProtocolHandler for StateSyncProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let remote = conn.remote_id();
        loop {
            let (mut send, mut recv) = match conn.accept_bi().await {
                Ok(pair) => pair,
                Err(e) => {
                    trace!(target: "tenzro_iroh::state_sync", %remote, error = %e, "state-sync connection closed");
                    return Ok(());
                }
            };
            let mut height = [0u8; 8];
            if recv.read_exact(&mut height).await.is_err() {
                return Ok(());
            }
            let height = u64::from_be_bytes(height);
            let answer = match self.directory.manifest_for(height).await {
                Some(hash) => {
                    let mut out = Vec::with_capacity(33);
                    out.push(1u8);
                    out.extend_from_slice(&hash);
                    out
                }
                None => vec![0u8],
            };
            debug!(target: "tenzro_iroh::state_sync", %remote, height, found = answer[0] == 1, "served manifest lookup");
            if send.write_all(&answer).await.is_err() || send.finish().is_err() {
                return Ok(());
            }
        }
    }
}

/// Asks `peer` for the manifest blob of its snapshot at `height`.
pub async fn request_manifest(
    endpoint: &Endpoint,
    peer: EndpointId,
    height: u64,
) -> IrohResult<Option<[u8; 32]>> {
    let conn = crate::bounded::connect(endpoint, peer, ALPN_STATE_SYNC, crate::bounded::BACKSTOP)
        .await
        .map_err(|e| IrohError::Backend(format!("state-sync connect to {peer}: {e}")))?;
    let (mut send, mut recv) = crate::bounded::open_bi(&conn, crate::bounded::BACKSTOP)
        .await
        .map_err(|e| IrohError::Backend(format!("state-sync open stream: {e}")))?;
    send.write_all(&height.to_be_bytes())
        .await
        .map_err(|e| IrohError::Backend(format!("state-sync write: {e}")))?;
    send.finish()
        .map_err(|e| IrohError::Backend(format!("state-sync finish: {e}")))?;
    let mut tag = [0u8; 1];
    recv.read_exact(&mut tag)
        .await
        .map_err(|e| IrohError::Backend(format!("state-sync read: {e}")))?;
    match tag[0] {
        0 => Ok(None),
        1 => {
            let mut hash = [0u8; 32];
            recv.read_exact(&mut hash)
                .await
                .map_err(|e| IrohError::Backend(format!("state-sync read hash: {e}")))?;
            Ok(Some(hash))
        }
        other => Err(IrohError::Backend(format!(
            "state-sync: unexpected response tag {other}"
        ))),
    }
}

/// Parses a peer the operator names: `<EndpointId>` (found by discovery) or
/// `<EndpointId>@<ip:port>` (dialled directly, for a network with no
/// discovery).
pub fn parse_peer(text: &str) -> Result<iroh::EndpointAddr, String> {
    let (id_text, addr_text) = match text.split_once('@') {
        Some((id, addr)) => (id, Some(addr)),
        None => (text, None),
    };
    let id: EndpointId = id_text
        .trim()
        .parse()
        .map_err(|e| format!("{id_text:?} is not an iroh EndpointId: {e}"))?;
    let mut peer = iroh::EndpointAddr::new(id);
    if let Some(addr) = addr_text {
        let addr: std::net::SocketAddr = addr
            .trim()
            .parse()
            .map_err(|e| format!("{addr:?} is not an ip:port address: {e}"))?;
        peer = peer.with_ip_addr(addr);
    }
    Ok(peer)
}

/// Joins repeated entries naming one endpoint into one, keeping the order of
/// first appearance and every direct address given for it.
pub fn merge_peers(peers: Vec<iroh::EndpointAddr>) -> Vec<iroh::EndpointAddr> {
    let mut merged: Vec<iroh::EndpointAddr> = Vec::new();
    for peer in peers {
        match merged.iter_mut().find(|m| m.id == peer.id) {
            Some(m) => m.addrs.extend(peer.addrs),
            None => merged.push(peer),
        }
    }
    merged
}

#[cfg(test)]
mod peer_tests {
    use super::*;

    fn id() -> EndpointId {
        iroh::SecretKey::from_bytes(&[7; 32]).public()
    }

    #[test]
    fn a_bare_id_carries_no_address() {
        let p = parse_peer(&id().to_string()).unwrap();
        assert_eq!(p.id, id());
        assert!(p.addrs.is_empty());
    }

    #[test]
    fn an_id_with_an_address_is_dialled_directly() {
        let p = parse_peer(&format!("{}@127.0.0.1:4100", id())).unwrap();
        assert_eq!(p.id, id());
        assert_eq!(
            p.ip_addrs().copied().collect::<Vec<_>>(),
            vec!["127.0.0.1:4100".parse().unwrap()]
        );
        assert!(parse_peer(&format!("{}@[::1]:4100", id())).is_ok());
    }

    #[test]
    fn malformed_peers_are_refused() {
        assert!(parse_peer("nonsense").is_err());
        assert!(parse_peer(&format!("{}@127.0.0.1", id())).is_err());
        assert!(parse_peer(&format!("{}@", id())).is_err());
    }

    #[test]
    fn repeated_entries_for_one_id_merge() {
        let a = parse_peer(&format!("{}@127.0.0.1:1", id())).unwrap();
        let b = parse_peer(&format!("{}@127.0.0.1:2", id())).unwrap();
        let other =
            parse_peer(&iroh::SecretKey::from_bytes(&[8; 32]).public().to_string()).unwrap();
        let merged = merge_peers(vec![a, other, b]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].ip_addrs().count(), 2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::endpoint::presets;
    use iroh::protocol::Router;

    #[derive(Debug)]
    struct Holds(Option<Vec<u8>>);

    #[async_trait]
    impl AnchorSource for Holds {
        async fn newest_anchor(&self) -> AnchorAnswer {
            self.0
                .clone()
                .map_or(AnchorAnswer::None, AnchorAnswer::Anchor)
        }
    }

    /// A source that says it is busy building.
    #[derive(Debug)]
    struct Building;

    #[async_trait]
    impl AnchorSource for Building {
        async fn newest_anchor(&self) -> AnchorAnswer {
            AnchorAnswer::Busy
        }
    }

    /// A peer's anchor comes back byte for byte; one with none says so; a
    /// peer that does not serve the ALPN is an error, not "no anchor". A
    /// client asking again within the interval is told it is too soon while
    /// another client is still served, and an anchor over the size bound is
    /// never sent.
    #[tokio::test]
    async fn an_anchor_is_served_as_held() {
        let client = crate::identity_transport::on_loopback(Endpoint::builder(presets::Minimal))
            .bind()
            .await
            .unwrap();
        let serve = |held: Option<Vec<u8>>| async move {
            let server =
                crate::identity_transport::on_loopback(Endpoint::builder(presets::Minimal))
                    .bind()
                    .await
                    .unwrap();
            let source = DeferredAnchorSource::new();
            let router = Router::builder(server.clone())
                .accept(
                    ALPN_STATE_SYNC_ANCHOR,
                    AnchorProtocol::new(Arc::new(source.clone())),
                )
                .spawn();
            if let Some(held) = held {
                source.set(Arc::new(Holds(Some(held))));
            }
            (server, router)
        };

        let anchor = vec![7u8; 70_000];
        let (holding, _r1) = serve(Some(anchor.clone())).await;
        assert_eq!(
            request_anchor(&client, holding.addr()).await.unwrap(),
            Some(anchor.clone())
        );
        let again = request_anchor(&client, holding.addr()).await.unwrap_err();
        assert!(again.to_string().contains("too soon"), "{again}");
        let other = crate::identity_transport::on_loopback(Endpoint::builder(presets::Minimal))
            .bind()
            .await
            .unwrap();
        assert_eq!(
            request_anchor(&other, holding.addr()).await.unwrap(),
            Some(anchor)
        );

        let (oversized, _r4) = serve(Some(vec![1u8; MAX_ANCHOR_BYTES + 1])).await;
        assert_eq!(
            request_anchor(&client, oversized.addr()).await.unwrap(),
            None
        );
        let (empty, _r2) = serve(None).await;
        assert_eq!(request_anchor(&client, empty.addr()).await.unwrap(), None);

        let old = crate::identity_transport::on_loopback(Endpoint::builder(presets::Minimal))
            .bind()
            .await
            .unwrap();
        let _r3 = Router::builder(old.clone())
            .accept(
                ALPN_STATE_SYNC,
                StateSyncProtocol::new(Arc::new(DeferredSnapshotDirectory::new())),
            )
            .spawn();
        assert!(request_anchor(&client, old.addr()).await.is_err());
    }

    /// One remote is answered once per interval and again after it; one
    /// address once per its own interval whatever endpoint ids come from it; a
    /// full table forgets its oldest entry instead of refusing a new asker.
    #[test]
    fn pacing_answers_a_remote_once_per_interval() {
        let key = |n: u8| iroh::SecretKey::from_bytes(&[n; 32]).public();
        let ip = |n: u8| std::net::IpAddr::from([10, 0, 0, n]);
        let pacing = Pacing::default();
        let t0 = tokio::time::Instant::now();
        assert!(pacing.admit(key(1), None, t0));
        assert!(!pacing.admit(key(1), None, t0 + ANCHOR_REQUEST_INTERVAL / 2));
        assert!(pacing.admit(key(1), None, t0 + ANCHOR_REQUEST_INTERVAL));

        // Endpoint ids from one address: the second waits for the address.
        let by_address = Pacing::default();
        assert!(by_address.admit(key(1), Some(ip(1)), t0));
        assert!(!by_address.admit(key(2), Some(ip(1)), t0 + ANCHOR_ADDRESS_INTERVAL / 2));
        assert!(by_address.admit(key(3), Some(ip(2)), t0));
        assert!(by_address.admit(key(2), Some(ip(1)), t0 + ANCHOR_ADDRESS_INTERVAL));
        // A refused address records nothing for its endpoint.
        let refused = Pacing::default();
        assert!(refused.admit(key(1), Some(ip(1)), t0));
        assert!(!refused.admit(key(2), Some(ip(1)), t0 + ANCHOR_ADDRESS_INTERVAL / 2));
        assert!(refused.admit(key(2), Some(ip(3)), t0 + ANCHOR_ADDRESS_INTERVAL / 2));

        // Full tables: a new asker is answered, the oldest entry is the one
        // forgotten, and neither table grows past its bound.
        let full = Pacing::default();
        for i in 0..MAX_PACED_REMOTES {
            let mut seed = [0u8; 32];
            seed[..8].copy_from_slice(&(i as u64).to_le_bytes());
            seed[31] = 9;
            let at = t0 + std::time::Duration::from_millis(i as u64);
            let addr = std::net::IpAddr::from((i as u32 + 1).to_be_bytes());
            assert!(full.admit(iroh::SecretKey::from_bytes(&seed).public(), Some(addr), at));
        }
        let soon = t0 + std::time::Duration::from_secs(1);
        assert!(full.admit(key(2), Some(ip(200)), soon));
        assert_eq!(full.last.lock().len(), MAX_PACED_REMOTES);
        assert_eq!(full.addresses.lock().len(), MAX_PACED_REMOTES);
        assert!(full.last.lock().contains_key(&key(2)));
    }

    /// A busy node says so on the wire and the asker's error names it.
    #[tokio::test]
    async fn a_busy_node_says_it_is_busy() {
        let server = crate::identity_transport::on_loopback(Endpoint::builder(presets::Minimal))
            .bind()
            .await
            .unwrap();
        let _router = Router::builder(server.clone())
            .accept(
                ALPN_STATE_SYNC_ANCHOR,
                AnchorProtocol::new(Arc::new(Building)),
            )
            .spawn();
        let client = crate::identity_transport::on_loopback(Endpoint::builder(presets::Minimal))
            .bind()
            .await
            .unwrap();
        let err = request_anchor(&client, server.addr()).await.unwrap_err();
        assert!(err.to_string().contains("busy"), "{err}");
    }
}
