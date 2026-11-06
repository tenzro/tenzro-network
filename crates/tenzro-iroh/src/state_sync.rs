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

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use iroh::endpoint::Connection;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointId};
use parking_lot::RwLock;
use tracing::{debug, trace};

use crate::error::{IrohError, IrohResult};

/// ALPN for manifest discovery.
pub const ALPN_STATE_SYNC: &[u8] = b"tenzro/state-sync";

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
    let conn = endpoint
        .connect(peer, ALPN_STATE_SYNC)
        .await
        .map_err(|e| IrohError::Backend(format!("state-sync connect to {peer}: {e}")))?;
    let (mut send, mut recv) = conn
        .open_bi()
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
        let other = parse_peer(&iroh::SecretKey::from_bytes(&[8; 32]).public().to_string()).unwrap();
        let merged = merge_peers(vec![a, other, b]);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].ip_addrs().count(), 2);
    }
}
