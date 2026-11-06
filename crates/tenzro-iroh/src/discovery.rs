//! Tenzro's own discovery network.
//!
//! Every node keeps a [`DiscoveryStore`]: the newest verified
//! [`EndpointRecord`] of each machine identity it has heard of. It answers
//! other nodes over the `tenzro/discovery` ALPN (publish a record, look one up
//! by identity, or take a snapshot of the public ones) and, as an iroh
//! address lookup, turns an `EndpointId` into the relays its record names.
//! Records spread by nodes exchanging snapshots with the peers they know, so
//! a node that knows one Tenzro node comes to know the rest. No service
//! outside the Tenzro network is consulted.
//!
//! A record is admitted only if it verifies (see
//! [`crate::identity_record`]) and is newer, by sequence number, than the one
//! held. A record scoped to the epoch set ([`RecordScope::EpochSet`]) is
//! answered only to a peer whose endpoint a member of that set certifies. A
//! private node's record ([`RecordScope::Counterparties`]) is answered only
//! to a lookup by a counterparty it lists and never travels in a snapshot.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use futures::stream::{self, StreamExt};
use iroh::address_lookup::{AddressLookup, Error as LookupError, Item};
use iroh::endpoint::Connection;
use iroh::endpoint_info::EndpointInfo;
use iroh::protocol::{AcceptError, ProtocolHandler};
use iroh::{Endpoint, EndpointAddr, EndpointId, TransportAddr};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::consensus::{read_frame, write_frame};
use crate::error::{IrohError, IrohResult};
use crate::identity_record::{EndpointRecord, RecordBook, RecordError, RecordScope};
use crate::identity_transport::{endpoint_addr, iroh_endpoint_key};
use crate::relay::now_ms;

/// ALPN of the discovery protocol.
pub const ALPN_DISCOVERY: &[u8] = b"tenzro/discovery";

/// Most records one snapshot carries.
pub const MAX_SNAPSHOT_RECORDS: usize = 512;

/// Largest request or response frame.
const MAX_FRAME: usize = 1024 * 1024;

/// A discovery request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryRequest {
    /// Store this record.
    Publish(EndpointRecord),
    /// The current record of this identity.
    Lookup(String),
    /// The current records the answering node may share with the asker.
    Snapshot,
    /// The address the answering node sees the asker at over a direct path.
    Observe,
}

/// A discovery response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DiscoveryResponse {
    /// Whether a published record was kept, or why it was refused.
    Published(Result<bool, String>),
    /// The record asked for, if the node holds one it may share.
    Record(Option<EndpointRecord>),
    /// Current records the node may share.
    Records(Vec<EndpointRecord>),
    /// The asker's address on a direct path, or none when the connection
    /// runs only through a relay.
    Observed(Option<SocketAddr>),
}

/// How long the answer to an `Observe` request waits for a direct path to
/// open on the connection it came over.
pub const OBSERVE_WAIT: Duration = Duration::from_secs(5);

/// `addr` with an IPv4-mapped IPv6 address written as the IPv4 address.
fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::new(v4.into(), v6.port()),
            None => addr,
        },
        v4 => v4,
    }
}

/// The remote address of a direct path on `conn`, the selected one first,
/// waiting up to [`OBSERVE_WAIT`] for one to open: a connection starts on a
/// relay and moves to a direct path once hole punching succeeds.
async fn direct_remote_addr(conn: &Connection) -> Option<SocketAddr> {
    let deadline = tokio::time::Instant::now() + OBSERVE_WAIT;
    loop {
        let paths = conn.paths();
        let mut ip: Vec<(bool, SocketAddr)> = paths
            .iter()
            .filter_map(|p| match p.remote_addr() {
                TransportAddr::Ip(addr) => Some((p.is_selected(), canonical(*addr))),
                _ => None,
            })
            .collect();
        ip.sort_by_key(|(selected, _)| !*selected);
        if let Some((_, addr)) = ip.first() {
            return Some(*addr);
        }
        if tokio::time::Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// The records a node holds, and who may see its epoch-set records.
#[derive(Debug, Default)]
pub struct DiscoveryStore {
    book: RwLock<RecordBook>,
    epoch_set: RwLock<HashSet<String>>,
}

impl DiscoveryStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Keeps `record` as its identity's if it verifies and is newer than the
    /// one held.
    pub fn offer(&self, record: EndpointRecord) -> Result<bool, RecordError> {
        let did = record.machine_did();
        self.book.write().offer(&did, record, now_ms())
    }

    /// `did`'s current record.
    pub fn lookup(&self, did: &str) -> Option<EndpointRecord> {
        self.book.read().get(did, now_ms()).cloned()
    }

    /// Every current record.
    pub fn records(&self) -> Vec<EndpointRecord> {
        self.book
            .read()
            .current(now_ms())
            .map(|(_, r)| r.clone())
            .collect()
    }

    /// Sets the machine identities of the epoch set: the only peers
    /// epoch-set records are answered to.
    pub fn set_epoch_set(&self, set: HashSet<String>) {
        *self.epoch_set.write() = set;
    }

    /// Whether `did` is in the epoch set.
    pub fn in_epoch_set(&self, did: &str) -> bool {
        self.epoch_set.read().contains(did)
    }

    /// The current record naming the peer that authenticated with
    /// `endpoint`.
    pub fn naming(&self, endpoint: EndpointId) -> Option<EndpointRecord> {
        self.book
            .read()
            .naming(&iroh_endpoint_key(endpoint), now_ms())
            .cloned()
    }

    /// Holds `did`'s records to the hardware ML-DSA key `machine_pq_key`
    /// (tagged with its scheme), as registered on chain.
    pub fn pin_pq_key(&self, did: &str, machine_pq_key: Vec<u8>) {
        self.book.write().pin_pq_key(did, machine_pq_key);
    }

    /// The hardware ML-DSA key `did`'s records are held to, if any.
    pub fn pinned_pq_key(&self, did: &str) -> Option<Vec<u8>> {
        self.book.read().pinned_pq_key(did).map(<[u8]>::to_vec)
    }

    /// Takes back the ML-DSA pins an earlier run saved at `path` (see
    /// [`crate::pq_endpoint::save_pins`]). Returns how many it read.
    pub fn restore_pq_pins(&self, path: &std::path::Path) -> std::io::Result<usize> {
        let saved = crate::pq_endpoint::load_pins(path)?;
        let n = saved.len();
        self.book.write().restore_pq_pins(saved);
        Ok(n)
    }

    /// Saves the ML-DSA pins to `path` when they changed since `since`
    /// changes; returns the count of changes now saved, for the next call.
    pub fn save_pq_pins(&self, path: &std::path::Path, since: u64) -> std::io::Result<u64> {
        let (changes, saved) = {
            let book = self.book.read();
            let changes = book.pq_pin_changes();
            if changes == since {
                return Ok(since);
            }
            (changes, book.saved_pq_pins())
        };
        crate::pq_endpoint::save_pins(path, &saved)?;
        Ok(changes)
    }

    /// Whether the peer that authenticated with `endpoint` holds a current
    /// record stating its operator accepted the licence `id`.
    pub fn accepts_licence(&self, endpoint: EndpointId, id: &str) -> bool {
        self.book
            .read()
            .naming(&iroh_endpoint_key(endpoint), now_ms())
            .is_some_and(|r| r.accepts_licence(id))
    }

    /// The identity in `set` whose current record certifies `endpoint`: the
    /// check that a peer authenticated as `endpoint` belongs to `set`.
    pub fn certified_in(&self, endpoint: EndpointId, set: &HashSet<String>) -> Option<String> {
        self.book
            .read()
            .certifier_in(&iroh_endpoint_key(endpoint), set, now_ms())
            .map(str::to_string)
    }

    /// Whether `record` may be answered to the peer authenticated as
    /// `asker`: anyone for a network-wide record, a certified member for an
    /// epoch-set record, and only a certified counterparty the record lists
    /// for a private node's record.
    fn may_share(&self, record: &EndpointRecord, asker: EndpointId) -> bool {
        match &record.scope {
            RecordScope::Network => true,
            RecordScope::EpochSet => {
                let set = self.epoch_set.read();
                set.contains(&record.machine_did()) && self.certified_in(asker, &set).is_some()
            }
            RecordScope::Counterparties(list) => {
                let set: HashSet<String> = list.iter().cloned().collect();
                self.certified_in(asker, &set).is_some()
            }
        }
    }

    /// Whether `record` may travel in a snapshot to `asker`. A private
    /// node's record never does: it is answered only to a lookup by a listed
    /// counterparty.
    fn may_replicate(&self, record: &EndpointRecord, asker: EndpointId) -> bool {
        !matches!(record.scope, RecordScope::Counterparties(_)) && self.may_share(record, asker)
    }

    fn answer(&self, request: DiscoveryRequest, asker: EndpointId) -> DiscoveryResponse {
        match request {
            DiscoveryRequest::Publish(record) => {
                DiscoveryResponse::Published(self.offer(record).map_err(|e| e.to_string()))
            }
            DiscoveryRequest::Lookup(did) => {
                DiscoveryResponse::Record(self.lookup(&did).filter(|r| self.may_share(r, asker)))
            }
            DiscoveryRequest::Snapshot => DiscoveryResponse::Records(
                self.records()
                    .into_iter()
                    .filter(|r| self.may_replicate(r, asker))
                    .take(MAX_SNAPSHOT_RECORDS)
                    .collect(),
            ),
            // Answered by the protocol handler, which holds the connection.
            DiscoveryRequest::Observe => DiscoveryResponse::Observed(None),
        }
    }
}

impl AddressLookup for DiscoveryStore {
    fn resolve(
        &self,
        endpoint_id: EndpointId,
    ) -> Option<stream::BoxStream<'static, Result<Item, LookupError>>> {
        let key = iroh_endpoint_key(endpoint_id);
        let record = self
            .book
            .read()
            .current(now_ms())
            .find(|(_, r)| r.endpoint == key)
            .map(|(_, r)| r.clone())?;
        let addr = endpoint_addr(&record).ok()?;
        let info = EndpointInfo::from(addr);
        Some(stream::iter([Ok(Item::new(info, "tenzro-discovery", None))]).boxed())
    }
}

/// Serves the discovery protocol from a store.
#[derive(Debug, Clone)]
pub struct DiscoveryProtocol {
    store: Arc<DiscoveryStore>,
}

impl DiscoveryProtocol {
    /// Answers from `store`.
    pub fn new(store: Arc<DiscoveryStore>) -> Self {
        Self { store }
    }
}

impl ProtocolHandler for DiscoveryProtocol {
    async fn accept(&self, conn: Connection) -> Result<(), AcceptError> {
        let asker = conn.remote_id();
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            let frame = read_frame(&mut recv, MAX_FRAME)
                .await
                .map_err(AcceptError::from_err)?;
            let request: DiscoveryRequest =
                serde_json::from_slice(&frame).map_err(AcceptError::from_err)?;
            let answer = match request {
                DiscoveryRequest::Observe => {
                    DiscoveryResponse::Observed(direct_remote_addr(&conn).await)
                }
                other => self.store.answer(other, asker),
            };
            let response = serde_json::to_vec(&answer).map_err(AcceptError::from_err)?;
            write_frame(&mut send, &response)
                .await
                .map_err(AcceptError::from_err)?;
            send.finish().map_err(AcceptError::from_err)?;
        }
        Ok(())
    }
}

/// Sends one request to `peer` and reads its response.
pub async fn ask(
    endpoint: &Endpoint,
    peer: EndpointAddr,
    request: &DiscoveryRequest,
) -> IrohResult<DiscoveryResponse> {
    let id = peer.id;
    let conn = endpoint
        .connect(peer, ALPN_DISCOVERY)
        .await
        .map_err(|e| IrohError::Backend(format!("discovery connect to {id}: {e}")))?;
    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| IrohError::Backend(format!("discovery stream to {id}: {e}")))?;
    let body = serde_json::to_vec(request).map_err(|e| IrohError::Backend(e.to_string()))?;
    write_frame(&mut send, &body).await?;
    send.finish()
        .map_err(|e| IrohError::Backend(e.to_string()))?;
    let frame = read_frame(&mut recv, MAX_FRAME).await?;
    conn.close(0u32.into(), b"done");
    serde_json::from_slice(&frame)
        .map_err(|e| IrohError::Backend(format!("discovery response from {id}: {e}")))
}
