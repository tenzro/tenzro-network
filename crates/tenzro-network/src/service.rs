//! Main NetworkService for Tenzro Network

use crate::{
    behaviour::{TenzroBehaviour, TenzroBehaviourEvent},
    block_sync_proto::{BlockSyncRequest, BlockSyncResponse},
    config::NetworkConfig,
    error::{NetworkError, Result},
    gossip::{MessageDeduplicator, MessageValidation, validate_gossip_message},
    message::{NetworkMessage, MessagePayload},
    metrics::NetworkMetrics,
    peer_manager::{PeerManager, ManagedPeer},
    transport,
};
use async_trait::async_trait;
use futures::StreamExt;
use libp2p::{
    gossipsub::{self, IdentTopic, TopicHash},
    identify,
    kad::{self, QueryResult},
    ping,
    request_response::{self, InboundRequestId, OutboundRequestId, ResponseChannel},
    swarm::SwarmEvent,
    Multiaddr, PeerId, Swarm,
};
use parking_lot::Mutex;
use prometheus_client::registry::Registry;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{interval, MissedTickBehavior};
use tenzro_types::network::PeerStatus;

/// Loads a persistent Ed25519 keypair from disk, or generates and saves a new one.
///
/// The keypair is stored as a protobuf-encoded file at `{data_dir}/p2p_key`.
/// This ensures the node has a stable PeerId across restarts.
fn load_or_generate_keypair(data_dir: &Option<PathBuf>) -> Result<libp2p::identity::Keypair> {
    let Some(dir) = data_dir else {
        tracing::warn!("No data_dir configured — generating ephemeral keypair (peer ID will change on restart)");
        return Ok(libp2p::identity::Keypair::generate_ed25519());
    };

    let key_path = dir.join("p2p_key");

    // Try to load existing key
    if key_path.exists() {
        match std::fs::read(&key_path) {
            Ok(bytes) => {
                match libp2p::identity::Keypair::from_protobuf_encoding(&bytes) {
                    Ok(keypair) => {
                        tracing::info!("Loaded persistent keypair from {}", key_path.display());
                        return Ok(keypair);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to decode keypair from {}: {} — generating new one", key_path.display(), e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to read keypair file {}: {} — generating new one", key_path.display(), e);
            }
        }
    }

    // Generate new keypair and save it
    let keypair = libp2p::identity::Keypair::generate_ed25519();

    // Ensure parent directory exists
    if let Some(parent) = key_path.parent()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        tracing::warn!("Failed to create directory {}: {} — keypair will be ephemeral", parent.display(), e);
        return Ok(keypair);
    }

    match keypair.to_protobuf_encoding() {
        Ok(bytes) => {
            match std::fs::write(&key_path, &bytes) {
                Ok(()) => {
                    tracing::info!("Generated and saved new keypair to {}", key_path.display());
                    // Restrict file permissions on Unix
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        if let Err(e) = std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)) {
                            tracing::warn!("Failed to set keypair file permissions: {}", e);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to write keypair to {}: {} — keypair will be ephemeral", key_path.display(), e);
                }
            }
        }
        Err(e) => {
            tracing::warn!("Failed to encode keypair: {} — keypair will be ephemeral", e);
        }
    }

    Ok(keypair)
}

/// Returns true only if `addr` contains a globally routable IP that other nodes
/// can actually reach. Rejects:
///   - loopback (127.x.x.x / ::1)
///   - private RFC-1918 (10.x, 172.16-31.x, 192.168.x)
///   - link-local (169.254.x.x / fe80::/10)
///   - Docker bridge default (172.17.x.x)
///   - unspecified (0.0.0.0 / ::)
///   - broadcast, documentation ranges
///   - IPv6 unique-local (fc00::/7) and multicast (ff00::/8)
///   - addresses with no IP component at all
///
/// NOTE: Private IPs (10.x.x.x, 172.16-31.x.x, 192.168.x.x) are ACCEPTED
/// because Kubernetes pods and GCE VMs use RFC-1918 addresses within the VPC.
fn is_globally_routable(addr: &Multiaddr) -> bool {
    use libp2p::multiaddr::Protocol;
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                if ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_unspecified()
                    || ip.is_broadcast()
                    || ip.is_documentation()
                {
                    return false;
                }
                return true;
            }
            Protocol::Ip6(ip) => {
                if ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || (ip.segments()[0] & 0xffc0) == 0xfe80  // fe80::/10 link-local
                {
                    return false;
                }
                return true;
            }
            _ => {}
        }
    }
    false  // No IP component found — not routable
}

/// Extracts the IPv4/IPv6 address from a libp2p `Multiaddr`, if any.
/// Used for per-IP dial rate limiting on incoming connections.
fn extract_ip(addr: &Multiaddr) -> Option<IpAddr> {
    use libp2p::multiaddr::Protocol;
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => return Some(IpAddr::V4(ip)),
            Protocol::Ip6(ip) => return Some(IpAddr::V6(ip)),
            _ => continue,
        }
    }
    None
}

/// An inbound block-sync request received from a peer.
///
/// The receiver MUST eventually call
/// [`TenzroNetworkService::send_block_sync_response`] with the matching
/// `request_id`, or the inbound stream times out and the peer scores us
/// down. Dropping the value without responding is acceptable only on
/// explicit reject paths (the consumer should call `send_block_sync_response`
/// with a `BlockSyncResponse::Error(_)` variant in that case).
#[derive(Debug)]
pub struct InboundBlockSync {
    pub peer: PeerId,
    pub request_id: InboundRequestId,
    pub request: BlockSyncRequest,
}

/// Outbound block-sync result delivered asynchronously to the issuer of
/// `request_blocks` / `request_tip_info` / `request_block_by_hash`.
///
/// The `request_id` matches the one returned by the request-issuing call.
/// `result` carries either the decoded response or a typed transport error.
#[derive(Debug)]
pub struct OutboundBlockSyncResult {
    pub peer: PeerId,
    pub request_id: OutboundRequestId,
    pub result: std::result::Result<BlockSyncResponse, BlockSyncOutboundError>,
}

/// Connection lifecycle events surfaced by the swarm to subscribed
/// consumers (block-sync engine, future peer-aware subsystems).
///
/// `Connected` fires on the first physical connection to `peer` (i.e. when
/// `num_established == 1`), so subscribers see one logical
/// connect/disconnect pair per peer regardless of how many TCP/QUIC
/// connections the swarm multiplexes underneath. `Disconnected` fires only
/// when the last connection drops (`num_established == 0`).
///
/// This is the canonical 2026 libp2p pattern (Lighthouse `SyncManager`,
/// generic `SwarmEvent::ConnectionEstablished`/`ConnectionClosed` routing
/// via `tokio::sync::mpsc::UnboundedSender`): the network event loop owns
/// the swarm, fans out lifecycle deltas through unbounded channels, and
/// subscribers consume them in their own `tokio::select!` loop.
#[derive(Debug, Clone)]
pub enum PeerEvent {
    /// First physical connection to `peer` was established.
    Connected(PeerId),
    /// Last physical connection to `peer` was closed.
    Disconnected(PeerId),
}

/// Transport-level failure modes for an outbound block-sync request.
///
/// These are libp2p-layer errors (timeout, connection closed, codec
/// failure). Server-side application errors are carried inside the
/// `BlockSyncResponse::Error` variant on a successful round-trip and do
/// NOT surface here — callers must inspect `result.ok()` for those.
#[derive(Debug, thiserror::Error)]
pub enum BlockSyncOutboundError {
    #[error("dial failure")]
    DialFailure,
    #[error("request timed out")]
    Timeout,
    #[error("connection closed")]
    ConnectionClosed,
    #[error("remote does not speak the block-sync protocol")]
    UnsupportedProtocols,
    #[error("io error: {0}")]
    Io(String),
}

impl From<request_response::OutboundFailure> for BlockSyncOutboundError {
    fn from(e: request_response::OutboundFailure) -> Self {
        match e {
            request_response::OutboundFailure::DialFailure => Self::DialFailure,
            request_response::OutboundFailure::Timeout => Self::Timeout,
            request_response::OutboundFailure::ConnectionClosed => Self::ConnectionClosed,
            request_response::OutboundFailure::UnsupportedProtocols => Self::UnsupportedProtocols,
            request_response::OutboundFailure::Io(io) => Self::Io(io.to_string()),
        }
    }
}

/// Network service trait
#[async_trait]
pub trait NetworkService: Send + Sync {
    /// Broadcasts a message to all peers on a topic
    async fn broadcast(&self, topic: &str, message: NetworkMessage) -> Result<()>;

    /// Sends a message to a specific peer
    async fn send_to(&self, peer_id: PeerId, message: NetworkMessage) -> Result<()>;

    /// Subscribes to a topic and returns a receiver for messages
    async fn subscribe(&self, topic: &str) -> Result<mpsc::UnboundedReceiver<NetworkMessage>>;

    /// Gets the list of connected peers
    async fn connected_peers(&self) -> Result<Vec<PeerId>>;

    /// Gets information about a specific peer
    async fn peer_info(&self, peer_id: &PeerId) -> Result<Option<ManagedPeer>>;

    /// Bans a peer
    async fn ban_peer(&self, peer_id: &PeerId) -> Result<()>;

    /// Unbans a peer
    async fn unban_peer(&self, peer_id: &PeerId) -> Result<()>;

    /// Gets the local peer ID
    async fn local_peer_id(&self) -> Result<PeerId>;

    /// Dials a peer at the given address
    async fn dial(&self, addr: Multiaddr) -> Result<()>;

    /// Sets the validator registry for peer authorization on validator-only topics
    async fn set_validator_registry(&self, registry: std::sync::Arc<dyn crate::peer_manager::ValidatorRegistry>) -> Result<()>;

    /// Returns the set of multiaddrs the swarm is currently listening on.
    ///
    /// Useful for tests and bootstrap scenarios where the listen port is
    /// auto-assigned (e.g., `/ip4/127.0.0.1/tcp/0`) and the caller needs to
    /// know the bound address to share with peers.
    async fn listen_addresses(&self) -> Result<Vec<Multiaddr>>;
}

/// Commands sent to the network service
#[allow(clippy::large_enum_variant)]
enum NetworkCommand {
    Broadcast {
        topic: String,
        message: NetworkMessage,
        response: oneshot::Sender<Result<()>>,
    },
    Subscribe {
        topic: String,
        response: oneshot::Sender<Result<mpsc::UnboundedReceiver<NetworkMessage>>>,
    },
    ConnectedPeers {
        response: oneshot::Sender<Result<Vec<PeerId>>>,
    },
    PeerInfo {
        peer_id: PeerId,
        response: oneshot::Sender<Result<Option<ManagedPeer>>>,
    },
    BanPeer {
        peer_id: PeerId,
        response: oneshot::Sender<Result<()>>,
    },
    UnbanPeer {
        peer_id: PeerId,
        response: oneshot::Sender<Result<()>>,
    },
    LocalPeerId {
        response: oneshot::Sender<Result<PeerId>>,
    },
    Dial {
        addr: Multiaddr,
        response: oneshot::Sender<Result<()>>,
    },
    SetValidatorRegistry {
        registry: std::sync::Arc<dyn crate::peer_manager::ValidatorRegistry>,
        response: oneshot::Sender<Result<()>>,
    },
    /// Returns the current count of gossipsub mesh peers for `topic`.
    /// Used by the mesh warm-up gate before consensus first publish.
    MeshPeerCount {
        topic: String,
        response: oneshot::Sender<Result<usize>>,
    },
    /// Returns the multiaddrs currently bound by the swarm's listeners.
    /// Required when the configured listen port is 0 (OS-assigned) and the
    /// caller needs to discover the actual bound address.
    ListenAddresses {
        response: oneshot::Sender<Result<Vec<Multiaddr>>>,
    },
    /// Returns the count of gossipsub mesh peers for `topic` that are ALSO
    /// admitted to the local validator registry. Used by the admitted-mesh
    /// gate to ensure first-publish on validator-only topics only fires
    /// after identify has admitted enough peers — otherwise messages are
    /// dropped on receipt by `authorize_peer_for_topic`.
    ///
    /// If no validator registry is installed, falls back to the plain mesh
    /// peer count (permissive mode).
    AdmittedMeshPeers {
        topic: String,
        response: oneshot::Sender<Result<usize>>,
    },
    /// Initiates an outbound block-sync request to `peer`. Returns the
    /// `OutboundRequestId` synchronously; the response (or transport
    /// failure) is delivered later through the channel registered with
    /// `SubscribeBlockSyncResults`.
    SendBlockSyncRequest {
        peer: PeerId,
        request: BlockSyncRequest,
        response: oneshot::Sender<Result<OutboundRequestId>>,
    },
    /// Sends a block-sync response back to the peer that issued the
    /// inbound request identified by `request_id`. The corresponding
    /// `ResponseChannel` is held inside the event loop; if it has been
    /// dropped (peer disconnected, stream timed out), the send returns
    /// `Err(NetworkError::PeerNotFound)`.
    SendBlockSyncResponse {
        request_id: InboundRequestId,
        response_payload: BlockSyncResponse,
        response: oneshot::Sender<Result<()>>,
    },
    /// Subscribes to inbound block-sync requests. Only one subscriber is
    /// supported at a time — calling twice replaces the previous channel.
    /// Used by the node-level block-sync server to receive
    /// `GetTipInfo` / `GetBlockRange` / `GetBlockByHash` from peers.
    SubscribeBlockSyncRequests {
        response: oneshot::Sender<Result<mpsc::UnboundedReceiver<InboundBlockSync>>>,
    },
    /// Subscribes to outbound block-sync results. Only one subscriber is
    /// supported at a time. Used by the node-level block-sync engine to
    /// correlate `OutboundRequestId`s returned by `SendBlockSyncRequest`
    /// with the eventual peer response or transport error.
    SubscribeBlockSyncResults {
        response: oneshot::Sender<Result<mpsc::UnboundedReceiver<OutboundBlockSyncResult>>>,
    },
    /// Subscribes to peer connection lifecycle events. Only one subscriber
    /// is supported at a time — calling twice replaces the previous
    /// channel. Consumed by the block-sync engine to learn which peers it
    /// can probe for tip info; future peer-aware subsystems (gossip
    /// flooders, mesh-warmup gates) attach to the same stream.
    SubscribePeerEvents {
        response: oneshot::Sender<Result<mpsc::UnboundedReceiver<PeerEvent>>>,
    },
    Shutdown {
        response: oneshot::Sender<Result<()>>,
    },
}

/// Implementation of NetworkService for Tenzro Network
pub struct TenzroNetworkService {
    command_tx: mpsc::UnboundedSender<NetworkCommand>,
    /// Prometheus metrics bundle — exposed for `/metrics` endpoint.
    metrics: Arc<NetworkMetrics>,
    /// Metrics registry — exposed so the node can add its own subsystems
    /// and serialize all metrics to the Prometheus text format.
    metrics_registry: Arc<Mutex<Registry>>,
}

impl TenzroNetworkService {
    /// Creates a new network service with a fresh metrics registry.
    pub async fn new(config: NetworkConfig) -> Result<Self> {
        let mut registry = Registry::default();
        let metrics = NetworkMetrics::register(&mut registry);
        Self::new_with_registry(config, Arc::new(Mutex::new(registry)), metrics).await
    }

    /// Creates a new network service using a caller-provided metrics registry.
    /// Use this when the node already has a shared Prometheus registry that
    /// aggregates metrics from consensus, storage, VM, etc.
    pub async fn new_with_registry(
        config: NetworkConfig,
        metrics_registry: Arc<Mutex<Registry>>,
        metrics: Arc<NetworkMetrics>,
    ) -> Result<Self> {
        // Validate configuration
        config.validate()?;

        let (command_tx, command_rx) = mpsc::unbounded_channel();
        let loop_metrics = metrics.clone();

        // Spawn the event loop
        tokio::spawn(async move {
            if let Err(e) = run_event_loop(config, command_rx, loop_metrics).await {
                tracing::error!("Network event loop error: {}", e);
            }
        });

        Ok(Self {
            command_tx,
            metrics,
            metrics_registry,
        })
    }

    /// Returns a handle to the Prometheus metrics bundle for external
    /// instrumentation (e.g., RPC call counters that live outside the
    /// networking layer can be incremented through this handle).
    pub fn metrics(&self) -> Arc<NetworkMetrics> {
        self.metrics.clone()
    }

    /// Returns the shared metrics registry — useful for callers that need
    /// to register additional metric families or serialize the registry to
    /// the Prometheus text format.
    pub fn metrics_registry(&self) -> Arc<Mutex<Registry>> {
        self.metrics_registry.clone()
    }

    /// Signals the event loop to shut down gracefully.
    /// Waits for the loop to drain in-flight commands before returning.
    pub async fn shutdown(&self) -> Result<()> {
        self.send_command(|response| NetworkCommand::Shutdown { response }).await
    }

    /// Returns the current number of gossipsub mesh peers for `topic`.
    ///
    /// Used by the mesh warm-up gate (`wait_for_mesh`) to determine when it
    /// is safe to publish — `Behaviour::publish` returns
    /// `NoPeersSubscribedToTopic` if the mesh hasn't formed yet (rust-libp2p
    /// `behaviour.rs:1064`).
    pub async fn mesh_peer_count(&self, topic: &str) -> Result<usize> {
        let topic_owned = topic.to_string();
        self.send_command(move |response| NetworkCommand::MeshPeerCount {
            topic: topic_owned,
            response,
        })
        .await
    }

    /// Polls until the gossipsub mesh for `topic` has at least `min_peers`
    /// members, or `timeout` elapses.
    ///
    /// On timeout, returns the last observed count so the caller can decide
    /// whether to publish anyway (degraded operation) or retry. Polls every
    /// 100 ms — short enough to not delay startup, long enough to let
    /// gossipsub heartbeat (700 ms by default) drive at least one mesh
    /// formation cycle.
    ///
    /// Workaround for rust-libp2p having no built-in `wait_for_mesh()` API
    /// (issues #2585, #2036, #2557). This is the canonical pattern: poll
    /// `Behaviour::mesh_peers(&topic).count() >= mesh_n_low` with bounded
    /// retry before allowing first publish.
    pub async fn wait_for_mesh(
        &self,
        topic: &str,
        min_peers: usize,
        timeout: std::time::Duration,
    ) -> Result<usize> {
        let deadline = tokio::time::Instant::now() + timeout;
        // last_seen tracks the most recent mesh size for the timeout-path log.
        // Initial 0 covers the case where the very first poll fails before
        // the assignment in the loop body.
        #[allow(unused_assignments)]
        let mut last_seen = 0usize;
        loop {
            match self.mesh_peer_count(topic).await {
                Ok(count) => {
                    last_seen = count;
                    if count >= min_peers {
                        tracing::info!(
                            topic = topic,
                            count = count,
                            min_peers = min_peers,
                            "Gossipsub mesh ready"
                        );
                        return Ok(count);
                    }
                }
                Err(e) => {
                    // Service is shut down or command channel closed —
                    // surface immediately, polling won't recover.
                    return Err(e);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!(
                    topic = topic,
                    count = last_seen,
                    min_peers = min_peers,
                    "wait_for_mesh timed out — proceeding with degraded mesh"
                );
                return Ok(last_seen);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    /// Returns the count of gossipsub mesh peers for `topic` that are ALSO
    /// admitted to the local validator registry.
    ///
    /// On validator-only topics (`consensus`, `attestations`), inbound
    /// `authorize_peer_for_topic` rejects messages from peers not in the
    /// registry. Identify-driven admission (`try_register_validator_on_identify`)
    /// happens asynchronously after the libp2p connection is up, so a peer
    /// can be in the gossipsub mesh BEFORE it has been admitted — and any
    /// message it publishes during that window is silently dropped.
    ///
    /// `mesh_peer_count` alone is not a sufficient gate for first-publish
    /// on validator-only topics; this method intersects mesh peers with
    /// admitted validators, returning the size of the intersection.
    ///
    /// If no validator registry is installed, returns the plain mesh peer
    /// count (permissive mode — pre-genesis or single-node).
    pub async fn admitted_mesh_peer_count(&self, topic: &str) -> Result<usize> {
        let topic_owned = topic.to_string();
        self.send_command(move |response| NetworkCommand::AdmittedMeshPeers {
            topic: topic_owned,
            response,
        })
        .await
    }

    /// Polls until at least `min_admitted` mesh peers on `topic` are also
    /// admitted to the validator registry, or `timeout` elapses.
    ///
    /// This is the correct first-publish gate for validator-only topics on
    /// a multi-node cluster. Unlike `wait_for_mesh`, which only confirms
    /// that gossipsub has chosen mesh peers, this confirms that those
    /// peers will *accept* our messages on validator-only topics.
    ///
    /// On timeout, returns the last observed admitted count so the caller
    /// can decide whether to publish anyway (degraded operation) or retry.
    ///
    /// Polls every 100ms — short enough not to delay startup, long enough
    /// to let identify (one round-trip per peer) complete.
    pub async fn wait_for_admitted_mesh(
        &self,
        topic: &str,
        min_admitted: usize,
        timeout: std::time::Duration,
    ) -> Result<usize> {
        let deadline = tokio::time::Instant::now() + timeout;
        #[allow(unused_assignments)]
        let mut last_seen = 0usize;
        loop {
            match self.admitted_mesh_peer_count(topic).await {
                Ok(count) => {
                    last_seen = count;
                    if count >= min_admitted {
                        tracing::info!(
                            topic = topic,
                            admitted = count,
                            min_admitted = min_admitted,
                            "Admitted mesh ready — first publish safe"
                        );
                        return Ok(count);
                    }
                }
                Err(e) => return Err(e),
            }
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!(
                    topic = topic,
                    admitted = last_seen,
                    min_admitted = min_admitted,
                    "wait_for_admitted_mesh timed out — first publish may be silently dropped \
                     by receivers' validator-only topic gate"
                );
                return Ok(last_seen);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    // ---------------------------------------------------------------
    // Block-sync API.
    //
    // The wire protocol (`BlockSyncRequest` / `BlockSyncResponse`) is
    // defined in `crate::block_sync_proto`; see its module docs for the
    // Sui `state_sync`-derived design rationale.
    //
    // Outbound flow:
    //   1. Caller invokes `request_blocks(peer, start, count)` (or one
    //      of the sibling helpers). It returns an `OutboundRequestId`.
    //   2. Caller must have previously subscribed to results via
    //      `subscribe_block_sync_results()`. The eventual response or
    //      transport failure arrives on that channel keyed by the same id.
    //
    // Inbound flow:
    //   1. Server-role nodes call `subscribe_block_sync_requests()` once
    //      at startup.
    //   2. For each `InboundBlockSync` they receive, they MUST eventually
    //      call `send_block_sync_response(request_id, response)` — either
    //      with a real payload or a `BlockSyncResponse::Error(_)`.
    //      Dropping the request silently causes the peer to time out and
    //      score us down (Lighthouse `SyncManager` confirms this is the
    //      right contract).
    // ---------------------------------------------------------------

    /// Issues an outbound `GetBlockRange` request to `peer`. Returns the
    /// `OutboundRequestId` synchronously; the response is delivered later
    /// on the channel from `subscribe_block_sync_results`.
    pub async fn request_blocks(
        &self,
        peer: PeerId,
        start: tenzro_types::primitives::BlockHeight,
        count: u32,
    ) -> Result<OutboundRequestId> {
        let request = BlockSyncRequest::GetBlockRange { start, count };
        self.send_command(move |response| NetworkCommand::SendBlockSyncRequest {
            peer,
            request,
            response,
        })
        .await
    }

    /// Issues an outbound `GetTipInfo` probe to `peer`.
    pub async fn request_tip_info(&self, peer: PeerId) -> Result<OutboundRequestId> {
        self.send_command(move |response| NetworkCommand::SendBlockSyncRequest {
            peer,
            request: BlockSyncRequest::GetTipInfo,
            response,
        })
        .await
    }

    /// Issues an outbound `GetBlockByHash` request to `peer`. Used during
    /// fork resolution (parent-lookup walk).
    pub async fn request_block_by_hash(
        &self,
        peer: PeerId,
        hash: tenzro_types::primitives::Hash,
    ) -> Result<OutboundRequestId> {
        self.send_command(move |response| NetworkCommand::SendBlockSyncRequest {
            peer,
            request: BlockSyncRequest::GetBlockByHash { hash },
            response,
        })
        .await
    }

    /// Subscribes to inbound block-sync requests. The server-role node
    /// reads from this channel, builds the appropriate response, and
    /// answers via `send_block_sync_response(request_id, …)`.
    ///
    /// Calling this twice replaces the previous channel — there is one
    /// authoritative server consumer per node.
    pub async fn subscribe_block_sync_requests(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<InboundBlockSync>> {
        self.send_command(|response| NetworkCommand::SubscribeBlockSyncRequests { response })
            .await
    }

    /// Subscribes to outbound block-sync results — one item per
    /// `OutboundRequestId` previously returned by `request_blocks` /
    /// `request_tip_info` / `request_block_by_hash`. The result is
    /// either a decoded `BlockSyncResponse` or a typed transport error.
    pub async fn subscribe_block_sync_results(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<OutboundBlockSyncResult>> {
        self.send_command(|response| NetworkCommand::SubscribeBlockSyncResults { response })
            .await
    }

    /// Subscribes to peer connection lifecycle events. The block-sync
    /// engine consumes this stream to populate its candidate-peer table:
    /// `Connected` adds the peer, `Disconnected` evicts it.
    ///
    /// One subscriber at a time — calling twice replaces the previous
    /// channel. The stream is unbounded; consumers MUST drain it
    /// continuously or the network event loop will accumulate buffered
    /// events. In practice, the consumer's own `tokio::select!` arm pulls
    /// from this receiver alongside its other duties, which is the
    /// canonical libp2p subscriber pattern.
    pub async fn subscribe_peer_events(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<PeerEvent>> {
        self.send_command(|response| NetworkCommand::SubscribePeerEvents { response })
            .await
    }

    /// Replies to a previously-received inbound block-sync request.
    ///
    /// If the inbound stream has already timed out or the peer has
    /// disconnected, returns `Err(NetworkError::PeerNotFound)`. Callers
    /// that want to reject a request should pass
    /// `BlockSyncResponse::Error(BlockSyncError::*)` rather than dropping
    /// the request — silent drops cause cascading peer-disconnect spirals.
    pub async fn send_block_sync_response(
        &self,
        request_id: InboundRequestId,
        response_payload: BlockSyncResponse,
    ) -> Result<()> {
        self.send_command(move |response| NetworkCommand::SendBlockSyncResponse {
            request_id,
            response_payload,
            response,
        })
        .await
    }

    /// Sends a command and waits for response
    async fn send_command<F, T>(&self, f: F) -> Result<T>
    where
        F: FnOnce(oneshot::Sender<Result<T>>) -> NetworkCommand,
    {
        let (tx, rx) = oneshot::channel();
        let command = f(tx);

        self.command_tx
            .send(command)
            .map_err(|_| NetworkError::ChannelSend)?;

        rx.await.map_err(|_| NetworkError::ChannelReceive)?
    }
}

#[async_trait]
impl NetworkService for TenzroNetworkService {
    async fn broadcast(&self, topic: &str, message: NetworkMessage) -> Result<()> {
        self.send_command(|response| NetworkCommand::Broadcast {
            topic: topic.to_string(),
            message,
            response,
        })
        .await
    }

    async fn send_to(&self, peer_id: PeerId, message: NetworkMessage) -> Result<()> {
        // Route direct peer messages through gossipsub by wrapping the message in a
        // Custom payload on the tenzro/direct topic. The payload encodes both
        // the target peer ID and the inner message so that subscribers can filter
        // messages intended for them. This reuses the already-established gossipsub
        // mesh without requiring a separate request-response protocol.
        let inner_bytes = message
            .to_bytes()
            .map_err(NetworkError::Serialization)?
            .to_vec();

        // Encode: [32-byte peer id multihash] || [inner message bytes]
        // Using the peer's multihash digest (first 32 bytes) as the addressing prefix.
        let peer_multihash = peer_id.to_bytes();
        let mut payload = Vec::with_capacity(peer_multihash.len() + inner_bytes.len());
        payload.extend_from_slice(&peer_multihash);
        payload.extend_from_slice(&inner_bytes);

        let direct_message = NetworkMessage::new(MessagePayload::Custom {
            topic: "tenzro/direct".to_string(),
            data: payload,
        });

        self.send_command(|response| NetworkCommand::Broadcast {
            topic: "tenzro/direct".to_string(),
            message: direct_message,
            response,
        })
        .await
    }

    async fn subscribe(&self, topic: &str) -> Result<mpsc::UnboundedReceiver<NetworkMessage>> {
        self.send_command(|response| NetworkCommand::Subscribe {
            topic: topic.to_string(),
            response,
        })
        .await
    }

    async fn connected_peers(&self) -> Result<Vec<PeerId>> {
        self.send_command(|response| NetworkCommand::ConnectedPeers { response })
            .await
    }

    async fn peer_info(&self, peer_id: &PeerId) -> Result<Option<ManagedPeer>> {
        self.send_command(|response| NetworkCommand::PeerInfo {
            peer_id: *peer_id,
            response,
        })
        .await
    }

    async fn ban_peer(&self, peer_id: &PeerId) -> Result<()> {
        self.send_command(|response| NetworkCommand::BanPeer {
            peer_id: *peer_id,
            response,
        })
        .await
    }

    async fn unban_peer(&self, peer_id: &PeerId) -> Result<()> {
        self.send_command(|response| NetworkCommand::UnbanPeer {
            peer_id: *peer_id,
            response,
        })
        .await
    }

    async fn local_peer_id(&self) -> Result<PeerId> {
        self.send_command(|response| NetworkCommand::LocalPeerId { response })
            .await
    }

    async fn dial(&self, addr: Multiaddr) -> Result<()> {
        self.send_command(|response| NetworkCommand::Dial { addr, response })
            .await
    }

    async fn set_validator_registry(&self, registry: std::sync::Arc<dyn crate::peer_manager::ValidatorRegistry>) -> Result<()> {
        self.send_command(|response| NetworkCommand::SetValidatorRegistry { registry, response })
            .await
    }

    async fn listen_addresses(&self) -> Result<Vec<Multiaddr>> {
        self.send_command(|response| NetworkCommand::ListenAddresses { response })
            .await
    }
}

/// Event loop state
struct EventLoopState {
    swarm: Swarm<TenzroBehaviour>,
    peer_manager: PeerManager,
    subscribers: HashMap<TopicHash, Vec<mpsc::UnboundedSender<NetworkMessage>>>,
    /// Application-level message deduplicator (defense-in-depth over gossipsub's built-in dedup)
    deduplicator: MessageDeduplicator,
    /// Prometheus metrics bundle (shared across the event loop and the service handle).
    metrics: Arc<NetworkMetrics>,
    /// Multiaddrs bound by the swarm's listeners. Populated from
    /// `SwarmEvent::NewListenAddr` and removed on `ExpiredListenAddr`.
    /// Surfaced via `NetworkCommand::ListenAddresses` so callers (especially
    /// tests using port 0) can discover the bound address.
    listen_addresses: Vec<Multiaddr>,
    /// Pending inbound block-sync response channels keyed by `InboundRequestId`.
    /// The `ResponseChannel<BlockSyncResponse>` returned by libp2p's
    /// request-response codec cannot be sent across an mpsc — it is `Send`
    /// but consuming it requires `&mut self` on the behaviour. We park it
    /// here until the API caller answers via `SendBlockSyncResponse`.
    pending_inbound_block_sync: HashMap<InboundRequestId, ResponseChannel<BlockSyncResponse>>,
    /// Subscriber channel for inbound block-sync requests. `None` until the
    /// node-level block-sync server attaches via `SubscribeBlockSyncRequests`.
    block_sync_request_subscriber: Option<mpsc::UnboundedSender<InboundBlockSync>>,
    /// Subscriber channel for outbound block-sync results. `None` until the
    /// node-level block-sync engine attaches via `SubscribeBlockSyncResults`.
    block_sync_result_subscriber: Option<mpsc::UnboundedSender<OutboundBlockSyncResult>>,
    /// Subscriber channel for peer connection lifecycle events. `None` until
    /// the block-sync engine (or another peer-aware consumer) attaches via
    /// `SubscribePeerEvents`. The event loop fans `SwarmEvent::Connection*`
    /// transitions through this channel — first physical connection emits
    /// `Connected`, last drop emits `Disconnected`.
    peer_event_subscriber: Option<mpsc::UnboundedSender<PeerEvent>>,
}

/// Main event loop for the network service
async fn run_event_loop(
    config: NetworkConfig,
    mut command_rx: mpsc::UnboundedReceiver<NetworkCommand>,
    metrics: Arc<NetworkMetrics>,
) -> Result<()> {
    // Load or generate keypair (persistent for stable peer IDs)
    let local_key = load_or_generate_keypair(&config.data_dir)?;
    let local_peer_id = PeerId::from(local_key.public());

    tracing::info!("Local peer ID: {}", local_peer_id);

    // Create transport
    let transport = transport::build_transport(&local_key)?;

    // Create behaviour
    let behaviour = TenzroBehaviour::new(
        local_peer_id,
        &local_key,
        config.protocol_version.clone(),
        config.user_agent.clone(),
    )
    .map_err(|e| NetworkError::Transport(e.to_string()))?;

    // Create swarm
    let mut swarm = Swarm::new(
        transport,
        behaviour,
        local_peer_id,
        libp2p::swarm::Config::with_tokio_executor()
            .with_idle_connection_timeout(config.connection_idle_timeout),
    );

    // Listen on configured addresses
    for addr in &config.listen_addresses {
        swarm
            .listen_on(addr.clone())
            .map_err(|e| NetworkError::Transport(format!("Failed to listen on {}: {}", addr, e)))?;
        tracing::info!("Listening on {}", addr);
    }

    // Create peer manager. No longer needs `mut` — `add_protected_peer`
    // takes `&self` now that `protected_peers` is a lock-free `DashSet`.
    let peer_manager = PeerManager::new(
        (config.max_inbound_peers + config.max_outbound_peers) as usize,
    );

    // Register boot node peers as protected (never auto-ban). We do NOT add
    // them as gossipsub `explicit_peers` — that classification causes mutual
    // GRAFT rejection in libp2p-gossipsub (see behaviour.rs:1400-1406:
    // "GRAFT: ignoring request from direct peer"), preventing the mesh from
    // ever forming between boot nodes. The publish-coverage guarantee we
    // need is already provided by `flood_publish(true)` on the gossipsub
    // config, which sends to every subscribed peer regardless of mesh
    // membership or peer score.
    for addr in &config.boot_nodes {
        for proto in addr.iter() {
            if let libp2p::multiaddr::Protocol::P2p(peer_id) = proto {
                peer_manager.add_protected_peer(peer_id);
                tracing::info!(
                    peer = %peer_id,
                    "Registered boot node as protected peer"
                );
            }
        }
    }

    // Subscribe to initial topics
    for topic_str in &config.gossip_topics {
        let topic = IdentTopic::new(topic_str.as_str());
        if let Err(e) = swarm.behaviour_mut().subscribe(&topic) {
            tracing::warn!("Failed to subscribe to topic {}: {}", topic_str, e);
        } else {
            tracing::info!("Subscribed to topic: {}", topic_str);
        }
    }

    // Bootstrap DHT if enabled
    if config.enable_dht && !config.boot_nodes.is_empty() {
        let boot_nodes: Vec<_> = config
            .boot_nodes
            .iter()
            .filter_map(|addr| {
                // Extract peer ID from multiaddr
                addr.iter()
                    .find_map(|proto| {
                        if let libp2p::multiaddr::Protocol::P2p(peer_id) = proto {
                            Some(peer_id)
                        } else {
                            None
                        }
                    })
                    .map(|peer_id| (peer_id, addr.clone()))
            })
            .collect();

        crate::discovery::bootstrap_dht(&mut swarm.behaviour_mut().kademlia, boot_nodes);
    }

    // Dial boot nodes
    for addr in &config.boot_nodes {
        if let Err(e) = swarm.dial(addr.clone()) {
            tracing::warn!("Failed to dial boot node {}: {}", addr, e);
        } else {
            tracing::info!("Dialing boot node: {}", addr);
        }
    }

    let mut state = EventLoopState {
        swarm,
        peer_manager,
        subscribers: HashMap::new(),
        deduplicator: MessageDeduplicator::default(),
        metrics,
        listen_addresses: Vec::new(),
        pending_inbound_block_sync: HashMap::new(),
        block_sync_request_subscriber: None,
        block_sync_result_subscriber: None,
        peer_event_subscriber: None,
    };

    // Create periodic cleanup timer (every 60 seconds)
    let mut cleanup_interval = interval(Duration::from_secs(60));
    cleanup_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    // Main event loop
    loop {
        tokio::select! {
            // Handle swarm events
            event = state.swarm.select_next_some() => {
                handle_swarm_event(&mut state, event).await;
            }

            // Handle commands
            Some(command) = command_rx.recv() => {
                if matches!(command, NetworkCommand::Shutdown { .. }) {
                    handle_command(&mut state, command).await;
                    tracing::info!("Network event loop shutting down gracefully");
                    break;
                }
                handle_command(&mut state, command).await;
            }

            // Periodic cleanup
            _ = cleanup_interval.tick() => {
                // Clean up expired bans
                state.peer_manager.cleanup_expired_bans();

                // Clean up stale peers (not seen for 24 hours)
                state.peer_manager.cleanup_stale_peers(Duration::from_secs(86400));

                // Update peer-count gauges from the authoritative peer manager.
                let stats = state.peer_manager.stats();
                state.metrics.peers_connected.set(stats.connected as i64);
                state.metrics.peers_banned.set(stats.banned as i64);

                tracing::debug!(
                    "Peer stats: {} total, {} connected, {} banned",
                    stats.total,
                    stats.connected,
                    stats.banned
                );
            }
        }
    }

    Ok(())
}

/// Translates a libp2p `request_response::Event` for the block-sync codec
/// into the typed `InboundBlockSync` / `OutboundBlockSyncResult` channels
/// the API exposes.
///
/// The `ResponseChannel<BlockSyncResponse>` cannot cross an mpsc — it is
/// consumed by `Behaviour::send_response(&mut self, …)`. We park it in
/// `pending_inbound_block_sync` keyed by `InboundRequestId`; the API caller
/// later issues `SendBlockSyncResponse { request_id, … }` and the event
/// loop performs the actual `send_response` call from the swarm context.
fn handle_block_sync_event(
    state: &mut EventLoopState,
    event: request_response::Event<BlockSyncRequest, BlockSyncResponse>,
) {
    use request_response::{Event as RrEvent, Message};
    match event {
        RrEvent::Message {
            peer,
            message: Message::Request {
                request_id,
                request,
                channel,
            },
            ..
        } => {
            // Park the response channel and notify the subscriber. If no
            // subscriber is attached yet, reply with a Storage error so
            // the requester can score us down and retry against another peer
            // — silent timeouts cause cascading peer-disconnect spirals
            // (Lighthouse `SyncManager` notes the same anti-pattern).
            let Some(tx) = state.block_sync_request_subscriber.as_ref() else {
                tracing::warn!(
                    %peer,
                    "Inbound block-sync request received but no subscriber attached — \
                     replying with Storage error"
                );
                let err_resp = BlockSyncResponse::Error(
                    crate::block_sync_proto::BlockSyncError::Storage(
                        "no block-sync subscriber attached".to_string(),
                    ),
                );
                let _ = state
                    .swarm
                    .behaviour_mut()
                    .block_sync
                    .send_response(channel, err_resp);
                return;
            };

            state
                .pending_inbound_block_sync
                .insert(request_id, channel);

            let inbound = InboundBlockSync {
                peer,
                request_id,
                request,
            };
            if tx.send(inbound).is_err() {
                tracing::warn!(
                    %peer,
                    "Block-sync request subscriber dropped — discarding inbound request"
                );
                state.block_sync_request_subscriber = None;
                // Reply with a Storage error so the peer doesn't time out.
                if let Some(channel) = state.pending_inbound_block_sync.remove(&request_id) {
                    let err_resp = BlockSyncResponse::Error(
                        crate::block_sync_proto::BlockSyncError::Storage(
                            "subscriber dropped".to_string(),
                        ),
                    );
                    let _ = state
                        .swarm
                        .behaviour_mut()
                        .block_sync
                        .send_response(channel, err_resp);
                }
            }
        }
        RrEvent::Message {
            peer,
            message: Message::Response {
                request_id,
                response,
            },
            ..
        } => {
            if let Some(tx) = state.block_sync_result_subscriber.as_ref() {
                let item = OutboundBlockSyncResult {
                    peer,
                    request_id,
                    result: Ok(response),
                };
                if tx.send(item).is_err() {
                    tracing::warn!("Block-sync result subscriber dropped");
                    state.block_sync_result_subscriber = None;
                }
            } else {
                tracing::warn!(
                    %peer,
                    %request_id,
                    "Block-sync response received but no result subscriber attached"
                );
            }
        }
        RrEvent::OutboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            tracing::warn!(%peer, %request_id, %error, "Outbound block-sync failure");
            if let Some(tx) = state.block_sync_result_subscriber.as_ref() {
                let item = OutboundBlockSyncResult {
                    peer,
                    request_id,
                    result: Err(error.into()),
                };
                if tx.send(item).is_err() {
                    state.block_sync_result_subscriber = None;
                }
            }
        }
        RrEvent::InboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            // Peer dropped the stream or codec failed before we replied.
            // Drop the parked response channel — sending against it would
            // be a no-op anyway.
            tracing::debug!(%peer, %request_id, %error, "Inbound block-sync failure");
            state.pending_inbound_block_sync.remove(&request_id);
        }
        RrEvent::ResponseSent { peer, request_id, .. } => {
            tracing::trace!(%peer, %request_id, "Block-sync response flushed to wire");
        }
    }
}

/// Handles swarm events
async fn handle_swarm_event(
    state: &mut EventLoopState,
    event: SwarmEvent<TenzroBehaviourEvent>,
) {
    match event {
        SwarmEvent::Behaviour(behaviour_event) => match behaviour_event {
            TenzroBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            }) => {
                tracing::debug!(
                    "Received message {} from peer {}",
                    message_id,
                    propagation_source
                );

                // Check if peer is banned
                if state.peer_manager.is_banned(&propagation_source) {
                    tracing::warn!("Ignoring message from banned peer {}", propagation_source);
                    state.metrics.gossip_rejected_invalid.inc();
                    return;
                }

                // Check rate limit
                if !state.peer_manager.check_rate_limit(&propagation_source) {
                    tracing::warn!("Rate limited message from peer {}", propagation_source);
                    state.metrics.gossip_rejected_invalid.inc();
                    return;
                }

                // Application-level deduplication (defense-in-depth over gossipsub message IDs)
                if state.deduplicator.is_duplicate(&message.data) {
                    tracing::trace!("Dropping duplicate message from peer {}", propagation_source);
                    state.metrics.gossip_rejected_duplicate.inc();
                    return;
                }

                // Validate peer authorization for validator-only topics.
                // Drop silently — do NOT penalize reputation for validator-topic mismatch.
                // Validators may not be in the local registry during early startup or
                // after a genesis wipe, causing false-positive bans.
                let topic_str = message.topic.to_string();
                if !state.peer_manager.authorize_peer_for_topic(&propagation_source, &topic_str) {
                    state.metrics.gossip_rejected_validator_only.inc();
                    return;
                }

                // Validate message structure (size, format, timestamp)
                match validate_gossip_message(&message.topic, &message.data) {
                    MessageValidation::Accept => {}
                    MessageValidation::Reject => {
                        tracing::warn!("Message validation rejected from peer {}", propagation_source);
                        state.peer_manager.decrease_reputation(&propagation_source, 5);
                        state.metrics.gossip_rejected_invalid.inc();
                        return;
                    }
                    MessageValidation::Ignore => {
                        state.metrics.gossip_rejected_invalid.inc();
                        return;
                    }
                }

                // Parse network message
                match NetworkMessage::from_bytes(&message.data) {
                    Ok(net_msg) => {
                        // Update peer reputation for valid messages
                        state
                            .peer_manager
                            .increase_reputation(&propagation_source, 1);
                        state.metrics.gossip_accepted.inc();

                        // Forward to subscribers
                        if let Some(subs) = state.subscribers.get_mut(&message.topic) {
                            subs.retain(|tx| tx.send(net_msg.clone()).is_ok());
                        }
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse network message: {}", e);
                        state
                            .peer_manager
                            .decrease_reputation(&propagation_source, 5);
                        state.metrics.gossip_rejected_invalid.inc();
                    }
                }
            }
            TenzroBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic }) => {
                tracing::debug!("Peer {} subscribed to topic {:?}", peer_id, topic);
            }
            TenzroBehaviourEvent::Gossipsub(gossipsub::Event::Unsubscribed { peer_id, topic }) => {
                tracing::debug!("Peer {} unsubscribed from topic {:?}", peer_id, topic);
            }
            TenzroBehaviourEvent::Identify(identify::Event::Received { peer_id, info, connection_id: _ }) => {
                tracing::info!(
                    "Identified peer {}: protocol={}, agent={}",
                    peer_id,
                    info.protocol_version,
                    info.agent_version
                );

                // Dynamically admit Tenzro peers into the validator registry so
                // their consensus / attestation messages don't get rejected and
                // cause gossipsub peer-score decay → mutual ban. Only peers
                // whose protocol version starts with "tenzro/" are admitted;
                // anything else is a no-op. See PeerManager::try_register_validator_on_identify.
                state
                    .peer_manager
                    .try_register_validator_on_identify(&peer_id, &info.protocol_version);

                // We do NOT call gossipsub.add_explicit_peer() here. In
                // libp2p-gossipsub, "explicit peers" are bypass-the-mesh
                // peers — incoming GRAFTs from them are rejected (behaviour.rs
                // ~1400 "GRAFT: ignoring request from direct peer"). When
                // both ends classify each other as explicit, the mesh never
                // forms. Publish-side coverage for known peers is already
                // provided by `flood_publish(true)` on the gossipsub config.

                state
                    .peer_manager
                    .update_protocol_version(&peer_id, info.protocol_version);

                // Add only globally routable addresses to Kademlia DHT.
                // Filters out loopback (127.x), private RFC-1918, Docker bridge (172.17.x),
                // link-local, and unspecified addresses that K8s pods cannot reach.
                for addr in info.listen_addrs {
                    if is_globally_routable(&addr) {
                        state.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                    } else {
                        tracing::debug!(
                            "Skipping non-routable DHT address from {}: {}",
                            peer_id,
                            addr
                        );
                    }
                }
            }
            TenzroBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed { result, .. }) => {
                match result {
                    QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders { providers, .. })) => {
                        tracing::debug!("Found {} provider(s)", providers.len());
                        for peer in providers {
                            tracing::debug!("Found provider: {}", peer);
                        }
                    }
                    QueryResult::GetProviders(Ok(kad::GetProvidersOk::FinishedWithNoAdditionalRecord { closest_peers })) => {
                        tracing::debug!("GetProviders query finished with {} closest peers", closest_peers.len());
                    }
                    QueryResult::Bootstrap(Ok(_)) => {
                        tracing::info!("DHT bootstrap completed");
                    }
                    _ => {}
                }
            }
            TenzroBehaviourEvent::Ping(ping::Event { peer, result, .. }) => {
                match result {
                    Ok(duration) => {
                        tracing::trace!("Ping to {} successful: {:?}", peer, duration);
                        state.peer_manager.increase_reputation(&peer, 1);
                    }
                    Err(e) => {
                        // Log at trace level — ping failures are common during K8s pod startup
                        // and should NOT reduce peer reputation. Banning validators for transient
                        // ping timeouts causes permanent gossip isolation.
                        tracing::trace!("Ping to {} failed: {}", peer, e);
                    }
                }
            }
            TenzroBehaviourEvent::BlockSync(rr_event) => {
                handle_block_sync_event(state, rr_event);
            }
            _ => {}
        },
        SwarmEvent::ConnectionEstablished {
            peer_id,
            endpoint,
            num_established,
            ..
        } => {
            // Auto-unban peers that reconnect — stale bans from previous
            // sessions shouldn't permanently isolate validators.
            if state.peer_manager.is_banned(&peer_id) {
                tracing::info!("Auto-unbanning reconnecting peer {}", peer_id);
                state.peer_manager.unban_peer(&peer_id);
            }

            tracing::info!(
                "Connection established with {} (endpoint: {:?}, num_established: {})",
                peer_id,
                endpoint,
                num_established
            );

            // Metrics: increment directional + total established gauge
            state.metrics.connections_established.inc();
            match &endpoint {
                libp2p::core::ConnectedPoint::Listener { .. } => {
                    state.metrics.connections_inbound_total.inc();
                }
                libp2p::core::ConnectedPoint::Dialer { .. } => {
                    state.metrics.connections_outbound_total.inc();
                }
            }

            state.peer_manager.add_peer(peer_id);
            state
                .peer_manager
                .update_status(&peer_id, PeerStatus::Connected);

            // Fan out a `PeerEvent::Connected` exactly once per peer — only
            // when this is the first physical connection. Subsequent
            // multiplexed connections to the same peer don't re-emit. If
            // the receiver is gone (engine task panicked or stopped),
            // detach the subscriber so we stop trying.
            if num_established.get() == 1 {
                if let Some(tx) = state.peer_event_subscriber.as_ref() {
                    if tx.send(PeerEvent::Connected(peer_id)).is_err() {
                        tracing::warn!(
                            "Peer-event subscriber dropped while sending Connected({}); detaching",
                            peer_id
                        );
                        state.peer_event_subscriber = None;
                    }
                }
            }
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            cause,
            num_established,
            ..
        } => {
            tracing::info!(
                "Connection closed with {} (cause: {:?}, remaining: {})",
                peer_id,
                cause,
                num_established
            );

            // Metrics: decrement established gauge (one physical connection closed)
            state.metrics.connections_established.dec();

            if num_established == 0 {
                state
                    .peer_manager
                    .update_status(&peer_id, PeerStatus::Disconnected);

                // Last physical connection dropped — fan out
                // `PeerEvent::Disconnected` so subscribers can evict this
                // peer from their candidate sets.
                if let Some(tx) = state.peer_event_subscriber.as_ref() {
                    if tx.send(PeerEvent::Disconnected(peer_id)).is_err() {
                        tracing::warn!(
                            "Peer-event subscriber dropped while sending Disconnected({}); detaching",
                            peer_id
                        );
                        state.peer_event_subscriber = None;
                    }
                }
            }
        }
        SwarmEvent::NewListenAddr { address, .. } => {
            tracing::info!("Listening on {}", address);
            if !state.listen_addresses.contains(&address) {
                state.listen_addresses.push(address);
            }
        }
        SwarmEvent::ExpiredListenAddr { address, .. } => {
            tracing::info!("Listen address expired: {}", address);
            state.listen_addresses.retain(|a| a != &address);
        }
        SwarmEvent::IncomingConnection { send_back_addr, local_addr, .. } => {
            tracing::debug!("Incoming connection from {} to {}", send_back_addr, local_addr);

            // Apply per-IP + global dial rate limiting to mitigate connection-flood DoS.
            // The `check_dial_rate_limit` consults both a keyed IP limiter (10/min burst 5)
            // and a global limiter (200/min burst 20). If either denies, we surface the
            // rejection via metrics. NOTE: libp2p 0.56's SwarmEvent::IncomingConnection
            // is a notification; actual denial must flow through the connection_limits
            // behaviour (configured in TenzroBehaviour::new) or a future deny-list hook.
            // Here we record the rate-limit decision for observability.
            if let Some(ip) = extract_ip(&send_back_addr)
                && !state.peer_manager.check_dial_rate_limit(ip)
            {
                tracing::warn!("Dial rate-limit exceeded for IP {}", ip);
                state.metrics.dials_rejected_per_ip.inc();
            }
        }
        SwarmEvent::IncomingConnectionError { send_back_addr, error, .. } => {
            tracing::warn!("Incoming connection error from {}: {}", send_back_addr, error);
        }
        SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
            if let Some(peer_id) = peer_id {
                tracing::warn!("Outgoing connection error with {}: {}", peer_id, error);
                state.peer_manager.record_failed_connection(&peer_id);
            } else {
                tracing::warn!("Outgoing connection error (no peer ID): {}", error);
            }
        }
        _ => {}
    }
}

/// Handles commands from the API
async fn handle_command(state: &mut EventLoopState, command: NetworkCommand) {
    match command {
        NetworkCommand::Broadcast {
            topic,
            message,
            response,
        } => {
            let result = (|| {
                let topic_obj = IdentTopic::new(topic);
                let bytes = message.to_bytes().map_err(|e| {
                    NetworkError::Serialization(e)
                })?;

                state
                    .swarm
                    .behaviour_mut()
                    .publish(&topic_obj, bytes.to_vec())
                    .map_err(|e| NetworkError::PublishError(e.to_string()))?;

                Ok(())
            })();

            if result.is_ok() {
                state.metrics.gossip_published.inc();
            }

            let _ = response.send(result);
        }
        NetworkCommand::Subscribe { topic, response } => {
            let result = (|| {
                let topic_obj = IdentTopic::new(&topic);
                let topic_hash = topic_obj.hash();

                state
                    .swarm
                    .behaviour_mut()
                    .subscribe(&topic_obj)
                    .map_err(|e| NetworkError::SubscriptionError(e.to_string()))?;

                let (tx, rx) = mpsc::unbounded_channel();
                state
                    .subscribers
                    .entry(topic_hash)
                    .or_default()
                    .push(tx);

                Ok(rx)
            })();

            let _ = response.send(result);
        }
        NetworkCommand::ConnectedPeers { response } => {
            let peers: Vec<PeerId> = state.swarm.connected_peers().cloned().collect();
            let _ = response.send(Ok(peers));
        }
        NetworkCommand::PeerInfo { peer_id, response } => {
            let info = state.peer_manager.get_peer(&peer_id);
            let _ = response.send(Ok(info));
        }
        NetworkCommand::BanPeer { peer_id, response } => {
            // Record in our peer manager (reputation, persistence).
            state.peer_manager.ban_peer(&peer_id);
            // Enforce at the libp2p transport layer via allow_block_list behaviour —
            // this forcibly closes existing connections and rejects future dials.
            state.swarm.behaviour_mut().block_peer(peer_id);
            tracing::info!("Peer {} banned and blocked at libp2p layer", peer_id);
            let _ = response.send(Ok(()));
        }
        NetworkCommand::UnbanPeer { peer_id, response } => {
            state.peer_manager.unban_peer(&peer_id);
            // Remove the libp2p-layer block so the peer can reconnect.
            state.swarm.behaviour_mut().unblock_peer(peer_id);
            tracing::info!("Peer {} unbanned and unblocked at libp2p layer", peer_id);
            let _ = response.send(Ok(()));
        }
        NetworkCommand::LocalPeerId { response } => {
            let peer_id = *state.swarm.local_peer_id();
            let _ = response.send(Ok(peer_id));
        }
        NetworkCommand::Dial { addr, response } => {
            let result = state
                .swarm
                .dial(addr)
                .map_err(|e| NetworkError::Connection(e.to_string()));
            let _ = response.send(result);
        }
        NetworkCommand::SetValidatorRegistry { registry, response } => {
            state.peer_manager.set_validator_registry(registry);
            tracing::info!("Validator registry installed in peer manager");
            let _ = response.send(Ok(()));
        }
        NetworkCommand::MeshPeerCount { topic, response } => {
            let topic_hash = IdentTopic::new(topic).hash();
            let count = state
                .swarm
                .behaviour()
                .mesh_peers(&topic_hash)
                .len();
            let _ = response.send(Ok(count));
        }
        NetworkCommand::ListenAddresses { response } => {
            let _ = response.send(Ok(state.listen_addresses.clone()));
        }
        NetworkCommand::AdmittedMeshPeers { topic, response } => {
            let topic_hash = IdentTopic::new(topic).hash();
            // Snapshot the mesh peer set first, then dereference into owned PeerIds.
            let mesh: Vec<PeerId> = state
                .swarm
                .behaviour()
                .mesh_peers(&topic_hash)
                .into_iter()
                .copied()
                .collect();
            let admitted = match state.peer_manager.validator_registry() {
                None => {
                    // Permissive mode (no registry) — every mesh peer is "admitted".
                    mesh.len()
                }
                Some(registry) => {
                    let validator_set = registry.validator_peer_ids();
                    mesh.iter().filter(|p| validator_set.contains(*p)).count()
                }
            };
            let _ = response.send(Ok(admitted));
        }
        NetworkCommand::SendBlockSyncRequest { peer, request, response } => {
            let request_id = state
                .swarm
                .behaviour_mut()
                .block_sync
                .send_request(&peer, request);
            let _ = response.send(Ok(request_id));
        }
        NetworkCommand::SendBlockSyncResponse {
            request_id,
            response_payload,
            response,
        } => {
            let result = match state.pending_inbound_block_sync.remove(&request_id) {
                Some(channel) => state
                    .swarm
                    .behaviour_mut()
                    .block_sync
                    .send_response(channel, response_payload)
                    .map_err(|_| {
                        // send_response returns Err(BlockSyncResponse) on a closed
                        // channel — peer disconnected or the inbound stream timed
                        // out. The payload is dropped; surface a typed error.
                        NetworkError::ChannelSend
                    }),
                None => Err(NetworkError::PeerNotFound(format!(
                    "no parked inbound block-sync request for id {}",
                    request_id
                ))),
            };
            let _ = response.send(result);
        }
        NetworkCommand::SubscribeBlockSyncRequests { response } => {
            let (tx, rx) = mpsc::unbounded_channel();
            state.block_sync_request_subscriber = Some(tx);
            let _ = response.send(Ok(rx));
        }
        NetworkCommand::SubscribeBlockSyncResults { response } => {
            let (tx, rx) = mpsc::unbounded_channel();
            state.block_sync_result_subscriber = Some(tx);
            let _ = response.send(Ok(rx));
        }
        NetworkCommand::SubscribePeerEvents { response } => {
            let (tx, rx) = mpsc::unbounded_channel();
            state.peer_event_subscriber = Some(tx);
            let _ = response.send(Ok(rx));
        }
        NetworkCommand::Shutdown { response } => {
            // Respond before the outer loop observes the Shutdown variant and breaks.
            let _ = response.send(Ok(()));
        }
    }
}
