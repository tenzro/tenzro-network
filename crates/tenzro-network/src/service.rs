//! Main NetworkService for Tenzro Network

use crate::{
    behaviour::{TenzroBehaviour, TenzroBehaviourEvent},
    config::NetworkConfig,
    error::{NetworkError, Result},
    gossip::{GossipTopics, MessageDeduplicator, MessageValidation, validate_gossip_message},
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
    if let Some(parent) = key_path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            tracing::warn!("Failed to create directory {}: {} — keypair will be ephemeral", parent.display(), e);
            return Ok(keypair);
        }
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
        // Custom payload on the tenzro/direct/1.0.0 topic. The payload encodes both
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
            topic: "tenzro/direct/1.0.0".to_string(),
            data: payload,
        });

        self.send_command(|response| NetworkCommand::Broadcast {
            topic: "tenzro/direct/1.0.0".to_string(),
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
    /// Gossip topics (stored for potential future introspection/unsubscribe APIs)
    #[allow(dead_code)]
    topics: GossipTopics,
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

    // Create topics
    let topics = GossipTopics::new();

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
        topics,
        subscribers: HashMap::new(),
        deduplicator: MessageDeduplicator::default(),
        metrics,
        listen_addresses: Vec::new(),
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
            if let Some(ip) = extract_ip(&send_back_addr) {
                if !state.peer_manager.check_dial_rate_limit(ip) {
                    tracing::warn!("Dial rate-limit exceeded for IP {}", ip);
                    state.metrics.dials_rejected_per_ip.inc();
                }
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
        NetworkCommand::Shutdown { response } => {
            // Respond before the outer loop observes the Shutdown variant and breaks.
            let _ = response.send(Ok(()));
        }
    }
}
