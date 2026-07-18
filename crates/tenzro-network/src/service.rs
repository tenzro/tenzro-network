//! Main NetworkService for Tenzro Network

use crate::{
    behaviour::{TenzroBehaviour, TenzroBehaviourEvent},
    block_sync_proto::{BlockSyncRequest, BlockSyncResponse},
    config::NetworkConfig,
    consensus_direct_proto::{
        ConsensusDirectError, ConsensusDirectRequest, ConsensusDirectResponse,
        MAX_INBOUND_STREAMS_PER_PEER,
    },
    da_committee_relay::{
        DaCommitteeError, DaCommitteeRequest, DaCommitteeResponse,
        MAX_INBOUND_STREAMS_PER_PEER as DA_COMMITTEE_MAX_INBOUND_STREAMS_PER_PEER,
    },
    db_replicate_proto::{
        DbReplicateError, DbReplicateRequest, DbReplicateResponse,
        MAX_INBOUND_STREAMS_PER_PEER as DB_REPLICATE_MAX_INBOUND_STREAMS_PER_PEER,
    },
    error::{NetworkError, Result},
    gossip::{MessageDeduplicator, MessageValidation, validate_gossip_message},
    message::{ConsensusMessage, NetworkMessage, MessagePayload},
    metrics::NetworkMetrics,
    peer_manager::{PeerManager, ManagedPeer},
};
use async_trait::async_trait;
use futures::StreamExt;
use libp2p::{
    autonat, dcutr,
    gossipsub::{self, IdentTopic, TopicHash},
    identify,
    kad::{self, QueryResult},
    mdns, ping, relay,
    request_response::{self, InboundRequestId, OutboundRequestId, ResponseChannel},
    swarm::{dial_opts::DialOpts, SwarmEvent},
    Multiaddr, PeerId, Swarm,
};
use parking_lot::Mutex;
use prometheus_client::registry::Registry;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{interval, MissedTickBehavior};
use tenzro_types::network::PeerStatus;

/// Builds `DialOpts` for an outbound dial that forces a freshly-allocated
/// source port (`PortUse::New`) instead of libp2p's default best-effort reuse
/// of the listen port.
///
/// Port reuse binds the dial socket to our listen port (e.g. 9000). When the
/// remote peer also dials us back on that same port — which the boot nodes do
/// via the Identify-driven `add_peer_address` + `dial` path below — the two
/// SYNs cross and the OS fuses them into a single TCP *simultaneous open*
/// socket. On a fused socket BOTH ends believe they are the dialer, so both
/// libp2p-tls halves send a ClientHello and the handshake desyncs with
/// `rustls: Received a ClientHello while expecting [ServerHello]` →
/// `Failed to upgrade client connection`. This is invisible on a LAN/loopback
/// (timing rarely collides) but reproduces reliably against an internet peer
/// that dials back. Allocating a new ephemeral source port per dial removes
/// the shared 5-tuple and makes simultaneous open impossible.
///
/// A `/p2p/<peer-id>` suffix in `addr`, if present, is preserved so the dial
/// is still authenticated against the expected peer.
fn dial_opts_new_port(addr: Multiaddr) -> DialOpts {
    let peer_id = addr.iter().find_map(|proto| match proto {
        libp2p::multiaddr::Protocol::P2p(peer_id) => Some(peer_id),
        _ => None,
    });
    match peer_id {
        Some(peer_id) => DialOpts::peer_id(peer_id)
            .addresses(vec![addr])
            .allocate_new_port()
            .build(),
        None => DialOpts::unknown_peer_id()
            .address(addr)
            .allocate_new_port()
            .build(),
    }
}

/// Promote Kademlia from Client to Server mode once sustained direct
/// reachability is confirmed. No-op if already in Server mode. Called from
/// AutoNAT-client success + DCUtR-success handlers where reachability
/// confidence advances.
///
/// Rationale (per libp2p `kad::Mode` docs + go-libp2p auto-mode): a NAT'd
/// node in Server mode hands out records other peers can't validate via
/// dial-back and pollutes k-buckets. Start in Client and promote once the
/// reachability tracker reports `Direct` at full confidence.
fn maybe_promote_kad_to_server(state: &mut EventLoopState) {
    if state.reachability.tier() == crate::reachability::ReachabilityTier::Direct {
        // libp2p exposes no getter for the current mode; setting Server is
        // idempotent — a repeat call is a no-op inside kad::Behaviour.
        state
            .swarm
            .behaviour_mut()
            .kademlia
            .set_mode(Some(libp2p::kad::Mode::Server));
        tracing::info!(
            "Kademlia promoted to Server mode — sustained direct reachability confirmed"
        );
    }
}

/// Loads a persistent Ed25519 keypair from disk, or generates and saves a new one.
///
/// The keypair is stored as a protobuf-encoded file at `{data_dir}/p2p_key`.
/// This ensures the node has a stable PeerId across restarts.
///
/// Idempotent: the first call generates and persists the key; later calls
/// (including the node computing its local PeerId before network start to
/// sign a PeerId↔validator-identity binding) load the same key.
pub fn load_or_generate_keypair(data_dir: &Option<PathBuf>) -> Result<libp2p::identity::Keypair> {
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

/// Returns true only if `addr` contains an IP that other nodes can actually
/// reach. Rejects:
///   - loopback (127.0.0.0/8 / ::1)
///   - link-local (169.254.0.0/16 / fe80::/10)
///   - unspecified (0.0.0.0 / ::)
///   - broadcast, documentation, benchmarking ranges
///   - Docker bridge default range 172.16.0.0/12 — when a node `--network host`s
///     a container, libp2p enumerates the docker0 bridge (commonly 172.17.0.1)
///     and advertises it via Identify. Other peers then dial that address, hit
///     their OWN docker0 bridge, and get "Unexpected peer ID" from whatever
///     local container happens to be there. Per-IP rate limiters then ban the
///     legitimate peer. Observed on the GCE multi-region testnet 2026-05-14.
///   - IPv4 192.168.0.0/16 (consumer-NAT range — never inside our datacenter
///     deployment; if a node reports it, it's a misconfig / NAT leak)
///   - IPv6 unique-local (fc00::/7) and multicast (ff00::/8)
///   - addresses with no IP component at all
///
/// IPv4 10.0.0.0/8 is intentionally ACCEPTED — this is the GCE/AWS/K8s VPC
/// subnet range and is the only reachable address for intra-region peers
/// before AutoNAT confirms a public external IP. Cross-region peers connect
/// via the public IPs that GCE allocates (which aren't in any RFC-1918 range).
fn is_globally_routable(addr: &Multiaddr) -> bool {
    use libp2p::multiaddr::Protocol;
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => {
                let octets = ip.octets();
                // 172.16.0.0/12 — docker bridge default + corp-NAT range
                let is_docker_or_corp = octets[0] == 172 && (octets[1] & 0xf0) == 16;
                // 192.168.0.0/16 — consumer NAT, never in our DC deploy
                let is_consumer_nat = octets[0] == 192 && octets[1] == 168;
                // 100.64.0.0/10 — RFC 6598 carrier-grade NAT
                let is_cgn = octets[0] == 100 && (octets[1] & 0xc0) == 64;
                if ip.is_loopback()
                    || ip.is_link_local()
                    || ip.is_unspecified()
                    || ip.is_broadcast()
                    || ip.is_documentation()
                    || is_docker_or_corp
                    || is_consumer_nat
                    || is_cgn
                {
                    return false;
                }
                return true;
            }
            Protocol::Ip6(ip) => {
                let seg0 = ip.segments()[0];
                if ip.is_loopback()
                    || ip.is_unspecified()
                    || ip.is_multicast()
                    || (seg0 & 0xffc0) == 0xfe80  // fe80::/10 link-local
                    || (seg0 & 0xfe00) == 0xfc00  // fc00::/7 unique-local
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

/// Extracts the transport port from a libp2p `Multiaddr`, if any.
///
/// Walks the protocol stack and returns the first TCP/UDP/QUIC port encoded
/// in the address. Used to gate `observed_addr` promotion on a
/// listen-port match — see `is_observed_port_one_of_ours` below.
fn extract_port(addr: &Multiaddr) -> Option<u16> {
    use libp2p::multiaddr::Protocol;
    for proto in addr.iter() {
        match proto {
            Protocol::Tcp(p) | Protocol::Udp(p) => return Some(p),
            _ => continue,
        }
    }
    None
}

/// Returns `true` if the port carried by `observed` matches at least one
/// of the ports we are actually listening on.
///
/// This is the canonical defence against promoting a NAT-translated outbound
/// source port as if it were a reachable listen address. The mode where this
/// matters in practice: a node behind a stateful NAT (cloud VPC, home
/// router, mobile carrier) dials a peer; the peer's libp2p Identify reports
/// `observed_addr` = `(our_public_ip, ephemeral_source_port)`. The
/// ephemeral source port is *not* a listener — nothing is bound there. If we
/// promote it via `Swarm::add_external_address`, we advertise an unreachable
/// address that subsequent peers will dial and fail on, halting consensus
/// when the bootstrap node restarts (see `consensus_stall_2026_05_18`).
///
/// Pattern mirrors go-libp2p `observedAddrManager.shouldRecordObservation`
/// and rust-libp2p ≥ 0.45 Identify, both of which require the observation
/// to match one of the host's actual listen addresses before promotion.
///
/// Wildcard `0.0.0.0` / `::` listen addresses are bound to their port; the
/// port is the salient comparison key because the public IP cannot be
/// determined from the wildcard.
fn is_observed_port_one_of_ours(observed: &Multiaddr, our_listen_addrs: &[Multiaddr]) -> bool {
    let Some(observed_port) = extract_port(observed) else {
        return false;
    };
    our_listen_addrs
        .iter()
        .filter_map(extract_port)
        .any(|p| p == observed_port)
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

/// An inbound cluster-tunnel frame received from a head peer.
///
/// The cluster member's serving runtime MUST eventually call
/// [`TenzroNetworkService::send_cluster_tunnel_response`] with the matching
/// `request_id`, supplying any return-path frames its local `rpc-server`
/// produced. Dropping the value without responding leaves the head's request
/// to time out, which it treats as a stage failure.
#[derive(Debug)]
pub struct InboundClusterTunnel {
    pub peer: PeerId,
    pub request_id: InboundRequestId,
    pub request: crate::cluster_tunnel_proto::ClusterTunnelRequest,
}

/// Outbound cluster-tunnel result delivered asynchronously to the head's
/// serving runtime after it issues `send_cluster_tunnel_frame`.
///
/// `result` carries either the peer's `ClusterTunnelResponse` (an `Ack` whose
/// `return_frames` are the member's return-path bytes, or an `Error`) or a
/// typed transport failure. The runtime drops the session on either error
/// class and fails over.
#[derive(Debug)]
pub struct OutboundClusterTunnelResult {
    pub peer: PeerId,
    pub request_id: OutboundRequestId,
    pub result: std::result::Result<
        crate::cluster_tunnel_proto::ClusterTunnelResponse,
        BlockSyncOutboundError,
    >,
}

/// An inbound committee-DA request (`StoreSliver` or `FetchSliver`) received
/// from a writer or reader peer.
///
/// The serving member's DA handler MUST eventually call
/// [`NetworkService::send_da_committee_response`] with the matching
/// `request_id`, supplying the signed attestation (for `StoreSliver`) or the
/// held sliver bytes (for `FetchSliver`). Dropping the value without
/// responding leaves the requester's request to time out, which it treats the
/// same as a missing attestation / missing sliver.
#[derive(Debug)]
pub struct InboundDaCommittee {
    pub peer: PeerId,
    pub request_id: InboundRequestId,
    pub request: DaCommitteeRequest,
}

/// An inbound database replicated-write request (`ApplyWrite`) received from a
/// peer holder of the same partition.
///
/// The serving holder's replication handler MUST eventually call
/// [`NetworkService::send_db_replicate_response`] with the matching
/// `request_id`, supplying the engine's response body (for a successful apply)
/// or an error. Dropping the value without responding leaves the requester's
/// request to time out, which it treats the same as a failed holder for write
/// consistency.
#[derive(Debug)]
pub struct InboundDbReplicate {
    pub peer: PeerId,
    pub request_id: InboundRequestId,
    pub request: DbReplicateRequest,
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

    /// Sets the durable ban store; persisted bans are hydrated and re-enforced
    /// at the libp2p transport layer immediately.
    async fn set_ban_store(&self, store: std::sync::Arc<dyn crate::peer_manager::BanStore>) -> Result<()>;

    /// Returns the set of multiaddrs the swarm is currently listening on.
    ///
    /// Useful for tests and bootstrap scenarios where the listen port is
    /// auto-assigned (e.g., `/ip4/127.0.0.1/tcp/0`) and the caller needs to
    /// know the bound address to share with peers.
    async fn listen_addresses(&self) -> Result<Vec<Multiaddr>>;

    /// Sends a HotStuff-2 `ConsensusMessage` directly to every currently-
    /// admitted validator over the `consensus-direct` request-response
    /// overlay.
    ///
    /// Replaces the gossipsub `tenzro/consensus` publish path. The local
    /// `ValidatorRegistry` snapshot is taken at send time; the message is
    /// fanned out one request per peer. Per-peer transport failures are
    /// logged but do NOT fail the call — quorum is the consumer's
    /// responsibility, not the transport's.
    ///
    /// Returns `Ok(usize)` with the number of peers the request was
    /// successfully dispatched to (in-flight; not yet acknowledged).
    /// Returns `Err` only if no validator registry is installed or if
    /// the validator set is empty (single-node operation; nothing to do).
    async fn broadcast_to_validators(&self, message: ConsensusMessage) -> Result<usize>;

    /// Returns the count of currently-connected peers that are also
    /// admitted to the local validator registry.
    ///
    /// This is the warm-up gate for first-publish on the consensus-direct
    /// overlay: a non-zero count means at least one validator peer is
    /// reachable AND admitted, so `broadcast_to_validators` will dispatch
    /// to at least one wire-bound stream.
    ///
    /// Returns 0 if no validator registry is installed (single-node /
    /// pre-genesis operation).
    async fn connected_validator_count(&self) -> Result<usize>;

    /// Subscribes to inbound `ConsensusMessage`s arriving over the
    /// `consensus-direct` overlay. Replaces the consensus-side
    /// `subscribe("tenzro/consensus")` path.
    ///
    /// Only one subscriber is supported at a time — calling twice replaces
    /// the previous channel. The subscriber MUST drain the receiver
    /// continuously; if the channel is full or dropped, the event loop
    /// responds to the sending peer with `ConsensusDirectError::NoSubscriber`,
    /// surfacing the back-pressure to the consensus engine on the other side.
    async fn subscribe_consensus_direct(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<ConsensusMessage>>;

    /// Installs the DID-to-PeerId resolver used by the MPC relay overlay.
    ///
    /// The resolver is consulted on every outbound `send_mpc_relay_message`
    /// (to find the PeerId for `to_did`) and on every inbound MPC request
    /// (to audit that `from_did` is in fact controlled by the sending peer).
    /// A missing resolver causes outbound sends to fail with
    /// `NetworkError::InvalidConfig` and inbound messages to be rejected
    /// with `MpcRelayError::UnknownSender` — the relay is fail-closed.
    ///
    /// Idempotent — calling twice replaces the prior resolver.
    async fn set_mpc_did_resolver(
        &self,
        resolver: std::sync::Arc<dyn crate::mpc_relay::MpcDidResolver>,
    ) -> Result<()>;

    /// Sends one MPC round message to the peer that controls `to_did`.
    ///
    /// Resolves `to_did` through the installed `MpcDidResolver`; returns
    /// `Err(NetworkError::PeerNotFound)` if the DID does not resolve. The
    /// returned `Ok(())` means the request was handed to the libp2p
    /// request-response codec — not that the peer has acknowledged it. The
    /// MPC session driver on the other side will reply `Ack`/`Error`
    /// asynchronously; transport-level failures (peer unreachable, timeout)
    /// surface through the codec's `OutboundFailure` event and are logged
    /// by the event loop. The bridge-side session driver's per-message
    /// receive timer is the authoritative end-to-end deadline.
    async fn send_mpc_relay_message(
        &self,
        message: crate::mpc_relay::MpcRelayRequest,
    ) -> Result<()>;

    /// Subscribes to inbound MPC relay round messages.
    ///
    /// Only one subscriber is supported at a time — calling twice replaces
    /// the previous channel. The subscriber MUST drain the receiver
    /// continuously; if the channel is full or dropped, the event loop
    /// responds to the sending peer with `MpcRelayError::NoSubscriber` so
    /// the sender's session driver can fast-fail and abort the session
    /// rather than wait for a per-round timeout. The receiver delivers
    /// `MpcRelayRequest` envelopes that have already been audited
    /// (`from_did` ↔ peer-ID match verified against the installed DID
    /// resolver) — the consumer can trust the `from_did` field.
    async fn subscribe_mpc_relay(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<crate::mpc_relay::MpcRelayRequest>>;

    /// Sends one cluster-tunnel frame to a member peer over the
    /// `cluster-tunnel` request-response overlay.
    ///
    /// Used by the pipeline head's serving runtime to relay its local ggml
    /// `rpc-server` byte stream to a member. Returns the `OutboundRequestId`
    /// synchronously; the member's `Ack` (carrying any return-path frames) or
    /// a transport failure is delivered later through the channel registered
    /// with `subscribe_cluster_tunnel_results`. The head addresses the member
    /// by `PeerId` directly — no DID resolution, since cluster membership is
    /// established out of band by the cluster planner.
    async fn send_cluster_tunnel_frame(
        &self,
        peer: PeerId,
        request: crate::cluster_tunnel_proto::ClusterTunnelRequest,
    ) -> Result<OutboundRequestId>;

    /// Answers an inbound cluster-tunnel frame identified by `request_id`.
    ///
    /// Called by a member's serving runtime after it splices the frame into
    /// its local `rpc-server` socket. The `response` is an `Ack` whose
    /// `return_frames` carry bytes read back from that socket, or an `Error`
    /// describing why the frame could not be served. If the parked channel
    /// has been dropped (head disconnected, stream timed out) the call
    /// returns `Err(NetworkError::ChannelSend)`.
    async fn send_cluster_tunnel_response(
        &self,
        request_id: InboundRequestId,
        response: crate::cluster_tunnel_proto::ClusterTunnelResponse,
    ) -> Result<()>;

    /// Subscribes to inbound cluster-tunnel frames. Only one subscriber is
    /// supported at a time — calling twice replaces the previous channel.
    /// Used by a member's serving runtime to receive frames a head relays to
    /// its loopback `rpc-server`.
    async fn subscribe_cluster_tunnel_requests(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<InboundClusterTunnel>>;

    /// Subscribes to outbound cluster-tunnel results. Only one subscriber is
    /// supported at a time. Used by the head's serving runtime to correlate
    /// `OutboundRequestId`s from `send_cluster_tunnel_frame` with the
    /// member's response or a transport error.
    async fn subscribe_cluster_tunnel_results(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<OutboundClusterTunnelResult>>;

    /// Sends one committee-DA request (`StoreSliver` / `FetchSliver`) to a
    /// member peer and awaits its reply.
    ///
    /// Unlike the fire-and-forget cluster-tunnel / MPC-relay overlays, the
    /// committee-DA protocol is reply-carrying: a `StoreSliver` returns the
    /// member's signed attestation and a `FetchSliver` returns the held sliver
    /// bytes. The event loop parks the caller's reply channel keyed by the
    /// `OutboundRequestId` and fulfils it when the peer's `Message::Response`
    /// arrives (or an `OutboundFailure` maps to a transport error). The member
    /// is addressed by `PeerId` directly — the node-layer adapter resolves the
    /// committee index → validator address → `PeerId` before calling this.
    async fn da_committee_request(
        &self,
        peer: PeerId,
        request: DaCommitteeRequest,
    ) -> Result<DaCommitteeResponse>;

    /// Answers an inbound committee-DA request identified by `request_id`.
    ///
    /// Called by a member's DA handler after it stores its sliver (returning
    /// [`DaCommitteeResponse::Attestation`]) or looks up a held sliver
    /// (returning [`DaCommitteeResponse::Sliver`]). If the parked channel has
    /// been dropped (requester disconnected, inbound stream timed out) the call
    /// returns `Err(NetworkError::ChannelSend)`.
    async fn send_da_committee_response(
        &self,
        request_id: InboundRequestId,
        response: DaCommitteeResponse,
    ) -> Result<()>;

    /// Subscribes to inbound committee-DA requests. Only one subscriber is
    /// supported at a time — calling twice replaces the previous channel. Used
    /// by a validator's DA handler to receive `StoreSliver` / `FetchSliver`
    /// requests from writers and readers.
    async fn subscribe_da_committee_requests(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<InboundDaCommittee>>;

    /// Sends one database replicated-write request (`ApplyWrite`) to a peer
    /// holder of the same partition and awaits its reply.
    ///
    /// Reply-carrying like the committee-DA protocol: the caller needs the
    /// peer's `Applied` acknowledgment (or an error) to count it toward the
    /// write's consistency requirement. The event loop parks the caller's reply
    /// channel keyed by the `OutboundRequestId` and fulfils it when the peer's
    /// `Message::Response` arrives. The holder is addressed by `PeerId`
    /// directly — the node-layer adapter resolves the holder endpoint id
    /// (`host#peer`) → `PeerId` before calling this.
    async fn db_replicate_request(
        &self,
        peer: PeerId,
        request: DbReplicateRequest,
    ) -> Result<DbReplicateResponse>;

    /// Answers an inbound database replicated-write request identified by
    /// `request_id`. Called by a holder's replication handler after it applies
    /// the write against its local engine. If the parked channel has been
    /// dropped the call returns `Err(NetworkError::ChannelSend)`.
    async fn send_db_replicate_response(
        &self,
        request_id: InboundRequestId,
        response: DbReplicateResponse,
    ) -> Result<()>;

    /// Subscribes to inbound database replicated-write requests. Only one
    /// subscriber is supported at a time — calling twice replaces the previous
    /// channel. Used by a holder's replication handler to receive `ApplyWrite`
    /// requests fanned out by serving holders.
    async fn subscribe_db_replicate_requests(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<InboundDbReplicate>>;
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
    SetBanStore {
        store: std::sync::Arc<dyn crate::peer_manager::BanStore>,
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
    /// Fans out a HotStuff-2 `ConsensusMessage` over the consensus-direct
    /// request-response overlay to every validator currently admitted to
    /// the local registry. Returns the number of peers the request was
    /// dispatched to.
    BroadcastToValidators {
        message: ConsensusMessage,
        response: oneshot::Sender<Result<usize>>,
    },
    /// Returns the count of currently-connected peers that are also
    /// admitted to the local validator registry. Used by the consensus
    /// engine warm-up gate before the first `BroadcastToValidators`.
    ConnectedValidatorCount {
        response: oneshot::Sender<Result<usize>>,
    },
    /// Subscribes to inbound consensus-direct messages. One subscriber per
    /// node — calling twice replaces the previous channel.
    SubscribeConsensusDirect {
        response: oneshot::Sender<Result<mpsc::UnboundedReceiver<ConsensusMessage>>>,
    },
    /// Installs the DID-to-PeerId resolver used by the MPC relay overlay.
    /// Idempotent — calling twice replaces the prior resolver.
    SetMpcDidResolver {
        resolver: std::sync::Arc<dyn crate::mpc_relay::MpcDidResolver>,
        response: oneshot::Sender<Result<()>>,
    },
    /// Dispatches one MPC round message to the peer that controls
    /// `message.to_did`. The `to_did` is resolved through the installed
    /// `MpcDidResolver`; failure to resolve returns `PeerNotFound`.
    SendMpcRelayMessage {
        message: crate::mpc_relay::MpcRelayRequest,
        response: oneshot::Sender<Result<()>>,
    },
    /// Subscribes to inbound MPC relay round messages. One subscriber per
    /// node — calling twice replaces the previous channel.
    SubscribeMpcRelay {
        response: oneshot::Sender<
            Result<mpsc::UnboundedReceiver<crate::mpc_relay::MpcRelayRequest>>,
        >,
    },
    /// Sends one cluster-tunnel frame to `peer`. Returns the
    /// `OutboundRequestId`; the member's `Ack`/`Error` or a transport
    /// failure is delivered through `SubscribeClusterTunnelResults`.
    SendClusterTunnelFrame {
        peer: PeerId,
        request: crate::cluster_tunnel_proto::ClusterTunnelRequest,
        response: oneshot::Sender<Result<OutboundRequestId>>,
    },
    /// Answers an inbound cluster-tunnel frame parked under `request_id`.
    SendClusterTunnelResponse {
        request_id: InboundRequestId,
        response_payload: crate::cluster_tunnel_proto::ClusterTunnelResponse,
        response: oneshot::Sender<Result<()>>,
    },
    /// Subscribes to inbound cluster-tunnel frames. One subscriber per node —
    /// calling twice replaces the previous channel.
    SubscribeClusterTunnelRequests {
        response: oneshot::Sender<Result<mpsc::UnboundedReceiver<InboundClusterTunnel>>>,
    },
    /// Subscribes to outbound cluster-tunnel results. One subscriber per node.
    SubscribeClusterTunnelResults {
        response: oneshot::Sender<Result<mpsc::UnboundedReceiver<OutboundClusterTunnelResult>>>,
    },
    /// Sends one committee-DA request to `peer`. The `response` oneshot is
    /// parked in `pending_da_committee_requests` keyed by the returned
    /// `OutboundRequestId` and fulfilled asynchronously when the peer's
    /// `Message::Response` arrives (or an `OutboundFailure` maps to an error).
    DaCommitteeRequest {
        peer: PeerId,
        request: DaCommitteeRequest,
        response: oneshot::Sender<Result<DaCommitteeResponse>>,
    },
    /// Answers an inbound committee-DA request parked under `request_id`.
    SendDaCommitteeResponse {
        request_id: InboundRequestId,
        response_payload: DaCommitteeResponse,
        response: oneshot::Sender<Result<()>>,
    },
    /// Subscribes to inbound committee-DA requests. One subscriber per node —
    /// calling twice replaces the previous channel.
    SubscribeDaCommitteeRequests {
        response: oneshot::Sender<Result<mpsc::UnboundedReceiver<InboundDaCommittee>>>,
    },
    /// Sends one database replicated-write request to `peer`. The `response`
    /// oneshot is parked in `pending_db_replicate_requests` keyed by the
    /// returned `OutboundRequestId` and fulfilled asynchronously when the
    /// peer's `Message::Response` arrives (or an `OutboundFailure` maps to an
    /// error).
    DbReplicateRequest {
        peer: PeerId,
        request: DbReplicateRequest,
        response: oneshot::Sender<Result<DbReplicateResponse>>,
    },
    /// Answers an inbound database replicated-write request parked under
    /// `request_id`.
    SendDbReplicateResponse {
        request_id: InboundRequestId,
        response_payload: DbReplicateResponse,
        response: oneshot::Sender<Result<()>>,
    },
    /// Subscribes to inbound database replicated-write requests. One subscriber
    /// per node — calling twice replaces the previous channel.
    SubscribeDbReplicateRequests {
        response: oneshot::Sender<Result<mpsc::UnboundedReceiver<InboundDbReplicate>>>,
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
    /// Sustained connectivity verdict for THIS node. Written by the event loop
    /// from AutoNAT / external-address / relay events; read by role admission
    /// and the request router to decide whether this node is reachable enough
    /// to serve traffic.
    reachability: Arc<crate::reachability::ReachabilityTracker>,
    /// Peer IDs (as strings) currently discovered on THIS node's local network
    /// segment via mDNS. Written by the event loop's mDNS handler; read by the
    /// request router to prefer a same-LAN provider over any WAN provider for
    /// the same model. A local provider avoids the public internet entirely —
    /// lowest latency and no relay budget — so it is the strongest pick.
    local_peers: Arc<crate::reachability::LocalPeerSet>,
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
        let reachability = Arc::new(crate::reachability::ReachabilityTracker::new());
        let loop_reachability = reachability.clone();
        let local_peers = Arc::new(crate::reachability::LocalPeerSet::new());
        let loop_local_peers = local_peers.clone();

        // Spawn the event loop
        tokio::spawn(async move {
            if let Err(e) = run_event_loop(
                config,
                command_rx,
                loop_metrics,
                loop_reachability,
                loop_local_peers,
            )
            .await
            {
                tracing::error!("Network event loop error: {}", e);
            }
        });

        Ok(Self {
            command_tx,
            metrics,
            metrics_registry,
            reachability,
            local_peers,
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

    /// Returns the sustained reachability tracker for this node. Role
    /// admission reads the tier to gate serving roles; the request router
    /// reads it to prefer directly-reachable providers over relay-only ones.
    pub fn reachability(&self) -> Arc<crate::reachability::ReachabilityTracker> {
        self.reachability.clone()
    }

    /// Returns the set of peer IDs currently on this node's local network
    /// segment (mDNS-discovered). The request router consults it to prefer a
    /// same-LAN provider over any WAN provider for the same model.
    pub fn local_peers(&self) -> Arc<crate::reachability::LocalPeerSet> {
        self.local_peers.clone()
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

    /// Polls until at least `min_validators` peers are both connected at
    /// the libp2p layer AND admitted to the local validator registry, or
    /// `timeout` elapses.
    ///
    /// This is the warm-up gate for the consensus-direct overlay (#144) —
    /// it replaces the gossipsub-mesh-based gate that consensus used while
    /// it was still publishing through gossipsub. Direct request-response
    /// has no "mesh" — the only meaningful liveness signal is "I have a
    /// connection open to a validator I'm willing to send to".
    ///
    /// On timeout, returns the last observed count so the caller can
    /// decide whether to proceed in degraded mode (single-node operation,
    /// pre-genesis) or keep waiting. Polls every 100ms — short enough not
    /// to delay startup, long enough to let identify-driven admission
    /// complete on a freshly-dialed peer.
    pub async fn wait_for_connected_validators(
        &self,
        min_validators: usize,
        timeout: std::time::Duration,
    ) -> Result<usize> {
        let deadline = tokio::time::Instant::now() + timeout;
        #[allow(unused_assignments)]
        let mut last_seen = 0usize;
        loop {
            match self.connected_validator_count().await {
                Ok(count) => {
                    last_seen = count;
                    if count >= min_validators {
                        tracing::info!(
                            connected_validators = count,
                            min_validators = min_validators,
                            "Connected validators ready — first consensus-direct broadcast safe"
                        );
                        return Ok(count);
                    }
                }
                Err(e) => return Err(e),
            }
            if tokio::time::Instant::now() >= deadline {
                tracing::warn!(
                    connected_validators = last_seen,
                    min_validators = min_validators,
                    "wait_for_connected_validators timed out — first \
                     consensus-direct broadcast may dispatch to zero peers"
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
    // state-sync design rationale.
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

    async fn set_ban_store(&self, store: std::sync::Arc<dyn crate::peer_manager::BanStore>) -> Result<()> {
        self.send_command(|response| NetworkCommand::SetBanStore { store, response })
            .await
    }

    async fn listen_addresses(&self) -> Result<Vec<Multiaddr>> {
        self.send_command(|response| NetworkCommand::ListenAddresses { response })
            .await
    }

    async fn broadcast_to_validators(&self, message: ConsensusMessage) -> Result<usize> {
        self.send_command(move |response| NetworkCommand::BroadcastToValidators {
            message,
            response,
        })
        .await
    }

    async fn subscribe_consensus_direct(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<ConsensusMessage>> {
        self.send_command(|response| NetworkCommand::SubscribeConsensusDirect { response })
            .await
    }

    async fn connected_validator_count(&self) -> Result<usize> {
        self.send_command(|response| NetworkCommand::ConnectedValidatorCount { response })
            .await
    }

    async fn set_mpc_did_resolver(
        &self,
        resolver: std::sync::Arc<dyn crate::mpc_relay::MpcDidResolver>,
    ) -> Result<()> {
        self.send_command(|response| NetworkCommand::SetMpcDidResolver { resolver, response })
            .await
    }

    async fn send_mpc_relay_message(
        &self,
        message: crate::mpc_relay::MpcRelayRequest,
    ) -> Result<()> {
        self.send_command(move |response| NetworkCommand::SendMpcRelayMessage {
            message,
            response,
        })
        .await
    }

    async fn subscribe_mpc_relay(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<crate::mpc_relay::MpcRelayRequest>> {
        self.send_command(|response| NetworkCommand::SubscribeMpcRelay { response })
            .await
    }

    async fn send_cluster_tunnel_frame(
        &self,
        peer: PeerId,
        request: crate::cluster_tunnel_proto::ClusterTunnelRequest,
    ) -> Result<OutboundRequestId> {
        self.send_command(move |response| NetworkCommand::SendClusterTunnelFrame {
            peer,
            request,
            response,
        })
        .await
    }

    async fn send_cluster_tunnel_response(
        &self,
        request_id: InboundRequestId,
        response: crate::cluster_tunnel_proto::ClusterTunnelResponse,
    ) -> Result<()> {
        self.send_command(move |resp| NetworkCommand::SendClusterTunnelResponse {
            request_id,
            response_payload: response,
            response: resp,
        })
        .await
    }

    async fn subscribe_cluster_tunnel_requests(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<InboundClusterTunnel>> {
        self.send_command(|response| NetworkCommand::SubscribeClusterTunnelRequests { response })
            .await
    }

    async fn subscribe_cluster_tunnel_results(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<OutboundClusterTunnelResult>> {
        self.send_command(|response| NetworkCommand::SubscribeClusterTunnelResults { response })
            .await
    }

    async fn da_committee_request(
        &self,
        peer: PeerId,
        request: DaCommitteeRequest,
    ) -> Result<DaCommitteeResponse> {
        // The `response` oneshot is not fulfilled at dispatch — the event loop
        // parks it keyed by the `OutboundRequestId` and completes it when the
        // peer replies. `send_command` awaits exactly that completion.
        self.send_command(move |response| NetworkCommand::DaCommitteeRequest {
            peer,
            request,
            response,
        })
        .await
    }

    async fn send_da_committee_response(
        &self,
        request_id: InboundRequestId,
        response: DaCommitteeResponse,
    ) -> Result<()> {
        self.send_command(move |resp| NetworkCommand::SendDaCommitteeResponse {
            request_id,
            response_payload: response,
            response: resp,
        })
        .await
    }

    async fn subscribe_da_committee_requests(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<InboundDaCommittee>> {
        self.send_command(|response| NetworkCommand::SubscribeDaCommitteeRequests { response })
            .await
    }

    async fn db_replicate_request(
        &self,
        peer: PeerId,
        request: DbReplicateRequest,
    ) -> Result<DbReplicateResponse> {
        // The `response` oneshot is not fulfilled at dispatch — the event loop
        // parks it keyed by the `OutboundRequestId` and completes it when the
        // peer replies. `send_command` awaits exactly that completion.
        self.send_command(move |response| NetworkCommand::DbReplicateRequest {
            peer,
            request,
            response,
        })
        .await
    }

    async fn send_db_replicate_response(
        &self,
        request_id: InboundRequestId,
        response: DbReplicateResponse,
    ) -> Result<()> {
        self.send_command(move |resp| NetworkCommand::SendDbReplicateResponse {
            request_id,
            response_payload: response,
            response: resp,
        })
        .await
    }

    async fn subscribe_db_replicate_requests(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<InboundDbReplicate>> {
        self.send_command(|response| NetworkCommand::SubscribeDbReplicateRequests { response })
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
    /// Sustained reachability verdict, fed from AutoNAT / external-address /
    /// relay events and read by role admission + the request router.
    reachability: Arc<crate::reachability::ReachabilityTracker>,
    /// Peer IDs on this node's local segment, fed from mDNS discover/expire
    /// events and read by the request router to prefer same-LAN providers.
    local_peers: Arc<crate::reachability::LocalPeerSet>,
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
    /// Latched once `SubscribeBlockSyncRequests` runs. Used to distinguish
    /// "no subscriber yet" (legitimate bootstrap window before the event
    /// loop spawns the block-sync engine — log at debug) from "subscriber
    /// dropped after attach" (the genuinely anomalous channel-closed case —
    /// log at warn).
    block_sync_request_subscriber_ever_attached: bool,
    /// Subscriber channel for outbound block-sync results. `None` until the
    /// node-level block-sync engine attaches via `SubscribeBlockSyncResults`.
    block_sync_result_subscriber: Option<mpsc::UnboundedSender<OutboundBlockSyncResult>>,
    /// Subscriber channel for peer connection lifecycle events. `None` until
    /// the block-sync engine (or another peer-aware consumer) attaches via
    /// `SubscribePeerEvents`. The event loop fans `SwarmEvent::Connection*`
    /// transitions through this channel — first physical connection emits
    /// `Connected`, last drop emits `Disconnected`.
    peer_event_subscriber: Option<mpsc::UnboundedSender<PeerEvent>>,
    /// Subscriber channel for inbound consensus-direct messages. `None` until
    /// the node-level consensus engine attaches via `SubscribeConsensusDirect`.
    /// Inbound requests arriving while this is `None` are answered with
    /// `ConsensusDirectError::NoSubscriber` so the sender stops retrying
    /// against this peer.
    consensus_direct_subscriber: Option<mpsc::UnboundedSender<ConsensusMessage>>,
    /// Latched once `SubscribeConsensusDirect` runs. Same rationale as
    /// `block_sync_request_subscriber_ever_attached` — separates the
    /// bootstrap-pre-attach debug case from the dropped-channel warn case.
    consensus_direct_subscriber_ever_attached: bool,
    /// Per-peer count of currently-in-flight inbound consensus-direct
    /// streams. Used to enforce `MAX_INBOUND_STREAMS_PER_PEER` and reject
    /// overflow with `ConsensusDirectError::ServerBusy` rather than queueing.
    /// Decremented on `ResponseSent` / `InboundFailure`.
    consensus_direct_inbound_inflight: HashMap<PeerId, usize>,
    /// Subscriber channel for inbound MPC relay round messages. `None` until
    /// the node-level MPC adapter attaches via `SubscribeMpcRelay`. Inbound
    /// requests arriving while this is `None` are answered with
    /// `MpcRelayError::NoSubscriber`.
    mpc_relay_subscriber: Option<mpsc::UnboundedSender<crate::mpc_relay::MpcRelayRequest>>,
    /// Latched once `SubscribeMpcRelay` runs. Same rationale as
    /// `consensus_direct_subscriber_ever_attached`.
    mpc_relay_subscriber_ever_attached: bool,
    /// Per-peer count of currently-in-flight inbound MPC relay streams.
    /// Enforces `mpc_relay::MAX_INBOUND_STREAMS_PER_PEER`; overflow is
    /// rejected with `MpcRelayError::ServerBusy`. Decremented on
    /// `ResponseSent` / `InboundFailure`.
    mpc_relay_inbound_inflight: HashMap<PeerId, usize>,
    /// DID-to-PeerId resolver for the MPC relay overlay. `None` until the
    /// node-level adapter installs it via `SetMpcDidResolver`. Missing
    /// resolver causes outbound sends to fail and inbound messages to be
    /// rejected with `MpcRelayError::UnknownSender` — the relay is
    /// fail-closed.
    mpc_did_resolver: Option<std::sync::Arc<dyn crate::mpc_relay::MpcDidResolver>>,
    /// Pending inbound cluster-tunnel response channels keyed by
    /// `InboundRequestId`. Parked here until the member's serving runtime
    /// answers via `SendClusterTunnelResponse`. Same rationale as
    /// `pending_inbound_block_sync`.
    pending_inbound_cluster_tunnel:
        HashMap<InboundRequestId, ResponseChannel<crate::cluster_tunnel_proto::ClusterTunnelResponse>>,
    /// Subscriber channel for inbound cluster-tunnel frames. `None` until a
    /// member's serving runtime attaches via `SubscribeClusterTunnelRequests`.
    /// Inbound frames arriving while this is `None` are answered with
    /// `ClusterTunnelError::NoMember` so the head fails over.
    cluster_tunnel_request_subscriber: Option<mpsc::UnboundedSender<InboundClusterTunnel>>,
    /// Latched once `SubscribeClusterTunnelRequests` runs — separates the
    /// bootstrap-pre-attach debug case from the dropped-channel warn case.
    cluster_tunnel_request_subscriber_ever_attached: bool,
    /// Subscriber channel for outbound cluster-tunnel results. `None` until
    /// the head's serving runtime attaches via `SubscribeClusterTunnelResults`.
    cluster_tunnel_result_subscriber: Option<mpsc::UnboundedSender<OutboundClusterTunnelResult>>,
    /// Per-peer count of currently-in-flight inbound cluster-tunnel streams.
    /// Enforces `cluster_tunnel_proto::MAX_INBOUND_STREAMS_PER_PEER`; overflow
    /// is rejected with `ClusterTunnelError::ServerBusy`. Decremented on
    /// `ResponseSent` / `InboundFailure`.
    cluster_tunnel_inbound_inflight: HashMap<PeerId, usize>,
    /// Pending outbound committee-DA reply channels keyed by
    /// `OutboundRequestId`. Parked when a `DaCommitteeRequest` command is
    /// dispatched; fulfilled with the peer's `DaCommitteeResponse` on
    /// `Message::Response`, or with a transport error on `OutboundFailure`.
    pending_da_committee_requests:
        HashMap<OutboundRequestId, oneshot::Sender<Result<DaCommitteeResponse>>>,
    /// Pending inbound committee-DA response channels keyed by
    /// `InboundRequestId`. Parked until the member's DA handler answers via
    /// `SendDaCommitteeResponse`. Same rationale as `pending_inbound_block_sync`.
    pending_inbound_da_committee: HashMap<InboundRequestId, ResponseChannel<DaCommitteeResponse>>,
    /// Subscriber channel for inbound committee-DA requests. `None` until a
    /// validator's DA handler attaches via `SubscribeDaCommitteeRequests`.
    /// Requests arriving while this is `None` are answered with
    /// `DaCommitteeError::NoHandler` so the requester scores us down and retries.
    da_committee_request_subscriber: Option<mpsc::UnboundedSender<InboundDaCommittee>>,
    /// Latched once `SubscribeDaCommitteeRequests` runs — separates the
    /// bootstrap-pre-attach debug case from the dropped-channel warn case.
    da_committee_request_subscriber_ever_attached: bool,
    /// Per-peer count of currently-in-flight inbound committee-DA streams.
    /// Enforces `DA_COMMITTEE_MAX_INBOUND_STREAMS_PER_PEER`; overflow is
    /// rejected with `DaCommitteeError::ServerBusy`. Decremented on
    /// `ResponseSent` / `InboundFailure`.
    da_committee_inbound_inflight: HashMap<PeerId, usize>,
    /// Pending outbound database replicated-write reply channels keyed by
    /// `OutboundRequestId`. Parked when a `DbReplicateRequest` command is
    /// dispatched; fulfilled with the peer's `DbReplicateResponse` on
    /// `Message::Response`, or with a transport error on `OutboundFailure`.
    pending_db_replicate_requests:
        HashMap<OutboundRequestId, oneshot::Sender<Result<DbReplicateResponse>>>,
    /// Pending inbound database replicated-write response channels keyed by
    /// `InboundRequestId`. Parked until the holder's replication handler
    /// answers via `SendDbReplicateResponse`.
    pending_inbound_db_replicate:
        HashMap<InboundRequestId, ResponseChannel<DbReplicateResponse>>,
    /// Subscriber channel for inbound database replicated-write requests. `None`
    /// until a holder's replication handler attaches via
    /// `SubscribeDbReplicateRequests`. Requests arriving while this is `None`
    /// are answered with `DbReplicateError::NoHandler`.
    db_replicate_request_subscriber: Option<mpsc::UnboundedSender<InboundDbReplicate>>,
    /// Latched once `SubscribeDbReplicateRequests` runs — separates the
    /// bootstrap-pre-attach debug case from the dropped-channel warn case.
    db_replicate_request_subscriber_ever_attached: bool,
    /// Per-peer count of currently-in-flight inbound database replicated-write
    /// streams. Enforces `DB_REPLICATE_MAX_INBOUND_STREAMS_PER_PEER`; overflow
    /// is rejected with `DbReplicateError::ServerBusy`. Decremented on
    /// `ResponseSent` / `InboundFailure`.
    db_replicate_inbound_inflight: HashMap<PeerId, usize>,
    /// Tally of `observed_addr` reports received via Identify, keyed by the
    /// reported external multiaddr → set of distinct peer IDs that have
    /// reported it. Once a candidate accumulates reports from at least
    /// `OBSERVED_ADDR_CONFIRMATION_THRESHOLD` distinct peers, we promote it
    /// via `Swarm::add_external_address` so Identify advertises it on the
    /// next exchange. This is the permissionless-NAT-discovery primitive:
    /// every node learns its own public address from what its peers see,
    /// without any per-deployment `--external-p2p-addr` configuration.
    ///
    /// The defence against an attacker lying about our address is AutoNAT v2
    /// probe-back (registered in `TenzroBehaviour::autonat_client`): a third
    /// party cannot fake a server-initiated dial-back to a candidate, so the
    /// candidate is only advertised network-wide after AutoNAT confirms it.
    /// The Identify observed_addr tally surfaces candidates; AutoNAT gates
    /// promotion to confirmed-external.
    observed_addrs: HashMap<Multiaddr, HashSet<PeerId>>,
    /// External addresses we have already promoted via `add_external_address`
    /// to avoid double-promotion when more `observed_addr` reports arrive
    /// from additional peers after confirmation.
    advertised_external_addrs: HashSet<Multiaddr>,
    /// Peers on which this node has already attempted a Circuit-Relay v2
    /// reservation (`Swarm::listen_on(<relay>/p2p-circuit)`). Prevents
    /// double-reservation as the identify handler fires repeatedly for the
    /// same relay peer on every gossip round. The set is drained when the
    /// reservation is lost (the RelayClient event handler removes the entry
    /// on `Event::ReservationReqDenied` / connection close so the next
    /// identify tick can retry). Also gated by `reachability.tier()` — a
    /// node with `Direct` reachability skips relay reservation entirely:
    /// relay is a fallback for the NAT'd lane only.
    attempted_relay_reservations: HashSet<PeerId>,
    /// Operator-configured bootstrap multiaddrs, retained for periodic
    /// re-dial. Whenever a configured bootstrap peer is not currently
    /// connected, the cleanup tick re-issues `Swarm::dial(addr)` from this
    /// authoritative ground-truth set — independent of whatever Kademlia /
    /// Identify learned about the peer. This is the Lighthouse/Substrate
    /// self-healing pattern (`recurring_boot_dial`): bootstrap addresses
    /// are the operator's source of truth, and the libp2p peer-store's
    /// cached `(ip, ephemeral_port)` from a prior outbound connection
    /// must never displace them across a bootstrap restart.
    bootstrap_peers: Vec<(PeerId, Multiaddr)>,

    /// Operator-configured bootstrap multiaddrs that carry NO `/p2p/<peer_id>`
    /// component (e.g. `/dns4/host/tcp/9000`). These can't be matched against
    /// `Swarm::is_connected(peer_id)`, so the peer-keyed `bootstrap_peers`
    /// re-dial sweep above skips them entirely — leaving a node with a
    /// peerless boot config unable to recover if its single startup dial
    /// fails. We retain them here and re-dial on the cleanup tick whenever the
    /// node has ZERO live connections (the only connection signal available
    /// without a peer id). The Identify handshake learns the real peer id on
    /// the first successful connect, after which Kademlia takes over.
    bootstrap_addrs_peerless: Vec<Multiaddr>,

    /// Per-bootstrap-target reconnection schedule (decorrelated jitter),
    /// keyed by the target multiaddr. Gates the cleanup-tick re-dial so an
    /// unreachable bootstrap node is probed on a backing-off, jittered
    /// cadence instead of a synchronized fixed 60s pulse across every joiner.
    /// A target's schedule is reset the moment a connection to it succeeds.
    bootstrap_backoff: HashMap<Multiaddr, crate::discovery::ReconnectBackoff>,

    /// Mid-session peer recovery table. When a non-bootstrap peer we had a
    /// live connection to drops, we retain its last-known dial address here
    /// so the cleanup tick can re-dial it (under a per-peer jittered backoff)
    /// while the node is below its target peer count. Entries are removed on
    /// successful reconnect or once the node is comfortably meshed — Identify
    /// and Kademlia handle steady-state discovery; this table only covers the
    /// gap where a small mesh loses a peer and would otherwise wait for a slow
    /// DHT walk to notice.
    peer_redial: HashMap<PeerId, (Multiaddr, crate::discovery::ReconnectBackoff)>,
}

/// Target minimum number of live peer connections below which mid-session
/// peer recovery re-dials known-but-dropped peers. Not a topology assumption:
/// it is a lower bound that applies identically to a 4-node mesh and a
/// 10,000-node network — above it, steady-state discovery (Identify/Kademlia)
/// is sufficient and re-dialing would only add churn.
const PEER_RECOVERY_FLOOR: usize = 8;

/// Number of distinct peers that must independently report the same
/// `observed_addr` via Identify before we promote it to an external-address
/// candidate. Set to 1 because AutoNAT v2 probe-back is the actual
/// reachability gate: Identify gives us a candidate, AutoNAT confirms it
/// cryptographically by asking a public peer to dial us back on that
/// address. A liar can name any candidate; they cannot fake an AutoNAT
/// dial-back from a third-party server. The higher N-distinct-peers value
/// (3) used by Substrate is a belt without braces — appropriate when
/// AutoNAT is not in the stack. Our stack has both, so the lower threshold
/// is correct and necessary: a freshly-joined node typically has 1 peer at
/// bootstrap (the seed) and cannot reach N=3 distinct reporters until it
/// is already meshed, which is the very problem this primitive is meant
/// to solve.
const OBSERVED_ADDR_CONFIRMATION_THRESHOLD: usize = 1;

/// Main event loop for the network service
async fn run_event_loop(
    config: NetworkConfig,
    mut command_rx: mpsc::UnboundedReceiver<NetworkCommand>,
    metrics: Arc<NetworkMetrics>,
    reachability: Arc<crate::reachability::ReachabilityTracker>,
    local_peers: Arc<crate::reachability::LocalPeerSet>,
) -> Result<()> {
    // Load or generate keypair (persistent for stable peer IDs)
    let local_key = load_or_generate_keypair(&config.data_dir)?;
    let local_peer_id = PeerId::from(local_key.public());

    tracing::info!("Local peer ID: {}", local_peer_id);

    // Swarm construction via `SwarmBuilder` — required for `with_relay_client()`
    // which both adds the relay-client behaviour AND wraps the transport so
    // that `/p2p-circuit` multiaddrs become dialable. The pre-existing
    // hand-rolled `Swarm::new(transport, behaviour, ...)` path can't express
    // that wrap, which is why the migration is needed for #132.
    //
    // Composition order (libp2p 0.56 docs):
    //   identity → tokio → tcp(TLS+Yamux) → quic → dns → relay_client → behaviour → swarm_config
    //
    // The TCP transport keeps `libp2p-tls` (rustls + aws-lc-rs, PQ-hybrid
    // X25519MLKEM768) — `with_tcp()` accepts the same `libp2p::tls::Config`
    // constructor that `transport::build_transport()` used previously. The
    // QUIC half is similarly inherited from the SwarmBuilder.
    //
    // `with_relay_client()` is unconditional here even when the role's
    // `enable_hole_punching` is false: the cost of installing the transport
    // wrapper is negligible and keeping it always-on lets a future config
    // change re-enable hole punching without touching the swarm topology.
    // The `relay_client` behaviour half is then conditionally toggled
    // on/off inside `TenzroBehaviour::new()`.
    let enable_relay = config.enable_relay;
    let enable_hole_punching = config.enable_hole_punching;
    let enable_mdns = config.enable_mdns;
    let protocol_version = config.protocol_version.clone();
    let user_agent = config.user_agent.clone();
    let idle_timeout = config.connection_idle_timeout;

    let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
        .with_tokio()
        .with_tcp(
            libp2p::tcp::Config::default().nodelay(true),
            libp2p::tls::Config::new,
            libp2p::yamux::Config::default,
        )
        .map_err(|e| NetworkError::Transport(format!("TCP/TLS upgrade failed: {}", e)))?
        .with_quic()
        .with_dns()
        .map_err(|e| NetworkError::Transport(format!("DNS transport failed: {}", e)))?
        .with_relay_client(libp2p::tls::Config::new, libp2p::yamux::Config::default)
        .map_err(|e| NetworkError::Transport(format!("Relay client transport failed: {}", e)))?
        .with_behaviour(|key, relay_client| {
            // libp2p's `TryIntoBehaviour` impl requires
            // `Result<B, Box<dyn std::error::Error + Send + Sync>>`.
            // `TenzroBehaviour::new` returns the non-Send/Sync variant, so
            // re-box the error here. The boxed error is later surfaced
            // through `NetworkError::Transport` at the `?` site below.
            TenzroBehaviour::new(
                local_peer_id,
                key,
                protocol_version,
                user_agent,
                enable_relay,
                enable_hole_punching,
                enable_mdns,
                Some(relay_client),
            )
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                e.to_string().into()
            })
        })
        .map_err(|e| NetworkError::Transport(format!("Behaviour construction failed: {}", e)))?
        .with_swarm_config(|cfg| cfg.with_idle_connection_timeout(idle_timeout))
        .build();

    // Listen on configured addresses
    for addr in &config.listen_addresses {
        swarm
            .listen_on(addr.clone())
            .map_err(|e| NetworkError::Transport(format!("Failed to listen on {}: {}", addr, e)))?;
        tracing::info!("Listening on {}", addr);
    }

    // Register statically-configured external addresses with the swarm.
    // These are the ONLY addresses Identify will advertise to peers (because
    // `hide_listen_addrs(true)` is set on the identify config) — see the
    // long-form rationale in `behaviour.rs::TenzroBehaviour::new`. On cloud
    // deployments where the node knows its own public IP at boot (validator
    // VMs in our GCE testnet, for example) this is the cleanest way to
    // prevent the docker0 / loopback / VPC-only addresses from being
    // advertised. For nodes behind NAT, leave this empty and let AutoNAT v2
    // confirm an external address dynamically.
    for addr in &config.external_addresses {
        if !is_globally_routable(addr) {
            tracing::warn!(
                "Refusing to advertise non-routable external address {} — \
                 check NetworkConfig::external_addresses",
                addr
            );
            continue;
        }
        swarm.add_external_address(addr.clone());
        tracing::info!("Advertising external address {}", addr);
    }
    // Snapshot static external addresses so the observed_addr promotion path
    // below doesn't re-promote them — see `EventLoopState::advertised_external_addrs`.
    let preconfigured_external: HashSet<Multiaddr> = config
        .external_addresses
        .iter()
        .filter(|a| is_globally_routable(a))
        .cloned()
        .collect();

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

    // Parse `(PeerId, Multiaddr)` pairs out of the configured bootstrap
    // multiaddrs exactly once. Used for (a) the one-shot Kademlia bootstrap,
    // (b) the initial dial round below, and (c) the periodic re-dial sweep
    // stored on `EventLoopState::bootstrap_peers`.
    let bootstrap_peers: Vec<(PeerId, Multiaddr)> = config
        .boot_nodes
        .iter()
        .filter_map(|addr| {
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

    // The complement set: configured boot addrs WITHOUT a `/p2p/<peer_id>`
    // (e.g. `/dns4/host/tcp/9000`). The peer-keyed re-dial sweep can't touch
    // these, so retain them for the zero-connections self-heal re-dial.
    let bootstrap_addrs_peerless: Vec<Multiaddr> = config
        .boot_nodes
        .iter()
        .filter(|addr| {
            !addr
                .iter()
                .any(|proto| matches!(proto, libp2p::multiaddr::Protocol::P2p(_)))
        })
        .cloned()
        .collect();

    // Bootstrap DHT if enabled
    if config.enable_dht && !bootstrap_peers.is_empty() {
        crate::discovery::bootstrap_dht(
            &mut swarm.behaviour_mut().kademlia,
            bootstrap_peers.clone(),
        );
    }

    // Dial boot nodes
    for addr in &config.boot_nodes {
        if let Err(e) = swarm.dial(dial_opts_new_port(addr.clone())) {
            tracing::warn!("Failed to dial boot node {}: {}", addr, e);
        } else {
            tracing::info!("Dialing boot node: {}", addr);
        }
    }

    let mut state = EventLoopState {
        swarm,
        reachability,
        local_peers,
        peer_manager,
        subscribers: HashMap::new(),
        deduplicator: MessageDeduplicator::default(),
        metrics,
        listen_addresses: Vec::new(),
        pending_inbound_block_sync: HashMap::new(),
        block_sync_request_subscriber: None,
        block_sync_request_subscriber_ever_attached: false,
        block_sync_result_subscriber: None,
        peer_event_subscriber: None,
        consensus_direct_subscriber: None,
        consensus_direct_subscriber_ever_attached: false,
        consensus_direct_inbound_inflight: HashMap::new(),
        mpc_relay_subscriber: None,
        mpc_relay_subscriber_ever_attached: false,
        mpc_relay_inbound_inflight: HashMap::new(),
        mpc_did_resolver: None,
        pending_inbound_cluster_tunnel: HashMap::new(),
        cluster_tunnel_request_subscriber: None,
        cluster_tunnel_request_subscriber_ever_attached: false,
        cluster_tunnel_result_subscriber: None,
        cluster_tunnel_inbound_inflight: HashMap::new(),
        pending_da_committee_requests: HashMap::new(),
        pending_inbound_da_committee: HashMap::new(),
        da_committee_request_subscriber: None,
        da_committee_request_subscriber_ever_attached: false,
        da_committee_inbound_inflight: HashMap::new(),
        pending_db_replicate_requests: HashMap::new(),
        pending_inbound_db_replicate: HashMap::new(),
        db_replicate_request_subscriber: None,
        db_replicate_request_subscriber_ever_attached: false,
        db_replicate_inbound_inflight: HashMap::new(),
        observed_addrs: HashMap::new(),
        advertised_external_addrs: preconfigured_external,
        attempted_relay_reservations: HashSet::new(),
        bootstrap_backoff: bootstrap_peers
            .iter()
            .map(|(_, addr)| addr.clone())
            .chain(bootstrap_addrs_peerless.iter().cloned())
            .map(|addr| (addr, crate::discovery::ReconnectBackoff::default_schedule()))
            .collect(),
        bootstrap_peers,
        bootstrap_addrs_peerless,
        peer_redial: HashMap::new(),
    };

    // Create periodic cleanup timer (every 60 seconds)
    let mut cleanup_interval = interval(Duration::from_secs(60));
    cleanup_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    // Periodic Kademlia bootstrap (every 60 seconds, mirrors Lighthouse).
    //
    // Kademlia routing tables degrade on churn-y networks: peers come and go,
    // buckets thin out, and DHT lookups start to stall. Re-issuing `bootstrap()`
    // on a slow tick keeps the routing table populated by re-exploring the
    // ID space from our own peer ID. The QueryId is fire-and-forget — actual
    // results land in `KademliaEvent::OutboundQueryProgressed` with
    // `QueryResult::Bootstrap(_)` and are handled by the swarm event handler.
    //
    // Gated by `config.enable_dht` for symmetry with the one-shot bootstrap
    // above; if the DHT is disabled, periodic bootstrap is meaningless.
    let dht_enabled = config.enable_dht;
    let mut kademlia_bootstrap_interval = interval(Duration::from_secs(60));
    kademlia_bootstrap_interval.set_missed_tick_behavior(MissedTickBehavior::Skip);

    // Main event loop
    'event_loop: loop {
        tokio::select! {
            // Fair poll across commands and swarm events. An earlier revision
            // biased toward `command_rx` and drained a bounded batch per turn,
            // on the theory that `SendBlockSyncResponse` had to reach
            // `send_response` quickly. That was the wrong lever: `handle_command`
            // only *enqueues* the response into the behaviour's send queue, and
            // the bytes do not egress until the swarm's connection handlers are
            // polled repeatedly as the socket becomes writable. Prioritising the
            // enqueue while throttling the swarm poll therefore did the opposite
            // of the intent — the response sat queued and the requester's inbound
            // substream hit `REQUEST_TIMEOUT_BODIES` (seen as `InboundFailure:
            // Timeout` on the serve side, `Eof`/`request timed out` on the
            // requester, and the same timeout on the consensus-direct overlay,
            // which shares the request_response machinery). Fair scheduling gives
            // the swarm continuous poll time so writes drain to completion; one
            // command per turn is sufficient because the command channel is not
            // the bottleneck — the wire is.
            Some(command) = command_rx.recv() => {
                if matches!(command, NetworkCommand::Shutdown { .. }) {
                    handle_command(&mut state, command).await;
                    tracing::info!("Network event loop shutting down gracefully");
                    break 'event_loop;
                }
                handle_command(&mut state, command).await;
            }

            // Handle swarm events
            event = state.swarm.select_next_some() => {
                handle_swarm_event(&mut state, event).await;

                // Enforce reputation-driven auto-bans at the transport layer.
                for peer_id in state.peer_manager.take_newly_banned() {
                    state.swarm.behaviour_mut().block_peer(peer_id);
                    let _ = state.swarm.disconnect_peer_id(peer_id);
                }
            }

            // Periodic cleanup
            _ = cleanup_interval.tick() => {
                // Lift transport-layer blocks for bans that have expired.
                for peer_id in state.peer_manager.cleanup_expired_bans() {
                    state.swarm.behaviour_mut().unblock_peer(peer_id);
                }
                // Backstop: enforce any auto-bans raised outside the swarm loop.
                for peer_id in state.peer_manager.take_newly_banned() {
                    state.swarm.behaviour_mut().block_peer(peer_id);
                    let _ = state.swarm.disconnect_peer_id(peer_id);
                }

                // Clean up stale peers (not seen for 24 hours)
                state.peer_manager.cleanup_stale_peers(Duration::from_secs(86400));

                // Refresh gossipsub's P5 (application-specific) factor from
                // the peer manager's reputation for every connected peer, so
                // protocol-level misbehaviour tracked outside gossipsub
                // (failed connections, invalid protocol messages) flows into
                // mesh selection and graylisting.
                for peer_id in state.peer_manager.connected_peers() {
                    let score = state.peer_manager.app_specific_score(&peer_id);
                    state.swarm.behaviour_mut().set_application_score(&peer_id, score);
                }

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

                // Re-dial any configured bootstrap peer we are not currently
                // connected to. This is the self-healing leg for the case
                // where a bootstrap node restarts and peers' libp2p
                // peer-stores still hold a cached `(ip, ephemeral_port)`
                // observation from a prior outbound connection — without
                // this sweep, peers will keep dialing the stale ephemeral
                // port and never re-converge until manually restarted.
                //
                // Mirrors Lighthouse's `recurring_boot_dial` and Substrate's
                // periodic bootnode dial, but each target is gated behind its
                // own decorrelated-jitter backoff (`bootstrap_backoff`) so an
                // unreachable boot node is not hammered on a synchronized 60s
                // pulse by every joiner at once. The configured bootstrap
                // multiaddr is the operator's authoritative ground truth; the
                // swarm's dial selector should still try it in addition to
                // whatever was learned via Identify — just on a backing-off,
                // per-node-jittered cadence.
                //
                // Collect the due targets first (immutable read of
                // bootstrap_peers + mutable stamp of bootstrap_backoff) so we
                // don't hold a borrow across the swarm dial below.
                let mut due_boot_dials: Vec<(Option<PeerId>, Multiaddr)> = Vec::new();
                for (peer_id, addr) in &state.bootstrap_peers {
                    if state.swarm.is_connected(peer_id) {
                        continue;
                    }
                    let due = state
                        .bootstrap_backoff
                        .get(addr)
                        .map(|b| b.due())
                        .unwrap_or(true);
                    if due {
                        if let Some(b) = state.bootstrap_backoff.get_mut(addr) {
                            let delay = b.record_attempt();
                            tracing::debug!(%addr, ?delay, "Bootstrap re-dial due (backoff advanced)");
                        }
                        due_boot_dials.push((Some(*peer_id), addr.clone()));
                    }
                }

                // Peerless boot addrs (no `/p2p/`) can't be checked against a
                // specific peer id. The only available connection signal is the
                // global connected count: if it's zero, the node is isolated and
                // its single startup dial must have failed (DNS hiccup, boot node
                // restart mid-handshake, transient timeout). Re-dial peerless
                // boot addrs — still under per-target backoff — while the node
                // has ZERO live connections. Once ANY connection is up, Identify
                // + Kademlia take over peer discovery.
                let live_connections = state.swarm.connected_peers().count();
                if live_connections == 0 {
                    let peerless: Vec<Multiaddr> = state.bootstrap_addrs_peerless.clone();
                    for addr in peerless {
                        let due = state
                            .bootstrap_backoff
                            .get(&addr)
                            .map(|b| b.due())
                            .unwrap_or(true);
                        if due {
                            if let Some(b) = state.bootstrap_backoff.get_mut(&addr) {
                                b.record_attempt();
                            }
                            due_boot_dials.push((None, addr));
                        }
                    }
                }

                for (peer_id, addr) in due_boot_dials {
                    match state.swarm.dial(dial_opts_new_port(addr.clone())) {
                        Ok(()) => tracing::info!(
                            ?peer_id,
                            %addr,
                            "Re-dialing bootstrap target (backoff-gated)"
                        ),
                        Err(e) => tracing::debug!(
                            ?peer_id,
                            %addr,
                            error = %e,
                            "Bootstrap re-dial skipped"
                        ),
                    }
                }

                // Mid-session peer recovery. When a non-bootstrap peer we had a
                // live connection to drops, its last-known dial address is kept
                // in `peer_redial`. While the node is below its peer-count
                // floor, re-dial those peers on the same jittered backoff so a
                // small mesh that loses a member recovers in seconds rather than
                // waiting for a slow DHT walk. Above the floor, drop the table:
                // steady-state discovery is sufficient and re-dialing would only
                // add churn.
                if live_connections >= PEER_RECOVERY_FLOOR {
                    if !state.peer_redial.is_empty() {
                        state.peer_redial.clear();
                    }
                } else if !state.peer_redial.is_empty() {
                    let mut due_peer_dials: Vec<(PeerId, Multiaddr)> = Vec::new();
                    for (peer_id, (addr, backoff)) in state.peer_redial.iter_mut() {
                        if state.swarm.is_connected(peer_id) {
                            continue;
                        }
                        if backoff.due() {
                            backoff.record_attempt();
                            due_peer_dials.push((*peer_id, addr.clone()));
                        }
                    }
                    // Drop any peer that has meanwhile reconnected.
                    state
                        .peer_redial
                        .retain(|peer_id, _| !state.swarm.is_connected(peer_id));
                    for (peer_id, addr) in due_peer_dials {
                        match state.swarm.dial(dial_opts_new_port(addr.clone())) {
                            Ok(()) => tracing::info!(
                                %peer_id,
                                %addr,
                                "Re-dialing dropped peer (mid-session recovery, below floor)"
                            ),
                            Err(e) => tracing::debug!(
                                %peer_id,
                                %addr,
                                error = %e,
                                "Mid-session peer re-dial skipped"
                            ),
                        }
                    }
                }
            }

            // Periodic Kademlia bootstrap — keeps the DHT routing table fresh
            // on long-running validators. Fire-and-forget; progress arrives
            // via `KademliaEvent::OutboundQueryProgressed`.
            _ = kademlia_bootstrap_interval.tick(), if dht_enabled => {
                match state.swarm.behaviour_mut().kademlia.bootstrap() {
                    Ok(query_id) => {
                        tracing::debug!(
                            ?query_id,
                            "Periodic Kademlia bootstrap initiated"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "Periodic Kademlia bootstrap failed to start \
                             (no known peers in routing table?)"
                        );
                    }
                }
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
                // Pre-attach is normal during the bootstrap window: the
                // libp2p stack starts accepting inbound block-sync requests
                // as soon as listeners bind, but the node-level engine in
                // `event_loop.rs` only spawns after the validator-mesh
                // warm-up gate. Log noisily only if a subscriber was once
                // attached and has since been dropped (the genuinely
                // anomalous case).
                if state.block_sync_request_subscriber_ever_attached {
                    tracing::warn!(
                        %peer,
                        "Inbound block-sync request received but subscriber was dropped — \
                         replying with Storage error"
                    );
                } else {
                    tracing::debug!(
                        %peer,
                        "Inbound block-sync request received during bootstrap window \
                         (subscriber not yet attached) — replying with Storage error"
                    );
                }
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

/// Translates a libp2p `request_response::Event` for the consensus-direct
/// codec into the typed `ConsensusMessage` channel exposed to the consensus
/// engine.
///
/// Inbound flow:
///   1. Peer sends a `ConsensusDirectRequest::Message(ConsensusMessage)`.
///   2. We check per-peer inbound concurrency; if at cap, immediately reply
///      `Error(ServerBusy{limit})` (no queuing — same anti-pattern guard as
///      block-sync).
///   3. If no consensus subscriber is attached, immediately reply
///      `Error(NoSubscriber)` so the sender stops retrying against us.
///   4. Otherwise: bump in-flight count, push the message to the subscriber,
///      and synchronously reply `Ack` (the consensus engine processes from
///      its own queue independently — we do not block the wire on its
///      pipeline).
///
/// Outbound flow:
///   * `ResponseSent` → trace log (request fully flushed; nothing else to do).
///   * `InboundFailure` → decrement in-flight counter and log.
///   * `OutboundFailure` → log; the consensus retry policy in tenzro-consensus
///     reacts to the typed error class returned through `Ack`/transport.
fn handle_consensus_direct_event(
    state: &mut EventLoopState,
    event: request_response::Event<ConsensusDirectRequest, ConsensusDirectResponse>,
) {
    use request_response::{Event as RrEvent, Message};
    match event {
        RrEvent::Message {
            peer,
            message: Message::Request {
                request_id: _,
                request,
                channel,
            },
            ..
        } => {
            // Per-peer inbound concurrency cap. Reject overflow synchronously
            // with ServerBusy rather than queueing — queuing causes the
            // requester's response timeout to fire while the request still
            // sits in our backlog.
            let inflight = state
                .consensus_direct_inbound_inflight
                .entry(peer)
                .or_insert(0);
            if *inflight >= MAX_INBOUND_STREAMS_PER_PEER {
                tracing::warn!(
                    %peer,
                    limit = MAX_INBOUND_STREAMS_PER_PEER,
                    "consensus-direct: rejecting overflow inbound stream"
                );
                let _ = state
                    .swarm
                    .behaviour_mut()
                    .consensus_direct
                    .send_response(
                        channel,
                        ConsensusDirectResponse::Error(ConsensusDirectError::ServerBusy {
                            limit: MAX_INBOUND_STREAMS_PER_PEER,
                        }),
                    );
                return;
            }

            // No subscriber attached — sender should NOT retry against us.
            // Reply NoSubscriber so the consensus retry policy on the other
            // side can prune us from its targets.
            //
            // Pre-attach is normal during the validator-mesh warm-up window:
            // the libp2p stack accepts inbound consensus-direct requests as
            // soon as listeners bind, but the node-level engine attaches via
            // `subscribe_consensus_direct()` only after `init_consensus()`
            // and the bootstrap-quorum gate clear. Log noisily only when a
            // subscriber was once attached and has since been dropped.
            let Some(tx) = state.consensus_direct_subscriber.as_ref() else {
                if state.consensus_direct_subscriber_ever_attached {
                    tracing::warn!(
                        %peer,
                        "consensus-direct: subscriber was dropped — replying NoSubscriber"
                    );
                } else {
                    tracing::debug!(
                        %peer,
                        "consensus-direct: inbound during bootstrap window \
                         (subscriber not yet attached) — replying NoSubscriber"
                    );
                }
                let _ = state
                    .swarm
                    .behaviour_mut()
                    .consensus_direct
                    .send_response(
                        channel,
                        ConsensusDirectResponse::Error(ConsensusDirectError::NoSubscriber),
                    );
                return;
            };

            // Forward to the consensus engine. We Ack synchronously — the
            // engine processes the message from its own queue. The Ack means
            // "we accepted the message into our pipeline", not "we processed
            // the consensus state-machine effect of this message".
            let ConsensusDirectRequest::Message(consensus_msg) = request;
            let send_result = tx.send(consensus_msg);
            if send_result.is_err() {
                tracing::warn!(
                    %peer,
                    "consensus-direct: subscriber dropped — replying NoSubscriber"
                );
                state.consensus_direct_subscriber = None;
                let _ = state
                    .swarm
                    .behaviour_mut()
                    .consensus_direct
                    .send_response(
                        channel,
                        ConsensusDirectResponse::Error(ConsensusDirectError::NoSubscriber),
                    );
                return;
            }

            *inflight += 1;

            let _ = state
                .swarm
                .behaviour_mut()
                .consensus_direct
                .send_response(channel, ConsensusDirectResponse::Ack);
        }
        RrEvent::Message {
            peer,
            message: Message::Response {
                request_id,
                response,
            },
            ..
        } => {
            // Outbound responses are Ack/Error. We log Error variants because
            // the sender's consensus retry policy may want to skip future
            // dispatches to a NoSubscriber peer (the per-validator dispatch
            // loop in event_loop.rs picks the validator set fresh each call,
            // so a NoSubscriber decision is naturally recomputed next round).
            match response {
                ConsensusDirectResponse::Ack => {
                    tracing::trace!(%peer, %request_id, "consensus-direct ack");
                }
                ConsensusDirectResponse::Error(err) => {
                    tracing::warn!(
                        %peer,
                        %request_id,
                        %err,
                        "consensus-direct: peer returned error response"
                    );
                }
            }
        }
        RrEvent::OutboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            tracing::warn!(
                %peer,
                %request_id,
                %error,
                "consensus-direct outbound failure"
            );
        }
        RrEvent::InboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            tracing::debug!(
                %peer,
                %request_id,
                %error,
                "consensus-direct inbound failure"
            );
            // Decrement inflight on the failure path — the request never
            // reached `send_response`, so the slot is freed here.
            if let Some(count) = state.consensus_direct_inbound_inflight.get_mut(&peer)
                && *count > 0
            {
                *count -= 1;
            }
        }
        RrEvent::ResponseSent { peer, request_id, .. } => {
            tracing::trace!(
                %peer,
                %request_id,
                "consensus-direct response flushed to wire"
            );
            // Decrement inflight on the happy path — the response is now on
            // the wire and the inbound stream slot is freed.
            if let Some(count) = state.consensus_direct_inbound_inflight.get_mut(&peer)
                && *count > 0
            {
                *count -= 1;
            }
        }
    }
}

/// Handles inbound and outbound events from the MPC relay
/// request-response codec (`/tenzro/mpc/req-resp/1.0.0`).
///
/// Mirrors `handle_consensus_direct_event` with one extra step: every
/// inbound `MpcRelayRequest` is audited against the installed
/// `MpcDidResolver` — the sender's claimed `from_did` must round-trip back
/// to the connection's `PeerId`. A mismatch (or a missing resolver) means
/// either no identity is bound or the sender is spoofing a DID they don't
/// control; either way we reject with `MpcRelayError::UnknownSender` so the
/// session driver on the other side fails fast.
fn handle_mpc_relay_event(
    state: &mut EventLoopState,
    event: request_response::Event<
        crate::mpc_relay::MpcRelayRequest,
        crate::mpc_relay::MpcRelayResponse,
    >,
) {
    use crate::mpc_relay::{MpcRelayError, MpcRelayResponse, MAX_INBOUND_STREAMS_PER_PEER};
    use request_response::{Event as RrEvent, Message};
    match event {
        RrEvent::Message {
            peer,
            message: Message::Request {
                request_id: _,
                request,
                channel,
            },
            ..
        } => {
            // Per-peer inbound concurrency cap. Reject overflow synchronously
            // with ServerBusy — queueing would cause the requester's
            // per-round timeout to fire while the request sits in our
            // backlog (same rationale as consensus-direct).
            let inflight = state
                .mpc_relay_inbound_inflight
                .entry(peer)
                .or_insert(0);
            if *inflight >= MAX_INBOUND_STREAMS_PER_PEER {
                tracing::warn!(
                    %peer,
                    limit = MAX_INBOUND_STREAMS_PER_PEER,
                    "mpc-relay: rejecting overflow inbound stream"
                );
                let _ = state
                    .swarm
                    .behaviour_mut()
                    .mpc_relay
                    .send_response(
                        channel,
                        MpcRelayResponse::Error(MpcRelayError::ServerBusy {
                            limit: MAX_INBOUND_STREAMS_PER_PEER,
                        }),
                    );
                return;
            }

            // Sender-DID audit. The relay is fail-closed: no resolver means
            // no identity binding is wired, so we cannot prove who the peer
            // claims to be. Either way the inbound message is rejected
            // before it reaches the session pipeline.
            let claimed_did = request.from_did.clone();
            let audit_ok = match state.mpc_did_resolver.as_ref() {
                None => {
                    tracing::warn!(
                        %peer,
                        claimed_did = %claimed_did,
                        "mpc-relay: rejecting inbound — no DID resolver installed"
                    );
                    false
                }
                Some(resolver) => match resolver.did_for_peer_id(&peer) {
                    Some(actual_did) if actual_did == claimed_did => true,
                    Some(actual_did) => {
                        tracing::warn!(
                            %peer,
                            claimed_did = %claimed_did,
                            actual_did = %actual_did,
                            "mpc-relay: from_did does not match peer's bound DID — rejecting"
                        );
                        false
                    }
                    None => {
                        tracing::warn!(
                            %peer,
                            claimed_did = %claimed_did,
                            "mpc-relay: peer has no bound DID — rejecting"
                        );
                        false
                    }
                },
            };
            if !audit_ok {
                let _ = state
                    .swarm
                    .behaviour_mut()
                    .mpc_relay
                    .send_response(
                        channel,
                        MpcRelayResponse::Error(MpcRelayError::UnknownSender),
                    );
                return;
            }

            // No subscriber attached — fast-fail so the sending session
            // driver can abort rather than wait for a per-round timeout.
            // Pre-attach is normal during bootstrap (the bridge attaches
            // the MPC subscriber only after the keyshare store loads).
            let Some(tx) = state.mpc_relay_subscriber.as_ref() else {
                if state.mpc_relay_subscriber_ever_attached {
                    tracing::warn!(
                        %peer,
                        "mpc-relay: subscriber was dropped — replying NoSubscriber"
                    );
                } else {
                    tracing::debug!(
                        %peer,
                        "mpc-relay: inbound during bootstrap window \
                         (subscriber not yet attached) — replying NoSubscriber"
                    );
                }
                let _ = state
                    .swarm
                    .behaviour_mut()
                    .mpc_relay
                    .send_response(
                        channel,
                        MpcRelayResponse::Error(MpcRelayError::NoSubscriber),
                    );
                return;
            };

            // Forward into the session pipeline and Ack synchronously. The
            // Ack means "we accepted the round message into our pipeline",
            // not "we completed the protocol round".
            let send_result = tx.send(request);
            if send_result.is_err() {
                tracing::warn!(
                    %peer,
                    "mpc-relay: subscriber dropped — replying NoSubscriber"
                );
                state.mpc_relay_subscriber = None;
                let _ = state
                    .swarm
                    .behaviour_mut()
                    .mpc_relay
                    .send_response(
                        channel,
                        MpcRelayResponse::Error(MpcRelayError::NoSubscriber),
                    );
                return;
            }

            *inflight += 1;

            let _ = state
                .swarm
                .behaviour_mut()
                .mpc_relay
                .send_response(channel, MpcRelayResponse::Ack);
        }
        RrEvent::Message {
            peer,
            message: Message::Response {
                request_id,
                response,
            },
            ..
        } => match response {
            MpcRelayResponse::Ack => {
                tracing::trace!(%peer, %request_id, "mpc-relay ack");
            }
            MpcRelayResponse::Error(err) => {
                tracing::warn!(
                    %peer,
                    %request_id,
                    %err,
                    "mpc-relay: peer returned error response"
                );
            }
        },
        RrEvent::OutboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            tracing::warn!(
                %peer,
                %request_id,
                %error,
                "mpc-relay outbound failure"
            );
        }
        RrEvent::InboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            tracing::debug!(
                %peer,
                %request_id,
                %error,
                "mpc-relay inbound failure"
            );
            if let Some(count) = state.mpc_relay_inbound_inflight.get_mut(&peer)
                && *count > 0
            {
                *count -= 1;
            }
        }
        RrEvent::ResponseSent { peer, request_id, .. } => {
            tracing::trace!(
                %peer,
                %request_id,
                "mpc-relay response flushed to wire"
            );
            if let Some(count) = state.mpc_relay_inbound_inflight.get_mut(&peer)
                && *count > 0
            {
                *count -= 1;
            }
        }
    }
}

/// Handles inbound and outbound events from the cluster-tunnel
/// request-response codec (`/tenzro/cluster-tunnel/1.0.0`).
///
/// Mirrors `handle_block_sync_event` (full-duplex parked-channel pattern):
///   * Inbound `Request` — enforce the per-peer concurrency cap (reject
///     overflow with `ServerBusy`), then park the response channel and notify
///     the member's runtime subscriber. No subscriber means this node is not
///     a cluster member, so reply `NoMember` and let the head fail over.
///   * Inbound `Response` (the member's `Ack`/`Error`) — forward to the head's
///     result subscriber so its splice loop can consume the piggybacked
///     return frames.
///   * `OutboundFailure` — surface as a transport error on the result channel.
///   * `InboundFailure` — drop the parked channel and decrement in-flight.
///   * `ResponseSent` — decrement in-flight.
fn handle_cluster_tunnel_event(
    state: &mut EventLoopState,
    event: request_response::Event<
        crate::cluster_tunnel_proto::ClusterTunnelRequest,
        crate::cluster_tunnel_proto::ClusterTunnelResponse,
    >,
) {
    use crate::cluster_tunnel_proto::{
        ClusterTunnelError, ClusterTunnelResponse, MAX_INBOUND_STREAMS_PER_PEER,
    };
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
            // Per-peer inbound concurrency cap. Reject overflow synchronously
            // — the head's splice loop pipelines frames, so a backlog would
            // stall its session past the request timeout.
            let inflight = state
                .cluster_tunnel_inbound_inflight
                .entry(peer)
                .or_insert(0);
            if *inflight >= MAX_INBOUND_STREAMS_PER_PEER {
                tracing::warn!(
                    %peer,
                    limit = MAX_INBOUND_STREAMS_PER_PEER,
                    "cluster-tunnel: rejecting overflow inbound stream"
                );
                let _ = state
                    .swarm
                    .behaviour_mut()
                    .cluster_tunnel
                    .send_response(
                        channel,
                        ClusterTunnelResponse::Error(ClusterTunnelError::ServerBusy {
                            limit: MAX_INBOUND_STREAMS_PER_PEER,
                        }),
                    );
                return;
            }

            // No subscriber attached — this node is not running a cluster
            // member runtime, so there is no local rpc-server to splice to.
            // Reply NoMember so the head stops dialing this peer's tunnel.
            let Some(tx) = state.cluster_tunnel_request_subscriber.as_ref() else {
                if state.cluster_tunnel_request_subscriber_ever_attached {
                    tracing::warn!(
                        %peer,
                        "cluster-tunnel: subscriber was dropped — replying NoMember"
                    );
                } else {
                    tracing::debug!(
                        %peer,
                        "cluster-tunnel: inbound before member runtime attached \
                         — replying NoMember"
                    );
                }
                let _ = state
                    .swarm
                    .behaviour_mut()
                    .cluster_tunnel
                    .send_response(
                        channel,
                        ClusterTunnelResponse::Error(ClusterTunnelError::NoMember),
                    );
                return;
            };

            state
                .pending_inbound_cluster_tunnel
                .insert(request_id, channel);

            let inbound = InboundClusterTunnel {
                peer,
                request_id,
                request,
            };
            if tx.send(inbound).is_err() {
                tracing::warn!(
                    %peer,
                    "cluster-tunnel: request subscriber dropped — replying NoMember"
                );
                state.cluster_tunnel_request_subscriber = None;
                if let Some(channel) = state.pending_inbound_cluster_tunnel.remove(&request_id) {
                    let _ = state
                        .swarm
                        .behaviour_mut()
                        .cluster_tunnel
                        .send_response(
                            channel,
                            ClusterTunnelResponse::Error(ClusterTunnelError::NoMember),
                        );
                }
                return;
            }

            *inflight += 1;
        }
        RrEvent::Message {
            peer,
            message: Message::Response {
                request_id,
                response,
            },
            ..
        } => {
            if let Some(tx) = state.cluster_tunnel_result_subscriber.as_ref() {
                let item = OutboundClusterTunnelResult {
                    peer,
                    request_id,
                    result: Ok(response),
                };
                if tx.send(item).is_err() {
                    tracing::warn!("cluster-tunnel: result subscriber dropped");
                    state.cluster_tunnel_result_subscriber = None;
                }
            } else {
                tracing::warn!(
                    %peer,
                    %request_id,
                    "cluster-tunnel: response received but no result subscriber attached"
                );
            }
        }
        RrEvent::OutboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            tracing::warn!(%peer, %request_id, %error, "cluster-tunnel outbound failure");
            if let Some(tx) = state.cluster_tunnel_result_subscriber.as_ref() {
                let item = OutboundClusterTunnelResult {
                    peer,
                    request_id,
                    result: Err(error.into()),
                };
                if tx.send(item).is_err() {
                    state.cluster_tunnel_result_subscriber = None;
                }
            }
        }
        RrEvent::InboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            tracing::debug!(%peer, %request_id, %error, "cluster-tunnel inbound failure");
            state.pending_inbound_cluster_tunnel.remove(&request_id);
            if let Some(count) = state.cluster_tunnel_inbound_inflight.get_mut(&peer)
                && *count > 0
            {
                *count -= 1;
            }
        }
        RrEvent::ResponseSent { peer, request_id, .. } => {
            tracing::trace!(%peer, %request_id, "cluster-tunnel response flushed to wire");
            if let Some(count) = state.cluster_tunnel_inbound_inflight.get_mut(&peer)
                && *count > 0
            {
                *count -= 1;
            }
        }
    }
}

/// Drives the committee-DA request-response overlay.
///
/// Inbound (`StoreSliver` / `FetchSliver`) requests are subject to a per-peer
/// inflight cap (`DA_COMMITTEE_MAX_INBOUND_STREAMS_PER_PEER`, reject overflow
/// with `ServerBusy` — do not queue), then parked and handed to the attached
/// DA handler; the handler answers later via `SendDaCommitteeResponse`. When no
/// handler is attached the request is answered with `NoHandler`.
///
/// Outbound replies are correlated per-request: a `Message::Response` fulfils
/// the `oneshot` the caller is awaiting (parked under its `OutboundRequestId`),
/// and an `OutboundFailure` fulfils it with a transport error.
fn handle_da_committee_event(
    state: &mut EventLoopState,
    event: request_response::Event<DaCommitteeRequest, DaCommitteeResponse>,
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
            // Per-peer inbound concurrency cap. Reject overflow synchronously —
            // queueing would let the requester's response timeout fire while
            // the request still sits in our backlog.
            let inflight = state
                .da_committee_inbound_inflight
                .entry(peer)
                .or_insert(0);
            if *inflight >= DA_COMMITTEE_MAX_INBOUND_STREAMS_PER_PEER {
                tracing::warn!(
                    %peer,
                    limit = DA_COMMITTEE_MAX_INBOUND_STREAMS_PER_PEER,
                    "committee-DA: rejecting overflow inbound stream"
                );
                let _ = state
                    .swarm
                    .behaviour_mut()
                    .da_committee
                    .send_response(
                        channel,
                        DaCommitteeResponse::Error(DaCommitteeError::ServerBusy {
                            limit: DA_COMMITTEE_MAX_INBOUND_STREAMS_PER_PEER,
                        }),
                    );
                return;
            }

            // No handler attached — this node is not running a committee-DA
            // member handler (bootstrap window, or handler dropped). Reply
            // NoHandler so the requester scores us down and retries elsewhere.
            let Some(tx) = state.da_committee_request_subscriber.as_ref() else {
                if state.da_committee_request_subscriber_ever_attached {
                    tracing::warn!(
                        %peer,
                        "committee-DA: handler was dropped — replying NoHandler"
                    );
                } else {
                    tracing::debug!(
                        %peer,
                        "committee-DA: inbound before member handler attached \
                         — replying NoHandler"
                    );
                }
                let _ = state
                    .swarm
                    .behaviour_mut()
                    .da_committee
                    .send_response(
                        channel,
                        DaCommitteeResponse::Error(DaCommitteeError::NoHandler),
                    );
                return;
            };

            state
                .pending_inbound_da_committee
                .insert(request_id, channel);

            let inbound = InboundDaCommittee {
                peer,
                request_id,
                request,
            };
            if tx.send(inbound).is_err() {
                tracing::warn!(
                    %peer,
                    "committee-DA: request handler dropped — replying NoHandler"
                );
                state.da_committee_request_subscriber = None;
                if let Some(channel) = state.pending_inbound_da_committee.remove(&request_id) {
                    let _ = state
                        .swarm
                        .behaviour_mut()
                        .da_committee
                        .send_response(
                            channel,
                            DaCommitteeResponse::Error(DaCommitteeError::NoHandler),
                        );
                }
                return;
            }

            *inflight += 1;
        }
        RrEvent::Message {
            peer,
            message: Message::Response {
                request_id,
                response,
            },
            ..
        } => {
            match state.pending_da_committee_requests.remove(&request_id) {
                Some(reply) => {
                    let _ = reply.send(Ok(response));
                }
                None => {
                    tracing::warn!(
                        %peer,
                        %request_id,
                        "committee-DA: response for unknown outbound request"
                    );
                }
            }
        }
        RrEvent::OutboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            tracing::warn!(%peer, %request_id, %error, "committee-DA outbound failure");
            if let Some(reply) = state.pending_da_committee_requests.remove(&request_id) {
                let _ = reply.send(Err(NetworkError::PeerNotFound(format!(
                    "committee-DA outbound failure to {}: {}",
                    peer, error
                ))));
            }
        }
        RrEvent::InboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            tracing::debug!(%peer, %request_id, %error, "committee-DA inbound failure");
            state.pending_inbound_da_committee.remove(&request_id);
            if let Some(count) = state.da_committee_inbound_inflight.get_mut(&peer)
                && *count > 0
            {
                *count -= 1;
            }
        }
        RrEvent::ResponseSent { peer, request_id, .. } => {
            tracing::trace!(%peer, %request_id, "committee-DA response flushed to wire");
            if let Some(count) = state.da_committee_inbound_inflight.get_mut(&peer)
                && *count > 0
            {
                *count -= 1;
            }
        }
    }
}

/// Drives the database replicated-write request-response overlay.
///
/// Inbound (`ApplyWrite`) requests are subject to a per-peer inflight cap
/// (`DB_REPLICATE_MAX_INBOUND_STREAMS_PER_PEER`, reject overflow with
/// `ServerBusy` — do not queue), then parked and handed to the attached
/// replication handler; the handler answers later via `SendDbReplicateResponse`.
/// When no handler is attached the request is answered with `NoHandler`.
///
/// Outbound replies are correlated per-request: a `Message::Response` fulfils
/// the `oneshot` the caller is awaiting (parked under its `OutboundRequestId`),
/// and an `OutboundFailure` fulfils it with a transport error.
fn handle_db_replicate_event(
    state: &mut EventLoopState,
    event: request_response::Event<DbReplicateRequest, DbReplicateResponse>,
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
            let inflight = state
                .db_replicate_inbound_inflight
                .entry(peer)
                .or_insert(0);
            if *inflight >= DB_REPLICATE_MAX_INBOUND_STREAMS_PER_PEER {
                tracing::warn!(
                    %peer,
                    limit = DB_REPLICATE_MAX_INBOUND_STREAMS_PER_PEER,
                    "db-replicate: rejecting overflow inbound stream"
                );
                let _ = state
                    .swarm
                    .behaviour_mut()
                    .db_replicate
                    .send_response(
                        channel,
                        DbReplicateResponse::Error(DbReplicateError::ServerBusy {
                            limit: DB_REPLICATE_MAX_INBOUND_STREAMS_PER_PEER,
                        }),
                    );
                return;
            }

            let Some(tx) = state.db_replicate_request_subscriber.as_ref() else {
                if state.db_replicate_request_subscriber_ever_attached {
                    tracing::warn!(
                        %peer,
                        "db-replicate: handler was dropped — replying NoHandler"
                    );
                } else {
                    tracing::debug!(
                        %peer,
                        "db-replicate: inbound before holder handler attached \
                         — replying NoHandler"
                    );
                }
                let _ = state
                    .swarm
                    .behaviour_mut()
                    .db_replicate
                    .send_response(
                        channel,
                        DbReplicateResponse::Error(DbReplicateError::NoHandler),
                    );
                return;
            };

            state
                .pending_inbound_db_replicate
                .insert(request_id, channel);

            let inbound = InboundDbReplicate {
                peer,
                request_id,
                request,
            };
            if tx.send(inbound).is_err() {
                tracing::warn!(
                    %peer,
                    "db-replicate: request handler dropped — replying NoHandler"
                );
                state.db_replicate_request_subscriber = None;
                if let Some(channel) = state.pending_inbound_db_replicate.remove(&request_id) {
                    let _ = state
                        .swarm
                        .behaviour_mut()
                        .db_replicate
                        .send_response(
                            channel,
                            DbReplicateResponse::Error(DbReplicateError::NoHandler),
                        );
                }
                return;
            }

            *inflight += 1;
        }
        RrEvent::Message {
            peer,
            message: Message::Response {
                request_id,
                response,
            },
            ..
        } => {
            match state.pending_db_replicate_requests.remove(&request_id) {
                Some(reply) => {
                    let _ = reply.send(Ok(response));
                }
                None => {
                    tracing::warn!(
                        %peer,
                        %request_id,
                        "db-replicate: response for unknown outbound request"
                    );
                }
            }
        }
        RrEvent::OutboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            tracing::warn!(%peer, %request_id, %error, "db-replicate outbound failure");
            if let Some(reply) = state.pending_db_replicate_requests.remove(&request_id) {
                let _ = reply.send(Err(NetworkError::PeerNotFound(format!(
                    "db-replicate outbound failure to {}: {}",
                    peer, error
                ))));
            }
        }
        RrEvent::InboundFailure {
            peer,
            request_id,
            error,
            ..
        } => {
            tracing::debug!(%peer, %request_id, %error, "db-replicate inbound failure");
            state.pending_inbound_db_replicate.remove(&request_id);
            if let Some(count) = state.db_replicate_inbound_inflight.get_mut(&peer)
                && *count > 0
            {
                *count -= 1;
            }
        }
        RrEvent::ResponseSent { peer, request_id, .. } => {
            tracing::trace!(%peer, %request_id, "db-replicate response flushed to wire");
            if let Some(count) = state.db_replicate_inbound_inflight.get_mut(&peer)
                && *count > 0
            {
                *count -= 1;
            }
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

                // Dynamically admit validators into the registry so their
                // consensus / attestation messages don't get rejected and
                // cause gossipsub peer-score decay → mutual ban. Admission
                // requires a verified `tenzro-peer-binding=` token in the
                // agent_version — an Ed25519 signature by an active validator
                // identity over this transport-authenticated PeerId. Anything
                // else is a no-op. See PeerManager::try_register_validator_on_identify.
                state
                    .peer_manager
                    .try_register_validator_on_identify(&peer_id, &info.agent_version);

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

                // Circuit-Relay v2 reservation on peers that advertise HOP.
                //
                // The DCUtR + relay-client + AutoNAT-client behaviours are all
                // constructed on any node with `enable_hole_punching: true`
                // (default), but until this point NOTHING ever *triggered*
                // an actual reservation. libp2p 0.21's relay-client uses
                // `Swarm::listen_on(<relay-addr>/p2p-circuit)` as the
                // reservation-request mechanism (see `priv_client/transport.rs`
                // docs: "listen via remote relay node"). Without this call,
                // a NAT'd edge node ends up with all the traversal machinery
                // wired but never books a reservation slot, so peers can't
                // reach it and DCUtR has no relayed connection to upgrade.
                //
                // Gating:
                //   * Only attempt if OUR reachability tier is NOT `Direct`.
                //     A publicly-reachable node has no need for a relay; using
                //     one would burn a slot on the relay-server side that a
                //     NAT'd peer could use.
                //   * Only attempt if the peer advertises the HOP protocol
                //     (`/libp2p/circuit/relay/0.2.0/hop`) — i.e. it's actually
                //     running the relay-*server* half.
                //   * Idempotent per peer: `attempted_relay_reservations`
                //     tracks who we've already tried. Cleared on relay-lost.
                //   * Only attempt with a globally-routable peer address —
                //     reserving on a LAN peer produces a useless circuit that
                //     is unreachable from the WAN.
                {
                    use crate::reachability::ReachabilityTier;
                    let our_tier = state.reachability.tier();
                    let peer_speaks_hop = info
                        .protocols
                        .contains(&libp2p::relay::HOP_PROTOCOL_NAME);
                    // Bootstrap peers are the validator-class relay-serving
                    // nodes by convention. If the peer connected via one of
                    // our configured boot addresses, treat it as a relay
                    // candidate even if its identify `protocols` field
                    // didn't advertise HOP explicitly — the deployed
                    // validator image runs `enable_relay: true` per role
                    // config so relay-server is up. This is the fallback
                    // for the case where identify's protocol-list
                    // serialization drops HOP (observed empty in the
                    // 2026-07-15 verification run against a healthy fleet).
                    let peer_is_bootstrap = state
                        .bootstrap_peers
                        .iter()
                        .any(|(pid, _)| *pid == peer_id);
                    let peer_looks_relayable = peer_speaks_hop || peer_is_bootstrap;
                    let already_attempted =
                        state.attempted_relay_reservations.contains(&peer_id);
                    tracing::debug!(
                        %peer_id,
                        our_tier = %our_tier.as_str(),
                        peer_speaks_hop,
                        peer_is_bootstrap,
                        already_attempted,
                        proto_count = info.protocols.len(),
                        "Identify: evaluating relay-reservation candidacy"
                    );
                    if our_tier != ReachabilityTier::Direct
                        && peer_looks_relayable
                        && !already_attempted
                    {
                        // Pick a reachable listen address for the relay
                        // multiaddr. `is_globally_routable` rejects DNS
                        // components (it only accepts Ip4/Ip6), so use a
                        // laxer filter here: accept anything that isn't
                        // obviously LAN/loopback. A publicly-advertised DNS
                        // listen addr (e.g. `/dns4/testnet-boot-1.tenzro.xyz`)
                        // is the CORRECT reservation target — libp2p will
                        // resolve it against an existing connection to the
                        // same peer_id, and it survives IP rotations.
                        let is_relay_target_ok = |addr: &Multiaddr| -> bool {
                            use libp2p::multiaddr::Protocol;
                            for proto in addr.iter() {
                                match proto {
                                    Protocol::Ip4(ip) => {
                                        if ip.is_loopback()
                                            || ip.is_link_local()
                                            || ip.is_unspecified()
                                        {
                                            return false;
                                        }
                                        return true;
                                    }
                                    Protocol::Ip6(ip) => {
                                        if ip.is_loopback() || ip.is_unspecified() {
                                            return false;
                                        }
                                        return true;
                                    }
                                    Protocol::Dns(_)
                                    | Protocol::Dns4(_)
                                    | Protocol::Dns6(_)
                                    | Protocol::Dnsaddr(_) => return true,
                                    _ => {}
                                }
                            }
                            false
                        };
                        let relay_addr = info
                            .listen_addrs
                            .iter()
                            .find(|addr| is_relay_target_ok(addr))
                            .cloned();
                        if let Some(base_addr) = relay_addr {
                            // Compose `/dns-or-ip/tcp/port/p2p/<relay>/p2p-circuit`.
                            // The relay-client transport wraps `listen_on` on
                            // any multiaddr ending in `/p2p-circuit` into a
                            // HOP reservation request to the relay peer.
                            let mut circuit_addr = base_addr.clone();
                            // Ensure the /p2p/<peer_id> component is present —
                            // relay-client needs it to know which peer to
                            // reserve on.
                            let has_p2p = circuit_addr.iter().any(|p| {
                                matches!(p, libp2p::multiaddr::Protocol::P2p(_))
                            });
                            if !has_p2p {
                                circuit_addr = circuit_addr
                                    .with(libp2p::multiaddr::Protocol::P2p(peer_id));
                            }
                            circuit_addr =
                                circuit_addr.with(libp2p::multiaddr::Protocol::P2pCircuit);

                            match state.swarm.listen_on(circuit_addr.clone()) {
                                Ok(listener_id) => {
                                    tracing::info!(
                                        %peer_id,
                                        our_tier = %our_tier.as_str(),
                                        ?listener_id,
                                        circuit = %circuit_addr,
                                        "Requesting Circuit-Relay v2 reservation \
                                         (NAT-traversal fallback)"
                                    );
                                    state
                                        .attempted_relay_reservations
                                        .insert(peer_id);
                                }
                                Err(e) => {
                                    tracing::debug!(
                                        %peer_id,
                                        error = %e,
                                        "Relay reservation listen_on failed"
                                    );
                                }
                            }
                        }
                    }
                }

                // Add only globally routable addresses to Kademlia DHT, then
                // dial the discovered peer to actually form a mesh connection.
                //
                // Filters out loopback (127.x), private RFC-1918, Docker bridge (172.17.x),
                // link-local, and unspecified addresses that K8s pods cannot reach.
                //
                // The dial-on-discovery step is the canonical permissionless-mesh
                // pattern used by Substrate (`discovery.rs::next_kad_random_query` →
                // dial via Behaviour::poll), Lighthouse (`network/src/discovery.rs`
                // `Discovery::dial_peer`), and IPFS Kubo. Without it, joiners learn
                // about the other validators via Kademlia/Identify but never open
                // TCP connections to them — the routing table fills up while
                // `swarm.connected_peers()` stays at 0, producing a permanent
                // star topology around the bootstrap node.
                let already_connected = state.swarm.is_connected(&peer_id);
                for addr in &info.listen_addrs {
                    if is_globally_routable(addr) {
                        state
                            .swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&peer_id, addr.clone());

                        // Feed the discovered address into the Swarm's per-peer
                        // address book so `request_response` behaviours
                        // (`consensus_direct`, `block_sync`, etc.) can dial out
                        // when they enqueue a request.
                        //
                        // **This is the canonical libp2p fix for "send_request
                        // returns RequestId synchronously, then dial fails
                        // silently."** `request_response::Behaviour` does not
                        // auto-discover addresses from existing swarm
                        // connections — it requires either an explicit address
                        // on the request or a prior `Swarm::add_peer_address`
                        // call. Without this hook, every cross-replica vote
                        // dispatch was a no-op: `send_request` happily allocated
                        // a RequestId, the dispatcher logged `dispatched=9`,
                        // and the request sat in the state machine waiting for
                        // a dial that never happened — never delivered as
                        // `OutboundFailure::DialFailure` either, because the
                        // dial wasn't scheduled. Result: consensus QC never
                        // formed (`votes=1 threshold=7` forever).
                        //
                        // Identify's `Event::Received { peer_id, info }` is
                        // the natural hook — `info.listen_addrs` is the peer's
                        // self-advertised reachable set, which is exactly what
                        // request_response needs to dial. The same address set
                        // is already fed into Kademlia immediately above; this
                        // call extends the same data into the swarm-level
                        // address book that all behaviours consult.
                        //
                        // Refs: libp2p/rust-libp2p#5708, request_response
                        // Behaviour docs (the `add_address` method on the
                        // behaviour itself is deprecated in favour of
                        // `Swarm::add_peer_address`).
                        state.swarm.add_peer_address(peer_id, addr.clone());

                        if !already_connected {
                            match state.swarm.dial(
                                DialOpts::peer_id(peer_id)
                                    .addresses(vec![addr.clone()])
                                    .allocate_new_port()
                                    .build(),
                            ) {
                                Ok(()) => tracing::info!(
                                    %peer_id,
                                    %addr,
                                    "Dialing Kademlia-discovered peer (Identify)"
                                ),
                                Err(e) => tracing::debug!(
                                    %peer_id,
                                    %addr,
                                    error = %e,
                                    "Dial-on-discovery skipped"
                                ),
                            }
                        }
                    } else {
                        tracing::debug!(
                            "Skipping non-routable DHT address from {}: {}",
                            peer_id,
                            addr
                        );
                    }
                }

                // Permissionless NAT discovery: every Identify exchange reports
                // the local-node address the remote peer observed us at. Tally
                // distinct peers per observed address; once N≥3 independent
                // peers agree on the same external multiaddr, promote it via
                // `Swarm::add_external_address` so Identify advertises it on
                // the next exchange (libp2p sources advertised addrs from
                // `Swarm::external_addresses()`).
                //
                // This is the same primitive used to run NAT-agnostic
                // permissionless networks —
                // no `--external-p2p-addr` flag required, no per-deployment
                // config, works from home wifi, mobile, EC2, GCE alike.
                //
                // The N-distinct-peers gate is the standard rust-libp2p
                // defence against a single malicious peer lying about our
                // address (see libp2p-identify CHANGELOG 0.43.0: observed
                // addresses are no longer trusted by default). AutoNAT v2
                // client (registered in `TenzroBehaviour::autonat_client`)
                // adds orthogonal probe-back confirmation: it picks one of
                // our advertised external addresses and asks a public peer
                // to dial back to verify reachability. Both gates must pass.
                let obs = info.observed_addr.clone();
                if !is_globally_routable(&obs) {
                    tracing::trace!(
                        %peer_id,
                        observed = %obs,
                        "Ignoring non-routable observed address from peer"
                    );
                } else if !is_observed_port_one_of_ours(&obs, &state.listen_addresses) {
                    // Reject NAT-translated outbound source ports. The peer
                    // observed us at `(public_ip, ephemeral_port)` because
                    // our outbound connection was source-NAT'd; nothing is
                    // listening on the ephemeral port, so advertising it
                    // would publish an unreachable address. Subsequent peers
                    // would dial the ephemeral port, fail, and cache the
                    // stale entry — which is exactly the failure mode that
                    // halted consensus when v0 restarted (see
                    // `consensus_stall_2026_05_18` runbook).
                    //
                    // Only an observation whose port matches one of our
                    // actual listen-port bindings can plausibly be a
                    // dial-back-reachable address.
                    tracing::debug!(
                        %peer_id,
                        observed = %obs,
                        "Ignoring observed address — port not in our listen-port set \
                         (NAT-translated source port, not a reachable listen address)"
                    );
                } else if !state.advertised_external_addrs.contains(&obs) {
                    let reporters = state.observed_addrs.entry(obs.clone()).or_default();
                    if reporters.insert(peer_id) {
                        tracing::debug!(
                            %peer_id,
                            observed = %obs,
                            count = reporters.len(),
                            threshold = OBSERVED_ADDR_CONFIRMATION_THRESHOLD,
                            "Observed-address report received via Identify"
                        );
                    }
                    if reporters.len() >= OBSERVED_ADDR_CONFIRMATION_THRESHOLD {
                        tracing::info!(
                            address = %obs,
                            reporters = reporters.len(),
                            "Promoting observed address to advertised external address \
                             (N distinct peers agree — permissionless NAT discovery)"
                        );
                        state.swarm.add_external_address(obs.clone());
                        state.advertised_external_addrs.insert(obs.clone());
                        // Free the tally memory for this address — once promoted,
                        // additional reports are not actionable.
                        state.observed_addrs.remove(&obs);
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
            TenzroBehaviourEvent::ConsensusDirect(rr_event) => {
                handle_consensus_direct_event(state, rr_event);
            }
            TenzroBehaviourEvent::MpcRelay(rr_event) => {
                handle_mpc_relay_event(state, rr_event);
            }
            TenzroBehaviourEvent::ClusterTunnel(rr_event) => {
                handle_cluster_tunnel_event(state, rr_event);
            }
            TenzroBehaviourEvent::DaCommittee(rr_event) => {
                handle_da_committee_event(state, rr_event);
            }
            TenzroBehaviourEvent::DbReplicate(rr_event) => {
                handle_db_replicate_event(state, rr_event);
            }
            TenzroBehaviourEvent::AutonatClient(autonat::v2::client::Event {
                tested_addr,
                bytes_sent,
                server,
                result,
            }) => {
                // AutoNAT v2 client probe result. Successful probes confirm
                // an external address; libp2p's autonat client behaviour
                // emits `SwarmEvent::ExternalAddrConfirmed` on success
                // independently, so we just log here for observability.
                match result {
                    Ok(()) => {
                        tracing::info!(
                            %server,
                            address = %tested_addr,
                            bytes_sent,
                            "AutoNAT probe succeeded — address reachable"
                        );
                        state
                            .reachability
                            .record(crate::reachability::ReachabilityEvent::DirectConfirmed);
                        maybe_promote_kad_to_server(state);
                    }
                    Err(e) => {
                        tracing::debug!(
                            %server,
                            address = %tested_addr,
                            bytes_sent,
                            error = %e,
                            "AutoNAT probe failed — address not reachable from server"
                        );
                        state
                            .reachability
                            .record(crate::reachability::ReachabilityEvent::DirectLost);
                    }
                }
            }
            TenzroBehaviourEvent::AutonatServer(_) => {
                // Server-side dial-back requests. No action needed — the
                // behaviour serves probes autonomously.
            }
            TenzroBehaviourEvent::RelayClient(relay_event) => match relay_event {
                relay::client::Event::ReservationReqAccepted {
                    relay_peer_id,
                    renewal,
                    limit,
                } => {
                    tracing::info!(
                        %relay_peer_id,
                        renewal,
                        ?limit,
                        "Circuit-Relay v2 reservation accepted — this node is now \
                         reachable via /p2p/<relay>/p2p-circuit/p2p/<self>"
                    );
                    // Reachable via relay even if no direct path holds — enough
                    // to serve as a fallback tier.
                    state
                        .reachability
                        .record(crate::reachability::ReachabilityEvent::RelayReserved);
                }
                relay::client::Event::OutboundCircuitEstablished {
                    relay_peer_id,
                    limit,
                } => {
                    tracing::info!(
                        %relay_peer_id,
                        ?limit,
                        "Outbound circuit established via relay"
                    );
                }
                relay::client::Event::InboundCircuitEstablished {
                    src_peer_id,
                    limit,
                } => {
                    tracing::info!(
                        %src_peer_id,
                        ?limit,
                        "Inbound circuit established via relay"
                    );
                }
            },
            TenzroBehaviourEvent::Relay(_) => {
                // Server-side relay events (reservation requests served to
                // other peers). No action needed — the behaviour handles
                // them autonomously according to `relay::Config`.
            }
            TenzroBehaviourEvent::Dcutr(dcutr::Event {
                remote_peer_id,
                result,
            }) => match result {
                Ok(conn_id) => {
                    tracing::info!(
                        %remote_peer_id,
                        ?conn_id,
                        "DCUtR hole-punch succeeded — direct connection upgraded from relayed"
                    );
                    // A hole-punched direct path is, empirically, as reliable
                    // as a born-public address — corroborate direct reachability.
                    state
                        .reachability
                        .record(crate::reachability::ReachabilityEvent::DirectConfirmed);
                    maybe_promote_kad_to_server(state);
                }
                Err(e) => tracing::debug!(
                    %remote_peer_id,
                    error = %e,
                    "DCUtR hole-punch failed — will continue using relayed connection"
                ),
            },
            TenzroBehaviourEvent::Mdns(mdns_event) => match mdns_event {
                mdns::Event::Discovered(peers) => {
                    // A Tenzro node on the same L2 segment. Dial it directly on
                    // its private/link-local address and seed it into Kademlia
                    // so the local peer is reachable through the same paths as
                    // any other. Reachability records a local-direct signal so
                    // a node behind NAT — Unreachable on the public lane — can
                    // still serve roles to peers it can reach on the LAN.
                    for (peer_id, addr) in peers {
                        tracing::info!(
                            %peer_id,
                            %addr,
                            "mDNS discovered a local-network peer"
                        );
                        state
                            .swarm
                            .behaviour_mut()
                            .kademlia
                            .add_address(&peer_id, addr.clone());
                        if !state.swarm.is_connected(&peer_id)
                            && let Err(e) = state.swarm.dial(dial_opts_new_port(addr.clone()))
                        {
                            tracing::debug!(
                                %peer_id,
                                %addr,
                                error = %e,
                                "mDNS local-peer dial skipped"
                            );
                        }
                        state
                            .reachability
                            .record(crate::reachability::ReachabilityEvent::LocalDirectConfirmed);
                        state.local_peers.insert(peer_id.to_string());
                    }
                }
                mdns::Event::Expired(peers) => {
                    // mDNS TTLs lapsed for these peers. The swarm keeps any
                    // live connection; this only means they stopped announcing
                    // on the local segment, so drop the local-direct signal.
                    for (peer_id, addr) in peers {
                        tracing::debug!(
                            %peer_id,
                            %addr,
                            "mDNS local-network peer record expired"
                        );
                        state
                            .reachability
                            .record(crate::reachability::ReachabilityEvent::LocalDirectLost);
                        state.local_peers.remove(&peer_id.to_string());
                    }
                }
            },
            _ => {}
        },
        SwarmEvent::ConnectionEstablished {
            peer_id,
            endpoint,
            num_established,
            ..
        } => {
            // Enforce bans on reconnect. A banned peer that manages to
            // establish a connection (e.g. the ban predates the libp2p
            // block-list entry, or the block was hydrated after the dial)
            // is disconnected immediately and re-blocked for the remainder
            // of its ban window. `is_banned` returns false for protected
            // peers (boot nodes, binding-verified validators), so cluster
            // infrastructure can always reconnect.
            if state.peer_manager.is_banned(&peer_id) {
                tracing::warn!(
                    peer = %peer_id,
                    "Rejecting connection from banned peer; enforcing libp2p block for remaining ban window"
                );
                state.swarm.behaviour_mut().block_peer(peer_id);
                let _ = state.swarm.disconnect_peer_id(peer_id);
                return;
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

            // Application-layer peer address migration detection. libp2p's
            // `ConnectionEstablished` surfaces the remote multiaddr via
            // `endpoint.get_remote_address()`; comparing against the
            // previously observed remote for this peer lets us count QUIC
            // path migrations, mobile-network switches, and NAT rebinding
            // events without reaching into quinn-proto internals.
            let remote_addr = endpoint.get_remote_address().clone();
            if state.peer_manager.update_endpoint(&peer_id, remote_addr.clone()) {
                state.metrics.peer_address_migrations_total.inc();
                tracing::info!(
                    %peer_id,
                    new_addr = %remote_addr,
                    "Peer address migration observed — counter incremented"
                );
            }

            // Reset reconnection backoff on success. A bootstrap target that
            // just connected should start its next (hypothetical) recovery
            // from the floor, not carry forward a long stale backoff; and a
            // peer that flapped back out of `peer_redial` no longer needs
            // re-dialing. Bootstrap targets are keyed by the *configured*
            // multiaddr, which may differ from the observed remote (ephemeral
            // port), so reset by peer id where we can and by exact addr match
            // otherwise.
            state.peer_redial.remove(&peer_id);
            for (addr, backoff) in state.bootstrap_backoff.iter_mut() {
                let addr_matches_peer = state
                    .bootstrap_peers
                    .iter()
                    .any(|(pid, a)| *pid == peer_id && a == addr);
                if addr_matches_peer || *addr == remote_addr {
                    backoff.reset();
                }
            }

            // Fan out a `PeerEvent::Connected` exactly once per peer — only
            // when this is the first physical connection. Subsequent
            // multiplexed connections to the same peer don't re-emit. If
            // the receiver is gone (engine task panicked or stopped),
            // detach the subscriber so we stop trying.
            // Fan out `PeerEvent::Connected` once per peer, on the first
            // physical connection. If the receiver is gone, detach so we
            // stop trying.
            //
            // NOTE: the on-connect eager reservation trigger was removed
            // 2026-07-16. It raced with libp2p 0.21's relay-client
            // handler installation: `listen_on(<relay>/p2p-circuit)`
            // synchronously enqueues a Reserve message via the transport
            // channel, but at connection-established time the
            // ConnectionHandler that would consume that message on the
            // relay's ConnectionId hasn't been installed yet, so the
            // message drops silently — no reservation event, no error,
            // no `NewListenAddr`. The IDENTIFY-time trigger (see the
            // `identify::Event::Received` handler) fires ~200 ms later
            // once the connection is fully set up and we've confirmed
            // the peer speaks HOP, which is when reservations actually
            // succeed.
            if num_established.get() == 1
                && let Some(tx) = state.peer_event_subscriber.as_ref()
                && tx.send(PeerEvent::Connected(peer_id)).is_err()
            {
                tracing::warn!(
                    "Peer-event subscriber dropped while sending Connected({}); detaching",
                    peer_id
                );
                state.peer_event_subscriber = None;
            }
        }
        SwarmEvent::ConnectionClosed {
            peer_id,
            cause,
            num_established,
            endpoint,
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

                // Mid-session recovery bookkeeping. When a non-bootstrap peer
                // fully drops, retain its last-known dial address so the
                // cleanup tick can re-dial it (under backoff) while the node
                // is below its peer-count floor. Bootstrap peers are skipped —
                // they have their own authoritative re-dial path from the
                // operator-configured ground truth. Peers reached only via an
                // inbound listener have no dial address we can re-use, so only
                // record dialer endpoints.
                let is_bootstrap = state
                    .bootstrap_peers
                    .iter()
                    .any(|(pid, _)| *pid == peer_id);
                if !is_bootstrap
                    && let libp2p::core::ConnectedPoint::Dialer { address, .. } = &endpoint
                {
                    state.peer_redial.insert(
                        peer_id,
                        (
                            address.clone(),
                            crate::discovery::ReconnectBackoff::default_schedule(),
                        ),
                    );
                }

                // Last physical connection dropped — fan out
                // `PeerEvent::Disconnected` so subscribers can evict this
                // peer from their candidate sets.
                if let Some(tx) = state.peer_event_subscriber.as_ref()
                    && tx.send(PeerEvent::Disconnected(peer_id)).is_err()
                {
                    tracing::warn!(
                        "Peer-event subscriber dropped while sending Disconnected({}); detaching",
                        peer_id
                    );
                    state.peer_event_subscriber = None;
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
        SwarmEvent::IncomingConnection { connection_id, send_back_addr, local_addr } => {
            tracing::debug!("Incoming connection from {} to {}", send_back_addr, local_addr);

            // Apply per-IP + global dial rate limiting to mitigate connection-flood DoS.
            // `check_dial_rate_limit` consults both a keyed IP limiter (10/min burst 5)
            // and a global limiter (200/min burst 20). If either denies, the pending
            // connection is torn down before the handshake completes.
            if let Some(ip) = extract_ip(&send_back_addr)
                && !state.peer_manager.check_dial_rate_limit(ip)
            {
                tracing::warn!("Dial rate-limit exceeded for IP {}; closing connection", ip);
                state.metrics.dials_rejected_per_ip.inc();
                state.swarm.close_connection(connection_id);
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
        SwarmEvent::NewExternalAddrCandidate { address } => {
            // libp2p emits this when a behaviour (typically Identify or
            // AutoNAT) surfaces an externally-observed address. We don't
            // auto-promote here — the observed_addr tally in the Identify
            // handler is what gates promotion. Logged for operator
            // observability.
            tracing::debug!(%address, "New external address candidate");
        }
        SwarmEvent::ExternalAddrConfirmed { address } => {
            tracing::info!(
                %address,
                "External address confirmed (AutoNAT probe-back succeeded)"
            );
            // Belt-and-braces: AutoNAT-confirmed addresses are reliable
            // reachability evidence. Make sure we also record it so the
            // observed_addr tally doesn't waste cycles re-counting.
            state.advertised_external_addrs.insert(address.clone());
            state.observed_addrs.remove(&address);
            // A confirmed direct external address is the strongest reachability
            // signal; fold it into the sustained verdict.
            state
                .reachability
                .record(crate::reachability::ReachabilityEvent::DirectConfirmed);
        }
        SwarmEvent::ExternalAddrExpired { address } => {
            tracing::info!(
                %address,
                "External address expired — stopping advertisement"
            );
            state.advertised_external_addrs.remove(&address);
            // Contrary evidence — decrements confidence rather than flipping
            // the tier, so a brief NAT-mapping lapse doesn't drop a stable node.
            state
                .reachability
                .record(crate::reachability::ReachabilityEvent::DirectLost);
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
                .dial(dial_opts_new_port(addr))
                .map_err(|e| NetworkError::Connection(e.to_string()));
            let _ = response.send(result);
        }
        NetworkCommand::SetValidatorRegistry { registry, response } => {
            state.peer_manager.set_validator_registry(registry);
            tracing::info!("Validator registry installed in peer manager");
            let _ = response.send(Ok(()));
        }
        NetworkCommand::SetBanStore { store, response } => {
            let hydrated = state.peer_manager.set_ban_store(store);
            let hydrated_count = hydrated.len();
            for peer_id in hydrated {
                state.swarm.behaviour_mut().block_peer(peer_id);
            }
            tracing::info!(
                bans_hydrated = hydrated_count,
                "Durable ban store installed in peer manager"
            );
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
            state.block_sync_request_subscriber_ever_attached = true;
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
        NetworkCommand::BroadcastToValidators { message, response } => {
            // Snapshot the validator set at send time. Per the
            // `ValidatorRegistry` trait contract, `validator_peer_ids()` is
            // a cheap clone of the current admitted-validator set.
            let result = match state.peer_manager.validator_registry() {
                None => Err(NetworkError::InvalidConfig(
                    "consensus-direct broadcast requires an installed ValidatorRegistry"
                        .to_string(),
                )),
                Some(registry) => {
                    let validator_set = registry.validator_peer_ids();
                    let local = *state.swarm.local_peer_id();
                    let request = ConsensusDirectRequest::Message(message);
                    let mut dispatched = 0usize;
                    for peer in validator_set.iter() {
                        if *peer == local {
                            // Skip self — consensus engine consumes its own
                            // outbound messages directly via the in-process
                            // channel, not over the wire.
                            continue;
                        }
                        let _request_id = state
                            .swarm
                            .behaviour_mut()
                            .consensus_direct
                            .send_request(peer, request.clone());
                        dispatched += 1;
                    }
                    Ok(dispatched)
                }
            };
            let _ = response.send(result);
        }
        NetworkCommand::SubscribeConsensusDirect { response } => {
            let (tx, rx) = mpsc::unbounded_channel();
            state.consensus_direct_subscriber = Some(tx);
            state.consensus_direct_subscriber_ever_attached = true;
            let _ = response.send(Ok(rx));
        }
        NetworkCommand::ConnectedValidatorCount { response } => {
            let count = match state.peer_manager.validator_registry() {
                None => 0,
                Some(registry) => {
                    let validator_set = registry.validator_peer_ids();
                    let local = *state.swarm.local_peer_id();
                    state
                        .swarm
                        .connected_peers()
                        .filter(|p| **p != local && validator_set.contains(*p))
                        .count()
                }
            };
            let _ = response.send(Ok(count));
        }
        NetworkCommand::SetMpcDidResolver { resolver, response } => {
            state.mpc_did_resolver = Some(resolver);
            let _ = response.send(Ok(()));
        }
        NetworkCommand::SendMpcRelayMessage { message, response } => {
            let result = match state.mpc_did_resolver.as_ref() {
                None => Err(NetworkError::InvalidConfig(
                    "mpc-relay send requires an installed MpcDidResolver".to_string(),
                )),
                Some(resolver) => match resolver.peer_id_for_did(&message.to_did) {
                    None => Err(NetworkError::PeerNotFound(message.to_did.clone())),
                    Some(peer) => {
                        let _req_id = state
                            .swarm
                            .behaviour_mut()
                            .mpc_relay
                            .send_request(&peer, message);
                        Ok(())
                    }
                },
            };
            let _ = response.send(result);
        }
        NetworkCommand::SubscribeMpcRelay { response } => {
            let (tx, rx) = mpsc::unbounded_channel();
            state.mpc_relay_subscriber = Some(tx);
            state.mpc_relay_subscriber_ever_attached = true;
            let _ = response.send(Ok(rx));
        }
        NetworkCommand::SendClusterTunnelFrame { peer, request, response } => {
            let request_id = state
                .swarm
                .behaviour_mut()
                .cluster_tunnel
                .send_request(&peer, request);
            let _ = response.send(Ok(request_id));
        }
        NetworkCommand::SendClusterTunnelResponse {
            request_id,
            response_payload,
            response,
        } => {
            let result = match state.pending_inbound_cluster_tunnel.remove(&request_id) {
                Some(channel) => state
                    .swarm
                    .behaviour_mut()
                    .cluster_tunnel
                    .send_response(channel, response_payload)
                    .map_err(|_| NetworkError::ChannelSend),
                None => Err(NetworkError::PeerNotFound(format!(
                    "no parked inbound cluster-tunnel frame for id {}",
                    request_id
                ))),
            };
            let _ = response.send(result);
        }
        NetworkCommand::SubscribeClusterTunnelRequests { response } => {
            let (tx, rx) = mpsc::unbounded_channel();
            state.cluster_tunnel_request_subscriber = Some(tx);
            state.cluster_tunnel_request_subscriber_ever_attached = true;
            let _ = response.send(Ok(rx));
        }
        NetworkCommand::SubscribeClusterTunnelResults { response } => {
            let (tx, rx) = mpsc::unbounded_channel();
            state.cluster_tunnel_result_subscriber = Some(tx);
            let _ = response.send(Ok(rx));
        }
        NetworkCommand::DaCommitteeRequest { peer, request, response } => {
            // Dispatch and park the caller's reply channel keyed by the
            // outbound request id. The event handler fulfils it when the peer
            // replies (or the request fails). No `response.send()` here — the
            // caller is awaiting the peer's actual `DaCommitteeResponse`.
            let request_id = state
                .swarm
                .behaviour_mut()
                .da_committee
                .send_request(&peer, request);
            state
                .pending_da_committee_requests
                .insert(request_id, response);
        }
        NetworkCommand::SendDaCommitteeResponse {
            request_id,
            response_payload,
            response,
        } => {
            let result = match state.pending_inbound_da_committee.remove(&request_id) {
                Some(channel) => state
                    .swarm
                    .behaviour_mut()
                    .da_committee
                    .send_response(channel, response_payload)
                    .map_err(|_| NetworkError::ChannelSend),
                None => Err(NetworkError::PeerNotFound(format!(
                    "no parked inbound committee-DA request for id {}",
                    request_id
                ))),
            };
            let _ = response.send(result);
        }
        NetworkCommand::SubscribeDaCommitteeRequests { response } => {
            let (tx, rx) = mpsc::unbounded_channel();
            state.da_committee_request_subscriber = Some(tx);
            state.da_committee_request_subscriber_ever_attached = true;
            let _ = response.send(Ok(rx));
        }
        NetworkCommand::DbReplicateRequest { peer, request, response } => {
            // Dispatch and park the caller's reply channel keyed by the
            // outbound request id. The event handler fulfils it when the peer
            // replies (or the request fails). No `response.send()` here — the
            // caller is awaiting the peer's actual `DbReplicateResponse`.
            let request_id = state
                .swarm
                .behaviour_mut()
                .db_replicate
                .send_request(&peer, request);
            state
                .pending_db_replicate_requests
                .insert(request_id, response);
        }
        NetworkCommand::SendDbReplicateResponse {
            request_id,
            response_payload,
            response,
        } => {
            let result = match state.pending_inbound_db_replicate.remove(&request_id) {
                Some(channel) => state
                    .swarm
                    .behaviour_mut()
                    .db_replicate
                    .send_response(channel, response_payload)
                    .map_err(|_| NetworkError::ChannelSend),
                None => Err(NetworkError::PeerNotFound(format!(
                    "no parked inbound db-replicate request for id {}",
                    request_id
                ))),
            };
            let _ = response.send(result);
        }
        NetworkCommand::SubscribeDbReplicateRequests { response } => {
            let (tx, rx) = mpsc::unbounded_channel();
            state.db_replicate_request_subscriber = Some(tx);
            state.db_replicate_request_subscriber_ever_attached = true;
            let _ = response.send(Ok(rx));
        }
        NetworkCommand::Shutdown { response } => {
            // Respond before the outer loop observes the Shutdown variant and breaks.
            let _ = response.send(Ok(()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ma(s: &str) -> Multiaddr {
        s.parse().expect("valid multiaddr")
    }

    #[test]
    fn extract_port_pulls_tcp_port() {
        assert_eq!(extract_port(&ma("/ip4/35.184.63.8/tcp/9000")), Some(9000));
    }

    #[test]
    fn extract_port_pulls_udp_port_for_quic() {
        assert_eq!(
            extract_port(&ma("/ip4/35.184.63.8/udp/9000/quic-v1")),
            Some(9000)
        );
    }

    #[test]
    fn extract_port_handles_p2p_suffix() {
        let m = ma("/ip4/10.0.0.5/tcp/9000/p2p/12D3KooWGgjoKhKXBvN6jFWqn5sJE6KD38bXtNaoE6itbRUjGBxK");
        assert_eq!(extract_port(&m), Some(9000));
    }

    #[test]
    fn observed_port_accepted_when_matches_listen() {
        // Wildcard listen on tcp/9000 — peer observes us at our public IP
        // on tcp/9000 (correct, dial-back-reachable address).
        let listen = vec![ma("/ip4/0.0.0.0/tcp/9000")];
        let observed = ma("/ip4/35.184.63.8/tcp/9000");
        assert!(is_observed_port_one_of_ours(&observed, &listen));
    }

    #[test]
    fn observed_port_rejected_when_ephemeral_source_port() {
        // The exact bug pattern: v0 listens on tcp/9000, dials a peer,
        // peer sees the connection coming from the NAT'd source port 39692
        // and reports `(public_ip, 39692)` in Identify. We must NOT
        // promote 39692 — nothing is listening there.
        let listen = vec![ma("/ip4/0.0.0.0/tcp/9000")];
        let observed = ma("/ip4/35.184.63.8/tcp/39692");
        assert!(!is_observed_port_one_of_ours(&observed, &listen));
    }

    #[test]
    fn observed_port_accepted_against_quic_listener() {
        // A QUIC listener on udp/9000 should accept a tcp/9000 observation
        // *iff* the ports match — `extract_port` is transport-agnostic on
        // the comparison key, which is what we want for a node that
        // simultaneously listens on both transports at the same port (the
        // tenzro-node universal default).
        let listen = vec![ma("/ip4/0.0.0.0/udp/9000/quic-v1")];
        let observed = ma("/ip4/35.184.63.8/tcp/9000");
        assert!(is_observed_port_one_of_ours(&observed, &listen));
    }

    #[test]
    fn observed_port_rejected_when_no_listeners() {
        let listen: Vec<Multiaddr> = vec![];
        let observed = ma("/ip4/35.184.63.8/tcp/9000");
        assert!(!is_observed_port_one_of_ours(&observed, &listen));
    }

    #[test]
    fn observed_port_rejected_when_no_port_in_observation() {
        // Pathological / malformed observation with no transport port —
        // can't match anything, must reject.
        let listen = vec![ma("/ip4/0.0.0.0/tcp/9000")];
        let observed = ma("/ip4/35.184.63.8");
        assert!(!is_observed_port_one_of_ours(&observed, &listen));
    }
}

