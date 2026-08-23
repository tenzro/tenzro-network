//! P2P networking layer for Tenzro Network
//!
//! This crate provides the networking infrastructure for Tenzro Network,
//! an AI-Native, Agentic, Tokenized Settlement Layer blockchain.
//!
//! # Overview
//!
//! The networking layer is built on libp2p and provides:
//!
//! - **Gossipsub**: Pub/sub messaging for blocks, transactions, and consensus
//! - **Kademlia DHT**: Peer discovery and routing
//! - **Identify**: Peer information exchange
//! - **Ping**: Connection health monitoring
//!
//! # Architecture
//!
//! The network service runs an event loop in a background task and communicates
//! with the rest of the node through async channels. This allows the networking
//! layer to be decoupled from the rest of the application.
//!
//! # Example
//!
//! ```no_run
//! use tenzro_network::{NetworkService, TenzroNetworkService, NetworkConfig, NetworkMessage, MessagePayload};
//!
//! # async fn example() -> tenzro_network::Result<()> {
//! // Create network service
//! let config = NetworkConfig::default();
//! let network = TenzroNetworkService::new(config).await?;
//!
//! // Subscribe to blocks
//! let mut blocks_rx = network.subscribe("tenzro/blocks").await?;
//!
//! // Broadcast a message
//! let message = NetworkMessage::new(MessagePayload::Ping);
//! network.broadcast("tenzro/status", message).await?;
//!
//! // Receive messages
//! tokio::spawn(async move {
//!     while let Some(msg) = blocks_rx.recv().await {
//!         println!("Received block message: {:?}", msg);
//!     }
//! });
//!
//! # Ok(())
//! # }
//! ```
//!
//! # Topics
//!
//! The network uses gossipsub topics for different message types:
//!
//! - `tenzro/blocks` - Block propagation
//! - `tenzro/transactions` - Transaction propagation
//! - `tenzro/consensus` - Consensus messages
//! - `tenzro/attestations` - TEE attestations
//! - `tenzro/models` - Model registrations
//! - `tenzro/inference` - Inference requests/responses
//! - `tenzro/status` - Status and discovery messages
//!
//! For testnet and mainnet, topics are prefixed accordingly:
//! - Testnet: `tenzro/testnet/blocks/1.0.0`
//! - Mainnet: `tenzro/mainnet/blocks/1.0.0`

pub mod behaviour;
pub mod block_sync_proto;
pub mod cluster_tunnel_proto;
pub mod config;
pub mod consensus_direct_proto;
pub mod da_committee_relay;
pub mod db_replicate_proto;
pub mod discovery;
pub mod error;
pub mod gossip;
pub mod message;
pub mod metrics;
pub mod mpc_relay;
pub mod node_delegation;
pub mod peer_binding;
pub mod peer_manager;
pub mod peer_status;
pub mod pq_announce;
pub mod reachability;
pub mod service;
pub mod transport;

// Re-export commonly used types
pub use behaviour::{TenzroBehaviour, TenzroNetwork};
pub use block_sync_proto::{
    BLOCK_SYNC_PROTOCOL, BlockSyncBehaviour, BlockSyncError, BlockSyncRequest, BlockSyncResponse,
    MAX_BLOCK_HASHES_PER_REQUEST, MAX_BLOCK_RANGE_BYTES, MAX_BLOCKS_PER_RANGE,
    MAX_INBOUND_STREAMS_PER_PEER,
    MAX_INFLIGHT_REQUESTS_PER_PEER,
};
pub use cluster_tunnel_proto::{
    CLUSTER_TUNNEL_PROTOCOL, ClusterTunnelBehaviour, ClusterTunnelError, ClusterTunnelRequest,
    ClusterTunnelResponse, MAX_FRAME_PAYLOAD,
    MAX_INBOUND_STREAMS_PER_PEER as TUNNEL_MAX_INBOUND_STREAMS_PER_PEER,
    MAX_INFLIGHT_FRAMES_PER_PEER, TunnelFrame, TunnelFrameKind,
};
pub use config::NetworkConfig;
pub use consensus_direct_proto::{
    CONSENSUS_DIRECT_PROTOCOL, ConsensusDirectBehaviour, ConsensusDirectError,
    ConsensusDirectRequest, ConsensusDirectResponse,
};
pub use da_committee_relay::{
    DA_COMMITTEE_PROTOCOL, DaCommitteeBehaviour, DaCommitteeError, DaCommitteeRequest,
    DaCommitteeResponse, MAX_INBOUND_STREAMS_PER_PEER as DA_COMMITTEE_MAX_INBOUND_STREAMS_PER_PEER,
    MAX_REQUEST_SIZE as DA_COMMITTEE_MAX_REQUEST_SIZE,
    MAX_RESPONSE_SIZE as DA_COMMITTEE_MAX_RESPONSE_SIZE,
    REQUEST_TIMEOUT as DA_COMMITTEE_REQUEST_TIMEOUT, WireMemberAttestation,
};
pub use db_replicate_proto::{
    DB_REPLICATE_PROTOCOL, DbReplicateBehaviour, DbReplicateError, DbReplicateRequest,
    DbReplicateResponse, MAX_INBOUND_STREAMS_PER_PEER as DB_REPLICATE_MAX_INBOUND_STREAMS_PER_PEER,
    MAX_REQUEST_SIZE as DB_REPLICATE_MAX_REQUEST_SIZE,
    MAX_RESPONSE_SIZE as DB_REPLICATE_MAX_RESPONSE_SIZE,
    REQUEST_TIMEOUT as DB_REPLICATE_REQUEST_TIMEOUT,
};
pub use discovery::{BootstrapConfig, DiscoveryConfig, ProviderType};
pub use error::{NetworkError, Result};
pub use gossip::{GossipTopics, MessageDeduplicator, MessageValidation, TopicSubscriptions};
pub use message::{
    AgentAnnouncementMessage, AttestationMessage, BlobAnnouncementMessage, ConsensusMessage,
    DatabaseAnnouncementMessage, InferenceRequestMessage, InferenceResponseMessage, MessagePayload,
    ModelRegistrationMessage, ModelSchedule, NetworkMessage, PaymentDetails, PricingInfo,
    ProviderAnnouncementMessage, ShardReplicationEntry, ShardReplicationMessage, StatusMessage,
    VoteType,
};
pub use metrics::NetworkMetrics;
pub use mpc_relay::{
    MPC_RELAY_GOSSIP_TOPIC_PREFIX, MPC_RELAY_PROTOCOL, MpcDidResolver, MpcRelayBehaviour,
    MpcRelayError, MpcRelayRequest, MpcRelayResponse, session_topic as mpc_session_topic,
};
pub use peer_binding::{
    AGENT_BINDING_PREFIX, PEER_BINDING_DOMAIN, binding_payload, encode_agent_binding,
    parse_agent_binding, verify_peer_binding,
};
pub use peer_manager::{
    BanStore, ManagedPeer, PeerManager, PeerManagerStats, VALIDATOR_ONLY_TOPICS, ValidatorRegistry,
};
pub use peer_status::{DEFAULT_FRESHNESS, PeerStatus as PeerChainStatus, PeerStatusTracker};
pub use reachability::{
    CONFIDENCE_THRESHOLD, LocalPeerSet, ReachabilityEvent, ReachabilityTier, ReachabilityTracker,
};
pub use service::{
    BlockSyncOutboundError, InboundBlockSync, InboundClusterTunnel, NetworkService,
    OutboundBlockSyncResult, OutboundClusterTunnelResult, PeerEvent, TenzroNetworkService,
    node_identity_keypair,
};

// Re-export libp2p types that are commonly used
pub use libp2p::request_response::{InboundRequestId, OutboundRequestId};
pub use libp2p::{Multiaddr, PeerId};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let config = NetworkConfig::default();
        assert!(config.validate().is_ok());

        let invalid_config = NetworkConfig {
            listen_addresses: vec![],
            ..Default::default()
        };
        assert!(invalid_config.validate().is_err());
    }

    #[test]
    fn test_message_serialization() {
        let msg = NetworkMessage::new(MessagePayload::Ping);
        let bytes = msg.to_bytes().unwrap();
        let decoded = NetworkMessage::from_bytes(&bytes).unwrap();

        assert_eq!(msg.message_id, decoded.message_id);
        assert_eq!(msg.timestamp, decoded.timestamp);
    }

    #[tokio::test]
    async fn test_network_service_creation() {
        let config = NetworkConfig::local();
        let result = TenzroNetworkService::new(config).await;
        assert!(result.is_ok());
    }
}
