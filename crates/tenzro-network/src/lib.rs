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
//! let config = NetworkConfig::testnet();
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
pub mod config;
pub mod consensus_direct_proto;
pub mod discovery;
pub mod error;
pub mod gossip;
pub mod message;
pub mod metrics;
pub mod mpc_relay;
pub mod peer_manager;
pub mod peer_status;
pub mod service;
pub mod transport;

// Re-export commonly used types
pub use behaviour::{TenzroBehaviour, TenzroNetwork};
pub use block_sync_proto::{
    BlockSyncBehaviour, BlockSyncError, BlockSyncRequest, BlockSyncResponse,
    BLOCK_SYNC_PROTOCOL, MAX_BLOCKS_PER_RANGE, MAX_BLOCK_HASHES_PER_REQUEST,
    MAX_INBOUND_STREAMS_PER_PEER, MAX_INFLIGHT_REQUESTS_PER_PEER,
};
pub use consensus_direct_proto::{
    ConsensusDirectBehaviour, ConsensusDirectError, ConsensusDirectRequest,
    ConsensusDirectResponse, CONSENSUS_DIRECT_PROTOCOL,
};
pub use mpc_relay::{
    session_topic as mpc_session_topic, MpcDidResolver, MpcRelayBehaviour, MpcRelayError,
    MpcRelayRequest, MpcRelayResponse, MPC_RELAY_GOSSIP_TOPIC_PREFIX, MPC_RELAY_PROTOCOL,
};
pub use config::NetworkConfig;
pub use discovery::{BootstrapConfig, DiscoveryConfig, ProviderType};
pub use error::{NetworkError, Result};
pub use gossip::{GossipTopics, MessageDeduplicator, MessageValidation, TopicSubscriptions};
pub use metrics::NetworkMetrics;
pub use message::{
    AgentAnnouncementMessage, AttestationMessage, ConsensusMessage, InferenceRequestMessage,
    InferenceResponseMessage, MessagePayload, ModelRegistrationMessage, ModelSchedule,
    NetworkMessage, PaymentDetails, PricingInfo, ProviderAnnouncementMessage, StatusMessage,
    VoteType,
};
pub use peer_manager::{ManagedPeer, PeerManager, PeerManagerStats, ValidatorRegistry, VALIDATOR_ONLY_TOPICS};
pub use peer_status::{PeerStatus as PeerChainStatus, PeerStatusTracker, DEFAULT_FRESHNESS};
pub use service::{
    BlockSyncOutboundError, InboundBlockSync, NetworkService, OutboundBlockSyncResult,
    PeerEvent, TenzroNetworkService,
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
