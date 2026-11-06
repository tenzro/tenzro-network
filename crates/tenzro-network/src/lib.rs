//! Gossip layer for Tenzro Network
//!
//! This crate provides the gossip messages, topics and validation for Tenzro
//! Network, an AI-Native, Agentic, Tokenized Settlement Layer blockchain.
//! Every topic is carried by iroh-gossip over the node's iroh endpoint
//! ([`gossip`]); finding peers, relays and point-to-point paths belongs to
//! `tenzro-iroh`.
//!
//! # Example
//!
//! ```no_run
//! use std::time::Duration;
//! use tenzro_network::{
//!     GossipLimits, MessagePayload, NetworkMessage, NetworkService, TenzroNetworkService,
//! };
//!
//! # async fn example() -> tenzro_network::Result<()> {
//! // A node takes these from the network's governed parameters.
//! let limits = GossipLimits {
//!     window: Duration::from_secs(10),
//!     consensus_messages: 20_000,
//!     general_messages: 50_000,
//!     ban: Duration::from_secs(300),
//! };
//! let network = TenzroNetworkService::new(limits).await?;
//!
//! // Subscribe to blocks
//! let mut blocks_rx = network.subscribe("tenzro/blocks").await?;
//!
//! // Broadcast a message
//! let message = NetworkMessage::new(MessagePayload::Ping);
//! network.broadcast("tenzro/status", message).await?;
//!
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
//! Gossip topics are named by the message types they carry, for example:
//!
//! - `tenzro/blocks` - Block propagation
//! - `tenzro/transactions` - Transaction propagation
//! - `tenzro/certificates` - Checkpoint certificates, for followers
//! - `tenzro/validators` - Validators' signed per-boot endpoint announcements
//! - `tenzro/models` - Model registrations
//! - `tenzro/status` - Status and discovery messages

pub mod error;
pub mod gossip;
pub mod gossip_validation;
pub mod message;
pub mod metrics;
pub mod peer_status;
pub mod service;

pub use error::{NetworkError, Result};
pub use gossip::NetworkGossip;
pub use gossip_validation::{
    CONSENSUS_TOPICS, GossipLimits, PeerIdentities, VALIDATORS_TOPIC, ValidatedMessage,
    ValidationTicket,
};
pub use message::{
    AnnouncementKind, BatchedAnnouncementMessage, BlobAnnouncementMessage, MessagePayload, ModelRegistrationMessage, ModelSchedule,
    NetworkMessage, ProviderAnnouncementMessage, ProviderHeartbeatMessage, ShardReplicationEntry,
    ShardReplicationMessage, SignedAnnouncement, StatusMessage,
};
pub use metrics::NetworkMetrics;
pub use peer_status::{DEFAULT_FRESHNESS, PeerStatus as PeerChainStatus, PeerStatusTracker};
pub use service::{NetworkService, TenzroNetworkService};

#[cfg(test)]
mod tests {
    use super::*;

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
        let limits = GossipLimits {
            window: std::time::Duration::from_secs(10),
            consensus_messages: 1_000,
            general_messages: 1_000,
            ban: std::time::Duration::from_secs(300),
        };
        assert!(TenzroNetworkService::new(limits).await.is_ok());
    }
}
