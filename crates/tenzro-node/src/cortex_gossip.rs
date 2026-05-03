//! libp2p gossipsub adapter for the Cortex advertisement pipeline.
//!
//! `tenzro-cortex` defines an abstract [`CortexGossipPublisher`] trait so the
//! core cortex crate does not depend on any particular networking stack. This
//! module wires that trait to the node's real libp2p-backed
//! [`NetworkService`] so signed [`tenzro_cortex::CortexAdvertisement`]
//! payloads broadcast over the `tenzro/cortex/1.0.0` gossipsub topic reach
//! every peer in the mesh.
//!
//! The wire format mirrors the existing direct-message channel: the raw
//! `CortexAdvertisement` bytes (bincode-serialized by the cortex crate) are
//! wrapped in a [`MessagePayload::Custom`] envelope so downstream consumers
//! can inspect both the topic and the opaque binary body without any
//! cortex-specific knowledge on the networking side.
//!
//! Publish errors are reported via `CortexError::Other` — the cortex crate
//! intentionally does not depend on `tenzro-network`, so richer error types
//! would require a circular dependency.

use async_trait::async_trait;
use std::sync::Arc;

use tenzro_cortex::{
    error::{CortexError, Result as CortexResult},
    CortexGossipPublisher,
};
use tenzro_network::{MessagePayload, NetworkMessage, NetworkService};

/// Adapter that forwards Cortex gossip publishes through the node's libp2p
/// `NetworkService`.
///
/// Construct one per node after `TenzroNetworkService` has been started, then
/// hand it to an [`tenzro_cortex::AdvertisementBroadcaster`] as an
/// `Arc<dyn CortexGossipPublisher>`.
pub struct NetworkCortexPublisher {
    network: Arc<dyn NetworkService>,
}

impl NetworkCortexPublisher {
    /// Wrap an existing `NetworkService` handle.
    pub fn new(network: Arc<dyn NetworkService>) -> Self {
        Self { network }
    }
}

#[async_trait]
impl CortexGossipPublisher for NetworkCortexPublisher {
    async fn publish(&self, topic: &str, payload: Vec<u8>) -> CortexResult<()> {
        let message = NetworkMessage::new(MessagePayload::Custom {
            topic: topic.to_string(),
            data: payload,
        });
        self.network
            .broadcast(topic, message)
            .await
            .map_err(|e| CortexError::Other(format!("cortex gossipsub publish failed: {e}")))
    }
}
