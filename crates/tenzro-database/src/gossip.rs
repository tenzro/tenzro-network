//! Gossip wire format for distributed-database registration and rescale events.
//!
//! One topic, [`DATABASES_TOPIC`] (`tenzro/databases`): when a node creates or
//! rescales a network-tier database it broadcasts the new descriptor so that
//! other nodes tracking the same owner or membership view can hydrate the same
//! placement without polling. Local- and LAN-tier databases stay off the topic —
//! they have no network holders to announce.
//!
//! The topic carries a single bincode-encoded [`DatabaseGossipMessage`]. The
//! enum is externally-tagged (serde default), the same encoding the rest of
//! `tenzro-network` uses for `MessagePayload`. The consumer-side helper
//! [`decode_for_topic`] rejects a payload that arrived on the wrong topic so the
//! event loop never has to know the wire format.

use serde::{Deserialize, Serialize};

use crate::database::DatabaseDescriptor;
use crate::error::{DatabaseError, Result};

/// Registration/rescale broadcast topic for network-tier databases.
pub const DATABASES_TOPIC: &str = "tenzro/databases";

/// Bincode-serialised envelope for the database gossip topic.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DatabaseGossipMessage {
    /// A newly-created network-tier database. Receivers upsert the descriptor
    /// into their registry idempotently — re-receiving a descriptor a node
    /// already holds is a no-op.
    Registered(DatabaseDescriptor),
    /// A rescaled network-tier database: partition/replica counts or placement
    /// mode changed. Carries the full post-rescale descriptor so receivers
    /// converge on the same shape without a diff.
    Rescaled(DatabaseDescriptor),
}

impl DatabaseGossipMessage {
    /// The descriptor this message carries, regardless of variant.
    pub fn descriptor(&self) -> &DatabaseDescriptor {
        match self {
            DatabaseGossipMessage::Registered(d) | DatabaseGossipMessage::Rescaled(d) => d,
        }
    }
}

/// Bincode-encode a `Registered` announcement for [`DATABASES_TOPIC`].
pub fn encode_registered(descriptor: &DatabaseDescriptor) -> Result<Vec<u8>> {
    let msg = DatabaseGossipMessage::Registered(descriptor.clone());
    bincode::serialize(&msg)
        .map_err(|e| DatabaseError::Persistence(format!("encode Registered: {}", e)))
}

/// Bincode-encode a `Rescaled` announcement for [`DATABASES_TOPIC`].
pub fn encode_rescaled(descriptor: &DatabaseDescriptor) -> Result<Vec<u8>> {
    let msg = DatabaseGossipMessage::Rescaled(descriptor.clone());
    bincode::serialize(&msg)
        .map_err(|e| DatabaseError::Persistence(format!("encode Rescaled: {}", e)))
}

/// Decode an inbound gossip payload, rejecting anything that did not arrive on
/// [`DATABASES_TOPIC`].
pub fn decode_for_topic(topic: &str, bytes: &[u8]) -> Result<DatabaseGossipMessage> {
    if topic != DATABASES_TOPIC {
        return Err(DatabaseError::InvalidRequest(format!(
            "unexpected database gossip topic '{}'",
            topic
        )));
    }
    bincode::deserialize(bytes)
        .map_err(|e| DatabaseError::Persistence(format!("decode gossip message: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_control::AccessPolicy;
    use crate::database::PlacementMode;

    fn sample_descriptor() -> DatabaseDescriptor {
        DatabaseDescriptor {
            database_id: "db-1".to_string(),
            engine_id: "postgres".to_string(),
            placement: PlacementMode::Network,
            partitions: 3,
            replicas: 2,
            engine_config: serde_json::json!({}),
            access_policy: AccessPolicy::OwnerOnly {
                owner_did: "did:tenzro:human:abc".to_string(),
            },
            pricing: crate::pricing::DatabasePricing::free(),
            confidential: None,
        }
    }

    #[test]
    fn registered_round_trips() {
        let desc = sample_descriptor();
        let bytes = encode_registered(&desc).unwrap();
        let decoded = decode_for_topic(DATABASES_TOPIC, &bytes).unwrap();
        match decoded {
            DatabaseGossipMessage::Registered(d) => assert_eq!(d, desc),
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn rescaled_round_trips() {
        let desc = sample_descriptor();
        let bytes = encode_rescaled(&desc).unwrap();
        let decoded = decode_for_topic(DATABASES_TOPIC, &bytes).unwrap();
        match decoded {
            DatabaseGossipMessage::Rescaled(d) => assert_eq!(d, desc),
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn wrong_topic_rejected() {
        let desc = sample_descriptor();
        let bytes = encode_registered(&desc).unwrap();
        assert!(decode_for_topic("tenzro/blocks", &bytes).is_err());
    }
}
