//! Gossip wire format for distributed-database registration and rescale events.
//!
//! One topic, [`DATABASES_TOPIC`] (`tenzro/databases`): when a node creates or
//! rescales a network-tier database it broadcasts the new descriptor so that
//! other nodes tracking the same owner or membership view can hydrate the same
//! placement without polling. Local- and LAN-tier databases stay off the topic —
//! they have no network holders to announce.
//!
//! The topic carries a single JSON-encoded [`DatabaseGossipMessage`], matching
//! how [`DatabaseDescriptor`] is already persisted in `database.rs`.
//!
//! JSON rather than bincode because the descriptor is not encodable by a
//! non-self-describing format, and encoding it with one fails on *decode*
//! rather than encode — so it looks fine until a peer tries to read it:
//!
//! - [`tenzro_types::access_policy::AccessPolicy`] is an internally-tagged enum
//!   (`#[serde(tag = "kind")]`). Serde has to buffer the content to find the tag,
//!   which means `deserialize_any`, which bincode refuses.
//! - `confidential` is `#[serde(skip_serializing_if = "Option::is_none")]`, so
//!   the field is omitted when absent while the derived `Deserialize` still
//!   expects it — a field-count desync in any fixed-layout format.
//! - `engine_config` is a `serde_json::Value`, whose shape is only knowable from
//!   the data, so it too needs `deserialize_any`.
//!
//! Those are properties of the descriptor, not of this module, and the rest of
//! the crate already treats it as a JSON-shaped type. The consumer-side helper
//! [`decode_for_topic`] rejects a payload that arrived on the wrong topic so the
//! event loop never has to know the wire format.

use serde::{Deserialize, Serialize};

use crate::database::DatabaseDescriptor;
use crate::error::{DatabaseError, Result};

/// Registration/rescale broadcast topic for network-tier databases.
pub const DATABASES_TOPIC: &str = "tenzro/databases";

/// JSON-serialised envelope for the database gossip topic.
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

/// JSON-encode a `Registered` announcement for [`DATABASES_TOPIC`].
pub fn encode_registered(descriptor: &DatabaseDescriptor) -> Result<Vec<u8>> {
    let msg = DatabaseGossipMessage::Registered(descriptor.clone());
    serde_json::to_vec(&msg)
        .map_err(|e| DatabaseError::Persistence(format!("encode Registered: {}", e)))
}

/// JSON-encode a `Rescaled` announcement for [`DATABASES_TOPIC`].
pub fn encode_rescaled(descriptor: &DatabaseDescriptor) -> Result<Vec<u8>> {
    let msg = DatabaseGossipMessage::Rescaled(descriptor.clone());
    serde_json::to_vec(&msg)
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
    serde_json::from_slice(bytes)
        .map_err(|e| DatabaseError::Persistence(format!("decode gossip message: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_control::AccessPolicy;
    use crate::database::{PlacementMode, ReplicationPolicy};

    fn sample_descriptor() -> DatabaseDescriptor {
        DatabaseDescriptor {
            database_id: "db-1".to_string(),
            engine_id: "postgres".to_string(),
            placement: PlacementMode::Network,
            partitions: 3,
            replication: ReplicationPolicy::default(),
            engine_config: serde_json::json!({}),
            access_policy: AccessPolicy::OwnerOnly {
                owner_did: "did:tenzro:human:abc".to_string(),
            },
            pricing: crate::pricing::DatabasePricing::free(),
            access: tenzro_types::resource_access::ResourceAccess::Private,
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
