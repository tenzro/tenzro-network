//! Gossip wire format for cross-node TDIP revocation propagation.
//!
//! Topic: [`IDENTITY_TOPIC`] (`tenzro/identity`). Every node that holds an
//! [`IdentityRegistry`](crate::IdentityRegistry) subscribes; the local
//! `revoke()` path signs each [`SignedRevocationEntry`] with the node's
//! hybrid (Ed25519 + ML-DSA-65) validator key and broadcasts it, and
//! receivers apply the inbound entry via
//! [`apply_remote_revocation`](crate::IdentityRegistry::apply_remote_revocation),
//! which verifies both signature legs before mutating any state and is
//! idempotent for already-revoked identities.
//!
//! Topic discipline is enforced by [`decode_identity_for_topic`], which
//! rejects any payload arriving on a topic other than [`IDENTITY_TOPIC`].
//!
//! Per the project convention against version segments in tenzro-owned
//! identifiers, the topic name is `tenzro/identity`.

use serde::{Deserialize, Serialize};

use crate::error::{IdentityError, Result};
use crate::registry::SignedRevocationEntry;

/// Gossipsub topic carrying [`IdentityGossipMessage`] envelopes.
pub const IDENTITY_TOPIC: &str = "tenzro/identity";

/// Bincode-serialised envelope for cross-node identity state propagation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IdentityGossipMessage {
    /// A signed revocation entry produced by [`crate::IdentityRegistry::revoke`]
    /// on the originating node. Receivers verify both hybrid signature legs
    /// before applying.
    RevocationBroadcast(SignedRevocationEntry),
}

/// Bincode-encode an [`IdentityGossipMessage::RevocationBroadcast`] payload.
pub fn encode_revocation_broadcast(signed: &SignedRevocationEntry) -> Result<Vec<u8>> {
    let msg = IdentityGossipMessage::RevocationBroadcast(signed.clone());
    bincode::serialize(&msg)
        .map_err(|e| IdentityError::SerializationError(format!("encode RevocationBroadcast: {}", e)))
}

/// Decode an inbound gossip payload and reject any message that does not
/// match the topic it arrived on. Returns the typed variant on success.
pub fn decode_identity_for_topic(topic: &str, bytes: &[u8]) -> Result<IdentityGossipMessage> {
    if topic != IDENTITY_TOPIC {
        return Err(IdentityError::SerializationError(format!(
            "identity gossip payload arrived on unexpected topic '{}'",
            topic
        )));
    }
    bincode::deserialize(bytes).map_err(|e| {
        IdentityError::SerializationError(format!("decode IdentityGossipMessage: {}", e))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::RevocationEntry;
    use chrono::Utc;
    use tenzro_crypto::composite::InMemoryHybridSigner;
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_crypto::signatures::Ed25519SignerImpl;
    use tenzro_crypto::{KeyPair, KeyType};

    fn sample_signed_entry() -> SignedRevocationEntry {
        let kp = KeyPair::generate(KeyType::Ed25519).expect("keypair");
        let classical = Ed25519SignerImpl::new(kp).expect("signer");
        let signer = InMemoryHybridSigner::new(Box::new(classical), MlDsaSigningKey::generate());
        let entry = RevocationEntry {
            did: "did:tenzro:human:test".to_string(),
            revoked_at: Utc::now(),
            reason: "test".to_string(),
            revoked_by: "did:tenzro:system:tenzro-network".to_string(),
        };
        SignedRevocationEntry::sign(entry, &signer).expect("sign")
    }

    #[test]
    fn round_trip_revocation_broadcast() {
        let signed = sample_signed_entry();
        let bytes = encode_revocation_broadcast(&signed).expect("encode");
        let decoded = decode_identity_for_topic(IDENTITY_TOPIC, &bytes).expect("decode");
        let IdentityGossipMessage::RevocationBroadcast(inner) = decoded;
        assert_eq!(inner.entry.did, signed.entry.did);
        assert!(inner.verify().is_ok());
    }

    #[test]
    fn wrong_topic_rejected() {
        let signed = sample_signed_entry();
        let bytes = encode_revocation_broadcast(&signed).expect("encode");
        assert!(decode_identity_for_topic("tenzro/blocks", &bytes).is_err());
    }
}
