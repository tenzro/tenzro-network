//! Node-side bridge from the sync [`RevocationBroadcaster`] trait to the
//! async gossipsub publish path.
//!
//! [`IdentityRegistry::revoke`](tenzro_identity::IdentityRegistry::revoke)
//! calls `broadcast_revocation` synchronously while holding registry state,
//! so the broadcaster cannot await the network directly. Instead it pushes
//! each [`SignedRevocationEntry`] onto an unbounded channel; a forwarder
//! task (spawned with the node's network handle) encodes the entry into an
//! [`IdentityGossipMessage`](tenzro_identity::IdentityGossipMessage)
//! envelope and publishes it on `tenzro/identity`. Same decoupling pattern
//! as the SeedAgent gossip channel.
//!
//! Receivers consume the topic via the node's subscribe bridge and apply
//! entries through
//! [`IdentityRegistry::apply_remote_revocation`](tenzro_identity::IdentityRegistry::apply_remote_revocation),
//! which verifies both hybrid signature legs before mutating state.

use std::sync::Arc;

use tenzro_identity::IdentityError;
use tenzro_identity::gossip::{IDENTITY_TOPIC, encode_revocation_broadcast};
use tenzro_identity::registry::{RevocationBroadcaster, SignedRevocationEntry};
use tenzro_network::{MessagePayload, NetworkMessage, NetworkService, TenzroNetworkService};

/// Channel-backed [`RevocationBroadcaster`] whose forwarder task publishes
/// signed revocation entries on the `tenzro/identity` gossipsub topic.
pub struct GossipRevocationBroadcaster {
    tx: tokio::sync::mpsc::UnboundedSender<SignedRevocationEntry>,
}

impl GossipRevocationBroadcaster {
    /// Creates the broadcaster and spawns its forwarder task on the given
    /// network handle. Publish failures are logged and dropped — the local
    /// revocation is authoritative for this node regardless of fan-out.
    pub fn spawn(network: Arc<TenzroNetworkService>) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<SignedRevocationEntry>();
        tokio::spawn(async move {
            while let Some(signed) = rx.recv().await {
                let bytes = match encode_revocation_broadcast(&signed) {
                    Ok(b) => b,
                    Err(e) => {
                        tracing::warn!(
                            did = %signed.entry.did,
                            error = %e,
                            "Failed to encode revocation broadcast envelope"
                        );
                        continue;
                    }
                };
                let net_msg = NetworkMessage::new(MessagePayload::Custom {
                    topic: IDENTITY_TOPIC.to_string(),
                    data: bytes,
                });
                if let Err(e) = network.broadcast(IDENTITY_TOPIC, net_msg).await {
                    tracing::warn!(
                        did = %signed.entry.did,
                        error = %e,
                        "Failed to broadcast revocation on tenzro/identity"
                    );
                }
            }
        });
        Self { tx }
    }
}

impl RevocationBroadcaster for GossipRevocationBroadcaster {
    fn broadcast_revocation(&self, entry: &SignedRevocationEntry) -> tenzro_identity::Result<()> {
        self.tx.send(entry.clone()).map_err(|e| {
            IdentityError::BroadcastError(format!("revocation gossip forwarder unavailable: {}", e))
        })
    }
}
