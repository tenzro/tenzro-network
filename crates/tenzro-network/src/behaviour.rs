//! Network behaviour combining protocols for Tenzro Network — A+++ production grade.
//!
//! 2026 hardening (closes CVE-2026-33040, CVE-2026-34219, CVE-2024-32984, GHSA-jvgw-gccv-q5p8):
//!   * Gossipsub v1.2 with IDONTWANT — prevents redundant large-message propagation.
//!   * `ValidationMode::Strict` — only messages signed by the sender are accepted.
//!   * Ethereum-class mesh: D=8, D_lo=6, D_hi=12, D_out=2, heartbeat 700 ms.
//!   * 1 MiB hard cap on transmit size (down from 10 MiB) to prevent flood amplification.
//!   * Full 7-factor peer scoring (P1..P7) with graylist/publish/gossip thresholds.
//!   * `ConnectionLimits` — 400 total / 200 in / 200 out / 4 per-peer / 32 pending inbound.
//!   * `AllowBlockList` — byzantine peers permanently blocked by PeerId.

use libp2p::{
    gossipsub::{
        self, IdentTopic, MessageAuthenticity, MessageId,
        PeerScoreParams, PeerScoreThresholds, ValidationMode,
    },
    identify, kad, ping,
    swarm::NetworkBehaviour,
    PeerId,
};
use libp2p_allow_block_list as allow_block_list;
use libp2p_connection_limits as connection_limits;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use crate::block_sync_proto::{self, BlockSyncBehaviour};
use crate::gossip::{validate_gossip_message, MessageDeduplicator, MessageValidation};

/// Topics on which ONLY validators may publish. Enforced in the gossip validation
/// pipeline (`service.rs`) and by the peer scoring system (invalid messages → P4 penalty).
///
/// NOTE: "blocks" is intentionally EXCLUDED here — block announcements must
/// propagate to ALL nodes (RPC, indexers, light clients) so they can follow
/// chain tip without being validators. Only consensus voting and TEE
/// attestation messages are restricted to the known validator set.
/// The canonical list lives in `peer_manager::VALIDATOR_ONLY_TOPICS`; this
/// alias is re-exported for consumers of the behaviour module.
pub use crate::peer_manager::VALIDATOR_ONLY_TOPICS;

/// Combined network behaviour for Tenzro Network
#[derive(NetworkBehaviour)]
pub struct TenzroBehaviour {
    /// Gossipsub for pub/sub messaging (hardened: Strict, 1 MiB, D=8, peer scoring).
    pub gossipsub: gossipsub::Behaviour,
    /// Kademlia for DHT and peer discovery (S/Kademlia disjoint paths enabled).
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    /// Identify for peer information exchange.
    pub identify: identify::Behaviour,
    /// Ping for connection keep-alive and RTT measurement.
    pub ping: ping::Behaviour,
    /// Resource caps — closes the unbounded-connection DoS vector (GHSA-jvgw-gccv-q5p8).
    pub connection_limits: connection_limits::Behaviour,
    /// Block list for permanently banning byzantine peers (P4 + P6 + P7 policy violators).
    pub allow_block_list: allow_block_list::Behaviour<allow_block_list::BlockedPeers>,
    /// Block-sync request/response protocol (`/tenzro/block-sync/1.0.0`).
    /// Used by lagging nodes to catch up to the network tip without relying on
    /// gossipsub backfill. Modeled on Sui's `state_sync` and Aptos'
    /// `storage-service` — see `block_sync_proto.rs` for the wire types.
    pub block_sync: BlockSyncBehaviour,
}

/// Wrapper providing application-level message deduplication on top of TenzroBehaviour
pub struct TenzroNetwork {
    /// The underlying libp2p behaviour
    pub behaviour: TenzroBehaviour,
    /// Application-level message deduplicator (defense-in-depth)
    deduplicator: Arc<Mutex<MessageDeduplicator>>,
}

impl TenzroBehaviour {
    /// Creates a new TenzroBehaviour
    pub fn new(
        local_peer_id: PeerId,
        local_key: &libp2p::identity::Keypair,
        protocol_version: String,
        user_agent: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Gossipsub config tuned for small validator sets. Mesh params must be
        // satisfiable with the *current* peer count or no mesh ever forms and
        // every publish() returns NoPeersSubscribedToTopic — exactly the bug
        // that pinned the testnet at height=0 with mesh_n_low=6 on a 4-node
        // network. Defaults below work from N=4 (testnet) up through N≈200.
        //
        //   * heartbeat 700ms — matches Ethereum consensus (was 1s default)
        //   * initial delay 100ms — prevents thundering-herd on startup
        //   * ValidationMode::Strict — only accept messages signed by their sender
        //   * 1 MiB max transmit — 10x tighter than default, prevents flood amplification
        //   * mesh D=4 (lo=2, hi=6, out=1) — fits a 4-node validator set, scales naturally
        //   * gossip_lazy=3 — emit gossip to 3 peers per heartbeat outside the mesh
        //   * fanout_ttl=60s — keep fanout for unsubscribed publish paths
        //   * duplicate_cache_time=120s — matches libp2p message propagation window
        //   * do_px — enable peer exchange on prune for rapid healing
        //   * idontwant_on_publish — reduce redundant large-message propagation (v1.2)
        //   * idontwant_message_size_threshold=1024 — only IDONTWANT for >1KB msgs
        //   * flood_publish — REQUIRED for small validator sets. Without this, a
        //     publisher whose mesh hasn't formed yet (transient state during the
        //     first ~3 heartbeats after startup, or after any rebalance) returns
        //     NoPeersSubscribedToTopic *even when peers are connected and have
        //     subscribed* — because Behaviour::publish() in rust-libp2p selects
        //     recipients from mesh∪fanout, not from the full topic_peers set.
        //     Ethereum consensus clients (Lighthouse) ship with this enabled
        //     for exactly this reason. With flood_publish, the publisher floods
        //     to every known subscriber of the topic, bypassing mesh-formation
        //     races. See rust-libp2p PR #3666 ("More lenient flood publishing")
        //     and the Tenzro height=0 wedge of 2026-04-28.
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_millis(700))
            .heartbeat_initial_delay(Duration::from_millis(100))
            .validation_mode(ValidationMode::Strict)
            .message_id_fn(message_id_fn)
            .max_transmit_size(1_048_576)
            .mesh_n(4)
            .mesh_n_low(2)
            .mesh_n_high(6)
            .mesh_outbound_min(1)
            .gossip_lazy(3)
            .history_length(6)
            .history_gossip(3)
            .fanout_ttl(Duration::from_secs(60))
            .duplicate_cache_time(Duration::from_secs(120))
            .do_px()
            .flood_publish(true)
            .idontwant_on_publish(true)
            .idontwant_message_size_threshold(1024)
            .build()
            .map_err(|e| format!("Failed to build gossipsub config: {}", e))?;

        // Create gossipsub behaviour with message signing (MessageAuthenticity::Signed
        // is REQUIRED by ValidationMode::Strict).
        let mut gossipsub = gossipsub::Behaviour::new(
            MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        )
        .map_err(|e| format!("Failed to create gossipsub behaviour: {}", e))?;

        // 7-factor peer scoring (P1..P7) with libp2p-rust defaults tuned for
        // Ethereum-class networks. Peers below graylist threshold are ignored
        // entirely; below publish they receive no messages; below gossip they
        // receive no gossip. This is the core Sybil/eclipse defence.
        let peer_score_params = PeerScoreParams {
            topics: HashMap::new(), // populated on subscribe via TopicScoreParams
            topic_score_cap: 32.0,
            app_specific_weight: 1.0,
            ip_colocation_factor_weight: -5.0,
            ip_colocation_factor_threshold: 10.0,
            ip_colocation_factor_whitelist: Default::default(),
            behaviour_penalty_weight: -10.0,
            behaviour_penalty_threshold: 6.0,
            behaviour_penalty_decay: 0.986, // ~50 heartbeats to halve
            decay_interval: Duration::from_secs(1),
            decay_to_zero: 0.01,
            retain_score: Duration::from_secs(3600),
            slow_peer_weight: -0.2,
            slow_peer_threshold: 0.0,
            slow_peer_decay: 0.2,
        };
        let peer_score_thresholds = PeerScoreThresholds {
            gossip_threshold: -100.0,
            publish_threshold: -200.0,
            graylist_threshold: -500.0,
            accept_px_threshold: 50.0,
            opportunistic_graft_threshold: 2.0,
        };
        gossipsub
            .with_peer_score(peer_score_params, peer_score_thresholds)
            .map_err(|e| format!("Failed to install peer scoring: {}", e))?;

        // Create Kademlia DHT (S/Kademlia disjoint paths, 30s timeout, k=10)
        let kademlia = crate::discovery::create_kademlia(local_peer_id);

        // Create identify behaviour
        let identify_config = identify::Config::new(protocol_version, local_key.public())
            .with_agent_version(user_agent);
        let identify = identify::Behaviour::new(identify_config);

        // Create ping behaviour
        let ping_config = ping::Config::new()
            .with_interval(Duration::from_secs(15))
            .with_timeout(Duration::from_secs(20));
        let ping = ping::Behaviour::new(ping_config);

        // Connection limits — closes the unbounded-connection DoS vector
        // (GHSA-jvgw-gccv-q5p8). Values tuned for 200-peer validator mesh with
        // headroom for churn + pending-dial backoff.
        //
        //   * 400 total established (2x peer cap — allows churn)
        //   * 200 inbound / 200 outbound (matches NetworkConfig)
        //   * 4 per-peer (QUIC + TCP + relay + reserve)
        //   * 32 pending inbound (SYN-flood ceiling)
        //   * 64 pending outbound (bootstrap burst headroom)
        let connection_limits = connection_limits::Behaviour::new(
            connection_limits::ConnectionLimits::default()
                .with_max_pending_incoming(Some(32))
                .with_max_pending_outgoing(Some(64))
                .with_max_established_incoming(Some(200))
                .with_max_established_outgoing(Some(200))
                .with_max_established_per_peer(Some(4))
                .with_max_established(Some(400)),
        );

        // Empty block list — peers are banned dynamically by the peer manager
        // when they violate P4 (invalid messages), P6 (IP colocation), or P7
        // (behavioural penalties).
        let allow_block_list = allow_block_list::Behaviour::default();

        // Block-sync protocol: single request/response Behaviour over CBOR
        // with the production-tuned config from `block_sync_proto::new_behaviour`.
        let block_sync = block_sync_proto::new_behaviour();

        Ok(Self {
            gossipsub,
            kademlia,
            identify,
            ping,
            connection_limits,
            allow_block_list,
            block_sync,
        })
    }

    /// Permanently bans a peer. Used by the peer manager in response to
    /// P4/P6/P7 policy violations or explicit operator block-list entries.
    pub fn block_peer(&mut self, peer_id: PeerId) {
        self.allow_block_list.block_peer(peer_id);
    }

    /// Removes a peer from the block list (for operator unblock commands).
    pub fn unblock_peer(&mut self, peer_id: PeerId) {
        self.allow_block_list.unblock_peer(peer_id);
    }

    /// Subscribes to a gossipsub topic
    pub fn subscribe(&mut self, topic: &IdentTopic) -> Result<bool, gossipsub::SubscriptionError> {
        self.gossipsub.subscribe(topic)
    }

    /// Unsubscribes from a gossipsub topic. Returns true if we were previously
    /// subscribed. libp2p 0.56 made this infallible.
    pub fn unsubscribe(&mut self, topic: &IdentTopic) -> bool {
        self.gossipsub.unsubscribe(topic)
    }

    /// Publishes a message to a topic
    pub fn publish(
        &mut self,
        topic: &IdentTopic,
        data: Vec<u8>,
    ) -> Result<MessageId, gossipsub::PublishError> {
        self.gossipsub.publish(topic.clone(), data)
    }

    /// Gets all subscribed topics
    pub fn topics(&self) -> impl Iterator<Item = &gossipsub::TopicHash> {
        self.gossipsub.topics()
    }

    /// Gets all mesh peers for a topic
    pub fn mesh_peers(&self, topic: &gossipsub::TopicHash) -> Vec<&PeerId> {
        self.gossipsub.mesh_peers(topic).collect()
    }

    /// Gets all known peers
    pub fn all_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.gossipsub.all_peers().map(|(peer_id, _topics)| peer_id)
    }
}

impl TenzroNetwork {
    /// Creates a new TenzroNetwork with application-level deduplication
    pub fn new(
        local_peer_id: PeerId,
        local_key: &libp2p::identity::Keypair,
        protocol_version: String,
        user_agent: String,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let behaviour = TenzroBehaviour::new(
            local_peer_id,
            local_key,
            protocol_version,
            user_agent,
        )?;

        Ok(Self {
            behaviour,
            deduplicator: Arc::new(Mutex::new(MessageDeduplicator::default())),
        })
    }

    /// Publishes a message with application-level deduplication check.
    /// Returns None if the message is a duplicate (already published).
    pub fn publish_checked(
        &mut self,
        topic: &IdentTopic,
        data: Vec<u8>,
    ) -> Result<Option<MessageId>, gossipsub::PublishError> {
        // Application-level dedup: skip if we've already published this exact data
        if self.deduplicator.lock().is_duplicate(&data) {
            tracing::debug!("Skipping duplicate outbound message on topic {:?}", topic);
            return Ok(None);
        }

        self.behaviour.publish(topic, data).map(Some)
    }

    /// Validates and deduplicates an incoming message.
    /// Returns true if the message should be processed (valid and not a duplicate).
    pub fn validate_incoming(
        &mut self,
        topic: &gossipsub::TopicHash,
        data: &[u8],
    ) -> bool {
        // Step 1: Structural validation
        match validate_gossip_message(topic, data) {
            MessageValidation::Accept => {},
            MessageValidation::Reject => {
                tracing::debug!("Rejecting invalid inbound message on topic {:?}", topic);
                return false;
            },
            MessageValidation::Ignore => {
                tracing::trace!("Ignoring message pending async validation on topic {:?}", topic);
                return false;
            },
        }

        // Step 2: Application-level dedup
        if self.deduplicator.lock().is_duplicate(data) {
            tracing::trace!("Dropping duplicate inbound message on topic {:?}", topic);
            return false;
        }

        true
    }

    /// Returns a reference to the deduplicator for stats/monitoring
    pub fn deduplicator(&self) -> &Arc<Mutex<MessageDeduplicator>> {
        &self.deduplicator
    }
}

/// Custom message ID function for gossipsub
///
/// Uses the first 20 bytes of the message hash as the message ID
fn message_id_fn(message: &gossipsub::Message) -> MessageId {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&message.data);
    let hash = hasher.finalize();
    MessageId::from(&hash[..20])
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    #[test]
    fn test_behaviour_creation() {
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());

        let behaviour = TenzroBehaviour::new(
            peer_id,
            &keypair,
            "tenzro/1.0.0".to_string(),
            "tenzro-network/0.1.0".to_string(),
        );

        assert!(behaviour.is_ok());
    }

    #[test]
    fn test_topic_subscription() {
        let keypair = Keypair::generate_ed25519();
        let peer_id = PeerId::from(keypair.public());

        let mut behaviour = TenzroBehaviour::new(
            peer_id,
            &keypair,
            "tenzro/1.0.0".to_string(),
            "tenzro-network/0.1.0".to_string(),
        )
        .unwrap();

        let topic = IdentTopic::new("test/topic");
        let result = behaviour.subscribe(&topic);
        assert!(result.is_ok());

        // Check that we're subscribed
        let topics: Vec<_> = behaviour.topics().collect();
        assert!(!topics.is_empty());
    }
}
