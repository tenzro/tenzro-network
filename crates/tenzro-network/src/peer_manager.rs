//! Peer tracking and reputation management for Tenzro Network
//!
//! This module implements comprehensive peer management including:
//!
//! - **Reputation scoring**: Peers earn reputation from +100 to -100 based on behavior
//! - **Rate limiting**: Per-peer sliding window rate limiting (default: 100 msgs/10s)
//! - **Automatic banning**: Peers are auto-banned when reputation drops below -50
//! - **Ban management**: Configurable ban duration (default: 1 hour) with automatic expiry
//! - **Connection tracking**: Failed connection attempts trigger auto-banning after 5 failures
//!
//! Rate limiting is implemented using a sliding window approach with timestamps stored
//! in a VecDeque. The `check_rate_limit()` method should be called for each incoming
//! message to enforce limits.

use dashmap::{DashMap, DashSet};
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use libp2p::PeerId;
use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tenzro_types::network::{NetworkRole, PeerStatus};

/// Type alias for a keyed rate limiter over IP addresses.
/// Each IP gets its own token bucket; eviction is handled by governor internally.
type IpRateLimiter = RateLimiter<IpAddr, dashmap::DashMap<IpAddr, governor::state::InMemoryState>, DefaultClock>;

/// Type alias for a global (non-keyed) rate limiter.
type GlobalRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock>;

/// Trait for checking validator set membership.
///
/// Implemented by the node to provide the network layer with access to the
/// current validator set without creating a circular dependency on tenzro-consensus.
pub trait ValidatorRegistry: Send + Sync {
    /// Returns true if the given PeerId is a known, active validator.
    fn is_validator(&self, peer_id: &PeerId) -> bool;

    /// Returns the set of all active validator PeerIds.
    fn validator_peer_ids(&self) -> HashSet<PeerId>;

    /// Attempt to dynamically register this peer as a validator after the
    /// identify handshake has confirmed it speaks a trusted Tenzro protocol.
    ///
    /// Default implementation: no-op. The node-level registry overrides this
    /// to admit peers so that long-running validator topics (consensus,
    /// attestations) don't cause mutual peer-score decay & gossipsub bans
    /// when a new validator joins after the boot set has been wired.
    fn try_add_validator(&self, _peer_id: &PeerId) {}
}

/// Topics that require validator authorization for message publishing.
/// Non-validators can subscribe and receive these topics (light clients)
/// but cannot publish to them.
/// NOTE: "blocks" is intentionally excluded — block announcements must propagate
/// to ALL nodes including RPC nodes and nodes not yet in the local validator registry.
/// Only consensus voting and attestation messages are restricted to known validators.
pub const VALIDATOR_ONLY_TOPICS: &[&str] = &[
    "consensus",
    "attestations",
];

/// Peer information tracked by the manager
#[derive(Debug, Clone)]
pub struct ManagedPeer {
    /// Peer ID
    pub peer_id: PeerId,
    /// Peer role
    pub role: Option<NetworkRole>,
    /// Reputation score (-100 to 100)
    pub reputation: i32,
    /// Connection status
    pub status: PeerStatus,
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Number of failed connections
    pub failed_connections: u32,
    /// Ban expiration time (if banned)
    pub ban_until: Option<Instant>,
    /// Protocol version
    pub protocol_version: Option<String>,
    /// Message timestamps for rate limiting (sliding window)
    pub message_timestamps: VecDeque<Instant>,
}

impl ManagedPeer {
    /// Creates a new peer entry
    pub fn new(peer_id: PeerId) -> Self {
        Self {
            peer_id,
            role: None,
            reputation: 0,
            status: PeerStatus::Disconnected,
            last_seen: Instant::now(),
            failed_connections: 0,
            ban_until: None,
            protocol_version: None,
            message_timestamps: VecDeque::new(),
        }
    }

    /// Checks if the peer is banned
    pub fn is_banned(&self) -> bool {
        if let Some(until) = self.ban_until {
            Instant::now() < until
        } else {
            false
        }
    }

    /// Increases reputation
    pub fn increase_reputation(&mut self, amount: i32) {
        self.reputation = (self.reputation + amount).min(100);
    }

    /// Decreases reputation
    pub fn decrease_reputation(&mut self, amount: i32) {
        self.reputation = (self.reputation - amount).max(-100);
    }

    /// Updates last seen time
    pub fn update_last_seen(&mut self) {
        self.last_seen = Instant::now();
    }
}

/// Peer manager for tracking and managing peers
pub struct PeerManager {
    /// Map of peer ID to peer info
    peers: DashMap<PeerId, ManagedPeer>,
    /// Maximum allowed peers
    max_peers: usize,
    /// Ban duration for misbehaving peers
    ban_duration: Duration,
    /// Reputation threshold for banning
    ban_threshold: i32,
    /// Maximum messages per peer per rate limit window
    rate_limit_max_messages: u32,
    /// Rate limit sliding window duration
    rate_limit_window: Duration,
    /// Optional validator registry for peer authorization
    validator_registry: Option<Arc<dyn ValidatorRegistry>>,
    /// Boot-node peers that should never be banned.
    /// These are critical infrastructure peers (e.g., boot nodes from --boot-nodes CLI).
    /// They may trigger rate limits due to high block production rates, but banning them
    /// would isolate the node from the network entirely.
    /// Peers protected from auto-ban. Boot nodes are added at startup; any
    /// peer that completes a libp2p Identify handshake announcing a
    /// `tenzro/` protocol is promoted here, so cluster validators can never
    /// ban each other via reputation decay or rate-limit penalties.
    ///
    /// Stored as a lock-free `DashSet` so Identify-time promotion can mutate
    /// it from the `&self` swarm event path (see
    /// `try_register_validator_on_identify`).
    protected_peers: DashSet<PeerId>,
    /// Per-IP dial rate limiter (Sybil / eclipse attack defence).
    ///
    /// Limits inbound dial attempts from a single IP to prevent an attacker
    /// from consuming all 32 pending-inbound slots by repeatedly reconnecting.
    /// Default quota: 10 dials/minute per IP with burst of 5.
    ip_dial_limiter: Arc<IpRateLimiter>,
    /// Global dial rate limiter — protects against aggregate dial floods.
    /// Default: 200 dials/minute with burst of 20.
    global_dial_limiter: Arc<GlobalRateLimiter>,
}

impl PeerManager {
    /// Creates a new peer manager
    pub fn new(max_peers: usize) -> Self {
        // Per-IP dial limit: 10/min, burst 5. Blocks Sybil-by-reconnect where
        // an attacker tries to fill our 32 pending-inbound slots by repeatedly
        // dialling from one IP. Legitimate boot-node reconnects use ≤1 dial/min.
        let ip_quota = Quota::per_minute(NonZeroU32::new(10).unwrap())
            .allow_burst(NonZeroU32::new(5).unwrap());
        let ip_dial_limiter = Arc::new(RateLimiter::dashmap_with_clock(ip_quota, DefaultClock::default()));

        // Global dial limit: 200/min, burst 20. Aggregate protection against
        // dial floods spread across many IPs (distributed Sybil).
        let global_quota = Quota::per_minute(NonZeroU32::new(200).unwrap())
            .allow_burst(NonZeroU32::new(20).unwrap());
        let global_dial_limiter = Arc::new(RateLimiter::direct_with_clock(global_quota, DefaultClock::default()));

        Self {
            peers: DashMap::new(),
            max_peers,
            ban_duration: Duration::from_secs(300), // 5 minutes (was 1 hour — too aggressive)
            ban_threshold: -50,
            rate_limit_max_messages: 1000, // 1000 messages per window (high to accommodate block production)
            rate_limit_window: Duration::from_secs(10), // 10 second window
            validator_registry: None,
            protected_peers: DashSet::new(),
            ip_dial_limiter,
            global_dial_limiter,
        }
    }

    /// Checks if a dial from the given IP should be allowed.
    ///
    /// Consults two rate limiters:
    /// 1. Per-IP bucket — blocks Sybil-by-reconnect from a single source
    /// 2. Global bucket — blocks aggregate dial floods across many IPs
    ///
    /// Returns `true` if the dial is within both rate limits, `false` if
    /// either limit has been exceeded. The caller (service.rs swarm dial
    /// handler) should reject the connection and increment
    /// `DIAL_REJECTED_RATE_LIMIT` on a `false` result.
    pub fn check_dial_rate_limit(&self, remote_ip: IpAddr) -> bool {
        if self.global_dial_limiter.check().is_err() {
            tracing::warn!("Global dial rate limit exceeded; rejecting connection");
            return false;
        }
        if self.ip_dial_limiter.check_key(&remote_ip).is_err() {
            tracing::warn!(ip = %remote_ip, "Per-IP dial rate limit exceeded; rejecting connection");
            return false;
        }
        true
    }

    /// Returns the gossipsub application-specific score for a peer.
    ///
    /// Maps our internal reputation (-100 .. +100) onto the f64 range used
    /// by libp2p gossipsub's P5 factor. Gossipsub combines this with P1-P4
    /// and P6-P7 via weighted sum. Typical mapping:
    ///
    /// - Reputation  +100 → P5 score +32.0  (capped at topic_score_cap)
    /// - Reputation     0 → P5 score   0.0
    /// - Reputation  -100 → P5 score -32.0
    ///
    /// Peers not tracked return 0.0 (neutral). This method is designed to
    /// be hot-path safe — no allocations, single DashMap lookup.
    pub fn app_specific_score(&self, peer_id: &PeerId) -> f64 {
        self.peers
            .get(peer_id)
            .map(|p| (p.reputation as f64) * 0.32)
            .unwrap_or(0.0)
    }

    /// Creates a new peer manager with custom rate limiting
    pub fn with_rate_limit(max_peers: usize, max_messages: u32, window_secs: u64) -> Self {
        Self {
            rate_limit_max_messages: max_messages,
            rate_limit_window: Duration::from_secs(window_secs),
            ..Self::new(max_peers)
        }
    }

    /// Sets the validator registry for peer authorization
    pub fn set_validator_registry(&mut self, registry: Arc<dyn ValidatorRegistry>) {
        self.validator_registry = Some(registry);
    }

    /// Returns a clone of the installed validator registry, if any.
    ///
    /// Used by the network service's admitted-mesh gate to intersect the
    /// gossipsub mesh peer set with the validator-admitted set, so that the
    /// first consensus publish only fires after enough mesh peers have been
    /// admitted via identify (closing the race where messages arrive before
    /// `try_register_validator_on_identify` has fired and get silently dropped
    /// by `authorize_peer_for_topic`).
    pub fn validator_registry(&self) -> Option<Arc<dyn ValidatorRegistry>> {
        self.validator_registry.clone()
    }

    /// Checks if a peer is authorized to publish on a validator-only topic.
    ///
    /// Returns `true` if:
    /// - The topic is not validator-only (e.g., transactions, status, inference), OR
    /// - No validator registry is set (permissive mode), OR
    /// - The peer is a known validator in the current validator set
    ///
    /// Returns `false` if the topic requires validator status and the peer is not a validator.
    pub fn authorize_peer_for_topic(&self, peer_id: &PeerId, topic_name: &str) -> bool {
        // Check if this topic requires validator authorization
        let is_validator_topic = VALIDATOR_ONLY_TOPICS.iter().any(|t| topic_name.contains(t));

        if !is_validator_topic {
            // Non-validator topics (transactions, models, inference, status) are open to all
            return true;
        }

        // Validator-only topic — check registry
        match &self.validator_registry {
            Some(registry) => {
                let authorized = registry.is_validator(peer_id);
                if !authorized {
                    tracing::warn!(
                        peer = %peer_id,
                        topic = topic_name,
                        "Rejected message from non-validator on validator-only topic"
                    );
                }
                authorized
            }
            None => {
                // No registry configured — permissive mode (pre-genesis or single-node)
                true
            }
        }
    }

    /// Dynamically admit a peer as a validator after the identify handshake
    /// confirms it speaks a trusted Tenzro protocol.
    ///
    /// This closes the "mutual ban" gap where a peer that joins AFTER the
    /// static boot-node list was wired would never be admitted to validator
    /// topics, causing its consensus/attestation messages to be rejected and
    /// its peer score to decay below thresholds.
    ///
    /// Only protocol versions starting with `"tenzro/"` are admitted. All
    /// other identify payloads are ignored (no-op).
    pub fn try_register_validator_on_identify(&self, peer_id: &PeerId, protocol_version: &str) {
        if !protocol_version.starts_with("tenzro/") {
            return;
        }

        // Promote to protected so cluster validators can never mutually ban
        // each other via reputation decay / rate-limit penalties. This is
        // the load-bearing fix for the "all blocks empty; peers perpetually
        // banned" class of outage on the live testnet.
        self.add_protected_peer(*peer_id);

        if let Some(registry) = &self.validator_registry {
            if !registry.is_validator(peer_id) {
                tracing::info!(
                    peer = %peer_id,
                    protocol = protocol_version,
                    "Dynamically admitting peer as validator via identify handshake"
                );
                registry.try_add_validator(peer_id);
            }
        }
    }

    /// Adds a new peer or updates existing peer
    pub fn add_peer(&self, peer_id: PeerId) {
        self.peers.entry(peer_id).or_insert_with(|| ManagedPeer::new(peer_id));
    }

    /// Removes a peer
    pub fn remove_peer(&self, peer_id: &PeerId) {
        self.peers.remove(peer_id);
    }

    /// Gets peer information
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<ManagedPeer> {
        self.peers.get(peer_id).map(|p| p.clone())
    }

    /// Updates peer status
    pub fn update_status(&self, peer_id: &PeerId, status: PeerStatus) {
        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            peer.status = status;
            peer.update_last_seen();
        }
    }

    /// Updates peer role
    pub fn update_role(&self, peer_id: &PeerId, role: NetworkRole) {
        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            peer.role = Some(role);
        }
    }

    /// Updates peer protocol version
    pub fn update_protocol_version(&self, peer_id: &PeerId, version: String) {
        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            peer.protocol_version = Some(version);
        }
    }

    /// Increases a peer's reputation
    pub fn increase_reputation(&self, peer_id: &PeerId, amount: i32) {
        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            peer.increase_reputation(amount);
            tracing::debug!(
                "Increased reputation for peer {} by {} (new: {})",
                peer_id,
                amount,
                peer.reputation
            );
        }
    }

    /// Decreases a peer's reputation and potentially bans them.
    ///
    /// Protected peers (boot nodes, peers that completed a `tenzro/`
    /// Identify handshake) are skipped entirely — neither their reputation
    /// nor their ban state is touched. This is deliberate: on a small
    /// validator set (e.g. 3 validators on the live testnet), HotStuff-2
    /// consensus bursts plus any single malformed gossip frame would
    /// otherwise drive mutual reputation below the ban threshold within
    /// seconds and wedge the chain in empty-block mode.
    pub fn decrease_reputation(&self, peer_id: &PeerId, amount: i32) {
        if self.protected_peers.contains(peer_id) {
            tracing::trace!(
                "Skipping reputation decrease for protected peer {} (amount={})",
                peer_id,
                amount
            );
            return;
        }
        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            peer.decrease_reputation(amount);
            tracing::debug!(
                "Decreased reputation for peer {} by {} (new: {})",
                peer_id,
                amount,
                peer.reputation
            );

            // Auto-ban if reputation drops too low
            if peer.reputation <= self.ban_threshold {
                self.ban_peer_internal(&mut peer);
            }
        }
    }

    /// Bans a peer for misbehavior
    pub fn ban_peer(&self, peer_id: &PeerId) {
        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            self.ban_peer_internal(&mut peer);
        }
    }

    /// Marks a peer as a protected peer (e.g., boot node).
    /// Protected peers will never be auto-banned, even if they trigger rate limits.
    ///
    /// Takes `&self` because `protected_peers` is a lock-free `DashSet`.
    /// The previous `&mut self` signature prevented Identify-time promotion
    /// from the swarm event loop (which holds only `&self` on PeerManager).
    pub fn add_protected_peer(&self, peer_id: PeerId) {
        if self.protected_peers.insert(peer_id) {
            tracing::info!("Added protected peer {}", peer_id);
        }
    }

    /// Checks if a peer is protected (boot node or critical infrastructure)
    pub fn is_protected(&self, peer_id: &PeerId) -> bool {
        self.protected_peers.contains(peer_id)
    }

    /// Internal ban implementation
    fn ban_peer_internal(&self, peer: &mut ManagedPeer) {
        if self.protected_peers.contains(&peer.peer_id) {
            tracing::debug!(
                "Skipping ban for protected peer {} (reputation: {})",
                peer.peer_id,
                peer.reputation
            );
            // Reset reputation to 0 instead of banning — prevents runaway negative scores
            peer.reputation = 0;
            return;
        }
        peer.status = PeerStatus::Banned;
        peer.ban_until = Some(Instant::now() + self.ban_duration);
        tracing::warn!("Banned peer {} for {} seconds", peer.peer_id, self.ban_duration.as_secs());
    }

    /// Unbans a peer
    pub fn unban_peer(&self, peer_id: &PeerId) {
        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            peer.ban_until = None;
            peer.status = PeerStatus::Disconnected;
            peer.reputation = 0; // Reset reputation
            tracing::info!("Unbanned peer {}", peer_id);
        }
    }

    /// Checks if a peer is banned
    pub fn is_banned(&self, peer_id: &PeerId) -> bool {
        // Protected peers are never considered banned, even if a previous
        // (pre-protection) ban is still lingering on their ManagedPeer record.
        // Clear the ban_until stamp on first read to keep downstream paths
        // (ban duration metrics, reconnect logic) consistent.
        if self.protected_peers.contains(peer_id) {
            if let Some(mut peer) = self.peers.get_mut(peer_id) {
                if peer.is_banned() {
                    tracing::info!(
                        peer = %peer_id,
                        "Clearing lingering ban on now-protected peer"
                    );
                    peer.ban_until = None;
                    peer.reputation = peer.reputation.max(0);
                }
            }
            return false;
        }
        self.peers
            .get(peer_id)
            .map(|p| p.is_banned())
            .unwrap_or(false)
    }

    /// Gets all connected peers
    pub fn connected_peers(&self) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|entry| entry.status == PeerStatus::Connected)
            .map(|entry| entry.peer_id)
            .collect()
    }

    /// Gets peers by role
    pub fn peers_by_role(&self, role: NetworkRole) -> Vec<PeerId> {
        self.peers
            .iter()
            .filter(|entry| entry.role == Some(role))
            .map(|entry| entry.peer_id)
            .collect()
    }

    /// Gets the number of connected peers
    pub fn connected_count(&self) -> usize {
        self.peers
            .iter()
            .filter(|entry| entry.status == PeerStatus::Connected)
            .count()
    }

    /// Checks if we can accept more peers
    pub fn can_accept_peer(&self) -> bool {
        self.connected_count() < self.max_peers
    }

    /// Checks if a peer is rate limited and records the message.
    ///
    /// Returns `true` if the peer is within rate limits (message allowed),
    /// `false` if the peer has exceeded the rate limit (message should be dropped).
    /// Automatically decreases reputation for rate-limited peers.
    pub fn check_rate_limit(&self, peer_id: &PeerId) -> bool {
        // Protected peers (boot nodes + identified tenzro/ peers) bypass
        // the rate limiter entirely. HotStuff-2 + gossip amplification can
        // legitimately exceed 1000 msgs/10s on a small cluster during
        // view changes; dropping those messages stalls consensus.
        if self.protected_peers.contains(peer_id) {
            return true;
        }

        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            let now = Instant::now();
            let window_start = now - self.rate_limit_window;

            // Evict timestamps outside the sliding window
            while peer.message_timestamps.front().is_some_and(|&t| t < window_start) {
                peer.message_timestamps.pop_front();
            }

            // Check if we're over the limit
            if peer.message_timestamps.len() >= self.rate_limit_max_messages as usize {
                // Rate limited — penalize reputation
                peer.decrease_reputation(5);
                tracing::warn!(
                    "Rate limited peer {} ({} msgs in {}s window)",
                    peer_id,
                    peer.message_timestamps.len(),
                    self.rate_limit_window.as_secs()
                );

                // Auto-ban if reputation drops too low
                if peer.reputation <= self.ban_threshold {
                    self.ban_peer_internal(&mut peer);
                }

                return false;
            }

            // Record this message
            peer.message_timestamps.push_back(now);
            true
        } else {
            // Unknown peer — allow but don't track
            true
        }
    }

    /// Records a failed connection attempt.
    ///
    /// In a K8s environment, outgoing connection errors are common during pod startup
    /// (e.g., when validators 1/2 try to dial validator-0 before it's fully ready).
    /// These are transient and should NOT trigger banning — only actual misbehavior
    /// (equivocation, spam, invalid messages) warrants a ban. We still track the
    /// failure count for diagnostics.
    pub fn record_failed_connection(&self, peer_id: &PeerId) {
        if let Some(mut peer) = self.peers.get_mut(peer_id) {
            peer.failed_connections += 1;
            tracing::debug!(
                "Recorded failed connection for peer {} (total: {})",
                peer_id,
                peer.failed_connections
            );
            // NOTE: Intentionally NOT auto-banning on connection failures.
            // libp2p will retry with exponential backoff; banning here causes
            // permanent validator isolation after just a few startup glitches.
        }
    }

    /// Cleans up stale peers (not seen for a long time)
    pub fn cleanup_stale_peers(&self, max_age: Duration) {
        let now = Instant::now();
        let stale_peers: Vec<PeerId> = self
            .peers
            .iter()
            .filter(|entry| {
                entry.status == PeerStatus::Disconnected
                    && now.duration_since(entry.last_seen) > max_age
            })
            .map(|entry| entry.peer_id)
            .collect();

        for peer_id in stale_peers {
            self.remove_peer(&peer_id);
            tracing::debug!("Removed stale peer {}", peer_id);
        }
    }

    /// Cleans up expired bans
    pub fn cleanup_expired_bans(&self) {
        let now = Instant::now();
        for mut entry in self.peers.iter_mut() {
            if let Some(until) = entry.ban_until {
                if now >= until {
                    entry.ban_until = None;
                    entry.status = PeerStatus::Disconnected;
                    entry.reputation = 0;
                    tracing::info!("Ban expired for peer {}", entry.peer_id);
                }
            }
        }
    }

    /// Gets statistics about peers
    pub fn stats(&self) -> PeerManagerStats {
        let mut stats = PeerManagerStats::default();

        for peer in self.peers.iter() {
            match peer.status {
                PeerStatus::Connected => stats.connected += 1,
                PeerStatus::Connecting => stats.connecting += 1,
                PeerStatus::Disconnected => stats.disconnected += 1,
                PeerStatus::Failed => stats.failed += 1,
                PeerStatus::Banned => stats.banned += 1,
            }
        }

        stats.total = self.peers.len();
        stats
    }
}

/// Peer manager statistics
#[derive(Debug, Default, Clone, Copy)]
pub struct PeerManagerStats {
    pub total: usize,
    pub connected: usize,
    pub connecting: usize,
    pub disconnected: usize,
    pub failed: usize,
    pub banned: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test implementation of ValidatorRegistry
    struct TestValidatorRegistry {
        validators: HashSet<PeerId>,
    }

    impl TestValidatorRegistry {
        fn new(validators: Vec<PeerId>) -> Self {
            Self {
                validators: validators.into_iter().collect(),
            }
        }
    }

    impl ValidatorRegistry for TestValidatorRegistry {
        fn is_validator(&self, peer_id: &PeerId) -> bool {
            self.validators.contains(peer_id)
        }

        fn validator_peer_ids(&self) -> HashSet<PeerId> {
            self.validators.clone()
        }
    }

    #[test]
    fn test_peer_reputation() {
        let manager = PeerManager::new(10);
        let peer_id = PeerId::random();

        manager.add_peer(peer_id);

        manager.increase_reputation(&peer_id, 10);
        let peer = manager.get_peer(&peer_id).unwrap();
        assert_eq!(peer.reputation, 10);

        manager.decrease_reputation(&peer_id, 5);
        let peer = manager.get_peer(&peer_id).unwrap();
        assert_eq!(peer.reputation, 5);
    }

    #[test]
    fn test_peer_banning() {
        let manager = PeerManager::new(10);
        let peer_id = PeerId::random();

        manager.add_peer(peer_id);
        assert!(!manager.is_banned(&peer_id));

        manager.ban_peer(&peer_id);
        assert!(manager.is_banned(&peer_id));

        manager.unban_peer(&peer_id);
        assert!(!manager.is_banned(&peer_id));
    }

    #[test]
    fn test_auto_ban_on_low_reputation() {
        let manager = PeerManager::new(10);
        let peer_id = PeerId::random();

        manager.add_peer(peer_id);
        manager.decrease_reputation(&peer_id, 160); // 100 - 160 = -60, below -50 threshold

        assert!(manager.is_banned(&peer_id));
    }

    #[test]
    fn test_rate_limiting() {
        // Allow only 5 messages in a 10 second window
        let manager = PeerManager::with_rate_limit(10, 5, 10);
        let peer_id = PeerId::random();

        manager.add_peer(peer_id);

        // First 5 messages should pass
        for _ in 0..5 {
            assert!(manager.check_rate_limit(&peer_id));
        }

        // 6th message should be rate limited
        assert!(!manager.check_rate_limit(&peer_id));

        // Reputation should have decreased
        let peer = manager.get_peer(&peer_id).unwrap();
        assert!(peer.reputation < 0);
    }

    #[test]
    fn test_validator_authorization_no_registry() {
        // Without a registry, all peers are allowed (permissive mode)
        let manager = PeerManager::new(10);
        let peer_id = PeerId::random();

        assert!(manager.authorize_peer_for_topic(&peer_id, "tenzro/blocks/1.0.0"));
        assert!(manager.authorize_peer_for_topic(&peer_id, "tenzro/consensus/1.0.0"));
        assert!(manager.authorize_peer_for_topic(&peer_id, "tenzro/transactions/1.0.0"));
    }

    #[test]
    fn test_validator_authorization_with_registry() {
        let validator = PeerId::random();
        let non_validator = PeerId::random();

        let registry = Arc::new(TestValidatorRegistry::new(vec![validator]));

        let mut manager = PeerManager::new(10);
        manager.set_validator_registry(registry);

        // Validator should be allowed on all topics
        assert!(manager.authorize_peer_for_topic(&validator, "tenzro/blocks/1.0.0"));
        assert!(manager.authorize_peer_for_topic(&validator, "tenzro/consensus/1.0.0"));
        assert!(manager.authorize_peer_for_topic(&validator, "tenzro/attestations/1.0.0"));
        assert!(manager.authorize_peer_for_topic(&validator, "tenzro/transactions/1.0.0"));

        // Non-validator should be blocked on validator-only topics (consensus, attestations)
        // NOTE: "tenzro/blocks/1.0.0" is intentionally open to all peers so that
        // RPC nodes and model providers can receive block gossip for chain sync.
        assert!(manager.authorize_peer_for_topic(&non_validator, "tenzro/blocks/1.0.0"));
        assert!(!manager.authorize_peer_for_topic(&non_validator, "tenzro/consensus/1.0.0"));
        assert!(!manager.authorize_peer_for_topic(&non_validator, "tenzro/attestations/1.0.0"));

        // Non-validator should be allowed on open topics
        assert!(manager.authorize_peer_for_topic(&non_validator, "tenzro/transactions/1.0.0"));
        assert!(manager.authorize_peer_for_topic(&non_validator, "tenzro/status/1.0.0"));
        assert!(manager.authorize_peer_for_topic(&non_validator, "tenzro/inference/1.0.0"));
        assert!(manager.authorize_peer_for_topic(&non_validator, "tenzro/models/1.0.0"));
    }

    #[test]
    fn test_protected_peer_not_banned() {
        let manager = PeerManager::new(10);
        let protected = PeerId::random();
        let normal = PeerId::random();

        // Register protected peer
        manager.add_protected_peer(protected);
        assert!(manager.is_protected(&protected));
        assert!(!manager.is_protected(&normal));

        // Add both peers
        manager.add_peer(protected);
        manager.add_peer(normal);

        // Tank both peers' reputation below ban threshold (-50)
        manager.decrease_reputation(&protected, 160);
        manager.decrease_reputation(&normal, 160);

        // Normal peer should be banned
        assert!(manager.is_banned(&normal));

        // Protected peer should NOT be banned, and reputation reset to 0
        assert!(!manager.is_banned(&protected));
        let peer = manager.get_peer(&protected).unwrap();
        assert_eq!(peer.reputation, 0);
    }
}
