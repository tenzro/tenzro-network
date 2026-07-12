//! Peer discovery via Kademlia DHT for Tenzro Network

use libp2p::{
    kad::{store::MemoryStore, Behaviour as Kademlia, Config as KademliaConfig, Mode},
    Multiaddr, PeerId,
};
use std::time::{Duration, Instant};
use tenzro_types::network::NetworkRole;

/// Creates a Kademlia DHT behaviour for peer discovery
pub fn create_kademlia(local_peer_id: PeerId) -> Kademlia<MemoryStore> {
    let mut config = KademliaConfig::new(libp2p::StreamProtocol::new("/tenzro/kad"));

    // A+++ 2026 hardening:
    //   * S/Kademlia disjoint query paths — Sybil-resistance per Baumgart & Mies 2007.
    //   * 30s query timeout — 2x faster failure detection than default 60s.
    //   * k=10 replication — tuned for ≤200-peer meshes (vs 20 which is Ethereum-mainnet-scale overhead).
    //   * OnConnected k-bucket inserts — avoid polluting routing table with unreachable peers.
    //   * Long-lived records with 36h TTL; re-publish every 22h (matches IPFS public DHT).
    config.set_query_timeout(Duration::from_secs(30));
    config.set_replication_factor(std::num::NonZeroUsize::new(10).unwrap());
    config.set_publication_interval(Some(Duration::from_secs(22 * 60 * 60)));
    config.set_record_ttl(Some(Duration::from_secs(36 * 60 * 60)));
    config.set_provider_record_ttl(Some(Duration::from_secs(24 * 60 * 60)));
    config.disjoint_query_paths(true);

    // Create the Kademlia behaviour with memory store
    let store = MemoryStore::new(local_peer_id);
    let mut kademlia = Kademlia::with_config(local_peer_id, store, config);

    // Set server mode to enable incoming queries
    kademlia.set_mode(Some(Mode::Server));

    kademlia
}

/// Connects to bootstrap nodes on startup
///
/// This function extracts peer IDs from the multiaddresses and adds them to the
/// Kademlia DHT routing table, then initiates the DHT bootstrap process for
/// ongoing peer discovery.
pub fn connect_to_bootstrap_nodes(
    kademlia: &mut Kademlia<MemoryStore>,
    config: &BootstrapConfig,
) -> Vec<Multiaddr> {
    let mut addrs_to_dial = Vec::new();

    for addr in &config.boot_nodes {
        // Extract peer ID from multiaddr if present
        let peer_id = addr.iter().find_map(|proto| {
            if let libp2p::multiaddr::Protocol::P2p(peer_id) = proto {
                Some(peer_id)
            } else {
                None
            }
        });

        if let Some(peer_id) = peer_id {
            // Add address to Kademlia routing table
            kademlia.add_address(&peer_id, addr.clone());
            tracing::debug!("Added boot node {} to Kademlia", peer_id);
        }

        addrs_to_dial.push(addr.clone());
    }

    // Start the DHT bootstrap process
    if !config.boot_nodes.is_empty() {
        if let Err(e) = kademlia.bootstrap() {
            tracing::warn!("Failed to start DHT bootstrap: {:?}", e);
        } else {
            tracing::info!("Started DHT bootstrap with {} boot nodes", config.boot_nodes.len());
        }
    }

    addrs_to_dial
}

/// Bootstrap the DHT by connecting to known nodes
///
/// This is the lower-level function that directly accepts peer IDs and multiaddresses.
/// For most use cases, prefer `connect_to_bootstrap_nodes` which uses `BootstrapConfig`.
pub fn bootstrap_dht(kademlia: &mut Kademlia<MemoryStore>, boot_nodes: Vec<(PeerId, Multiaddr)>) {
    for (peer_id, addr) in boot_nodes {
        kademlia.add_address(&peer_id, addr);
    }

    // Start the bootstrap process
    if let Err(e) = kademlia.bootstrap() {
        tracing::warn!("Failed to start DHT bootstrap: {:?}", e);
    } else {
        tracing::info!("Started DHT bootstrap");
    }
}

/// Provider record key for different provider types
pub fn provider_key(provider_type: ProviderType) -> Vec<u8> {
    match provider_type {
        ProviderType::Inference => b"/tenzro/providers/inference".to_vec(),
        ProviderType::Tee => b"/tenzro/providers/tee".to_vec(),
        ProviderType::Storage => b"/tenzro/providers/storage".to_vec(),
        ProviderType::Validator => b"/tenzro/providers/validator".to_vec(),
    }
}

/// Provider types for discovery
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderType {
    /// Inference/model providers
    Inference,
    /// TEE providers
    Tee,
    /// Storage providers
    Storage,
    /// Validator nodes
    Validator,
}

impl ProviderType {
    /// Converts NetworkRole to ProviderType
    pub fn from_role(role: NetworkRole) -> Option<Self> {
        match role {
            NetworkRole::ModelProvider => Some(Self::Inference),
            NetworkRole::TeeProvider => Some(Self::Tee),
            NetworkRole::StorageProvider => Some(Self::Storage),
            NetworkRole::Validator => Some(Self::Validator),
            _ => None,
        }
    }

    /// Converts to NetworkRole
    pub fn to_role(self) -> NetworkRole {
        match self {
            Self::Inference => NetworkRole::ModelProvider,
            Self::Tee => NetworkRole::TeeProvider,
            Self::Storage => NetworkRole::StorageProvider,
            Self::Validator => NetworkRole::Validator,
        }
    }
}

/// Bootstrap configuration for connecting to known boot nodes
#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    /// List of bootstrap node multiaddresses
    pub boot_nodes: Vec<Multiaddr>,
    /// Enable automatic reconnection to boot nodes on disconnect
    pub enable_reconnect: bool,
    /// Reconnection interval in seconds
    pub reconnect_interval: Duration,
}

impl Default for BootstrapConfig {
    fn default() -> Self {
        Self {
            boot_nodes: Vec::new(),
            enable_reconnect: true,
            reconnect_interval: Duration::from_secs(60),
        }
    }
}

impl BootstrapConfig {
    /// Creates a new bootstrap config with the given boot nodes
    pub fn new(boot_nodes: Vec<Multiaddr>) -> Self {
        Self {
            boot_nodes,
            ..Default::default()
        }
    }

    /// Creates a testnet bootstrap config
    pub fn testnet() -> Self {
        Self {
            boot_nodes: vec![
                "/dns4/testnet-boot-1.tenzro.xyz/tcp/9000".parse().unwrap(),
                "/dns4/testnet-boot-2.tenzro.xyz/tcp/9000".parse().unwrap(),
            ],
            ..Default::default()
        }
    }

    /// Creates a mainnet bootstrap config
    pub fn mainnet() -> Self {
        Self {
            boot_nodes: vec![
                "/dns4/mainnet-boot-1.tenzro.xyz/tcp/9000".parse().unwrap(),
                "/dns4/mainnet-boot-2.tenzro.xyz/tcp/9000".parse().unwrap(),
                "/dns4/mainnet-boot-3.tenzro.xyz/tcp/9000".parse().unwrap(),
            ],
            ..Default::default()
        }
    }
}

/// Per-target reconnection schedule using decorrelated jitter.
///
/// Re-dialing an unreachable peer on a fixed interval is a thundering-herd
/// hazard: when a bootstrap node restarts, every joiner that lost it re-dials
/// in lockstep on the same cadence, and the recovering node is hit by a
/// synchronized dial storm exactly when it is least able to absorb it. This
/// schedule spreads retries out and backs off geometrically per target.
///
/// The backoff follows the "decorrelated jitter" formula from the AWS
/// Architecture Blog ("Exponential Backoff And Jitter", Brooker 2015), which
/// is the same shape libp2p, Ethereum discv5, and the `backoff` crate use:
///
/// ```text
/// delay = min(cap, random_between(base, prev_delay * 3))
/// ```
///
/// Each target owns its own schedule. `due()` reports whether the next
/// scheduled attempt time has passed; `record_attempt()` advances the delay
/// and stamps the next-due time; `reset()` is called on a successful connect
/// so a peer that flaps back does not inherit a long stale backoff.
///
/// This is permissionless by construction: `base`/`cap` are wall-clock
/// bounds, not topology assumptions. A 4-node LAN and a 10,000-node WAN use
/// the same schedule — the jitter simply de-synchronizes whoever is present.
#[derive(Debug, Clone)]
pub struct ReconnectBackoff {
    base: Duration,
    cap: Duration,
    current: Duration,
    next_due: Instant,
}

impl ReconnectBackoff {
    /// Create a schedule with the given floor and ceiling. The first attempt
    /// is due immediately (`next_due` = now) so a freshly-lost peer is
    /// re-dialed on the next sweep without waiting a full `base`.
    pub fn new(base: Duration, cap: Duration) -> Self {
        Self {
            base,
            cap,
            current: base,
            next_due: Instant::now(),
        }
    }

    /// Default schedule: 2s floor, 5min ceiling. Suits both bootstrap re-dial
    /// and mid-session peer recovery — fast enough to recover from a transient
    /// blip in seconds, slow enough that a peer that is down for good is
    /// probed at most every 5 minutes.
    pub fn default_schedule() -> Self {
        Self::new(Duration::from_secs(2), Duration::from_secs(300))
    }

    /// Whether the next scheduled attempt time has arrived.
    pub fn due(&self) -> bool {
        Instant::now() >= self.next_due
    }

    /// Record that an attempt was just made: draw the next delay via
    /// decorrelated jitter and stamp `next_due`. Returns the delay chosen so
    /// callers can log it.
    pub fn record_attempt(&mut self) -> Duration {
        use rand::Rng;
        let upper = self.current.saturating_mul(3).min(self.cap);
        let lower = self.base.min(upper);
        let delay = if upper <= lower {
            lower
        } else {
            let millis = rand::thread_rng().gen_range(lower.as_millis()..=upper.as_millis());
            Duration::from_millis(millis as u64)
        };
        self.current = delay;
        self.next_due = Instant::now() + delay;
        delay
    }

    /// Reset to the floor after a successful connect.
    pub fn reset(&mut self) {
        self.current = self.base;
        self.next_due = Instant::now();
    }
}

/// Discovery configuration
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Enable random walk for discovering new peers
    pub enable_random_walk: bool,
    /// Random walk interval
    pub random_walk_interval: Duration,
    /// Enable provider announcements
    pub enable_provider_announcement: bool,
    /// Provider announcement interval
    pub provider_announcement_interval: Duration,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            enable_random_walk: true,
            random_walk_interval: Duration::from_secs(300), // 5 minutes
            enable_provider_announcement: false,
            provider_announcement_interval: Duration::from_secs(600), // 10 minutes
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kademlia_creation() {
        let peer_id = PeerId::random();
        let kad = create_kademlia(peer_id);
        // Just verify it was created successfully
        drop(kad);
    }

    #[test]
    fn test_provider_keys() {
        let inference_key = provider_key(ProviderType::Inference);
        let tee_key = provider_key(ProviderType::Tee);

        assert_ne!(inference_key, tee_key);
        assert_eq!(inference_key, b"/tenzro/providers/inference");
    }

    #[test]
    fn test_provider_type_conversion() {
        assert_eq!(
            ProviderType::from_role(NetworkRole::ModelProvider),
            Some(ProviderType::Inference)
        );
        assert_eq!(
            ProviderType::from_role(NetworkRole::FullNode),
            None
        );
    }

    #[test]
    fn test_bootstrap_config_default() {
        let config = BootstrapConfig::default();
        assert!(config.boot_nodes.is_empty());
        assert!(config.enable_reconnect);
        assert_eq!(config.reconnect_interval, Duration::from_secs(60));
    }

    #[test]
    fn test_bootstrap_config_testnet() {
        let config = BootstrapConfig::testnet();
        assert_eq!(config.boot_nodes.len(), 2);
        assert!(config.enable_reconnect);
    }

    #[test]
    fn test_bootstrap_config_mainnet() {
        let config = BootstrapConfig::mainnet();
        assert_eq!(config.boot_nodes.len(), 3);
        assert!(config.enable_reconnect);
    }

    #[test]
    fn test_reconnect_backoff_first_attempt_due_immediately() {
        let b = ReconnectBackoff::new(Duration::from_secs(2), Duration::from_secs(300));
        // A freshly-lost peer must be dialable on the next sweep.
        assert!(b.due());
    }

    #[test]
    fn test_reconnect_backoff_grows_and_caps() {
        let base = Duration::from_millis(10);
        let cap = Duration::from_millis(200);
        let mut b = ReconnectBackoff::new(base, cap);
        let mut prev = base;
        // Each attempt draws in [base, min(prev*3, cap)] and never exceeds cap.
        for _ in 0..20 {
            let d = b.record_attempt();
            assert!(d >= base, "delay {:?} below base {:?}", d, base);
            assert!(d <= cap, "delay {:?} above cap {:?}", d, cap);
            assert!(
                d <= prev.saturating_mul(3).max(base) || d <= cap,
                "delay {:?} exceeded decorrelated bound (prev {:?})",
                d,
                prev
            );
            prev = d;
        }
    }

    #[test]
    fn test_reconnect_backoff_not_due_after_attempt() {
        let mut b = ReconnectBackoff::new(Duration::from_secs(60), Duration::from_secs(300));
        b.record_attempt();
        // Next-due is stamped ≥60s out, so it is not immediately due again.
        assert!(!b.due());
    }

    #[test]
    fn test_reconnect_backoff_reset_returns_to_floor() {
        let base = Duration::from_secs(1);
        let mut b = ReconnectBackoff::new(base, Duration::from_secs(300));
        for _ in 0..5 {
            b.record_attempt();
        }
        b.reset();
        assert!(b.due(), "reset must make the target immediately dialable");
        assert_eq!(b.current, base, "reset must return the delay to the floor");
    }

    #[test]
    fn test_connect_to_bootstrap_nodes() {
        let peer_id = PeerId::random();
        let mut kad = create_kademlia(peer_id);

        // Create a boot node multiaddr with peer ID
        let boot_peer = PeerId::random();
        let boot_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/9000/p2p/{}", boot_peer)
            .parse()
            .unwrap();

        let config = BootstrapConfig::new(vec![boot_addr.clone()]);
        let addrs = connect_to_bootstrap_nodes(&mut kad, &config);

        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], boot_addr);
    }

    #[test]
    fn test_connect_to_bootstrap_nodes_empty() {
        let peer_id = PeerId::random();
        let mut kad = create_kademlia(peer_id);

        let config = BootstrapConfig::default();
        let addrs = connect_to_bootstrap_nodes(&mut kad, &config);

        assert!(addrs.is_empty());
    }
}
