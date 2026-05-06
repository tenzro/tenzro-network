//! Peer discovery via Kademlia DHT for Tenzro Network

use libp2p::{
    kad::{store::MemoryStore, Behaviour as Kademlia, Config as KademliaConfig, Mode},
    Multiaddr, PeerId,
};
use std::time::Duration;
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
                "/dns4/testnet-boot-1.tenzro.network/tcp/9000".parse().unwrap(),
                "/dns4/testnet-boot-2.tenzro.network/tcp/9000".parse().unwrap(),
            ],
            ..Default::default()
        }
    }

    /// Creates a mainnet bootstrap config
    pub fn mainnet() -> Self {
        Self {
            boot_nodes: vec![
                "/dns4/mainnet-boot-1.tenzro.network/tcp/9000".parse().unwrap(),
                "/dns4/mainnet-boot-2.tenzro.network/tcp/9000".parse().unwrap(),
                "/dns4/mainnet-boot-3.tenzro.network/tcp/9000".parse().unwrap(),
            ],
            ..Default::default()
        }
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
