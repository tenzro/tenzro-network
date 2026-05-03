//! Network configuration for Tenzro Network

use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Data directory for persistent state (keypair, etc.)
    pub data_dir: Option<PathBuf>,

    /// Listen addresses (multiaddr format)
    pub listen_addresses: Vec<Multiaddr>,

    /// Bootstrap nodes to connect to on startup
    pub boot_nodes: Vec<Multiaddr>,

    /// Maximum number of inbound peers
    pub max_inbound_peers: u32,

    /// Maximum number of outbound peers
    pub max_outbound_peers: u32,

    /// Topics to subscribe to on startup
    pub gossip_topics: Vec<String>,

    /// Enable DHT for peer discovery
    pub enable_dht: bool,

    /// Enable mDNS for local peer discovery
    pub enable_mdns: bool,

    /// Connection idle timeout
    pub connection_idle_timeout: Duration,

    /// Heartbeat interval for gossipsub
    pub gossip_heartbeat_interval: Duration,

    /// Protocol version
    pub protocol_version: String,

    /// User agent string
    pub user_agent: String,

    /// Enable hole punching for NAT traversal
    pub enable_hole_punching: bool,

    /// Enable relay server
    pub enable_relay: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            data_dir: None,
            listen_addresses: vec![
                "/ip4/0.0.0.0/tcp/9000".parse().unwrap(),
                "/ip4/0.0.0.0/udp/9000/quic-v1".parse().unwrap(),
            ],
            boot_nodes: Vec::new(),
            // A+++ production-grade capacity: matches libp2p ConnectionLimits (200/200 max)
            max_inbound_peers: 200,
            max_outbound_peers: 200,
            gossip_topics: vec![
                "tenzro/blocks/1.0.0".to_string(),
                "tenzro/transactions/1.0.0".to_string(),
                "tenzro/consensus/1.0.0".to_string(),
            ],
            enable_dht: true,
            // SECURITY: mDNS leaks LAN presence — disabled by default for production;
            // `local()` preset re-enables it explicitly for dev.
            enable_mdns: false,
            connection_idle_timeout: Duration::from_secs(120),
            // Ethereum-class 700ms heartbeat for sub-second gossip propagation.
            gossip_heartbeat_interval: Duration::from_millis(700),
            protocol_version: "tenzro/1.0.0".to_string(),
            user_agent: "tenzro-network/0.1.0".to_string(),
            enable_hole_punching: true,
            enable_relay: false,
        }
    }
}

impl NetworkConfig {
    /// Creates a testnet configuration
    pub fn testnet() -> Self {
        Self {
            boot_nodes: vec![
                "/dns4/testnet-boot-1.tenzro.network/tcp/9000".parse().unwrap(),
                "/dns4/testnet-boot-2.tenzro.network/tcp/9000".parse().unwrap(),
            ],
            gossip_topics: vec![
                "tenzro/testnet/blocks/1.0.0".to_string(),
                "tenzro/testnet/transactions/1.0.0".to_string(),
                "tenzro/testnet/consensus/1.0.0".to_string(),
                "tenzro/testnet/attestations/1.0.0".to_string(),
                "tenzro/testnet/models/1.0.0".to_string(),
                "tenzro/testnet/inference/1.0.0".to_string(),
            ],
            enable_mdns: false,
            ..Default::default()
        }
    }

    /// Creates a mainnet configuration
    pub fn mainnet() -> Self {
        Self {
            boot_nodes: vec![
                "/dns4/mainnet-boot-1.tenzro.network/tcp/9000".parse().unwrap(),
                "/dns4/mainnet-boot-2.tenzro.network/tcp/9000".parse().unwrap(),
                "/dns4/mainnet-boot-3.tenzro.network/tcp/9000".parse().unwrap(),
            ],
            gossip_topics: vec![
                "tenzro/mainnet/blocks/1.0.0".to_string(),
                "tenzro/mainnet/transactions/1.0.0".to_string(),
                "tenzro/mainnet/consensus/1.0.0".to_string(),
                "tenzro/mainnet/attestations/1.0.0".to_string(),
                "tenzro/mainnet/models/1.0.0".to_string(),
                "tenzro/mainnet/inference/1.0.0".to_string(),
            ],
            enable_relay: false,
            enable_mdns: false,
            ..Default::default()
        }
    }

    /// Creates a local development configuration
    pub fn local() -> Self {
        Self {
            listen_addresses: vec![
                "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
                "/ip4/127.0.0.1/udp/0/quic-v1".parse().unwrap(),
            ],
            boot_nodes: Vec::new(),
            max_inbound_peers: 10,
            max_outbound_peers: 5,
            // mDNS only re-enabled for local dev — never for test/main-net.
            enable_mdns: true,
            enable_dht: false,
            ..Default::default()
        }
    }

    /// Validates the configuration
    pub fn validate(&self) -> crate::error::Result<()> {
        if self.max_inbound_peers == 0 && self.max_outbound_peers == 0 {
            return Err(crate::error::NetworkError::InvalidConfig("At least one peer connection must be allowed".to_string()));
        }

        if self.listen_addresses.is_empty() {
            return Err(crate::error::NetworkError::InvalidConfig("At least one listen address must be specified".to_string()));
        }

        if self.gossip_topics.is_empty() {
            return Err(crate::error::NetworkError::InvalidConfig("At least one gossip topic must be specified".to_string()));
        }

        Ok(())
    }
}
