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

    /// Statically-configured external addresses this node advertises to peers
    /// via Identify. Required on cloud deployments where the host binds to
    /// `0.0.0.0` and Identify's listen-addr enumeration is hidden (see
    /// `behaviour.rs::hide_listen_addrs`). Each multiaddr listed here is
    /// passed to `Swarm::add_external_address` at startup.
    ///
    /// For validator-0 in the live GCE testnet this is set to
    /// `/ip4/<external-ip>/tcp/9000` from the per-VM Terraform output. For
    /// nodes whose external address must be discovered (community joiners
    /// behind NAT), leave this empty and rely on AutoNAT v2 + Relay v2 +
    /// DCUtR to confirm a reachable address dynamically.
    pub external_addresses: Vec<Multiaddr>,
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
                "tenzro/blocks".to_string(),
                "tenzro/transactions".to_string(),
                "tenzro/consensus".to_string(),
            ],
            enable_dht: true,
            // SECURITY: mDNS leaks LAN presence — disabled by default for production;
            // `local()` preset re-enables it explicitly for dev.
            enable_mdns: false,
            // 10 minutes. Two reasons it has to be this high on cloud deployments:
            // (1) rust-libp2p closes any connection that stays idle this long with
            //     no in-flight substream — and HotStuff-2 has long quiet pairwise
            //     links during normal operation. A short value (e.g. 120s) causes
            //     constant close+redial churn and degrades the gossipsub mesh from
            //     full N-1 to 0-4 peers over an hour, stalling consensus (observed
            //     on GCE multi-region 2026-05-14).
            // (2) many NAT/VPC fabrics silently evict idle conntrack entries
            //     at ~10 minutes WITHOUT sending RST. Keeping libp2p's idle
            //     timeout at or above 600s, combined with kernel TCP keepalive
            //     set to fire every ~120s at the host layer, keeps the
            //     conntrack entries warm before either side drops the connection.
            connection_idle_timeout: Duration::from_secs(600),
            // Ethereum-class 700ms heartbeat for sub-second gossip propagation.
            gossip_heartbeat_interval: Duration::from_millis(700),
            protocol_version: "tenzro/1.0.0".to_string(),
            user_agent: "tenzro-network/0.1.0".to_string(),
            enable_hole_punching: true,
            enable_relay: false,
            external_addresses: Vec::new(),
        }
    }
}

impl NetworkConfig {
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
