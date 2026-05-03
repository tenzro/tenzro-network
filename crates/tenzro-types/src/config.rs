//! Configuration types for Tenzro Network
//!
//! This module defines configuration structures for nodes and
//! network parameters.

use crate::primitives::ChainId;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Network configuration for Tenzro Network
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Chain ID
    pub chain_id: ChainId,
    /// Network name
    pub network_name: String,
    /// Genesis block hash
    pub genesis_hash: String,
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<String>,
    /// Consensus parameters
    pub consensus: ConsensusConfig,
    /// Protocol version
    pub protocol_version: u32,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            chain_id: ChainId::mainnet(),
            network_name: "Tenzro Network Mainnet".to_string(),
            genesis_hash: String::new(),
            bootstrap_nodes: Vec::new(),
            consensus: ConsensusConfig::default(),
            protocol_version: 1,
        }
    }
}

impl NetworkConfig {
    /// Creates a mainnet configuration
    pub fn mainnet() -> Self {
        Self {
            chain_id: ChainId::mainnet(),
            network_name: "Tenzro Network Mainnet".to_string(),
            genesis_hash: String::new(),
            bootstrap_nodes: Vec::new(),
            consensus: ConsensusConfig::default(),
            protocol_version: 1,
        }
    }

    /// Creates a testnet configuration
    pub fn testnet() -> Self {
        Self {
            chain_id: ChainId::testnet(),
            network_name: "Tenzro Network Testnet".to_string(),
            genesis_hash: String::new(),
            bootstrap_nodes: Vec::new(),
            consensus: ConsensusConfig::default(),
            protocol_version: 1,
        }
    }

    /// Creates a local development configuration
    pub fn devnet() -> Self {
        Self {
            chain_id: ChainId::new(31337),
            network_name: "Tenzro Network Devnet".to_string(),
            genesis_hash: String::new(),
            bootstrap_nodes: Vec::new(),
            consensus: ConsensusConfig::default(),
            protocol_version: 1,
        }
    }
}

/// Consensus configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsensusConfig {
    /// Block time in milliseconds
    pub block_time_ms: u64,
    /// Maximum block size in bytes
    pub max_block_size: u64,
    /// Maximum transactions per block
    pub max_transactions_per_block: u32,
    /// Minimum validator stake (in smallest TNZO unit)
    pub min_validator_stake: u64,
    /// Maximum number of validators
    pub max_validators: u32,
    /// Consensus algorithm
    pub algorithm: String,
}

impl Default for ConsensusConfig {
    fn default() -> Self {
        Self {
            block_time_ms: 2000, // 2 seconds
            max_block_size: 1024 * 1024, // 1 MB
            max_transactions_per_block: 1000,
            min_validator_stake: 10_000 * 10u64.pow(18), // 10,000 TNZO
            max_validators: 100,
            algorithm: "PoS".to_string(),
        }
    }
}

/// Node configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Node name/identifier
    pub node_name: String,
    /// Data directory
    pub data_dir: PathBuf,
    /// Network configuration
    pub network: NetworkConfig,
    /// P2P configuration
    pub p2p: P2pConfig,
    /// RPC configuration
    pub rpc: RpcConfig,
    /// Storage configuration
    pub storage: StorageConfig,
    /// Logging configuration
    pub logging: LoggingConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_name: "tenzro-node".to_string(),
            data_dir: PathBuf::from("./data"),
            network: NetworkConfig::default(),
            p2p: P2pConfig::default(),
            rpc: RpcConfig::default(),
            storage: StorageConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

/// P2P network configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct P2pConfig {
    /// Listen address
    pub listen_address: SocketAddr,
    /// Public address (for NAT traversal)
    pub public_address: Option<SocketAddr>,
    /// Maximum inbound peers
    pub max_inbound_peers: u32,
    /// Maximum outbound peers
    pub max_outbound_peers: u32,
    /// Enable peer discovery
    pub enable_discovery: bool,
    /// Bootstrap nodes
    pub bootstrap_nodes: Vec<String>,
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self {
            listen_address: "0.0.0.0:26656".parse().unwrap(),
            public_address: None,
            max_inbound_peers: 50,
            max_outbound_peers: 25,
            enable_discovery: true,
            bootstrap_nodes: Vec::new(),
        }
    }
}

/// RPC server configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcConfig {
    /// Enable RPC server
    pub enabled: bool,
    /// RPC listen address
    pub listen_address: SocketAddr,
    /// Enable HTTP
    pub enable_http: bool,
    /// Enable WebSocket
    pub enable_ws: bool,
    /// CORS allowed origins
    pub cors_allowed_origins: Vec<String>,
    /// Maximum request size in bytes
    pub max_request_size: usize,
}

impl Default for RpcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            listen_address: "127.0.0.1:8545".parse().unwrap(),
            enable_http: true,
            enable_ws: true,
            cors_allowed_origins: vec!["*".to_string()],
            max_request_size: 1024 * 1024, // 1 MB
        }
    }
}

/// Storage configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageConfig {
    /// Storage backend type
    pub backend: StorageBackend,
    /// Database path
    pub db_path: PathBuf,
    /// Cache size in MB
    pub cache_size_mb: u64,
    /// Enable state pruning
    pub enable_pruning: bool,
    /// Pruning interval in blocks
    pub pruning_interval: u64,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: StorageBackend::RocksDb,
            db_path: PathBuf::from("./data/db"),
            cache_size_mb: 512,
            enable_pruning: false,
            pruning_interval: 1000,
        }
    }
}

/// Storage backend types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageBackend {
    /// RocksDB backend
    RocksDb,
    /// In-memory backend (for testing)
    Memory,
    /// Custom backend
    Custom,
}

/// Logging configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level
    pub level: LogLevel,
    /// Log format
    pub format: LogFormat,
    /// Log to file
    pub log_to_file: bool,
    /// Log file path
    pub log_file_path: Option<PathBuf>,
    /// Enable JSON logging
    pub json_logs: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            format: LogFormat::Text,
            log_to_file: false,
            log_file_path: None,
            json_logs: false,
        }
    }
}

/// Log level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogLevel {
    /// Trace level
    Trace,
    /// Debug level
    Debug,
    /// Info level
    Info,
    /// Warning level
    Warn,
    /// Error level
    Error,
}

/// Log format
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LogFormat {
    /// Plain text format
    Text,
    /// JSON format
    Json,
    /// Compact format
    Compact,
}
