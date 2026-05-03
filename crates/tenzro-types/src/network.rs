//! Network types for Tenzro Network
//!
//! This module defines network topology, peer discovery, and node
//! information structures.

use crate::primitives::{Address, Timestamp};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// The role of a node in the Tenzro Network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NetworkRole {
    /// Full validator node
    Validator,
    /// Full node (non-validating)
    FullNode,
    /// Light client
    LightClient,
    /// TEE provider node
    TeeProvider,
    /// Model inference provider node
    ModelProvider,
    /// Storage provider node
    StorageProvider,
    /// Archive node (stores full history)
    Archive,
    /// Bootstrap/seed node
    Bootstrap,
    /// Micro node / participant — ultra-lightweight, no P2P required.
    /// Humans or AI agents joining via MCP server, Claude, ClawBot,
    /// or other agentic frameworks. Auto-provisioned DID + MPC wallet.
    MicroNode,
}

impl NetworkRole {
    /// Checks if this role can validate blocks
    pub fn is_validator(&self) -> bool {
        matches!(self, Self::Validator)
    }

    /// Checks if this role is a provider
    pub fn is_provider(&self) -> bool {
        matches!(
            self,
            Self::TeeProvider | Self::ModelProvider | Self::StorageProvider
        )
    }

    /// Checks if this role maintains full state
    pub fn is_full_node(&self) -> bool {
        matches!(
            self,
            Self::Validator | Self::FullNode | Self::Archive | Self::Bootstrap
        )
    }

    /// Checks if this role is a micro node (zero-install participant)
    pub fn is_micro_node(&self) -> bool {
        matches!(self, Self::MicroNode)
    }
}

/// Information about a peer in the network
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer's unique identifier
    pub peer_id: String,
    /// Peer's network addresses
    pub addresses: Vec<SocketAddr>,
    /// Peer's role in the network
    pub role: NetworkRole,
    /// Protocol version
    pub protocol_version: u32,
    /// User agent string
    pub user_agent: String,
    /// Last seen timestamp
    pub last_seen: Timestamp,
    /// Peer reputation score
    pub reputation: i64,
    /// Connection status
    pub status: PeerStatus,
}

impl PeerInfo {
    /// Creates a new PeerInfo
    pub fn new(peer_id: String, addresses: Vec<SocketAddr>, role: NetworkRole) -> Self {
        Self {
            peer_id,
            addresses,
            role,
            protocol_version: 1,
            user_agent: "tenzro/1.0".to_string(),
            last_seen: Timestamp::now(),
            reputation: 0,
            status: PeerStatus::Disconnected,
        }
    }

    /// Updates the last seen timestamp
    pub fn update_last_seen(&mut self) {
        self.last_seen = Timestamp::now();
    }

    /// Increases the reputation score
    pub fn increase_reputation(&mut self, amount: i64) {
        self.reputation = self.reputation.saturating_add(amount);
    }

    /// Decreases the reputation score
    pub fn decrease_reputation(&mut self, amount: i64) {
        self.reputation = self.reputation.saturating_sub(amount);
    }
}

/// Peer connection status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerStatus {
    /// Not connected
    Disconnected,
    /// Attempting to connect
    Connecting,
    /// Successfully connected
    Connected,
    /// Connection failed
    Failed,
    /// Peer is banned
    Banned,
}

/// Information about the local node
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeInfo {
    /// Node's unique identifier
    pub node_id: String,
    /// Node's account address (if applicable)
    pub address: Option<Address>,
    /// Node's role in the network
    pub role: NetworkRole,
    /// Listen addresses
    pub listen_addresses: Vec<SocketAddr>,
    /// Public addresses (for NAT traversal)
    pub public_addresses: Vec<SocketAddr>,
    /// Protocol version
    pub protocol_version: u32,
    /// User agent string
    pub user_agent: String,
    /// Node start time
    pub start_time: Timestamp,
    /// Node configuration
    pub config: NodeConfiguration,
}

impl NodeInfo {
    /// Creates a new NodeInfo
    pub fn new(node_id: String, role: NetworkRole) -> Self {
        Self {
            node_id,
            address: None,
            role,
            listen_addresses: Vec::new(),
            public_addresses: Vec::new(),
            protocol_version: 1,
            user_agent: "tenzro/1.0".to_string(),
            start_time: Timestamp::now(),
            config: NodeConfiguration::default(),
        }
    }

    /// Sets the node's account address
    pub fn with_address(mut self, address: Address) -> Self {
        self.address = Some(address);
        self
    }

    /// Adds a listen address
    pub fn add_listen_address(&mut self, addr: SocketAddr) {
        if !self.listen_addresses.contains(&addr) {
            self.listen_addresses.push(addr);
        }
    }

    /// Adds a public address
    pub fn add_public_address(&mut self, addr: SocketAddr) {
        if !self.public_addresses.contains(&addr) {
            self.public_addresses.push(addr);
        }
    }

    /// Returns the node uptime in milliseconds
    pub fn uptime(&self) -> i64 {
        Timestamp::now().as_millis() - self.start_time.as_millis()
    }
}

/// Node configuration parameters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeConfiguration {
    /// Maximum number of inbound peers
    pub max_inbound_peers: u32,
    /// Maximum number of outbound peers
    pub max_outbound_peers: u32,
    /// Enable peer discovery
    pub enable_discovery: bool,
    /// Enable metrics collection
    pub enable_metrics: bool,
    /// Enable RPC server
    pub enable_rpc: bool,
    /// RPC listen address
    pub rpc_address: Option<SocketAddr>,
}

impl Default for NodeConfiguration {
    fn default() -> Self {
        Self {
            max_inbound_peers: 50,
            max_outbound_peers: 25,
            enable_discovery: true,
            enable_metrics: true,
            enable_rpc: true,
            rpc_address: None,
        }
    }
}

/// Network statistics
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct NetworkStats {
    /// Total number of connected peers
    pub connected_peers: u32,
    /// Total bytes sent
    pub bytes_sent: u64,
    /// Total bytes received
    pub bytes_received: u64,
    /// Total messages sent
    pub messages_sent: u64,
    /// Total messages received
    pub messages_received: u64,
}

impl NetworkStats {
    /// Records a sent message
    pub fn record_sent(&mut self, bytes: u64) {
        self.messages_sent += 1;
        self.bytes_sent = self.bytes_sent.saturating_add(bytes);
    }

    /// Records a received message
    pub fn record_received(&mut self, bytes: u64) {
        self.messages_received += 1;
        self.bytes_received = self.bytes_received.saturating_add(bytes);
    }
}

/// Full capabilities available to a micro node participant.
///
/// MicroNodes are zero-install full participants — they access everything
/// via JSON-RPC, MCP tools, A2A protocol, or agentic frameworks.
/// All capabilities default to `true` (full participant).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroNodeCapabilities {
    /// AI model inference from network providers
    pub inference: bool,
    /// TNZO payments (send, receive, escrow)
    pub payments: bool,
    /// A2A agent-to-agent collaboration
    pub agent_collaboration: bool,
    /// MCP tool access (24 tools)
    pub mcp_tools: bool,
    /// Task marketplace — request tasks and complete tasks for others
    pub task_execution: bool,
    /// Chain state queries (blocks, transactions, balances)
    pub chain_query: bool,
    /// Smart contract interaction (EVM/SVM/DAML)
    pub smart_contracts: bool,
    /// TEE confidential compute and key management
    pub tee_services: bool,
    /// Cross-chain bridge (Ethereum, Solana, Canton)
    pub bridge: bool,
    /// Governance — proposals and voting
    pub governance: bool,
}

impl Default for MicroNodeCapabilities {
    fn default() -> Self {
        // All capabilities enabled — full participant by default
        Self {
            inference: true,
            payments: true,
            agent_collaboration: true,
            mcp_tools: true,
            task_execution: true,
            chain_query: true,
            smart_contracts: true,
            tee_services: true,
            bridge: true,
            governance: true,
        }
    }
}

/// Information about a registered micro node participant
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MicroNodeInfo {
    /// TDIP decentralized identifier (did:tenzro:...)
    pub did: String,
    /// Auto-provisioned MPC wallet address
    pub wallet_address: String,
    /// Human-readable display name (optional)
    pub display_name: String,
    /// Timestamp when the micro node joined
    pub joined_at: Timestamp,
    /// Entry point: "mcp", "claude", "clawbot", "a2a", "sdk", "api", "cli", "app"
    pub origin: String,
    /// What kind of participant joined
    pub participant_type: MicroNodeParticipantType,
    /// Capabilities available to this micro node
    pub capabilities: MicroNodeCapabilities,
}

impl MicroNodeInfo {
    /// Creates a new MicroNodeInfo with full capabilities
    pub fn new(
        did: String,
        wallet_address: String,
        display_name: String,
        origin: String,
        participant_type: MicroNodeParticipantType,
    ) -> Self {
        Self {
            did,
            wallet_address,
            display_name,
            joined_at: Timestamp::now(),
            origin,
            participant_type,
            capabilities: MicroNodeCapabilities::default(),
        }
    }
}

/// The type of participant joining as a micro node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MicroNodeParticipantType {
    /// A human user (via Claude, ClawBot, CLI, desktop, SDK)
    Human,
    /// An AI agent (via A2A protocol, MCP, agentic framework)
    Agent,
    /// An automated bot or service
    Bot,
}
