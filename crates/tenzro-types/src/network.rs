//! Network types for Tenzro Network
//!
//! This module defines network topology, peer discovery, and node
//! information structures.

use crate::primitives::{Address, Timestamp};
use crate::token::StakeCapacity;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;

/// The role of a node in the Tenzro Network
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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
    /// Compute provider node — rents accelerator capacity for fixed terms.
    /// Distinct from [`Self::ModelProvider`]: serving weights from the
    /// catalogue and renting a card to run someone else's workload are
    /// different obligations and carry different bonds.
    ComputeProvider,
    /// Storage provider node
    StorageProvider,
    /// RPC operator — carries tenant traffic and mints tenant API keys.
    Rpc,
    /// Attestor — an operator that connected a payment rail (bank transfer,
    /// card, ISO 20022) under its own relationship and confirms a settlement
    /// plan's rail legs on it. A payee's evidenced dispute slashes the bond.
    Attestor,
    /// Wallet provider — serves passkey wallets on its own relying-party
    /// domain. Its bond declares that domain, and validators confirm the
    /// domain names the bonding account, so a wallet can show a credential
    /// from that domain as coming from a staked provider. Wallets from
    /// unbonded domains still work; they are only not shown as staked.
    WalletProvider,
    /// Catalog publisher — signs model catalog entries other nodes serve.
    /// Its bond answers for every entry it signs: an entry whose pinned bytes
    /// its source does not hold is a catalog fault that slashes it.
    CatalogPublisher,
    /// Edge/ingress node — terminates public TLS at a controlled DNS name and
    /// host-routes any incoming hostname to whichever fleet node holds the
    /// content, serving locally or forwarding over p2p. It also serves the
    /// relay at the URL its bond publishes, which nodes admit as a relay.
    /// Any operator can run one; it is a public front door, not a consensus
    /// participant.
    Edge,
    /// Archive node (stores full history)
    Archive,
    /// Bootstrap/seed node
    Bootstrap,
    /// Micro node / participant — ultra-lightweight, no P2P required.
    /// Humans or AI agents joining via MCP server, Claude, ClawBot,
    /// or other agentic frameworks. Auto-provisioned DID + permissionless wallet.
    MicroNode,
}

/// Governed keys of the bond amounts, each in whole TNZO, in the order of
/// [`StakeLadder::from_whole_tnzo`].
pub const STAKE_PARAMS: [&str; 12] = [
    "stake.validator_tnzo",
    "stake.rpc_tnzo",
    "stake.attestor_tnzo",
    "stake.wallet_tnzo",
    "stake.catalog_tnzo",
    "stake.tee_tnzo",
    "stake.ai_tnzo",
    "stake.compute_floor_tnzo",
    "stake.compute_per_accelerator_tnzo",
    "stake.storage_floor_tnzo",
    "stake.storage_per_tb_tnzo",
    "stake.edge_tnzo",
];

/// The bond amounts every role is held to, in wei. Each is a governed
/// parameter ([`STAKE_PARAMS`]); chain state holds the values in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakeLadder {
    /// Validator self-stake admitted to the active set.
    #[serde(with = "crate::primitives::u128_serde")]
    pub validator: u128,
    /// RPC operator.
    #[serde(with = "crate::primitives::u128_serde")]
    pub rpc: u128,
    /// Attestor; also admits it to bridge committees and reserve attestation.
    #[serde(with = "crate::primitives::u128_serde")]
    pub attestor: u128,
    /// Wallet provider.
    #[serde(with = "crate::primitives::u128_serde")]
    pub wallet: u128,
    /// Catalog publisher.
    #[serde(with = "crate::primitives::u128_serde")]
    pub catalog: u128,
    /// TEE provider.
    #[serde(with = "crate::primitives::u128_serde")]
    pub tee: u128,
    /// Model provider.
    #[serde(with = "crate::primitives::u128_serde")]
    pub model: u128,
    /// Compute provider floor.
    #[serde(with = "crate::primitives::u128_serde")]
    pub compute_floor: u128,
    /// Compute bond per accelerator at consumer class, before its multiplier.
    #[serde(with = "crate::primitives::u128_serde")]
    pub compute_per_accelerator: u128,
    /// Storage provider floor.
    #[serde(with = "crate::primitives::u128_serde")]
    pub storage_floor: u128,
    /// Storage bond per whole terabyte pledged.
    #[serde(with = "crate::primitives::u128_serde")]
    pub storage_per_tb: u128,
    /// Edge operator, which serves a relay at the URL its bond publishes.
    #[serde(with = "crate::primitives::u128_serde")]
    pub edge: u128,
}

impl StakeLadder {
    /// The ladder from `whole_tnzo(key)`, the value in whole TNZO of each
    /// key of [`STAKE_PARAMS`].
    pub fn from_whole_tnzo(whole_tnzo: impl Fn(&'static str) -> u64) -> Self {
        let v = |i: usize| {
            u128::from(whole_tnzo(STAKE_PARAMS[i])).saturating_mul(crate::constants::ONE_TNZO)
        };
        Self {
            validator: v(0),
            rpc: v(1),
            attestor: v(2),
            wallet: v(3),
            catalog: v(4),
            tee: v(5),
            model: v(6),
            compute_floor: v(7),
            compute_per_accelerator: v(8),
            storage_floor: v(9),
            storage_per_tb: v(10),
            edge: v(11),
        }
    }

    /// Every amount passed through `f`.
    pub fn map(self, f: impl Fn(u128) -> u128) -> Self {
        Self {
            validator: f(self.validator),
            rpc: f(self.rpc),
            attestor: f(self.attestor),
            wallet: f(self.wallet),
            catalog: f(self.catalog),
            tee: f(self.tee),
            model: f(self.model),
            compute_floor: f(self.compute_floor),
            compute_per_accelerator: f(self.compute_per_accelerator),
            storage_floor: f(self.storage_floor),
            storage_per_tb: f(self.storage_per_tb),
            edge: f(self.edge),
        }
    }

    /// The genesis ladder: the bond amounts the network starts with.
    pub fn genesis() -> Self {
        use crate::constants::*;
        let t = |wei: u128| (wei / ONE_TNZO) as u64;
        let genesis = [
            t(MIN_VALIDATOR_STAKE),
            t(MIN_RPC_OPERATOR_STAKE),
            t(MIN_ATTESTOR_STAKE),
            t(MIN_WALLET_PROVIDER_STAKE),
            t(MIN_CATALOG_PUBLISHER_STAKE),
            t(MIN_TEE_PROVIDER_STAKE),
            t(MIN_MODEL_PROVIDER_STAKE),
            t(MIN_COMPUTE_PROVIDER_STAKE),
            t(COMPUTE_STAKE_PER_ACCELERATOR),
            t(MIN_STORAGE_PROVIDER_STAKE),
            t(STORAGE_STAKE_PER_TB),
            t(MIN_EDGE_OPERATOR_STAKE),
        ];
        Self::from_whole_tnzo(|key| {
            let i = STAKE_PARAMS.iter().position(|k| *k == key).unwrap_or(0);
            genesis[i]
        })
    }

    /// The genesis value, whole TNZO, of the bond parameter `key`.
    pub fn genesis_whole_tnzo(key: &str) -> Option<u64> {
        let g = Self::genesis();
        let all = [
            g.validator,
            g.rpc,
            g.attestor,
            g.wallet,
            g.catalog,
            g.tee,
            g.model,
            g.compute_floor,
            g.compute_per_accelerator,
            g.storage_floor,
            g.storage_per_tb,
            g.edge,
        ];
        let i = STAKE_PARAMS.iter().position(|k| *k == key)?;
        Some((all[i] / crate::constants::ONE_TNZO) as u64)
    }
}

impl NetworkRole {
    /// Every role.
    pub const ALL: [NetworkRole; 15] = [
        Self::Validator,
        Self::FullNode,
        Self::LightClient,
        Self::TeeProvider,
        Self::ModelProvider,
        Self::ComputeProvider,
        Self::StorageProvider,
        Self::Rpc,
        Self::Attestor,
        Self::WalletProvider,
        Self::CatalogPublisher,
        Self::Edge,
        Self::Archive,
        Self::Bootstrap,
        Self::MicroNode,
    ];

    /// Checks if this role can validate blocks
    pub fn is_validator(&self) -> bool {
        matches!(self, Self::Validator)
    }

    /// Checks if this role is a provider
    pub fn is_provider(&self) -> bool {
        matches!(
            self,
            Self::TeeProvider
                | Self::ModelProvider
                | Self::ComputeProvider
                | Self::StorageProvider
                | Self::Rpc
        )
    }

    /// Whether serving this role takes a bond. A validator bonds through
    /// `RegisterValidator`; every other bonded role through a `Stake` bond for
    /// that role.
    pub fn requires_bond(&self) -> bool {
        self.is_validator()
            || self.is_provider()
            || matches!(
                self,
                Self::Attestor | Self::WalletProvider | Self::CatalogPublisher | Self::Edge
            )
    }

    /// Bond this role requires for the declared `capacity` under the bond
    /// amounts in force (`ladder`), or zero for a role that takes none.
    ///
    /// Capacity is ignored by roles that do not scale, so passing
    /// [`StakeCapacity::None`] to a scaling role yields that role's floor
    /// rather than zero — bonding is never free.
    pub fn required_stake(&self, capacity: &StakeCapacity, ladder: &StakeLadder) -> u128 {
        match self {
            Self::Validator => ladder.validator,
            Self::Rpc => ladder.rpc,
            Self::Attestor => ladder.attestor,
            Self::WalletProvider => ladder.wallet,
            Self::CatalogPublisher => ladder.catalog,
            Self::TeeProvider => ladder.tee,
            Self::ModelProvider => ladder.model,
            Self::ComputeProvider => {
                let pledged = match capacity {
                    StakeCapacity::Accelerators(classes) => classes
                        .iter()
                        .map(|c| {
                            ladder
                                .compute_per_accelerator
                                .saturating_mul(c.stake_multiplier_bps() as u128)
                                / 10_000
                        })
                        .fold(0u128, |acc, v| acc.saturating_add(v)),
                    _ => 0,
                };
                pledged.max(ladder.compute_floor)
            }
            Self::StorageProvider => {
                let pledged = match capacity {
                    StakeCapacity::Terabytes(tb) => {
                        ladder.storage_per_tb.saturating_mul(*tb as u128)
                    }
                    _ => 0,
                };
                pledged.max(ladder.storage_floor)
            }
            Self::Edge => ladder.edge,
            Self::FullNode
            | Self::LightClient
            | Self::Archive
            | Self::Bootstrap
            | Self::MicroNode => 0,
        }
    }

    /// Checks if this role terminates public TLS and host-routes ingress.
    pub fn is_edge(&self) -> bool {
        matches!(self, Self::Edge)
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

    /// Lowercase wire/CLI token for this role.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Validator => "validator",
            Self::FullNode => "fullnode",
            Self::LightClient => "light",
            Self::TeeProvider => "tee",
            Self::ModelProvider => "ai",
            Self::ComputeProvider => "compute",
            Self::StorageProvider => "storage",
            Self::Edge => "edge",
            Self::Archive => "archive",
            Self::Bootstrap => "bootstrap",
            Self::MicroNode => "micro",
            Self::Rpc => "rpc",
            Self::Attestor => "attestor",
            Self::WalletProvider => "wallet",
            Self::CatalogPublisher => "catalog",
        }
    }
}

/// Serde for a [`NetworkRole`] as its wire token (`ai`, `rpc`, `storage`...),
/// the spelling `--roles` and every client use.
pub mod role_token {
    use super::NetworkRole;
    use serde::{Deserialize, Deserializer, Serializer};
    use std::str::FromStr;

    pub fn serialize<S: Serializer>(role: &NetworkRole, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(role.as_str())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<NetworkRole, D::Error> {
        let token = String::deserialize(d)?;
        NetworkRole::from_str(&token).map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for NetworkRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for NetworkRole {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Hyphen and underscore spellings are interchangeable, so
        // `model-provider` and `model_provider` both resolve.
        let normalized = s.trim().to_ascii_lowercase().replace('-', "_");
        match normalized.as_str() {
            "validator" => Ok(Self::Validator),
            "fullnode" | "full" | "full_node" => Ok(Self::FullNode),
            "light" | "lightclient" | "light_client" => Ok(Self::LightClient),
            "tee" | "teeprovider" | "tee_provider" => Ok(Self::TeeProvider),
            "ai" | "model" | "modelprovider" | "model_provider" | "inference" => {
                Ok(Self::ModelProvider)
            }
            "compute" | "computeprovider" | "compute_provider" | "gpu" => Ok(Self::ComputeProvider),
            "storage" | "storageprovider" | "storage_provider" => Ok(Self::StorageProvider),
            "edge" | "ingress" => Ok(Self::Edge),
            "archive" => Ok(Self::Archive),
            "bootstrap" | "seed" => Ok(Self::Bootstrap),
            "micro" | "micronode" | "user" => Ok(Self::MicroNode),
            "rpc" => Ok(Self::Rpc),
            "attestor" => Ok(Self::Attestor),
            "wallet" | "walletprovider" | "wallet_provider" => Ok(Self::WalletProvider),
            "catalog" | "catalogpublisher" | "catalog_publisher" | "publisher" => {
                Ok(Self::CatalogPublisher)
            }
            other => Err(format!("unknown network role: {other}")),
        }
    }
}

/// A set of roles a single node serves simultaneously.
///
/// A node stakes once and may serve many roles — validating consensus while
/// also providing AI inference and hosting storage. The roles are reward tiers
/// layered on one identity, not separate eligibility gates. Order is
/// normalized (sorted, deduplicated) so equal role combinations compare equal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleSet(BTreeSet<NetworkRole>);

impl RoleSet {
    /// A lightweight client/participant with no service obligations.
    pub fn client() -> Self {
        let mut s = BTreeSet::new();
        s.insert(NetworkRole::MicroNode);
        Self(s)
    }

    /// A pure validator with no extra service roles.
    pub fn validator_only() -> Self {
        let mut s = BTreeSet::new();
        s.insert(NetworkRole::Validator);
        Self(s)
    }

    /// A storage provider that does not validate.
    pub fn storage_only() -> Self {
        let mut s = BTreeSet::new();
        s.insert(NetworkRole::StorageProvider);
        Self(s)
    }

    /// A validator that also serves AI inference and storage.
    pub fn full_provider() -> Self {
        let mut s = BTreeSet::new();
        s.insert(NetworkRole::Validator);
        s.insert(NetworkRole::ModelProvider);
        s.insert(NetworkRole::StorageProvider);
        Self(s)
    }

    /// Builds a role set from an iterator of roles. Empty input falls back to
    /// a client role so a node always has at least one role.
    pub fn from_roles(roles: impl IntoIterator<Item = NetworkRole>) -> Self {
        let set: BTreeSet<NetworkRole> = roles.into_iter().collect();
        if set.is_empty() {
            Self::client()
        } else {
            Self(set)
        }
    }

    /// Adds a role to the set.
    pub fn insert(&mut self, role: NetworkRole) {
        self.0.insert(role);
    }

    /// True if the node serves the given role.
    pub fn has(&self, role: NetworkRole) -> bool {
        self.0.contains(&role)
    }

    /// True if the node participates in consensus.
    pub fn is_validator(&self) -> bool {
        self.has(NetworkRole::Validator)
    }

    /// True if the node offers AI model inference.
    pub fn serves_ai(&self) -> bool {
        self.has(NetworkRole::ModelProvider)
    }

    /// True if the node hosts decentralized storage.
    pub fn serves_storage(&self) -> bool {
        self.has(NetworkRole::StorageProvider)
    }

    /// True if the node rents its accelerators out by the hour.
    pub fn serves_compute(&self) -> bool {
        self.has(NetworkRole::ComputeProvider)
    }

    /// True if the node offers TEE confidential compute.
    pub fn serves_tee(&self) -> bool {
        self.has(NetworkRole::TeeProvider)
    }

    /// True if the node terminates public TLS and host-routes ingress.
    pub fn serves_edge(&self) -> bool {
        self.has(NetworkRole::Edge)
    }

    /// True if the node provides any paid service (AI, storage, or TEE).
    pub fn is_provider(&self) -> bool {
        self.0.iter().any(NetworkRole::is_provider)
    }

    /// The primary role used where a single role is required (peer
    /// announcement). Validator wins, then any provider role, then whatever
    /// remains.
    pub fn primary(&self) -> NetworkRole {
        if self.is_validator() {
            NetworkRole::Validator
        } else if let Some(provider) = self.0.iter().find(|r| r.is_provider()) {
            *provider
        } else {
            self.0
                .iter()
                .next()
                .copied()
                .unwrap_or(NetworkRole::MicroNode)
        }
    }

    /// Iterates over the roles in normalized order.
    pub fn iter(&self) -> impl Iterator<Item = NetworkRole> + '_ {
        self.0.iter().copied()
    }

    /// Number of roles in the set.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True if the set somehow holds no roles (should not happen via the
    /// constructors, which always fall back to a client role).
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for RoleSet {
    fn default() -> Self {
        Self::client()
    }
}

impl fmt::Display for RoleSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let joined = self
            .0
            .iter()
            .map(NetworkRole::as_str)
            .collect::<Vec<_>>()
            .join(",");
        f.write_str(&joined)
    }
}

impl FromStr for RoleSet {
    type Err = String;

    /// Parses a comma-separated role list, e.g. `"validator,storage,ai"`.
    /// Whitespace around tokens is ignored. An empty string yields a client.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut set = BTreeSet::new();
        for token in s.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            set.insert(NetworkRole::from_str(token)?);
        }
        Ok(if set.is_empty() {
            Self::client()
        } else {
            Self(set)
        })
    }
}

impl From<NetworkRole> for RoleSet {
    fn from(role: NetworkRole) -> Self {
        let mut s = BTreeSet::new();
        s.insert(role);
        Self(s)
    }
}

/// Information about a peer in the network
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerInfo {
    /// Peer's unique identifier
    pub peer_id: String,
    /// Peer's network addresses
    pub addresses: Vec<SocketAddr>,
    /// Every role this peer serves (a node may validate while also providing
    /// AI/storage). Discovery and role-filtered queries match on set membership.
    pub roles: RoleSet,
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
    pub fn new(peer_id: String, addresses: Vec<SocketAddr>, roles: RoleSet) -> Self {
        Self {
            peer_id,
            addresses,
            roles,
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
    /// Every role this node serves. A node stakes once and may hold many roles
    /// at once (validator + AI + storage); service roles are reward tiers on one
    /// identity, not separate eligibility gates.
    pub roles: RoleSet,
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
    pub fn new(node_id: String, roles: RoleSet) -> Self {
        Self {
            node_id,
            address: None,
            roles,
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
    /// Smart contract interaction (EVM/SVM)
    pub smart_contracts: bool,
    /// Confidential compute inside a TEE: secure inference, secure training,
    /// ZK proving, and the attestation that makes each checkable.
    ///
    /// Not custody. A node advertising this is offering to run a workload the
    /// host cannot read — it is not offering to hold anyone's keys, and
    /// nothing in the identity model roots authority in an enclave.
    pub tee_services: bool,
    /// Cross-chain bridge (Ethereum, Solana)
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
    /// Auto-provisioned permissionless wallet address
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_roundtrips_through_str() {
        // Every variant, so adding one without a matching `as_str` /
        // `FromStr` arm fails here rather than silently shipping a role that
        // cannot survive the `--roles` CLI round trip.
        for role in [
            NetworkRole::Validator,
            NetworkRole::FullNode,
            NetworkRole::LightClient,
            NetworkRole::TeeProvider,
            NetworkRole::ModelProvider,
            NetworkRole::ComputeProvider,
            NetworkRole::StorageProvider,
            NetworkRole::Attestor,
            NetworkRole::WalletProvider,
            NetworkRole::CatalogPublisher,
            NetworkRole::Edge,
            NetworkRole::Archive,
            NetworkRole::Bootstrap,
            NetworkRole::MicroNode,
        ] {
            assert_eq!(NetworkRole::from_str(role.as_str()).unwrap(), role);
        }
    }

    #[test]
    fn parses_comma_separated_roles() {
        let set: RoleSet = "validator,storage,ai".parse().unwrap();
        assert!(set.is_validator());
        assert!(set.serves_storage());
        assert!(set.serves_ai());
        assert!(!set.serves_tee());
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn parse_is_order_and_whitespace_insensitive() {
        let a: RoleSet = "ai, validator ,storage".parse().unwrap();
        let b: RoleSet = "storage,validator,ai".parse().unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn display_is_normalized_and_reparses() {
        let set: RoleSet = "storage,validator".parse().unwrap();
        let reparsed: RoleSet = set.to_string().parse().unwrap();
        assert_eq!(set, reparsed);
    }

    #[test]
    fn empty_string_yields_client() {
        let set: RoleSet = "".parse().unwrap();
        assert_eq!(set, RoleSet::client());
        assert!(!set.is_validator());
    }

    #[test]
    fn unknown_role_errors() {
        assert!("validator,bogus".parse::<RoleSet>().is_err());
    }

    #[test]
    fn underscored_aliases_parse_to_canonical_roles() {
        let set: RoleSet = "model_provider,storage_provider,tee_provider"
            .parse()
            .unwrap();
        assert!(set.serves_ai());
        assert!(set.serves_storage());
        assert!(set.serves_tee());
    }

    #[test]
    fn primary_prefers_validator_then_provider() {
        assert_eq!(RoleSet::full_provider().primary(), NetworkRole::Validator);
        let provider: RoleSet = "storage,ai".parse().unwrap();
        assert!(provider.primary().is_provider());
        assert_eq!(RoleSet::client().primary(), NetworkRole::MicroNode);
    }

    #[test]
    fn from_empty_roles_falls_back_to_client() {
        assert_eq!(RoleSet::from_roles([]), RoleSet::client());
    }
}
