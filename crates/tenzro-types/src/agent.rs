//! AI Agent types for Tenzro Network
//!
//! This module defines types for AI agents, their capabilities,
//! configuration, and communication on the network.

use crate::primitives::{Address, Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// AI agent identity on Tenzro Network
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentIdentity {
    /// Unique agent identifier
    pub agent_id: String,
    /// Agent's on-chain address
    pub address: Address,
    /// Agent name
    pub name: String,
    /// Agent version
    pub version: String,
    /// Agent creator/owner
    pub creator: Address,
}

impl AgentIdentity {
    /// Creates a new agent identity
    pub fn new(agent_id: String, address: Address, name: String, creator: Address) -> Self {
        Self {
            agent_id,
            address,
            name,
            version: "1.0.0".to_string(),
            creator,
        }
    }

    /// Sets the version
    pub fn with_version(mut self, version: String) -> Self {
        self.version = version;
        self
    }
}

/// AI agent configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Agent identity
    pub identity: AgentIdentity,
    /// Agent capabilities
    pub capabilities: Vec<Capability>,
    /// Agent description
    pub description: String,
    /// Execution environment requirements
    pub execution_requirements: ExecutionRequirements,
    /// Agent permissions
    pub permissions: AgentPermissions,
    /// Resource limits
    pub resource_limits: ResourceLimits,
    /// Configuration metadata
    pub metadata: HashMap<String, String>,
}

impl AgentConfig {
    /// Creates a new agent configuration
    pub fn new(identity: AgentIdentity, capabilities: Vec<Capability>) -> Self {
        Self {
            identity,
            capabilities,
            description: String::new(),
            execution_requirements: ExecutionRequirements::default(),
            permissions: AgentPermissions::default(),
            resource_limits: ResourceLimits::default(),
            metadata: HashMap::new(),
        }
    }

    /// Adds a description
    pub fn with_description(mut self, description: String) -> Self {
        self.description = description;
        self
    }

    /// Adds metadata
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
}

/// Capabilities that an AI agent can perform
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "config")]
pub enum Capability {
    /// Natural language processing
    NaturalLanguageProcessing {
        /// Supported languages
        languages: Vec<String>,
    },
    /// Computer vision
    ComputerVision {
        /// Supported vision tasks
        tasks: Vec<String>,
    },
    /// Code generation and analysis
    CodeGeneration {
        /// Supported programming languages
        languages: Vec<String>,
    },
    /// Data analysis
    DataAnalysis {
        /// Supported data formats
        formats: Vec<String>,
    },
    /// Blockchain interaction
    BlockchainInteraction {
        /// Supported chains
        chains: Vec<String>,
    },
    /// Smart contract execution
    SmartContractExecution,
    /// External API integration
    ExternalAPIIntegration {
        /// Supported APIs
        apis: Vec<String>,
    },
    /// Multi-agent coordination
    MultiAgentCoordination,
    /// Custom capability
    Custom {
        /// Capability name
        name: String,
        /// Capability parameters
        parameters: HashMap<String, String>,
    },
}

/// Execution environment requirements for an agent
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionRequirements {
    /// Requires TEE execution
    pub requires_tee: bool,
    /// Required TEE vendor (if any)
    pub tee_vendor: Option<String>,
    /// Minimum memory (bytes)
    pub min_memory: u64,
    /// Minimum CPU cores
    pub min_cpu_cores: u32,
    /// Requires GPU
    pub requires_gpu: bool,
    /// Network access required
    pub requires_network: bool,
}

impl Default for ExecutionRequirements {
    fn default() -> Self {
        Self {
            requires_tee: false,
            tee_vendor: None,
            min_memory: 1024 * 1024 * 512, // 512 MB
            min_cpu_cores: 1,
            requires_gpu: false,
            requires_network: true,
        }
    }
}

/// Agent permissions
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPermissions {
    /// Can execute transactions
    pub can_execute_transactions: bool,
    /// Can access external APIs
    pub can_access_external_apis: bool,
    /// Can interact with other agents
    pub can_interact_with_agents: bool,
    /// Can store data on-chain
    pub can_store_data: bool,
    /// Maximum transaction value (in smallest TNZO unit)
    pub max_transaction_value: u64,
    /// Allowed contract addresses
    pub allowed_contracts: Vec<Address>,
}

impl Default for AgentPermissions {
    fn default() -> Self {
        Self {
            can_execute_transactions: false,
            can_access_external_apis: true,
            can_interact_with_agents: true,
            can_store_data: true,
            max_transaction_value: 0,
            allowed_contracts: Vec::new(),
        }
    }
}

/// Resource limits for agent execution
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Maximum execution time (milliseconds)
    pub max_execution_time: u64,
    /// Maximum memory usage (bytes)
    pub max_memory: u64,
    /// Maximum CPU usage percentage
    pub max_cpu_percent: u8,
    /// Maximum storage (bytes)
    pub max_storage: u64,
    /// Maximum API calls per execution
    pub max_api_calls: u32,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_execution_time: 60_000, // 60 seconds
            max_memory: 1024 * 1024 * 1024, // 1 GB
            max_cpu_percent: 80,
            max_storage: 1024 * 1024 * 100, // 100 MB
            max_api_calls: 100,
        }
    }
}

/// A message between agents on Tenzro Network
///
/// Wave 3d hybrid signing: signed messages carry BOTH `signature` (Ed25519
/// classical) and `pq_signature` (ML-DSA-65). When the message is signed,
/// both legs are `Some(_)`. When the message is unsigned (trusted
/// single-process tests), both legs are `None`. Mixing — one `Some`, one
/// `None` — is rejected by the router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentMessage {
    /// Message ID
    pub message_id: String,
    /// Sender agent
    pub from: AgentIdentity,
    /// Recipient agent
    pub to: AgentIdentity,
    /// Message type
    pub message_type: AgentMessageType,
    /// Message payload
    pub payload: Vec<u8>,
    /// Message timestamp
    pub timestamp: Timestamp,
    /// Classical Ed25519 message signature (None when unsigned)
    pub signature: Option<Vec<u8>>,
    /// Post-quantum ML-DSA-65 message signature (3309 bytes when signed,
    /// None when unsigned). Must be present whenever `signature` is present.
    pub pq_signature: Option<Vec<u8>>,
    /// Reply-to message ID (if this is a reply)
    pub reply_to: Option<String>,
}

impl AgentMessage {
    /// Creates a new agent message
    pub fn new(
        from: AgentIdentity,
        to: AgentIdentity,
        message_type: AgentMessageType,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            message_id: uuid::Uuid::new_v4().to_string(),
            from,
            to,
            message_type,
            payload,
            timestamp: Timestamp::now(),
            signature: None,
            pq_signature: None,
            reply_to: None,
        }
    }

    /// Sets the message as a reply to another message
    pub fn as_reply_to(mut self, message_id: String) -> Self {
        self.reply_to = Some(message_id);
        self
    }

    /// Adds a classical-only signature to the message.
    ///
    /// Wave 3d hybrid signing: this is the classical (Ed25519) leg only.
    /// Production agent message production should call `with_hybrid_signature`
    /// instead so both legs are populated; the router rejects messages with
    /// only the classical leg present.
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Adds a full hybrid (Ed25519 + ML-DSA-65) signature to the message.
    pub fn with_hybrid_signature(
        mut self,
        classical: Vec<u8>,
        pq: Vec<u8>,
    ) -> Self {
        self.signature = Some(classical);
        self.pq_signature = Some(pq);
        self
    }

    /// Returns the canonical bytes that should be signed.
    ///
    /// This deliberately **excludes** the `signature` field so that signing
    /// followed by verifying yields a stable hash. The encoding is a simple
    /// length-prefixed concatenation of the message-determining fields:
    ///
    /// ```text
    /// signing_data = len(message_id) || message_id
    ///              || from.agent_id_len || from.agent_id || from.address
    ///              || to.agent_id_len   || to.agent_id   || to.address
    ///              || message_type_tag (u8)
    ///              || payload_len (u64 LE) || payload
    ///              || timestamp_millis (i64 LE)
    ///              || reply_to_present (u8) [|| reply_to_len || reply_to]
    /// ```
    ///
    /// All `len()` fields are encoded as little-endian `u64` for
    /// deterministic, length-prefixed framing. This avoids ambiguity attacks
    /// where two different field arrangements collide into the same byte
    /// stream (e.g. concatenating two strings without a length prefix).
    pub fn signing_data(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256 + self.payload.len());

        // message_id
        buf.extend_from_slice(&(self.message_id.len() as u64).to_le_bytes());
        buf.extend_from_slice(self.message_id.as_bytes());

        // from agent identity
        buf.extend_from_slice(&(self.from.agent_id.len() as u64).to_le_bytes());
        buf.extend_from_slice(self.from.agent_id.as_bytes());
        buf.extend_from_slice(self.from.address.as_bytes());

        // to agent identity
        buf.extend_from_slice(&(self.to.agent_id.len() as u64).to_le_bytes());
        buf.extend_from_slice(self.to.agent_id.as_bytes());
        buf.extend_from_slice(self.to.address.as_bytes());

        // message_type as a single tag byte
        buf.push(self.message_type as u8);

        // payload (length-prefixed)
        buf.extend_from_slice(&(self.payload.len() as u64).to_le_bytes());
        buf.extend_from_slice(&self.payload);

        // timestamp
        buf.extend_from_slice(&self.timestamp.0.to_le_bytes());

        // optional reply_to (1-byte presence flag, then length-prefixed value)
        match &self.reply_to {
            Some(reply) => {
                buf.push(1);
                buf.extend_from_slice(&(reply.len() as u64).to_le_bytes());
                buf.extend_from_slice(reply.as_bytes());
            }
            None => {
                buf.push(0);
            }
        }

        buf
    }

    /// Computes the SHA-256 hash of the message's canonical signing data.
    ///
    /// This is the value passed to a signer when producing the
    /// `signature` field, and the value verified against the public key
    /// when validating an inbound message. Because it is computed from
    /// [`Self::signing_data`], the `signature` field itself is **not**
    /// included in the hash, so signing is idempotent.
    pub fn hash(&self) -> Hash {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.signing_data());
        let digest = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        Hash::new(bytes)
    }
}

/// Types of agent-to-agent messages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentMessageType {
    /// Request for task execution
    TaskRequest,
    /// Response to a task request
    TaskResponse,
    /// Query for information
    Query,
    /// Response to a query
    QueryResponse,
    /// Notification
    Notification,
    /// Coordination message for multi-agent tasks
    Coordination,
    /// Error message
    Error,
    /// Request to spawn a new sub-agent
    SpawnRequest,
    /// Confirmation that a sub-agent was successfully spawned
    SpawnConfirmation,
    /// Orchestrator dispatching a task to a swarm member
    SwarmCoordination,
    /// Swarm member returning result to orchestrator
    SwarmResult,
}

/// A tool call made by an agent during autonomous execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentToolCall {
    /// Tool name: "spawn_agent" | "delegate_task" | "collect_results" | "complete"
    pub tool_name: String,
    /// Tool arguments as JSON
    pub arguments: serde_json::Value,
}

/// Configuration for a swarm of agents
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmConfig {
    /// Maximum number of member agents (default: 10)
    pub max_members: usize,
    /// Per-task timeout in seconds (default: 300)
    pub task_timeout_secs: u64,
    /// Whether to dispatch tasks in parallel (default: true)
    pub parallel: bool,
}

impl Default for SwarmConfig {
    fn default() -> Self {
        Self {
            max_members: 10,
            task_timeout_secs: 300,
            parallel: true,
        }
    }
}

/// A member of an agent swarm
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwarmMember {
    /// Agent ID of this member
    pub agent_id: String,
    /// Role/name of this member in the swarm
    pub role: String,
    /// Current status of this member
    pub status: SwarmMemberStatus,
    /// Result produced by this member (if completed)
    pub result: Option<String>,
}

/// Status of a swarm member
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SwarmMemberStatus {
    /// Idle, waiting for a task
    Idle,
    /// Currently executing a task
    Working,
    /// Successfully completed its task
    Completed,
    /// Failed to complete its task
    Failed(String),
}
