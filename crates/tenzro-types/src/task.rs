//! Task marketplace types for Tenzro Network
//!
//! Defines the types for the decentralized task marketplace where
//! agents and users can post tasks for AI agents to discover and fulfill.

use crate::primitives::{Address, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Status of a task in the marketplace
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskStatus {
    /// Task is open and available for agents to bid on / accept
    Open,
    /// Task has been assigned to a specific agent
    Assigned,
    /// Task is actively being worked on
    InProgress,
    /// Task has been completed successfully
    Completed,
    /// Task was cancelled by the poster
    Cancelled,
    /// Task deadline passed without completion
    Expired,
    /// Task is in dispute
    Disputed,
}

/// Type of task being requested
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskType {
    /// AI inference/completion task
    Inference,
    /// Code review or generation task
    CodeReview,
    /// Data analysis task
    DataAnalysis,
    /// Content generation task
    ContentGeneration,
    /// Execute an agent from the agent marketplace
    AgentExecution,
    /// Translation task
    Translation,
    /// Research task
    Research,
    /// Custom task type
    Custom(String),
}

impl TaskType {
    pub fn as_str(&self) -> &str {
        match self {
            TaskType::Inference => "inference",
            TaskType::CodeReview => "code_review",
            TaskType::DataAnalysis => "data_analysis",
            TaskType::ContentGeneration => "content_generation",
            TaskType::AgentExecution => "agent_execution",
            TaskType::Translation => "translation",
            TaskType::Research => "research",
            TaskType::Custom(s) => s.as_str(),
        }
    }
}

/// Priority level for a task
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum TaskPriority {
    Low,
    #[default]
    Normal,
    High,
    Urgent,
}

/// The class of proof a task completion must carry to be accepted.
///
/// These variants map 1:1 onto `tenzro_settlement::SettlementEngine`'s proof
/// dispatch (ZeroKnowledge / TeeAttestation / Cryptographic / Oracle / Merkle).
/// We keep a self-contained copy here so `tenzro-types` does not depend on the
/// settlement crate (settlement depends on types, not the reverse).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ProofRequirement {
    /// A zero-knowledge proof, optionally pinned to a circuit and/or the model
    /// the inference was claimed to run on.
    ZeroKnowledge {
        #[serde(default)]
        circuit_id: Option<String>,
        #[serde(default)]
        model_id: Option<String>,
    },
    /// A TEE attestation report, optionally restricted to a provider/enclave class.
    TeeAttestation {
        #[serde(default)]
        provider_class: Option<String>,
    },
    /// A plain cryptographic signature over the result by the provider.
    Cryptographic,
    /// An oracle-signed attestation of the result.
    Oracle,
    /// A Merkle inclusion proof against a poster-pinned root. The completion
    /// proof's `proof_data` must be `leaf(32) ‖ leaf_index(u32-le, 4) ‖
    /// siblings(32·k)`; the task layer recomputes the positional SHA-256 root
    /// and requires it to equal `expected_root`.
    Merkle {
        /// Hex Merkle root (poster-supplied, trusted task state) the inclusion
        /// proof must reproduce. `0x` prefix optional; compared case-insensitively.
        expected_root: String,
    },
}

/// Structured acceptance criteria for a task (lifecycle Stage 1 / P1).
///
/// When present on a `TaskInfo`, `tenzro_completeTask` validates the submitted
/// output and, if `required_proof` is set, routes the completion proof through
/// the `SettlementEngine` proof dispatch before releasing escrow.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct AcceptanceCriteria {
    /// Proof the completion must carry (None = free-form, no proof gate).
    #[serde(default)]
    pub required_proof: Option<ProofRequirement>,
    /// Required output MIME/format, e.g. "markdown", "application/json".
    #[serde(default)]
    pub format: Option<String>,
    /// Minimum word count of the textual output.
    #[serde(default)]
    pub min_word_count: Option<u64>,
    /// Sections/keys that must be present in the output.
    #[serde(default)]
    pub required_sections: Vec<String>,
    /// Arbitrary additional structured constraints (free-form key/value).
    #[serde(default)]
    pub constraints: HashMap<String, String>,
}

/// A Merkle inclusion proof that a provider holds an ERC-8004 reputation leaf
/// at or above some score, without an RPC round-trip to read the registry
/// (lifecycle Stage 2 / P3). The poster recomputes the root from
/// `leaf` + `merkle_path` and compares it to the on-chain `ReputationRegistry`
/// root for `registry_root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReputationProof {
    /// ERC-8004 agent id (decimal string) the leaf belongs to.
    pub agent_id: String,
    /// Score claimed by this proof.
    pub claimed_score: u32,
    /// Expected Merkle root (hex), matched against the registry's published root.
    pub registry_root: String,
    /// Hex-encoded leaf preimage hash for `(agent_id, claimed_score)`.
    pub leaf: String,
    /// Sibling hashes (hex) from leaf to root, in order.
    pub merkle_path: Vec<String>,
    /// Index of the leaf in the tree (determines left/right hashing order).
    pub leaf_index: u64,
}

/// Dispute state attached to a task (lifecycle P4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskDispute {
    /// Who raised the dispute.
    pub raised_by: Address,
    /// Human-readable reason.
    pub reason: String,
    /// When it was raised.
    pub raised_at: Timestamp,
    /// Resolution once an oracle/governance hook arbitrates (None while open).
    #[serde(default)]
    pub resolution: Option<DisputeResolution>,
}

/// Outcome of an arbitrated task dispute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputeResolution {
    /// Escrow released to the assignee (provider wins).
    ReleaseToProvider,
    /// Escrow refunded to the poster (poster wins).
    RefundToPoster,
}

/// A task posted to the Tenzro Network task marketplace
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskInfo {
    /// Unique task identifier (UUID v4)
    pub task_id: String,

    /// Short title describing the task
    pub title: String,

    /// Detailed description of the task and expected output
    pub description: String,

    /// Type of task
    pub task_type: TaskType,

    /// Address of the entity that posted the task
    pub poster: Address,

    /// Optional: agent assigned to fulfill the task
    pub assignee: Option<Address>,

    /// Maximum price the poster is willing to pay (in TNZO micro-units)
    #[serde(with = "crate::primitives::u128_serde")]
    pub max_price: u128,

    /// Actual price quoted/agreed (set when task is assigned)
    pub quoted_price: Option<u128>,

    /// Current status of the task
    pub status: TaskStatus,

    /// When the task was posted
    pub created_at: Timestamp,

    /// Deadline for task completion (Unix timestamp seconds)
    pub deadline: Option<u64>,

    /// Minimum model capability required (e.g., "7b", "70b", "any")
    pub required_model: Option<String>,

    /// Specific model ID to use (if None, any capable model is acceptable)
    pub preferred_model_id: Option<String>,

    /// Input data or prompt for the task
    pub input: String,

    /// Output/result (populated when completed)
    pub output: Option<String>,

    /// Task priority level
    pub priority: TaskPriority,

    /// Additional task-specific metadata
    pub metadata: HashMap<String, String>,

    /// Transaction hash of the task posting (for escrow reference)
    pub tx_hash: Option<String>,

    /// Structured acceptance criteria / proof spec (Stage 1, P1). When present,
    /// completion must satisfy these constraints and, if `required_proof` is
    /// set, carry a proof verified by the `SettlementEngine`.
    #[serde(default)]
    pub acceptance_criteria: Option<AcceptanceCriteria>,

    /// Escrow id that locks the reward once the task is assigned (Stage 3, P0).
    /// `None` until `tenzro_assignTask` funds the escrow vault.
    #[serde(default)]
    pub escrow_id: Option<String>,

    /// Dispute state (P4). `None` unless `tenzro_disputeTask` was called.
    #[serde(default)]
    pub dispute: Option<TaskDispute>,
}

impl TaskInfo {
    /// Creates a new open task
    pub fn new(
        title: String,
        description: String,
        task_type: TaskType,
        poster: Address,
        max_price: u128,
        input: String,
    ) -> Self {
        let task_id = uuid::Uuid::new_v4().to_string();
        Self {
            task_id,
            title,
            description,
            task_type,
            poster,
            assignee: None,
            max_price,
            quoted_price: None,
            status: TaskStatus::Open,
            created_at: Timestamp(chrono::Utc::now().timestamp()),
            deadline: None,
            required_model: None,
            preferred_model_id: None,
            input,
            output: None,
            priority: TaskPriority::Normal,
            metadata: HashMap::new(),
            tx_hash: None,
            acceptance_criteria: None,
            escrow_id: None,
            dispute: None,
        }
    }

    /// Returns true if the task can still be accepted by an agent
    pub fn is_available(&self) -> bool {
        self.status == TaskStatus::Open
    }

    /// Returns true if the task is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(
            self.status,
            TaskStatus::Completed | TaskStatus::Cancelled | TaskStatus::Expired
        )
    }
}

/// A quote for a task from a provider agent
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskQuote {
    /// The task being quoted
    pub task_id: String,

    /// Provider agent address
    pub provider: Address,

    /// Quoted price in TNZO micro-units
    #[serde(with = "crate::primitives::u128_serde")]
    pub price: u128,

    /// Estimated time to complete (seconds)
    pub estimated_duration_secs: u64,

    /// Model the provider will use
    pub model_id: String,

    /// Provider's confidence score (0-100)
    pub confidence: u8,

    /// Quote expiry (Unix timestamp)
    pub expires_at: u64,

    /// Optional notes from the provider
    pub notes: Option<String>,

    /// Optional TEE attestation bound to this quote (base64-encoded attestation
    /// report), so the poster can prefer attested providers (Stage 2, P3).
    #[serde(default)]
    pub provider_attestation: Option<String>,

    /// Optional Merkle proof that the provider's ERC-8004 reputation is at or
    /// above a threshold, avoiding an RPC round-trip to the registry (P3).
    #[serde(default)]
    pub provider_reputation_proof: Option<ReputationProof>,
}

/// Filter parameters for listing tasks
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskFilter {
    /// Filter by task type
    pub task_type: Option<TaskType>,

    /// Filter by status
    pub status: Option<TaskStatus>,

    /// Filter by poster address
    pub poster: Option<String>,

    /// Filter by assignee address
    pub assignee: Option<String>,

    /// Maximum price filter (only show tasks at or below this price)
    pub max_price: Option<u128>,

    /// Filter tasks requiring a specific model
    pub required_model: Option<String>,

    /// Maximum number of results to return
    pub limit: Option<usize>,

    /// Offset for pagination
    pub offset: Option<usize>,
}
