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
