//! Error types for Tenzro Node

use thiserror::Error;

/// Result type for node operations
pub type Result<T> = std::result::Result<T, NodeError>;

/// Node-specific error types
#[derive(Debug, Error)]
pub enum NodeError {
    /// Network subsystem error
    #[error("Network error: {0}")]
    Network(#[from] tenzro_network::NetworkError),

    /// Storage subsystem error
    #[error("Storage error: {0}")]
    Storage(#[from] tenzro_storage::StorageError),

    /// Consensus subsystem error
    #[error("Consensus error: {0}")]
    Consensus(#[from] tenzro_consensus::ConsensusError),

    /// VM subsystem error
    #[error("VM error: {0}")]
    Vm(#[from] tenzro_vm::VmError),

    /// Wallet subsystem error
    #[error("Wallet error: {0}")]
    Wallet(#[from] tenzro_wallet::WalletError),

    /// Token subsystem error
    #[error("Token error: {0}")]
    Token(#[from] tenzro_token::TokenError),

    /// Agent subsystem error
    #[error("Agent error: {0}")]
    Agent(#[from] tenzro_agent::AgentError),

    /// Model subsystem error
    #[error("Model error: {0}")]
    Model(#[from] tenzro_model::ModelError),

    /// Settlement subsystem error
    #[error("Settlement error: {0}")]
    Settlement(#[from] tenzro_settlement::SettlementError),

    /// Bridge subsystem error
    #[error("Bridge error: {0}")]
    Bridge(#[from] tenzro_bridge::BridgeError),

    /// TEE subsystem error
    #[error("TEE error: {0}")]
    Tee(#[from] tenzro_tee::TeeError),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Config(String),

    /// Returned by `Node::start` when the node has already been started or
    /// is currently transitioning to `Running`. Distinguishes the
    /// idempotent "already running" case from a generic invalid-state
    /// mismatch so operators can react appropriately (e.g., a startup
    /// supervisor can treat this as success).
    #[error("Subsystem {0} already started")]
    AlreadyStarted(String),

    /// Returned by `Node::stop` when the node has not yet reached
    /// `Running` (still in `Created` / `Starting`). Distinguishes the
    /// "stop before start" case from a generic invalid-state mismatch.
    #[error("Subsystem {0} not started")]
    NotStarted(String),

    /// Invalid state transition
    #[error("Invalid state transition: {0}")]
    InvalidState(String),

    /// Invalid transaction
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    /// A required validator key file is missing on disk. The node
    /// binary on `start` never generates validator keys (see
    /// `keygen.rs` for the rationale); operators must run
    /// `tenzro-node init` to provision them explicitly.
    #[error("Validator {kind} not found at {path}: {hint}")]
    KeyMissing {
        kind: &'static str,
        path: String,
        hint: &'static str,
    },

    /// `tenzro-node init` refused to overwrite existing validator
    /// key files. Pass `--force` to rotate; doing so abandons the
    /// previous validator identity and any bonded stake.
    #[error("validator key file(s) already exist: {0} — refusing to overwrite without --force")]
    KeysAlreadyExist(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Generic error
    #[error("{0}")]
    Other(String),
}

impl From<String> for NodeError {
    fn from(s: String) -> Self {
        NodeError::Other(s)
    }
}

impl From<&str> for NodeError {
    fn from(s: &str) -> Self {
        NodeError::Other(s.to_string())
    }
}
