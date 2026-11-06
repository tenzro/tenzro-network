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

    /// The recovery check finished: the manifest passed every check and the
    /// recovery root is the value given. Nothing was changed.
    #[error("recovery manifest checks passed; recovery root 0x{}; nothing applied", hex::encode(.0))]
    RecoveryChecked([u8; 32]),

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

    /// This machine has no hardware root to derive the node's keys from
    /// (see `tenzro_keygen`).
    #[error("{kind} unavailable ({path}): {hint}")]
    KeyMissing {
        kind: &'static str,
        path: String,
        hint: &'static str,
    },

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

/// Keyset errors become node errors.
///
/// `keygen` moved to its own crate so the CLI could provision a validator
/// without depending on the node. The variants map one to one, because
/// `KeygenError` was built from the three `NodeError` variants that code ever
/// constructed — so nothing is flattened into a string on the way through, and
/// a caller matching on `KeyMissing` still sees which key and where.
impl From<tenzro_keygen::KeygenError> for NodeError {
    fn from(e: tenzro_keygen::KeygenError) -> Self {
        match e {
            tenzro_keygen::KeygenError::KeyMissing { kind, path, hint } => {
                Self::KeyMissing { kind, path, hint }
            }
            tenzro_keygen::KeygenError::Other(m) => Self::Other(m),
        }
    }
}
