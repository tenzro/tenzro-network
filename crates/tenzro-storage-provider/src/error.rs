//! Storage-provider error types.

use thiserror::Error;

/// Result type for storage-provider operations.
pub type Result<T> = std::result::Result<T, StorageProviderError>;

/// Errors that can occur in the storage provider.
#[derive(Error, Debug)]
pub enum StorageProviderError {
    /// Object not known to this provider/registry.
    #[error("object not found: {0}")]
    ObjectNotFound(String),

    /// A shard referenced by an object could not be located.
    #[error("shard not found: object {object_id} index {shard_index}")]
    ShardNotFound {
        /// Object the shard belongs to.
        object_id: String,
        /// Index of the missing shard.
        shard_index: usize,
    },

    /// The bytes served back failed their integrity hash check.
    #[error("integrity check failed for {0}: served bytes do not match committed hash")]
    IntegrityMismatch(String),

    /// A retrievability challenge response was wrong or missing.
    #[error("retrievability challenge failed for object {object_id}: {reason}")]
    ChallengeFailed {
        /// Object under challenge.
        object_id: String,
        /// Why the challenge failed.
        reason: String,
    },

    /// Too few shards survived to reconstruct the object.
    #[error("insufficient shards to reconstruct {object_id}: have {have}, need {need}")]
    InsufficientShards {
        /// Object being reconstructed.
        object_id: String,
        /// Surviving shard count.
        have: usize,
        /// Minimum shards required (the data-shard count `k`).
        need: usize,
    },

    /// Invalid redundancy parameters (e.g. zero data shards).
    #[error("invalid redundancy parameters: {0}")]
    InvalidRedundancy(String),

    /// Erasure-coding backend error.
    #[error("erasure coding error: {0}")]
    Erasure(String),

    /// Underlying iroh transport error.
    #[error("transport error: {0}")]
    Transport(String),

    /// Settlement/metering error.
    #[error("settlement error: {0}")]
    Settlement(String),

    /// Invalid request parameters.
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

impl From<tenzro_iroh::IrohError> for StorageProviderError {
    fn from(err: tenzro_iroh::IrohError) -> Self {
        Self::Transport(err.to_string())
    }
}

impl From<tenzro_settlement::SettlementError> for StorageProviderError {
    fn from(err: tenzro_settlement::SettlementError) -> Self {
        Self::Settlement(err.to_string())
    }
}
