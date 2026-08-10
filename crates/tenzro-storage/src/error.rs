//! Error types for Tenzro Network storage layer
//!
//! This module defines error types used throughout the storage subsystem.

use thiserror::Error;

/// Storage-specific errors
#[derive(Debug, Error)]
pub enum StorageError {
    /// Database error
    #[error("Database error: {0}")]
    DatabaseError(String),

    /// RocksDB error
    #[error("RocksDB error: {0}")]
    RocksDbError(#[from] rocksdb::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// Key not found
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    /// Block not found
    #[error("Block not found: {0}")]
    BlockNotFound(String),

    /// Account not found
    #[error("Account not found: {0}")]
    AccountNotFound(String),

    /// Invalid state root
    #[error("Invalid state root: expected {expected}, got {actual}")]
    InvalidStateRoot { expected: String, actual: String },

    /// Merkle proof verification failed
    #[error("Merkle proof verification failed")]
    InvalidMerkleProof,

    /// Snapshot not found
    #[error("Snapshot not found at height {0}")]
    SnapshotNotFound(u64),

    /// Invalid snapshot data
    #[error("Invalid snapshot data: {0}")]
    InvalidSnapshot(String),

    /// Column family not found
    #[error("Column family not found: {0}")]
    ColumnFamilyNotFound(String),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Invalid key format
    #[error("Invalid key format: {0}")]
    InvalidKey(String),

    /// Invalid value format
    #[error("Invalid value format: {0}")]
    InvalidValue(String),

    /// Transaction rollback failed
    #[error("Transaction rollback failed: {0}")]
    RollbackFailed(String),

    /// Transaction commit failed
    #[error("Transaction commit failed: {0}")]
    CommitFailed(String),

    /// Concurrent modification error
    #[error("Concurrent modification detected")]
    ConcurrentModification,

    /// Storage capacity exceeded
    #[error("Storage capacity exceeded")]
    CapacityExceeded,

    /// Generic error
    #[error("{0}")]
    Generic(String),
}

/// Result type for storage operations
pub type Result<T> = std::result::Result<T, StorageError>;

impl From<bincode::Error> for StorageError {
    fn from(err: bincode::Error) -> Self {
        StorageError::SerializationError(err.to_string())
    }
}

impl From<serde_json::Error> for StorageError {
    fn from(err: serde_json::Error) -> Self {
        StorageError::SerializationError(err.to_string())
    }
}
