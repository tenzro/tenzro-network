//! Database-layer error types.

use thiserror::Error;

/// Result type for database-layer operations.
pub type Result<T> = std::result::Result<T, DatabaseError>;

/// Errors that can occur in the distributed database layer.
#[derive(Error, Debug)]
pub enum DatabaseError {
    /// The requested engine is not in the catalog.
    #[error("unknown database engine: {0}")]
    UnknownEngine(String),

    /// A database instance is not known to this registry.
    #[error("database not found: {0}")]
    DatabaseNotFound(String),

    /// A database with the requested id already exists.
    #[error("database already exists: {0}")]
    DatabaseExists(String),

    /// A partition referenced by a database could not be located.
    #[error("partition not found: database {database_id} index {partition_index}")]
    PartitionNotFound {
        /// Database the partition belongs to.
        database_id: String,
        /// Index of the missing partition.
        partition_index: usize,
    },

    /// No holder could be selected for a partition (no data-plane-eligible
    /// member in the caller's membership view).
    #[error("no holder available for partition {partition_index} of database {database_id}")]
    NoHolder {
        /// Database being placed.
        database_id: String,
        /// Index of the unplaceable partition.
        partition_index: usize,
    },

    /// The engine cannot serve the requested placement mode (e.g. an embedded
    /// engine asked to shard across the network).
    #[error("engine {engine} does not support placement mode {mode}")]
    UnsupportedPlacement {
        /// Engine catalog id.
        engine: String,
        /// The rejected placement mode.
        mode: String,
    },

    /// The backend engine (external process or embedded runtime) reported a
    /// failure spinning up, serving, or tearing down a database.
    #[error("engine backend error: {0}")]
    Backend(String),

    /// A query could not be dispatched or its result decoded.
    #[error("query error: {0}")]
    Query(String),

    /// Invalid request parameters.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Persistence (RocksDB write-through / hydrate) error.
    #[error("persistence error: {0}")]
    Persistence(String),
}
