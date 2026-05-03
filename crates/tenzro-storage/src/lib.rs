//! State storage layer for Tenzro Network
//!
//! This crate provides the storage infrastructure for the Tenzro Network blockchain,
//! including:
//!
//! - **Key-Value Store**: Abstract storage layer with RocksDB and in-memory implementations
//! - **Merkle Patricia Trie**: Efficient state commitment and proof generation
//! - **Block Storage**: Indexing and retrieval of blocks by hash and height
//! - **Account Storage**: Management of account state and balances
//! - **Snapshots**: State snapshot creation and restoration
//!
//! # Architecture
//!
//! The storage layer uses RocksDB with multiple column families to organize different
//! data types. It provides async/await interfaces for all storage operations.
//!
//! # Example
//!
//! ```rust,no_run
//! use tenzro_storage::{
//!     config::StorageConfig,
//!     kv::{RocksDbStore, MemoryStore},
//!     block_store::BlockStoreImpl,
//!     account_store::AccountStoreImpl,
//!     traits::{BlockStore, AccountStore},
//! };
//! use std::sync::Arc;
//! use std::path::PathBuf;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a storage configuration
//! let config = StorageConfig::new(PathBuf::from("./data/tenzro-db"));
//!
//! // Open the RocksDB store
//! let kv_store = Arc::new(RocksDbStore::open(&config)?);
//!
//! // Create block and account stores
//! let block_store = BlockStoreImpl::new(kv_store.clone())?;
//! let account_store = AccountStoreImpl::new(kv_store.clone());
//!
//! // Use the stores...
//! # Ok(())
//! # }
//! ```

pub mod config;
pub mod error;
pub mod traits;
pub mod kv;
pub mod merkle;
pub mod block_store;
pub mod account_store;
pub mod snapshot;

// Re-export commonly used types
pub use config::StorageConfig;
pub use error::{Result, StorageError};
pub use traits::{AccountStore, BlockStore, StateStore};
pub use kv::{KvStore, RocksDbStore, MemoryStore, WriteOp, CF_BLOCKS, CF_STATE, CF_ACCOUNTS, CF_TRANSACTIONS, CF_METADATA, CF_SNAPSHOTS, CF_IDENTITIES, CF_DELEGATIONS, CF_CREDENTIALS, CF_CHANNELS, CF_AGENTS, CF_MODELS, CF_PROVIDERS, CF_TASKS, CF_AGENT_TEMPLATES, CF_SKILLS, CF_TOOLS, CF_TOKENS, CF_SETTLEMENTS, CF_MODEL_SERVICES, CF_NFTS, CF_EVENTS, CF_WEBHOOKS, CF_COMPLIANCE, CF_TRAINING_RUNS, CF_TRAINING_RECEIPTS, CF_AUDIT, CF_APPROVALS};
pub use merkle::{MerklePatriciaTrie, MerkleProof, ProofNode};
pub use block_store::BlockStoreImpl;
pub use account_store::{AccountStoreImpl, StateStoreImpl};
pub use snapshot::{Snapshot, SnapshotManager, SnapshotMetadata, CompressionType, SnapshotRestorer, RestoredState, SnapshotEntry, serialize_snapshot_entries};

/// Storage version for compatibility tracking
pub const STORAGE_VERSION: u32 = 1;

/// Maximum cache size for the storage layer (in bytes)
pub const MAX_CACHE_SIZE: usize = 1024 * 1024 * 1024; // 1 GB

/// Default snapshot retention count
pub const DEFAULT_SNAPSHOT_RETENTION: u64 = 100;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_version() {
        assert_eq!(STORAGE_VERSION, 1);
    }
}
