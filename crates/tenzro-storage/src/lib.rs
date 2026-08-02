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

pub mod account_store;
pub mod block_store;
pub mod config;
pub mod da;
pub mod error;
pub mod kv;
pub mod merkle;
pub mod snapshot;
pub mod traits;

// Re-export commonly used types
pub use account_store::{AccountStoreImpl, StateStoreImpl};
pub use block_store::BlockStoreImpl;
pub use config::StorageConfig;
#[cfg(feature = "celestia")]
pub use da::CelestiaBackend;
pub use da::redstuff::{self, CommitteeShape, EncodedBlob, SliverPair};
pub use da::{
    DaBackend, DaBackendId, DaBackendStatus, DaPointer, InlineFallbackBackend, MandateRef,
    ReceiptEnvelope, ReceiptKind, ReceiptStorageMode, ReceiptSummary, compute_commitment,
};
pub use error::{Result, StorageError};
pub use kv::{
    CF_ACCOUNTS, CF_AGENT_TEMPLATES, CF_AGENTS, CF_API_KEYS, CF_APPROVALS, CF_AUDIT, CF_BLOCKS,
    CF_BRIDGE_ANALYTICS, CF_CANTON_ANALYTICS, CF_CHALLENGES, CF_CHANNELS, CF_COMPLIANCE,
    CF_CREDENTIALS, CF_DA_COMMITTEE, CF_DATABASES, CF_DELEGATIONS, CF_EVENTS, CF_IDENTITIES,
    CF_KNOWLEDGE, CF_MEDIA_GEN_RECEIPTS, CF_MEDIA_GEN_RUNS, CF_MEDIA_GEN_WORKERS, CF_METADATA,
    CF_MODEL_HASHES, CF_MODEL_SERVICES, CF_MODELS, CF_MPC_KEYSHARES, CF_NFTS, CF_PROVIDERS,
    CF_SETTLEMENTS, CF_SKILLS, CF_SNAPSHOTS, CF_STATE, CF_TASKS, CF_TOKENS, CF_TOOLS,
    CF_TRAINING_RECEIPTS, CF_TRAINING_RUNS, CF_TRANSACTIONS, CF_VALIDATOR_MODULES, CF_WEBHOOKS,
    CF_WORKFLOW_TEMPLATES, KvStore, MemoryStore, RocksDbStore, WriteOp,
};
pub use merkle::{MerklePatriciaTrie, MerkleProof, ProofNode};
pub use snapshot::{
    CompressionType, RestoredState, Snapshot, SnapshotEntry, SnapshotManager, SnapshotMetadata,
    SnapshotRestorer, serialize_snapshot_entries,
};
pub use traits::{AccountStore, BlockStore, StateStore};

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
