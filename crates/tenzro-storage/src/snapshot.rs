//! State snapshot management for Tenzro Network
//!
//! This module provides functionality for creating, storing, and restoring
//! state snapshots at specific block heights.
//!
//! # Concurrency Model
//!
//! ## For `SnapshotManager<RocksDbStore>`
//!
//! Prefer `create_checkpoint_snapshot()` which uses RocksDB's built-in atomic checkpoint
//! mechanism. The checkpoint creates a point-in-time consistent view of the database
//! without blocking writes.
//!
//! ## For other `KvStore` implementations
//!
//! Use the `state_lock` for coordination:
//!
//! 1. Writers must hold a write lock when modifying state that needs to be
//!    consistent in snapshots.
//! 2. Callers collecting state data for `create_snapshot()` must hold a read lock
//!    while collecting state data to ensure consistency.
//!
//! ```ignore
//! // Example usage:
//! let state_lock = manager.state_lock();
//! let state_data = {
//!     let _guard = state_lock.read();
//!     // Collect state data here while holding read lock
//!     collect_state_data()
//! };
//! manager.create_snapshot(height, state_root, block_hash, state_data).await?;
//! ```

use crate::error::{Result, StorageError};
use crate::kv::{KvStore, RocksDbStore, WriteOp, CF_SNAPSHOTS};
use flate2::read::{GzDecoder, GzEncoder};
use flate2::Compression;
use parking_lot::RwLock;
use rocksdb::checkpoint::Checkpoint;
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use tenzro_types::{BlockHeight, Hash, Timestamp};

/// A state snapshot at a specific block height
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// The block height at which this snapshot was taken
    pub height: BlockHeight,
    /// The state root hash at this height
    pub state_root: Hash,
    /// The block hash at this height
    pub block_hash: Hash,
    /// The timestamp when the snapshot was created
    pub timestamp: Timestamp,
    /// Snapshot metadata
    pub metadata: SnapshotMetadata,
    /// Compressed state data
    pub state_data: Vec<u8>,
}

/// Metadata for a snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMetadata {
    /// Total number of accounts in the snapshot
    pub account_count: u64,
    /// Total state size in bytes (before compression)
    pub state_size: u64,
    /// Compressed size in bytes
    pub compressed_size: u64,
    /// Compression algorithm used
    pub compression: CompressionType,
}

/// Compression types for snapshots
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CompressionType {
    /// No compression
    None,
    /// LZ4 compression
    Lz4,
    /// Zstandard compression
    Zstd,
    /// Gzip compression (flate2)
    Gzip,
}

/// Compresses raw data using gzip.
///
/// Returns the compressed bytes. If compression fails (should not happen for
/// valid input), returns a `StorageError`.
fn compress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(data, Compression::default());
    let mut compressed = Vec::new();
    encoder.read_to_end(&mut compressed).map_err(|e| {
        StorageError::InvalidSnapshot(format!("gzip compression failed: {}", e))
    })?;
    Ok(compressed)
}

/// Decompresses gzip-compressed data.
///
/// Returns the original uncompressed bytes. Returns a `StorageError` if the
/// data is not valid gzip.
fn decompress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).map_err(|e| {
        StorageError::InvalidSnapshot(format!("gzip decompression failed: {}", e))
    })?;
    Ok(decompressed)
}

/// Snapshot manager for creating and managing state snapshots
pub struct SnapshotManager<K: KvStore> {
    kv_store: Arc<K>,
    retention_count: Arc<RwLock<u64>>,
    /// Lock to ensure consistent state reads during snapshot creation.
    /// Callers must hold a read lock on this while collecting state data,
    /// and writers must hold a write lock when modifying state.
    state_lock: Arc<RwLock<()>>,
}

impl<K: KvStore> SnapshotManager<K> {
    /// Creates a new snapshot manager
    pub fn new(kv_store: Arc<K>, retention_count: u64) -> Self {
        Self {
            kv_store,
            retention_count: Arc::new(RwLock::new(retention_count)),
            state_lock: Arc::new(RwLock::new(())),
        }
    }

    /// Returns the state lock for coordinating snapshot consistency.
    ///
    /// Hold a read lock while collecting state data for `create_snapshot()`.
    /// Writers should hold a write lock when modifying state that needs
    /// to be consistent in snapshots.
    ///
    /// # Example
    ///
    /// ```ignore
    /// // Collect state data with read lock held
    /// let state_lock = manager.state_lock();
    /// let state_data = {
    ///     let _guard = state_lock.read();
    ///     collect_state_data()
    /// };
    /// manager.create_snapshot(height, state_root, block_hash, state_data).await?;
    /// ```
    pub fn state_lock(&self) -> Arc<RwLock<()>> {
        self.state_lock.clone()
    }

    /// Creates a consistent snapshot by collecting state data under the lock.
    ///
    /// This method atomically:
    /// 1. Acquires the state write lock (prevents all concurrent modifications)
    /// 2. Calls the provided closure to collect state data
    /// 3. Stores the snapshot while the lock is held
    ///
    /// This eliminates the race condition where state could change between
    /// data collection and snapshot creation.
    ///
    /// # Example
    ///
    /// ```ignore
    /// manager.create_consistent_snapshot(height, state_root, block_hash, || {
    ///     collect_state_data_from_vm()
    /// }).await?;
    /// ```
    // The parking_lot::RwLock guard is intentionally held across async calls here.
    // The called methods (store_snapshot, prune_snapshots) perform only synchronous
    // RocksDB I/O and never yield to the executor, so no deadlock is possible.
    #[allow(clippy::await_holding_lock)]
    pub async fn create_consistent_snapshot<F>(
        &self,
        height: BlockHeight,
        state_root: Hash,
        block_hash: Hash,
        collect_state: F,
    ) -> Result<Snapshot>
    where
        F: FnOnce() -> Vec<u8>,
    {
        // Acquire WRITE lock to prevent any concurrent state modifications
        // during both state collection AND snapshot serialization
        let _guard = self.state_lock.write();

        // Collect state data while holding the lock — no torn reads possible
        let state_data = collect_state();

        let state_size = state_data.len() as u64;
        let compressed_data = compress_gzip(&state_data)?;
        let compressed_size = compressed_data.len() as u64;

        let snapshot = Snapshot {
            height,
            state_root,
            block_hash,
            timestamp: Timestamp::now(),
            metadata: SnapshotMetadata {
                account_count: 0,
                state_size,
                compressed_size,
                compression: CompressionType::Gzip,
            },
            state_data: compressed_data,
        };

        // Store the snapshot while still holding the lock
        self.store_snapshot(&snapshot).await?;

        // Prune old snapshots
        self.prune_snapshots(height).await?;

        Ok(snapshot)
    }

    /// Creates a snapshot at the given height
    ///
    /// # Consistency
    ///
    /// The caller is responsible for ensuring `state_data` is consistent by
    /// holding a read lock on `state_lock()` while collecting the data.
    /// Prefer `create_consistent_snapshot()` which handles locking automatically.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let state_lock = manager.state_lock();
    /// let state_data = {
    ///     let _guard = state_lock.read();
    ///     // Collect state data here
    ///     collect_state_data()
    /// };
    /// manager.create_snapshot(height, state_root, block_hash, state_data).await?;
    /// ```
    // See create_consistent_snapshot for rationale on #[allow(clippy::await_holding_lock)]
    #[allow(clippy::await_holding_lock)]
    pub async fn create_snapshot(
        &self,
        height: BlockHeight,
        state_root: Hash,
        block_hash: Hash,
        state_data: Vec<u8>,
    ) -> Result<Snapshot> {
        // Acquire read lock to prevent state modifications during snapshot serialization
        let _guard = self.state_lock.read();

        let state_size = state_data.len() as u64;

        // Compress with gzip
        let compressed_data = compress_gzip(&state_data)?;
        let compressed_size = compressed_data.len() as u64;

        let snapshot = Snapshot {
            height,
            state_root,
            block_hash,
            timestamp: Timestamp::now(),
            metadata: SnapshotMetadata {
                account_count: 0, // Would be calculated from state_data
                state_size,
                compressed_size,
                compression: CompressionType::Gzip,
            },
            state_data: compressed_data,
        };

        // Store the snapshot
        self.store_snapshot(&snapshot).await?;

        // Prune old snapshots
        self.prune_snapshots(height).await?;

        Ok(snapshot)
    }

    /// Stores a snapshot
    async fn store_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        let key = Self::snapshot_key(snapshot.height);
        let data = bincode::serialize(snapshot)?;
        self.kv_store.put(CF_SNAPSHOTS, &key, &data)?;

        // Also store in the index
        let index_key = Self::snapshot_index_key();
        let mut index = self.load_snapshot_index().await?;
        index.push(snapshot.height);
        index.sort_by_key(|h| h.0);
        let index_data = bincode::serialize(&index)?;
        self.kv_store.put(CF_SNAPSHOTS, &index_key, &index_data)?;

        Ok(())
    }

    /// Loads a snapshot at the given height
    pub async fn load_snapshot(&self, height: BlockHeight) -> Result<Option<Snapshot>> {
        let key = Self::snapshot_key(height);
        if let Some(data) = self.kv_store.get(CF_SNAPSHOTS, &key)? {
            let snapshot: Snapshot = bincode::deserialize(&data)?;
            Ok(Some(snapshot))
        } else {
            Ok(None)
        }
    }

    /// Deletes a snapshot at the given height
    pub async fn delete_snapshot(&self, height: BlockHeight) -> Result<()> {
        let key = Self::snapshot_key(height);
        self.kv_store.delete(CF_SNAPSHOTS, &key)?;

        // Remove from index
        let index_key = Self::snapshot_index_key();
        let mut index = self.load_snapshot_index().await?;
        index.retain(|h| *h != height);
        let index_data = bincode::serialize(&index)?;
        self.kv_store.put(CF_SNAPSHOTS, &index_key, &index_data)?;

        Ok(())
    }

    /// Lists all available snapshots
    pub async fn list_snapshots(&self) -> Result<Vec<BlockHeight>> {
        self.load_snapshot_index().await
    }

    /// Gets the latest snapshot
    pub async fn latest_snapshot(&self) -> Result<Option<Snapshot>> {
        let index = self.load_snapshot_index().await?;
        if let Some(height) = index.last() {
            self.load_snapshot(*height).await
        } else {
            Ok(None)
        }
    }

    /// Prunes old snapshots based on retention policy
    async fn prune_snapshots(&self, _current_height: BlockHeight) -> Result<()> {
        let retention = *self.retention_count.read();
        let index = self.load_snapshot_index().await?;

        if index.len() as u64 <= retention {
            return Ok(());
        }

        // Calculate how many to delete
        let to_delete = index.len() as u64 - retention;
        let mut ops = Vec::new();

        for height in index.iter().take(to_delete as usize) {
            let key = Self::snapshot_key(*height);
            ops.push(WriteOp::Delete {
                cf: CF_SNAPSHOTS.to_string(),
                key,
            });
        }

        // Update index
        let new_index: Vec<BlockHeight> = index.into_iter().skip(to_delete as usize).collect();
        let index_key = Self::snapshot_index_key();
        let index_data = bincode::serialize(&new_index)?;
        ops.push(WriteOp::Put {
            cf: CF_SNAPSHOTS.to_string(),
            key: index_key,
            value: index_data,
        });

        self.kv_store.write_batch(ops)?;

        Ok(())
    }

    /// Loads the snapshot index
    async fn load_snapshot_index(&self) -> Result<Vec<BlockHeight>> {
        let key = Self::snapshot_index_key();
        if let Some(data) = self.kv_store.get(CF_SNAPSHOTS, &key)? {
            let index: Vec<BlockHeight> = bincode::deserialize(&data)?;
            Ok(index)
        } else {
            Ok(Vec::new())
        }
    }

    /// Generates a key for storing a snapshot
    fn snapshot_key(height: BlockHeight) -> Vec<u8> {
        let mut key = b"snapshot:".to_vec();
        key.extend_from_slice(&height.0.to_be_bytes());
        key
    }

    /// Generates the key for the snapshot index
    fn snapshot_index_key() -> Vec<u8> {
        b"snapshot_index".to_vec()
    }

    /// Sets the retention count
    pub fn set_retention_count(&self, count: u64) {
        *self.retention_count.write() = count;
    }

    /// Gets the retention count
    pub fn retention_count(&self) -> u64 {
        *self.retention_count.read()
    }
}

impl SnapshotManager<RocksDbStore> {
    /// Creates a consistent snapshot using RocksDB checkpoint
    /// This ensures atomicity and consistency by using RocksDB's built-in checkpoint mechanism.
    /// The checkpoint creates a point-in-time consistent view of the database without blocking writes.
    pub async fn create_checkpoint_snapshot(
        &self,
        height: BlockHeight,
        state_root: Hash,
        block_hash: Hash,
        checkpoint_path: &Path,
    ) -> Result<Snapshot> {
        // Create a RocksDB checkpoint for consistent point-in-time snapshot
        let db = self.kv_store.db();
        let checkpoint = Checkpoint::new(db)
            .map_err(|e| StorageError::InvalidSnapshot(format!("Failed to create checkpoint: {}", e)))?;

        checkpoint.create_checkpoint(checkpoint_path)
            .map_err(|e| StorageError::InvalidSnapshot(format!("Failed to create checkpoint at path: {}", e)))?;

        // The checkpoint is now a consistent snapshot of the entire database
        // For the metadata, we need to read the checkpoint to get the actual size
        let checkpoint_size = calculate_directory_size(checkpoint_path)?;

        let snapshot = Snapshot {
            height,
            state_root,
            block_hash,
            timestamp: Timestamp::now(),
            metadata: SnapshotMetadata {
                account_count: 0, // Would need to scan checkpoint to calculate
                state_size: checkpoint_size,
                compressed_size: checkpoint_size,
                compression: CompressionType::None,
            },
            state_data: checkpoint_path.to_string_lossy().as_bytes().to_vec(),
        };

        // Store the snapshot using the base implementation
        let key = Self::snapshot_key(snapshot.height);
        let data = bincode::serialize(&snapshot)?;
        self.kv_store.put(CF_SNAPSHOTS, &key, &data)?;

        // Update the index
        let index_key = Self::snapshot_index_key();
        let index_data_opt = self.kv_store.get(CF_SNAPSHOTS, &index_key)?;
        let mut index: Vec<BlockHeight> = if let Some(data) = index_data_opt {
            bincode::deserialize(&data)?
        } else {
            Vec::new()
        };
        index.push(snapshot.height);
        index.sort_by_key(|h| h.0);
        let index_data = bincode::serialize(&index)?;
        self.kv_store.put(CF_SNAPSHOTS, &index_key, &index_data)?;

        // Prune old snapshots
        let retention = *self.retention_count.read();
        if index.len() as u64 > retention {
            let to_delete = index.len() as u64 - retention;
            let mut ops = Vec::new();

            for height in index.iter().take(to_delete as usize) {
                let key = Self::snapshot_key(*height);
                ops.push(WriteOp::Delete {
                    cf: CF_SNAPSHOTS.to_string(),
                    key,
                });
            }

            // Update index
            let new_index: Vec<BlockHeight> = index.into_iter().skip(to_delete as usize).collect();
            let index_data = bincode::serialize(&new_index)?;
            ops.push(WriteOp::Put {
                cf: CF_SNAPSHOTS.to_string(),
                key: index_key,
                value: index_data,
            });

            self.kv_store.write_batch(ops)?;
        }

        Ok(snapshot)
    }
}

/// Helper function to calculate the total size of a directory recursively
fn calculate_directory_size(path: &Path) -> Result<u64> {
    let mut total_size = 0u64;

    if path.is_file() {
        return Ok(std::fs::metadata(path)?.len());
    }

    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let metadata = entry.metadata()?;
            if metadata.is_file() {
                total_size += metadata.len();
            } else if metadata.is_dir() {
                total_size += calculate_directory_size(&entry.path())?;
            }
        }
    }

    Ok(total_size)
}

/// A single key-value entry within a snapshot's serialized state data.
///
/// `state_data` in a `Snapshot` is a `bincode`-serialized `Vec<SnapshotEntry>`.
/// This allows `SnapshotRestorer::restore_from_snapshot` to write each entry
/// back into the correct column family of any `KvStore` implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotEntry {
    /// Column family name (e.g. CF_STATE, CF_ACCOUNTS)
    pub cf: String,
    /// Key bytes
    pub key: Vec<u8>,
    /// Value bytes
    pub value: Vec<u8>,
}

/// Serializes a collection of column-family key-value pairs into the wire
/// format expected by `Snapshot::state_data`.
///
/// # Example
///
/// ```ignore
/// let entries = vec![
///     SnapshotEntry { cf: CF_STATE.to_string(), key: b"k1".to_vec(), value: b"v1".to_vec() },
/// ];
/// let bytes = serialize_snapshot_entries(&entries)?;
/// manager.create_snapshot(height, state_root, block_hash, bytes).await?;
/// ```
pub fn serialize_snapshot_entries(entries: &[SnapshotEntry]) -> Result<Vec<u8>> {
    bincode::serialize(entries).map_err(|e| {
        StorageError::SerializationError(format!("Failed to serialize snapshot entries: {}", e))
    })
}

/// Snapshot restoration helper
pub struct SnapshotRestorer;

impl SnapshotRestorer {
    /// Restores state from a snapshot by writing all stored key-value entries
    /// back into `store`.
    ///
    /// The `snapshot.state_data` field must contain a `bincode`-serialized
    /// `Vec<SnapshotEntry>` (produced by `serialize_snapshot_entries`).
    /// Each entry is written to the corresponding column family atomically via
    /// a single `write_batch_sync` call so the restoration is crash-safe.
    ///
    /// For RocksDB checkpoint snapshots (created by
    /// `create_checkpoint_snapshot`), `state_data` holds the checkpoint path
    /// as UTF-8 bytes and cannot be replayed through this method — use a
    /// filesystem-level restore for those.
    ///
    /// Returns the number of key-value entries restored.
    pub async fn restore_from_snapshot(
        snapshot: &Snapshot,
        store: &dyn KvStore,
    ) -> Result<RestoredState> {
        if snapshot.state_data.is_empty() {
            return Err(StorageError::InvalidSnapshot(
                "snapshot contains no state data".to_string(),
            ));
        }

        // Decompress state data if needed
        let raw_data = match snapshot.metadata.compression {
            CompressionType::Gzip => decompress_gzip(&snapshot.state_data)?,
            CompressionType::None => snapshot.state_data.clone(),
            other => {
                return Err(StorageError::InvalidSnapshot(format!(
                    "unsupported compression type: {:?}",
                    other
                )));
            }
        };

        // Attempt to decode as a Vec<SnapshotEntry>. If the data is not in
        // that format (e.g. it is a checkpoint path), return an error rather
        // than silently ignoring the contents.
        let entries: Vec<SnapshotEntry> =
            bincode::deserialize(&raw_data).map_err(|e| {
                StorageError::InvalidSnapshot(format!(
                    "state_data is not a valid SnapshotEntry list \
                     (is this a RocksDB checkpoint snapshot?): {}",
                    e
                ))
            })?;

        let entry_count = entries.len();
        tracing::info!(
            "Restoring snapshot at height {} with {} entries",
            snapshot.height.0,
            entry_count
        );

        // Convert to WriteOps and flush in one atomic fsync'd batch.
        let ops: Vec<WriteOp> = entries
            .iter()
            .map(|e| WriteOp::Put {
                cf: e.cf.clone(),
                key: e.key.clone(),
                value: e.value.clone(),
            })
            .collect();

        if !ops.is_empty() {
            store.write_batch_sync(ops)?;
        }

        tracing::info!(
            "Snapshot at height {} restored successfully ({} entries)",
            snapshot.height.0,
            entry_count
        );

        Ok(RestoredState {
            height: snapshot.height,
            state_root: snapshot.state_root,
            account_count: snapshot.metadata.account_count,
            entries_restored: entry_count as u64,
        })
    }

    /// Validates a snapshot
    pub fn validate_snapshot(snapshot: &Snapshot) -> Result<bool> {
        // Basic validation
        if snapshot.state_data.is_empty() {
            return Ok(false);
        }

        if snapshot.metadata.compressed_size != snapshot.state_data.len() as u64 {
            return Ok(false);
        }

        Ok(true)
    }
}

/// Result of restoring from a snapshot
#[derive(Debug, Clone)]
pub struct RestoredState {
    /// The block height of the restored state
    pub height: BlockHeight,
    /// The state root hash
    pub state_root: Hash,
    /// Number of accounts in the snapshot (from metadata)
    pub account_count: u64,
    /// Number of key-value entries actually written back to the store
    pub entries_restored: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv::MemoryStore;

    #[tokio::test]
    async fn test_snapshot_creation() {
        let kv_store = Arc::new(MemoryStore::new());
        let manager = SnapshotManager::new(kv_store, 5);

        let state_data = vec![1, 2, 3, 4, 5];
        let snapshot = manager
            .create_snapshot(
                BlockHeight::new(100),
                Hash::zero(),
                Hash::zero(),
                state_data,
            )
            .await
            .unwrap();

        assert_eq!(snapshot.height, BlockHeight::new(100));
        assert_eq!(snapshot.metadata.state_size, 5);
    }

    #[tokio::test]
    async fn test_snapshot_load() {
        let kv_store = Arc::new(MemoryStore::new());
        let manager = SnapshotManager::new(kv_store, 5);

        let state_data = vec![1, 2, 3, 4, 5];
        manager
            .create_snapshot(
                BlockHeight::new(100),
                Hash::zero(),
                Hash::zero(),
                state_data,
            )
            .await
            .unwrap();

        let loaded = manager
            .load_snapshot(BlockHeight::new(100))
            .await
            .unwrap();
        assert!(loaded.is_some());
        assert_eq!(loaded.unwrap().height, BlockHeight::new(100));
    }

    #[tokio::test]
    async fn test_snapshot_pruning() {
        let kv_store = Arc::new(MemoryStore::new());
        let manager = SnapshotManager::new(kv_store, 3);

        // Create 5 snapshots
        for i in 1..=5 {
            manager
                .create_snapshot(
                    BlockHeight::new(i * 100),
                    Hash::zero(),
                    Hash::zero(),
                    vec![i as u8],
                )
                .await
                .unwrap();
        }

        // Should only have 3 snapshots (retention policy)
        let snapshots = manager.list_snapshots().await.unwrap();
        assert_eq!(snapshots.len(), 3);

        // Should have the latest 3
        assert_eq!(snapshots[0], BlockHeight::new(300));
        assert_eq!(snapshots[1], BlockHeight::new(400));
        assert_eq!(snapshots[2], BlockHeight::new(500));
    }

    #[tokio::test]
    async fn test_latest_snapshot() {
        let kv_store = Arc::new(MemoryStore::new());
        let manager = SnapshotManager::new(kv_store, 5);

        manager
            .create_snapshot(
                BlockHeight::new(100),
                Hash::zero(),
                Hash::zero(),
                vec![1],
            )
            .await
            .unwrap();

        manager
            .create_snapshot(
                BlockHeight::new(200),
                Hash::zero(),
                Hash::zero(),
                vec![2],
            )
            .await
            .unwrap();

        let latest = manager.latest_snapshot().await.unwrap();
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().height, BlockHeight::new(200));
    }

    #[tokio::test]
    async fn test_snapshot_deletion() {
        let kv_store = Arc::new(MemoryStore::new());
        let manager = SnapshotManager::new(kv_store, 5);

        manager
            .create_snapshot(
                BlockHeight::new(100),
                Hash::zero(),
                Hash::zero(),
                vec![1],
            )
            .await
            .unwrap();

        manager.delete_snapshot(BlockHeight::new(100)).await.unwrap();

        let loaded = manager.load_snapshot(BlockHeight::new(100)).await.unwrap();
        assert!(loaded.is_none());
    }

    #[tokio::test]
    async fn test_restore_from_snapshot_writes_entries() {
        use crate::kv::{MemoryStore, CF_STATE, CF_ACCOUNTS};

        let entries = vec![
            SnapshotEntry {
                cf: CF_STATE.to_string(),
                key: b"balance:0xabc".to_vec(),
                value: 1234u128.to_le_bytes().to_vec(),
            },
            SnapshotEntry {
                cf: CF_ACCOUNTS.to_string(),
                key: b"account:0xabc".to_vec(),
                value: b"account_data".to_vec(),
            },
        ];

        let state_data = serialize_snapshot_entries(&entries).unwrap();
        let restore_store = Arc::new(MemoryStore::new());
        let manager = SnapshotManager::new(restore_store.clone(), 5);

        let snapshot = manager
            .create_snapshot(
                BlockHeight::new(42),
                Hash::zero(),
                Hash::zero(),
                state_data,
            )
            .await
            .unwrap();

        // Restore into a fresh store
        let target_store = Arc::new(MemoryStore::new());
        let restored = SnapshotRestorer::restore_from_snapshot(&snapshot, target_store.as_ref())
            .await
            .unwrap();

        assert_eq!(restored.height, BlockHeight::new(42));
        assert_eq!(restored.entries_restored, 2);

        // Verify entries are actually in the target store
        let balance_bytes = target_store
            .get(CF_STATE, b"balance:0xabc")
            .unwrap()
            .expect("balance entry should be present");
        assert_eq!(u128::from_le_bytes(balance_bytes.try_into().unwrap()), 1234u128);

        let account_bytes = target_store
            .get(CF_ACCOUNTS, b"account:0xabc")
            .unwrap()
            .expect("account entry should be present");
        assert_eq!(account_bytes, b"account_data");
    }

    #[tokio::test]
    async fn test_restore_from_snapshot_empty_data_returns_error() {
        let kv_store = Arc::new(MemoryStore::new());
        let target_store = Arc::new(MemoryStore::new());

        // Build a snapshot with empty state_data
        let snapshot = Snapshot {
            height: BlockHeight::new(1),
            state_root: Hash::zero(),
            block_hash: Hash::zero(),
            timestamp: Timestamp::now(),
            metadata: SnapshotMetadata {
                account_count: 0,
                state_size: 0,
                compressed_size: 0,
                compression: CompressionType::None,
            },
            state_data: vec![],
        };

        let result = SnapshotRestorer::restore_from_snapshot(&snapshot, target_store.as_ref()).await;
        assert!(result.is_err(), "empty state_data must return an error");

        // Silence unused variable warning
        let _ = kv_store;
    }

    #[tokio::test]
    async fn test_restore_roundtrip_via_snapshot_manager() {
        use crate::kv::{MemoryStore, CF_STATE};

        // Populate source state
        let source_entries = (0u8..5).map(|i| SnapshotEntry {
            cf: CF_STATE.to_string(),
            key: format!("key:{}", i).into_bytes(),
            value: vec![i * 10],
        }).collect::<Vec<_>>();

        let state_data = serialize_snapshot_entries(&source_entries).unwrap();

        let snap_store = Arc::new(MemoryStore::new());
        let manager = SnapshotManager::new(snap_store, 10);

        let snapshot = manager
            .create_snapshot(BlockHeight::new(77), Hash::zero(), Hash::zero(), state_data)
            .await
            .unwrap();

        // Validate the snapshot first
        assert!(SnapshotRestorer::validate_snapshot(&snapshot).unwrap());

        // Restore into a fresh target
        let target = Arc::new(MemoryStore::new());
        let result = SnapshotRestorer::restore_from_snapshot(&snapshot, target.as_ref())
            .await
            .unwrap();
        assert_eq!(result.entries_restored, 5);

        // Confirm all entries are present
        for i in 0u8..5 {
            let key = format!("key:{}", i).into_bytes();
            let val = target.get(CF_STATE, &key).unwrap().expect("entry missing");
            assert_eq!(val, vec![i * 10]);
        }
    }
}
