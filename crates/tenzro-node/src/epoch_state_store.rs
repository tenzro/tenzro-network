//! RocksDB-backed `EpochStateStore` for consensus epoch persistence.
//!
//! `tenzro-consensus` defines the `EpochStateStore` trait but does not depend
//! on `tenzro-storage` (kept storage-agnostic, matching the pattern in
//! `tenzro-vm::StateAdapter` and `tenzro-token::RocksDbBackend`). This adapter
//! shim lives in `tenzro-node` and implements the trait over `Arc<RocksDbStore>`
//! using `CF_METADATA` under the `epoch_validators:` key prefix.
//!
//! ## Why this matters
//!
//! Before this adapter existed, `EpochManager` was reconstructed from genesis
//! on every node restart with `max_history: 10` and an empty in-memory history
//! vec — meaning the validator-set history for past epochs was unrecoverable.
//! A node that fell behind across an epoch boundary then verified incoming
//! block-sync responses against the **current** validator set, rejecting every
//! historical block with `InvalidValidatorSet`. That asymmetry caused the
//! May 2026 testnet stall: 4 of 10 nodes stuck mid-epoch, quorum impossible,
//! liveness deadlock for 3 days.
//!
//! ## Key layout
//!
//! All entries live in `CF_METADATA` under the `epoch_validators:` prefix:
//!
//! ```text
//! epoch_validators:<epoch_number_be>  →  bincode-encoded Epoch
//! ```
//!
//! The 8-byte big-endian encoding of `epoch_number` keeps RocksDB's lexical
//! scan order aligned with epoch ordering, so `load_all_epochs` returns
//! ascending epochs without an in-memory sort (the consensus crate sorts
//! defensively anyway). Big-endian also means we can later switch to a
//! range-scan-bounded API without re-keying.

use std::sync::Arc;

use tenzro_consensus::epoch_manager::EpochStateStore;
use tenzro_consensus::error::{ConsensusError, Result as ConsensusResult};
use tenzro_storage::{CF_METADATA, KvStore, RocksDbStore, WriteOp};

/// Key prefix for persisted epoch records under `CF_METADATA`.
///
/// Versioning note: this prefix is final — never add a `v2` segment to a
/// tenzro-owned key. If the on-disk format ever changes incompatibly, we
/// migrate by clearing the prefix at upgrade time, since the genesis epoch
/// is the only required seed.
const EPOCH_KEY_PREFIX: &[u8] = b"epoch_validators:";

/// Builds the storage key for a given epoch number.
///
/// Big-endian u64 encoding preserves lexicographic = numeric ordering for
/// RocksDB prefix scans.
/// Metadata key of epoch `epoch_number`'s record.
pub(crate) fn epoch_key(epoch_number: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(EPOCH_KEY_PREFIX.len() + 8);
    key.extend_from_slice(EPOCH_KEY_PREFIX);
    key.extend_from_slice(&epoch_number.to_be_bytes());
    key
}

/// Deletes the records of epochs below `floor`: a proof of the handover
/// chain covers them and their history is archived. The newest epochs, which
/// the epoch manager reads at start, stay. Returns how many were deleted.
pub fn prune_epochs_below(storage: &dyn KvStore, floor: u64) -> usize {
    let ops: Vec<WriteOp> = storage
        .get_keys_with_prefix(CF_METADATA, EPOCH_KEY_PREFIX)
        .unwrap_or_default()
        .into_iter()
        .filter(|key| {
            key.strip_prefix(EPOCH_KEY_PREFIX)
                .and_then(|r| <[u8; 8]>::try_from(r).ok())
                .is_some_and(|e| u64::from_be_bytes(e) < floor)
        })
        .map(|key| WriteOp::Delete {
            cf: CF_METADATA.to_string(),
            key,
        })
        .collect();
    let n = ops.len();
    if n > 0 && storage.write_batch(ops).is_err() {
        return 0;
    }
    n
}

/// Adapter that exposes a `RocksDbStore` as an `EpochStateStore`.
///
/// Holds a clone of the shared `Arc<RocksDbStore>` already constructed by
/// the node's storage subsystem — no separate handle, no separate fsync
/// schedule. Writes go through `KvStore::put` (buffered, batched by RocksDB
/// memtable), not `write_batch_sync`: an epoch transition is rare (once per
/// `epoch_duration` blocks, 10_000 by default) so the WAL fsync is amortized
/// over thousands of finalized-block fsyncs.
pub struct RocksDbEpochStateStore {
    storage: Arc<RocksDbStore>,
}

impl RocksDbEpochStateStore {
    /// Creates a new adapter over the given storage handle.
    pub fn new(storage: Arc<RocksDbStore>) -> Self {
        Self { storage }
    }
}

impl EpochStateStore for RocksDbEpochStateStore {
    fn put_epoch(&self, epoch_number: u64, bytes: Vec<u8>) -> ConsensusResult<()> {
        self.storage
            .put(CF_METADATA, &epoch_key(epoch_number), &bytes)
            .map_err(|e| {
                ConsensusError::Internal(format!("epoch persist (epoch {epoch_number}): {e}"))
            })
    }

    fn load_all_epochs(&self) -> ConsensusResult<Vec<Vec<u8>>> {
        let pairs = self
            .storage
            .scan_prefix(CF_METADATA, EPOCH_KEY_PREFIX)
            .map_err(|e| ConsensusError::Internal(format!("epoch scan_prefix: {e}")))?;

        // scan_prefix returns (key, value) pairs in RocksDB lexicographic order.
        // Because the key suffix is u64::to_be_bytes, lexicographic order ==
        // ascending epoch number. We discard keys (consensus layer sorts by
        // decoded epoch.number defensively).
        Ok(pairs.into_iter().map(|(_, v)| v).collect())
    }

    fn load_epoch(&self, epoch_number: u64) -> ConsensusResult<Option<Vec<u8>>> {
        self.storage
            .get(CF_METADATA, &epoch_key(epoch_number))
            .map_err(|e| {
                ConsensusError::Internal(format!("epoch read (epoch {epoch_number}): {e}"))
            })
    }

    fn for_each_epoch(&self, f: &mut dyn FnMut(&[u8])) -> ConsensusResult<()> {
        self.storage
            .scan_prefix_for_each(CF_METADATA, EPOCH_KEY_PREFIX, &mut |_, value| {
                f(value);
                Ok(())
            })
            .map_err(|e| ConsensusError::Internal(format!("epoch scan: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use tenzro_storage::StorageConfig;

    fn setup() -> (TempDir, RocksDbEpochStateStore) {
        let dir = TempDir::new().unwrap();
        let config = StorageConfig {
            db_path: dir.path().to_path_buf(),
            ..Default::default()
        };
        let store = Arc::new(RocksDbStore::open(&config).unwrap());
        let adapter = RocksDbEpochStateStore::new(store);
        (dir, adapter)
    }

    #[test]
    fn epoch_key_is_ordered_big_endian() {
        let k0 = epoch_key(0);
        let k1 = epoch_key(1);
        let k256 = epoch_key(256);
        let k_max = epoch_key(u64::MAX);
        assert!(k0 < k1);
        assert!(k1 < k256);
        assert!(k256 < k_max);
    }

    #[test]
    fn round_trip_put_and_load() {
        let (_dir, adapter) = setup();
        adapter.put_epoch(0, b"epoch-0-bytes".to_vec()).unwrap();
        adapter.put_epoch(1, b"epoch-1-bytes".to_vec()).unwrap();
        adapter.put_epoch(2, b"epoch-2-bytes".to_vec()).unwrap();

        let all = adapter.load_all_epochs().unwrap();
        assert_eq!(all.len(), 3);
        // Returned in ascending order via big-endian key sort.
        assert_eq!(all[0], b"epoch-0-bytes");
        assert_eq!(all[1], b"epoch-1-bytes");
        assert_eq!(all[2], b"epoch-2-bytes");
    }

    #[test]
    fn load_empty_returns_empty_vec() {
        let (_dir, adapter) = setup();
        let all = adapter.load_all_epochs().unwrap();
        assert!(all.is_empty());
    }

    #[test]
    fn overwrite_same_epoch_keeps_latest() {
        let (_dir, adapter) = setup();
        adapter.put_epoch(5, b"v1".to_vec()).unwrap();
        adapter.put_epoch(5, b"v2".to_vec()).unwrap();
        let all = adapter.load_all_epochs().unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], b"v2");
    }
}
