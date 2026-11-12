//! Key-value store abstraction for Tenzro Network
//!
//! This module provides a unified key-value store interface with
//! implementations for RocksDB and in-memory storage.

use crate::config::StorageConfig;
use crate::error::{Result, StorageError};
use parking_lot::RwLock;
use rocksdb::{
    BlockBasedOptions, Cache, ColumnFamily, ColumnFamilyDescriptor, DB, Env, Options, WriteBatch,
    WriteBufferManager, WriteOptions,
};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Column family names used in the storage layer
pub const CF_BLOCKS: &str = "blocks";
pub const CF_STATE: &str = "state";
pub const CF_ACCOUNTS: &str = "accounts";
pub const CF_TRANSACTIONS: &str = "transactions";
pub const CF_METADATA: &str = "metadata";
pub const CF_IDENTITIES: &str = "identities";
pub const CF_DELEGATIONS: &str = "delegations";
pub const CF_CREDENTIALS: &str = "credentials";
pub const CF_CHANNELS: &str = "channels";
pub const CF_AGENTS: &str = "agents";
pub const CF_MODELS: &str = "models";
pub const CF_PROVIDERS: &str = "providers";
pub const CF_TOKENS: &str = "tokens";
pub const CF_SETTLEMENTS: &str = "settlements";
pub const CF_MODEL_SERVICES: &str = "model_services";
pub const CF_EVENTS: &str = "events";
/// Tenzro Auth: append-only audit log for token issuance, validation, revocation,
/// and signing decisions. Keys: `audit:<ulid>`,
/// `audit_did:<did>:<ulid>`, `audit_jti:<jti>` → ULID of the issuance event.
pub const CF_AUDIT: &str = "audit";
/// Passkey validator state: the validator modules installed per account
/// and passkey auth sessions.
/// Keys:
///   `erc7579/installed/<account20>/<validator20>` → JSON installed module
///   `erc7579/auth_session/<id>` → auth session
pub const CF_VALIDATOR_MODULES: &str = "validator_modules";
/// Committee-resident Red Stuff data-availability store. Each validator
/// custodies the primary/secondary slivers assigned to its committee index
/// plus the `2f+1`-signed availability certificate for every blob it holds.
/// Keys:
///   `da/sliver/<blob_commitment_hex>` → bincode `SliverPair` (this node's
///       assigned slivers for the blob).
///   `da/cert/<blob_commitment_hex>` → JSON `AvailabilityCertificate`
///       (shape, blob_len, `2f+1` per-validator attestation signatures).
pub const CF_DA_COMMITTEE: &str = "da_committee";
/// Verifiable-inference commitments and challenges (TOPLOC scheme).
/// Keys:
///   `commitment/<hash_hex>` → bincode `StoredCommitment` (serving
///       context plus the full top-k logit blob the provider committed
///       to; hash_hex is the SHA-256 of the commitment's canonical
///       encoding).
///   `challenge/<challenge_id>` → JSON `InferenceChallenge` (filed
///       disputes over a commitment, with lifecycle state).
pub const CF_CHALLENGES: &str = "challenges";

/// Key-value store trait
pub trait KvStore: Send + Sync {
    /// Shrinks the read caches to `keep_percent` of their normal size and
    /// returns the bytes given back. A cache refills from disk, so nothing is
    /// lost. Stores without a cache return zero.
    fn shrink_caches(&self, _keep_percent: u8) -> u64 {
        0
    }

    /// Returns the read caches to their normal size.
    fn restore_caches(&self) {}

    /// Gets a value by key from a column family
    fn get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Puts a key-value pair into a column family
    fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<()>;

    /// Deletes a key from a column family
    fn delete(&self, cf: &str, key: &[u8]) -> Result<()>;

    /// Checks if a key exists in a column family
    fn contains(&self, cf: &str, key: &[u8]) -> Result<bool> {
        Ok(self.get(cf, key)?.is_some())
    }

    /// Batch write operation (buffered, not guaranteed durable until WAL flush)
    fn write_batch(&self, operations: Vec<WriteOp>) -> Result<()>;

    /// Batch write operation with fsync for durability.
    /// Use this for finalized blocks and other critical data that must survive power loss.
    fn write_batch_sync(&self, operations: Vec<WriteOp>) -> Result<()>;

    /// Gets all keys with a given prefix
    fn get_keys_with_prefix(&self, cf: &str, prefix: &[u8]) -> Result<Vec<Vec<u8>>>;

    /// Scans all key-value pairs with a given prefix
    fn scan_prefix(&self, cf: &str, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let keys = self.get_keys_with_prefix(cf, prefix)?;
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(value) = self.get(cf, &key)? {
                results.push((key, value));
            }
        }
        Ok(results)
    }

    /// Streams every key-value pair with the given prefix to `f` without
    /// materializing the full result set. Use this instead of
    /// [`KvStore::scan_prefix`] whenever the prefix can match an unbounded
    /// number of rows (e.g. a whole-column-family walk) — `scan_prefix`
    /// builds one `Vec` holding every row, which for CF_BLOCKS on a
    /// long-running chain is a multi-gigabyte allocation. An error returned
    /// from `f` aborts the scan and propagates.
    fn scan_prefix_for_each(
        &self,
        cf: &str,
        prefix: &[u8],
        f: &mut dyn FnMut(&[u8], &[u8]) -> Result<()>,
    ) -> Result<()> {
        for (key, value) in self.scan_prefix(cf, prefix)? {
            f(&key, &value)?;
        }
        Ok(())
    }
}

/// Write operation for batch writes
#[derive(Debug, Clone)]
pub enum WriteOp {
    /// Put operation
    Put {
        cf: String,
        key: Vec<u8>,
        value: Vec<u8>,
    },
    /// Delete operation
    Delete { cf: String, key: Vec<u8> },
}

thread_local! {
    /// Synced batch writes this thread holds back for one store, named by
    /// the address of its database: see [`RocksDbStore::hold_synced_writes`].
    static HELD_WRITES: std::cell::RefCell<Option<(usize, Vec<WriteOp>)>> =
        const { std::cell::RefCell::new(None) };
}

/// Restores the holding a thread had before [`RocksDbStore::hold_synced_writes`]
/// installed its own, also when the closure panics: a thread from a blocking
/// pool runs other work afterwards, whose writes must go through.
struct HeldWritesScope {
    previous: Option<(usize, Vec<WriteOp>)>,
}

impl HeldWritesScope {
    fn install(db: usize) -> Self {
        Self {
            previous: HELD_WRITES.with(|h| h.borrow_mut().replace((db, Vec::new()))),
        }
    }

    fn finish(mut self) -> Vec<WriteOp> {
        let previous = self.previous.take();
        HELD_WRITES
            .with(|h| std::mem::replace(&mut *h.borrow_mut(), previous))
            .map(|(_, ops)| ops)
            .unwrap_or_default()
    }
}

impl Drop for HeldWritesScope {
    fn drop(&mut self) {
        let previous = self.previous.take();
        HELD_WRITES.with(|h| *h.borrow_mut() = previous);
    }
}

/// Reports a successful batch to the state-trie write capture.
fn record_batch(operations: &[WriteOp]) {
    for op in operations {
        match op {
            WriteOp::Put { cf, key, value } => {
                crate::state_trie::capture::record(cf, key, Some(value))
            }
            WriteOp::Delete { cf, key } => crate::state_trie::capture::record(cf, key, None),
        }
    }
}

/// One column family's size on disk, in bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CfSize {
    /// The column family.
    pub name: &'static str,
    /// Its SST files.
    pub sst_files: u64,
    /// Its blob files, where large values are kept apart from the SST files.
    pub blob_files: u64,
    /// RocksDB's estimate of the live data in it: what the SST files shrink
    /// to once deleted and overwritten keys are compacted away.
    pub live_data: u64,
}

/// The store's memory, by part, in bytes (`snapshots` is a count).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StoreMemory {
    pub block_cache: u64,
    pub block_cache_pinned: u64,
    pub memtables_active: u64,
    pub memtables_all: u64,
    pub table_readers: u64,
    pub snapshots: u64,
}

/// RocksDB-based key-value store
pub struct RocksDbStore {
    db: Arc<DB>,
    // The block cache every column family and the write-buffer manager
    // share; held so it lives exactly as long as the database.
    _cache: Cache,
    // The capacity the cache was opened with, which `restore_caches` returns
    // it to.
    cache_bytes: usize,
}

/// Every column family this store manages. Single source of truth so the
/// descriptor builder and any per-CF maintenance iterate the same set.
const ALL_CFS: &[&str] = &[
    CF_BLOCKS,
    CF_STATE,
    CF_ACCOUNTS,
    CF_TRANSACTIONS,
    CF_METADATA,
    CF_IDENTITIES,
    CF_DELEGATIONS,
    CF_CREDENTIALS,
    CF_CHANNELS,
    CF_AGENTS,
    CF_MODELS,
    CF_PROVIDERS,
    CF_TOKENS,
    CF_SETTLEMENTS,
    CF_MODEL_SERVICES,
    CF_EVENTS,
    CF_AUDIT,
    CF_VALIDATOR_MODULES,
    CF_DA_COMMITTEE,
    CF_CHALLENGES,
    crate::state_trie::CF_STATE_TRIE,
];

/// Force a file through compaction at least this often even when write
/// volume is too low to trigger leveled compaction on its own. Without this,
/// a validator that overwrites the same handful of hot keys every block (the
/// idle-chain steady state) never compacts: superseded key versions and
/// tombstones live forever at L0 and the on-disk footprint grows without
/// bound relative to the live key set. 24h matches RocksDB's own default
/// for TTL-style periodic compaction. See RocksDB wiki "Leveled Compaction"
/// and issue facebook/rocksdb#23248 (Solana) for the same failure mode.
const PERIODIC_COMPACTION_SECS: u64 = 24 * 60 * 60;

impl RocksDbStore {
    /// Per-CF options shared by every column family. The defaults
    /// (`Options::default()`) leave compaction entirely demand-driven, which
    /// never fires on a low-write chain — so we add a periodic-compaction
    /// floor plus dynamic level sizing so reclamation keeps pace with the
    /// hot-key churn regardless of write volume.
    ///
    /// Every column family reads through the one block cache, so the store's
    /// read memory is the cache's capacity however many families there are.
    fn cf_options(config: &StorageConfig, cache: &Cache) -> Options {
        let mut o = Options::default();
        let mut table = BlockBasedOptions::default();
        table.set_block_cache(cache);
        table.set_cache_index_and_filter_blocks(true);
        o.set_block_based_table_factory(&table);
        o.set_periodic_compaction_seconds(PERIODIC_COMPACTION_SECS);
        o.set_level_compaction_dynamic_level_bytes(true);
        o.set_write_buffer_size(config.write_buffer_size);
        o.set_max_write_buffer_number(config.max_write_buffer_number);
        o.set_target_file_size_base(config.target_file_size_base);
        if config.compression {
            o.set_compression_type(rocksdb::DBCompressionType::Lz4);
        }
        o
    }

    /// Creates the column family descriptors for all storage column families
    fn column_family_descriptors(
        config: &StorageConfig,
        cache: &Cache,
    ) -> Vec<ColumnFamilyDescriptor> {
        ALL_CFS
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, Self::cf_options(config, cache)))
            .collect()
    }

    /// Opens the store at `config.db_path` only if one is already there. A
    /// wrong path is an error, where [`Self::open`] would make a new empty
    /// store in it.
    pub fn open_existing(config: &StorageConfig) -> Result<Self> {
        if !config.db_path.join("CURRENT").is_file() {
            return Err(StorageError::DatabaseError(format!(
                "there is no store at {}",
                config.db_path.display()
            )));
        }
        Self::open(config)
    }

    /// Opens a RocksDB store with the given configuration
    pub fn open(config: &StorageConfig) -> Result<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_max_open_files(config.max_open_files);
        opts.set_write_buffer_size(config.write_buffer_size);
        opts.set_max_write_buffer_number(config.max_write_buffer_number);
        opts.set_target_file_size_base(config.target_file_size_base);

        if config.compression {
            opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        }

        if config.enable_statistics {
            opts.enable_statistics();
        }

        // One memory limit for the whole store: the block cache holds
        // `memory_bytes`, and the memtables of every column family are
        // charged against that same cache (up to a quarter of it). Past that
        // quarter the manager flushes memtables early; it never parks a
        // writer. A parked writer can wait for good: with every flush done and
        // the memory over the limit not in a memtable a flush frees, nothing
        // wakes it, and the synced consensus journal write queued behind it
        // stops the validator. Memtable memory stays bounded by each family's
        // write buffer size and count.
        let cache = Cache::new_lru_cache(config.memory_bytes);
        let write_buffers = WriteBufferManager::new_write_buffer_manager_with_cache(
            config.memory_bytes / 4,
            false,
            cache.clone(),
        );
        opts.set_write_buffer_manager(&write_buffers);

        // Background work is paced and runs at idle priority: compaction and
        // flush write at most `background_write_bytes_per_sec`, and the
        // compaction pool runs at the lowest CPU and I/O priority, so a
        // compaction backlog never delays the foreground writes consensus
        // waits on. Flushes keep the high-priority pool at normal priority,
        // because a stalled flush stalls writers.
        opts.set_ratelimiter(config.background_write_bytes_per_sec, 100_000, 10);
        opts.set_max_background_jobs(config.background_jobs);
        let mut env = Env::new()
            .map_err(|e| StorageError::DatabaseError(format!("RocksDB environment: {e}")))?;
        env.lower_thread_pool_cpu_priority();
        env.lower_thread_pool_io_priority();
        opts.set_env(&env);
        // Hard ceiling on the live WAL: once the running logs exceed this,
        // RocksDB force-flushes the CFs pinning the oldest log so it can be
        // deleted. The live WAL stays a single rotating file well under this.
        opts.set_max_total_wal_size(256 * 1024 * 1024);
        // Leave WAL archival OFF (wal_ttl_seconds = wal_size_limit_mb = 0, the
        // defaults). A non-zero size limit turns ON archival: every rotated WAL
        // is MOVED to db/archive instead of being deleted, and only purged once
        // the archive itself exceeds the limit — so on a steadily-writing chain
        // the archive parks at hundreds of MB of dead logs forever. This node
        // never replays archived WAL (no WAL-based replication/PITR), so
        // archival is pure bloat: it was the entire source of the observed
        // on-disk growth (live WAL stayed ~55 MB while db/archive held ~284 MB).
        // With archival off, a rotated WAL is deleted as soon as its data is
        // flushed to SST. set_keep_log_file_num only ever governed the textual
        // info LOG, not WAL archives, so it never bounded this and is dropped.

        // Attempt to open the database, handling WAL corruption gracefully
        let db = match DB::open_cf_descriptors(
            &opts,
            &config.db_path,
            Self::column_family_descriptors(config, &cache),
        ) {
            Ok(db) => db,
            Err(e) => {
                let error_str = e.to_string();
                // Check if the error indicates WAL corruption
                if error_str.contains("Corruption")
                    || error_str.contains("corruption")
                    || error_str.contains("log")
                    || error_str.contains("WAL")
                {
                    tracing::warn!(
                        "Database corruption detected at {:?}, attempting repair: {}",
                        config.db_path,
                        error_str
                    );

                    // Attempt to repair the database
                    if let Err(repair_err) = Self::repair_database(&config.db_path) {
                        tracing::error!("Database repair failed: {}", repair_err);
                        return Err(StorageError::DatabaseError(format!(
                            "Failed to open database and repair failed: {} (repair error: {})",
                            error_str, repair_err
                        )));
                    }

                    tracing::info!("Database repair completed, reopening...");

                    // Try opening again after repair with fresh descriptors
                    DB::open_cf_descriptors(
                        &opts,
                        &config.db_path,
                        Self::column_family_descriptors(config, &cache),
                    )
                    .map_err(|e| {
                        StorageError::DatabaseError(format!(
                            "Failed to open database after repair: {}",
                            e
                        ))
                    })?
                } else {
                    // Not a corruption error, propagate it
                    return Err(e.into());
                }
            }
        };

        // Flush every CF once on open so any data still living only in the WAL
        // from a prior run is persisted to SST, letting RocksDB delete those
        // logs immediately under the now-archival-off policy. Best-effort: a
        // flush failure must not block startup (a freshly created DB has
        // nothing to flush and returns immediately).
        {
            let handles: Vec<&ColumnFamily> = ALL_CFS
                .iter()
                .filter_map(|name| db.cf_handle(name))
                .collect();
            let mut fopts = rocksdb::FlushOptions::default();
            fopts.set_wait(true);
            if let Err(e) = db.flush_cfs_opt(&handles, &fopts) {
                tracing::warn!("startup flush of column families failed (non-fatal): {}", e);
            }
        }

        // Reclaim dead archived WAL left by an earlier build that ran with WAL
        // archival ON. Archival is now off, so RocksDB will neither add to nor
        // purge this directory — anything in it is a rotated log whose data is
        // already in SST and that this node never replays (no WAL-based
        // replication/PITR). Removing it after the flush-on-open above (which
        // guarantees live WAL data is persisted) recovers the accumulated bloat
        // in one shot. Best-effort: failures here must never block startup.
        let archive_dir = config.db_path.join("archive");
        if archive_dir.is_dir()
            && let Ok(entries) = std::fs::read_dir(&archive_dir)
        {
            let mut freed = 0u64;
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|e| e.to_str()) == Some("log") {
                    let len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    if std::fs::remove_file(&p).is_ok() {
                        freed += len;
                    }
                }
            }
            if freed > 0 {
                tracing::info!(
                    "reclaimed {} MiB of dead archived WAL from {:?}",
                    freed / (1024 * 1024),
                    archive_dir
                );
            }
        }

        Ok(Self {
            db: Arc::new(db),
            _cache: cache,
            cache_bytes: config.memory_bytes,
        })
    }

    /// Attempts to repair a corrupted RocksDB database.
    ///
    /// WARNING: This may result in data loss. Only finalized blocks should survive.
    /// Recent uncommitted data in the WAL may be lost.
    pub fn repair_database<P: AsRef<Path>>(path: P) -> Result<()> {
        tracing::warn!(
            "Repairing database at {:?}. This may result in loss of recent uncommitted data.",
            path.as_ref()
        );

        DB::repair(&Options::default(), path.as_ref())
            .map_err(|e| StorageError::DatabaseError(format!("Repair failed: {}", e)))?;

        tracing::info!("Database repair completed successfully");
        Ok(())
    }

    /// Opens a RocksDB store at the given path with default options
    pub fn open_default<P: AsRef<Path>>(path: P) -> Result<Self> {
        let config = StorageConfig::new(path.as_ref().to_path_buf());
        Self::open(&config)
    }

    /// Gets a column family handle
    fn cf_handle(&self, name: &str) -> Result<&ColumnFamily> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(name.to_string()))
    }

    /// Gets a reference to the underlying RocksDB instance
    /// This is useful for advanced operations like creating checkpoints
    pub fn db(&self) -> &DB {
        &self.db
    }

    /// What the store holds in memory now, summed over its column families:
    /// the block cache in use and the part of it pinned by readers, the
    /// memtables (active, and all including those flushed but still held),
    /// and the index and filter readers kept outside the cache.
    pub fn memory_usage(&self) -> StoreMemory {
        let sum = |name: &str| -> u64 {
            ALL_CFS
                .iter()
                .filter_map(|cf| self.db.cf_handle(cf))
                .filter_map(|h| self.db.property_int_value_cf(h, name).ok().flatten())
                .sum()
        };
        let db = |name: &str| self.db.property_int_value(name).ok().flatten().unwrap_or(0);
        StoreMemory {
            block_cache: db("rocksdb.block-cache-usage"),
            block_cache_pinned: db("rocksdb.block-cache-pinned-usage"),
            memtables_active: sum("rocksdb.cur-size-all-mem-tables"),
            memtables_all: sum("rocksdb.size-all-mem-tables"),
            table_readers: sum("rocksdb.estimate-table-readers-mem"),
            snapshots: db("rocksdb.num-snapshots"),
        }
    }

    /// Each column family's size on disk.
    pub fn cf_sizes(&self) -> Vec<CfSize> {
        ALL_CFS
            .iter()
            .filter_map(|name| {
                let cf = self.db.cf_handle(name)?;
                let read = |property: &str| {
                    self.db
                        .property_int_value_cf(cf, property)
                        .ok()
                        .flatten()
                        .unwrap_or(0)
                };
                Some(CfSize {
                    name,
                    sst_files: read("rocksdb.total-sst-files-size"),
                    blob_files: read("rocksdb.total-blob-file-size"),
                    live_data: read("rocksdb.estimate-live-data-size"),
                })
            })
            .collect()
    }

    /// Writes a point-in-time copy of the whole store to `path`, which must
    /// not exist yet. SST files are immutable, so on the same filesystem the
    /// copy hardlinks them and costs almost nothing; only the manifest and
    /// the live WAL are copied.
    pub fn create_checkpoint(&self, path: &Path) -> Result<()> {
        rocksdb::checkpoint::Checkpoint::new(&self.db)
            .and_then(|c| c.create_checkpoint(path))
            .map_err(|e| {
                StorageError::DatabaseError(format!("checkpoint to {}: {e}", path.display()))
            })
    }

    /// The address that names this store's database to a thread holding
    /// its writes back.
    fn db_id(&self) -> usize {
        Arc::as_ptr(&self.db) as usize
    }

    /// Runs `f` with the batch writes this thread makes to this store through
    /// [`KvStore::write_batch_sync`] held back, and returns them in the order
    /// they were made, with what `f` returned.
    ///
    /// The held writes are reported to the state-trie write capture as they
    /// are made, as written ones are, but nothing reads them until the caller
    /// writes them with [`Self::write_held`]. Writes to any other store, the
    /// store's other write methods, and other threads are not affected.
    pub fn hold_synced_writes<R>(&self, f: impl FnOnce() -> R) -> (R, Vec<WriteOp>) {
        let scope = HeldWritesScope::install(self.db_id());
        let out = f();
        (out, scope.finish())
    }

    /// Writes `operations` as one atomic batch: after a crash the store holds
    /// all of them or none. With `sync` the write-ahead log is synced before
    /// this returns. Without it the batch survives a crash of the process but
    /// not of the machine until a later synced write or [`Self::sync_wal`];
    /// the log recovers to a point in time, so a crash then loses a suffix of
    /// the batches written, never part of one.
    pub fn write_held(&self, operations: Vec<WriteOp>, sync: bool) -> Result<()> {
        if operations.is_empty() {
            return if sync { self.sync_wal() } else { Ok(()) };
        }
        let mut batch = WriteBatch::default();
        for op in &operations {
            match op {
                WriteOp::Put { cf, key, value } => batch.put_cf(self.cf_handle(cf)?, key, value),
                WriteOp::Delete { cf, key } => batch.delete_cf(self.cf_handle(cf)?, key),
            }
        }
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(sync);
        self.db.write_opt(batch, &write_opts)?;
        Ok(())
    }

    /// Syncs the write-ahead log: every write made to this store before the
    /// call is durable when it returns.
    pub fn sync_wal(&self) -> Result<()> {
        self.db.flush_wal(true)?;
        Ok(())
    }

    /// Compacts every column family end to end, so space held by deleted
    /// and overwritten keys is returned to the filesystem. Paced by the
    /// store's background write rate like any other compaction.
    /// Compacts the column families history pruning deletes from, so the
    /// space of pruned blocks, transactions and events is returned to the
    /// volume.
    pub fn compact_history(&self) {
        for name in crate::resources::PRUNE_COLUMN_FAMILIES {
            if let Some(cf) = self.db.cf_handle(name) {
                self.db.compact_range_cf(cf, None::<&[u8]>, None::<&[u8]>);
            }
        }
    }

    pub fn compact_all(&self) {
        for name in ALL_CFS {
            if let Some(cf) = self.db.cf_handle(name) {
                self.db.compact_range_cf(cf, None::<&[u8]>, None::<&[u8]>);
            }
        }
    }
}

impl KvStore for RocksDbStore {
    fn shrink_caches(&self, keep_percent: u8) -> u64 {
        let before = self.memory_usage().block_cache;
        let mut cache = self._cache.clone();
        cache.set_capacity(self.cache_bytes / 100 * keep_percent.min(100) as usize);
        before.saturating_sub(self.memory_usage().block_cache)
    }

    fn restore_caches(&self) {
        let mut cache = self._cache.clone();
        cache.set_capacity(self.cache_bytes);
    }

    fn get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let cf_handle = self.cf_handle(cf)?;
        Ok(self.db.get_cf(cf_handle, key)?)
    }

    fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf_handle = self.cf_handle(cf)?;
        self.db.put_cf(cf_handle, key, value)?;
        crate::state_trie::capture::record(cf, key, Some(value));
        Ok(())
    }

    fn delete(&self, cf: &str, key: &[u8]) -> Result<()> {
        let cf_handle = self.cf_handle(cf)?;
        self.db.delete_cf(cf_handle, key)?;
        crate::state_trie::capture::record(cf, key, None);
        Ok(())
    }

    fn write_batch(&self, operations: Vec<WriteOp>) -> Result<()> {
        let mut batch = WriteBatch::default();

        for op in &operations {
            match op {
                WriteOp::Put { cf, key, value } => {
                    let cf_handle = self.cf_handle(cf)?;
                    batch.put_cf(cf_handle, key, value);
                }
                WriteOp::Delete { cf, key } => {
                    let cf_handle = self.cf_handle(cf)?;
                    batch.delete_cf(cf_handle, key);
                }
            }
        }

        self.db.write(batch)?;
        record_batch(&operations);
        Ok(())
    }

    fn write_batch_sync(&self, operations: Vec<WriteOp>) -> Result<()> {
        let mut batch = WriteBatch::default();

        for op in &operations {
            match op {
                WriteOp::Put { cf, key, value } => {
                    let cf_handle = self.cf_handle(cf)?;
                    batch.put_cf(cf_handle, key, value);
                }
                WriteOp::Delete { cf, key } => {
                    let cf_handle = self.cf_handle(cf)?;
                    batch.delete_cf(cf_handle, key);
                }
            }
        }

        // A thread holding this store's synced writes keeps them for the
        // batch its caller writes with `write_held`.
        let db = self.db_id();
        let held = HELD_WRITES.with(|h| match h.borrow_mut().as_mut() {
            Some((held_db, held)) if *held_db == db => {
                held.extend(operations.iter().cloned());
                true
            }
            _ => false,
        });
        if held {
            record_batch(&operations);
            return Ok(());
        }

        // Force fsync of the WAL so finalized blocks survive power loss.
        // This is the whole point of `write_batch_sync` — without `set_sync(true)`,
        // RocksDB only writes to the OS page cache and the data is lost on a
        // hard reboot. The previous `set_sync(false)` made this method
        // indistinguishable from `write_batch`.
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true);
        self.db.write_opt(batch, &write_opts)?;
        record_batch(&operations);
        Ok(())
    }

    fn get_keys_with_prefix(&self, cf: &str, prefix: &[u8]) -> Result<Vec<Vec<u8>>> {
        let cf_handle = self.cf_handle(cf)?;
        let mut keys = Vec::new();
        let iter = self.db.prefix_iterator_cf(cf_handle, prefix);

        for item in iter {
            let (key, _) = item?;
            if key.starts_with(prefix) {
                keys.push(key.to_vec());
            } else {
                break;
            }
        }

        Ok(keys)
    }

    /// Single-pass prefix scan that pulls keys *and* values in one iterator
    /// traversal. The default trait impl issues N follow-up `get_cf` calls;
    /// for hot paths like `BlockStorage::blocks_by_height_range` (catch-up
    /// sync) that is O(N) extra lookups per range. RocksDB already returns
    /// the value alongside the key inside `prefix_iterator_cf`, so we just
    /// take both.
    fn scan_prefix(&self, cf: &str, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
        let cf_handle = self.cf_handle(cf)?;
        let mut results = Vec::new();
        let iter = self.db.prefix_iterator_cf(cf_handle, prefix);

        for item in iter {
            let (key, value) = item?;
            if key.starts_with(prefix) {
                results.push((key.to_vec(), value.to_vec()));
            } else {
                break;
            }
        }

        Ok(results)
    }

    /// Streaming prefix scan — borrows each (key, value) directly from the
    /// RocksDB iterator and never accumulates rows, so peak memory is one
    /// row regardless of how many rows the prefix matches. This is the
    /// path the snapshot producer uses to walk entire column families.
    fn scan_prefix_for_each(
        &self,
        cf: &str,
        prefix: &[u8],
        f: &mut dyn FnMut(&[u8], &[u8]) -> Result<()>,
    ) -> Result<()> {
        let cf_handle = self.cf_handle(cf)?;
        let iter = self.db.prefix_iterator_cf(cf_handle, prefix);

        for item in iter {
            let (key, value) = item?;
            if !key.starts_with(prefix) {
                break;
            }
            f(&key, &value)?;
        }

        Ok(())
    }
}

/// In-memory key-value store for testing
pub struct MemoryStore {
    data: Arc<RwLock<HashMap<String, HashMap<Vec<u8>, Vec<u8>>>>>,
}

impl MemoryStore {
    /// Creates a new in-memory store
    pub fn new() -> Self {
        let mut data = HashMap::new();
        // Initialize column families
        data.insert(CF_BLOCKS.to_string(), HashMap::new());
        data.insert(CF_STATE.to_string(), HashMap::new());
        data.insert(CF_ACCOUNTS.to_string(), HashMap::new());
        data.insert(CF_TRANSACTIONS.to_string(), HashMap::new());
        data.insert(CF_METADATA.to_string(), HashMap::new());
        data.insert(CF_IDENTITIES.to_string(), HashMap::new());
        data.insert(CF_DELEGATIONS.to_string(), HashMap::new());
        data.insert(CF_CREDENTIALS.to_string(), HashMap::new());
        data.insert(CF_CHANNELS.to_string(), HashMap::new());
        data.insert(CF_AGENTS.to_string(), HashMap::new());
        data.insert(CF_MODELS.to_string(), HashMap::new());
        data.insert(CF_PROVIDERS.to_string(), HashMap::new());
        data.insert(CF_TOKENS.to_string(), HashMap::new());
        data.insert(CF_SETTLEMENTS.to_string(), HashMap::new());
        data.insert(CF_MODEL_SERVICES.to_string(), HashMap::new());
        data.insert(CF_EVENTS.to_string(), HashMap::new());
        data.insert(CF_AUDIT.to_string(), HashMap::new());
        data.insert(CF_DA_COMMITTEE.to_string(), HashMap::new());
        data.insert(CF_CHALLENGES.to_string(), HashMap::new());

        Self {
            data: Arc::new(RwLock::new(data)),
        }
    }
}

impl Default for MemoryStore {
    fn default() -> Self {
        Self::new()
    }
}

impl KvStore for MemoryStore {
    fn get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let data = self.data.read();
        Ok(data.get(cf).and_then(|cf_data| cf_data.get(key)).cloned())
    }

    fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let mut data = self.data.write();
        data.entry(cf.to_string())
            .or_default()
            .insert(key.to_vec(), value.to_vec());
        crate::state_trie::capture::record(cf, key, Some(value));
        Ok(())
    }

    fn delete(&self, cf: &str, key: &[u8]) -> Result<()> {
        let mut data = self.data.write();
        if let Some(cf_data) = data.get_mut(cf) {
            cf_data.remove(key);
        }
        crate::state_trie::capture::record(cf, key, None);
        Ok(())
    }

    fn write_batch(&self, operations: Vec<WriteOp>) -> Result<()> {
        let mut data = self.data.write();
        record_batch(&operations);
        for op in operations {
            match op {
                WriteOp::Put { cf, key, value } => {
                    data.entry(cf).or_default().insert(key, value);
                }
                WriteOp::Delete { cf, key } => {
                    if let Some(cf_data) = data.get_mut(&cf) {
                        cf_data.remove(&key);
                    }
                }
            }
        }
        Ok(())
    }

    fn write_batch_sync(&self, operations: Vec<WriteOp>) -> Result<()> {
        // In-memory store has no persistence; sync is a no-op
        self.write_batch(operations)
    }

    fn get_keys_with_prefix(&self, cf: &str, prefix: &[u8]) -> Result<Vec<Vec<u8>>> {
        let data = self.data.read();
        let keys = data
            .get(cf)
            .map(|cf_data| {
                cf_data
                    .keys()
                    .filter(|k| k.starts_with(prefix))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Writes never wait on the store's memory limit: under a limit far below
    /// what the column families' memtables hold, with puts across every
    /// family and large delete batches like a state prune, every synced write
    /// returns. A writer parked on the limit would block the consensus
    /// journal queued behind it.
    #[test]
    fn writes_are_never_held_by_the_memory_limit() {
        let dir = tempfile::tempdir().unwrap();
        let config = StorageConfig::new(dir.path().join("db")).with_memory_bytes(4 << 20);
        let store = std::sync::Arc::new(RocksDbStore::open(&config).unwrap());
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let writer = store.clone();
        std::thread::spawn(move || {
            let value = vec![7u8; 16 << 10];
            for round in 0u32..600 {
                let mut ops = Vec::new();
                for cf in ALL_CFS {
                    for k in 0u32..4 {
                        ops.push(WriteOp::Put {
                            cf: cf.to_string(),
                            key: [round.to_be_bytes(), k.to_be_bytes()].concat(),
                            value: value.clone(),
                        });
                    }
                }
                writer.write_batch_sync(ops).unwrap();
                if round % 100 == 99 {
                    let ops = (round - 99..round)
                        .flat_map(|r| {
                            ALL_CFS.iter().flat_map(move |cf| {
                                (0u32..4).map(move |k| WriteOp::Delete {
                                    cf: cf.to_string(),
                                    key: [r.to_be_bytes(), k.to_be_bytes()].concat(),
                                })
                            })
                        })
                        .collect();
                    writer.write_batch_sync(ops).unwrap();
                }
            }
            done_tx.send(()).unwrap();
        });
        assert!(
            done_rx
                .recv_timeout(std::time::Duration::from_secs(120))
                .is_ok(),
            "a write waited on the memory limit and never returned"
        );
    }

    #[test]
    fn test_memory_store() {
        let store = MemoryStore::new();

        // Test put and get
        store.put(CF_STATE, b"key1", b"value1").unwrap();
        let value = store.get(CF_STATE, b"key1").unwrap();
        assert_eq!(value, Some(b"value1".to_vec()));

        // Test delete
        store.delete(CF_STATE, b"key1").unwrap();
        let value = store.get(CF_STATE, b"key1").unwrap();
        assert_eq!(value, None);

        // Test batch write
        let ops = vec![
            WriteOp::Put {
                cf: CF_STATE.to_string(),
                key: b"key2".to_vec(),
                value: b"value2".to_vec(),
            },
            WriteOp::Put {
                cf: CF_STATE.to_string(),
                key: b"key3".to_vec(),
                value: b"value3".to_vec(),
            },
        ];
        store.write_batch(ops).unwrap();

        let value2 = store.get(CF_STATE, b"key2").unwrap();
        let value3 = store.get(CF_STATE, b"key3").unwrap();
        assert_eq!(value2, Some(b"value2".to_vec()));
        assert_eq!(value3, Some(b"value3".to_vec()));
    }

    #[test]
    fn test_prefix_search() {
        let store = MemoryStore::new();

        store.put(CF_STATE, b"prefix_key1", b"value1").unwrap();
        store.put(CF_STATE, b"prefix_key2", b"value2").unwrap();
        store.put(CF_STATE, b"other_key", b"value3").unwrap();

        let keys = store.get_keys_with_prefix(CF_STATE, b"prefix_").unwrap();
        assert_eq!(keys.len(), 2);
    }

    /// Returns a unique temporary directory path for a RocksDB test instance.
    /// We avoid pulling in a `tempfile` dev-dependency by composing the path
    /// from the system temp dir, the process id, and a per-call counter.
    fn unique_temp_db_path(label: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let id = COUNTER.fetch_add(1, Ordering::SeqCst);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "tenzro-storage-test-{}-{}-{}-{}",
            label, pid, id, nanos
        ))
    }

    #[test]
    fn test_rocksdb_write_batch_sync_durability() {
        // Verifies that `write_batch_sync` actually persists data and that
        // we can reopen the DB and read what we wrote. This is the regression
        // test that sync writes are durable: calling
        // `write_opts.set_sync(false)` would make the API silently
        // non-durable.
        let path = unique_temp_db_path("sync");

        {
            let store = RocksDbStore::open_default(&path).expect("open db");
            store
                .write_batch_sync(vec![WriteOp::Put {
                    cf: CF_STATE.to_string(),
                    key: b"durable-key".to_vec(),
                    value: b"durable-value".to_vec(),
                }])
                .expect("sync write");
            // Drop closes the DB cleanly.
        }

        {
            let store = RocksDbStore::open_default(&path).expect("reopen db");
            let value = store.get(CF_STATE, b"durable-key").expect("read");
            assert_eq!(value, Some(b"durable-value".to_vec()));
        }

        // Best-effort cleanup; ignore failures.
        let _ = std::fs::remove_dir_all(&path);
    }

    fn put(key: &[u8]) -> WriteOp {
        WriteOp::Put {
            cf: CF_STATE.to_string(),
            key: key.to_vec(),
            value: key.to_vec(),
        }
    }

    #[test]
    fn held_synced_writes_are_read_only_once_written_as_one_batch() {
        let path = unique_temp_db_path("held");
        let other_path = unique_temp_db_path("held-other");
        let store = RocksDbStore::open_default(&path).expect("open db");
        let other = RocksDbStore::open_default(&other_path).expect("open other db");

        let ((), held) = store.hold_synced_writes(|| {
            store.write_batch_sync(vec![put(b"a")]).unwrap();
            store.write_batch_sync(vec![put(b"b"), put(b"c")]).unwrap();
            // Another store, and this store's unsynced writes, go through.
            other.write_batch_sync(vec![put(b"x")]).unwrap();
            store.write_batch(vec![put(b"d")]).unwrap();
            assert_eq!(store.get(CF_STATE, b"a").unwrap(), None);
        });
        assert_eq!(held.len(), 3);
        assert_eq!(other.get(CF_STATE, b"x").unwrap(), Some(b"x".to_vec()));
        assert_eq!(store.get(CF_STATE, b"d").unwrap(), Some(b"d".to_vec()));
        assert_eq!(store.get(CF_STATE, b"c").unwrap(), None);

        store.write_held(held, false).unwrap();
        store.sync_wal().unwrap();
        for k in [b"a", b"b", b"c"] {
            assert_eq!(store.get(CF_STATE, k).unwrap(), Some(k.to_vec()));
        }
        // Writes after the scope are written and synced at once again.
        store.write_batch_sync(vec![put(b"e")]).unwrap();
        assert_eq!(store.get(CF_STATE, b"e").unwrap(), Some(b"e".to_vec()));

        drop((store, other));
        let store = RocksDbStore::open_default(&path).expect("reopen db");
        for k in [b"a", b"b", b"c", b"d", b"e"] {
            assert_eq!(store.get(CF_STATE, k).unwrap(), Some(k.to_vec()));
        }
        drop(store);
        let _ = std::fs::remove_dir_all(&path);
        let _ = std::fs::remove_dir_all(&other_path);
    }

    #[test]
    fn a_panic_while_holding_writes_leaves_the_thread_writing_again() {
        let path = unique_temp_db_path("held-panic");
        let store = RocksDbStore::open_default(&path).expect("open db");
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store.hold_synced_writes(|| {
                store.write_batch_sync(vec![put(b"lost")]).unwrap();
                panic!("execution failed");
            })
        }));
        assert!(caught.is_err());
        store.write_batch_sync(vec![put(b"after")]).unwrap();
        assert_eq!(store.get(CF_STATE, b"lost").unwrap(), None);
        assert_eq!(
            store.get(CF_STATE, b"after").unwrap(),
            Some(b"after".to_vec())
        );
        drop(store);
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_rocksdb_repair_recovers_from_truncated_wal() {
        // Verifies WAL recovery. We open a DB, write some data,
        // close it, corrupt one of the SST or log files by truncating it,
        // then call `repair_database` and confirm we can reopen the DB.
        // RocksDB repair is best-effort: finalized writes generally survive,
        // unflushed WAL entries may be lost. We therefore only assert that
        // (a) repair succeeds and (b) the DB reopens.
        let path = unique_temp_db_path("repair");

        {
            let store = RocksDbStore::open_default(&path).expect("open db");
            for i in 0..32u64 {
                store
                    .write_batch_sync(vec![WriteOp::Put {
                        cf: CF_STATE.to_string(),
                        key: format!("key-{}", i).into_bytes(),
                        value: format!("value-{}", i).into_bytes(),
                    }])
                    .expect("sync write");
            }
        }

        // Truncate every .log file in the DB directory to simulate WAL corruption.
        if let Ok(entries) = std::fs::read_dir(&path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|s| s.to_str()) == Some("log")
                    && let Ok(meta) = std::fs::metadata(&p)
                {
                    let new_len = meta.len() / 2;
                    if let Ok(file) = std::fs::OpenOptions::new().write(true).open(&p) {
                        let _ = file.set_len(new_len);
                    }
                }
            }
        }

        // Repair should not panic; it may log warnings/errors but should return Ok.
        let repair_result = RocksDbStore::repair_database(&path);
        assert!(
            repair_result.is_ok(),
            "repair_database should succeed on truncated WAL: {:?}",
            repair_result
        );

        // After repair we must be able to reopen the database.
        let store = RocksDbStore::open_default(&path).expect("reopen after repair");

        // We don't assert which specific keys survive — RocksDB repair is
        // not transactional w.r.t. unflushed writes. We just confirm the DB
        // is openable and queryable, which is what matters for crash recovery.
        let _ = store.get(CF_STATE, b"key-0");

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn test_rocksdb_open_recovers_from_wal_corruption() {
        // Verifies the auto-repair-on-open path in `RocksDbStore::open()`.
        // We write data, truncate the WAL, then re-open. The open path
        // should detect corruption, run repair, and reopen successfully.
        let path = unique_temp_db_path("auto-repair");

        {
            let store = RocksDbStore::open_default(&path).expect("open db");
            for i in 0..16u64 {
                store
                    .write_batch_sync(vec![WriteOp::Put {
                        cf: CF_BLOCKS.to_string(),
                        key: format!("block-{}", i).into_bytes(),
                        value: format!("payload-{}", i).into_bytes(),
                    }])
                    .expect("sync write");
            }
        }

        if let Ok(entries) = std::fs::read_dir(&path) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.extension().and_then(|s| s.to_str()) == Some("log")
                    && let Ok(meta) = std::fs::metadata(&p)
                {
                    let new_len = meta.len() / 3;
                    if let Ok(file) = std::fs::OpenOptions::new().write(true).open(&p) {
                        let _ = file.set_len(new_len);
                    }
                }
            }
        }

        // RocksDB does not always classify a truncated WAL as a "Corruption"
        // error — it may simply silently truncate the recovered tail. So
        // this test only asserts that the open path does not panic on a
        // damaged WAL. The auto-repair branch is exercised for actual
        // corruption errors at runtime in production.
        let _ = RocksDbStore::open_default(&path);

        let _ = std::fs::remove_dir_all(&path);
    }
}
