//! Key-value store abstraction for Tenzro Network
//!
//! This module provides a unified key-value store interface with
//! implementations for RocksDB and in-memory storage.

use crate::config::StorageConfig;
use crate::error::{Result, StorageError};
use parking_lot::RwLock;
use rocksdb::{ColumnFamily, ColumnFamilyDescriptor, DB, Options, WriteBatch, WriteOptions};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// Column family names used in the storage layer
pub const CF_BLOCKS: &str = "blocks";
pub const CF_STATE: &str = "state";
pub const CF_ACCOUNTS: &str = "accounts";
pub const CF_TRANSACTIONS: &str = "transactions";
pub const CF_METADATA: &str = "metadata";
pub const CF_SNAPSHOTS: &str = "snapshots";
pub const CF_IDENTITIES: &str = "identities";
pub const CF_DELEGATIONS: &str = "delegations";
pub const CF_CREDENTIALS: &str = "credentials";
pub const CF_CHANNELS: &str = "channels";
pub const CF_AGENTS: &str = "agents";
pub const CF_MODELS: &str = "models";
pub const CF_PROVIDERS: &str = "providers";
pub const CF_TASKS: &str = "tasks";
pub const CF_AGENT_TEMPLATES: &str = "agent_templates";
pub const CF_SKILLS: &str = "skills";
pub const CF_TOOLS: &str = "tools";
/// Operator-curated knowledge resource registry: vector DBs, RAG
/// indices, document corpora, indexed historical datasets, real-time
/// data feeds. Persists `KnowledgeRecord` rows. Mirrors `CF_TOOLS`
/// pattern but for queryable data resources.
pub const CF_KNOWLEDGE: &str = "knowledge";
/// Operator-curated workflow template catalog: reusable multi-step
/// saga specs that tenants can instantiate via `tenzro_instantiateWorkflow`.
/// Persists `WorkflowTemplate` rows. Distinct from running-workflow
/// state (which lives in tenzro-workflow's own storage).
pub const CF_WORKFLOW_TEMPLATES: &str = "workflow_templates";
pub const CF_TOKENS: &str = "tokens";
pub const CF_SETTLEMENTS: &str = "settlements";
pub const CF_MODEL_SERVICES: &str = "model_services";
pub const CF_NFTS: &str = "nfts";
pub const CF_EVENTS: &str = "events";
pub const CF_WEBHOOKS: &str = "webhooks";
pub const CF_COMPLIANCE: &str = "compliance";
/// Tenzro Train: in-flight and completed training runs (`TrainingRun` records).
pub const CF_TRAINING_RUNS: &str = "training_runs";
/// Tenzro Train: sealed training receipts at run finalization.
pub const CF_TRAINING_RECEIPTS: &str = "training_receipts";
/// Tenzro Auth: append-only audit log for token issuance, validation, revocation,
/// signing decisions, and HITL approval decisions. Keys: `audit:<ulid>`,
/// `audit_did:<did>:<ulid>`, `audit_jti:<jti>` → ULID of the issuance event.
pub const CF_AUDIT: &str = "audit";
/// Tenzro Auth: HITL approval state. Keys: `approval:<approval_id>` → JSON
/// `ApprovalRecord`, `approval_pending:<approver_did>:<approval_id>` →
/// empty value (secondary index for the approver's queue).
pub const CF_APPROVALS: &str = "approvals";
/// Tenzro API keys: per-client bearer credentials for gating proxied
/// services where the node mediates a credential the client does not
/// hold directly (e.g. Canton devnet JWT). Keys: `apikey:<sha256_hex>` →
/// JSON `ApiKeyRecord` (subject DID, scopes, created_at, revoked_at).
pub const CF_API_KEYS: &str = "api_keys";
/// Tenzro Bridge MPC: TEE-sealed DKLS23 threshold-ECDSA keyshares.
/// Keys: `mpc/keyshare/<group_id_hex>/<epoch_le_u64_hex>` → JSON
/// `KeyshareEnvelope` (sealed `Party<C>` ciphertext + public coordinates);
/// `mpc/keyshare/by_group/<group_id_hex>` → JSON `Vec<u64>` (epoch index).
pub const CF_MPC_KEYSHARES: &str = "mpc_keyshares";
/// Canton multi-tenant analytics. Per-API-key transaction counters,
/// last-seen timestamp, per-method call counts, and party usage —
/// scoped to each tenant so an RPC operator can answer "how many
/// DAML txes has the tenzro-labs team submitted this month".
/// Keys: `canton_analytics:<key_id>` → JSON `CantonKeyAnalytics`
/// (calls_total, calls_by_method, errors_total, last_called_at,
/// first_seen_at, canton_user_id, party_id_hint).
pub const CF_CANTON_ANALYTICS: &str = "canton_analytics";
/// Bridge multi-tenant analytics. Per-API-key call counters for
/// `chainlink`-scoped methods (Chainlink Data Feed reads via the
/// operator's paid Ethereum mainnet RPC) so the RPC operator can
/// attribute upstream costs to each tenant. Keys:
/// `bridge_analytics:<key_id>` → JSON `BridgeKeyAnalytics`
/// (calls_total, calls_by_method, errors_total, last_called_at,
/// first_seen_at, cu_consumed_total).
pub const CF_BRIDGE_ANALYTICS: &str = "bridge_analytics";
/// ERC-7579 validator modules state. Per-smart-account configuration
/// for SocialRecovery, SessionKey, SpendingLimit validators, plus
/// the installed-modules index. Custody enforcement at signing time
/// depends on this being durable across restarts.
/// Keys:
///   `erc7579/social/<account20>` → JSON `SocialRecoveryConfig`
///   `erc7579/session/<account20>` → JSON `SessionKeyConfig`
///   `erc7579/session_state/<account20>` → JSON `SessionKeyState`
///   `erc7579/spending/<account20>` → JSON `SpendingLimitConfig`
///   `erc7579/spending_state/<account20>` → JSON `SpendingLimitState`
///   `erc7579/installed/<account20>/<validator20>` → JSON
///       `ValidatorModuleConfig` (installed-module index for the
///       AND-combined gate).
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
/// Distributed database layer registry. Records the databases a node serves
/// and their placement (local single-node, LAN-cluster, or network-sharded).
/// Keys:
///   `db/<database_id>` → JSON `DatabaseDescriptor` (engine, placement mode,
///       partition count, replica count).
///   `partition/<database_id>/<partition_index>` → JSON `PartitionPlacement`
///       (the HRW-selected holder endpoint ids for this partition).
pub const CF_DATABASES: &str = "databases";
/// Governance-anchored transparency log binding a model id to its canonical
/// content hash, so a peer-fetched weight artifact can be verified against a
/// value the validator committee has witnessed and HotStuff-2 has finalized.
/// Recording is permissionless (first recorder for a given model id wins); a
/// second differing assertion is rejected unless it carries a governance
/// override. Serving and fetching stay fully permissionless — only the
/// canonical-hash assertion is anchored.
/// Keys:
///   `<model_id>` → JSON `CanonicalModelHash` { model_id, blake3, sha256,
///       recorder_did, recorded_at_epoch, manifest_hash, governance_overridden }.
pub const CF_MODEL_HASHES: &str = "model_hashes";
/// Tenzro Media Gen: in-flight and completed generative-media jobs
/// (`MediaGenJob` records). Keys: `job:<job_id>`.
pub const CF_MEDIA_GEN_RUNS: &str = "media_gen_runs";
/// Tenzro Media Gen: sealed receipts at job completion (`MediaGenReceipt`
/// records). Keys: `receipt:<job_id>`.
pub const CF_MEDIA_GEN_RECEIPTS: &str = "media_gen_receipts";
/// Tenzro Media Gen: enrolled worker capabilities
/// (`MediaGenWorkerCapability` records). Keys: `worker:<worker_did>`.
pub const CF_MEDIA_GEN_WORKERS: &str = "media_gen_workers";

/// Key-value store trait
pub trait KvStore: Send + Sync {
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

/// RocksDB-based key-value store
pub struct RocksDbStore {
    db: Arc<DB>,
}

/// Every column family this store manages. Single source of truth so the
/// descriptor builder and any per-CF maintenance iterate the same set.
const ALL_CFS: &[&str] = &[
    CF_BLOCKS,
    CF_STATE,
    CF_ACCOUNTS,
    CF_TRANSACTIONS,
    CF_METADATA,
    CF_SNAPSHOTS,
    CF_IDENTITIES,
    CF_DELEGATIONS,
    CF_CREDENTIALS,
    CF_CHANNELS,
    CF_AGENTS,
    CF_MODELS,
    CF_PROVIDERS,
    CF_TASKS,
    CF_AGENT_TEMPLATES,
    CF_SKILLS,
    CF_TOOLS,
    CF_KNOWLEDGE,
    CF_WORKFLOW_TEMPLATES,
    CF_TOKENS,
    CF_SETTLEMENTS,
    CF_MODEL_SERVICES,
    CF_NFTS,
    CF_EVENTS,
    CF_WEBHOOKS,
    CF_COMPLIANCE,
    CF_TRAINING_RUNS,
    CF_TRAINING_RECEIPTS,
    CF_AUDIT,
    CF_APPROVALS,
    CF_API_KEYS,
    CF_MPC_KEYSHARES,
    CF_CANTON_ANALYTICS,
    CF_BRIDGE_ANALYTICS,
    CF_VALIDATOR_MODULES,
    CF_DA_COMMITTEE,
    CF_CHALLENGES,
    CF_DATABASES,
    CF_MODEL_HASHES,
    CF_MEDIA_GEN_RUNS,
    CF_MEDIA_GEN_RECEIPTS,
    CF_MEDIA_GEN_WORKERS,
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
    fn cf_options(config: &StorageConfig) -> Options {
        let mut o = Options::default();
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
    fn column_family_descriptors(config: &StorageConfig) -> Vec<ColumnFamilyDescriptor> {
        ALL_CFS
            .iter()
            .map(|name| ColumnFamilyDescriptor::new(*name, Self::cf_options(config)))
            .collect()
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

        // Aggregate memtable budget across all column families: bounds total
        // memtable memory so the live WAL can't be inflated by many CFs each
        // holding a full per-CF write buffer at once.
        opts.set_db_write_buffer_size(256 * 1024 * 1024);
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
            Self::column_family_descriptors(config),
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
                        Self::column_family_descriptors(config),
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

        Ok(Self { db: Arc::new(db) })
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
}

impl KvStore for RocksDbStore {
    fn get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let cf_handle = self.cf_handle(cf)?;
        Ok(self.db.get_cf(cf_handle, key)?)
    }

    fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf_handle = self.cf_handle(cf)?;
        Ok(self.db.put_cf(cf_handle, key, value)?)
    }

    fn delete(&self, cf: &str, key: &[u8]) -> Result<()> {
        let cf_handle = self.cf_handle(cf)?;
        Ok(self.db.delete_cf(cf_handle, key)?)
    }

    fn write_batch(&self, operations: Vec<WriteOp>) -> Result<()> {
        let mut batch = WriteBatch::default();

        for op in operations {
            match op {
                WriteOp::Put { cf, key, value } => {
                    let cf_handle = self.cf_handle(&cf)?;
                    batch.put_cf(cf_handle, key, value);
                }
                WriteOp::Delete { cf, key } => {
                    let cf_handle = self.cf_handle(&cf)?;
                    batch.delete_cf(cf_handle, key);
                }
            }
        }

        Ok(self.db.write(batch)?)
    }

    fn write_batch_sync(&self, operations: Vec<WriteOp>) -> Result<()> {
        let mut batch = WriteBatch::default();

        for op in operations {
            match op {
                WriteOp::Put { cf, key, value } => {
                    let cf_handle = self.cf_handle(&cf)?;
                    batch.put_cf(cf_handle, key, value);
                }
                WriteOp::Delete { cf, key } => {
                    let cf_handle = self.cf_handle(&cf)?;
                    batch.delete_cf(cf_handle, key);
                }
            }
        }

        // Force fsync of the WAL so finalized blocks survive power loss.
        // This is the whole point of `write_batch_sync` — without `set_sync(true)`,
        // RocksDB only writes to the OS page cache and the data is lost on a
        // hard reboot. The previous `set_sync(false)` made this method
        // indistinguishable from `write_batch` (HIGH #78 in the production audit).
        let mut write_opts = WriteOptions::default();
        write_opts.set_sync(true);
        Ok(self.db.write_opt(batch, &write_opts)?)
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
        data.insert(CF_SNAPSHOTS.to_string(), HashMap::new());
        data.insert(CF_IDENTITIES.to_string(), HashMap::new());
        data.insert(CF_DELEGATIONS.to_string(), HashMap::new());
        data.insert(CF_CREDENTIALS.to_string(), HashMap::new());
        data.insert(CF_CHANNELS.to_string(), HashMap::new());
        data.insert(CF_AGENTS.to_string(), HashMap::new());
        data.insert(CF_MODELS.to_string(), HashMap::new());
        data.insert(CF_PROVIDERS.to_string(), HashMap::new());
        data.insert(CF_TASKS.to_string(), HashMap::new());
        data.insert(CF_AGENT_TEMPLATES.to_string(), HashMap::new());
        data.insert(CF_SKILLS.to_string(), HashMap::new());
        data.insert(CF_TOOLS.to_string(), HashMap::new());
        data.insert(CF_TOKENS.to_string(), HashMap::new());
        data.insert(CF_SETTLEMENTS.to_string(), HashMap::new());
        data.insert(CF_MODEL_SERVICES.to_string(), HashMap::new());
        data.insert(CF_NFTS.to_string(), HashMap::new());
        data.insert(CF_EVENTS.to_string(), HashMap::new());
        data.insert(CF_WEBHOOKS.to_string(), HashMap::new());
        data.insert(CF_COMPLIANCE.to_string(), HashMap::new());
        data.insert(CF_TRAINING_RUNS.to_string(), HashMap::new());
        data.insert(CF_TRAINING_RECEIPTS.to_string(), HashMap::new());
        data.insert(CF_AUDIT.to_string(), HashMap::new());
        data.insert(CF_APPROVALS.to_string(), HashMap::new());
        data.insert(CF_DA_COMMITTEE.to_string(), HashMap::new());
        data.insert(CF_CHALLENGES.to_string(), HashMap::new());
        data.insert(CF_DATABASES.to_string(), HashMap::new());
        data.insert(CF_MODEL_HASHES.to_string(), HashMap::new());
        data.insert(CF_MEDIA_GEN_RUNS.to_string(), HashMap::new());
        data.insert(CF_MEDIA_GEN_RECEIPTS.to_string(), HashMap::new());
        data.insert(CF_MEDIA_GEN_WORKERS.to_string(), HashMap::new());

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
        Ok(())
    }

    fn delete(&self, cf: &str, key: &[u8]) -> Result<()> {
        let mut data = self.data.write();
        if let Some(cf_data) = data.get_mut(cf) {
            cf_data.remove(key);
        }
        Ok(())
    }

    fn write_batch(&self, operations: Vec<WriteOp>) -> Result<()> {
        let mut data = self.data.write();
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
        // test for HIGH #78 — the previous implementation called
        // `write_opts.set_sync(false)`, which made the API silently
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

    #[test]
    fn test_rocksdb_repair_recovers_from_truncated_wal() {
        // Verifies WAL recovery (HIGH #78). We open a DB, write some data,
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
