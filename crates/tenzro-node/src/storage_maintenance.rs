//! Keeps the node's disk and memory bounded.
//!
//! - **Retention.** Blocks older than the governed retention window are
//!   handed to the committee's DA layer and deleted locally
//!   ([`crate::history_archive`]).
//! - **Epoch snapshots.** When an epoch's last checkpoint is certified, the
//!   store is checkpointed (hardlinked SST files, near-zero cost) under
//!   `<data_dir>/epoch-snapshots`, keeping the newest
//!   [`StoragePolicy::snapshots_kept`]. `tenzro-node backup` copies the newest
//!   one to a path the operator names, transferring only SST files an earlier
//!   backup there does not hold; the node itself never sends a backup
//!   anywhere. `tenzro-node restore` rebuilds a store from one and verifies
//!   its state against the checkpoint it was taken at before the node uses it.
//! - **Degradation ladder.** The node reads the free bytes and free percent
//!   of its data volume, the bytes its data grows per block, and the host's
//!   memory, I/O and inode pressure (all in [`tenzro_storage::resources`]),
//!   and moves along [`Level`]s with hysteresis: it warns first, then prunes
//!   to a shorter retention window and compacts, then refuses non-essential
//!   data (model downloads, relay forwarding, snapshots, public history
//!   queries), and at the last level releases a ballast file and shouts.
//!   Levels change on measurements, never on elapsed time, and each change
//!   is logged once. A level needs free bytes and free percent both under
//!   its pair, so a large volume that is nearly full by percent and still
//!   has room is left alone. Consensus-critical writes are never refused.
//! - **Data classes.** Only data classed expendable, then regenerable, then
//!   important is ever removed automatically, and only down to its safe
//!   floor; the tables are [`tenzro_storage::resources::DATA_LAYOUT`].
//! - **Memory.** The store's block cache and memtables and the consensus
//!   core's buffers are charged to the node's memory budget, the same ledger
//!   model loads are admitted against.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tenzro_consensus::Checkpoint;
use tenzro_consensus::committee::Committee;
use tenzro_consensus::light_client::{
    Certification, CheckpointProof, EpochHandover, GenesisAnchor, HandoverChainJournal,
    HandoverChainProof,
};
use tenzro_model::memory_budget::{MemoryBudget, Tier};
use tenzro_storage::backup::{self, BackupReport, SnapshotDir};
use tenzro_storage::resources::{
    self, Action, GrowthTracker, Ladder, LadderConfig, Level, Reading, StatusReport,
};
use tenzro_storage::state_trie::snapshot::{root_from_buckets, verify_bucket};
use tenzro_storage::{KvStore, RocksDbStore, StateTrie, StorageConfig};
use tracing::{info, warn};

use crate::consensus_driver::ConsensusHandle;
use crate::error::{NodeError, Result};
use crate::health::HealthMonitor;
use crate::history_archive::HistoryArchive;
use crate::tier::Tuning;

/// Ledger key the store's memory is charged under.
pub const STORAGE_MEMORY_KEY: &str = "node/storage";
/// Ledger key the consensus core's buffers are charged under.
pub const CONSENSUS_MEMORY_KEY: &str = "node/consensus";
/// Health subsystem carrying the disk flag.
pub const DISK_SUBSYSTEM: &str = "disk";

/// How often the maintenance pass runs.
const TICK: Duration = Duration::from_secs(60);
/// Checkpoints whose compact and stride certificates a node keeps however
/// slowly its history ages: a week at the public network's 500 ms spacing.
pub const CERTIFICATE_WINDOW_CHECKPOINTS: u64 = 1_209_600;
/// Shortest spacing between full compactions under disk pressure.
/// Where a prover drops its newest proof of the handover chain (a
/// [`HandoverChainProof`], bincode) under the proof log's directory, for the
/// node to verify and install on its next pass.
pub const INCOMING_CHAIN_PROOF: &str = "incoming-chain.bin";

/// Epochs before the current one whose records a node keeps whatever a chain
/// proof covers: the epoch manager reads the newest epochs at start, and a
/// peer catching up is served recent handovers.
pub const EPOCH_RECORDS_KEPT: u64 = 12;

/// Segments (of up to 4,096 blocks each) one pass hands over while the
/// volume has room.
pub const PRUNE_STEP_SEGMENTS: usize = 4;

/// The fewest recent blocks a node under disk pressure keeps: the governed
/// minimum of the retention parameter.
pub const MIN_PRESSURE_RETENTION_BLOCKS: u64 = 10_000;

/// The retention window, in blocks, a node applies at `pressure`, given the
/// governed `retention`. Under pressure the window shrinks, so a node already
/// at its retention floor still sheds history to the DA layer; it never keeps
/// fewer than [`MIN_PRESSURE_RETENTION_BLOCKS`] (or the governed window, when
/// that is smaller), and an archival node is not asked to call this.
pub fn pressure_retention(retention: u64, pressure: DiskPressure) -> u64 {
    let shrunk = match pressure {
        DiskPressure::Normal => return retention,
        DiskPressure::Pruning => retention / 4,
        DiskPressure::Refusing => retention / 16,
    };
    shrunk.max(MIN_PRESSURE_RETENTION_BLOCKS.min(retention))
}

/// The retention window at ladder `level`: the governed one while there is
/// room, a quarter at the prune level, a sixteenth at the refuse level and
/// the floor at the last; never below [`MIN_PRESSURE_RETENTION_BLOCKS`].
pub fn level_retention(retention: u64, level: Level) -> u64 {
    match level {
        Level::Ok | Level::Warn => retention,
        Level::Prune => pressure_retention(retention, DiskPressure::Pruning),
        Level::Refuse => pressure_retention(retention, DiskPressure::Refusing),
        Level::Reserve => MIN_PRESSURE_RETENTION_BLOCKS.min(retention),
    }
}

/// Default share of the data volume the stored history (blocks, transactions
/// and events) may take, percent.
pub const DEFAULT_HISTORY_BUDGET_PCT: u8 = 35;

/// History pruned for the byte budget goes down to this share of the budget,
/// percent, so the next pass does not prune again for a while.
pub const HISTORY_BUDGET_LOW_WATER_PCT: u64 = 90;

/// The bytes the stored history takes on disk: the blocks, transactions and
/// events column families.
pub fn history_bytes(store: &RocksDbStore) -> u64 {
    store
        .cf_sizes()
        .iter()
        .filter(|c| resources::PRUNE_COLUMN_FAMILIES.contains(&c.name))
        .map(|c| c.sst_files + c.blob_files)
        .sum()
}

/// The block height history must be pruned below to bring `held_bytes` of
/// history, held from height `oldest` up to `certified`, under `budget`
/// bytes; `None` while it is within the budget. The result is the height
/// that leaves `HISTORY_BUDGET_LOW_WATER_PCT` percent of the budget, and
/// never leaves fewer than `min_blocks` recent blocks.
pub fn budget_floor(
    held_bytes: u64,
    budget: u64,
    oldest: u64,
    certified: u64,
    min_blocks: u64,
) -> Option<u64> {
    if held_bytes <= budget || certified < oldest {
        return None;
    }
    let held_blocks = certified - oldest + 1;
    let per_block = (held_bytes as f64 / held_blocks as f64).max(1.0);
    let target = budget / 100 * HISTORY_BUDGET_LOW_WATER_PCT;
    let shed = ((held_bytes - target.min(held_bytes)) as f64 / per_block).ceil() as u64;
    let limit = certified.saturating_sub(min_blocks);
    Some(oldest.saturating_add(shed).min(limit))
}

const COMPACTION_SPACING: Duration = Duration::from_secs(600);

/// Operator policy for storage, the `[storage]` section of the node config.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct StoragePolicy {
    /// Memory for the store's block cache and memtables, MiB. Unset takes a
    /// share of the memory budget's pool set by the node's tier (see
    /// [`crate::tier`]): 1/32 between 256 MiB and 4 GiB on a server, 1/16
    /// between 32 MiB and 256 MiB on an edge device.
    pub memory_mb: Option<u64>,
    /// Rate compaction and flush may write at, MiB per second. Unset takes
    /// the tier's: 64 on a server, 16 on an edge device.
    pub background_write_mb_per_sec: Option<u64>,
    /// Background flush and compaction jobs. Unset takes the tier's.
    pub background_jobs: Option<i32>,
    /// Write buffer per column family, MiB. Unset takes the tier's.
    pub write_buffer_mb: Option<u64>,
    /// Files the store keeps open. Unset takes the tier's.
    pub max_open_files: Option<i32>,
    /// Epoch snapshots kept on the data volume: one verified snapshot, and
    /// the one being written beside it for as long as it takes.
    pub snapshots_kept: usize,
    /// Thresholds of the degradation ladder: free bytes and percent,
    /// runway in blocks, hysteresis, the ballast and the margin kept beyond
    /// a large write. Every level is configurable here.
    pub ladder: LadderConfig,
    /// Keep every block, event and transaction past the retention window.
    /// Off by default: a node keeps the window and hands older history to
    /// the DA layer, or deletes it when it has none. An archive opts in.
    pub archival: bool,
    /// Bytes the stored history (blocks, transactions and events) may take.
    /// Unset takes `history_budget_pct` of the data volume. Together with
    /// the governed block window, whichever is exceeded first prunes the
    /// oldest history; state and the certificates joiners need stay.
    pub history_budget_bytes: Option<u64>,
    /// Share of the data volume the history may take when
    /// `history_budget_bytes` is unset, percent; 0 turns the byte budget
    /// off.
    pub history_budget_pct: u8,
}

impl Default for StoragePolicy {
    fn default() -> Self {
        Self {
            memory_mb: None,
            background_write_mb_per_sec: None,
            background_jobs: None,
            write_buffer_mb: None,
            max_open_files: None,
            snapshots_kept: 1,
            ladder: LadderConfig::default(),
            archival: false,
            history_budget_bytes: None,
            history_budget_pct: DEFAULT_HISTORY_BUDGET_PCT,
        }
    }
}

impl StoragePolicy {
    /// The history budget on a volume of `volume_bytes`; `None` when off.
    pub fn history_budget(&self, volume_bytes: u64) -> Option<u64> {
        match (self.history_budget_bytes, self.history_budget_pct) {
            (Some(b), _) => Some(b),
            (None, 0) => None,
            (None, pct) => Some((volume_bytes as u128 * pct.min(100) as u128 / 100) as u64),
        }
    }

    /// Bytes the store may hold in memory, from the policy or the budget's
    /// pool under the tier's share and bounds.
    pub fn memory_bytes(&self, budget: &MemoryBudget, tuning: &Tuning) -> u64 {
        match self.memory_mb {
            Some(mb) => mb << 20,
            None => (budget.snapshot().pool_bytes / tuning.storage_memory_divisor)
                .clamp(tuning.storage_memory_min, tuning.storage_memory_max),
        }
    }

    /// The store configuration for `db_path` under this policy and the
    /// tier's defaults, its memory charged to `budget`.
    pub fn store_config(
        &self,
        db_path: PathBuf,
        budget: &MemoryBudget,
        tuning: &Tuning,
    ) -> StorageConfig {
        let memory = self.memory_bytes(budget, tuning);
        budget.charge(STORAGE_MEMORY_KEY, Tier::Resident, memory);
        let mut config = StorageConfig::new(db_path)
            .with_memory_bytes(memory as usize)
            .with_background_write_rate(
                (self
                    .background_write_mb_per_sec
                    .unwrap_or(tuning.background_write_mb_per_sec)
                    << 20) as i64,
            )
            .with_write_buffer_size(
                self.write_buffer_mb
                    .map_or(tuning.write_buffer_bytes, |mb| (mb << 20) as usize),
            )
            .with_max_open_files(self.max_open_files.unwrap_or(tuning.max_open_files));
        config.background_jobs = self.background_jobs.unwrap_or(tuning.background_jobs);
        config
    }
}

/// Where epoch snapshots live under a data directory.
pub fn snapshot_root(data_dir: &Path) -> PathBuf {
    data_dir.join("epoch-snapshots")
}

/// How full the data volume is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiskPressure {
    /// Above the prune level.
    Normal,
    /// At the prune level: pruning to the floor and compacting.
    Pruning,
    /// At the refuse level or past it: non-essential data is refused.
    Refusing,
}

/// The disk flag the node reports, and the check non-essential writers make.
#[derive(Debug, Default)]
pub struct DiskGuard {
    level: AtomicU8,
    used_pct: AtomicU8,
    report: parking_lot::Mutex<Option<StatusReport>>,
}

/// The disk flag as reported in the node status.
#[derive(Debug, Clone, Serialize)]
pub struct DiskStatus {
    /// Pressure level.
    pub pressure: DiskPressure,
    /// Percent of the data volume in use at the last check.
    pub used_pct: u8,
    /// Whether non-essential data is being refused.
    pub refusing_non_essential: bool,
    /// The ladder level.
    pub level: Level,
    /// The last assessment: free space, runway, growth, next class
    /// sacrificed; absent before the first check.
    pub assessment: Option<StatusReport>,
}

impl DiskGuard {
    /// The ladder level now.
    pub fn level(&self) -> Level {
        match self.level.load(Ordering::Acquire) {
            0 => Level::Ok,
            1 => Level::Warn,
            2 => Level::Prune,
            3 => Level::Refuse,
            _ => Level::Reserve,
        }
    }

    fn pressure(&self) -> DiskPressure {
        match self.level() {
            Level::Ok | Level::Warn => DiskPressure::Normal,
            Level::Prune => DiskPressure::Pruning,
            Level::Refuse | Level::Reserve => DiskPressure::Refusing,
        }
    }

    #[cfg(test)]
    pub(crate) fn set(&self, pressure: DiskPressure, used_pct: u8) {
        let level = match pressure {
            DiskPressure::Normal => Level::Ok,
            DiskPressure::Pruning => Level::Prune,
            DiskPressure::Refusing => Level::Refuse,
        };
        self.set_level(level, used_pct, None);
    }

    pub(crate) fn set_level(&self, level: Level, used_pct: u8, report: Option<StatusReport>) {
        self.used_pct.store(used_pct, Ordering::Release);
        self.level.store(level as u8, Ordering::Release);
        *self.report.lock() = report;
    }

    /// The flag for the node status.
    pub fn status(&self) -> DiskStatus {
        let pressure = self.pressure();
        DiskStatus {
            pressure,
            used_pct: self.used_pct.load(Ordering::Acquire),
            refusing_non_essential: pressure == DiskPressure::Refusing,
            level: self.level(),
            assessment: self.report.lock().clone(),
        }
    }

    /// `Some(reason)` when non-essential data (`what`) must be refused
    /// because the disk is past the refuse level; the refusal is logged.
    pub fn refusal(&self, what: &str) -> Option<String> {
        self.refuse(Action::Download, what)
    }

    /// `Some(reason)` when the ladder does not allow `action` at its level;
    /// the refusal is logged. Consensus writes never ask.
    pub fn refuse(&self, action: Action, what: &str) -> Option<String> {
        if self.level().allows(action) {
            return None;
        }
        let msg = format!(
            "{what} refused: the node's data volume is {}% full (level {}); only consensus-critical writes continue",
            self.used_pct.load(Ordering::Acquire),
            self.level().name()
        );
        warn!("{msg}");
        Some(msg)
    }
}

/// Percent of the filesystem holding `path` that is in use: used blocks over
/// the blocks an unprivileged writer can reach (used plus available), the
/// figure `df` reports, on every platform.
pub fn disk_used_pct(path: &Path) -> Result<u8> {
    let st = fs4::statvfs(path)
        .map_err(|e| NodeError::Other(format!("free space of {}: {e}", path.display())))?;
    let used = st.total_space().saturating_sub(st.free_space());
    let total = used + st.available_space();
    Ok((used * 100).checked_div(total).unwrap_or(0).min(100) as u8)
}

/// What one maintenance pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PassReport {
    /// Blocks handed to the DA layer and deleted locally.
    pub pruned_blocks: u64,
    /// Whether the store was compacted.
    pub compacted: bool,
    /// Records of epochs a chain proof covers, deleted.
    pub pruned_epoch_records: usize,
}

/// The node's storage maintenance.
pub struct StorageMaintenance {
    storage: Arc<RocksDbStore>,
    policy: StoragePolicy,
    guard: Arc<DiskGuard>,
    health: Arc<HealthMonitor>,
    snapshots: SnapshotDir,
    archive: Option<Arc<HistoryArchive>>,
    consensus: Option<Arc<ConsensusHandle>>,
    /// The consensus records' own store, whose size is reported with the
    /// node store's.
    consensus_records: Option<Arc<RocksDbStore>>,
    /// The handovers of the proof of each checkpoint, kept as each epoch
    /// closes, and the chain proof that replaces those it covers.
    proof_log: Option<Arc<parking_lot::Mutex<crate::proof_log::ProofLog>>>,
    /// Where a prover drops a new chain proof.
    incoming_chain_proof: PathBuf,
    budget: &'static MemoryBudget,
    last_compaction: Option<Instant>,
    data_dir: PathBuf,
    ladder: Ladder,
    growth: GrowthTracker,
    /// The level the last pass left the node at.
    level: Level,
    /// Whether the ballast was released and is to be laid again once the
    /// volume has recovered.
    ballast_released: bool,
    /// History was pruned for the byte budget and not yet compacted, so its
    /// size on disk still counts the pruned rows: the budget waits for the
    /// compaction before it measures again.
    history_dirty: bool,
}

impl StorageMaintenance {
    /// Maintenance of `storage` under `data_dir`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        storage: Arc<RocksDbStore>,
        data_dir: &Path,
        policy: StoragePolicy,
        guard: Arc<DiskGuard>,
        health: Arc<HealthMonitor>,
        archive: Option<Arc<HistoryArchive>>,
        consensus: Option<Arc<ConsensusHandle>>,
        budget: &'static MemoryBudget,
    ) -> Self {
        let snapshots = SnapshotDir::new(snapshot_root(data_dir), policy.snapshots_kept);
        match snapshots.clean_partials() {
            Ok(0) => {}
            Ok(freed) => info!(
                freed_mb = freed >> 20,
                "removed a snapshot left unfinished by an earlier run"
            ),
            Err(e) => warn!(error = %e, "removing unfinished snapshots failed"),
        }
        let proof_log = match crate::proof_log::ProofLog::open(&data_dir.join("epoch-proof")) {
            Ok(log) => Some(Arc::new(parking_lot::Mutex::new(log))),
            Err(e) => {
                warn!(error = %e, "the epoch proof log could not be opened; snapshots build their proof in memory");
                None
            }
        };
        Self {
            storage,
            guard,
            health,
            snapshots,
            archive,
            consensus,
            consensus_records: None,
            proof_log,
            incoming_chain_proof: data_dir.join("epoch-proof").join(INCOMING_CHAIN_PROOF),
            budget,
            last_compaction: None,
            data_dir: data_dir.to_path_buf(),
            ladder: Ladder::new(policy.ladder.clone()),
            growth: GrowthTracker::new(policy.ladder.growth_window_blocks),
            level: Level::Ok,
            ballast_released: false,
            history_dirty: false,
            policy,
        }
    }

    /// The proof log, shared with the RPC that serves it.
    pub fn proof_log(&self) -> Option<Arc<parking_lot::Mutex<crate::proof_log::ProofLog>>> {
        self.proof_log.clone()
    }

    /// Reports the size of the consensus records' store too.
    pub fn with_consensus_records(mut self, records: Option<Arc<RocksDbStore>>) -> Self {
        self.consensus_records = records;
        self
    }

    /// Logs the node's memory by part once a tick, so a run shows which part
    /// grows: resident memory, the store's parts, and the async tasks alive.
    fn report_memory(&self) {
        let m = self.storage.memory_usage();
        let rss = std::fs::read_to_string("/proc/self/status")
            .ok()
            .and_then(|s| {
                let line = s.lines().find(|l| l.starts_with("VmRSS:"))?;
                line.split_whitespace().nth(1)?.parse::<u64>().ok()
            })
            .map_or(0, |kb| kb << 10);
        let tasks =
            tokio::runtime::Handle::try_current().map_or(0, |h| h.metrics().num_alive_tasks());
        info!(
            target: "tenzro_node::memory",
            rss_mb = rss >> 20,
            block_cache_mb = m.block_cache >> 20,
            block_cache_pinned_mb = m.block_cache_pinned >> 20,
            memtables_active_mb = m.memtables_active >> 20,
            memtables_all_mb = m.memtables_all >> 20,
            table_readers_mb = m.table_readers >> 20,
            snapshots = m.snapshots,
            tasks,
            "memory"
        );
        // Disk by kind: every column family holding data, in both stores.
        let stores = [
            ("node", Some(&self.storage)),
            ("consensus", self.consensus_records.as_ref()),
        ];
        for (store, db) in stores {
            let Some(db) = db else { continue };
            for cf in db
                .cf_sizes()
                .into_iter()
                .filter(|c| c.sst_files > 0 || c.live_data > 0)
            {
                info!(
                    target: "tenzro_node::memory",
                    store,
                    cf = cf.name,
                    sst_mb = cf.sst_files >> 20,
                    live_mb = cf.live_data >> 20,
                    "column family"
                );
            }
        }
    }

    /// The bytes the node's own data holds, summed from the column families
    /// of the node store and the consensus records: the figure growth is
    /// measured on.
    fn data_bytes(&self) -> u64 {
        let size = |db: &RocksDbStore| {
            db.cf_sizes()
                .iter()
                .map(|c| c.sst_files + c.blob_files)
                .sum::<u64>()
        };
        size(&self.storage) + self.consensus_records.as_ref().map_or(0, |r| size(r))
    }

    /// Reads the data volume, the host and the growth at `height`.
    pub fn measure(&mut self, height: u64) -> std::io::Result<Reading> {
        let volume = resources::volume_stats(&self.data_dir)?;
        self.growth.record(height, self.data_bytes());
        Ok(Reading {
            volume,
            host: resources::host_pressure(),
            bytes_per_block: self.growth.bytes_per_block(),
        })
    }

    /// Logs a change of level, once, with what was measured.
    fn announce(&self, from: Level, a: &resources::Assessment, used_pct: u8) {
        let summary = a.summary();
        let why = a
            .causes
            .iter()
            .map(|c| c.what.as_str())
            .collect::<Vec<_>>()
            .join("; ");
        match a.level {
            Level::Ok => info!(
                used_pct,
                from = from.name(),
                "{summary}: data volume back to normal"
            ),
            Level::Warn => warn!(
                used_pct,
                from = from.name(),
                why,
                "data volume low: {summary}"
            ),
            Level::Prune => warn!(
                used_pct,
                from = from.name(),
                why,
                "data volume past the prune level: shortening the retention window, pruning and compacting: {summary}"
            ),
            Level::Refuse => warn!(
                used_pct,
                from = from.name(),
                why,
                "data volume past the refuse level: refusing non-essential data (snapshots, relay, history queries, downloads); consensus writes continue: {summary}"
            ),
            Level::Reserve => tracing::error!(
                used_pct,
                from = from.name(),
                why,
                "DATA VOLUME NEARLY FULL, last reserve: ballast released, snapshots stopped, only consensus writes continue: {summary}"
            ),
        }
    }

    /// One pass on a measured `reading`: moves along the ladder, sets the
    /// disk flag, prunes history below the retention floor of the level,
    /// and compacts under pressure.
    pub async fn pass_with(&mut self, reading: Reading, used_pct: u8) -> PassReport {
        let mut report = PassReport::default();
        // The consensus store and the node store are on the same volume, and
        // the ladder is the only thing that sets the level.
        let assessment = self.ladder.assess(&reading);
        let level = assessment.level;
        let before = self.level;
        self.level = level;
        self.guard
            .set_level(level, used_pct, Some(assessment.report()));
        if level != before {
            self.announce(before, &assessment, used_pct);
            match level {
                Level::Ok => self.health.mark_healthy(DISK_SUBSYSTEM),
                Level::Warn => self.health.mark_degraded(
                    DISK_SUBSYSTEM,
                    format!("data volume low: {}", assessment.summary()),
                ),
                Level::Prune => self.health.mark_degraded(
                    DISK_SUBSYSTEM,
                    format!("data volume {used_pct}% full: pruning"),
                ),
                Level::Refuse | Level::Reserve => self.health.mark_degraded(
                    DISK_SUBSYSTEM,
                    format!("data volume {used_pct}% full: refusing non-essential data"),
                ),
            }
        }
        self.keep_ballast(level, &reading);
        let pressure = self.guard.status().pressure;

        if let Some(consensus) = &self.consensus {
            if let Some(m) = consensus.metrics() {
                self.budget
                    .charge(CONSENSUS_MEMORY_KEY, Tier::Resident, m.buffered_bytes);
            }
            if let Some(archive) = self.archive.as_ref().filter(|_| !self.policy.archival) {
                let governed = self.retention_blocks();
                let retention = level_retention(governed, level);
                let certified = consensus.certified_height();
                let mut floor = certified.saturating_sub(retention);
                let mut over_budget = false;
                if !self.history_dirty
                    && let Some(budget) = self.policy.history_budget(reading.volume.total_bytes)
                    && let Some(oldest) = consensus
                        .checkpoint(archive.next_checkpoint().unwrap_or(0))
                        .map(|c| c.first_height)
                {
                    let held = history_bytes(&self.storage);
                    if let Some(by_bytes) = budget_floor(
                        held,
                        budget,
                        oldest,
                        certified,
                        MIN_PRESSURE_RETENTION_BLOCKS.min(governed),
                    ) && by_bytes > floor
                    {
                        info!(
                            held_mb = held >> 20,
                            budget_mb = budget >> 20,
                            window_floor = floor,
                            floor = by_bytes,
                            "history over its byte budget: pruning the oldest"
                        );
                        floor = by_bytes;
                        over_budget = true;
                    }
                }
                if retention < governed {
                    info!(
                        used_pct,
                        level = level.name(),
                        governed,
                        retention,
                        floor,
                        "disk pressure: retention window shortened"
                    );
                }
                // Small steps while there is room, everything eligible under
                // pressure; always below what a joining node and the finality
                // proofs still read (`MIN_PRESSURE_RETENTION_BLOCKS` is the
                // lowest window any level applies).
                let steps = if level >= Level::Prune || over_budget {
                    usize::MAX
                } else {
                    PRUNE_STEP_SEGMENTS
                };
                match archive.prune_below_limited(floor, steps).await {
                    Ok(r) => {
                        if r.blocks > 0 {
                            info!(
                                segments = r.segments,
                                blocks = r.blocks,
                                transactions = r.transactions,
                                floor,
                                "history below the retention floor handed to the DA layer and pruned (floor may be pressure-tightened)"
                            );
                        }
                        report.pruned_blocks = r.blocks;
                        if over_budget && r.blocks > 0 {
                            self.history_dirty = true;
                        }
                    }
                    Err(e) => warn!(floor, error = %e, "history pruning stopped"),
                }
                // Certificates of checkpoints whose blocks have left, or older
                // than the certificate window, are dropped; epoch handovers
                // and checkpoint bodies stay.
                let latest = consensus
                    .latest_certificate()
                    .map_or(0, |c| c.checkpoint.index);
                let below = archive
                    .next_checkpoint()
                    .unwrap_or(0)
                    .max(latest.saturating_sub(CERTIFICATE_WINDOW_CHECKPOINTS));
                let dropped = consensus.prune_certificates_below(below);
                if dropped > 0 {
                    info!(
                        below,
                        dropped, "certificates below the history floor pruned"
                    );
                }
                // Archived segments carry their own checkpoint bodies.
                let floor_index = archive.next_checkpoint().unwrap_or(0);
                let bodies = consensus.prune_bodies_below(floor_index);
                if bodies > 0 {
                    info!(
                        floor_index,
                        bodies, "checkpoint bodies below the history floor pruned"
                    );
                }
                // Epochs a chain proof covers and whose history is archived
                // leave no record behind.
                self.extend_proof_log();
                self.take_incoming_chain_proof();
                let floor = self.epoch_records_floor(consensus, archive);
                if floor > 0 {
                    let records = consensus.prune_epoch_records_below(floor);
                    let epochs =
                        crate::epoch_state_store::prune_epochs_below(&*self.storage, floor);
                    if records + epochs > 0 {
                        info!(
                            floor,
                            records, epochs, "records of epochs the chain proof covers pruned"
                        );
                    }
                    report.pruned_epoch_records = records + epochs;
                }
            }
        }

        if pressure != DiskPressure::Normal || self.history_dirty {
            if pressure != DiskPressure::Normal
                && let Err(e) = self.snapshots.trim(1)
            {
                warn!(error = %e, "trimming epoch snapshots failed");
            }
            // A compaction writes its output before it frees its input: it
            // needs room, and is not started without it.
            let need = self.compaction_need_bytes();
            let room = resources::headroom(&reading.volume, need, &self.policy.ladder);
            if let Err(short) = &room {
                warn!(need_mb = need >> 20, "compaction not started: {short}");
            }
            if room.is_ok()
                && level.allows(Action::Compaction)
                && self
                    .last_compaction
                    .is_none_or(|t| t.elapsed() >= COMPACTION_SPACING)
            {
                let storage = self.storage.clone();
                let everything = pressure != DiskPressure::Normal;
                if tokio::task::spawn_blocking(move || {
                    if everything {
                        storage.compact_all()
                    } else {
                        storage.compact_history()
                    }
                })
                .await
                .is_ok()
                {
                    report.compacted = true;
                    self.history_dirty = false;
                }
                self.last_compaction = Some(Instant::now());
            }
        }
        report
    }

    /// Bytes a full compaction may need beyond what the store holds: the
    /// largest column family, which is rewritten while its input stays.
    fn compaction_need_bytes(&self) -> u64 {
        self.storage
            .cf_sizes()
            .iter()
            .map(|c| c.sst_files)
            .max()
            .unwrap_or(0)
    }

    /// Lays the ballast while the volume has room, releases it at the last
    /// level, and lays it again once the level is back to normal.
    fn keep_ballast(&mut self, level: Level, reading: &Reading) {
        let size = self.policy.ladder.ballast_mb << 20;
        if size == 0 {
            return;
        }
        if level == Level::Reserve && !self.ballast_released {
            match resources::release_ballast(&self.data_dir) {
                Ok(0) => {}
                Ok(freed) => {
                    self.ballast_released = true;
                    tracing::error!(
                        freed_mb = freed >> 20,
                        "ballast file released to keep consensus writing: free space now {} MiB",
                        (reading.volume.free_bytes + freed) >> 20
                    );
                }
                Err(e) => warn!(error = %e, "releasing the ballast failed"),
            }
        } else if level == Level::Ok && self.ballast_released {
            self.lay_ballast();
        }
    }

    /// Lays the ballast file if the volume has room for it beyond the first
    /// level's free bytes. Called at start and after a release, once the
    /// level is normal again.
    pub fn lay_ballast(&mut self) {
        let size = self.policy.ladder.ballast_mb << 20;
        let keep = self.policy.ladder.warn_free_gib * resources::GIB;
        match resources::ensure_ballast(&self.data_dir, size, keep) {
            Ok(true) => {
                self.ballast_released = false;
                info!(size_mb = size >> 20, "ballast file laid");
            }
            Ok(false) => {}
            Err(e) => warn!(error = %e, "laying the ballast failed"),
        }
    }

    /// Appends to the proof log the handover of every epoch that closed
    /// since it was last extended, so the log never depends on records the
    /// node later prunes.
    pub fn extend_proof_log(&self) {
        let (Some(consensus), Some(log)) = (self.consensus.as_ref(), self.proof_log.as_ref())
        else {
            return;
        };
        let mut log = log.lock();
        while let Some((certificate, sessions, next)) = consensus.handover(log.count()) {
            let handover = EpochHandover {
                certificate,
                sessions,
                next_members: next.members().to_vec(),
            };
            if let Err(e) = log.append(&handover) {
                warn!(epoch = log.count(), error = %e, "appending to the proof log failed");
                return;
            }
        }
    }

    /// Installs the chain proof a prover dropped, if any, and removes the
    /// file either way: a proof that does not verify is logged and dropped.
    fn take_incoming_chain_proof(&self) {
        let path = &self.incoming_chain_proof;
        let Ok(bytes) = std::fs::read(path) else {
            return;
        };
        match self.install_chain_proof(&bytes) {
            Ok(epoch) => info!(epoch, "handover chain proof installed"),
            Err(e) => warn!(error = %e, "handover chain proof refused"),
        }
        if let Err(e) = std::fs::remove_file(path) {
            warn!(path = %path.display(), error = %e, "removing the delivered chain proof failed");
        }
    }

    /// Verifies a prover's proof of the handover chain (a
    /// [`HandoverChainProof`], bincode) against the handover program the
    /// chain names, and installs it in the proof log in place of the
    /// handovers it covers. Returns the epoch it reaches.
    pub fn install_chain_proof(&self, bytes: &[u8]) -> Result<u64> {
        let refuse = |what: String| NodeError::Other(format!("the chain proof is refused: {what}"));
        let consensus = self
            .consensus
            .as_ref()
            .ok_or_else(|| refuse("this node runs no consensus".into()))?;
        let log = self
            .proof_log
            .as_ref()
            .ok_or_else(|| refuse("this node keeps no proof log".into()))?;
        let state = tenzro_vm::StateAdapter::with_storage(self.storage.clone() as Arc<dyn KvStore>);
        let program = tenzro_vm::native::read_handover_program(&state)
            .ok_or_else(|| refuse("the chain names no handover program".into()))?;
        let proof: HandoverChainProof =
            bincode::deserialize(bytes).map_err(|e| refuse(format!("it does not decode: {e}")))?;
        let journal = tenzro_zk::handover_chain::verify_receipt(&program, &proof.receipt)
            .map_err(|e| refuse(format!("its receipt does not verify: {e}")))?;
        let journal = HandoverChainJournal::decode(&journal)
            .ok_or_else(|| refuse("its receipt commits no chain journal".into()))?;
        let latest = consensus
            .latest_certificate()
            .ok_or_else(|| refuse("this node has certified no checkpoint".into()))?
            .checkpoint;
        let mut log = log.lock();
        let genesis_root = match log.chain() {
            Some(c) => c.journal.genesis_root,
            None => consensus
                .committee_of(0)
                .ok_or_else(|| refuse("the genesis committee is not known here".into()))?
                .root(),
        };
        if journal.program != program
            || journal.chain_id != latest.chain_id
            || journal.genesis_hash != latest.genesis_hash
            || journal.genesis_root != genesis_root
        {
            return Err(refuse(
                "it is not this chain's, under the handover program".into(),
            ));
        }
        if journal.epoch > latest.epoch {
            return Err(refuse(format!(
                "it reaches epoch {}, past the certified epoch {}",
                journal.epoch, latest.epoch
            )));
        }
        let root = Committee::from_members(journal.epoch, proof.members.clone())
            .map_err(|e| refuse(e.to_string()))?
            .root();
        if root != journal.committee_root {
            return Err(refuse(
                "the members are not the committee it reaches".into(),
            ));
        }
        log.install(crate::proof_log::ChainProof {
            journal,
            members: proof.members,
            receipt: proof.receipt,
        })?;
        Ok(journal.epoch)
    }

    /// The epoch below which no record is needed: covered by the installed
    /// chain proof and the proof log, with every checkpoint archived, and
    /// [`EPOCH_RECORDS_KEPT`] behind the current epoch. 0 when nothing is.
    fn epoch_records_floor(&self, consensus: &ConsensusHandle, archive: &HistoryArchive) -> u64 {
        let Some(log) = self.proof_log.as_ref() else {
            return 0;
        };
        let (chain, logged) = {
            let log = log.lock();
            (log.chain_epoch(), log.count())
        };
        let Some(latest) = consensus.latest_certificate().map(|c| c.checkpoint) else {
            return 0;
        };
        let next = archive.next_checkpoint().unwrap_or(0);
        let archived = if next > latest.index {
            latest.epoch
        } else {
            consensus.checkpoint(next).map_or(0, |cp| cp.epoch)
        };
        chain
            .min(logged)
            .min(archived)
            .min(latest.epoch.saturating_sub(EPOCH_RECORDS_KEPT))
    }

    fn retention_blocks(&self) -> u64 {
        let chain = tenzro_vm::StateAdapter::with_storage(self.storage.clone() as Arc<dyn KvStore>);
        tenzro_vm::native::network_param(&chain, tenzro_vm::governance::HISTORY_RETENTION_PARAM)
    }

    /// Takes the epoch snapshot for `cp`, just certified, with the proof from
    /// genesis that certifies it written beside it. The handovers come from
    /// the proof log, extended by the epochs that closed since the last
    /// snapshot, and are streamed into the snapshot.
    pub fn snapshot_epoch(&self, cp: &Checkpoint) -> Result<PathBuf> {
        if let Some(why) = self.guard.refuse(Action::Snapshot, "epoch snapshot") {
            return Err(NodeError::Other(why));
        }
        let volume = resources::volume_stats(&self.data_dir)
            .map_err(|e| NodeError::Other(format!("free space of the data volume: {e}")))?;
        let need = resources::snapshot_need_bytes(
            &self.data_dir.join("db"),
            &snapshot_root(&self.data_dir),
        );
        resources::headroom(&volume, need, &self.policy.ladder)
            .map_err(|short| NodeError::Other(format!("epoch snapshot not started: {short}")))?;
        if let (Some(consensus), Some(log)) = (self.consensus.as_ref(), self.proof_log.as_ref()) {
            let missing = || {
                NodeError::Other(format!(
                    "no proof from genesis is kept for checkpoint {}",
                    cp.index
                ))
            };
            let certificate = consensus.certificate(cp.index).ok_or_else(missing)?;
            let sessions = consensus.session_bundle(&certificate);
            let mut log = log.lock();
            // Past a chain proof the genesis committee is not part of the
            // proof, and its record may be pruned.
            let genesis = match log.chain() {
                Some(_) => Vec::new(),
                None => consensus
                    .committee_of(0)
                    .ok_or_else(missing)?
                    .members()
                    .to_vec(),
            };
            while log.count() < cp.epoch {
                let (certificate, sessions, next) =
                    consensus.handover(log.count()).ok_or_else(missing)?;
                log.append(&tenzro_consensus::light_client::EpochHandover {
                    certificate,
                    sessions,
                    next_members: next.members().to_vec(),
                })?;
            }
            if log.count() == cp.epoch {
                let name = format!("epoch-{:020}-{:020}", cp.epoch, cp.index);
                return Ok(self.snapshots.take_with(&self.storage, &name, &mut |out| {
                    log.write_proof(&genesis, &certificate, &sessions, out)
                })?);
            }
        }
        let proof = self
            .consensus
            .as_ref()
            .and_then(|c| c.checkpoint_proof(cp.index))
            .ok_or_else(|| {
                NodeError::Other(format!(
                    "no proof from genesis is kept for checkpoint {}",
                    cp.index
                ))
            })?;
        self.snapshot_with_proof(&proof)
    }

    fn snapshot_with_proof(&self, proof: &CheckpointProof) -> Result<PathBuf> {
        let cp = &proof.certificate.checkpoint;
        let name = format!("epoch-{:020}-{:020}", cp.epoch, cp.index);
        let meta = bincode::serialize(proof)
            .map_err(|e| NodeError::Other(format!("encode checkpoint proof: {e}")))?;
        Ok(self.snapshots.take(&self.storage, &name, &meta)?)
    }

    /// Runs until the process exits: a pass every minute, and an epoch
    /// snapshot as each epoch's last checkpoint is certified.
    pub async fn run(mut self, data_dir: PathBuf) {
        let mut epochs = self
            .consensus
            .as_ref()
            .map(|c| c.subscribe_epoch_certified());
        let mut tick = tokio::time::interval(TICK);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        self.lay_ballast();
        loop {
            let epoch = async {
                match epochs.as_mut() {
                    Some(rx) => rx
                        .changed()
                        .await
                        .ok()
                        .and_then(|_| rx.borrow_and_update().clone()),
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = tick.tick() => {
                    self.report_memory();
                    let height = self.consensus.as_ref().map_or(0, |c| c.certified_height());
                    match self.measure(height) {
                        Ok(reading) => {
                            let pct = reading.volume.used_pct();
                            self.pass_with(reading, pct).await;
                        }
                        Err(e) => warn!(error = %e, "cannot read data volume usage; disk levels not evaluated"),
                    }
                }
                Some(cp) = epoch => {
                    match self.snapshot_epoch(&cp) {
                        Ok(dir) => {
                            let (_, extra) = resources::unique_bytes(&data_dir.join("db"), &dir);
                            info!(
                                epoch = cp.epoch,
                                index = cp.index,
                                dir = %dir.display(),
                                extra_mb = extra >> 20,
                                "epoch snapshot taken (extra_mb is what it holds beyond the live store)"
                            );
                        }
                        Err(e) => warn!(epoch = cp.epoch, error = %e, "epoch snapshot failed"),
                    }
                }
            }
        }
    }
}

/// Recomputes the state at `cp.state_height` from the store's own entries,
/// bucket by bucket, and checks it rebuilds `cp.state_root`.
pub fn verify_state(storage: Arc<RocksDbStore>, cp: &Checkpoint) -> Result<()> {
    let trie = StateTrie::new(storage as Arc<dyn KvStore>);
    let scheme = trie.scheme_at(cp.state_height)?;
    let summaries = trie.bucket_summaries(cp.state_height)?;
    for s in &summaries {
        let entries = trie.bucket_entries(cp.state_height, s.index)?;
        verify_bucket(scheme, s.index, &entries, &s.subtree)?;
    }
    let root = root_from_buckets(scheme, &summaries)?;
    if root.0 != cp.state_root {
        return Err(NodeError::Other(format!(
            "the snapshot's state at height {} has root {root}; checkpoint {} certifies {}",
            cp.state_height,
            cp.index,
            hex::encode(cp.state_root)
        )));
    }
    Ok(())
}

/// Copies the newest epoch snapshot under `data_dir` to `dest`, only SST
/// files not already backed up there, at `bytes_per_sec`.
pub fn backup_latest(data_dir: &Path, dest: &Path, bytes_per_sec: u64) -> Result<BackupReport> {
    let latest = SnapshotDir::new(snapshot_root(data_dir), usize::MAX)
        .latest()?
        .ok_or_else(|| {
            NodeError::Other(format!(
                "no epoch snapshot under {}",
                snapshot_root(data_dir).display()
            ))
        })?;
    Ok(backup::incremental_backup(&latest, dest, bytes_per_sec)?)
}

/// A checkpoint proof as the proof log writes it: from genesis, or
/// [`crate::proof_log::CHAINED_PROOF_TAG`] then a proof from the newest
/// proof of the handover chain. Untrusted until verified.
pub fn decode_proof(bytes: &[u8]) -> Result<Certification> {
    let tag = crate::proof_log::CHAINED_PROOF_TAG;
    if let Some(rest) = bytes.strip_prefix(tag.as_slice()) {
        bincode::deserialize(rest)
            .map(Certification::Chained)
            .map_err(|e| NodeError::Other(format!("chained checkpoint proof: {e}")))
    } else {
        bincode::deserialize(bytes)
            .map(Certification::FromGenesis)
            .map_err(|e| NodeError::Other(format!("checkpoint proof: {e}")))
    }
}

/// The proof a snapshot was written with. Untrusted until verified.
pub fn snapshot_proof(snapshot: &Path) -> Result<Certification> {
    decode_proof(&backup::read_meta(snapshot)?)
}

/// Restores the store under `data_dir` from `snapshot`. The snapshot's
/// checkpoint must be certified: `proof` (fetched from peers or given as a
/// file), or else the proof kept with the snapshot, must verify from the
/// genesis `anchor`, each certificate's signatures checked against the
/// committee of its epoch, and must certify exactly the snapshot's
/// checkpoint. The snapshot's state must then rebuild that checkpoint's
/// certified state root. Otherwise nothing is restored.
pub fn restore(
    snapshot: &Path,
    data_dir: &Path,
    anchor: &GenesisAnchor,
    proof: Option<Certification>,
    handover_program: Option<[u8; 32]>,
) -> Result<Checkpoint> {
    let kept = snapshot_proof(snapshot)?;
    let snapshot_digest = kept.checkpoint().digest();
    let proof = proof.unwrap_or(kept);
    let cp =
        crate::proof_log::verify_certification(&proof, anchor, handover_program).map_err(|e| {
            NodeError::Other(format!("the snapshot's checkpoint is not certified: {e}"))
        })?;
    if cp.digest() != snapshot_digest {
        return Err(NodeError::Other(format!(
            "the proof certifies checkpoint {} ({}), not the snapshot's ({})",
            cp.index,
            hex::encode(cp.digest()),
            hex::encode(snapshot_digest)
        )));
    }
    restore_certified(snapshot, data_dir, &cp)
}

/// One JSON-RPC call to the peer at `peer`.
async fn peer_call(
    peer: &str,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value> {
    let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
    let reply: serde_json::Value = reqwest::Client::new()
        .post(peer)
        .json(&body)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| NodeError::Other(format!("{method} from {peer}: {e}")))?
        .json()
        .await
        .map_err(|e| NodeError::Other(format!("{method} from {peer}: {e}")))?;
    reply
        .get("result")
        .cloned()
        .ok_or_else(|| NodeError::Other(format!("{method} from {peer}: {}", reply["error"])))
}

/// Fetches from the peer RPC at `peer` its newest proof of the handover
/// chain and the handovers since, up to epoch `to_epoch` (all it holds when
/// `None`). A peer that dropped the handovers its chain proof covers serves
/// it all the same. Nothing fetched is trusted.
pub async fn fetch_segment(
    peer: &str,
    to_epoch: Option<u64>,
) -> Result<crate::proof_log::ChainSegment> {
    let params = to_epoch.map_or(serde_json::json!([]), |e| serde_json::json!([e]));
    crate::proof_log::ChainSegment::from_reply(
        &peer_call(peer, "tenzro_getHandoverChain", params).await?,
    )
    .map_err(|e| NodeError::Other(format!("tenzro_getHandoverChain from {peer}: {e}")))
}

/// Fetches from the peer RPC at `peer` the certification of checkpoint
/// `index` of `epoch`: the peer's chain segment to that epoch and the
/// checkpoint's certificate. Nothing fetched is trusted: [`restore`]
/// verifies it.
pub async fn fetch_certification(peer: &str, epoch: u64, index: u64) -> Result<Certification> {
    fn field<T: serde::de::DeserializeOwned>(v: &serde_json::Value, name: &str) -> Result<T> {
        let hex_str = v[name]
            .as_str()
            .ok_or_else(|| NodeError::Other(format!("peer reply has no {name}")))?;
        let bytes = hex::decode(hex_str.trim_start_matches("0x"))
            .map_err(|e| NodeError::Other(format!("peer {name} is not hex: {e}")))?;
        bincode::deserialize(&bytes)
            .map_err(|e| NodeError::Other(format!("peer {name} does not decode: {e}")))
    }
    let segment = fetch_segment(peer, Some(epoch)).await?;
    let c = peer_call(
        peer,
        "tenzro_getCheckpointCertificate",
        serde_json::json!([index]),
    )
    .await?;
    Ok(segment.certify(field(&c, "certificate")?, field(&c, "sessions")?))
}

/// Restores the store under `data_dir` from `snapshot` once its state
/// rebuilds the root certified by `cp`; otherwise the restored files are
/// removed.
fn restore_certified(snapshot: &Path, data_dir: &Path, cp: &Checkpoint) -> Result<Checkpoint> {
    let db_path = data_dir.join("db");
    backup::restore_files(snapshot, &db_path)?;
    let verified = RocksDbStore::open(&StorageConfig::new(db_path.clone()))
        .map_err(NodeError::from)
        .and_then(|s| verify_state(Arc::new(s), cp));
    if let Err(e) = verified {
        if let Err(rm) = std::fs::remove_dir_all(&db_path) {
            warn!(path = %db_path.display(), error = %rm, "removing the refused restore failed");
        }
        return Err(e);
    }
    Ok(cp.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::SubsystemStatus;
    use std::collections::BTreeMap;
    use tenzro_storage::CF_STATE_TRIE;
    use tenzro_storage::resources::VolumeStats;

    fn small_store(dir: &Path) -> Arc<RocksDbStore> {
        Arc::new(
            RocksDbStore::open(&StorageConfig::new(dir.join("db")).with_memory_bytes(8 << 20))
                .unwrap(),
        )
    }

    fn checkpoint(state_height: u64, state_root: [u8; 32]) -> Checkpoint {
        Checkpoint {
            chain_id: 1,
            genesis_hash: [0; 32],
            epoch: 3,
            index: 7,
            prev: [0; 32],
            first_height: 1,
            last_height: 0,
            blocks_root: [0; 32],
            state_height,
            state_root,
            statement_root: [0; 32],
            next_committee_root: Some([1; 32]),
            anchor_round: 1,
            timestamp_ms: 0,
            ordering_root: [0; 32],
        }
    }

    /// A store with committed state at height 5, its epoch snapshot, and the
    /// checkpoint certifying that state.
    fn snapshotted(tmp: &Path) -> (PathBuf, Checkpoint) {
        let storage = small_store(tmp);
        let trie = StateTrie::new(storage.clone() as Arc<dyn KvStore>);
        let mut writes = BTreeMap::new();
        for i in 0..50u32 {
            writes.insert(
                ("accounts".to_string(), i.to_be_bytes().to_vec()),
                Some(vec![i as u8; 40]),
            );
        }
        let root = trie.commit(5, &writes).unwrap();
        let cp = checkpoint(5, root.0);
        let m = StorageMaintenance::new(
            storage,
            tmp,
            StoragePolicy::default(),
            Arc::new(DiskGuard::default()),
            Arc::new(HealthMonitor::new()),
            None,
            None,
            tenzro_model::memory_budget::global(),
        );
        (m.snapshot_with_proof(&uncertified(cp.clone())).unwrap(), cp)
    }

    /// A proof naming `cp` that carries no signatures.
    fn uncertified(cp: Checkpoint) -> CheckpointProof {
        CheckpointProof {
            genesis_members: Vec::new(),
            handovers: Vec::new(),
            certificate: tenzro_consensus::Certificate {
                checkpoint: cp,
                signers: Vec::new(),
                sessions: Vec::new(),
                signatures: Vec::new(),
            },
            sessions: Vec::new(),
        }
    }

    #[test]
    fn restore_verifies_the_state_against_the_checkpoint() {
        let tmp = tempfile::tempdir().unwrap();
        let (snap, cp) = snapshotted(tmp.path());
        let target = tmp.path().join("node");
        let got = restore_certified(&snap, &target, &cp).unwrap();
        assert_eq!(got, cp);
        assert!(target.join("db").exists());
    }

    #[test]
    fn restore_refuses_an_uncertified_snapshot() {
        let tmp = tempfile::tempdir().unwrap();
        let (snap, cp) = snapshotted(tmp.path());
        let anchor = GenesisAnchor {
            chain_id: cp.chain_id,
            genesis_hash: cp.genesis_hash,
            committee_root: [4; 32],
        };
        let target = tmp.path().join("node");
        let err = restore(&snap, &target, &anchor, None, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not certified"), "{err}");
        // The same checkpoint, its digest known, is still refused without
        // a certificate.
        let err = restore(
            &snap,
            &target,
            &anchor,
            Some(Certification::FromGenesis(uncertified(cp))),
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("not certified"), "{err}");
        assert!(!target.join("db").exists(), "nothing restored");
    }

    #[test]
    fn restore_rejects_a_tampered_state() {
        let tmp = tempfile::tempdir().unwrap();
        let (snap, cp) = snapshotted(tmp.path());
        // Alter one committed value inside the snapshot.
        {
            let s = RocksDbStore::open(&StorageConfig::new(snap.clone())).unwrap();
            let (key, mut value) = s
                .scan_prefix(CF_STATE_TRIE, b"V")
                .unwrap()
                .into_iter()
                .next()
                .unwrap();
            *value.last_mut().unwrap() ^= 0xff;
            s.put(CF_STATE_TRIE, &key, &value).unwrap();
        }
        let target = tmp.path().join("node");
        assert!(
            restore_certified(&snap, &target, &cp).is_err(),
            "a tampered state is refused"
        );
        assert!(
            !target.join("db").exists(),
            "the refused restore is removed"
        );
    }

    #[test]
    fn a_tampered_state_root_does_not_verify() {
        let tmp = tempfile::tempdir().unwrap();
        let (snap, cp) = snapshotted(tmp.path());
        let s = Arc::new(RocksDbStore::open(&StorageConfig::new(snap)).unwrap());
        let mut forged = cp.clone();
        forged.state_root[0] ^= 1;
        let err = verify_state(s.clone(), &forged).unwrap_err().to_string();
        assert!(err.contains("certifies"), "{err}");
        verify_state(s, &cp).unwrap();
    }

    #[tokio::test]
    async fn the_levels_flag_prune_compact_and_refuse_but_never_block_writes() {
        let tmp = tempfile::tempdir().unwrap();
        let storage = small_store(tmp.path());
        let guard = Arc::new(DiskGuard::default());
        let health = Arc::new(HealthMonitor::new());
        let mut m = StorageMaintenance::new(
            storage.clone(),
            tmp.path(),
            StoragePolicy::default(),
            guard.clone(),
            health.clone(),
            None,
            None,
            tenzro_model::memory_budget::global(),
        );

        // A hundred-gibibyte volume, half free.
        let r = m.pass_with(volume_reading(100, 50, None), 50).await;
        assert!(!r.compacted);
        assert_eq!(
            pressure_retention(1_000_000, DiskPressure::Normal),
            1_000_000
        );
        assert_eq!(
            pressure_retention(1_000_000, DiskPressure::Pruning),
            250_000
        );
        assert_eq!(
            pressure_retention(1_000_000, DiskPressure::Refusing),
            62_500
        );
        assert_eq!(pressure_retention(20_000, DiskPressure::Refusing), 10_000);
        assert_eq!(pressure_retention(10_000, DiskPressure::Refusing), 10_000);
        assert_eq!(guard.status().pressure, DiskPressure::Normal);
        assert!(guard.refusal("model download").is_none());

        // 10 GiB and 10 percent free: under the prune pair, over the refuse pair.
        let r = m.pass_with(volume_reading(100, 10, None), 90).await;
        assert!(r.compacted, "the prune level compacts");
        assert_eq!(guard.status().pressure, DiskPressure::Pruning);
        assert!(
            guard.refusal("model download").is_none(),
            "pruning alone refuses nothing"
        );
        let disk = |h: &HealthMonitor| {
            h.list_subsystems()
                .into_iter()
                .find(|(n, ..)| n == DISK_SUBSYSTEM)
                .map(|(_, s, _)| s)
        };
        assert!(matches!(
            disk(&health),
            Some(SubsystemStatus::Degraded { .. })
        ));

        // 5 GiB and 5 percent free: under the refuse pair.
        let r = m.pass_with(volume_reading(100, 5, None), 95).await;
        assert!(!r.compacted, "compaction is spaced out");
        let status = guard.status();
        assert_eq!(status.pressure, DiskPressure::Refusing);
        assert!(status.refusing_non_essential);
        assert!(
            guard
                .refusal("model download")
                .unwrap()
                .contains("95% full")
        );
        // Consensus-critical writes go to the store directly and continue.
        storage
            .write_batch_sync(vec![tenzro_storage::WriteOp::Put {
                cf: tenzro_storage::CF_BLOCKS.to_string(),
                key: b"block".to_vec(),
                value: b"body".to_vec(),
            }])
            .unwrap();

        m.pass_with(volume_reading(100, 60, None), 40).await;
        assert!(guard.refusal("model download").is_none());
        assert!(matches!(disk(&health), Some(SubsystemStatus::Healthy)));
    }

    #[tokio::test]
    async fn a_large_volume_with_room_is_left_alone_however_full_by_percent() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut m, guard) = maintenance(tmp.path(), 0);
        // 58 of 3700 GiB free is 99 percent used, and more room than the
        // first level asks for.
        m.pass_with(volume_reading(3700, 58, None), 99).await;
        assert_eq!(guard.status().pressure, DiskPressure::Normal);
        assert!(guard.refusal("snapshot").is_none());
        // The same percent on a small volume is the last reserve.
        m.pass_with(volume_reading(100, 1, None), 99).await;
        assert_eq!(guard.status().pressure, DiskPressure::Refusing);
        assert!(guard.refusal("snapshot").is_some());
    }

    #[test]
    fn the_edge_tier_sizes_the_store_for_a_small_board() {
        let edge = crate::tier::Tier::Edge.tuning(4);
        let server = crate::tier::Tier::Validator.tuning(4);
        let policy = StoragePolicy::default();
        for (gb, edge_mb, server_mb) in [(2u64, 96u64, 256u64), (4, 192, 256), (16, 256, 384)] {
            // A small machine's budget lends out three quarters of it.
            let budget = MemoryBudget::new(tenzro_model::memory_budget::BudgetConfig {
                total_bytes: gb << 30,
                reserve_bytes: (gb << 30) / 4,
                resident_ceiling_bytes: None,
                on_demand_ceiling_bytes: None,
            })
            .unwrap();
            assert_eq!(
                policy.memory_bytes(&budget, &edge) >> 20,
                edge_mb,
                "{gb} GB edge"
            );
            assert_eq!(
                policy.memory_bytes(&budget, &server) >> 20,
                server_mb,
                "{gb} GB server"
            );
        }
        let config = policy.store_config(
            PathBuf::from("/nonexistent"),
            &MemoryBudget::new(tenzro_model::memory_budget::BudgetConfig::with_total(
                64 << 30,
            ))
            .unwrap(),
            &edge,
        );
        assert_eq!(config.background_jobs, 1);
        assert_eq!(config.max_open_files, 256);
        assert_eq!(config.write_buffer_size, 16 << 20);
        assert_eq!(config.background_write_bytes_per_sec, 16 << 20);
    }

    #[test]
    fn the_store_memory_is_charged_to_the_budget() {
        let budget = MemoryBudget::new(tenzro_model::memory_budget::BudgetConfig::with_total(
            64 << 30,
        ))
        .unwrap();
        let before = budget.available_in(Tier::Resident);
        let policy = StoragePolicy {
            memory_mb: Some(512),
            ..StoragePolicy::default()
        };
        let config = policy.store_config(
            PathBuf::from("/nonexistent"),
            &budget,
            &crate::tier::Tier::Validator.tuning(8),
        );
        assert_eq!(config.memory_bytes, 512 << 20);
        assert_eq!(
            before - budget.available_in(Tier::Resident),
            512 << 20,
            "models see less room"
        );
    }

    fn maintenance(tmp: &Path, ballast_mb: u64) -> (StorageMaintenance, Arc<DiskGuard>) {
        let storage = small_store(&tmp.join("db"));
        let guard = Arc::new(DiskGuard::default());
        let policy = StoragePolicy {
            ladder: LadderConfig {
                ballast_mb,
                ..LadderConfig::default()
            },
            ..StoragePolicy::default()
        };
        let m = StorageMaintenance::new(
            storage,
            tmp,
            policy,
            guard.clone(),
            Arc::new(HealthMonitor::new()),
            None,
            None,
            tenzro_model::memory_budget::global(),
        );
        (m, guard)
    }

    fn volume_reading(total_gib: u64, free_gib: u64, per_block: Option<f64>) -> Reading {
        Reading {
            volume: VolumeStats::of(total_gib * resources::GIB, free_gib * resources::GIB),
            host: Default::default(),
            bytes_per_block: per_block,
        }
    }

    #[tokio::test]
    async fn a_fast_filler_raises_the_level_by_runway_while_the_percent_is_still_fine() {
        let tmp = tempfile::tempdir().unwrap();
        let (mut m, guard) = maintenance(tmp.path(), 0);
        // 500 of 1000 GiB free: 50 percent, no level near by size.
        m.pass_with(volume_reading(1000, 500, Some(1_000.0)), 50)
            .await;
        assert_eq!(guard.level(), Level::Ok);
        // 230 KB a block leaves about 2.3 million blocks: the first level.
        m.pass_with(volume_reading(1000, 500, Some(230_000.0)), 50)
            .await;
        assert_eq!(guard.level(), Level::Warn);
        let status = guard.status();
        assert_eq!(status.pressure, DiskPressure::Normal);
        let a = status.assessment.expect("an assessment is reported");
        assert!(a.runway_blocks.unwrap() < 3_000_000);
        assert!(a.summary.contains("runway"));
        // 4 MB a block leaves 130,000 blocks: refusing, at 50 percent used.
        m.pass_with(volume_reading(1000, 500, Some(4_000_000.0)), 50)
            .await;
        assert_eq!(guard.level(), Level::Refuse);
        assert!(guard.refuse(Action::Snapshot, "epoch snapshot").is_some());
        assert!(guard.refuse(Action::Relay, "relay").is_some());
        assert_eq!(
            guard.status().assessment.unwrap().next_sacrificed,
            Some(resources::DataClass::Regenerable)
        );
    }

    #[tokio::test]
    async fn the_last_level_releases_the_ballast_and_never_a_critical_path() {
        let tmp = tempfile::tempdir().unwrap();
        let d = tmp.path();
        for p in [
            "consensus",
            "iroh",
            "device-keys",
            "wallets",
            "epoch-proof",
            "audit",
        ] {
            std::fs::create_dir_all(d.join(p)).unwrap();
            std::fs::write(d.join(p).join("secret"), b"keep").unwrap();
        }
        std::fs::write(d.join("genesis.json"), b"{}").unwrap();
        let (mut m, guard) = maintenance(d, 1);
        std::fs::write(d.join(resources::BALLAST_FILE), vec![0u8; 1 << 20]).unwrap();
        std::fs::create_dir_all(d.join("epoch-snapshots/e1.partial")).unwrap();
        m.pass_with(volume_reading(100, 2, None), 98).await;
        assert_eq!(guard.level(), Level::Reserve);
        assert!(
            !d.join(resources::BALLAST_FILE).exists(),
            "the ballast is released"
        );
        assert!(guard.refuse(Action::Snapshot, "epoch snapshot").is_some());
        assert!(guard.refuse(Action::Compaction, "compaction").is_some());
        for p in [
            "consensus",
            "iroh",
            "device-keys",
            "wallets",
            "epoch-proof",
            "audit",
        ] {
            assert!(
                d.join(p).join("secret").exists(),
                "{p} must survive every level"
            );
        }
        assert!(d.join("genesis.json").exists());
        assert!(d.join("db").exists(), "the store is never removed");
    }

    #[test]
    fn an_unfinished_snapshot_is_removed_when_maintenance_starts() {
        let tmp = tempfile::tempdir().unwrap();
        let partial = tmp.path().join("epoch-snapshots/epoch-1-2.partial");
        std::fs::create_dir_all(&partial).unwrap();
        std::fs::write(partial.join("000001.sst"), vec![0u8; 4096]).unwrap();
        let done = tmp.path().join("epoch-snapshots/epoch-1-1");
        std::fs::create_dir_all(&done).unwrap();
        std::fs::write(done.join(tenzro_storage::backup::SNAPSHOT_META), b"m").unwrap();
        let _ = maintenance(tmp.path(), 0);
        assert!(!partial.exists());
        assert!(done.exists(), "a finished snapshot stays");
    }

    #[test]
    fn the_window_shrinks_with_the_level_and_never_below_the_floor() {
        assert_eq!(level_retention(1_209_600, Level::Ok), 1_209_600);
        assert_eq!(level_retention(1_209_600, Level::Warn), 1_209_600);
        assert_eq!(level_retention(1_209_600, Level::Prune), 302_400);
        assert_eq!(level_retention(1_209_600, Level::Refuse), 75_600);
        assert_eq!(
            level_retention(1_209_600, Level::Reserve),
            MIN_PRESSURE_RETENTION_BLOCKS
        );
        assert_eq!(level_retention(5_000, Level::Reserve), 5_000);
    }

    #[test]
    fn history_stays_under_a_small_byte_budget_as_the_chain_grows() {
        let per_block = 100_000u64;
        let budget = 20_000_000u64;
        let min_blocks = 10;
        let (mut oldest, mut certified) = (0u64, 0u64);
        let mut pruned_at_least_once = false;
        for _ in 0..400 {
            certified += 37;
            let held = (certified - oldest + 1) * per_block;
            if let Some(floor) = budget_floor(held, budget, oldest, certified, min_blocks) {
                assert!(floor > oldest && floor <= certified - min_blocks);
                oldest = floor;
                pruned_at_least_once = true;
            }
            let after = (certified - oldest + 1) * per_block;
            assert!(
                after <= budget,
                "{after} bytes held over a budget of {budget}"
            );
        }
        assert!(pruned_at_least_once);
        // The pass leaves room below the budget so it does not prune every time.
        let held = (certified - oldest + 1) * per_block;
        assert!(held <= budget / 100 * 100);
    }

    #[test]
    fn the_budget_never_cuts_below_the_recent_blocks_and_waits_while_within() {
        assert_eq!(budget_floor(10, 100, 0, 1_000, 10), None);
        // A budget smaller than the floor of recent blocks keeps the blocks.
        let floor = budget_floor(1_000_000, 10, 0, 999, 100).unwrap();
        assert_eq!(floor, 899);
        assert_eq!(budget_floor(5, 1, 500, 100, 10), None, "nothing held");
    }

    #[test]
    fn the_history_budget_is_a_share_of_the_volume_unless_set() {
        let p = StoragePolicy::default();
        assert_eq!(
            p.history_budget(1000 * resources::GIB),
            Some(350 * resources::GIB)
        );
        let own = StoragePolicy {
            history_budget_bytes: Some(7),
            ..StoragePolicy::default()
        };
        assert_eq!(own.history_budget(1000 * resources::GIB), Some(7));
        let off = StoragePolicy {
            history_budget_pct: 0,
            ..StoragePolicy::default()
        };
        assert_eq!(off.history_budget(1000 * resources::GIB), None);
    }

    #[test]
    fn history_bytes_counts_blocks_transactions_and_events_only() {
        let tmp = tempfile::tempdir().unwrap();
        let store = small_store(tmp.path());
        // Incompressible values, so the size on disk is the size written.
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut value = vec![0u8; 4096];
        for i in 0..2_000u32 {
            for cf in ["blocks", "transactions", "events"] {
                for b in value.iter_mut() {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    *b = x as u8;
                }
                store.put(cf, &i.to_be_bytes(), &value).unwrap();
            }
        }
        store.compact_history();
        let held = history_bytes(&store);
        assert!(held > 3 * 2_000 * 2_000, "{held}");
        let state_only: u64 = store
            .cf_sizes()
            .iter()
            .filter(|c| !resources::PRUNE_COLUMN_FAMILIES.contains(&c.name))
            .map(|c| c.sst_files)
            .sum();
        assert!(held > state_only);
    }
}
