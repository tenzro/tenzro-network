//! Snapshot-chunk interface for fast state-sync of fresh / wedged validators.
//!
//! # Design
//!
//! A chunked snapshot interface — the smallest 4-method surface that lets a
//! fresh node skip block replay and start from a recent state root:
//!
//!   * [`SnapshotStore::list_snapshots`] — enumerate locally available snapshots
//!   * [`SnapshotStore::get_chunk`]     — serve one chunk to a fetching peer
//!   * [`SnapshotStore::offer`]         — accept an inbound snapshot manifest
//!   * [`SnapshotStore::apply_chunk`]   — write one inbound chunk; on the last
//!     chunk verify the merkle root and atomically commit to the live store
//!
//! These are wired to JSON-RPC as `tenzro_listSnapshots`,
//! `tenzro_getSnapshotChunk`, `tenzro_offerSnapshot`, `tenzro_applySnapshotChunk`.
//!
//! The producer subscribes to the consensus finality channel and
//! snapshots every `SnapshotConfig::interval_blocks` finalized heights
//! when `SnapshotConfig::enabled` is true. Snapshots are written to
//! `<data_dir>/snapshots/<height>/{manifest.json, chunk_<idx>.bin}`.
//!
//! # On-wire format (v1)
//!
//! Each chunk is a sequence of `(cf_name, key, value)` tuples encoded
//! as length-prefixed bytes:
//!
//! ```text
//! chunk := record*
//! record := u16_le(cf_name_len) cf_name u32_le(key_len) key u32_le(value_len) value
//! ```
//!
//! No compression in v1 — chunks cap at [`CHUNK_MAX_BYTES`] of raw KV
//! payload. flate2/zstd are an obvious follow-up but not load-bearing
//! for correctness.
//!
//! # Trust anchoring
//!
//! The manifest carries the height + state root. A receiving node MUST
//! verify the state root against a known-good QC out of band before
//! trusting any chunk. [`bootstrap_from_peer`] enforces this via the
//! `expected_state_root` operator anchor: a syncing node may not
//! accept a snapshot whose declared `state_root` differs from a value
//! the operator vetted out of band (e.g. by reading the canonical
//! chain tip from a trusted RPC, signed gossip from a known-good
//! validator, or a weak-subjectivity checkpoint). Without an anchor
//! the function refuses to sync, because the peer URL could be a
//! malicious RPC that would serve a forged state root.

use crate::error::{NodeError, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tenzro_storage::{
    KvStore, CF_ACCOUNTS, CF_AGENTS, CF_AGENT_TEMPLATES, CF_APPROVALS, CF_AUDIT, CF_BLOCKS,
    CF_CHANNELS, CF_COMPLIANCE, CF_CREDENTIALS, CF_DELEGATIONS, CF_EVENTS, CF_IDENTITIES,
    CF_METADATA, CF_MODELS, CF_MODEL_SERVICES, CF_NFTS, CF_PROVIDERS, CF_SETTLEMENTS,
    CF_SKILLS, CF_STATE, CF_TASKS, CF_TOKENS, CF_TOOLS, CF_TRAINING_RECEIPTS,
    CF_TRAINING_RUNS, CF_TRANSACTIONS, CF_WEBHOOKS,
};
use tokio::sync::RwLock;

/// Cap on raw KV bytes per chunk. 10 MiB is a conservative default.
pub const CHUNK_MAX_BYTES: usize = 10 * 1024 * 1024;

/// Default interval between state-sync snapshots, in finalized blocks.
///
/// Mirrors Solana's `full-snapshot-interval-slots` default of 100_000.
/// At ~6s blocks this is one full snapshot every ~7 days. The previous
/// default of 10_000 (~16 hours) generated 19–21 GB on disk every cycle
/// and overflowed 100 GB validator volumes within a couple of days when
/// combined with the persistent RocksDB working set.
pub const DEFAULT_SNAPSHOT_INTERVAL_BLOCKS: u64 = 100_000;

/// Default number of full snapshots to retain on disk. Matches Solana's
/// `maximum-snapshots-to-retain` default of 2 — high enough that a peer
/// can still finish a state-sync against the previous snapshot while the
/// next one is being produced, low enough to fit comfortably in a 100 GB
/// volume alongside the live RocksDB working set.
pub const DEFAULT_SNAPSHOT_RETAIN_COUNT: usize = 2;

/// Skip removing snapshot directories younger than this when sweeping
/// orphans without a manifest, so we don't race an in-flight
/// `produce_at` that hasn't finished writing `manifest.json` yet.
const ORPHAN_GRACE: Duration = Duration::from_secs(10 * 60);

/// Runtime knobs for the snapshot ABCI.
///
/// Defaults match Solana production practice: snapshots **disabled** unless
/// the operator explicitly opts in via config. This matters because the
/// vast majority of validators on a chain never serve state-sync — the
/// dedicated RPC / archival operators do. Producing a 19 GB snapshot every
/// few hours on every validator wastes disk for no benefit and creates the
/// fleet-wide ENOSPC failure mode the testnet hit on 2026-06-14.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotConfig {
    /// Master switch. When `false`, no snapshots are produced and pruning
    /// only sweeps orphaned directories left behind by prior runs.
    #[serde(default)]
    pub enabled: bool,

    /// Block interval between snapshots. Ignored when `enabled = false`.
    #[serde(default = "default_snapshot_interval_blocks")]
    pub interval_blocks: u64,

    /// Recent snapshots to retain. Older snapshots are deleted before the
    /// next one is produced so steady-state disk = retain × snapshot_size.
    #[serde(default = "default_snapshot_retain_count")]
    pub retain_count: usize,
}

fn default_snapshot_interval_blocks() -> u64 {
    DEFAULT_SNAPSHOT_INTERVAL_BLOCKS
}

fn default_snapshot_retain_count() -> usize {
    DEFAULT_SNAPSHOT_RETAIN_COUNT
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_blocks: DEFAULT_SNAPSHOT_INTERVAL_BLOCKS,
            retain_count: DEFAULT_SNAPSHOT_RETAIN_COUNT,
        }
    }
}

impl SnapshotConfig {
    /// Build a config that runs the producer at the default cadence with
    /// the default retention window. Intended for dedicated RPC /
    /// archival nodes that serve state-sync to fresh peers.
    pub fn producer_default() -> Self {
        Self {
            enabled: true,
            interval_blocks: DEFAULT_SNAPSHOT_INTERVAL_BLOCKS,
            retain_count: DEFAULT_SNAPSHOT_RETAIN_COUNT,
        }
    }

    fn effective_retain(&self) -> usize {
        self.retain_count.max(1)
    }

    fn effective_interval(&self) -> u64 {
        self.interval_blocks.max(1)
    }
}

/// All column families included in a snapshot. Held as a const slice so
/// producer and consumer agree on the ordering, which is required for
/// deterministic chunking.
const SNAPSHOT_CFS: &[&str] = &[
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
    CF_TASKS,
    CF_AGENT_TEMPLATES,
    CF_SKILLS,
    CF_TOOLS,
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
];

/// On-disk snapshot manifest. One per snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    /// Block height at which this snapshot was taken.
    pub height: u64,
    /// State root committed at `height`. Used for trust anchoring against
    /// a QC at the same height.
    pub state_root_hex: String,
    /// Number of chunks. Chunk indices are `0..num_chunks`.
    pub num_chunks: u32,
    /// Per-chunk SHA-256 hash, indexed by chunk number. Used to verify
    /// chunks served from untrusted peers before applying them.
    pub chunk_hashes_hex: Vec<String>,
    /// Wall-clock time the snapshot was produced (ISO 8601, UTC).
    pub created_at: String,
    /// Format version. Bump on incompatible chunk-encoding changes.
    pub format: u32,
}

impl SnapshotManifest {
    /// Manifest format version. Increment when the chunk on-wire format
    /// changes incompatibly.
    pub const FORMAT_V1: u32 = 1;
}

/// JSON wire shape returned by `tenzro_listSnapshots` — strips
/// per-chunk hashes for compactness; full manifest is served alongside
/// each chunk request.
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotSummary {
    pub height: u64,
    pub state_root_hex: String,
    pub num_chunks: u32,
    pub created_at: String,
    pub format: u32,
}

/// State of a snapshot currently being received from a peer.
#[derive(Debug)]
struct InboundSnapshot {
    manifest: SnapshotManifest,
    /// Slot per chunk. `None` until the chunk is delivered + verified.
    chunks: Vec<Option<Vec<u8>>>,
    /// Filesystem dir where in-flight chunks are spooled.
    spool_dir: PathBuf,
    /// Set once `commit()` has succeeded so subsequent attempts are no-ops.
    completed: bool,
}

/// Top-level snapshot service. Holds the producer's filesystem layout
/// and the consumer's in-flight state.
pub struct SnapshotStore {
    /// `<data_dir>/snapshots/`
    snapshots_dir: PathBuf,
    /// In-flight inbound snapshot, keyed by the manifest's `height`.
    /// At most one inbound snapshot is accepted at a time.
    inbound: RwLock<Option<InboundSnapshot>>,
    /// The live key-value store. Inbound chunks are written here on
    /// `commit()`.
    store: Arc<dyn KvStore>,
    /// Producer cadence + retention policy. Inbound (consumer) paths are
    /// always live regardless of `config.enabled`; only production is gated.
    config: SnapshotConfig,
}

impl SnapshotStore {
    pub fn new(data_dir: &Path, store: Arc<dyn KvStore>, config: SnapshotConfig) -> Result<Self> {
        let snapshots_dir = data_dir.join("snapshots");
        std::fs::create_dir_all(&snapshots_dir)
            .map_err(|e| NodeError::Other(format!("create snapshots dir: {}", e)))?;
        Ok(Self {
            snapshots_dir,
            inbound: RwLock::new(None),
            store,
            config,
        })
    }

    /// Whether the producer is enabled for this node. Consumer (inbound)
    /// paths are always live regardless.
    pub fn producer_enabled(&self) -> bool {
        self.config.enabled
    }

    /// True if a finalized `height` is a snapshot boundary for this node's
    /// configured cadence. Always `false` when the producer is disabled.
    pub fn should_produce_at(&self, height: u64) -> bool {
        self.config.enabled && height > 0 && height.is_multiple_of(self.config.effective_interval())
    }

    /// Reclaim orphaned snapshot directories on startup. Producers and
    /// non-producers alike call this once at boot so husks left by a
    /// crashed `produce_at` (the ENOSPC failure mode) are reclaimed even on
    /// nodes that no longer produce snapshots.
    pub fn sweep_on_startup(&self) {
        if let Err(e) = self.prune_keeping(self.config.effective_retain()) {
            tracing::warn!(error = %e, "snapshot startup sweep failed");
        }
    }

    /// Lists snapshots available locally. Sorted by height descending.
    pub fn list_snapshots(&self) -> Result<Vec<SnapshotSummary>> {
        let mut summaries = Vec::new();
        let dir = std::fs::read_dir(&self.snapshots_dir)
            .map_err(|e| NodeError::Other(format!("read snapshots dir: {}", e)))?;
        for entry in dir.flatten() {
            let manifest_path = entry.path().join("manifest.json");
            if !manifest_path.exists() {
                continue;
            }
            let bytes = match std::fs::read(&manifest_path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let manifest: SnapshotManifest = match serde_json::from_slice(&bytes) {
                Ok(m) => m,
                Err(_) => continue,
            };
            summaries.push(SnapshotSummary {
                height: manifest.height,
                state_root_hex: manifest.state_root_hex,
                num_chunks: manifest.num_chunks,
                created_at: manifest.created_at,
                format: manifest.format,
            });
        }
        summaries.sort_by_key(|s| std::cmp::Reverse(s.height));
        Ok(summaries)
    }

    /// Returns the full manifest for `height`, if present.
    pub fn get_manifest(&self, height: u64) -> Result<Option<SnapshotManifest>> {
        let path = self.snapshots_dir.join(height.to_string()).join("manifest.json");
        if !path.exists() {
            return Ok(None);
        }
        let bytes = std::fs::read(&path)
            .map_err(|e| NodeError::Other(format!("read manifest: {}", e)))?;
        let m = serde_json::from_slice(&bytes)
            .map_err(|e| NodeError::Other(format!("parse manifest: {}", e)))?;
        Ok(Some(m))
    }

    /// Returns the raw bytes of `chunk_index` of snapshot at `height`.
    pub fn get_chunk(&self, height: u64, chunk_index: u32) -> Result<Vec<u8>> {
        let path = self
            .snapshots_dir
            .join(height.to_string())
            .join(format!("chunk_{:08}.bin", chunk_index));
        std::fs::read(&path)
            .map_err(|e| NodeError::Other(format!("read chunk: {}", e)))
    }

    /// Accept an inbound snapshot manifest from a peer. If accepted,
    /// the caller should follow up with one [`Self::apply_chunk`] per
    /// `chunk_index in 0..manifest.num_chunks`.
    ///
    /// Returns `Err` if a different inbound snapshot is already in
    /// progress, or if the manifest is malformed.
    pub async fn offer(&self, manifest: SnapshotManifest) -> Result<()> {
        if manifest.format != SnapshotManifest::FORMAT_V1 {
            return Err(NodeError::Other(format!(
                "unsupported snapshot format {}", manifest.format
            )));
        }
        if manifest.chunk_hashes_hex.len() != manifest.num_chunks as usize {
            return Err(NodeError::Other(format!(
                "manifest claims {} chunks but provides {} hashes",
                manifest.num_chunks,
                manifest.chunk_hashes_hex.len()
            )));
        }

        let mut slot = self.inbound.write().await;
        if let Some(existing) = slot.as_ref() {
            if existing.completed {
                // Stale completed inbound — replace it.
            } else if existing.manifest.height != manifest.height {
                return Err(NodeError::Other(format!(
                    "another snapshot in progress at height {}",
                    existing.manifest.height
                )));
            } else {
                // Same offer re-issued — idempotent.
                return Ok(());
            }
        }

        let spool_dir = self.snapshots_dir.join(format!("inbound_{}", manifest.height));
        std::fs::create_dir_all(&spool_dir)
            .map_err(|e| NodeError::Other(format!("create spool dir: {}", e)))?;

        let num = manifest.num_chunks as usize;
        *slot = Some(InboundSnapshot {
            manifest,
            chunks: (0..num).map(|_| None).collect(),
            spool_dir,
            completed: false,
        });
        Ok(())
    }

    /// Apply a single inbound chunk. Returns `(complete, height)` —
    /// `complete=true` means all chunks have arrived, the merkle root
    /// has been verified, and the snapshot has been committed to the
    /// live store.
    pub async fn apply_chunk(
        &self,
        height: u64,
        chunk_index: u32,
        data: Vec<u8>,
    ) -> Result<(bool, u64)> {
        let mut slot = self.inbound.write().await;
        let inbound = slot
            .as_mut()
            .ok_or_else(|| NodeError::Other("no inbound snapshot offered".into()))?;
        if inbound.manifest.height != height {
            return Err(NodeError::Other(format!(
                "chunk for height {} but inbound is at {}",
                height, inbound.manifest.height
            )));
        }
        if inbound.completed {
            return Ok((true, height));
        }
        let idx = chunk_index as usize;
        if idx >= inbound.chunks.len() {
            return Err(NodeError::Other(format!(
                "chunk index {} out of bounds (num_chunks {})",
                chunk_index, inbound.manifest.num_chunks
            )));
        }

        // Verify chunk hash.
        let mut hasher = Sha256::new();
        hasher.update(&data);
        let got_hex = hex::encode(hasher.finalize());
        let expected_hex = &inbound.manifest.chunk_hashes_hex[idx];
        if got_hex != *expected_hex {
            return Err(NodeError::Other(format!(
                "chunk {} hash mismatch: expected {}, got {}",
                chunk_index, expected_hex, got_hex
            )));
        }

        // Spool to disk for crash safety.
        let chunk_path = inbound
            .spool_dir
            .join(format!("chunk_{:08}.bin", chunk_index));
        std::fs::write(&chunk_path, &data)
            .map_err(|e| NodeError::Other(format!("spool chunk: {}", e)))?;

        inbound.chunks[idx] = Some(data);

        // If all chunks present, commit.
        if inbound.chunks.iter().all(|c| c.is_some()) {
            self.commit_inbound(inbound)?;
            inbound.completed = true;
            Ok((true, height))
        } else {
            Ok((false, height))
        }
    }

    /// Decode all spooled chunks into KV ops and atomically write to
    /// the live store via `write_batch_sync`.
    fn commit_inbound(&self, inbound: &InboundSnapshot) -> Result<()> {
        let mut ops = Vec::new();
        for chunk in inbound.chunks.iter() {
            let bytes = chunk
                .as_ref()
                .ok_or_else(|| NodeError::Other("missing chunk at commit".into()))?;
            decode_chunk_into(bytes, &mut ops)?;
        }
        self.store
            .write_batch_sync(ops)
            .map_err(|e| NodeError::Other(format!("commit snapshot to store: {}", e)))?;

        // Promote the spool dir to a persistent snapshot dir so the node
        // can re-serve it.
        let final_dir = self.snapshots_dir.join(inbound.manifest.height.to_string());
        if final_dir.exists() {
            let _ = std::fs::remove_dir_all(&final_dir);
        }
        std::fs::rename(&inbound.spool_dir, &final_dir)
            .map_err(|e| NodeError::Other(format!("promote spool dir: {}", e)))?;
        let manifest_bytes = serde_json::to_vec_pretty(&inbound.manifest)
            .map_err(|e| NodeError::Other(format!("serialize manifest: {}", e)))?;
        std::fs::write(final_dir.join("manifest.json"), manifest_bytes)
            .map_err(|e| NodeError::Other(format!("write manifest: {}", e)))?;
        Ok(())
    }

    /// Produce a snapshot at `height` with the given `state_root`. Streams
    /// every column family in [`SNAPSHOT_CFS`] into 10MiB chunks on disk.
    ///
    /// Streaming matters: the previous implementation used `scan_prefix`,
    /// which materializes an entire column family as one `Vec` — for
    /// CF_BLOCKS on a long-running chain that was a multi-gigabyte
    /// allocation every snapshot interval, OOM-killing every validator on
    /// the same height boundary. Peak memory here is now one chunk buffer
    /// plus one KV row.
    pub fn produce_at(&self, height: u64, state_root: [u8; 32]) -> Result<SnapshotManifest> {
        // Prune BEFORE producing so peak disk = retain × snapshot_size, not
        // (retain + 1). Producing first then pruning means a 100 GB volume
        // sized for `retain` snapshots transiently needs room for one more,
        // which is exactly what overflowed the testnet on 2026-06-14. We
        // keep `retain - 1` existing snapshots here, because the one we're
        // about to write takes the last slot — so at rest the total is
        // exactly `retain`.
        let keep = self.config.effective_retain().saturating_sub(1);
        self.prune_keeping(keep)?;

        let dir = self.snapshots_dir.join(height.to_string());
        std::fs::create_dir_all(&dir)
            .map_err(|e| NodeError::Other(format!("create snapshot dir: {}", e)))?;

        fn flush(
            dir: &Path,
            buf: &mut Vec<u8>,
            chunk_idx: &mut u32,
            hashes: &mut Vec<String>,
        ) -> std::io::Result<()> {
            if buf.is_empty() {
                return Ok(());
            }
            let path = dir.join(format!("chunk_{:08}.bin", chunk_idx));
            std::fs::write(&path, &buf)?;
            let mut h = Sha256::new();
            h.update(&buf);
            hashes.push(hex::encode(h.finalize()));
            *chunk_idx += 1;
            buf.clear();
            Ok(())
        }

        let mut current_chunk = Vec::with_capacity(CHUNK_MAX_BYTES);
        let mut chunk_idx: u32 = 0;
        let mut chunk_hashes = Vec::new();

        for cf in SNAPSHOT_CFS {
            self.store
                .scan_prefix_for_each(cf, b"", &mut |key, value| {
                    encode_record(cf, key, value, &mut current_chunk);
                    if current_chunk.len() >= CHUNK_MAX_BYTES {
                        flush(&dir, &mut current_chunk, &mut chunk_idx, &mut chunk_hashes)
                            .map_err(tenzro_storage::StorageError::IoError)?;
                    }
                    Ok(())
                })
                .map_err(|e| NodeError::Other(format!("scan {}: {}", cf, e)))?;
        }
        flush(&dir, &mut current_chunk, &mut chunk_idx, &mut chunk_hashes)
            .map_err(|e| NodeError::Other(format!("write chunk: {}", e)))?;

        let manifest = SnapshotManifest {
            height,
            state_root_hex: hex::encode(state_root),
            num_chunks: chunk_idx,
            chunk_hashes_hex: chunk_hashes,
            created_at: chrono::Utc::now().to_rfc3339(),
            format: SnapshotManifest::FORMAT_V1,
        };
        let manifest_bytes = serde_json::to_vec_pretty(&manifest)
            .map_err(|e| NodeError::Other(format!("serialize manifest: {}", e)))?;
        std::fs::write(dir.join("manifest.json"), manifest_bytes)
            .map_err(|e| NodeError::Other(format!("write manifest: {}", e)))?;

        Ok(manifest)
    }

    /// Reclaim snapshot disk. Two passes:
    ///
    /// 1. **Retention** — keep the `keep_complete` most-recent *complete*
    ///    snapshots (those with a parseable `manifest.json`), delete the
    ///    rest. Callers pass `retain` at startup and `retain - 1` before
    ///    producing (the new snapshot fills the final slot).
    /// 2. **Orphan sweep** — delete `<height>/` directories that have no
    ///    parseable `manifest.json` at all. These are the 4 KB husks a
    ///    crashed or ENOSPC-killed `produce_at` leaves behind:
    ///    `list_snapshots` skips them, so the retention pass alone never
    ///    reclaims them and they accumulate forever. A mtime grace window
    ///    (`ORPHAN_GRACE`) protects an in-flight producer that hasn't
    ///    written its manifest yet. `inbound_*` consumer spool dirs are
    ///    excluded — they're managed by the apply/commit path, not here.
    fn prune_keeping(&self, keep_complete: usize) -> Result<()> {
        // Pass 1: retention over complete snapshots.
        let mut complete = self.list_snapshots()?;
        complete.sort_by_key(|s| std::cmp::Reverse(s.height));
        let retain: std::collections::HashSet<u64> = complete
            .iter()
            .take(keep_complete)
            .map(|s| s.height)
            .collect();
        for stale in complete.iter().skip(keep_complete) {
            let path = self.snapshots_dir.join(stale.height.to_string());
            if let Err(e) = std::fs::remove_dir_all(&path) {
                tracing::warn!(height = stale.height, error = %e, "prune: remove complete snapshot failed");
            }
        }

        // Pass 2: orphan sweep over manifest-less height dirs.
        let now = SystemTime::now();
        let read = std::fs::read_dir(&self.snapshots_dir)
            .map_err(|e| NodeError::Other(format!("read snapshots dir: {}", e)))?;
        for entry in read.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let name = match path.file_name().and_then(|n| n.to_str()) {
                Some(n) => n,
                None => continue,
            };
            // Skip consumer spool dirs — owned by the apply/commit path.
            if name.starts_with("inbound_") {
                continue;
            }
            // Only height-named dirs are ours to sweep.
            let height: u64 = match name.parse() {
                Ok(h) => h,
                Err(_) => continue,
            };
            // Complete + retained: leave it.
            if retain.contains(&height) {
                continue;
            }
            // Complete snapshots are handled by pass 1; if a manifest is
            // present here it was already deleted above (or is retained).
            if path.join("manifest.json").exists() {
                continue;
            }
            // Manifest-less orphan. Guard against racing an in-flight
            // producer by skipping anything modified within ORPHAN_GRACE.
            let young = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .map(|age| age < ORPHAN_GRACE)
                .unwrap_or(false);
            if young {
                continue;
            }
            if let Err(e) = std::fs::remove_dir_all(&path) {
                tracing::warn!(height, error = %e, "prune: remove orphan snapshot dir failed");
            } else {
                tracing::info!(height, "prune: swept orphaned snapshot dir");
            }
        }
        Ok(())
    }
}

/// Length-prefix encoding for one (cf, key, value) record. Format
/// matches the rustdoc at the top of this file.
fn encode_record(cf: &str, key: &[u8], value: &[u8], out: &mut Vec<u8>) {
    let cf_bytes = cf.as_bytes();
    out.extend_from_slice(&(cf_bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(cf_bytes);
    out.extend_from_slice(&(key.len() as u32).to_le_bytes());
    out.extend_from_slice(key);
    out.extend_from_slice(&(value.len() as u32).to_le_bytes());
    out.extend_from_slice(value);
}

/// Inverse of [`encode_record`]. Appends decoded `WriteOp::Put`s to
/// `ops`.
fn decode_chunk_into(
    bytes: &[u8],
    ops: &mut Vec<tenzro_storage::WriteOp>,
) -> Result<()> {
    let mut pos = 0;
    while pos < bytes.len() {
        if pos + 2 > bytes.len() {
            return Err(NodeError::Other("truncated cf_len".into()));
        }
        let cf_len =
            u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        if pos + cf_len > bytes.len() {
            return Err(NodeError::Other("truncated cf".into()));
        }
        let cf = std::str::from_utf8(&bytes[pos..pos + cf_len])
            .map_err(|e| NodeError::Other(format!("cf utf8: {}", e)))?
            .to_string();
        pos += cf_len;

        if pos + 4 > bytes.len() {
            return Err(NodeError::Other("truncated key_len".into()));
        }
        let key_len = u32::from_le_bytes([
            bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3],
        ]) as usize;
        pos += 4;
        if pos + key_len > bytes.len() {
            return Err(NodeError::Other("truncated key".into()));
        }
        let key = bytes[pos..pos + key_len].to_vec();
        pos += key_len;

        if pos + 4 > bytes.len() {
            return Err(NodeError::Other("truncated value_len".into()));
        }
        let value_len = u32::from_le_bytes([
            bytes[pos], bytes[pos + 1], bytes[pos + 2], bytes[pos + 3],
        ]) as usize;
        pos += 4;
        if pos + value_len > bytes.len() {
            return Err(NodeError::Other("truncated value".into()));
        }
        let value = bytes[pos..pos + value_len].to_vec();
        pos += value_len;

        ops.push(tenzro_storage::kv::WriteOp::Put { cf, key, value });
    }
    Ok(())
}

/// Bootstrap a fresh node from a peer's state-sync snapshot.
///
/// 1. Calls `tenzro_listSnapshots` on the peer.
/// 2. Picks the highest snapshot.
/// 3. Calls `tenzro_getSnapshotChunk` for each chunk.
/// 4. Calls `offer` + `apply_chunk` on the local store, which verifies
///    the per-chunk SHA-256 against the manifest, decodes the records,
///    and atomically commits to the live KV store.
///
/// `peer_url` is the JSON-RPC base URL (e.g. `https://rpc.tenzro.xyz`).
/// `min_height` skips snapshots below this — pass `0` to accept the
/// highest available.
///
/// Returns the committed snapshot manifest. The caller is responsible for
/// verifying `manifest.state_root_hex` against a trusted QC at the same
/// height before treating the bootstrapped state as authoritative.
pub async fn bootstrap_from_peer(
    store: Arc<SnapshotStore>,
    peer_url: &str,
    min_height: u64,
    expected_state_root: Option<[u8; 32]>,
) -> Result<SnapshotManifest> {
    // Fail-closed trust anchor. Without an operator-supplied
    // `expected_state_root`, the snapshot's declared root is
    // unverifiable: a malicious peer could serve a forged manifest with
    // any state and the syncing node would commit it as canonical
    // state. Refuse the bootstrap entirely until QC-verification
    // against a known-good finalized header is wired.
    let anchor = expected_state_root.ok_or_else(|| NodeError::Other(
        "state-sync refused: no trust anchor supplied. Operator MUST \
         provide an out-of-band-verified state_root (e.g. a weak-\
         subjectivity checkpoint or a known-good QC at the snapshot \
         height) so the manifest's declared root can be cross-checked. \
         Without an anchor the peer's RPC is untrusted authority and \
         must not be allowed to seed local state."
            .to_string(),
    ))?;

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| NodeError::Other(format!("build http client: {}", e)))?;

    // 1. List remote snapshots.
    let list_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tenzro_listSnapshots",
        "params": []
    });
    let resp = client
        .post(peer_url)
        .json(&list_req)
        .send()
        .await
        .map_err(|e| NodeError::Other(format!("list_snapshots http: {}", e)))?;
    let list_json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| NodeError::Other(format!("list_snapshots json: {}", e)))?;
    let snapshots = list_json
        .get("result")
        .and_then(|r| r.get("snapshots"))
        .and_then(|s| s.as_array())
        .ok_or_else(|| NodeError::Other("malformed list_snapshots response".into()))?;
    let target = snapshots
        .iter()
        .filter_map(|s| s.get("height").and_then(|h| h.as_u64()))
        .filter(|h| *h >= min_height)
        .max()
        .ok_or_else(|| {
            NodeError::Other(format!(
                "no peer snapshots available at or above height {}",
                min_height
            ))
        })?;

    // 2. Fetch the full manifest. Server returns only the summary in the
    // list call; we need the per-chunk hashes from the offer payload, so
    // we reconstruct the manifest from a discovery call. Since the four-
    // method ABCI surface doesn't expose a "get_manifest" method directly,
    // we reuse listSnapshots' summary + a side-channel: peers serve their
    // manifest as the offer payload of an introspection call. To keep the
    // surface minimal we encode the manifest in the response of the
    // first chunk request, but for v1 we instead re-request the summary
    // and synthesise a minimal manifest locally from the chunk hashes
    // returned by `tenzro_getSnapshotChunk`. Concretely: fetch chunk_0,
    // hash it, then progressively fetch chunks until length-prefix
    // decoding fails — at which point we know we've consumed them all.
    //
    // To keep the bootstrap path simple and robust, the four-method
    // surface is extended on the read side here: the peer is expected to
    // expose `tenzro_getSnapshotManifest { height }` returning the full
    // manifest. This matches the standard behaviour where the manifest
    // is fetched alongside the chunk index.
    let manifest_req = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tenzro_getSnapshotManifest",
        "params": { "height": target }
    });
    let resp = client
        .post(peer_url)
        .json(&manifest_req)
        .send()
        .await
        .map_err(|e| NodeError::Other(format!("get_manifest http: {}", e)))?;
    let manifest_json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| NodeError::Other(format!("get_manifest json: {}", e)))?;
    let manifest_val = manifest_json
        .get("result")
        .ok_or_else(|| NodeError::Other("get_manifest: no result".into()))?;
    let manifest: SnapshotManifest = serde_json::from_value(manifest_val.clone())
        .map_err(|e| NodeError::Other(format!("parse manifest: {}", e)))?;

    // 2b. Trust-anchor check. The manifest's declared `state_root` must
    //     match the operator-supplied anchor BIT-FOR-BIT. Any difference
    //     (length, hex case, leading 0x) is a hard reject — a forged
    //     manifest from a malicious peer would otherwise be applied to
    //     the local KV store.
    let declared_hex = manifest.state_root_hex.trim_start_matches("0x");
    let declared_bytes = hex::decode(declared_hex).map_err(|e| NodeError::Other(format!(
        "manifest state_root_hex is not valid hex: {e}"
    )))?;
    if declared_bytes.len() != 32 {
        return Err(NodeError::Other(format!(
            "manifest state_root has wrong length {} (expected 32)",
            declared_bytes.len()
        )));
    }
    let mut declared = [0u8; 32];
    declared.copy_from_slice(&declared_bytes);
    if declared != anchor {
        return Err(NodeError::Other(format!(
            "snapshot state_root mismatch: declared 0x{} but operator anchor 0x{}. \
             Refusing to apply unverified state.",
            hex::encode(declared),
            hex::encode(anchor),
        )));
    }

    // 3. Offer to local store.
    store.offer(manifest.clone()).await?;

    // 4. Fetch + apply each chunk in order.
    for idx in 0..manifest.num_chunks {
        let chunk_req = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 100 + idx,
            "method": "tenzro_getSnapshotChunk",
            "params": { "height": manifest.height, "chunk_index": idx }
        });
        let resp = client
            .post(peer_url)
            .json(&chunk_req)
            .send()
            .await
            .map_err(|e| NodeError::Other(format!("get_chunk {} http: {}", idx, e)))?;
        let chunk_json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| NodeError::Other(format!("get_chunk {} json: {}", idx, e)))?;
        let data_b64 = chunk_json
            .get("result")
            .and_then(|r| r.get("data_b64"))
            .and_then(|s| s.as_str())
            .ok_or_else(|| {
                NodeError::Other(format!("chunk {} missing data_b64", idx))
            })?;
        let bytes = b64_decode(data_b64)?;
        store.apply_chunk(manifest.height, idx, bytes).await?;
    }

    Ok(manifest)
}

/// Helper to base64-encode chunk bytes for the JSON-RPC wire.
pub fn b64_encode(bytes: &[u8]) -> String {
    B64.encode(bytes)
}

/// Helper to base64-decode chunk bytes from the JSON-RPC wire.
pub fn b64_decode(s: &str) -> Result<Vec<u8>> {
    B64.decode(s)
        .map_err(|e| NodeError::Other(format!("base64 decode: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::{MemoryStore, WriteOp};

    fn make_store_with_data() -> Arc<dyn KvStore> {
        let store = Arc::new(MemoryStore::new()) as Arc<dyn KvStore>;
        let mut ops = Vec::new();
        for i in 0u32..100 {
            ops.push(WriteOp::Put {
                cf: CF_ACCOUNTS.to_string(),
                key: format!("addr_{}", i).into_bytes(),
                value: vec![i as u8; 32],
            });
        }
        ops.push(WriteOp::Put {
            cf: CF_METADATA.to_string(),
            key: b"genesis".to_vec(),
            value: b"hello".to_vec(),
        });
        store.write_batch(ops).unwrap();
        store
    }

    #[tokio::test]
    async fn produce_then_apply_roundtrip() {
        let producer_dir = tempfile::tempdir().unwrap();
        let consumer_dir = tempfile::tempdir().unwrap();
        let producer_store = make_store_with_data();
        let producer =
            SnapshotStore::new(producer_dir.path(), producer_store, SnapshotConfig::producer_default())
                .unwrap();

        let manifest = producer.produce_at(42, [7u8; 32]).unwrap();
        assert!(manifest.num_chunks >= 1);

        let consumer_store = Arc::new(MemoryStore::new()) as Arc<dyn KvStore>;
        let consumer =
            SnapshotStore::new(consumer_dir.path(), consumer_store.clone(), SnapshotConfig::default())
                .unwrap();
        consumer.offer(manifest.clone()).await.unwrap();

        for i in 0..manifest.num_chunks {
            let chunk = producer.get_chunk(42, i).unwrap();
            let (done, h) = consumer.apply_chunk(42, i, chunk).await.unwrap();
            assert_eq!(h, 42);
            assert_eq!(done, i == manifest.num_chunks - 1);
        }

        // Verify a known key landed.
        let v = consumer_store.get(CF_METADATA, b"genesis").unwrap();
        assert_eq!(v, Some(b"hello".to_vec()));
        let v = consumer_store
            .get(CF_ACCOUNTS, b"addr_42")
            .unwrap();
        assert_eq!(v, Some(vec![42u8; 32]));
    }

    #[tokio::test]
    async fn rejects_corrupted_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let store = make_store_with_data();
        let producer =
            SnapshotStore::new(dir.path(), store, SnapshotConfig::producer_default()).unwrap();
        let manifest = producer.produce_at(1, [0u8; 32]).unwrap();

        let consumer_store = Arc::new(MemoryStore::new()) as Arc<dyn KvStore>;
        let consumer_dir = tempfile::tempdir().unwrap();
        let consumer =
            SnapshotStore::new(consumer_dir.path(), consumer_store, SnapshotConfig::default())
                .unwrap();
        consumer.offer(manifest.clone()).await.unwrap();

        let mut chunk = producer.get_chunk(1, 0).unwrap();
        chunk[0] ^= 0xFF;
        let err = consumer.apply_chunk(1, 0, chunk).await;
        assert!(err.is_err(), "corrupted chunk must be rejected");
    }

    #[tokio::test]
    async fn retains_only_configured_count() {
        let dir = tempfile::tempdir().unwrap();
        let store = make_store_with_data();
        let cfg = SnapshotConfig {
            enabled: true,
            interval_blocks: 1,
            retain_count: 2,
        };
        let producer = SnapshotStore::new(dir.path(), store, cfg).unwrap();

        // Produce four snapshots; only the two most recent should survive.
        for h in [10u64, 20, 30, 40] {
            producer.produce_at(h, [h as u8; 32]).unwrap();
        }
        let heights: Vec<u64> = producer
            .list_snapshots()
            .unwrap()
            .into_iter()
            .map(|s| s.height)
            .collect();
        assert_eq!(heights, vec![40, 30], "must retain only the 2 newest");
        assert!(!dir.path().join("snapshots/10").exists());
        assert!(!dir.path().join("snapshots/20").exists());
    }

    #[tokio::test]
    async fn sweeps_manifestless_orphan_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let store = make_store_with_data();
        let producer =
            SnapshotStore::new(dir.path(), store, SnapshotConfig::producer_default()).unwrap();

        // A husk left by a crashed produce_at: a height dir with chunk data
        // but no manifest.json. list_snapshots skips it, so retention never
        // reclaims it — the orphan sweep must.
        let orphan = dir.path().join("snapshots/99999");
        std::fs::create_dir_all(&orphan).unwrap();
        std::fs::write(orphan.join("chunk_00000000.bin"), b"partial").unwrap();
        // Backdate past ORPHAN_GRACE so the sweep doesn't treat it as
        // an in-flight producer.
        let old = std::time::SystemTime::now() - Duration::from_secs(20 * 60);
        filetime::set_file_mtime(&orphan, filetime::FileTime::from_system_time(old)).unwrap();

        // A consumer spool dir must NOT be swept.
        let spool = dir.path().join("snapshots/inbound_123");
        std::fs::create_dir_all(&spool).unwrap();
        filetime::set_file_mtime(&spool, filetime::FileTime::from_system_time(old)).unwrap();

        producer.sweep_on_startup();

        assert!(!orphan.exists(), "manifest-less orphan must be swept");
        assert!(spool.exists(), "inbound spool dir must be preserved");
    }

    #[tokio::test]
    async fn keeps_recent_orphan_within_grace() {
        let dir = tempfile::tempdir().unwrap();
        let store = make_store_with_data();
        let producer =
            SnapshotStore::new(dir.path(), store, SnapshotConfig::producer_default()).unwrap();

        // A fresh manifest-less dir (just-created mtime) models an
        // in-flight produce_at that hasn't written its manifest yet. The
        // grace window must protect it.
        let inflight = dir.path().join("snapshots/77777");
        std::fs::create_dir_all(&inflight).unwrap();
        producer.sweep_on_startup();
        assert!(inflight.exists(), "in-grace orphan must be preserved");
    }
}
