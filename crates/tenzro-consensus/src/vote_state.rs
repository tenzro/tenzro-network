//! Persistent vote state for double-sign protection.
//!
//! Mirrors CometBFT's `FilePVLastSignState` (`privval/file.go:206-243`) and
//! Aptos' `PersistentSafetyStorage` (`consensus/safety-rules`): a validator
//! must record `(view, height, step, block_hash, signature)` durably **before**
//! its vote leaves the wire. On startup, the engine refuses to sign any
//! `(view, height, step) ≤ last_persisted` — so a crash between broadcast and
//! persist cannot lead to a re-vote on a different block in the same view,
//! which is the textbook trigger for self-equivocation slashing.
//!
//! # Why this lives in `tenzro-consensus`
//!
//! Persistence is layer-pure file I/O (`std::fs`) — no RocksDB, no other
//! crate. CometBFT does the same: `privval/file.go` is plain JSON with an
//! atomic `tempfile.WriteFileAtomic` rename. Keeping it in-crate avoids a
//! circular dep with `tenzro-storage` and matches the upstream pattern.
//!
//! # Atomic write protocol
//!
//! 1. Serialize updated state to bytes
//! 2. Write to `<path>.tmp` via `File::create` + `write_all` + `sync_all`
//!    (fsync on the temp file)
//! 3. Rename `<path>.tmp` → `<path>` (POSIX rename is atomic)
//! 4. fsync the parent directory so the rename is durable across crash
//!
//! Step 4 is critical and is the most-missed step in non-CometBFT
//! implementations (POSIX guarantees rename atomicity but not durability of
//! the directory entry without an explicit fsync of the dir).

use crate::error::{ConsensusError, Result};
use crate::voter::VoteType;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tenzro_types::primitives::Hash;

/// Step within a (view, height) — matches CometBFT's `step int8`.
///
/// Order is significant: `Prepare < Commit < Decide`. `check_vrs` uses
/// lexicographic ordering on `(view, height, step)` so a validator that has
/// already cast a Prepare vote at `(v=10, h=42)` will refuse another Prepare
/// in the same `(v, h)`, but is still allowed to cast a Commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
pub enum VoteStep {
    Prepare = 1,
    Commit = 2,
    Decide = 3,
}

impl VoteStep {
    pub fn from_vote_type(vt: VoteType) -> Self {
        match vt {
            VoteType::Prepare => VoteStep::Prepare,
            VoteType::Commit => VoteStep::Commit,
        }
    }
}

/// Last sign state — durable across crashes.
///
/// Field order intentionally mirrors CometBFT's `FilePVLastSignState` so the
/// schema is recognizable to operators familiar with that ecosystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LastSignState {
    /// Format version. Bump on incompatible schema changes.
    #[serde(default = "default_version")]
    pub version: u8,

    /// View number of the last vote we signed
    pub view: u64,

    /// Height of the last vote we signed
    pub height: u64,

    /// Step within `(view, height)` — Prepare/Commit/Decide
    pub step: VoteStep,

    /// Block hash we voted for (canonical commitment to *what* we voted on).
    /// Stored so an incoming proposal that hashes to the same bytes can be
    /// re-signed safely without producing a new signature (idempotent retry).
    #[serde(default)]
    pub block_hash: Option<Hash>,

    /// Signature bytes of the last vote (composite-signature wire format).
    /// CometBFT stores this so an in-flight retry of the *same* (h,r,s,hash)
    /// returns the same signature bytes instead of re-signing — preventing a
    /// stuck-validator scenario where a transient panic between sign and
    /// broadcast leaves us unable to re-emit our own vote.
    #[serde(default)]
    pub signature: Option<Vec<u8>>,
}

fn default_version() -> u8 {
    1
}

impl LastSignState {
    /// Empty state: no votes ever cast. All `(view, height, step)` are valid.
    pub fn empty() -> Self {
        Self {
            version: 1,
            view: 0,
            height: 0,
            step: VoteStep::Prepare,
            block_hash: None,
            signature: None,
        }
    }

    /// Returns `true` if a candidate `(view, height, step)` is strictly past
    /// the last persisted tuple — i.e. safe to sign.
    ///
    /// Lexicographic ordering: candidate must be greater than persisted.
    /// Equal tuples are **rejected** unless the block hash matches the
    /// already-signed block (idempotent retry of identical vote — handled by
    /// the caller via `check_vrs`).
    pub fn is_strictly_after(&self, view: u64, height: u64, step: VoteStep) -> bool {
        (view, height, step) > (self.view, self.height, self.step)
    }
}

/// Outcome of a `check_vrs` (Vote Rejection / Sign) call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VrsDecision {
    /// Safe to sign. Caller should sign and then call `record(...)` to persist.
    Sign,
    /// Identical to the last signed vote — caller may re-broadcast the
    /// persisted signature (idempotent retry).
    Reuse {
        signature: Vec<u8>,
    },
    /// Refusal — signing this would equivocate or reverse a finalized step.
    Reject {
        reason: String,
    },
}

/// Trait for persisting vote state. Sync API — fsync-on-write must complete
/// before returning.
///
/// Implementations MUST guarantee:
/// - `record` returns only after the new state is durable on disk
/// - `load` returns the most recently `record`ed state, even after a crash
/// - All operations are safe across concurrent callers (interior locking is
///   the implementor's responsibility)
pub trait VoteStateStore: Send + Sync {
    /// Loads the persisted state. Returns `LastSignState::empty()` if no state
    /// has been recorded yet.
    fn load(&self) -> Result<LastSignState>;

    /// Atomically persists the new state. Must fsync before returning.
    fn record(&self, state: &LastSignState) -> Result<()>;

    /// Checks whether `(view, height, step)` for `block_hash` is safe to sign.
    ///
    /// Default implementation enforces the canonical CometBFT `CheckHRS` rule:
    /// strictly after the last persisted tuple. An override can implement the
    /// idempotent-reuse path if the block hash matches.
    fn check_vrs(
        &self,
        view: u64,
        height: u64,
        step: VoteStep,
        block_hash: &Hash,
    ) -> Result<VrsDecision> {
        let last = self.load()?;

        // Strictly after — safe.
        if last.is_strictly_after(view, height, step) {
            return Ok(VrsDecision::Sign);
        }

        // Equal tuple AND same block hash AND we have the signature — reuse.
        if last.view == view
            && last.height == height
            && last.step == step
            && last.block_hash.as_ref() == Some(block_hash)
        {
            if let Some(sig) = last.signature.clone() {
                return Ok(VrsDecision::Reuse { signature: sig });
            }
        }

        // Anything else is a refusal.
        Ok(VrsDecision::Reject {
            reason: format!(
                "double-sign refused: candidate (view={}, height={}, step={:?}, hash={}) \
                 conflicts with last (view={}, height={}, step={:?}, hash={:?})",
                view,
                height,
                step,
                block_hash,
                last.view,
                last.height,
                last.step,
                last.block_hash,
            ),
        })
    }
}

/// In-memory store. Useful for tests and ephemeral validators (e.g. light
/// clients, dev networks). Holds state under a `parking_lot::Mutex` for
/// concurrent access.
pub struct MemoryVoteStateStore {
    inner: parking_lot::Mutex<LastSignState>,
}

impl MemoryVoteStateStore {
    pub fn new() -> Self {
        Self {
            inner: parking_lot::Mutex::new(LastSignState::empty()),
        }
    }
}

impl Default for MemoryVoteStateStore {
    fn default() -> Self {
        Self::new()
    }
}

impl VoteStateStore for MemoryVoteStateStore {
    fn load(&self) -> Result<LastSignState> {
        Ok(self.inner.lock().clone())
    }

    fn record(&self, state: &LastSignState) -> Result<()> {
        let mut guard = self.inner.lock();
        *guard = state.clone();
        Ok(())
    }
}

/// File-backed store using atomic-rename + fsync semantics.
///
/// Persists JSON to a single file (e.g. `<data-dir>/consensus/last_sign.json`).
/// Updates are serialized through a mutex; the disk write itself is sync.
pub struct FileVoteStateStore {
    path: PathBuf,
    parent_dir: PathBuf,
    inner: parking_lot::Mutex<LastSignState>,
}

impl FileVoteStateStore {
    /// Opens (or creates) the store at `path`. If the file exists, parses it;
    /// otherwise initializes empty state.
    ///
    /// The parent directory must already exist — the caller is responsible for
    /// ensuring `<data-dir>/consensus/` is created during node startup.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let parent_dir = path
            .parent()
            .ok_or_else(|| {
                ConsensusError::Internal(format!(
                    "FileVoteStateStore: path {:?} has no parent directory",
                    path
                ))
            })?
            .to_path_buf();

        let initial = if path.exists() {
            let bytes = std::fs::read(&path).map_err(|e| {
                ConsensusError::Internal(format!(
                    "FileVoteStateStore: failed to read {:?}: {}",
                    path, e
                ))
            })?;
            // If the file exists but is empty, treat as fresh.
            if bytes.is_empty() {
                LastSignState::empty()
            } else {
                serde_json::from_slice::<LastSignState>(&bytes).map_err(|e| {
                    ConsensusError::Internal(format!(
                        "FileVoteStateStore: corrupt state at {:?}: {}",
                        path, e
                    ))
                })?
            }
        } else {
            LastSignState::empty()
        };

        Ok(Self {
            path,
            parent_dir,
            inner: parking_lot::Mutex::new(initial),
        })
    }

    /// Atomic write: temp file → fsync → rename → fsync(parent).
    fn write_atomic(&self, state: &LastSignState) -> Result<()> {
        use std::io::Write;

        let bytes = serde_json::to_vec_pretty(state).map_err(|e| {
            ConsensusError::Internal(format!(
                "FileVoteStateStore: serialize failed: {}",
                e
            ))
        })?;

        let tmp_path = self.path.with_extension("tmp");

        // Step 1+2: write + fsync the temp file.
        {
            let mut tmp = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)
                .map_err(|e| {
                    ConsensusError::Internal(format!(
                        "FileVoteStateStore: open tmp {:?}: {}",
                        tmp_path, e
                    ))
                })?;
            tmp.write_all(&bytes).map_err(|e| {
                ConsensusError::Internal(format!(
                    "FileVoteStateStore: write tmp {:?}: {}",
                    tmp_path, e
                ))
            })?;
            tmp.sync_all().map_err(|e| {
                ConsensusError::Internal(format!(
                    "FileVoteStateStore: fsync tmp {:?}: {}",
                    tmp_path, e
                ))
            })?;
        }

        // Step 3: atomic rename.
        std::fs::rename(&tmp_path, &self.path).map_err(|e| {
            ConsensusError::Internal(format!(
                "FileVoteStateStore: rename {:?} -> {:?}: {}",
                tmp_path, self.path, e
            ))
        })?;

        // Step 4: fsync the parent directory so the rename is durable.
        // CometBFT does this; without it, a crash between the rename and the
        // dir-entry hitting disk can lose the new state.
        if let Ok(dir) = std::fs::File::open(&self.parent_dir) {
            // Best-effort: not all filesystems require this (NTFS, APFS-on-mac
            // are mostly fine), and fsync on a directory is a no-op on some
            // platforms. But on ext4/xfs/zfs it is necessary for durability.
            let _ = dir.sync_all();
        }

        Ok(())
    }
}

impl VoteStateStore for FileVoteStateStore {
    fn load(&self) -> Result<LastSignState> {
        Ok(self.inner.lock().clone())
    }

    fn record(&self, state: &LastSignState) -> Result<()> {
        let mut guard = self.inner.lock();
        // Persist first, in-memory second — if the disk write fails we don't
        // advance the in-memory tip (caller must surface the error).
        self.write_atomic(state)?;
        *guard = state.clone();
        Ok(())
    }
}

/// Convenience: returns an `Arc<dyn VoteStateStore>` configured for production.
///
/// Path is `<data_dir>/consensus/last_sign.json`. Creates the parent directory
/// if missing.
pub fn open_default_file_store(data_dir: &Path) -> Result<Arc<dyn VoteStateStore>> {
    let consensus_dir = data_dir.join("consensus");
    std::fs::create_dir_all(&consensus_dir).map_err(|e| {
        ConsensusError::Internal(format!(
            "open_default_file_store: create_dir_all {:?}: {}",
            consensus_dir, e
        ))
    })?;
    let path = consensus_dir.join("last_sign.json");
    let store = FileVoteStateStore::open(path)?;
    Ok(Arc::new(store))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn h(b: u8) -> Hash {
        Hash::new([b; 32])
    }

    #[test]
    fn empty_state_allows_anything() {
        let s = LastSignState::empty();
        assert!(s.is_strictly_after(0, 1, VoteStep::Prepare));
        assert!(s.is_strictly_after(1, 0, VoteStep::Prepare));
    }

    #[test]
    fn lexicographic_ordering() {
        let s = LastSignState {
            version: 1,
            view: 5,
            height: 10,
            step: VoteStep::Prepare,
            block_hash: Some(h(1)),
            signature: Some(vec![0xAA]),
        };

        // Same (view, height) but later step — allowed
        assert!(s.is_strictly_after(5, 10, VoteStep::Commit));
        // Same (view, height, step) — REJECTED (equal not strictly after)
        assert!(!s.is_strictly_after(5, 10, VoteStep::Prepare));
        // Earlier view — REJECTED
        assert!(!s.is_strictly_after(4, 10, VoteStep::Decide));
        // Same view, earlier height — REJECTED
        assert!(!s.is_strictly_after(5, 9, VoteStep::Decide));
        // Strictly later view — allowed
        assert!(s.is_strictly_after(6, 0, VoteStep::Prepare));
    }

    #[test]
    fn memory_store_sign_then_reject_double_sign() {
        let store = MemoryVoteStateStore::new();

        // First vote — Sign.
        match store.check_vrs(10, 42, VoteStep::Prepare, &h(1)).unwrap() {
            VrsDecision::Sign => {}
            other => panic!("expected Sign, got {:?}", other),
        }

        // Record it.
        store
            .record(&LastSignState {
                version: 1,
                view: 10,
                height: 42,
                step: VoteStep::Prepare,
                block_hash: Some(h(1)),
                signature: Some(vec![0xDE, 0xAD]),
            })
            .unwrap();

        // Same (v,h,step) but DIFFERENT block — Reject (this is the
        // equivocation case).
        match store.check_vrs(10, 42, VoteStep::Prepare, &h(2)).unwrap() {
            VrsDecision::Reject { .. } => {}
            other => panic!("expected Reject, got {:?}", other),
        }

        // Same (v,h,step) and SAME block — Reuse (idempotent retry).
        match store.check_vrs(10, 42, VoteStep::Prepare, &h(1)).unwrap() {
            VrsDecision::Reuse { signature } => assert_eq!(signature, vec![0xDE, 0xAD]),
            other => panic!("expected Reuse, got {:?}", other),
        }

        // Earlier view — Reject (regression attack).
        match store.check_vrs(9, 99, VoteStep::Decide, &h(3)).unwrap() {
            VrsDecision::Reject { .. } => {}
            other => panic!("expected Reject for earlier view, got {:?}", other),
        }

        // Strictly later — Sign.
        match store.check_vrs(11, 0, VoteStep::Prepare, &h(4)).unwrap() {
            VrsDecision::Sign => {}
            other => panic!("expected Sign for later view, got {:?}", other),
        }
    }

    #[test]
    fn memory_store_advancing_step_within_same_view() {
        let store = MemoryVoteStateStore::new();
        store
            .record(&LastSignState {
                version: 1,
                view: 7,
                height: 21,
                step: VoteStep::Prepare,
                block_hash: Some(h(9)),
                signature: Some(vec![1, 2, 3]),
            })
            .unwrap();

        // Commit on the same (view, height) — allowed.
        match store.check_vrs(7, 21, VoteStep::Commit, &h(9)).unwrap() {
            VrsDecision::Sign => {}
            other => panic!("expected Sign for Commit advance, got {:?}", other),
        }
    }

    #[test]
    fn file_store_round_trip() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("last_sign.json");

        let store = FileVoteStateStore::open(&path).unwrap();
        store
            .record(&LastSignState {
                version: 1,
                view: 12,
                height: 100,
                step: VoteStep::Commit,
                block_hash: Some(h(7)),
                signature: Some(vec![0xCA, 0xFE]),
            })
            .unwrap();

        // Reopen — state should survive.
        let store2 = FileVoteStateStore::open(&path).unwrap();
        let loaded = store2.load().unwrap();
        assert_eq!(loaded.view, 12);
        assert_eq!(loaded.height, 100);
        assert_eq!(loaded.step, VoteStep::Commit);
        assert_eq!(loaded.block_hash, Some(h(7)));
        assert_eq!(loaded.signature, Some(vec![0xCA, 0xFE]));
    }

    #[test]
    fn file_store_rejects_replay_after_restart() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("last_sign.json");

        let store = FileVoteStateStore::open(&path).unwrap();
        store
            .record(&LastSignState {
                version: 1,
                view: 50,
                height: 200,
                step: VoteStep::Prepare,
                block_hash: Some(h(1)),
                signature: Some(vec![0xAB]),
            })
            .unwrap();

        // Simulate restart by reopening.
        let store2 = FileVoteStateStore::open(&path).unwrap();

        // The exact equivocation scenario: same view, different block.
        match store2.check_vrs(50, 200, VoteStep::Prepare, &h(2)).unwrap() {
            VrsDecision::Reject { reason } => {
                assert!(reason.contains("double-sign refused"), "reason: {}", reason);
            }
            other => panic!("expected Reject after restart, got {:?}", other),
        }
    }

    #[test]
    fn file_store_handles_corrupt_file_via_error() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("last_sign.json");
        std::fs::write(&path, b"not valid json{{{").unwrap();

        let result = FileVoteStateStore::open(&path);
        assert!(result.is_err(), "expected error opening corrupt file");
    }

    #[test]
    fn file_store_handles_empty_file_as_fresh() {
        let tmp = TempDir::new().unwrap();
        let path = tmp.path().join("last_sign.json");
        std::fs::write(&path, b"").unwrap();

        let store = FileVoteStateStore::open(&path).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(loaded, LastSignState::empty());
    }
}
