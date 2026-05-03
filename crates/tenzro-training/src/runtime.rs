//! Tenzro Train syncer runtime: in-memory state machine + write-through
//! persistence to RocksDB column families `CF_TRAINING_RUNS` and
//! `CF_TRAINING_RECEIPTS`.
//!
//! The syncer holds one [`SyncerState`] per active run. Per round it:
//! 1. Receives [`OuterGradient`] submissions over gossip topic
//!    `tenzro/training/1.0.0`.
//! 2. Calls [`accept_outer_gradient`](SyncerState::accept_outer_gradient) to
//!    validate and buffer.
//! 3. Once K-of-M is reached for a fragment (or grace window τ elapses),
//!    calls [`finalize_round`](SyncerState::finalize_round) which delegates
//!    aggregation + outer-step to the Python reference trainer over JSON-RPC.
//! 4. The Python trainer returns post-step parameter hashes, the syncer
//!    builds a [`SyncRound`] with `state_root`, signs it, and broadcasts on
//!    gossip topic `tenzro/training/syncer/1.0.0`.
//!
//! At run completion the syncer calls [`finalize_run`](SyncerState::finalize_run)
//! which builds and persists a [`TrainingReceipt`].

use crate::commitments::{compute_run_root, compute_state_root};
use crate::error::{Result, TrainingError};
use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tenzro_storage::{KvStore, CF_TRAINING_RECEIPTS, CF_TRAINING_RUNS};
use tenzro_types::primitives::{Hash, Timestamp};
use tenzro_types::training::{
    FragmentQuorumStatus, OuterGradient, SyncRound, TrainingReceipt, TrainingRun,
    TrainingRunStatus, TrainingTaskSpec, TrainingTier,
};

/// Per-fragment buffer of outer gradients accepted so far for the current
/// round. Keyed by fragment id.
#[derive(Debug, Clone, Default)]
pub struct FragmentBuffer {
    pub accepted: Vec<OuterGradient>,
}

impl FragmentBuffer {
    pub fn quorum_met(&self, k: u32) -> bool {
        self.accepted.len() as u32 >= k
    }

    pub fn accepted_hashes(&self) -> Vec<Hash> {
        let mut hashes: Vec<&OuterGradient> = self.accepted.iter().collect();
        hashes.sort_by(|a, b| a.trainer_did.cmp(&b.trainer_did));
        hashes.iter().map(|g| g.safetensors_hash).collect()
    }
}

/// In-memory state for one active training run held by the elected syncer.
pub struct SyncerState {
    pub task_spec: TrainingTaskSpec,
    pub run: RwLock<TrainingRun>,
    /// Per-round, per-fragment outer-gradient buffers.
    /// Keyed first by round, then by fragment id.
    pub buffers: DashMap<(u32, u32), FragmentBuffer>,
}

impl SyncerState {
    pub fn new(task_spec: TrainingTaskSpec, syncer_did: String, syncer_address: tenzro_types::primitives::Address) -> Self {
        let now = Timestamp::now();
        let run = TrainingRun {
            task_id: task_spec.task_id.clone(),
            task_spec: task_spec.clone(),
            status: TrainingRunStatus::Enrolling,
            syncer_did: Some(syncer_did),
            syncer_address: Some(syncer_address),
            trainers: Vec::new(),
            current_round: 0,
            round_state_roots: Vec::new(),
            created_at: now,
            last_update: now,
        };
        Self {
            task_spec,
            run: RwLock::new(run),
            buffers: DashMap::new(),
        }
    }

    pub fn enroll_trainer(&self, trainer_did: String) -> Result<()> {
        let mut run = self.run.write();
        if !matches!(
            run.status,
            TrainingRunStatus::Pending | TrainingRunStatus::Enrolling
        ) {
            return Err(TrainingError::EnrollmentClosed(self.task_spec.task_id.clone()));
        }
        if run.trainers.contains(&trainer_did) {
            return Err(TrainingError::AlreadyEnrolled(trainer_did));
        }
        run.trainers.push(trainer_did);
        run.last_update = Timestamp::now();
        if run.trainers.len() as u32 >= self.task_spec.quorum {
            run.status = TrainingRunStatus::Training;
        }
        Ok(())
    }

    /// Validate and buffer an outer gradient submission.
    pub fn accept_outer_gradient(&self, gradient: OuterGradient) -> Result<()> {
        // Round must match current.
        let current_round = self.run.read().current_round;
        if gradient.round != current_round {
            return Err(TrainingError::InvalidRound {
                expected: current_round,
                got: gradient.round,
            });
        }
        // Fragment in range.
        if gradient.fragment >= self.task_spec.architecture.fragment_count {
            return Err(TrainingError::FragmentOutOfRange {
                fragment: gradient.fragment,
                max: self.task_spec.architecture.fragment_count,
            });
        }
        // Tier requirement: Verified/Confidential require attestation.
        if matches!(
            self.task_spec.tier,
            TrainingTier::Verified | TrainingTier::Confidential
        ) && gradient.attestation.is_none()
        {
            return Err(TrainingError::AttestationRequired(self.task_spec.tier));
        }

        let key = (gradient.round, gradient.fragment);
        let mut entry = self.buffers.entry(key).or_default();
        // Idempotency: don't double-count the same trainer.
        if entry
            .accepted
            .iter()
            .any(|g| g.trainer_did == gradient.trainer_did)
        {
            return Ok(());
        }
        entry.accepted.push(gradient);
        Ok(())
    }

    /// Snapshot the current quorum status for every fragment in `round`.
    pub fn fragment_statuses(
        &self,
        round: u32,
        post_step_hashes: &HashMap<u32, Hash>,
    ) -> Vec<FragmentQuorumStatus> {
        let frag_count = self.task_spec.architecture.fragment_count;
        let k = self.task_spec.quorum;
        let mut out = Vec::with_capacity(frag_count as usize);
        for f in 0..frag_count {
            let buf = self.buffers.get(&(round, f));
            let (accepted, accepted_hashes, quorum_met) = match buf {
                Some(b) => {
                    let n = b.accepted.len() as u32;
                    (n, b.accepted_hashes(), n >= k)
                }
                None => (0, Vec::new(), false),
            };
            out.push(FragmentQuorumStatus {
                fragment: f,
                accepted,
                accepted_hashes,
                quorum_met,
                post_step_hash: post_step_hashes
                    .get(&f)
                    .copied()
                    .unwrap_or_else(Hash::zero),
            });
        }
        out
    }

    /// Build the SyncRound for `round` given post-aggregation parameter
    /// hashes (which the Python reference trainer returns after aggregating
    /// + applying the outer optimizer step).
    pub fn build_sync_round(
        &self,
        round: u32,
        post_step_hashes: HashMap<u32, Hash>,
    ) -> Result<SyncRound> {
        let fragment_statuses = self.fragment_statuses(round, &post_step_hashes);
        let state_root = compute_state_root(&self.task_spec.task_id, round, &fragment_statuses);
        let mut fragment_quorums = HashMap::new();
        for s in fragment_statuses {
            fragment_quorums.insert(s.fragment, s);
        }
        // Signature is filled in by the caller (which holds the syncer key).
        let sync_round = SyncRound {
            task_id: self.task_spec.task_id.clone(),
            round,
            fragment_quorums,
            state_root,
            syncer_signature: tenzro_types::primitives::Signature::default(),
            published_at: Timestamp::now(),
        };
        Ok(sync_round)
    }

    /// Advance to the next round. Records the previous round's state root
    /// in the run and clears that round's buffers.
    pub fn finalize_round(&self, round: u32, state_root: Hash) -> Result<()> {
        let mut run = self.run.write();
        if round != run.current_round {
            return Err(TrainingError::InvalidRound {
                expected: run.current_round,
                got: round,
            });
        }
        run.round_state_roots.push(state_root);
        run.current_round = round + 1;
        run.last_update = Timestamp::now();
        if run.current_round >= self.task_spec.max_rounds {
            run.status = TrainingRunStatus::Completed;
        }
        // Drop buffers for the finalized round.
        let frag_count = self.task_spec.architecture.fragment_count;
        for f in 0..frag_count {
            self.buffers.remove(&(round, f));
        }
        Ok(())
    }

    /// Build the final receipt. Caller must sign it before persisting.
    pub fn build_receipt(
        &self,
        final_model_hash: Hash,
        syncer_attestation: tenzro_types::training::TrainingAttestation,
        trainer_contributions: HashMap<String, u32>,
        trainer_rewards: HashMap<String, u128>,
        network_commission: u128,
    ) -> Result<TrainingReceipt> {
        let run = self.run.read();
        let run_root = compute_run_root(&run.round_state_roots);
        let receipt = TrainingReceipt {
            task_id: self.task_spec.task_id.clone(),
            task_spec: self.task_spec.clone(),
            final_model_hash,
            syncer_did: run
                .syncer_did
                .clone()
                .ok_or_else(|| TrainingError::Internal("no syncer DID".into()))?,
            syncer_address: run
                .syncer_address
                .ok_or_else(|| TrainingError::Internal("no syncer address".into()))?,
            trainer_contributions,
            trainer_rewards,
            network_commission,
            round_state_roots: run.round_state_roots.clone(),
            run_root,
            syncer_attestation,
            finalized_at: Timestamp::now(),
            syncer_signature: tenzro_types::primitives::Signature::default(),
        };
        Ok(receipt)
    }
}

// ---------------------------------------------------------------------------
// TrainingRuntime — central registry + persistence
// ---------------------------------------------------------------------------

/// Top-level runtime held by the node. Tracks active runs the local node
/// is syncing and maintains write-through persistence to RocksDB.
pub struct TrainingRuntime {
    /// Active syncer states, keyed by task_id.
    pub syncers: DashMap<String, Arc<SyncerState>>,
    storage: Option<Arc<dyn KvStore>>,
}

impl Default for TrainingRuntime {
    fn default() -> Self {
        Self {
            syncers: DashMap::new(),
            storage: None,
        }
    }
}

impl TrainingRuntime {
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct with write-through persistence. CFs `CF_TRAINING_RUNS` and
    /// `CF_TRAINING_RECEIPTS` MUST be opened by the caller (they are
    /// declared in `tenzro-storage`).
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        Self {
            syncers: DashMap::new(),
            storage: Some(storage),
        }
    }

    /// Hydrate active runs from storage at node startup.
    /// Returns the number of runs restored.
    pub fn hydrate(&self) -> Result<usize> {
        let storage = match &self.storage {
            Some(s) => s,
            None => return Ok(0),
        };
        let pairs = storage
            .scan_prefix(CF_TRAINING_RUNS, b"run:")
            .map_err(|e| TrainingError::Storage(format!("hydrate scan: {}", e)))?;
        let mut count = 0;
        for (_key, value) in pairs {
            let run: TrainingRun = serde_json::from_slice(&value)
                .map_err(|e| TrainingError::Serialization(format!("decode TrainingRun: {}", e)))?;
            // Skip terminal runs — they're audit-only.
            if matches!(
                run.status,
                TrainingRunStatus::Completed | TrainingRunStatus::Failed | TrainingRunStatus::Cancelled
            ) {
                continue;
            }
            let task_id = run.task_id.clone();
            let syncer_did = run.syncer_did.clone().unwrap_or_default();
            let syncer_addr = run
                .syncer_address
                .unwrap_or_else(|| tenzro_types::primitives::Address::new([0u8; 32]));
            let state = Arc::new(SyncerState::new(
                run.task_spec.clone(),
                syncer_did,
                syncer_addr,
            ));
            *state.run.write() = run;
            self.syncers.insert(task_id, state);
            count += 1;
        }
        Ok(count)
    }

    /// Register a new training run (sponsor + syncer election complete).
    pub fn register_run(&self, state: Arc<SyncerState>) -> Result<()> {
        let task_id = state.task_spec.task_id.clone();
        self.persist_run(&state)?;
        self.syncers.insert(task_id, state);
        Ok(())
    }

    /// Persist a run record under `run:<task_id>` in CF_TRAINING_RUNS.
    pub fn persist_run(&self, state: &SyncerState) -> Result<()> {
        if let Some(storage) = &self.storage {
            let run = state.run.read().clone();
            let key = format!("run:{}", run.task_id);
            let value = serde_json::to_vec(&run)
                .map_err(|e| TrainingError::Serialization(e.to_string()))?;
            storage
                .put(CF_TRAINING_RUNS, key.as_bytes(), &value)
                .map_err(|e| TrainingError::Storage(e.to_string()))?;
        }
        Ok(())
    }

    /// Persist a sealed receipt under `receipt:<task_id>` in CF_TRAINING_RECEIPTS.
    pub fn persist_receipt(&self, receipt: &TrainingReceipt) -> Result<()> {
        if let Some(storage) = &self.storage {
            let key = format!("receipt:{}", receipt.task_id);
            let value = serde_json::to_vec(receipt)
                .map_err(|e| TrainingError::Serialization(e.to_string()))?;
            storage
                .put(CF_TRAINING_RECEIPTS, key.as_bytes(), &value)
                .map_err(|e| TrainingError::Storage(e.to_string()))?;
        }
        Ok(())
    }

    /// Look up a sealed receipt.
    pub fn get_receipt(&self, task_id: &str) -> Result<Option<TrainingReceipt>> {
        let storage = match &self.storage {
            Some(s) => s,
            None => return Ok(None),
        };
        let key = format!("receipt:{}", task_id);
        let bytes = storage
            .get(CF_TRAINING_RECEIPTS, key.as_bytes())
            .map_err(|e| TrainingError::Storage(e.to_string()))?;
        match bytes {
            None => Ok(None),
            Some(b) => Ok(Some(
                serde_json::from_slice(&b)
                    .map_err(|e| TrainingError::Serialization(e.to_string()))?,
            )),
        }
    }

    /// List all active syncer states (caller-visible read).
    pub fn list_runs(&self) -> Vec<TrainingRun> {
        self.syncers
            .iter()
            .map(|kv| kv.value().run.read().clone())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::MemoryStore;
    use tenzro_types::primitives::Address;
    use tenzro_types::training::{ArchitectureSpec, TrainingModality};

    fn dummy_task() -> TrainingTaskSpec {
        TrainingTaskSpec {
            task_id: "task-1".into(),
            sponsor_did: "did:tenzro:human:abc".into(),
            sponsor_address: Address::new([1u8; 32]),
            architecture: ArchitectureSpec {
                family: "timesfm".into(),
                param_count: 200_000_000,
                modality: TrainingModality::Timeseries,
                fragment_count: 4,
                dtype: Some("bf16".into()),
                metadata: HashMap::new(),
            },
            tier: TrainingTier::Open,
            aggregation: tenzro_types::training::AggregationRule::Mean,
            trainer_count: 4,
            quorum: 2,
            inner_steps: 100,
            max_rounds: 10,
            grace_window_ms: 5_000,
            reward_pool: 1_000,
            dataset_ref: "ipfs://Qm...".into(),
            dataset_hash: Hash::zero(),
            min_throughput: None,
            created_at: Timestamp::now(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn enroll_then_promote_to_training() {
        let state = SyncerState::new(
            dummy_task(),
            "did:tenzro:machine:syncer".into(),
            Address::new([9u8; 32]),
        );
        state.enroll_trainer("did:tenzro:machine:t1".into()).unwrap();
        assert_eq!(state.run.read().status, TrainingRunStatus::Enrolling);
        state.enroll_trainer("did:tenzro:machine:t2".into()).unwrap();
        assert_eq!(state.run.read().status, TrainingRunStatus::Training);
    }

    #[test]
    fn enroll_rejects_duplicates() {
        let state = SyncerState::new(
            dummy_task(),
            "did:tenzro:machine:syncer".into(),
            Address::new([9u8; 32]),
        );
        state.enroll_trainer("did:tenzro:machine:t1".into()).unwrap();
        let err = state.enroll_trainer("did:tenzro:machine:t1".into());
        assert!(matches!(err, Err(TrainingError::AlreadyEnrolled(_))));
    }

    #[test]
    fn finalize_round_advances_and_records_root() {
        let state = SyncerState::new(
            dummy_task(),
            "did:tenzro:machine:syncer".into(),
            Address::new([9u8; 32]),
        );
        let root = Hash::from_bytes(&[7u8; 32]).unwrap();
        state.finalize_round(0, root).unwrap();
        let run = state.run.read();
        assert_eq!(run.current_round, 1);
        assert_eq!(run.round_state_roots, vec![root]);
    }

    #[test]
    fn runtime_persists_and_hydrates_runs() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let runtime = TrainingRuntime::with_storage(storage.clone());
        let state = Arc::new(SyncerState::new(
            dummy_task(),
            "did:tenzro:machine:syncer".into(),
            Address::new([9u8; 32]),
        ));
        runtime.register_run(state).unwrap();
        // New runtime over same storage should hydrate.
        let runtime2 = TrainingRuntime::with_storage(storage);
        let restored = runtime2.hydrate().unwrap();
        assert_eq!(restored, 1);
        assert!(runtime2.syncers.contains_key("task-1"));
    }
}
