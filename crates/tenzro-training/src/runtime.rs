//! Tenzro Train syncer runtime: in-memory state machine + write-through
//! persistence to RocksDB column families `CF_TRAINING_RUNS` and
//! `CF_TRAINING_RECEIPTS`.
//!
//! The syncer holds one [`SyncerState`] per active run. Per round it:
//! 1. Receives [`OuterGradient`] submissions over gossip topic
//!    `tenzro/training`.
//! 2. Calls [`accept_outer_gradient`](SyncerState::accept_outer_gradient) to
//!    validate and buffer.
//! 3. Once K-of-M is reached for a fragment (or grace window τ elapses),
//!    calls [`finalize_round`](SyncerState::finalize_round) which delegates
//!    aggregation + outer-step to the Python reference trainer over JSON-RPC.
//! 4. The Python trainer returns post-step parameter hashes, the syncer
//!    builds a [`SyncRound`] with `state_root`, signs it, and broadcasts on
//!    gossip topic `tenzro/training/syncer`.
//!
//! At run completion the syncer calls [`finalize_run`](SyncerState::finalize_run)
//! which builds and persists a [`TrainingReceipt`].

use crate::commitments::{compute_run_root, compute_state_root};
use crate::confidential::{
    validate_confidential_enrollment, verify_manifest_binding, SealedManifestStore,
    SealedShardStore,
};
use crate::error::{Result, TrainingError};
use crate::payload_store::GradientPayloadStore;
use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tenzro_storage::{KvStore, CF_TRAINING_RECEIPTS, CF_TRAINING_RUNS};
use tenzro_types::primitives::{Hash, Timestamp};
use tenzro_types::training::{
    AggregationRule, FragmentQuorumStatus, OuterGradient, PipelineAssignment,
    SealedDatasetManifest, SyncRound, TrainingAttestation, TrainingReceipt, TrainingRun,
    TrainingRunStatus, TrainingTaskSpec, TrainingTier,
};

/// Tier × aggregation-rule policy.
///
/// `Mean` is universally available (it is not Byzantine-robust, but the Open
/// tier already relies on stake bonding + redundant assignment, so Mean is the
/// natural choice). Every Byzantine-robust rule requires at least `Verified`
/// tier — without TEE attestation there is no way for the syncer to bind a
/// gradient to a specific trainer's program/data, which makes a defense like
/// Krum or coordinate-median meaningless: an adversary just submits gradients
/// from sybil DIDs until they form the cluster.
///
/// Returns the minimum tier required to use `rule`.
pub fn min_tier_for_rule(rule: AggregationRule) -> TrainingTier {
    match rule {
        AggregationRule::Mean => TrainingTier::Open,
        AggregationRule::TrimmedMean { .. }
        | AggregationRule::CoordinateMedian
        | AggregationRule::Krum { .. } => TrainingTier::Verified,
    }
}

fn tier_rank(tier: TrainingTier) -> u8 {
    match tier {
        TrainingTier::Open => 0,
        TrainingTier::Verified => 1,
        TrainingTier::Confidential => 2,
    }
}

/// Reject a task spec whose aggregation rule is not permitted by its tier.
pub fn validate_aggregation_for_tier(spec: &TrainingTaskSpec) -> Result<()> {
    let required = min_tier_for_rule(spec.aggregation);
    if tier_rank(spec.tier) < tier_rank(required) {
        return Err(TrainingError::AggregationRuleTierMismatch {
            rule: spec.aggregation,
            required,
            actual: spec.tier,
        });
    }
    Ok(())
}

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
            pipeline_assignments: HashMap::new(),
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
        // DiLoCoX pipeline-parallel groups: enrollment order determines the
        // (group, stage) slot. Group g is complete once all num_stages slots
        // are filled; each complete group acts as one logical trainer for
        // quorum purposes.
        if let Some(pipeline) = &self.task_spec.pipeline {
            let idx = run.trainers.len() as u32;
            let stages = pipeline.num_stages.max(1);
            run.pipeline_assignments.insert(
                trainer_did.clone(),
                PipelineAssignment {
                    group_id: idx / stages,
                    stage: idx % stages,
                },
            );
        }
        run.trainers.push(trainer_did);
        run.last_update = Timestamp::now();
        let logical_trainers = match &self.task_spec.pipeline {
            Some(p) => run.trainers.len() as u32 / p.num_stages.max(1),
            None => run.trainers.len() as u32,
        };
        if logical_trainers >= self.task_spec.quorum {
            run.status = TrainingRunStatus::Training;
        }
        Ok(())
    }

    /// Validate and buffer an outer gradient submission.
    pub fn accept_outer_gradient(&self, gradient: OuterGradient) -> Result<()> {
        // Enrollment gate (fail-closed): only trainers who completed
        // `enroll_trainer` may submit gradients. Without this, the Open-tier
        // mean aggregator would happily fold poison gradients from any
        // anonymous submitter into the next-round model state.
        {
            let run = self.run.read();
            if !run.trainers.contains(&gradient.trainer_did) {
                return Err(TrainingError::TrainerNotEnrolled(gradient.trainer_did));
            }
        }
        // Round must match current.
        let current_round = self.run.read().current_round;
        if gradient.round != current_round {
            return Err(TrainingError::InvalidRound {
                expected: current_round,
                got: gradient.round,
            });
        }
        // Fragment in range.
        let frag_count = self.task_spec.architecture.fragment_count;
        if gradient.fragment >= frag_count {
            return Err(TrainingError::FragmentOutOfRange {
                fragment: gradient.fragment,
                max: frag_count,
            });
        }
        // Quantization must match the task spec's policy — the syncer's
        // dequantize step is wire-format-specific, so a mismatched payload
        // would decode to garbage tensors.
        if gradient.quantization != self.task_spec.quantization {
            return Err(TrainingError::QuantizationMismatch {
                expected: self.task_spec.quantization,
                got: gradient.quantization,
            });
        }
        // Streaming DiLoCo: only fragments in the round's active shard sync
        // this round; submissions for inactive shards are rejected so the
        // per-fragment quorum accounting stays scoped to the active shard.
        let strategy = self.task_spec.sync_strategy;
        if !strategy.fragment_active(gradient.fragment, frag_count, gradient.round) {
            return Err(TrainingError::FragmentNotInActiveShard {
                fragment: gradient.fragment,
                shard: strategy.shard_of_fragment(gradient.fragment, frag_count),
                active_shard: strategy.active_shard(gradient.round),
                round: gradient.round,
            });
        }
        // DiLoCoX pipeline groups: a trainer may only submit gradients for
        // fragments owned by its assigned pipeline stage.
        if let Some(pipeline) = &self.task_spec.pipeline {
            let run = self.run.read();
            if let Some(assignment) = run.pipeline_assignments.get(&gradient.trainer_did) {
                let fragment_stage = pipeline.stage_of_fragment(gradient.fragment, frag_count);
                if assignment.stage != fragment_stage {
                    return Err(TrainingError::PipelineStageMismatch {
                        fragment: gradient.fragment,
                        fragment_stage,
                        trainer_did: gradient.trainer_did.clone(),
                        trainer_stage: assignment.stage,
                    });
                }
            }
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

    /// Snapshot the current quorum status for every fragment in the round's
    /// active shard. Under [`SyncStrategy::Full`](tenzro_types::training::SyncStrategy)
    /// this covers every fragment; under `Streaming` only the active shard's
    /// fragments appear — the state root for the round commits to exactly
    /// the fragments that synced.
    pub fn fragment_statuses(
        &self,
        round: u32,
        post_step_hashes: &HashMap<u32, Hash>,
    ) -> Vec<FragmentQuorumStatus> {
        let frag_count = self.task_spec.architecture.fragment_count;
        let strategy = self.task_spec.sync_strategy;
        let k = self.task_spec.quorum;
        let mut out = Vec::with_capacity(frag_count as usize);
        for f in (0..frag_count).filter(|f| strategy.fragment_active(*f, frag_count, round)) {
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
            no_quorum_witnesses: None,
        };
        Ok(sync_round)
    }

    /// Build a No-Endorsement-Certificate sync round for `round`. Used when
    /// the witness committee cannot assemble a quorum within
    /// `grace_window_ms` — the run carries forward the prior `state_root`
    /// (or `Hash::zero()` for round 0). The caller provides each committee
    /// member's signature over [`crate::commitments::sync_round_signing_bytes`].
    pub fn build_nec_sync_round(
        &self,
        round: u32,
        witnesses: Vec<tenzro_types::primitives::Signature>,
    ) -> Result<SyncRound> {
        let run = self.run.read();
        let carry_forward = if round == 0 {
            Hash::zero()
        } else {
            run.round_state_roots
                .get((round - 1) as usize)
                .copied()
                .ok_or_else(|| {
                    TrainingError::Internal(format!(
                        "NEC for round {} but prior round's state_root is missing",
                        round
                    ))
                })?
        };
        Ok(SyncRound {
            task_id: self.task_spec.task_id.clone(),
            round,
            fragment_quorums: HashMap::new(),
            state_root: carry_forward,
            syncer_signature: tenzro_types::primitives::Signature::default(),
            published_at: Timestamp::now(),
            no_quorum_witnesses: Some(witnesses),
        })
    }

    /// Advance to the next round. Records the round's state root in the run
    /// and clears its buffers.
    ///
    /// # Idempotency (multi-syncer witness committee)
    ///
    /// Under the k-of-N witness-committee design, multiple witnesses may race
    /// to submit a finalize for the same `(round, state_root)`. This method
    /// is **idempotent under repeated valid submissions** and **rejects
    /// conflicts**:
    ///
    /// - `round == current_round`: first writer wins, round advances.
    /// - `round < current_round` and `state_root` matches the previously
    ///   recorded root: returns `Ok(())` (redundant witness submission).
    /// - `round < current_round` and `state_root` differs from the recorded
    ///   root: returns
    ///   [`TrainingError::ConflictingFinalize`](crate::error::TrainingError::ConflictingFinalize)
    ///   so the node layer can surface a fork-detection event.
    /// - `round > current_round`: returns
    ///   [`TrainingError::InvalidRound`](crate::error::TrainingError::InvalidRound)
    ///   (premature, must catch up first).
    pub fn finalize_round(&self, round: u32, state_root: Hash) -> Result<()> {
        let mut run = self.run.write();
        // Idempotent / conflict path: round already finalized.
        if round < run.current_round {
            let prior = run
                .round_state_roots
                .get(round as usize)
                .copied()
                .ok_or_else(|| {
                    TrainingError::Internal(format!(
                        "round {} is below current_round {} but missing from state-root log",
                        round, run.current_round
                    ))
                })?;
            if prior == state_root {
                return Ok(());
            }
            return Err(TrainingError::ConflictingFinalize {
                task_id: self.task_spec.task_id.clone(),
                round,
                expected: prior,
                got: state_root,
            });
        }
        if round > run.current_round {
            return Err(TrainingError::InvalidRound {
                expected: run.current_round,
                got: round,
            });
        }
        // round == current_round: advance.
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
    /// Per-task sealed-shard manifests for Confidential-tier runs. Loaded
    /// on demand at task registration and hydrated on startup. Empty for
    /// Open / Verified tier tasks.
    pub manifests: Arc<SealedManifestStore>,
    /// Content-addressed publish/fetch surface for outer-gradient
    /// safetensors payloads. `None` means no networked adapter is wired —
    /// callers that need bulk payload distribution should attach an
    /// implementation (the in-memory default, or `tenzro-iroh`'s
    /// `IrohGradientStore`, Phase B1 #216).
    payload_store: Option<Arc<dyn GradientPayloadStore>>,
    /// Content-addressed publish/fetch surface for Confidential-tier
    /// sealed shard ciphertexts (Phase B2, #217). `None` means no networked
    /// adapter is wired — Open / Verified tier runs do not need it. Phase B2
    /// ships `IrohSealedShardStore` in `tenzro-iroh`.
    sealed_shard_store: Option<Arc<dyn SealedShardStore>>,
    storage: Option<Arc<dyn KvStore>>,
}

impl Default for TrainingRuntime {
    fn default() -> Self {
        Self {
            syncers: DashMap::new(),
            manifests: Arc::new(SealedManifestStore::new()),
            payload_store: None,
            sealed_shard_store: None,
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
            manifests: Arc::new(SealedManifestStore::with_storage(storage.clone())),
            payload_store: None,
            sealed_shard_store: None,
            storage: Some(storage),
        }
    }

    /// Attach a content-addressed payload store (builder). Consumed by the
    /// gossip → fetch → aggregate path: when an [`OuterGradient`] arrives,
    /// the syncer fetches the safetensors payload from this store before
    /// running aggregation.
    pub fn with_payload_store(mut self, store: Arc<dyn GradientPayloadStore>) -> Self {
        self.payload_store = Some(store);
        self
    }

    /// Borrow the wired payload store, if any.
    pub fn payload_store(&self) -> Option<&Arc<dyn GradientPayloadStore>> {
        self.payload_store.as_ref()
    }

    /// Attach a content-addressed sealed-shard ciphertext store (builder).
    /// Phase B2 (#217): the sponsor publishes ciphertexts to this store and
    /// announces a [`SealedDatasetManifest`] via gossip; trainers fetch
    /// shard ciphertexts via this store keyed on `shard_ciphertext_hash`.
    pub fn with_sealed_shard_store(mut self, store: Arc<dyn SealedShardStore>) -> Self {
        self.sealed_shard_store = Some(store);
        self
    }

    /// Borrow the wired sealed-shard store, if any.
    pub fn sealed_shard_store(&self) -> Option<&Arc<dyn SealedShardStore>> {
        self.sealed_shard_store.as_ref()
    }

    /// Hydrate active runs and sealed manifests from storage at node
    /// startup. Returns the number of runs restored. Manifest hydration
    /// errors are logged but do not abort run hydration.
    pub fn hydrate(&self) -> Result<usize> {
        // Manifests first — runs may reference them at admission time.
        match self.manifests.hydrate() {
            Ok(n) => tracing::info!(restored = n, "Hydrated sealed-shard manifests"),
            Err(e) => tracing::warn!(error = %e, "Failed to hydrate sealed manifests"),
        }
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
    ///
    /// Rejects task specs that violate the tier × aggregation-rule policy
    /// (see [`min_tier_for_rule`]) and Confidential-tier specs whose
    /// `dataset_ref` is not a `tee://<manifest_hash>` URI. This is the
    /// single admission point — hydrated runs are trusted because they
    /// were validated at original registration time, and the spec is
    /// immutable on a registered run.
    pub fn register_run(&self, state: Arc<SyncerState>) -> Result<()> {
        validate_aggregation_for_tier(&state.task_spec)?;
        if state.task_spec.tier == TrainingTier::Confidential
            && crate::confidential::parse_tee_dataset_ref(&state.task_spec.dataset_ref).is_none()
        {
            return Err(TrainingError::InvalidTaskSpec(format!(
                "Confidential-tier task {} must use a tee:// dataset_ref, got '{}'",
                state.task_spec.task_id, state.task_spec.dataset_ref
            )));
        }
        let task_id = state.task_spec.task_id.clone();
        self.persist_run(&state)?;
        self.syncers.insert(task_id, state);
        Ok(())
    }

    /// Install a sealed-shard manifest for a Confidential-tier task. The
    /// manifest's hash must match the `tee://` reference in the task spec;
    /// a mismatch is rejected. Returns the canonical (hash-stamped) copy.
    pub fn install_sealed_manifest(
        &self,
        manifest: SealedDatasetManifest,
    ) -> Result<Arc<SealedDatasetManifest>> {
        let task_id = manifest.task_id.clone();
        let state = self
            .syncers
            .get(&task_id)
            .ok_or_else(|| TrainingError::TaskNotFound(task_id.clone()))?
            .clone();
        // Stamp the canonical hash before binding-check so the sponsor's
        // free-form input is normalized to the deterministic value.
        let mut normalized = manifest;
        normalized.manifest_hash =
            crate::confidential::compute_manifest_hash(&normalized.envelopes);
        verify_manifest_binding(&task_id, &state.task_spec.dataset_ref, &normalized)?;
        self.manifests.put(normalized)
    }

    /// Enroll a trainer with Confidential-tier policy enforced. The caller
    /// supplies the trainer's attestation and the enclave-bound key /
    /// measurements the syncer's TEE verifier extracted from the
    /// attestation report. Open/Verified tier callers can pass empty
    /// `trainer_enclave_pubkey` and `trainer_measurements_hex` — the
    /// validator short-circuits on tier.
    pub fn enroll_trainer(
        &self,
        task_id: &str,
        trainer_did: String,
        trainer_attestation: Option<&TrainingAttestation>,
        trainer_enclave_pubkey: &[u8],
        trainer_measurements_hex: &str,
    ) -> Result<()> {
        let state = self
            .syncers
            .get(task_id)
            .ok_or_else(|| TrainingError::TaskNotFound(task_id.to_string()))?
            .clone();
        let manifest = self.manifests.get(task_id);
        validate_confidential_enrollment(
            task_id,
            state.task_spec.tier,
            manifest.as_deref(),
            &trainer_did,
            trainer_attestation,
            trainer_enclave_pubkey,
            trainer_measurements_hex,
        )?;
        state.enroll_trainer(trainer_did)?;
        self.persist_run(&state)?;
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

    /// Compute the witness committee for `(task_id, round)` given chain
    /// entropy plumbed by the caller (the finalized block hash at round
    /// start). Uses the run's enrolled validator-eligible syncer set as the
    /// universe. Returns the committee DIDs in canonical (ascending-score)
    /// order, or an empty Vec if the task is unknown.
    ///
    /// The committee size is [`crate::committee::recommended_committee_size`]
    /// of the enrolled set: `min(5, max(3, n/5))`.
    pub fn witness_committee(
        &self,
        task_id: &str,
        round: u32,
        chain_entropy: Hash,
    ) -> Vec<String> {
        let state = match self.syncers.get(task_id) {
            Some(s) => s.clone(),
            None => return Vec::new(),
        };
        let validators = state.run.read().trainers.clone();
        let k = crate::committee::recommended_committee_size(validators.len());
        crate::committee::select_witness_committee(task_id, round, chain_entropy, &validators, k)
    }

    /// Check whether `local_did` is a witness for `(task_id, round)`.
    /// Consumed by the gossip listener to decide active-coordinate vs.
    /// passive-observe behavior.
    pub fn is_local_node_in_committee(
        &self,
        local_did: &str,
        task_id: &str,
        round: u32,
        chain_entropy: Hash,
    ) -> bool {
        self.witness_committee(task_id, round, chain_entropy)
            .iter()
            .any(|d| d == local_did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::MemoryStore;
    use tenzro_types::primitives::Address;
    use tenzro_types::training::{
        ArchitectureSpec, GradientQuantization, PipelineConfig, SyncStrategy, TrainingModality,
    };

    fn make_gradient(spec: &TrainingTaskSpec, trainer_did: &str, round: u32, fragment: u32) -> OuterGradient {
        OuterGradient {
            task_id: spec.task_id.clone(),
            round,
            fragment,
            trainer_did: trainer_did.to_string(),
            trainer_address: Address::new([2u8; 32]),
            safetensors_hash: Hash::from_bytes(&[3u8; 32]).unwrap(),
            payload_bytes: 1024,
            quantization: spec.quantization,
            inner_step_count: 100,
            submitted_at: Timestamp::now(),
            signature: tenzro_types::primitives::Signature::default(),
            attestation: None,
        }
    }

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
            sync_strategy: SyncStrategy::Full,
            quantization: GradientQuantization::None,
            delayed_apply: false,
            pipeline: None,
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
    fn finalize_round_idempotent_on_matching_resubmit() {
        // Two witnesses race to finalize the same (round, state_root).
        // First wins, second sees the matching root and returns Ok.
        let state = SyncerState::new(
            dummy_task(),
            "did:tenzro:machine:syncer".into(),
            Address::new([9u8; 32]),
        );
        let root = Hash::from_bytes(&[7u8; 32]).unwrap();
        state.finalize_round(0, root).unwrap();
        // Re-submit the same root: idempotent Ok.
        state.finalize_round(0, root).unwrap();
        let run = state.run.read();
        assert_eq!(run.current_round, 1);
        assert_eq!(run.round_state_roots, vec![root]);
    }

    #[test]
    fn finalize_round_rejects_conflicting_root() {
        // A second witness submits a different state_root for an already
        // finalized round — surfaces as ConflictingFinalize for fork
        // detection.
        let state = SyncerState::new(
            dummy_task(),
            "did:tenzro:machine:syncer".into(),
            Address::new([9u8; 32]),
        );
        let root_a = Hash::from_bytes(&[7u8; 32]).unwrap();
        let root_b = Hash::from_bytes(&[8u8; 32]).unwrap();
        state.finalize_round(0, root_a).unwrap();
        let err = state.finalize_round(0, root_b);
        assert!(matches!(
            err,
            Err(TrainingError::ConflictingFinalize { round: 0, .. })
        ));
        // Run state must not advance further.
        let run = state.run.read();
        assert_eq!(run.current_round, 1);
        assert_eq!(run.round_state_roots, vec![root_a]);
    }

    #[test]
    fn finalize_round_rejects_premature_round() {
        let state = SyncerState::new(
            dummy_task(),
            "did:tenzro:machine:syncer".into(),
            Address::new([9u8; 32]),
        );
        let root = Hash::from_bytes(&[7u8; 32]).unwrap();
        // current_round is 0; submitting for 1 is premature.
        let err = state.finalize_round(1, root);
        assert!(matches!(
            err,
            Err(TrainingError::InvalidRound {
                expected: 0,
                got: 1
            })
        ));
    }

    #[test]
    fn build_nec_sync_round_carries_forward_prior_root() {
        let state = SyncerState::new(
            dummy_task(),
            "did:tenzro:machine:syncer".into(),
            Address::new([9u8; 32]),
        );
        // Finalize round 0 normally.
        let r0 = Hash::from_bytes(&[7u8; 32]).unwrap();
        state.finalize_round(0, r0).unwrap();
        // Round 1 fails to assemble quorum; build a NEC for round 1.
        let nec = state
            .build_nec_sync_round(1, vec![tenzro_types::primitives::Signature::default(); 3])
            .unwrap();
        assert_eq!(nec.round, 1);
        assert_eq!(nec.state_root, r0);
        assert!(nec.no_quorum_witnesses.is_some());
        assert_eq!(nec.no_quorum_witnesses.unwrap().len(), 3);
        assert!(nec.fragment_quorums.is_empty());
    }

    #[test]
    fn build_nec_sync_round_for_round_zero_uses_zero_root() {
        let state = SyncerState::new(
            dummy_task(),
            "did:tenzro:machine:syncer".into(),
            Address::new([9u8; 32]),
        );
        let nec = state
            .build_nec_sync_round(0, vec![tenzro_types::primitives::Signature::default(); 3])
            .unwrap();
        assert_eq!(nec.state_root, Hash::zero());
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

    #[test]
    fn open_tier_with_mean_admits() {
        let runtime = TrainingRuntime::new();
        let mut spec = dummy_task();
        spec.tier = TrainingTier::Open;
        spec.aggregation = AggregationRule::Mean;
        let state = Arc::new(SyncerState::new(
            spec,
            "did:tenzro:machine:syncer".into(),
            Address::new([9u8; 32]),
        ));
        runtime.register_run(state).unwrap();
    }

    #[test]
    fn open_tier_with_krum_rejected() {
        let runtime = TrainingRuntime::new();
        let mut spec = dummy_task();
        spec.tier = TrainingTier::Open;
        spec.aggregation = AggregationRule::Krum { f: 1 };
        let state = Arc::new(SyncerState::new(
            spec,
            "did:tenzro:machine:syncer".into(),
            Address::new([9u8; 32]),
        ));
        let err = runtime.register_run(state);
        assert!(matches!(
            err,
            Err(TrainingError::AggregationRuleTierMismatch { .. })
        ));
    }

    #[test]
    fn verified_tier_admits_all_rules() {
        let rules = [
            AggregationRule::Mean,
            AggregationRule::TrimmedMean { alpha_bps: 1000 },
            AggregationRule::CoordinateMedian,
            AggregationRule::Krum { f: 1 },
        ];
        for (i, rule) in rules.into_iter().enumerate() {
            let runtime = TrainingRuntime::new();
            let mut spec = dummy_task();
            spec.task_id = format!("task-v{}", i);
            spec.tier = TrainingTier::Verified;
            spec.aggregation = rule;
            let state = Arc::new(SyncerState::new(
                spec,
                "did:tenzro:machine:syncer".into(),
                Address::new([9u8; 32]),
            ));
            runtime.register_run(state).unwrap();
        }
    }

    #[test]
    fn confidential_tier_admits_byzantine_rules() {
        let runtime = TrainingRuntime::new();
        let mut spec = dummy_task();
        spec.tier = TrainingTier::Confidential;
        spec.aggregation = AggregationRule::CoordinateMedian;
        // Confidential-tier specs must bind to a sealed-shard manifest via
        // a `tee://<hex>` dataset_ref — see `register_run`.
        spec.dataset_ref = format!("tee://{}", hex::encode([0u8; 32]));
        let state = Arc::new(SyncerState::new(
            spec,
            "did:tenzro:machine:syncer".into(),
            Address::new([9u8; 32]),
        ));
        runtime.register_run(state).unwrap();
    }

    #[test]
    fn witness_committee_selects_from_enrolled_set() {
        // quorum=10 keeps the run in Enrolling until all 10 are in, so we
        // can populate the full set without flipping to Training mid-loop
        // (which would close enrollment).
        let mut spec = dummy_task();
        spec.trainer_count = 10;
        spec.quorum = 10;
        let state = Arc::new(SyncerState::new(
            spec,
            "did:tenzro:machine:syncer".into(),
            Address::new([9u8; 32]),
        ));
        for i in 0..10 {
            state
                .enroll_trainer(format!("did:tenzro:machine:t{:02}", i))
                .unwrap();
        }
        let runtime = TrainingRuntime::new();
        runtime.register_run(state).unwrap();
        let entropy = Hash::from_bytes(&[42u8; 32]).unwrap();
        let committee = runtime.witness_committee("task-1", 0, entropy);
        // n=10 → recommended size clamped to 3.
        assert_eq!(committee.len(), 3);
        // Every member is from the enrolled set.
        for did in &committee {
            assert!(did.starts_with("did:tenzro:machine:t"));
        }
        // Deterministic: re-querying with the same entropy yields the same
        // committee.
        let committee2 = runtime.witness_committee("task-1", 0, entropy);
        assert_eq!(committee, committee2);
    }

    #[test]
    fn witness_committee_empty_for_unknown_task() {
        let runtime = TrainingRuntime::new();
        let entropy = Hash::from_bytes(&[42u8; 32]).unwrap();
        assert!(runtime
            .witness_committee("does-not-exist", 0, entropy)
            .is_empty());
    }

    #[test]
    fn streaming_rejects_inactive_shard_fragment() {
        // 4 fragments, 2 shards → shard 0 = {0,1}, shard 1 = {2,3}.
        // Round 0 activates shard 0, so fragment 2 must be rejected.
        let mut spec = dummy_task();
        spec.sync_strategy = SyncStrategy::Streaming { num_shards: 2 };
        let state = SyncerState::new(
            spec.clone(),
            "did:tenzro:machine:syncer".into(),
            Address::new([9u8; 32]),
        );
        state.enroll_trainer("did:tenzro:machine:t1".into()).unwrap();
        state.enroll_trainer("did:tenzro:machine:t2".into()).unwrap();

        let active = make_gradient(&spec, "did:tenzro:machine:t1", 0, 0);
        state.accept_outer_gradient(active).unwrap();

        let inactive = make_gradient(&spec, "did:tenzro:machine:t1", 0, 2);
        let err = state.accept_outer_gradient(inactive);
        assert!(matches!(
            err,
            Err(TrainingError::FragmentNotInActiveShard {
                fragment: 2,
                shard: 1,
                active_shard: 0,
                round: 0,
            })
        ));
    }

    #[test]
    fn streaming_fragment_statuses_scope_to_active_shard() {
        let mut spec = dummy_task();
        spec.sync_strategy = SyncStrategy::Streaming { num_shards: 2 };
        let state = SyncerState::new(
            spec,
            "did:tenzro:machine:syncer".into(),
            Address::new([9u8; 32]),
        );
        // Round 0 → shard 0 → fragments {0, 1} only.
        let statuses = state.fragment_statuses(0, &HashMap::new());
        let fragments: Vec<u32> = statuses.iter().map(|s| s.fragment).collect();
        assert_eq!(fragments, vec![0, 1]);
        // Round 1 → shard 1 → fragments {2, 3} only.
        let statuses = state.fragment_statuses(1, &HashMap::new());
        let fragments: Vec<u32> = statuses.iter().map(|s| s.fragment).collect();
        assert_eq!(fragments, vec![2, 3]);
    }

    #[test]
    fn quantization_mismatch_rejected() {
        let mut spec = dummy_task();
        spec.quantization = GradientQuantization::Int8 { block_size: 256 };
        let state = SyncerState::new(
            spec.clone(),
            "did:tenzro:machine:syncer".into(),
            Address::new([9u8; 32]),
        );
        state.enroll_trainer("did:tenzro:machine:t1".into()).unwrap();
        state.enroll_trainer("did:tenzro:machine:t2".into()).unwrap();

        let mut gradient = make_gradient(&spec, "did:tenzro:machine:t1", 0, 0);
        gradient.quantization = GradientQuantization::None;
        let err = state.accept_outer_gradient(gradient);
        assert!(matches!(
            err,
            Err(TrainingError::QuantizationMismatch {
                expected: GradientQuantization::Int8 { block_size: 256 },
                got: GradientQuantization::None,
            })
        ));

        // Matching quantization is accepted.
        let gradient = make_gradient(&spec, "did:tenzro:machine:t1", 0, 0);
        state.accept_outer_gradient(gradient).unwrap();
    }

    #[test]
    fn pipeline_enrollment_assigns_groups_and_counts_group_quorum() {
        // 2 stages, quorum 2 → 4 trainers form 2 complete groups.
        let mut spec = dummy_task();
        spec.pipeline = Some(PipelineConfig { num_stages: 2 });
        let state = SyncerState::new(
            spec,
            "did:tenzro:machine:syncer".into(),
            Address::new([9u8; 32]),
        );
        for i in 0..3 {
            state
                .enroll_trainer(format!("did:tenzro:machine:t{}", i))
                .unwrap();
        }
        // 3 trainers = 1 complete group + 1 partial → still enrolling.
        assert_eq!(state.run.read().status, TrainingRunStatus::Enrolling);
        state.enroll_trainer("did:tenzro:machine:t3".into()).unwrap();
        // 4 trainers = 2 complete groups → quorum met.
        assert_eq!(state.run.read().status, TrainingRunStatus::Training);

        let run = state.run.read();
        let a0 = run.pipeline_assignments["did:tenzro:machine:t0"];
        let a1 = run.pipeline_assignments["did:tenzro:machine:t1"];
        let a2 = run.pipeline_assignments["did:tenzro:machine:t2"];
        let a3 = run.pipeline_assignments["did:tenzro:machine:t3"];
        assert_eq!((a0.group_id, a0.stage), (0, 0));
        assert_eq!((a1.group_id, a1.stage), (0, 1));
        assert_eq!((a2.group_id, a2.stage), (1, 0));
        assert_eq!((a3.group_id, a3.stage), (1, 1));
    }

    #[test]
    fn pipeline_stage_ownership_enforced_on_submission() {
        // 4 fragments, 2 stages → stage 0 owns {0,1}, stage 1 owns {2,3}.
        let mut spec = dummy_task();
        spec.pipeline = Some(PipelineConfig { num_stages: 2 });
        let state = SyncerState::new(
            spec.clone(),
            "did:tenzro:machine:syncer".into(),
            Address::new([9u8; 32]),
        );
        for i in 0..4 {
            state
                .enroll_trainer(format!("did:tenzro:machine:t{}", i))
                .unwrap();
        }
        // t0 is (group 0, stage 0): fragment 0 accepted, fragment 2 rejected.
        let ok = make_gradient(&spec, "did:tenzro:machine:t0", 0, 0);
        state.accept_outer_gradient(ok).unwrap();
        let wrong_stage = make_gradient(&spec, "did:tenzro:machine:t0", 0, 2);
        let err = state.accept_outer_gradient(wrong_stage);
        assert!(matches!(
            err,
            Err(TrainingError::PipelineStageMismatch {
                fragment: 2,
                fragment_stage: 1,
                trainer_stage: 0,
                ..
            })
        ));
        // t1 is (group 0, stage 1): fragment 2 accepted.
        let ok = make_gradient(&spec, "did:tenzro:machine:t1", 0, 2);
        state.accept_outer_gradient(ok).unwrap();
    }

    #[test]
    fn min_tier_classification() {
        assert_eq!(
            min_tier_for_rule(AggregationRule::Mean),
            TrainingTier::Open
        );
        assert_eq!(
            min_tier_for_rule(AggregationRule::TrimmedMean { alpha_bps: 1000 }),
            TrainingTier::Verified
        );
        assert_eq!(
            min_tier_for_rule(AggregationRule::CoordinateMedian),
            TrainingTier::Verified
        );
        assert_eq!(
            min_tier_for_rule(AggregationRule::Krum { f: 1 }),
            TrainingTier::Verified
        );
    }
}
