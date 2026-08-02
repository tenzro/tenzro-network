//! Tenzro Train — protocol-only Rust crate for decentralized verifiable
//! foundation-model training with decoupled outer aggregation.
//!
//! # Architecture
//!
//! This crate is **protocol only**. It owns:
//! - Outer-gradient + sync-round message types (re-exported from
//!   [`tenzro_types::training`]).
//! - Byzantine-robust aggregation rules ([`aggregation`]).
//! - Nesterov-momentum outer optimizer ([`outer_optimizer`]).
//! - Per-round and per-run on-chain commitments ([`commitments`]).
//! - The syncer state machine and write-through persistence to RocksDB
//!   ([`runtime`]).
//!
//! It deliberately does **not** depend on a tensor library — aggregation
//! operates over already-decoded `ndarray` views of safetensors-decoded
//! payloads. The inner training loop (forward/backward, optimizer steps)
//! is dispatched to the Python reference trainer at
//! `integrations/trainer/` (PyTorch FSDP2 + Hivemind + safetensors).
//!
//! See `AI.md` §7.7.1 for the full split rationale.
//!
//! # Scope
//!
//! - Modality: timeseries first (TimesFM-class 200M models). Llama 3 and
//!   ViT adapters dispatched to the Python trainer.
//! - Trust tiers: [`TrainingTier::Open`] (stake bonding only),
//!   [`TrainingTier::Verified`] (per-round TEE attestation),
//!   [`TrainingTier::Confidential`] (TEE-sealed data shards).
//! - Aggregation rules:
//!   - [`AggregationRule::Mean`] — admitted at all tiers, default for
//!     Open-tier runs.
//!   - [`AggregationRule::LoraAlternating`] — for LoRA/QLoRA adapter runs;
//!     the trainer freezes one low-rank factor per round so each round's
//!     delta is a single factor and per-coordinate mean is correct. Reuses
//!     the mean aggregator; admitted at all tiers like [`AggregationRule::Mean`].
//!   - [`AggregationRule::TrimmedMean`],
//!     [`AggregationRule::CoordinateMedian`],
//!     [`AggregationRule::Krum`] — Byzantine-robust; admitted only at
//!     [`TrainingTier::Verified`] or [`TrainingTier::Confidential`].
//!     Open-tier sybil submissions can defeat coordinate-wise medians and
//!     Krum's cluster-center heuristic, so the policy gate enforced by
//!     [`validate_aggregation_for_tier`] rejects them at task-registration
//!     time with [`TrainingError::AggregationRuleTierMismatch`].

pub mod activation;
pub mod aggregation;
pub mod commitments;
pub mod committee;
pub mod confidential;
pub mod error;
pub mod gossip;
pub mod outer_optimizer;
pub mod payload_store;
pub mod quantization;
pub mod runtime;
pub mod slashing;
pub mod sparse;

pub use activation::{
    ActivationVerification, MAX_MEAN_LOSS_REL_DELTA, MAX_MEAN_PROBE_REL_DELTA,
    MIN_PROBE_INDEX_OVERLAP, top_k_delta_probes, validate_activation_commitment,
    verify_activation_commitment,
};
pub use aggregation::{
    Aggregator, CoordinateMedianAggregator, KrumAggregator, MeanAggregator, TrimmedMeanAggregator,
    aggregator_for, clip_gradients, clip_to_l2_norm, l2_norm,
};
pub use commitments::{
    compute_run_root, compute_state_root, outer_gradient_signing_bytes, sync_round_signing_bytes,
};
pub use committee::{
    COMMITTEE_SCORE_DOMAIN_TAG, COMMITTEE_SEED_DOMAIN_TAG, committee_seed, is_in_committee,
    recommended_committee_size, select_witness_committee,
};
pub use confidential::{
    EnclaveIdentityVerifier, InMemorySealedShardStore, SealedManifestStore, SealedShardStore,
    VerifiedEnclaveIdentity, compute_manifest_hash, compute_shard_ciphertext_hash,
    parse_tee_dataset_ref, validate_confidential_enrollment, verify_manifest_binding,
    verify_shard_ciphertext,
};
pub use error::{Result, TrainingError};
pub use gossip::{
    TRAINING_SYNCER_TOPIC, TRAINING_TOPIC, TrainingGossipMessage, decode_for_topic,
    encode_install_sealed_manifest, encode_outer_gradient, encode_sync_round,
};
pub use outer_optimizer::{
    AdaptiveLrConfig, NesterovSgdConfig, NesterovSgdState, gradient_agreement, sparse_ef_step,
};
pub use payload_store::{
    GradientPayloadStore, InMemoryGradientStore, compute_payload_hash, verify_payload,
};
pub use quantization::{dequantize, encoded_len, quantize};
pub use runtime::{
    FragmentBuffer, RoundDecision, SyncerState, TrainingRuntime, min_tier_for_rule,
    validate_aggregation_for_tier, validate_objective, validate_payload_kind,
};
pub use slashing::{EvictionReason, TrainerSlashingCallback, eviction_decisions};
pub use sparse::{
    ErrorFeedback, SparseDecoded, select_transmitted, sparse_decode, sparse_encode,
    sparse_encoded_len,
};

// Re-export the protocol-level types from `tenzro-types` for convenience —
// downstream crates can `use tenzro_training::TrainingTaskSpec` instead of
// `use tenzro_types::training::TrainingTaskSpec`.
pub use tenzro_types::training::{
    ACTIVATION_COMMITMENT_DOMAIN_TAG, ActivationCommitment, AggregationRule, ArchitectureSpec,
    DEFAULT_PROBE_K, DeltaProbe, FragmentQuorumStatus, GradientQuantization, MAX_PROBE_K,
    OuterGradient, OuterUpdateMode, PayloadKind, PipelineAssignment, PipelineConfig, RlConfig,
    SealedDatasetManifest, SealedShardEnvelope, SparseTopKParams, SyncRound, SyncStrategy,
    TrainingAttestation, TrainingModality, TrainingObjective, TrainingReceipt, TrainingRun,
    TrainingRunStatus, TrainingTaskSpec, TrainingTier,
};
