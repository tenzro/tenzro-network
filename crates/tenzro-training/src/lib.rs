//! Tenzro Train — protocol-only Rust crate for decentralized verifiable
//! foundation-model training (Decoupled DiLoCo).
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
//! See `TRAIN.md` §7.1 for the full split rationale.
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
//!   - [`AggregationRule::TrimmedMean`],
//!     [`AggregationRule::CoordinateMedian`],
//!     [`AggregationRule::Krum`] — Byzantine-robust; admitted only at
//!     [`TrainingTier::Verified`] or [`TrainingTier::Confidential`].
//!     Open-tier sybil submissions can defeat coordinate-wise medians and
//!     Krum's cluster-center heuristic, so the policy gate enforced by
//!     [`validate_aggregation_for_tier`] rejects them at task-registration
//!     time with [`TrainingError::AggregationRuleTierMismatch`].

pub mod aggregation;
pub mod commitments;
pub mod committee;
pub mod confidential;
pub mod error;
pub mod gossip;
pub mod outer_optimizer;
pub mod payload_store;
pub mod runtime;

pub use aggregation::{
    aggregator_for, Aggregator, CoordinateMedianAggregator, KrumAggregator, MeanAggregator,
    TrimmedMeanAggregator,
};
pub use commitments::{compute_run_root, compute_state_root, sync_round_signing_bytes};
pub use committee::{
    committee_seed, is_in_committee, recommended_committee_size, select_witness_committee,
    COMMITTEE_SCORE_DOMAIN_TAG, COMMITTEE_SEED_DOMAIN_TAG,
};
pub use confidential::{
    compute_manifest_hash, compute_shard_ciphertext_hash, parse_tee_dataset_ref,
    validate_confidential_enrollment, verify_manifest_binding, verify_shard_ciphertext,
    InMemorySealedShardStore, SealedManifestStore, SealedShardStore,
};
pub use error::{Result, TrainingError};
pub use gossip::{
    decode_for_topic, encode_install_sealed_manifest, encode_outer_gradient, encode_sync_round,
    TrainingGossipMessage, TRAINING_SYNCER_TOPIC, TRAINING_TOPIC,
};
pub use outer_optimizer::{NesterovSgdConfig, NesterovSgdState};
pub use payload_store::{
    compute_payload_hash, verify_payload, GradientPayloadStore, InMemoryGradientStore,
};
pub use runtime::{
    min_tier_for_rule, validate_aggregation_for_tier, FragmentBuffer, SyncerState, TrainingRuntime,
};

// Re-export the protocol-level types from `tenzro-types` for convenience —
// downstream crates can `use tenzro_training::TrainingTaskSpec` instead of
// `use tenzro_types::training::TrainingTaskSpec`.
pub use tenzro_types::training::{
    AggregationRule, ArchitectureSpec, FragmentQuorumStatus, OuterGradient,
    SealedDatasetManifest, SealedShardEnvelope, SyncRound, TrainingAttestation, TrainingModality,
    TrainingReceipt, TrainingRun, TrainingRunStatus, TrainingTaskSpec, TrainingTier,
};
