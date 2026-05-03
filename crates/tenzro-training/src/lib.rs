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
//! # Phase 1 scope
//!
//! - Modality: timeseries first (TimesFM-class 200M models).
//! - Trust tier: Open only (stake bonding; no Byzantine defense yet).
//! - Aggregation: [`AggregationRule::Mean`] only.
//! - Other rules ([`TrimmedMean`](AggregationRule::TrimmedMean),
//!   [`CoordinateMedian`](AggregationRule::CoordinateMedian),
//!   [`Krum`](AggregationRule::Krum)) are implemented and tested but not
//!   exposed via tier policy until Phase 2.

pub mod aggregation;
pub mod commitments;
pub mod error;
pub mod outer_optimizer;
pub mod runtime;

pub use aggregation::{
    aggregator_for, Aggregator, CoordinateMedianAggregator, KrumAggregator, MeanAggregator,
    TrimmedMeanAggregator,
};
pub use commitments::{compute_run_root, compute_state_root, sync_round_signing_bytes};
pub use error::{Result, TrainingError};
pub use outer_optimizer::{NesterovSgdConfig, NesterovSgdState};
pub use runtime::{FragmentBuffer, SyncerState, TrainingRuntime};

// Re-export the protocol-level types from `tenzro-types` for convenience —
// downstream crates can `use tenzro_training::TrainingTaskSpec` instead of
// `use tenzro_types::training::TrainingTaskSpec`.
pub use tenzro_types::training::{
    AggregationRule, ArchitectureSpec, FragmentQuorumStatus, OuterGradient, SyncRound,
    TrainingAttestation, TrainingModality, TrainingReceipt, TrainingRun, TrainingRunStatus,
    TrainingTaskSpec, TrainingTier,
};
