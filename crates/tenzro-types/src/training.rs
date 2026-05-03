//! Tenzro Train — decentralized, verifiable, multi-modal foundation model
//! training types.
//!
//! These types live in `tenzro-types` so every crate (RPC, storage, network,
//! token, CLI, agent kit, the Python reference trainer over JSON) can talk
//! about training tasks, outer gradients, and receipts without circular
//! dependencies.
//!
//! Architecture: the **Rust protocol layer** (this crate plus
//! `tenzro-training`) owns coordination, aggregation, settlement, and
//! verification. The **Python reference trainer** (`integrations/trainer/`,
//! PyTorch FSDP2 + Hivemind + safetensors) owns the inner training loop. See
//! [`TRAIN.md`] §7.1 for the full split.
//!
//! # Lifecycle (Phase 1)
//!
//! 1. A [`TrainingTask`] is posted on-chain. Sponsor escrows TNZO.
//! 2. A syncer is elected (VRF-weighted by stake) and posts a TEE attestation.
//! 3. Trainers enroll, stake, and receive shard assignments.
//! 4. Each round: trainers run H inner SGD steps on their shard, submit an
//!    [`OuterGradient`], the syncer aggregates K-of-M, the result is committed
//!    on-chain.
//! 5. A [`TrainingReceipt`] is sealed at finalization and may be minted as an
//!    NFT.

use crate::primitives::{Address, Hash, Signature, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Trust tier
// ---------------------------------------------------------------------------

/// Trust tier selected by the sponsor at task posting. Defines what the
/// trainer hardware must provide and how rewards/penalties scale.
///
/// Per `TRAIN.md` §3.3: training compute is TEE-optional (Open tier),
/// key custody and verification are TEE-mandatory in every tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum TrainingTier {
    /// Any GPU or CPU, no TEE attestation required for training compute.
    /// Trust comes from stake bonding, Byzantine-robust aggregation, and
    /// redundant fragment assignment. Default and cheapest.
    #[default]
    Open,
    /// Trainer posts a TEE attestation per round binding {program hash,
    /// data shard hash, model hash, DID}. Higher reward weight.
    Verified,
    /// TEE-resident training. Data is sealed to the enclave; the host OS
    /// never sees cleartext. Used for private datasets.
    Confidential,
}

impl fmt::Display for TrainingTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Open => write!(f, "open"),
            Self::Verified => write!(f, "verified"),
            Self::Confidential => write!(f, "confidential"),
        }
    }
}

impl TrainingTier {
    /// Parse a tier from a string label (case-insensitive). Falls back to
    /// `Open` for unknown labels.
    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "verified" => Self::Verified,
            "confidential" => Self::Confidential,
            _ => Self::Open,
        }
    }
}

// ---------------------------------------------------------------------------
// Modality
// ---------------------------------------------------------------------------

/// What the training task is training. Modality drives which Python
/// reference-trainer adapter handles inner loops; the protocol layer is
/// modality-agnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrainingModality {
    /// Decoder-only or encoder-decoder language models (Llama, Mistral, T5).
    Language,
    /// Foundation timeseries forecasting (TimesFM, Chronos, Moirai, TFT,
    /// N-BEATS, Mamba). Phase 1's lead modality.
    Timeseries,
    /// Vision encoders/decoders (ViT, ConvNeXt, diffusion U-Nets).
    Vision,
    /// Multimodal towers (CLIP, audio, video).
    Multimodal,
}

impl fmt::Display for TrainingModality {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Language => write!(f, "language"),
            Self::Timeseries => write!(f, "timeseries"),
            Self::Vision => write!(f, "vision"),
            Self::Multimodal => write!(f, "multimodal"),
        }
    }
}

impl TrainingModality {
    /// Parse from a string label (case-insensitive).
    pub fn from_str_lossy(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "language" | "lm" | "text" => Some(Self::Language),
            "timeseries" | "ts" | "forecast" | "forecasting" => Some(Self::Timeseries),
            "vision" | "image" | "vis" => Some(Self::Vision),
            "multimodal" | "mm" | "clip" => Some(Self::Multimodal),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Aggregation rule
// ---------------------------------------------------------------------------

/// Byzantine-robust aggregation rule the syncer applies over K accepted
/// outer gradients. Phase 1 ships only `Mean`; remaining rules light up
/// in Phase 2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AggregationRule {
    /// Plain mean. Phase 1 default. Not Byzantine-robust.
    #[default]
    Mean,
    /// Trim top/bottom α% per parameter, mean the rest.
    TrimmedMean { alpha_bps: u16 },
    /// Coordinate-wise median, robust to up to f < M/2 Byzantine learners.
    CoordinateMedian,
    /// Krum / Multi-Krum: pick gradient(s) with lowest sum-of-distances to
    /// nearest neighbors.
    Krum { f: u32 },
}

// ---------------------------------------------------------------------------
// Architecture spec
// ---------------------------------------------------------------------------

/// Compact description of the model architecture being trained. The Python
/// reference trainer uses `family` to pick an inner training loop; the Rust
/// protocol uses `param_count` and `fragment_count` to size buffers and
/// route fragment messages.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArchitectureSpec {
    /// Family name, e.g. `transformer-decoder`, `timesfm`, `chronos-t5`,
    /// `vit-b16`, `clip-vit-l14`. The Python reference trainer maps this
    /// to a concrete model definition.
    pub family: String,
    /// Total parameter count (used for bandwidth and reward sizing).
    pub param_count: u64,
    /// Modality the architecture targets.
    pub modality: TrainingModality,
    /// Number of parameter fragments. The model is partitioned into this
    /// many fragments for Decoupled DiLoCo–style aggregation.
    pub fragment_count: u32,
    /// Optional dtype hint (e.g. `fp16`, `bf16`, `fp32`). Used for
    /// per-fragment byte sizing.
    pub dtype: Option<String>,
    /// Free-form architecture metadata (hidden_size, num_layers, etc.).
    /// Opaque to the Rust protocol; consumed by the Python trainer.
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Training task spec
// ---------------------------------------------------------------------------

/// The on-chain description of a training run. Posted by the sponsor,
/// referenced by trainers, and committed verbatim into the final
/// [`TrainingReceipt`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrainingTaskSpec {
    /// Unique task ID (deterministic hash of canonicalized task fields).
    pub task_id: String,
    /// Sponsor DID (`did:tenzro:human:...` or `did:tenzro:machine:...`).
    pub sponsor_did: String,
    /// Sponsor's address for any unspent escrow refund.
    pub sponsor_address: Address,
    /// Architecture being trained.
    pub architecture: ArchitectureSpec,
    /// Trust tier required for trainer enrollment.
    pub tier: TrainingTier,
    /// Aggregation rule the syncer must apply.
    pub aggregation: AggregationRule,
    /// Number of trainers (M). Total slots.
    pub trainer_count: u32,
    /// Quorum (K). Outer gradient is accepted once K of M have submitted
    /// for the same fragment.
    pub quorum: u32,
    /// Inner SGD steps between outer gradient submissions (H).
    pub inner_steps: u32,
    /// Total outer rounds the run will execute.
    pub max_rounds: u32,
    /// Adaptive grace window τ in milliseconds. Stragglers are absorbed
    /// up to this delay; their submissions count if they land within τ.
    pub grace_window_ms: u64,
    /// Total reward pool escrowed by sponsor (TNZO, in attoTNZO).
    pub reward_pool: u128,
    /// Reference to the dataset. Format depends on tier:
    /// - Open / Verified (public): `ipfs://...`, `ar://...`, `https://...`
    /// - Verified (encrypted-at-rest): `enc:...` (key sealed to TEE)
    /// - Confidential (TEE-resident): `tee://...` (data never leaves owner)
    pub dataset_ref: String,
    /// Hash of the dataset's manifest (root of shard hash tree). Bound
    /// into the receipt for provenance.
    pub dataset_hash: Hash,
    /// Optional minimum throughput requirement (samples/sec) for trainer
    /// enrollment. Syncer enforces at enrollment.
    pub min_throughput: Option<u64>,
    /// Posting timestamp.
    pub created_at: Timestamp,
    /// Free-form metadata (eval suite, target perplexity, etc.).
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Outer gradient
// ---------------------------------------------------------------------------

/// A trainer's outer gradient submission for one fragment in one round.
///
/// The actual tensor payload is referenced by `safetensors_hash` and lives
/// off-chain (gossip topic + content-addressed object store). The Rust
/// protocol layer aggregates over `ndarray` views of the decoded payload;
/// it never holds the raw tensor in memory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OuterGradient {
    /// Task this submission is for.
    pub task_id: String,
    /// Outer round number (0-indexed).
    pub round: u32,
    /// Fragment index within the architecture (0..fragment_count).
    pub fragment: u32,
    /// Trainer DID.
    pub trainer_did: String,
    /// Address bound to the trainer's TDIP identity.
    pub trainer_address: Address,
    /// SHA-256 of the safetensors payload. Aggregator pulls the payload
    /// by this hash; if it doesn't match, the submission is rejected.
    pub safetensors_hash: Hash,
    /// Payload size in bytes (for bandwidth accounting).
    pub payload_bytes: u64,
    /// Vector clock entry: number of inner SGD steps the trainer had
    /// completed when this gradient was emitted. Decoupled DiLoCo's
    /// asynchronous learner support hinges on this.
    pub inner_step_count: u64,
    /// Submission timestamp.
    pub submitted_at: Timestamp,
    /// Trainer's signature over the canonical bytes of all fields above.
    pub signature: Signature,
    /// Optional TEE attestation (Verified and Confidential tiers).
    pub attestation: Option<TrainingAttestation>,
}

/// Per-round TEE attestation a trainer submits in Verified or Confidential
/// tiers. Binds the program hash, the data shard hash, and the trainer DID
/// so the syncer can verify the trainer ran the announced code on the
/// announced data.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrainingAttestation {
    /// TEE vendor (`intel-tdx`, `amd-sev-snp`, `aws-nitro`, `nvidia-cc`).
    pub vendor: String,
    /// Vendor-specific attestation report bytes (hex-encoded for JSON).
    pub report_hex: String,
    /// Hash of the trainer program/binary that produced the gradient.
    pub program_hash: Hash,
    /// Hash of the assigned data shard.
    pub shard_hash: Hash,
}

// ---------------------------------------------------------------------------
// Sync round
// ---------------------------------------------------------------------------

/// Status of an in-flight or completed outer round, as published by the
/// syncer. `state_root` is committed on-chain; observers can challenge it
/// with a fraud proof.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncRound {
    pub task_id: String,
    pub round: u32,
    /// Per-fragment status: which fragments have reached quorum.
    pub fragment_quorums: HashMap<u32, FragmentQuorumStatus>,
    /// Merkle root over (fragment_id, accepted_outer_gradient_hashes,
    /// post-aggregation parameter hash). Committed on-chain each round.
    pub state_root: Hash,
    /// Syncer signature over `state_root || round || task_id`.
    pub syncer_signature: Signature,
    /// When this round status was published.
    pub published_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FragmentQuorumStatus {
    /// Fragment index.
    pub fragment: u32,
    /// Number of accepted outer-gradient submissions.
    pub accepted: u32,
    /// Hashes of the accepted submissions (in trainer-DID-sorted order).
    pub accepted_hashes: Vec<Hash>,
    /// Whether this fragment reached quorum (`accepted >= K`).
    pub quorum_met: bool,
    /// Hash of the fragment's parameters AFTER aggregation + outer
    /// optimizer step.
    pub post_step_hash: Hash,
}

// ---------------------------------------------------------------------------
// Training receipt
// ---------------------------------------------------------------------------

/// On-chain finalization artifact. Mintable as an NFT via the standard NFT
/// factory at precompile 0x1006. Represents proof-of-training.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrainingReceipt {
    pub task_id: String,
    /// The full task spec, captured verbatim for provenance.
    pub task_spec: TrainingTaskSpec,
    /// Final model parameter hash (Merkle root over fragments after the
    /// last accepted outer step).
    pub final_model_hash: Hash,
    /// Syncer DID + address.
    pub syncer_did: String,
    pub syncer_address: Address,
    /// Per-trainer contribution count: number of accepted outer gradients
    /// across all rounds.
    pub trainer_contributions: HashMap<String, u32>,
    /// Per-trainer reward in attoTNZO.
    pub trainer_rewards: HashMap<String, u128>,
    /// Network commission (treasury cut) in attoTNZO.
    pub network_commission: u128,
    /// Per-round state roots. Order matches `0..=last_completed_round`.
    pub round_state_roots: Vec<Hash>,
    /// Final Merkle root over the full sequence of `round_state_roots`.
    /// This single hash anchors the entire training run.
    pub run_root: Hash,
    /// Syncer's TEE attestation chain (vendor, report hex, cert chain).
    pub syncer_attestation: TrainingAttestation,
    /// When the run finalized.
    pub finalized_at: Timestamp,
    /// Syncer signature over the canonical bytes of all fields above.
    pub syncer_signature: Signature,
}

// ---------------------------------------------------------------------------
// Run status
// ---------------------------------------------------------------------------

/// Status of a training run as held in node storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrainingRunStatus {
    /// Posted on-chain; awaiting syncer election.
    Pending,
    /// Syncer elected; awaiting trainer enrollment.
    Enrolling,
    /// At least K trainers enrolled; rounds in progress.
    Training,
    /// Final round committed; receipt sealed.
    Completed,
    /// Sponsor abandoned, syncer slashed, or unrecoverable failure.
    Failed,
    /// Cancelled by sponsor before any rounds executed.
    Cancelled,
}

impl fmt::Display for TrainingRunStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Enrolling => write!(f, "enrolling"),
            Self::Training => write!(f, "training"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

/// In-flight training run state held off-chain (in CF_TRAINING_RUNS) and
/// mirrored to chain via per-round state roots. Receipt at completion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrainingRun {
    pub task_id: String,
    pub task_spec: TrainingTaskSpec,
    pub status: TrainingRunStatus,
    pub syncer_did: Option<String>,
    pub syncer_address: Option<Address>,
    /// Enrolled trainer DIDs.
    pub trainers: Vec<String>,
    /// Most recent completed round (0 = none).
    pub current_round: u32,
    /// State roots collected so far (length == current_round).
    pub round_state_roots: Vec<Hash>,
    pub created_at: Timestamp,
    pub last_update: Timestamp,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tier_roundtrip() {
        for s in ["open", "OPEN", "Open", "garbage"] {
            assert_eq!(TrainingTier::from_str_lossy(s), TrainingTier::Open);
        }
        assert_eq!(TrainingTier::from_str_lossy("verified"), TrainingTier::Verified);
        assert_eq!(
            TrainingTier::from_str_lossy("CONFIDENTIAL"),
            TrainingTier::Confidential
        );
    }

    #[test]
    fn modality_roundtrip() {
        assert_eq!(
            TrainingModality::from_str_lossy("timeseries"),
            Some(TrainingModality::Timeseries)
        );
        assert_eq!(
            TrainingModality::from_str_lossy("ts"),
            Some(TrainingModality::Timeseries)
        );
        assert_eq!(
            TrainingModality::from_str_lossy("language"),
            Some(TrainingModality::Language)
        );
        assert_eq!(TrainingModality::from_str_lossy("nonsense"), None);
    }

    #[test]
    fn aggregation_default_is_mean() {
        assert_eq!(AggregationRule::default(), AggregationRule::Mean);
    }

    #[test]
    fn run_status_display() {
        assert_eq!(TrainingRunStatus::Pending.to_string(), "pending");
        assert_eq!(TrainingRunStatus::Training.to_string(), "training");
    }
}
