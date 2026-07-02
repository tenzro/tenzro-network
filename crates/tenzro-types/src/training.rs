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
//! [`AI.md`] §7.7.1 for the full split.
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
/// Per `AI.md` §7.3.3: training compute is TEE-optional (Open tier),
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
// Gradient quantization
// ---------------------------------------------------------------------------

/// Wire-format quantization applied to outer-gradient tensor payloads.
///
/// Streaming DiLoCo (arXiv 2501.18512) demonstrates that outer gradients
/// tolerate aggressive low-bit quantization with no convergence loss because
/// they are momentum-smoothed deltas, not raw activations. Quantization is
/// blockwise symmetric: the tensor is split into fixed-size blocks, each
/// block stores one little-endian `f32` scale followed by the packed integer
/// codes. Dequantized value = `code * scale`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum GradientQuantization {
    /// Raw little-endian `f32` values. No compression.
    #[default]
    None,
    /// 8-bit symmetric per-block: `scale = max_abs / 127`, codes are `i8`.
    /// 4x smaller than f32.
    Int8 { block_size: u32 },
    /// 4-bit symmetric per-block: `scale = max_abs / 7`, codes in `[-7, 7]`
    /// packed two per byte (low nibble first, odd tail zero-padded).
    /// ~8x smaller than f32.
    Int4 { block_size: u32 },
}

impl fmt::Display for GradientQuantization {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Int8 { block_size } => write!(f, "int8/{block_size}"),
            Self::Int4 { block_size } => write!(f, "int4/{block_size}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Sync strategy
// ---------------------------------------------------------------------------

/// How fragments are scheduled for outer synchronization each round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SyncStrategy {
    /// Every fragment syncs every round. Classic DiLoCo.
    #[default]
    Full,
    /// Streaming DiLoCo (arXiv 2501.18512): fragments are partitioned into
    /// `num_shards` shards and only the active shard
    /// (`round % num_shards`) syncs each round, overlapping communication
    /// of one shard with computation on the others. Peak bandwidth drops
    /// by ~`num_shards`x.
    Streaming { num_shards: u32 },
}

impl SyncStrategy {
    /// Which shard is active for a given round. `Full` is always shard 0
    /// of 1.
    pub fn active_shard(&self, round: u32) -> u32 {
        match self {
            Self::Full => 0,
            Self::Streaming { num_shards } => round % (*num_shards).max(1),
        }
    }

    /// Number of shards under this strategy.
    pub fn shard_count(&self) -> u32 {
        match self {
            Self::Full => 1,
            Self::Streaming { num_shards } => (*num_shards).max(1),
        }
    }

    /// Which shard a fragment belongs to, given the total fragment count.
    /// Fragments are partitioned contiguously:
    /// `shard = fragment * num_shards / fragment_count`.
    pub fn shard_of_fragment(&self, fragment: u32, fragment_count: u32) -> u32 {
        let shards = self.shard_count() as u64;
        let count = fragment_count.max(1) as u64;
        ((fragment as u64 * shards) / count) as u32
    }

    /// Whether a fragment is expected to sync in a given round.
    pub fn fragment_active(&self, fragment: u32, fragment_count: u32, round: u32) -> bool {
        self.shard_of_fragment(fragment, fragment_count) == self.active_shard(round)
    }
}

// ---------------------------------------------------------------------------
// Pipeline config
// ---------------------------------------------------------------------------

/// DiLoCoX-style (arXiv 2506.21263) pipeline-parallel trainer groups.
///
/// When set, trainers enroll as `(group_id, stage)` pairs: a group of
/// `num_stages` trainers jointly holds one model replica, each stage owning
/// the contiguous fragment slice
/// `stage = fragment * num_stages / fragment_count`. Quorum counts distinct
/// **groups** per fragment, so a whole pipeline group is one logical trainer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineConfig {
    /// Pipeline stages per trainer group (>= 2 to be meaningful; 1 is
    /// equivalent to no pipelining).
    pub num_stages: u32,
}

impl PipelineConfig {
    /// Which stage owns a fragment, mirroring
    /// [`SyncStrategy::shard_of_fragment`] partitioning.
    pub fn stage_of_fragment(&self, fragment: u32, fragment_count: u32) -> u32 {
        let stages = self.num_stages.max(1) as u64;
        let count = fragment_count.max(1) as u64;
        ((fragment as u64 * stages) / count) as u32
    }
}

/// A trainer's position inside a pipeline-parallel group. Bound at
/// enrollment when the task spec carries a [`PipelineConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineAssignment {
    /// Pipeline group this trainer belongs to. Groups are numbered
    /// `0..(trainer_count / num_stages)`.
    pub group_id: u32,
    /// Stage within the group (`0..num_stages`).
    pub stage: u32,
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
    /// Fragment sync scheduling (full every round vs. Streaming DiLoCo
    /// shard rotation).
    pub sync_strategy: SyncStrategy,
    /// Quantization trainers must apply to outer-gradient payloads. The
    /// syncer rejects submissions whose declared quantization differs.
    pub quantization: GradientQuantization,
    /// DiLoCoX one-step-delay: when `true`, the aggregate computed at round
    /// `r` is applied by trainers at round `r + 1`, overlapping the outer
    /// sync with the next inner-step window.
    pub delayed_apply: bool,
    /// Pipeline-parallel trainer groups (DiLoCoX). `None` = each trainer
    /// holds a full replica.
    pub pipeline: Option<PipelineConfig>,
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
    /// Quantization applied to the payload. Must match the task spec's
    /// `quantization` policy; the syncer dequantizes before aggregation.
    pub quantization: GradientQuantization,
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
    /// No-Endorsement-Certificate carry-forward witnesses.
    ///
    /// `None` for normal rounds. `Some(sigs)` when the witness committee
    /// could not assemble a 2f+1 quorum within `grace_window_ms` — each
    /// committee member publishes a signed "no-quorum" cert and the run
    /// advances to `round + 1` carrying forward the prior `state_root`
    /// (which is set to the previous round's state root, or `Hash::zero()`
    /// for round 0 NEC).
    pub no_quorum_witnesses: Option<Vec<Signature>>,
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
// Confidential tier — sealed-shard manifest
// ---------------------------------------------------------------------------

/// One per-trainer sealed-shard record in a [`SealedDatasetManifest`].
///
/// The sponsor (data owner) shards the dataset offline, generates a fresh
/// AES-256-GCM data key per shard, encrypts the shard with that key, and
/// publishes the encrypted shards to a content-addressed object store. The
/// data keys are then wrapped one-per-trainer using each enrolled trainer's
/// **attested enclave public key** (HPKE / ECIES / vendor sealing key — the
/// concrete construction is encoded in `wrap_alg`). The wrapped key envelope
/// is what lives on-chain alongside the manifest.
///
/// At trainer side, the enclave unwraps the data key with its sealing private
/// key (which never leaves the TEE) and decrypts the assigned shard inside
/// the enclave. The host OS never sees the data key or cleartext.
///
/// `enclave_pubkey` and `enclave_measurements` are bound into the envelope so
/// the syncer can verify at enrollment that the trainer's TEE attestation
/// matches the recipient the sponsor sealed to. A mismatch means the trainer
/// presented a different enclave than the one the sponsor wrapped to —
/// enrollment is rejected.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SealedShardEnvelope {
    /// Trainer DID this envelope is intended for. Acts as the recipient
    /// selector when the trainer fetches the manifest.
    pub trainer_did: String,
    /// Index of the shard this envelope unlocks. Trainers are typically
    /// assigned one shard per round (or a fixed shard for the run).
    pub shard_index: u32,
    /// SHA-256 of the encrypted shard bytes. Trainer pulls the shard by
    /// this hash and verifies before decrypting.
    pub shard_ciphertext_hash: Hash,
    /// Size of the encrypted shard in bytes.
    pub shard_ciphertext_bytes: u64,
    /// The encrypted data key (wrapped to `enclave_pubkey`). Opaque bytes
    /// in the format dictated by `wrap_alg`.
    pub wrapped_data_key: Vec<u8>,
    /// Key-wrap algorithm identifier. Phase 4 ships `"hpke-x25519-hkdf-sha256-aes-256-gcm"`
    /// (RFC 9180 base mode). Other identifiers reserved for vendor sealing
    /// (e.g. `"intel-tdx-sealing"`, `"sev-snp-sealing"`).
    pub wrap_alg: String,
    /// The trainer's attested enclave public key the sponsor wrapped to.
    /// Format depends on `wrap_alg`; for HPKE-X25519 this is the 32-byte
    /// X25519 pubkey. Must match the pubkey carried in the trainer's
    /// per-round [`TrainingAttestation`] for enrollment to succeed.
    pub enclave_pubkey: Vec<u8>,
    /// The trainer's attested enclave measurements (program/firmware hashes)
    /// the sponsor sealed against. Must match the trainer's TEE attestation
    /// at enrollment. Format is vendor-specific (e.g. TDX MRTD + RTMR0..3,
    /// SEV-SNP measurement, Nitro PCR set). Stored as a hex string blob so
    /// the protocol layer stays vendor-agnostic.
    pub enclave_measurements_hex: String,
    /// AES-GCM authentication tag is included in `wrapped_data_key` per
    /// HPKE Base mode; no separate field needed.
    pub created_at: Timestamp,
}

/// Per-task sealed-shard manifest. Posted by the Confidential-tier sponsor
/// alongside the task spec, persisted under `manifest:<task_id>` in
/// `CF_TRAINING_RUNS`, and referenced from `TrainingTaskSpec::dataset_ref`
/// as `tee://<sha256(manifest_canonical)>`.
///
/// The manifest's `manifest_hash` is the content-addressed handle: trainers
/// fetch the manifest by hash, the syncer verifies the hash matches what's
/// referenced in `dataset_ref`. Once enrollment closes, the manifest is
/// effectively immutable — adding a new trainer requires a new manifest
/// version and a re-attestation round.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SealedDatasetManifest {
    /// Task this manifest belongs to.
    pub task_id: String,
    /// Sponsor DID that signed the manifest.
    pub sponsor_did: String,
    /// SHA-256 over the canonical serialization of all envelopes
    /// (sorted by `(shard_index, trainer_did)`). Self-referential: not
    /// signed into the manifest itself; recomputed by readers and matched
    /// against `dataset_ref`.
    pub manifest_hash: Hash,
    /// One envelope per (trainer, shard) tuple. Order is normalized to
    /// `(shard_index, trainer_did)` ascending.
    pub envelopes: Vec<SealedShardEnvelope>,
    /// Sponsor signature over `(task_id || sponsor_did || envelopes)`
    /// canonical bytes. Verifies sponsor authorship of the manifest.
    pub sponsor_signature: Signature,
    pub created_at: Timestamp,
}

impl SealedDatasetManifest {
    /// Look up the envelope addressed to a specific trainer. Returns `None`
    /// if no envelope exists (which means the trainer is not authorized to
    /// participate at the Confidential tier for this task).
    pub fn envelope_for(&self, trainer_did: &str) -> Option<&SealedShardEnvelope> {
        self.envelopes.iter().find(|e| e.trainer_did == trainer_did)
    }
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
    /// Pipeline-group assignment per trainer DID. Empty when the task spec
    /// has no [`PipelineConfig`].
    pub pipeline_assignments: HashMap<String, PipelineAssignment>,
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

    #[test]
    fn full_strategy_activates_every_fragment_every_round() {
        let s = SyncStrategy::Full;
        for round in 0..5 {
            for fragment in 0..8 {
                assert!(s.fragment_active(fragment, 8, round));
            }
        }
    }

    #[test]
    fn streaming_strategy_rotates_shards() {
        // 8 fragments, 4 shards -> 2 contiguous fragments per shard.
        let s = SyncStrategy::Streaming { num_shards: 4 };
        assert_eq!(s.shard_of_fragment(0, 8), 0);
        assert_eq!(s.shard_of_fragment(1, 8), 0);
        assert_eq!(s.shard_of_fragment(2, 8), 1);
        assert_eq!(s.shard_of_fragment(7, 8), 3);
        // Round r activates shard r % 4.
        assert!(s.fragment_active(0, 8, 0));
        assert!(!s.fragment_active(2, 8, 0));
        assert!(s.fragment_active(2, 8, 1));
        assert!(s.fragment_active(0, 8, 4));
        // Every fragment is active exactly once per num_shards rounds.
        for fragment in 0..8 {
            let active: Vec<u32> = (0..4).filter(|r| s.fragment_active(fragment, 8, *r)).collect();
            assert_eq!(active.len(), 1, "fragment {fragment} active {active:?}");
        }
    }

    #[test]
    fn streaming_strategy_uneven_partition_covers_all_fragments() {
        // 5 fragments, 2 shards: contiguous split 0..2 -> shard 0, 3..4 -> shard 1.
        let s = SyncStrategy::Streaming { num_shards: 2 };
        let shards: Vec<u32> = (0..5).map(|f| s.shard_of_fragment(f, 5)).collect();
        assert_eq!(shards, vec![0, 0, 0, 1, 1]);
    }

    #[test]
    fn pipeline_stage_partition_matches_shard_math() {
        let p = PipelineConfig { num_stages: 2 };
        assert_eq!(p.stage_of_fragment(0, 4), 0);
        assert_eq!(p.stage_of_fragment(1, 4), 0);
        assert_eq!(p.stage_of_fragment(2, 4), 1);
        assert_eq!(p.stage_of_fragment(3, 4), 1);
    }

    #[test]
    fn quantization_display() {
        assert_eq!(GradientQuantization::None.to_string(), "none");
        assert_eq!(GradientQuantization::Int8 { block_size: 256 }.to_string(), "int8/256");
        assert_eq!(GradientQuantization::Int4 { block_size: 128 }.to_string(), "int4/128");
    }
}
