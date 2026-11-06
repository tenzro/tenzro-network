//! Typed MCP tool inputs and outputs for the model runtimes, embeddings, media generation and training.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ─── Shared: quantities, units, settlement, receipts ───

/// A whole quantity: a JSON number up to `u64::MAX`, a decimal string above it.
#[derive(Debug, Clone, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ModelsWideUint {
    Number(u64),
    Decimal(String),
}

/// Billable units by meter key (`input_tokens`, `output_tokens`, `audio_ms`, ...).
pub type ModelsUnits = BTreeMap<String, ModelsWideUint>;

/// How an inference call was settled. `status` is `settled`, `pending` or
/// `not_applicable`; `via` is `channel` or `ledger` when it was settled.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InferenceSettlementOutput {
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    /// The channel debit, for a channel settlement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<String>,
    /// Wei, decimal string, for a channel settlement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount_wei: Option<String>,
    /// The provider paid, `0x` hex.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// The `PayerSettle` transaction, for a ledger settlement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<String>,
    /// Wei debited, decimal string, for a ledger settlement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_fee: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payee_credit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pay_ref: Option<String>,
}

/// A key or signature with its scheme: `key_type` is `Ed25519` or
/// `Secp256k1`, `bytes` the raw bytes.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReceiptKeyBytes {
    pub key_type: String,
    pub bytes: Vec<u8>,
}

/// The P-256 leg of a hardware signature, hex fields.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "form", rename_all = "snake_case")]
pub enum ReceiptClassicalProof {
    Raw {
        signature: String,
    },
    WebAuthn {
        authenticator_data: String,
        client_data_json: String,
        signature: String,
    },
}

/// A hardware identity signature: the P-256 leg and, when present, the
/// ML-DSA-65 leg (hex).
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReceiptCompositeSignature {
    pub classical: ReceiptClassicalProof,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq: Option<String>,
}

/// A hardware identity key: the P-256 point and, when enrolled, the ML-DSA-65
/// key (hex).
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReceiptCompositeKey {
    pub p256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq: Option<String>,
}

/// The identity key's statement that a session key may sign for it.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReceiptSessionCertificate {
    pub session_key: ReceiptKeyBytes,
    /// Last valid millisecond since the Unix epoch.
    pub not_after_ms: u64,
    pub signature: ReceiptCompositeSignature,
}

/// A session-key signature with the certificate binding the session key.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReceiptSessionSignature {
    pub certificate: ReceiptSessionCertificate,
    pub signature: ReceiptKeyBytes,
}

/// The price card a receipt's units were charged on.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReceiptPricedOn {
    /// Digest of the registry entry carrying the card.
    pub card: String,
    pub rate_nano_usd: ModelsWideUint,
    pub charge: ModelsWideUint,
}

/// The sampling a completion was decoded with.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReceiptSampling {
    pub seed: u64,
    pub temperature: f64,
    pub top_p: f64,
    pub top_k: Option<u32>,
    pub min_p: Option<f64>,
    pub max_output_tokens: u32,
    pub keyed_sampler: bool,
}

/// Numeric precision, engine build and hardware class of a decode.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReceiptDecodeContext {
    pub precision: String,
    pub engine_version: String,
    pub hardware_class: String,
}

/// A confidential-compute attestation report. Byte fields are arrays of
/// byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReceiptAttestationReport {
    /// UUID.
    pub id: String,
    /// `IntelSGX`, `IntelTdx`, `AMDSEV`, `AmdSevSnp`, `ARMTrustZone`,
    /// `AWSNitro`, `AwsNitro`, `NvidiaGpu` or `Generic`.
    pub vendor: String,
    pub user_data: Vec<u8>,
    pub attestation_data: Vec<u8>,
    pub certificates: Vec<Vec<u8>>,
    pub timestamp: i64,
    pub metadata: BTreeMap<String, String>,
    pub quote: Vec<u8>,
    pub measurement: Vec<u8>,
    pub signature: Vec<u8>,
    pub vendor_data: Vec<u8>,
}

/// The TEE evidence a receipt carries at the tee level.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReceiptTeeEvidence {
    pub report: ReceiptAttestationReport,
}

/// A serving node's signed receipt for one inference call.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InferenceReceiptOutput {
    pub model_id: String,
    /// Hash of the catalog entry's weights.
    pub model_hash: String,
    pub engine: String,
    /// `did:tenzro:machine:...`.
    pub machine_did: String,
    pub nonce: String,
    pub input_commitment: String,
    pub output_hash: String,
    pub units: ModelsUnits,
    #[serde(default)]
    pub priced: Option<ReceiptPricedOn>,
    #[serde(default)]
    pub provenance: Vec<String>,
    pub sampling: ReceiptSampling,
    pub decode: ReceiptDecodeContext,
    pub commitment_hash: Option<String>,
    pub tee: Option<ReceiptTeeEvidence>,
    pub activation_fingerprint: Option<String>,
    pub signed_at_ms: u64,
    pub public_key: ReceiptCompositeKey,
    pub signature: ReceiptSessionSignature,
}

/// The receipt, billing and settlement fields every modality answer carries,
/// and where it was served when another provider served it.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelsTaskBilling {
    /// Null when the serving node signs no receipt.
    #[serde(default)]
    pub tenzro_receipt: Option<InferenceReceiptOutput>,
    pub units: ModelsUnits,
    /// Wei, decimal string.
    pub cost_wei: String,
    pub settlement: InferenceSettlementOutput,
    /// `network` when a provider on the network served it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    /// The serving provider's name, when a provider on the network served it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

// ─── Modality answers ───

/// A univariate forecast.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ForecastOutput {
    /// Point forecast, one value per step.
    pub point: Vec<f32>,
    /// One series per quantile level.
    #[serde(default)]
    pub quantiles: Vec<Vec<f32>>,
    #[serde(default)]
    pub quantile_levels: Vec<f32>,
    pub generation_time_ms: u64,
    #[serde(flatten)]
    pub billing: ModelsTaskBilling,
}

/// One image's embedding.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ImageEmbedOutput {
    pub embedding: Vec<f32>,
    pub dim: u64,
    pub generation_time_ms: u64,
    #[serde(flatten)]
    pub billing: ModelsTaskBilling,
}

/// One embedding per input.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TextEmbedOutput {
    pub embeddings: Vec<Vec<f32>>,
    /// Effective dimension, after any truncation.
    pub dim: u64,
    pub prompt_tokens: u32,
    pub generation_time_ms: u64,
    #[serde(flatten)]
    pub billing: ModelsTaskBilling,
}

/// A clip-level video embedding.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VideoEmbedOutput {
    pub embedding: Vec<f32>,
    pub dim: u64,
    pub frames_consumed: u32,
    /// Source clip duration, ms; 0 when unknown.
    pub video_ms: u64,
    pub generation_time_ms: u64,
    #[serde(flatten)]
    pub billing: ModelsTaskBilling,
}

/// A segmentation mask: a flat `height * width` buffer of 0 (background) and
/// 1 (foreground).
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SegmentMaskOutput {
    pub width: u32,
    pub height: u32,
    pub mask: Vec<u8>,
    /// Predicted IoU, in [0, 1].
    pub score: f32,
}

/// Masks for the prompts given.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SegmentOutput {
    pub masks: Vec<SegmentMaskOutput>,
    pub generation_time_ms: u64,
    #[serde(flatten)]
    pub billing: ModelsTaskBilling,
}

/// One text-prompted detection with its mask.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TextSegmentationOutput {
    /// `[x0, y0, x1, y1]`, image pixels.
    pub bbox: [f32; 4],
    pub score: f32,
    pub width: u32,
    pub height: u32,
    /// Flat `height * width` buffer, 0 background, 1 foreground.
    pub mask: Vec<u8>,
}

/// Detections above the score threshold.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TextSegmentOutput {
    pub segmentations: Vec<TextSegmentationOutput>,
    pub generation_time_ms: u64,
    #[serde(flatten)]
    pub billing: ModelsTaskBilling,
}

/// One detected object.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DetectionOutput {
    /// `[x0, y0, x1, y1]`, image pixels.
    pub bbox: [f32; 4],
    pub label_id: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    pub score: f32,
}

/// Detected objects.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DetectOutput {
    pub detections: Vec<DetectionOutput>,
    pub generation_time_ms: u64,
    #[serde(flatten)]
    pub billing: ModelsTaskBilling,
}

/// One timed transcript segment.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TranscriptSegmentOutput {
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_seconds: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_seconds: Option<f32>,
}

/// A transcript.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TranscribeOutput {
    pub text: String,
    #[serde(default)]
    pub segments: Vec<TranscriptSegmentOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// Audio transcribed, ms.
    pub audio_ms: u64,
    pub generation_time_ms: u64,
    #[serde(flatten)]
    pub billing: ModelsTaskBilling,
}

// ─── Modality inputs ───

/// A point prompt in image pixels.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SegmentPointPrompt {
    pub x: f32,
    pub y: f32,
    /// True for a point inside the object, false for background.
    pub is_foreground: bool,
}

/// A segmentation prompt in original-image pixels.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SegmentPromptParam {
    Point(SegmentPointPrompt),
    Box { x0: f32, y0: f32, x1: f32, y1: f32 },
    Points { points: Vec<SegmentPointPrompt> },
}

/// A normalized centre-size box, each value in [0, 1].
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TextSegmentBoxParam {
    pub cx: f32,
    pub cy: f32,
    pub w: f32,
    pub h: f32,
}

// ─── Rerank, speech, streaming transcription, training, media ───

/// One scored document.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RerankResultOutput {
    /// Position of the document in the request.
    pub index: u64,
    pub relevance_score: f32,
    /// The document as sent, when `return_documents` was set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document: Option<super::server::EmbedInputParam>,
}

/// Documents ordered best first.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RerankOutput {
    pub model_id: String,
    pub results: Vec<RerankResultOutput>,
    #[serde(flatten)]
    pub billing: ModelsTaskBilling,
}

/// One answered question.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DecisionAnswerOutput {
    /// The question's id.
    pub id: String,
    /// `choice`, `score` or `noul`.
    #[serde(rename = "type")]
    pub kind: String,
    /// Choice: the most probable key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub choice: Option<String>,
    /// Score: the expected level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub score: Option<f64>,
    /// Yes or no: the probability of yes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub noul: Option<f64>,
    /// Probability of every key (choice and score).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probabilities: Option<std::collections::BTreeMap<String, f64>>,
    /// How decided the model is, 0 to 1 (choice and score).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    /// Score: what each level means.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legend: Option<std::collections::BTreeMap<String, super::server::JsonValue>>,
}

/// What a decision call used.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DecisionUsage {
    pub questions: u64,
    pub input_tokens: u64,
}

/// Answers to typed questions, in request order.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DecideOutput {
    pub model_id: String,
    pub answers: Vec<DecisionAnswerOutput>,
    pub usage: DecisionUsage,
    #[serde(flatten)]
    pub billing: ModelsTaskBilling,
}

/// Spoken audio.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SpeakOutput {
    pub model_id: String,
    /// `wav`.
    pub format: String,
    pub audio_sha256: String,
    /// RMS level of each 20 ms window.
    pub envelope: Vec<u16>,
    pub sample_rate: u32,
    pub duration_ms: u64,
    pub frames: u64,
    pub seed: u64,
    /// Base64 16-bit PCM WAV.
    pub audio_base64: String,
    #[serde(flatten)]
    pub billing: ModelsTaskBilling,
}

/// A partial transcript of the open segment; not billed.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TranscribePartialEvent {
    pub text: String,
    pub start_ms: u64,
    pub end_ms: u64,
}

/// A committed segment with its billing and receipt.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TranscribeFinalEvent {
    /// 1 for the first committed segment.
    pub seq: u64,
    pub text: String,
    pub start_ms: u64,
    pub end_ms: u64,
    pub units: Option<ModelsUnits>,
    pub cost_wei: Option<String>,
    pub settlement: Option<InferenceSettlementOutput>,
    pub tenzro_receipt: Option<InferenceReceiptOutput>,
}

/// The stream's totals.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TranscribeDoneEvent {
    /// Segments committed.
    pub segments: u64,
    pub audio_ms: u64,
    /// Wei, decimal string.
    pub cost_wei: String,
}

/// One event of a streamed transcription.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum TranscribeStreamEvent {
    Partial(TranscribePartialEvent),
    Final(TranscribeFinalEvent),
    Done(TranscribeDoneEvent),
    Error { message: String },
}

/// Every event of a streamed transcription, in order.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TranscribeStreamOutput {
    pub events: Vec<TranscribeStreamEvent>,
}

/// A reading signed by the machine that produced it.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrainingSensorData {
    pub device_did: String,
    /// SHA-256 of the payload, hex.
    pub payload_digest: String,
    pub measured_at_ms: u64,
    pub signature: ReceiptCompositeSignature,
}

/// A `sensor_data` evidence item.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrainingAttestation {
    pub sensor_data: TrainingSensorData,
}

/// One LoRA training round. Hashes and roots are hex.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrainingRoundOutput {
    pub model_id: String,
    pub base_sha256: String,
    pub records_sha256: String,
    pub data_root: String,
    pub recipe_hash: String,
    pub kernel_class: String,
    pub first_step: u64,
    pub steps: u64,
    pub start_root: String,
    pub end_root: String,
    pub log_head: String,
    pub commitment: String,
    /// Loss of each step.
    pub losses: Vec<f64>,
    pub adapter_sha256: String,
    pub adapter_uri: String,
    pub state_uri: String,
    pub log_uri: String,
    pub result_digest: String,
    pub attestation: TrainingAttestation,
    #[serde(flatten)]
    pub billing: ModelsTaskBilling,
}

/// A LoRA recipe.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct LoraRecipeParam {
    pub rank: u32,
    pub alpha: f32,
    /// Weight names the adapter targets, e.g. `attn_q.weight`.
    pub targets: Vec<String>,
    pub lr: f32,
    pub beta1: f32,
    pub beta2: f32,
    pub eps: f32,
    pub weight_decay: f32,
    pub seq_len: u32,
    pub batch: u32,
    pub grad_clip: f32,
}

/// A training record; the loss counts the completion's tokens.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrainingRecordParam {
    pub prompt: String,
    pub completion: String,
}

/// Where a round resumes: the previous round's state.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrainingStartParam {
    pub state_uri: String,
    /// 32 bytes, hex.
    pub start_root: String,
    pub steps_taken: u64,
}

/// A value in a render's `metadata`: a whole number, a number, text, or rows
/// of numbers.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum MediaMetadataValue {
    Integer(u64),
    Number(f64),
    Text(String),
    Rows(Vec<Vec<f64>>),
}

/// One input a render conditions on.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MediaGenInputParam {
    /// `first_frame`, `last_frame`, `reference`, `edit_source`, `mask` or
    /// `observation`.
    pub role: String,
    /// SHA-256 of the input bytes, as 32 byte values.
    pub hash: [u8; 32],
}

/// Sampling parameters of a render.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MediaGenParamsInput {
    pub prompt: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negative_prompt: Option<String>,
    pub width: u32,
    pub height: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub num_frames: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fps: Option<u32>,
    pub steps: u32,
    pub guidance_scale: f32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voxel_resolution: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio_duration_secs: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action_chunks: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_hold_secs: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inputs: Vec<MediaGenInputParam>,
    /// Model-specific settings, e.g. `actions` rows for a world model,
    /// `view_point` for an action policy, `bpm` for audio.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, MediaMetadataValue>,
}

/// What a render looks and sounds like, coarsely.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MediaFingerprintOutput {
    pub luma: Vec<u8>,
    pub envelope: Vec<u16>,
    pub geometry: Vec<u16>,
}

/// A rendered output, fetched by `output_blake3`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MediaRenderOutput {
    pub mime: String,
    pub output_sha256: String,
    pub output_bytes: u64,
    /// Tolerance a re-render must agree within, basis points.
    pub tolerance_bps: u32,
    pub fingerprint: MediaFingerprintOutput,
    /// BLAKE3 hash of the output in the content store, hex.
    pub output_blake3: String,
    #[serde(flatten)]
    pub billing: ModelsTaskBilling,
}

// ─── Inference commitments and challenges ───

/// One top-k logit of a committed step.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CommitmentTopKEntry {
    pub token_id: u32,
    pub logit: f32,
}

/// One decoded step: the token emitted and the top-k logits.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CommitmentStepRecord {
    pub token_id: u32,
    pub top_k: Vec<CommitmentTopKEntry>,
}

/// A top-k logit commitment over a decode.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InferenceCommitmentRecord {
    pub k: u8,
    pub prompt_tokens: u32,
    pub steps: Vec<CommitmentStepRecord>,
}

/// A stored inference commitment.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InferenceCommitmentOutput {
    pub commitment_hash: String,
    pub model_id: String,
    /// `0x` hex of the provider's announcement key.
    pub provider: String,
    /// Unix seconds.
    pub created_at: u64,
    pub k: u8,
    pub prompt_tokens: u32,
    /// Number of committed steps.
    pub steps: u64,
    pub commitment: InferenceCommitmentRecord,
}

/// Whether the emitted tokens follow from the committed logits.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DecodeCheckOutput {
    /// `greedy`, `keyed` or `unsupported`.
    pub mode: String,
    pub steps: u64,
    pub consistent: u64,
    pub inconsistent: u64,
    pub unverifiable: u64,
    pub first_inconsistent: Option<u64>,
    /// Null when the sampler cannot be checked from logits.
    pub pass: Option<bool>,
}

/// The result of re-executing a stored commitment.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CommitmentVerificationOutput {
    pub commitment_hash: String,
    pub model_id: String,
    pub provider: String,
    pub pass: bool,
    pub steps_total: u64,
    pub steps_passed: u64,
    pub failing_steps: Vec<u64>,
    /// Present when a receipt made the decode checkable.
    pub decode: Option<DecodeCheckOutput>,
}

/// A stake-weighted committee seat.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChallengeSeatOutput {
    /// `0x` hex registry address.
    pub voter: String,
    pub stake: u128,
    /// Hex Ed25519 consensus key.
    pub consensus_pubkey: String,
}

/// A committed, and once revealed, committee vote.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChallengeVoteOutput {
    pub voter: String,
    pub commit_hash: String,
    pub commit_signature: String,
    /// True upholds the challenge.
    pub verdict: Option<bool>,
    pub salt: Option<String>,
    pub reveal_signature: Option<String>,
    pub committed_at: u64,
    pub revealed_at: Option<u64>,
}

/// The tally recorded at finalize. Stakes are decimal strings.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChallengeTallyOutput {
    pub uphold_stake: String,
    pub dismiss_stake: String,
    pub quorum_threshold: String,
    pub total_committee_stake: String,
    pub votes_committed: u64,
    pub closed_without_quorum: bool,
}

/// A dispute over one inference commitment.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InferenceChallengeOutput {
    pub challenge_id: String,
    pub commitment_hash: String,
    pub model_id: String,
    pub provider: String,
    pub challenger: String,
    pub reason: String,
    /// `voting_commit`, `voting_reveal`, `upheld` or `dismissed`.
    pub status: String,
    pub chain_entropy: String,
    pub committee: Vec<ChallengeSeatOutput>,
    pub total_committee_stake: u128,
    pub votes: Vec<ChallengeVoteOutput>,
    /// Unix seconds.
    pub filed_at: u64,
    pub commit_deadline: u64,
    pub reveal_deadline: u64,
    pub resolved_at: Option<u64>,
    pub verification: Option<ChallengeTallyOutput>,
    /// On finalize: whether the provider's reputation was decremented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reputation_penalized: Option<bool>,
}

/// Inference challenges, newest first.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InferenceChallengesOutput {
    pub count: u64,
    pub challenges: Vec<InferenceChallengeOutput>,
}

// ─── Registry, price cards and quotes ───

/// The price of one meter key, per `10^per_exp` units.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RateLine {
    pub price: ModelsWideUint,
    #[serde(default)]
    pub per_exp: u8,
}

/// A rate card: prices by unit or `unit@tier`, in billionths of a dollar
/// (`nano_usd`) or TNZO base units (`wei`).
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelsRateCard {
    /// `nano_usd` or `wei`.
    #[serde(default = "default_denom")]
    pub denom: String,
    #[serde(default)]
    pub lines: BTreeMap<String, RateLine>,
    #[serde(default = "zero_wide")]
    pub min_charge: ModelsWideUint,
}

fn default_denom() -> String {
    "nano_usd".to_string()
}

fn zero_wide() -> ModelsWideUint {
    ModelsWideUint::Number(0)
}

/// An entry of the generic registry.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RegistryEntryOutput {
    pub id: String,
    pub kind: String,
    /// Owner address, hex.
    pub owner: String,
    pub version: u64,
    /// SHA-256 of the harness module, hex.
    pub anchor: String,
    /// The entry's data, hex.
    pub data: String,
    pub digest: String,
    pub put_at_ms: i64,
    pub retired_at_ms: Option<i64>,
    /// Whether the entry stands now.
    pub standing: bool,
}

/// A page of one kind of registry entry; `next` is the id to continue after.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RegistryPageOutput {
    pub kind: String,
    pub entries: Vec<RegistryEntryOutput>,
    pub next: Option<String>,
}

/// A published price card for a model.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PriceCardBody {
    pub model_id: String,
    /// Hash of the weights the card prices.
    pub model_hash: String,
    pub rates: ModelsRateCard,
}

/// A provider's price card with its registry entry.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PriceCardOutput {
    #[serde(flatten)]
    pub entry: RegistryEntryOutput,
    /// Null when the entry's data does not read as a card.
    pub card: Option<PriceCardBody>,
}

/// The live load of one served model.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OfferLoadOutput {
    pub model_id: String,
    /// `cold`, `warming`, `warm` or `evicting`.
    pub state: String,
    pub in_flight: u32,
    pub max_concurrent: u32,
    pub queue_depth: u32,
    pub warm_eta_ms: Option<u64>,
}

/// One provider's price for the request.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InferenceOfferOutput {
    /// `local` or `network`.
    pub source: String,
    pub endpoint_id: String,
    pub provider_address: Option<String>,
    pub card: ModelsRateCard,
    /// Wei before the verification surcharge, decimal string; null when the
    /// card cannot price the units.
    pub base_wei: Option<String>,
    pub price_wei: Option<String>,
    pub region: Option<String>,
    pub load: Option<OfferLoadOutput>,
}

/// Offers for one request, cheapest first.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InferenceQuoteOutput {
    pub model: String,
    pub verification: String,
    pub surcharge_bps: u64,
    pub offers: Vec<InferenceOfferOutput>,
}

/// This node's price cards.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProviderPricingOutput {
    pub default: ModelsRateCard,
    #[serde(default)]
    pub models: BTreeMap<String, ModelsRateCard>,
}

// ─── Model stacks ───

/// A stack member and whether it is serving or pending.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StackMemberOutput {
    pub id: String,
    /// `serving` or `pending`.
    pub state: String,
}

/// The stack serving now.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ActiveStackOutput {
    pub stack: String,
    pub timezone: String,
    /// RFC 3339.
    pub until: Option<String>,
    pub resident_ceiling_gb: u32,
    pub models: Vec<StackMemberOutput>,
}

/// The stack that runs next.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct NextStackOutput {
    pub stack: String,
    pub timezone: String,
    /// RFC 3339.
    pub starts_at: String,
    pub resident_ceiling_gb: u32,
    pub models: Vec<StackMemberOutput>,
}

/// A configured stack.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct StackWindowOutput {
    pub stack: String,
    pub timezone: String,
    pub start_hour: u8,
    pub end_hour: u8,
    /// Monday first.
    pub days_of_week: [bool; 7],
    pub resident_ceiling_gb: u32,
    pub models: Vec<String>,
}

/// This node's model stacks.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelStacksOutput {
    pub active: Option<ActiveStackOutput>,
    pub next: Option<NextStackOutput>,
    pub stacks: Vec<StackWindowOutput>,
    /// RFC 3339.
    pub node_time: String,
}

// ─── Model listings ───

/// How a resource may be used.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ModelsResourceAccess {
    Public {
        #[serde(default = "zero_wide")]
        price_per_request: ModelsWideUint,
    },
    Gated,
    Private,
}

/// A model this node holds.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HeldModelOutput {
    pub model_id: String,
    /// `chat`, `vision`, `embedding`, `forecast`, `segmentation`,
    /// `text-segmentation`, `detection`, `audio`, `video` or `media`.
    #[serde(rename = "type")]
    pub model_type: String,
    pub engine: Option<String>,
    pub visibility: String,
    /// `model` or `node`.
    pub visibility_source: String,
    pub access: ModelsResourceAccess,
    pub loaded: bool,
    pub serving: bool,
}

/// The models this node holds.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HeldModelsOutput {
    pub models: Vec<HeldModelOutput>,
}

/// A serving model's request load.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ServingLoadOutput {
    pub active_requests: u32,
    pub max_concurrent: u32,
    pub utilization_percent: u8,
    pub load_level: String,
}

/// A language model in the listing: a catalog entry, or a model only a
/// network provider announces (with `modality`, `provider_id`, `endpoint_id`).
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelListingOutput {
    pub id: String,
    pub name: String,
    pub description: String,
    pub parameters: String,
    pub context_length: u32,
    pub downloaded: bool,
    pub download_status: String,
    pub download_progress: f64,
    pub serving: bool,
    /// `local`, `network` or `downloadable`.
    pub availability: String,
    pub pricing: ModelsRateCard,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quantization: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_ram_gb: Option<u32>,
    /// The licence's name, when the catalog states one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hf_repo: Option<String>,
    /// Weights warm in this process.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub loaded: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load: Option<ServingLoadOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub modality: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<String>,
}

/// The language-model listing, or with `loaded`, every model this node holds.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ListModelsOutput {
    Held(HeldModelsOutput),
    Listing(Vec<ModelListingOutput>),
}

/// A discovered model.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DiscoveredModelOutput {
    pub model_id: String,
    pub name: String,
    pub description: String,
    /// The model's architecture.
    pub modality: String,
    pub serving: bool,
    pub served_here: bool,
    /// Null for a catalog-only entry.
    pub card: Option<ModelsRateCard>,
    pub context_window: u32,
    /// Null when nobody serves it.
    pub provider: Option<String>,
    pub endpoint_id: Option<String>,
}

/// Discovered models.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DiscoveredModelsOutput {
    pub models: Vec<DiscoveredModelOutput>,
    pub total: u64,
}

/// A model service endpoint.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelEndpointOutput {
    pub instance_id: String,
    pub model_id: String,
    pub model_name: String,
    pub provider_name: String,
    pub location: String,
    pub mcp_endpoint: String,
    pub iroh_endpoint_id: String,
    pub status: String,
    pub parameters: String,
    pub pricing: ModelsRateCard,
    pub created_at: u64,
    /// Verification levels offered: `none`, `receipt`, `optimistic`, `tee`.
    pub verification: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load: Option<ServingLoadOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepts_media: Option<bool>,
}

/// A model served now on this node.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ServeModelOutput {
    pub success: bool,
    pub model_id: String,
    pub instance_id: String,
    /// `serving` or `already_serving`.
    pub status: String,
    /// `public`, `gated` or `private`.
    pub visibility: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent: Option<u32>,
    /// Drafter status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<super::server::LoadProvenanceOutput>,
}

// ─── Provider stats ───

/// What a role stake is declared to cover.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ProviderStakeCapacity {
    None,
    /// Accelerator classes: `integrated`, `consumer`, `workstation`, `datacentre`.
    Accelerators(Vec<String>),
    Terabytes(u32),
    Domain(String),
    BridgeSigner {
        address: [u8; 20],
        rpc_provider: String,
        /// Hex.
        proof: String,
        /// ML-DSA-65 verifying key, hex.
        pq_public_key: String,
        /// ML-DSA-65 proof, hex.
        pq_proof: String,
    },
}

/// An account's stake in one role. Amounts are wei, decimal strings.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProviderRoleStakeOutput {
    pub role: String,
    pub bonded: String,
    pub required: String,
    pub entry_required: String,
    pub capacity: ProviderStakeCapacity,
    pub unbonding: String,
    pub release_at_ms: i64,
    pub endpoint: Option<String>,
    /// The SLA subject, for a role that owes one.
    pub sla_subject: Option<String>,
}

/// A provider's served models, inference counts, stake and earnings.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProviderStatsOutput {
    pub address: String,
    pub total_requests: u64,
    pub successful: u64,
    pub failed: u64,
    pub avg_latency_ms: u64,
    pub p95_latency_ms: Option<u64>,
    pub uptime_percentage: f64,
    pub reputation: Option<u64>,
    pub inference_count: u64,
    pub total_input_tokens: u128,
    pub total_output_tokens: u128,
    pub measured_tokens_per_sec: Option<f64>,
    /// Wei, decimal string.
    pub total_revenue_wei: String,
    pub last_inference_ms: Option<i64>,
    pub max_concurrent: u32,
    pub current_active: u32,
    pub advertised_requests_per_second: u32,
    pub served_models: u64,
    pub role_stakes: Vec<ProviderRoleStakeOutput>,
    /// `Active` or `Idle`.
    pub utilization: String,
}

// ─── Routing feedback ───

/// A reported routing outcome.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RouteOutcomeOutput {
    /// False when the node has no difficulty index and discarded it.
    pub retained: bool,
    pub model_id: String,
    pub cluster: u64,
    /// `resolved`, `escalated` or `failed`.
    pub outcome: String,
}

/// Prompts that landed in one cluster.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DifficultyClusterOutput {
    pub cluster: u64,
    pub prompts: u64,
}

/// One model's outcomes in one cluster.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DifficultyModelClusterOutput {
    pub cluster: u64,
    pub resolved: u64,
    pub escalated: u64,
    pub failed: u64,
    pub error_rate: f32,
}

/// The node's difficulty index.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RouteDifficultyStatsOutput {
    pub enabled: bool,
    pub cluster_count: u64,
    pub clusters: Vec<DifficultyClusterOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_dim: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub split_threshold: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_clusters: Option<Vec<DifficultyModelClusterOutput>>,
}

// ─── Catalog specs ───

use super::server::{
    AudioCatalogRow, DetectionCatalogRow, ForecastCatalogRow, MoeShapeOutput,
    SegmentationCatalogRow, TextSegmentationCatalogRow, VideoCatalogRow, VisionCatalogRow,
};

/// The licence fields a catalog listing adds to each row, when the signed
/// catalog states a licence for it.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CatalogLicenceFields {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_id: Option<String>,
    /// permissive, attribution, commercial_custom or non_commercial.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_tier: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_conditions: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paid_serving: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gated: Option<bool>,
}

/// A vision projector file.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MmprojSpecOutput {
    pub filename: String,
}

/// How pictures and video are cut into patches for a vision-language model.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct VisionPreprocessOutput {
    pub patch_size: u32,
    pub merge_size: u32,
    pub temporal_patch_size: u32,
    pub image_mean: [f32; 3],
    pub image_std: [f32; 3],
    pub image_min_pixels: u64,
    pub image_max_pixels: u64,
    pub video_frames: u32,
    pub video_sample_fps: f64,
    pub video_frame_round_factor: u32,
    pub video_frame_round_min_pixels: u64,
    pub video_frame_min_pixels: u64,
    pub video_frame_max_pixels: u64,
    pub video_total_pixels: u64,
}

/// Default sampling a model is served with.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ServingProfileOutput {
    pub temperature: f32,
    pub top_p: f32,
    pub top_k: u32,
    pub min_p: f32,
    pub presence_penalty: f32,
    pub jinja_required: bool,
    pub reasoning_default: bool,
}

/// Whether and how a model thinks before answering.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReasoningPolicyOutput {
    pub supports_thinking: bool,
    /// `auto`, `always` or `never`.
    pub default_mode: String,
    pub thinking_safe_min_b: f32,
    pub thinking_min_budget_tokens: u32,
}

/// A correction to a model's chat template.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case", tag = "kind", content = "spec")]
pub enum TemplateFixOutput {
    None,
    Vendored { filename: String },
    ForcePureContent,
}

/// A GGUF language model or reranker.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct GgufCatalogSpec {
    pub id: String,
    pub name: String,
    pub family: String,
    pub hf_repo: String,
    pub hf_filename: String,
    pub parameters: String,
    pub architecture: String,
    pub context_length: u32,
    pub quantization: String,
    pub size_bytes: u64,
    pub min_ram_gb: u32,
    pub description: String,
    pub drafter_id: Option<String>,
    /// `none`, `generic`, `draftmtp` or `draftdflash`.
    #[serde(default)]
    pub mtp_kind: String,
    #[serde(default)]
    pub mtp_default_draft_n: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moe: Option<MoeShapeOutput>,
    pub promotable: bool,
    pub serving: ServingProfileOutput,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mmproj: Option<MmprojSpecOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vision_input: Option<VisionPreprocessOutput>,
    pub reasoning: ReasoningPolicyOutput,
    pub template_fix: TemplateFixOutput,
    #[serde(default)]
    pub download_filename: String,
}

/// How an embedder phrases queries and documents.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub enum EmbeddingTemplateOutput {
    None,
    InstructQuery {
        default_task: String,
    },
    GemmaTask {
        default_task: String,
    },
    NomicPrefix,
    QueryPassagePrefix,
    ChatInstruct {
        default_task: String,
        document_task: String,
    },
}

/// An ONNX text encoder.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OnnxTextEmbeddingSpec {
    pub id: String,
    pub name: String,
    pub family: String,
    pub hf_repo: String,
    pub hf_filename: String,
    #[serde(default)]
    pub external_data_filenames: Vec<String>,
    pub tokenizer_filename: String,
    pub max_sequence_length: u32,
    pub embedding_dim: u32,
    pub matryoshka_dims: Vec<u32>,
    pub supports_fp16: bool,
    pub size_bytes: u64,
    pub min_ram_gb: u32,
    pub description: String,
    pub embedding_template: EmbeddingTemplateOutput,
}

/// A pooled embedder on the Praecise engine.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct PooledEmbedSpec {
    pub id: String,
    pub name: String,
    pub family: String,
    pub description: String,
    pub hf_repo: String,
    pub hf_filename: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mmproj: Option<MmprojSpecOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vision_input: Option<VisionPreprocessOutput>,
    pub quantization: String,
    pub max_sequence_length: u32,
    pub embedding_dim: u32,
    #[serde(default)]
    pub matryoshka_dims: Vec<u32>,
    pub embedding_template: EmbeddingTemplateOutput,
    pub size_bytes: u64,
    pub min_ram_gb: u32,
}

/// A text-to-speech model.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TtsCatalogSpec {
    pub id: String,
    pub name: String,
    pub family: String,
    pub hf_repo: String,
    pub hf_filename: String,
    pub mmproj_filename: String,
    pub size_bytes: u64,
    pub min_ram_gb: u32,
    pub sample_rate: u32,
    pub languages: Vec<String>,
    pub supports_voice_cloning: bool,
    pub description: String,
}

/// A speech-in, speech-out model.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OmniCatalogSpec {
    pub id: String,
    pub name: String,
    pub family: String,
    pub hf_repo: String,
    pub hf_filename: String,
    pub mmproj_filename: String,
    pub talker_filename: String,
    pub talker_mmproj_filename: String,
    pub size_bytes: u64,
    pub min_ram_gb: u32,
    pub sample_rate: u32,
    pub voices: Vec<String>,
    pub languages: Vec<String>,
    pub description: String,
}

/// What an action policy observes and emits.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ActionPolicySpecOutput {
    pub embodiment: String,
    pub cameras: u32,
    pub state_dim: u32,
    pub action_dim: u32,
    pub chunk_len: u32,
    pub control_hz: u32,
}

/// A denoising schedule split across two experts.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MediaGenExpertPairOutput {
    pub high_noise_component: String,
    pub low_noise_component: String,
    pub boundary_ratio: f32,
    pub min_vram_gb_per_expert: u32,
}

/// A generative-media model.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MediaGenCatalogSpec {
    pub id: String,
    pub name: String,
    pub family: String,
    pub hf_repo: String,
    /// `native` or `planned`.
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub engine_rev: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_voxel_resolution: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<ActionPolicySpecOutput>,
    pub pipeline_class: String,
    /// `text2image`, `image2image`, `text2video`, `image2video`,
    /// `text2audio`, `image23d`, `action_policy` or `world_model`.
    pub kinds: Vec<String>,
    pub default_width: u32,
    pub default_height: u32,
    pub max_resolution: u32,
    pub default_steps: u32,
    pub default_guidance_scale: f32,
    pub default_num_frames: Option<u32>,
    pub default_fps: Option<u32>,
    pub parameters: String,
    pub size_bytes: u64,
    pub min_vram_gb: u32,
    #[serde(default)]
    pub expert_pair: Option<MediaGenExpertPairOutput>,
    #[serde(default)]
    pub gguf_repo: Option<String>,
    #[serde(default)]
    pub gguf_file: Option<String>,
    #[serde(default)]
    pub transformer_class: Option<String>,
    #[serde(default)]
    pub config_repo: Option<String>,
    #[serde(default)]
    pub distilled: bool,
    #[serde(default)]
    pub latent_upsampler: Option<String>,
    #[serde(default)]
    pub load_int8: bool,
    pub description: String,
}

// ─── Catalog listings ───

/// A reranker in the catalog.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct RerankCatalogRow {
    #[serde(flatten)]
    pub spec: GgufCatalogSpec,
    #[serde(flatten)]
    pub licence: CatalogLicenceFields,
}

/// A decision model in the catalog.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct DecisionCatalogRow {
    #[serde(flatten)]
    pub spec: GgufCatalogSpec,
    #[serde(flatten)]
    pub licence: CatalogLicenceFields,
}

/// An embedding model in the catalog: an ONNX text encoder
/// (`engine: onnx-text-embedding`) or a pooled embedder (`engine: embed`).
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum TextEmbeddingCatalogRow {
    Onnx {
        #[serde(flatten)]
        spec: OnnxTextEmbeddingSpec,
        engine: String,
        #[serde(flatten)]
        licence: CatalogLicenceFields,
    },
    Pooled {
        #[serde(flatten)]
        spec: PooledEmbedSpec,
        engine: String,
        #[serde(flatten)]
        licence: CatalogLicenceFields,
    },
}

/// A generative-media model in the catalog.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MediaGenCatalogRow {
    #[serde(flatten)]
    pub spec: MediaGenCatalogSpec,
    #[serde(flatten)]
    pub licence: CatalogLicenceFields,
}

/// The generative-media catalog.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MediaGenCatalogOutput {
    pub count: u64,
    pub models: Vec<MediaGenCatalogRow>,
}

/// An embedding model loaded on this node.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TextEmbeddingLoadedOutput {
    pub model_id: String,
    pub bundle_dir: String,
    pub loaded: bool,
    pub provenance: super::server::LoadProvenanceOutput,
    pub embedding_dim: u64,
    pub max_sequence_length: u64,
    /// What it embeds: `text`, and `image` and `video` for a vision-language
    /// embedder.
    pub inputs: Vec<String>,
}

// ─── Signed catalog ───

/// A model's engine family and its engine-specific entry.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "engine", content = "spec", rename_all = "kebab-case")]
pub enum CatalogModelSpec {
    Gguf(GgufCatalogSpec),
    Rerank(GgufCatalogSpec),
    Decision(GgufCatalogSpec),
    OnnxVision(VisionCatalogRow),
    OnnxForecast(ForecastCatalogRow),
    OnnxTextEmbedding(OnnxTextEmbeddingSpec),
    Embed(PooledEmbedSpec),
    OnnxSegmentation(SegmentationCatalogRow),
    OnnxTextSegmentation(TextSegmentationCatalogRow),
    OnnxDetection(DetectionCatalogRow),
    OnnxAudio(AudioCatalogRow),
    Tts(TtsCatalogSpec),
    Omni(OmniCatalogSpec),
    OnnxVideo(VideoCatalogRow),
    MediaGen(MediaGenCatalogSpec),
}

/// The licence of one component of a model.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ComponentLicenceOutput {
    pub covers: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub tier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<String>,
}

/// A model's licence.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CatalogLicenceOutput {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// permissive, attribution, commercial_custom or non_commercial.
    pub tier: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conditions: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub components: Vec<ComponentLicenceOutput>,
}

/// A repository at a revision.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SourceCheckpointOutput {
    pub repo: String,
    pub revision: String,
}

/// Where a component's bytes come from: a Hub revision, or a blob the
/// network built from a source checkpoint.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ComponentSourceOutput {
    Network {
        blake3: String,
        built_from: SourceCheckpointOutput,
        recipe: String,
    },
    Hub {
        revision: String,
    },
}

/// One file a catalog entry downloads.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CatalogComponentOutput {
    pub repo: String,
    pub path: String,
    #[serde(flatten)]
    pub source: ComponentSourceOutput,
    pub size: u64,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
}

/// Parts of another entry this one needs.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EntryDependencyOutput {
    pub entry: String,
    pub parts: Vec<String>,
}

/// A signed catalog entry, with the units a call to it is billed on.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CatalogEntryRecord {
    pub model: CatalogModelSpec,
    pub licence: CatalogLicenceOutput,
    pub gated: bool,
    pub components: Vec<CatalogComponentOutput>,
    pub capabilities: Vec<String>,
    pub capability_priors: BTreeMap<String, u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moe_source: Option<SourceCheckpointOutput>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<EntryDependencyOutput>,
    pub billed_on: Vec<String>,
}

/// A published model this node left out, and why.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CatalogRefusedOutput {
    pub model: String,
    pub publishers: Vec<String>,
    pub reason: String,
}

/// How this node's catalog was assembled.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CatalogStatusOutput {
    pub named_publishers: Vec<String>,
    pub publishers: Vec<String>,
    pub entries: u64,
    pub refused: Vec<CatalogRefusedOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// The catalog this node serves.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CatalogListOutput {
    pub status: CatalogStatusOutput,
    pub count: u64,
    pub entries: Vec<CatalogEntryRecord>,
}

/// One model's catalog entry on this node.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct CatalogEntryOutput {
    pub model: String,
    pub served: bool,
    pub publishers: Vec<String>,
    pub entry: CatalogEntryRecord,
}

// ─── Engine releases ───

/// One platform's binary.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ReleaseArtifactOutput {
    /// `<arch>-<os>`, optionally with an accelerator.
    pub platform: String,
    pub size: u64,
    pub sha256: String,
    pub blake3: String,
}

/// A P-256 public key as a JWK.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct P256JwkOutput {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
}

/// A hardware-key or passkey proof over a trust document.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct TrustProofOutput {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub cryptosuite: String,
    #[serde(rename = "verificationMethod")]
    pub verification_method: String,
    #[serde(rename = "proofPurpose")]
    pub proof_purpose: String,
    /// RFC 3339.
    pub created: String,
    #[serde(rename = "publicKeyJwk")]
    pub public_key_jwk: P256JwkOutput,
    /// Multibase `r || s` signature.
    #[serde(rename = "proofValue")]
    pub proof_value: String,
    /// The WebAuthn relying party, for a passkey signer.
    #[serde(rename = "rpId", default, skip_serializing_if = "Option::is_none")]
    pub rp_id: Option<String>,
    #[serde(
        rename = "authenticatorData",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub authenticator_data: Option<String>,
    #[serde(
        rename = "clientDataJSON",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub client_data_json: Option<String>,
}

/// A signed engine release record. Unknown keys are refused rather than
/// dropped, since dropping one would break the record's signature.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EngineReleaseRecord {
    /// `["TenzroEngineRelease"]`.
    #[serde(rename = "type")]
    pub record_type: Vec<String>,
    pub publisher: String,
    pub version: String,
    pub artifacts: Vec<ReleaseArtifactOutput>,
    pub proof: TrustProofOutput,
}

/// An engine release.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EngineReleaseOutput {
    pub version: String,
    pub publisher: String,
    /// Newer than the running build.
    pub newer: bool,
    pub artifacts: Vec<ReleaseArtifactOutput>,
    pub record: EngineReleaseRecord,
}

/// The engine releases this node's operator trusts.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct EngineReleasesOutput {
    /// The running build's version.
    pub running: String,
    pub platform: String,
    pub publishers: Vec<String>,
    /// The newest version newer than the running build.
    pub available: Option<String>,
    pub releases: Vec<EngineReleaseOutput>,
    pub note: Option<String>,
}

// ─── Model provenance ───

/// One file of a model manifest. Hashes are hex.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ManifestFileOutput {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    pub blake3: String,
}

/// A content-addressed model manifest.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelManifestOutput {
    /// `["TenzroModelManifest"]`.
    #[serde(rename = "type")]
    pub manifest_type: Vec<String>,
    pub name: String,
    pub files: Vec<ManifestFileOutput>,
    /// BLAKE3 Merkle root, hex.
    pub root: String,
}

/// Proof that one file is in a manifest.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct InclusionProofOutput {
    pub index: u64,
    pub leaf_count: u64,
    /// Hex sibling hashes, bottom first.
    pub siblings: Vec<String>,
}

/// One file's entry and its inclusion proof.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ManifestInclusionOutput {
    pub entry: ManifestFileOutput,
    pub proof: InclusionProofOutput,
}

/// The observers and origin locators that agree with one file.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct FileSupportOutput {
    pub observers: Vec<String>,
    pub origins: Vec<String>,
}

/// A signed observation that contradicts a manifest.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProvenanceConflictOutput {
    pub observer: String,
    pub locator: String,
    pub attestation: String,
    pub paths: Vec<String>,
}

/// How well a manifest is corroborated.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ProvenanceStatusOutput {
    pub root: String,
    pub files: BTreeMap<String, FileSupportOutput>,
    pub conflicts: Vec<ProvenanceConflictOutput>,
    pub creator_signed: bool,
}

/// One origin observation of a manifest.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct OriginObservationOutput {
    pub digest: String,
    pub observer: String,
    /// `creator`, `huggingface`, `mirror` or `storage`.
    pub kind: String,
    pub locator: String,
    /// RFC 3339.
    #[serde(rename = "observedAt")]
    pub observed_at: String,
}

/// A manifest of the model, with its origins.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelProvenanceEntry {
    /// The named file's entry and proof, when a file was asked for.
    pub inclusion: Option<ManifestInclusionOutput>,
    /// `tenzro:model:<root>`.
    pub subject: String,
    pub manifest: ModelManifestOutput,
    pub verified: bool,
    pub status: ProvenanceStatusOutput,
    pub observations: Vec<OriginObservationOutput>,
}

/// A model's manifests.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ModelProvenanceOutput {
    pub manifests: Vec<ModelProvenanceEntry>,
}

// ─── Sealed models ───

/// An encrypted shard of a sealed model.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SealedShardOutput {
    pub index: u32,
    pub plaintext_bytes: u64,
    pub ciphertext_bytes: u64,
    /// 32 byte values.
    pub ciphertext_hash: [u8; 32],
    pub blob_uri: String,
}

/// A content key wrapped to one recipient. Byte fields are arrays of byte
/// values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct WrappedKeyOutput {
    /// The envelope version.
    pub version: u8,
    /// The data key sealed to the recipient's hybrid key.
    pub sealed_key: SealedKeyOutput,
    pub encrypted_data: Vec<u8>,
}

/// A key sealed to a hybrid X25519 + ML-KEM-768 key. Byte fields are arrays
/// of byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SealedKeyOutput {
    /// 32 byte values.
    pub x25519_share: [u8; 32],
    pub ml_kem_ciphertext: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// A hybrid X25519 + ML-KEM-768 public key. Byte fields are arrays of byte
/// values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct HybridKeyOutput {
    /// 32 byte values.
    pub x25519: [u8; 32],
    pub ml_kem: Vec<u8>,
}

/// A recipient a sealed model is addressed to.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SealedRecipientOutput {
    pub did: String,
    pub recipient_key: HybridKeyOutput,
    pub wrapped_key: WrappedKeyOutput,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enclave_measurement_hex: Option<String>,
}

/// A full sealed-model manifest. Hashes are arrays of 32 byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct SealedModelManifestOutput {
    pub model_id: String,
    pub artifact_name: String,
    pub model_hash: [u8; 32],
    pub total_bytes: u64,
    pub shard_bytes: u64,
    pub shards: Vec<SealedShardOutput>,
    pub recipients: Vec<SealedRecipientOutput>,
    pub wrap_alg: String,
    pub owner_did: String,
    pub created_at: u64,
    pub manifest_hash: [u8; 32],
    #[serde(default)]
    pub signature: Option<ReceiptCompositeSignature>,
    #[serde(default)]
    pub signer: Option<ReceiptCompositeKey>,
}

// ─── Compute claims ───

/// Where a claim stands: `offered`, `held`, `delivered`, `cancelled` or
/// `lapsed`.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ClaimStateOutput {
    pub state: String,
}

/// A standardized compute claim. Amounts are wei.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ComputeClaimOutput {
    pub claim_id: String,
    pub writer: String,
    pub holder: Option<String>,
    pub hardware_class: u8,
    pub region: String,
    pub delivery_start_ms: i64,
    pub epochs: u64,
    pub strike_per_epoch: ModelsWideUint,
    pub provider_did: String,
    #[serde(default)]
    pub storage_descriptor: Option<String>,
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(default = "zero_wide")]
    pub units_per_epoch: ModelsWideUint,
    pub epochs_settled: u64,
    pub collateral: ModelsWideUint,
    pub payment: ModelsWideUint,
    pub state: ClaimStateOutput,
    /// Decimal string.
    pub total_strike: String,
    pub delivery_end_ms: i64,
    /// `0x` hex.
    pub vault: String,
}

/// An address's compute claims.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ComputeClaimsOutput {
    pub total: u64,
    pub claims: Vec<ComputeClaimOutput>,
}

// ─── Mixture-of-experts serving ───

/// One expert of one layer.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoeExpertKey {
    pub layer: u32,
    pub expert: u32,
}

/// A provider holding an expert.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoeHolderOutput {
    /// Hex address.
    pub provider: String,
    pub residency: String,
    pub committed_tps: u32,
    pub iroh_endpoint_id: Option<String>,
    pub blob_uri: Option<String>,
}

/// An expert's holders.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoeExpertHoldersOutput {
    pub layer: u32,
    pub expert: u32,
    pub replication: u64,
    pub holders: Vec<MoeHolderOutput>,
}

/// A model's expert shard map.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoeShardMapOutput {
    pub model_id: String,
    pub covered_experts: u64,
    pub distinct_providers: u64,
    pub expert_holders_role_count: u64,
    pub router_role_count: u64,
    pub prefill_role_count: u64,
    pub decode_role_count: u64,
    pub replica_role_count: u64,
    pub policy: super::server::MoeReplicationPolicyOutput,
    pub under_replicated_experts: Vec<MoeExpertKey>,
    pub hot_experts: Vec<MoeExpertKey>,
    pub holders: Vec<MoeExpertHoldersOutput>,
}

/// One holder's batch.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoeDispatchBatchOutput {
    pub layer: u32,
    pub expert: u32,
    /// Hex address.
    pub provider: String,
    pub iroh_endpoint_id: Option<String>,
    pub token_indices: Vec<u32>,
}

/// Where one of a token's experts is served.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoeDispatchSlotOutput {
    pub layer: u32,
    pub expert: u32,
    /// Hex address; null when no holder was found.
    pub provider: Option<String>,
}

/// One token's slot assignments.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoeTokenAssignmentOutput {
    pub token_index: u32,
    pub slots: Vec<MoeDispatchSlotOutput>,
}

/// A dispatch plan.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoeDispatchPlanOutput {
    pub model_id: String,
    pub batch_count: u64,
    pub batches: Vec<MoeDispatchBatchOutput>,
    pub token_assignments: Vec<MoeTokenAssignmentOutput>,
}

/// Block quantization: a preset (`q4_k_m`, `q8_0`, `q4_k`, `q6_k`) or one
/// kind per projection.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum MoeQuantParam {
    Preset(String),
    PerProjection {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        gate: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        up: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        down: Option<String>,
    },
}

/// A started expert-preparation job.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoePrepareStartedOutput {
    pub job_id: String,
    pub model_id: String,
    pub layer: u32,
    pub total_experts: u64,
    pub include_gate: bool,
    pub quant: Option<MoeQuantParam>,
    /// `running`.
    pub state: String,
}

/// An expert holder that failed every replan, with the tokens left unserved.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoeMissingOutput {
    pub layer: u32,
    pub expert: u32,
    pub tokens: Vec<u32>,
}

/// Batches by transport.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoeTransportsOutput {
    pub local: u64,
    pub iroh: u64,
}

/// One gate-weighted slot of a routed token.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoeRoutedSlotOutput {
    pub layer: u32,
    pub expert: u32,
    pub weight: f32,
}

/// One token's gate routing.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoeRoutedTokenOutput {
    pub token_index: u32,
    pub slots: Vec<MoeRoutedSlotOutput>,
}

/// A distributed forward of one layer.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct MoeForwardOutput {
    pub model_id: String,
    pub layer: u32,
    pub d_model: u64,
    pub top_k: u64,
    pub tokens: u64,
    pub batches: u64,
    pub replans: u64,
    pub missing: Vec<MoeMissingOutput>,
    pub transports: MoeTransportsOutput,
    pub routed: Vec<MoeRoutedTokenOutput>,
    /// Base64 of little-endian f32 bytes.
    pub outputs: String,
}

// ─── Chat by intent ───

/// Marks a text block as a prompt-cache breakpoint.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChatCacheControl {
    Ephemeral,
}

/// A picture in a content block.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChatImageSource {
    Base64 {
        /// e.g. `image/png`.
        media_type: String,
        data: String,
    },
}

/// What a tool returned: text, or content blocks.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ChatToolResultContent {
    Text(String),
    Blocks(Vec<ChatContentBlock>),
}

/// One block of a chat turn.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChatContentBlock {
    Text {
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cache_control: Option<ChatCacheControl>,
    },
    Thinking {
        thinking: String,
    },
    /// A call of a tool the caller defined; `input` is that tool's arguments.
    ToolUse {
        id: String,
        name: String,
        input: super::server::JsonValue,
    },
    ToolResult {
        tool_use_id: String,
        content: ChatToolResultContent,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        is_error: Option<bool>,
    },
    Image {
        source: ChatImageSource,
    },
}

/// A turn's content: text, or content blocks.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ChatMessageContent {
    Text(String),
    Blocks(Vec<ChatContentBlock>),
}

/// One chat turn.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChatMessageParam {
    /// `user`, `assistant` or `system`.
    pub role: String,
    pub content: ChatMessageContent,
}

/// The inference commitment this answer stored, for challenges.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChatCommitmentRef {
    pub hash: String,
    pub k: u8,
    /// Committed steps.
    pub steps: u64,
}

/// The jurisdiction a serving node declares.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct JurisdictionClaimOutput {
    /// ISO 3166-1 alpha-2.
    pub country: String,
    #[serde(default)]
    pub blocs: Vec<String>,
    /// 32 byte values.
    #[serde(default)]
    pub attestation_hash: Option<Vec<u8>>,
    /// Unix ms.
    pub declared_at: i64,
}

/// A signed statement of where a response was served. Byte fields are arrays
/// of byte values.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct JurisdictionReceiptOutput {
    pub request_hash: Vec<u8>,
    pub response_hash: Vec<u8>,
    pub model_id: String,
    /// 32 bytes.
    pub provider: Vec<u8>,
    pub jurisdiction: JurisdictionClaimOutput,
    /// Unix ms.
    pub signed_at: i64,
    pub signer_public_key: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_pq_key: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batched: Option<Vec<u8>>,
}

/// Token counts of a rich answer.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChatUsageOutput {
    pub input_tokens: u32,
    pub output_tokens: u32,
    #[serde(default)]
    pub cache_creation_input_tokens: u32,
    #[serde(default)]
    pub cache_read_input_tokens: u32,
}

/// The answer to the rich shape (`messages`), served here or by a provider.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChatRichAnswer {
    pub id: String,
    pub model: String,
    /// `assistant`.
    pub role: String,
    pub content: Vec<ChatContentBlock>,
    /// `end_turn`, `tool_use`, `max_tokens` or `stop_sequence`.
    pub stop_reason: String,
    #[serde(default)]
    pub stop_sequence: Option<String>,
    pub usage: ChatUsageOutput,
    #[serde(default)]
    pub tenzro_receipt: Option<InferenceReceiptOutput>,
    pub units: ModelsUnits,
    /// Wei, decimal string.
    pub cost_wei: String,
    pub settlement: InferenceSettlementOutput,
    /// `local` or `network`.
    pub location: String,
    /// The serving provider, when a provider on the network served it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default)]
    pub commitment: Option<ChatCommitmentRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenzro_jurisdiction: Option<JurisdictionReceiptOutput>,
    #[serde(default)]
    pub load: Option<ServingLoadOutput>,
    /// How the intent was resolved.
    pub route: super::server::RouteDecisionOutput,
}

/// The session a continuity-pinned turn belongs to.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChatContinuityOutput {
    pub session_id: String,
    /// `none`, `standby` or `hot_successor`.
    pub level: String,
    /// This node's payee, `0x` hex.
    pub primary: Option<String>,
    pub successor: Option<String>,
    pub successor_endpoint: Option<String>,
}

/// The answer to a turn of a continuity session served on this node.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChatSessionAnswer {
    pub output: String,
    pub model_id: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Prompt tokens served from the session's KV cache.
    pub cached_tokens: u64,
    /// `local`.
    pub location: String,
    /// Wei, decimal string.
    pub cost_wei: String,
    pub settlement: InferenceSettlementOutput,
    pub continuity: ChatContinuityOutput,
    pub route: super::server::RouteDecisionOutput,
}

/// The answer to the simple shape (`message`), served here or by a provider.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
pub struct ChatSimpleAnswer {
    pub output: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking: Option<String>,
    pub input_tokens: u32,
    pub output_tokens: u32,
    pub units: ModelsUnits,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation_time_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_per_second: Option<f64>,
    /// Wei, decimal string.
    pub cost_wei: String,
    pub settlement: InferenceSettlementOutput,
    pub model_id: String,
    /// `local` or `network`.
    pub location: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load: Option<ServingLoadOutput>,
    #[serde(rename = "tenzro_contentProvenance", default)]
    pub tenzro_content_provenance: Option<super::tool_types_chain::ContentProvenanceOutput>,
    #[serde(default)]
    pub tenzro_jurisdiction: Option<JurisdictionReceiptOutput>,
    #[serde(default)]
    pub tenzro_receipt: Option<InferenceReceiptOutput>,
    #[serde(default)]
    pub commitment: Option<ChatCommitmentRef>,
    pub route: super::server::RouteDecisionOutput,
}

/// A chat answer with the routing decision under `route`: the rich shape's
/// answer, a continuity session's turn, or the simple shape's answer.
#[derive(Debug, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(untagged)]
pub enum ChatByIntentOutput {
    Rich(ChatRichAnswer),
    Session(ChatSessionAnswer),
    Simple(ChatSimpleAnswer),
}
