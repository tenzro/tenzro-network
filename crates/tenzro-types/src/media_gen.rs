//! Tenzro Media Gen — decentralized generative media job types.
//!
//! These types live in `tenzro-types` so every crate (RPC, storage, network,
//! token, CLI, agent kit, the Python reference media-gen worker over JSON)
//! can talk about media generation jobs and receipts without circular
//! dependencies. Scoped apart from `tenzro-training`/the chat inference path
//! by **output modality and job shape**, not by model architecture: this
//! subsystem covers jobs whose output is a media artifact (image, video, and
//! extensible to other non-text media), executed as a single posted job
//! claimed by one enrolled worker who returns a signed receipt referencing
//! content-addressed output — inference-shaped, not multi-party
//! training-shaped. It is not scoped to diffusion models specifically:
//! diffusion is a modeling technique, not a modality, and diffusion-based
//! text models (e.g. Diffusion Gemma) exist and are served on Tenzro's
//! existing text/LLM catalog and chat inference path like any other language
//! model, not through this module. The initial concrete [`MediaGenKind`]
//! variants cover image and video; new kinds are added as additional enum
//! variants plus a matching Python pipeline rather than a redesign of this
//! module.
//!
//! Architecture mirrors Tenzro Train: the **Rust protocol layer** (this
//! crate plus `tenzro-media-gen`) owns the job queue, worker registry,
//! pricing, and receipts. The **Python reference media-gen worker**
//! (`integrations/media_gen/`, HuggingFace `diffusers` pipelines) owns the
//! actual denoising loop for each media-gen pipeline. The flow is
//! single-worker inference-shaped, not multi-party training-shaped: a
//! requester posts a job, one enrolled worker claims and executes it, and
//! submits a signed receipt referencing the content-addressed output.
//!
//! # Lifecycle
//!
//! 1. A [`MediaGenTaskSpec`] is posted. Requester escrows or pre-pays
//!    `max_price` in attoTNZO.
//! 2. An enrolled [`MediaGenWorkerCapability`] claims the job.
//! 3. The worker runs the diffusion pipeline and publishes the output
//!    bytes to the content-addressed blob store.
//! 4. The worker submits a signed [`MediaGenReceipt`] referencing the
//!    output by content hash.
//!
//! # Content addressing
//!
//! Input and output media are referenced by SHA-256 [`Hash`] — the canonical
//! Tenzro content hash — never by a raw URI string. The `tenzro://blob/<hash>`
//! form uses BLAKE3 (a different hash of the same bytes), so keeping the
//! protocol type on SHA-256 and letting the transport adapter own the
//! SHA-256 → BLAKE3 mapping matches how outer-gradient payloads are
//! addressed in `tenzro-training`.

use crate::error::TenzroError;
use crate::primitives::{Address, Hash, Signature, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Largest output width or height, in pixels, a job may request.
pub const MAX_MEDIA_GEN_DIMENSION: u32 = 8192;

/// Largest denoising step count a job may request.
pub const MAX_MEDIA_GEN_STEPS: u32 = 500;

/// Largest video frame count a job may request.
pub const MAX_MEDIA_GEN_FRAMES: u32 = 3600;

/// Largest prompt length, in bytes, a job may carry.
pub const MAX_MEDIA_GEN_PROMPT_BYTES: usize = 8192;

// ---------------------------------------------------------------------------
// Media-gen kind
// ---------------------------------------------------------------------------

/// What kind of generative media job this is. Drives which Python worker
/// pipeline handles it and which [`MediaGenParams`] fields are required.
///
/// The serde labels are pinned per variant so the JSON label, the [`Display`]
/// label, and the [`MediaGenKind::from_str_lossy`] canonical spelling are the
/// same string wherever the kind is written or parsed.
///
/// [`Display`]: fmt::Display
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MediaGenKind {
    /// Text prompt -> still image.
    #[serde(rename = "text2image")]
    Text2Image,
    /// Reference image + text prompt -> still image.
    #[serde(rename = "image2image")]
    Image2Image,
    /// Text prompt -> video clip.
    #[serde(rename = "text2video")]
    Text2Video,
    /// Reference image + text prompt -> video clip.
    #[serde(rename = "image2video")]
    Image2Video,
}

impl fmt::Display for MediaGenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text2Image => write!(f, "text2image"),
            Self::Image2Image => write!(f, "image2image"),
            Self::Text2Video => write!(f, "text2video"),
            Self::Image2Video => write!(f, "image2video"),
        }
    }
}

impl MediaGenKind {
    /// Parse from a string label (case-insensitive). Accepts a few common
    /// aliases.
    pub fn from_str_lossy(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "text2image" | "text-to-image" | "t2i" => Some(Self::Text2Image),
            "image2image" | "image-to-image" | "i2i" => Some(Self::Image2Image),
            "text2video" | "text-to-video" | "t2v" => Some(Self::Text2Video),
            "image2video" | "image-to-video" | "i2v" => Some(Self::Image2Video),
            _ => None,
        }
    }

    /// Whether this kind requires an `input_image_hash` in [`MediaGenParams`].
    pub fn requires_input_image(&self) -> bool {
        matches!(self, Self::Image2Image | Self::Image2Video)
    }

    /// Whether this kind produces a video (multi-frame) output.
    pub fn is_video(&self) -> bool {
        matches!(self, Self::Text2Video | Self::Image2Video)
    }
}

// ---------------------------------------------------------------------------
// Job status
// ---------------------------------------------------------------------------

/// Status of a media-gen job as held in node storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MediaGenStatus {
    /// Posted; awaiting a worker claim.
    Pending,
    /// A worker has claimed the job and is expected to execute it.
    Claimed,
    /// Worker reported it started running the pipeline.
    Running,
    /// Worker submitted a receipt; job complete.
    Completed,
    /// Worker reported failure, or the job timed out unclaimed/unfinished.
    Failed,
    /// Cancelled by the requester before a worker claimed it.
    Cancelled,
}

impl fmt::Display for MediaGenStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Claimed => write!(f, "claimed"),
            Self::Running => write!(f, "running"),
            Self::Completed => write!(f, "completed"),
            Self::Failed => write!(f, "failed"),
            Self::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl MediaGenStatus {
    /// Parse from a string label (case-insensitive). Used by the job-listing
    /// RPC to filter on status.
    pub fn from_str_lossy(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "pending" => Some(Self::Pending),
            "claimed" => Some(Self::Claimed),
            "running" => Some(Self::Running),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "cancelled" | "canceled" => Some(Self::Cancelled),
            _ => None,
        }
    }

    /// Whether the job has reached a state it can never leave.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }

    /// Whether a transition to `next` is legal. Terminal states admit no
    /// transitions; a claim may only happen from `Pending`; a receipt may
    /// only complete a job a worker already holds.
    pub fn can_transition_to(&self, next: Self) -> bool {
        matches!(
            (self, next),
            (
                Self::Pending,
                Self::Claimed | Self::Cancelled | Self::Failed
            ) | (
                Self::Claimed,
                Self::Running | Self::Completed | Self::Failed
            ) | (Self::Running, Self::Completed | Self::Failed)
        )
    }
}

// ---------------------------------------------------------------------------
// Media-gen params
// ---------------------------------------------------------------------------

/// Diffusion sampling parameters. Field applicability depends on
/// [`MediaGenKind`]: `input_image_hash` is required for `Image2Image` /
/// `Image2Video`; `num_frames` and `fps` are required for `Text2Video` /
/// `Image2Video` and ignored for still-image kinds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediaGenParams {
    /// Text prompt.
    pub prompt: String,
    /// Optional negative prompt.
    pub negative_prompt: Option<String>,
    /// Output width in pixels.
    pub width: u32,
    /// Output height in pixels.
    pub height: u32,
    /// Video frame count. Required for video kinds.
    pub num_frames: Option<u32>,
    /// Video frames per second. Required for video kinds.
    pub fps: Option<u32>,
    /// Denoising steps.
    pub steps: u32,
    /// Classifier-free guidance scale.
    pub guidance_scale: f32,
    /// Optional deterministic seed. When `None` the worker picks one and
    /// reports it back in the receipt.
    pub seed: Option<u64>,
    /// SHA-256 of the reference input image bytes, published to the
    /// content-addressed media store before the job is posted. Required for
    /// `Image2Image` / `Image2Video`.
    pub input_image_hash: Option<Hash>,
    /// Free-form pipeline-specific metadata (e.g. `strength` for
    /// image-to-image, scheduler name). Opaque to the Rust protocol;
    /// consumed by the Python worker.
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

impl MediaGenParams {
    /// Validates the params against a [`MediaGenKind`]'s structural
    /// requirements and the protocol's bounds. Returns the first violation
    /// found, if any.
    pub fn validate_for(&self, kind: MediaGenKind) -> Result<(), TenzroError> {
        let reject = |msg: &str| Err(TenzroError::InvalidInferenceParameters(msg.to_string()));

        if self.prompt.trim().is_empty() {
            return reject("prompt must not be empty");
        }
        if self.prompt.len() > MAX_MEDIA_GEN_PROMPT_BYTES {
            return reject("prompt exceeds the maximum length");
        }
        if self.width == 0 || self.height == 0 {
            return reject("width and height must be greater than zero");
        }
        if self.width > MAX_MEDIA_GEN_DIMENSION || self.height > MAX_MEDIA_GEN_DIMENSION {
            return reject("width and height exceed the maximum dimension");
        }
        if self.steps == 0 {
            return reject("steps must be greater than zero");
        }
        if self.steps > MAX_MEDIA_GEN_STEPS {
            return reject("steps exceeds the maximum");
        }
        // The guidance scale is folded into the receipt signing preimage as
        // raw IEEE-754 bytes, so a NaN would break preimage determinism.
        if !self.guidance_scale.is_finite() || self.guidance_scale < 0.0 {
            return reject("guidance_scale must be a finite non-negative number");
        }
        if kind.requires_input_image() && self.input_image_hash.is_none() {
            return reject("input_image_hash is required for this media-gen kind");
        }
        if kind.is_video() {
            match (self.num_frames, self.fps) {
                (Some(frames), Some(fps)) => {
                    if frames == 0 || fps == 0 {
                        return reject("num_frames and fps must be greater than zero");
                    }
                    if frames > MAX_MEDIA_GEN_FRAMES {
                        return reject("num_frames exceeds the maximum");
                    }
                }
                _ => return reject("num_frames and fps are required for video media-gen kinds"),
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Media-gen task spec
// ---------------------------------------------------------------------------

/// The posted description of a media-gen job. Referenced by workers and
/// committed verbatim into the final [`MediaGenReceipt`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediaGenTaskSpec {
    /// Unique job ID (deterministic hash of canonicalized job fields).
    pub job_id: String,
    /// Requester DID (`did:tenzro:human:...` or `did:tenzro:machine:...`).
    pub requester_did: String,
    /// Requester's address for pricing and settlement.
    pub requester_address: Address,
    /// Catalog model ID (e.g. `qwen-image`, `flux2-klein`, `wan2.2-t2v-a14b`).
    pub model_id: String,
    /// What kind of media-gen job this is.
    pub kind: MediaGenKind,
    /// Diffusion sampling parameters.
    pub params: MediaGenParams,
    /// Maximum price the requester will pay, in attoTNZO.
    #[serde(with = "crate::primitives::u128_serde")]
    pub max_price: u128,
    /// Posting timestamp.
    pub created_at: Timestamp,
    /// Free-form metadata.
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Expert roles
// ---------------------------------------------------------------------------

/// Which half of a two-expert denoising schedule a worker serves.
///
/// Some pipelines carry two full transformers instead of one and switch between
/// them partway down the noise schedule — the high-noise expert denoises the
/// coarse early steps, the low-noise expert finishes. Because the switch
/// happens once, the whole handoff between them is a single latent tensor, so
/// two workers holding one expert each can split a job over a wide-area link.
/// A worker declares what it holds through [`MediaGenExpertHolding`].
///
/// [`None`] on an assignment means the job is not split and one worker runs
/// the entire schedule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MediaGenExpertRole {
    /// Denoises from the start of the schedule down to the model's boundary.
    #[serde(rename = "high_noise")]
    HighNoise,
    /// Takes the boundary latent and denoises it to the final output.
    #[serde(rename = "low_noise")]
    LowNoise,
}

impl fmt::Display for MediaGenExpertRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HighNoise => write!(f, "high_noise"),
            Self::LowNoise => write!(f, "low_noise"),
        }
    }
}

impl MediaGenExpertRole {
    /// Parse from a string label (case-insensitive).
    pub fn from_str_lossy(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "high_noise" | "high-noise" | "high" => Some(Self::HighNoise),
            "low_noise" | "low-noise" | "low" => Some(Self::LowNoise),
            _ => None,
        }
    }

    /// The other half of the schedule.
    pub fn partner(&self) -> Self {
        match self {
            Self::HighNoise => Self::LowNoise,
            Self::LowNoise => Self::HighNoise,
        }
    }
}

/// One expert of one model that a worker has resident and can serve.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MediaGenExpertHolding {
    /// Catalog model ID the expert belongs to.
    pub model_id: String,
    /// Which half of that model's schedule this worker holds.
    pub role: MediaGenExpertRole,
}

// ---------------------------------------------------------------------------
// Worker capability
// ---------------------------------------------------------------------------

/// A media-gen worker's advertised capability. Enrolled once; consulted
/// by the runtime when a worker attempts to claim a job.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediaGenWorkerCapability {
    /// Worker DID.
    pub worker_did: String,
    /// Address bound to the worker's TDIP identity.
    pub worker_address: Address,
    /// Catalog model IDs this worker can serve whole.
    pub supported_models: Vec<String>,
    /// Individual experts this worker holds, for models it cannot serve whole.
    /// A worker with the VRAM for both halves lists the model in
    /// `supported_models` instead.
    #[serde(default)]
    pub expert_holdings: Vec<MediaGenExpertHolding>,
    /// Maximum output dimension (width or height, in pixels) supported.
    pub max_resolution: u32,
    /// Maximum video frame count supported. `None` for image-only workers.
    pub max_frames: Option<u32>,
    /// Advertised GPU VRAM in GiB.
    pub gpu_vram_gb: f32,
    /// Enrollment timestamp.
    pub registered_at: Timestamp,
}

impl MediaGenWorkerCapability {
    /// Whether this worker can serve the given job spec in its entirety.
    pub fn can_serve(&self, spec: &MediaGenTaskSpec) -> bool {
        self.supported_models.iter().any(|m| m == &spec.model_id) && self.fits_output(spec)
    }

    /// Whether this worker can serve one half of the given job spec. A worker
    /// that holds the whole model qualifies for either half.
    pub fn can_serve_expert(&self, spec: &MediaGenTaskSpec, role: MediaGenExpertRole) -> bool {
        let holds = self.supported_models.iter().any(|m| m == &spec.model_id)
            || self
                .expert_holdings
                .iter()
                .any(|h| h.model_id == spec.model_id && h.role == role);
        holds && self.fits_output(spec)
    }

    /// Whether the requested output shape is within this worker's limits.
    /// Independent of which expert it holds — both halves work on the same
    /// latent geometry.
    fn fits_output(&self, spec: &MediaGenTaskSpec) -> bool {
        if spec.params.width.max(spec.params.height) > self.max_resolution {
            return false;
        }
        if spec.kind.is_video() {
            let frames = spec.params.num_frames.unwrap_or(0);
            match self.max_frames {
                Some(max) => frames <= max,
                None => false,
            }
        } else {
            true
        }
    }
}

// ---------------------------------------------------------------------------
// Media-gen receipt
// ---------------------------------------------------------------------------

/// Sealed completion artifact for a media-gen job. Worker-signed,
/// referencing the output by content hash.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediaGenReceipt {
    pub job_id: String,
    /// The full task spec, captured verbatim for provenance.
    pub task_spec: MediaGenTaskSpec,
    /// Worker DID that executed the job.
    pub worker_did: String,
    /// Address bound to the worker's TDIP identity.
    pub worker_address: Address,
    /// SHA-256 of the output bytes. The requester fetches the artifact from
    /// the content-addressed media store by this hash.
    pub output_hash: Hash,
    /// IANA media type of the output bytes (`image/png`, `video/mp4`, ...).
    /// The pipeline picks the container; the requester needs it to decode.
    pub output_mime: String,
    /// Output size in bytes.
    pub output_bytes: u64,
    /// Seed actually used (echoed back when the requester left `seed: None`).
    pub seed_used: u64,
    /// Wall-clock generation time in milliseconds.
    pub generation_time_ms: u64,
    /// Price actually charged, in attoTNZO (<= `task_spec.max_price`).
    #[serde(with = "crate::primitives::u128_serde")]
    pub price_paid: u128,
    /// Completion timestamp.
    pub completed_at: Timestamp,
    /// Worker signature over the canonical bytes of all fields above.
    pub worker_signature: Signature,
}

// ---------------------------------------------------------------------------
// Assignment and handoff
// ---------------------------------------------------------------------------

/// One worker's claim on a job. A job served whole has a single assignment
/// with `role: None`; a job split across a two-expert schedule has one
/// assignment per [`MediaGenExpertRole`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediaGenAssignment {
    /// DID of the worker holding this part of the job.
    pub worker_did: String,
    /// Address bound to the worker's TDIP identity.
    pub worker_address: Address,
    /// Which half of the schedule this worker runs; `None` when it runs all
    /// of it.
    pub role: Option<MediaGenExpertRole>,
    /// When this worker claimed its part.
    pub claimed_at: Timestamp,
    /// Share of `price_paid` owed to this worker, in basis points. Zero until
    /// the receipt lands and the split is known.
    pub share_bps: u32,
}

/// The intermediate latent one expert passes to the other, midway down the
/// noise schedule.
///
/// This is the whole of the inter-worker traffic on a split job: one tensor,
/// once. It is content-addressed like any other media payload, so the
/// receiving worker fetches it from the blob store rather than holding a
/// direct connection open, and the sending worker's signature over it is what
/// establishes the work it did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediaGenHandoff {
    /// Job this latent belongs to.
    pub job_id: String,
    /// DID of the worker that produced it.
    pub from_worker_did: String,
    /// Address bound to that worker's TDIP identity.
    pub from_worker_address: Address,
    /// SHA-256 of the serialized latent tensor.
    pub latent_hash: Hash,
    /// Size of the serialized latent in bytes.
    pub latent_bytes: u64,
    /// Denoising steps completed before the handoff. Against
    /// `task_spec.params.steps` this is what splits the payment.
    pub steps_completed: u32,
    /// When the latent was published.
    pub handed_off_at: Timestamp,
    /// Sending worker's signature over the canonical bytes of the fields
    /// above.
    pub worker_signature: Signature,
}

// ---------------------------------------------------------------------------
// Media-gen job (in-flight state)
// ---------------------------------------------------------------------------

/// In-flight media-gen job state held off-chain (in `CF_MEDIA_GEN_RUNS`).
/// Receipt attached at completion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MediaGenJob {
    pub job_id: String,
    pub task_spec: MediaGenTaskSpec,
    pub status: MediaGenStatus,
    /// Expert roles that must be claimed before the job can run. Empty for a
    /// job served whole by one worker.
    #[serde(default)]
    pub required_roles: Vec<MediaGenExpertRole>,
    /// Workers holding the job, one per claimed role. The job stays `Pending`
    /// until every entry in `required_roles` is covered.
    #[serde(default)]
    pub assignments: Vec<MediaGenAssignment>,
    /// The intermediate latent, once the high-noise expert has published it.
    /// Always `None` on a job served whole.
    pub handoff: Option<MediaGenHandoff>,
    /// Completion receipt, once completed.
    pub receipt: Option<MediaGenReceipt>,
    /// Failure reason, if `status == Failed`.
    pub error: Option<String>,
    pub created_at: Timestamp,
    pub last_update: Timestamp,
}

impl MediaGenJob {
    /// Whether the job's denoising schedule is split across two workers.
    pub fn is_split(&self) -> bool {
        !self.required_roles.is_empty()
    }

    /// The assignment held by `worker_did`, if any.
    pub fn assignment_for(&self, worker_did: &str) -> Option<&MediaGenAssignment> {
        self.assignments.iter().find(|a| a.worker_did == worker_did)
    }

    /// The worker assigned to `role`, if that role has been claimed.
    pub fn assignment_of_role(&self, role: MediaGenExpertRole) -> Option<&MediaGenAssignment> {
        self.assignments.iter().find(|a| a.role == Some(role))
    }

    /// Roles still open for claiming.
    pub fn unclaimed_roles(&self) -> Vec<MediaGenExpertRole> {
        self.required_roles
            .iter()
            .copied()
            .filter(|r| self.assignment_of_role(*r).is_none())
            .collect()
    }

    /// Whether every required role has a worker. A job served whole is fully
    /// assigned as soon as it has one assignment.
    pub fn is_fully_assigned(&self) -> bool {
        if self.is_split() {
            self.unclaimed_roles().is_empty()
        } else {
            !self.assignments.is_empty()
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_params(kind: MediaGenKind) -> MediaGenParams {
        MediaGenParams {
            prompt: "a fox in a diorama".to_string(),
            negative_prompt: None,
            width: 1024,
            height: 1024,
            num_frames: if kind.is_video() { Some(81) } else { None },
            fps: if kind.is_video() { Some(16) } else { None },
            steps: 30,
            guidance_scale: 4.5,
            seed: None,
            input_image_hash: if kind.requires_input_image() {
                Some(Hash::new([7u8; 32]))
            } else {
                None
            },
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn kind_roundtrip() {
        for s in ["text2image", "t2i", "TEXT-TO-IMAGE"] {
            assert_eq!(
                MediaGenKind::from_str_lossy(s),
                Some(MediaGenKind::Text2Image)
            );
        }
        assert_eq!(MediaGenKind::from_str_lossy("garbage"), None);
    }

    #[test]
    fn kind_requirements() {
        assert!(!MediaGenKind::Text2Image.requires_input_image());
        assert!(MediaGenKind::Image2Image.requires_input_image());
        assert!(!MediaGenKind::Text2Video.requires_input_image());
        assert!(MediaGenKind::Image2Video.requires_input_image());
        assert!(MediaGenKind::Text2Video.is_video());
        assert!(MediaGenKind::Image2Video.is_video());
        assert!(!MediaGenKind::Text2Image.is_video());
    }

    #[test]
    fn params_validate_text2image() {
        let p = sample_params(MediaGenKind::Text2Image);
        assert!(p.validate_for(MediaGenKind::Text2Image).is_ok());
    }

    #[test]
    fn params_validate_rejects_missing_input_image() {
        let mut p = sample_params(MediaGenKind::Image2Image);
        p.input_image_hash = None;
        let err = p.validate_for(MediaGenKind::Image2Image).unwrap_err();
        assert!(err.to_string().contains("input_image_hash"), "{err}");
    }

    #[test]
    fn params_validate_rejects_missing_video_fields() {
        let mut p = sample_params(MediaGenKind::Text2Video);
        p.num_frames = None;
        let err = p.validate_for(MediaGenKind::Text2Video).unwrap_err();
        assert!(err.to_string().contains("num_frames"), "{err}");
    }

    #[test]
    fn params_validate_rejects_out_of_bounds() {
        let mut p = sample_params(MediaGenKind::Text2Image);
        p.width = MAX_MEDIA_GEN_DIMENSION + 1;
        assert!(p.validate_for(MediaGenKind::Text2Image).is_err());

        let mut p = sample_params(MediaGenKind::Text2Image);
        p.steps = MAX_MEDIA_GEN_STEPS + 1;
        assert!(p.validate_for(MediaGenKind::Text2Image).is_err());

        let mut p = sample_params(MediaGenKind::Text2Image);
        p.guidance_scale = f32::NAN;
        assert!(p.validate_for(MediaGenKind::Text2Image).is_err());

        let mut p = sample_params(MediaGenKind::Text2Video);
        p.num_frames = Some(MAX_MEDIA_GEN_FRAMES + 1);
        assert!(p.validate_for(MediaGenKind::Text2Video).is_err());
    }

    #[test]
    fn worker_can_serve_checks_model_resolution_and_frames() {
        let worker = MediaGenWorkerCapability {
            worker_did: "did:tenzro:machine:worker-1".to_string(),
            worker_address: Address::zero(),
            supported_models: vec!["wan2.2-t2v-a14b".to_string()],
            expert_holdings: Vec::new(),
            max_resolution: 1280,
            max_frames: Some(81),
            gpu_vram_gb: 48.0,
            registered_at: Timestamp::new(0),
        };
        let spec = MediaGenTaskSpec {
            job_id: "job-1".to_string(),
            requester_did: "did:tenzro:human:req-1".to_string(),
            requester_address: Address::zero(),
            model_id: "wan2.2-t2v-a14b".to_string(),
            kind: MediaGenKind::Text2Video,
            params: sample_params(MediaGenKind::Text2Video),
            max_price: 1_000_000_000_000_000_000,
            created_at: Timestamp::new(0),
            metadata: HashMap::new(),
        };
        assert!(worker.can_serve(&spec));

        let mut too_big = spec.clone();
        too_big.params.width = 4096;
        assert!(!worker.can_serve(&too_big));

        let mut wrong_model = spec.clone();
        wrong_model.model_id = "other-model".to_string();
        assert!(!worker.can_serve(&wrong_model));
    }

    #[test]
    fn status_display() {
        assert_eq!(MediaGenStatus::Pending.to_string(), "pending");
        assert_eq!(MediaGenStatus::Completed.to_string(), "completed");
    }

    #[test]
    fn status_roundtrip_and_terminality() {
        for s in [
            MediaGenStatus::Pending,
            MediaGenStatus::Claimed,
            MediaGenStatus::Running,
            MediaGenStatus::Completed,
            MediaGenStatus::Failed,
            MediaGenStatus::Cancelled,
        ] {
            assert_eq!(MediaGenStatus::from_str_lossy(&s.to_string()), Some(s));
        }
        assert_eq!(MediaGenStatus::from_str_lossy("garbage"), None);
        assert!(!MediaGenStatus::Pending.is_terminal());
        assert!(!MediaGenStatus::Running.is_terminal());
        assert!(MediaGenStatus::Completed.is_terminal());
        assert!(MediaGenStatus::Cancelled.is_terminal());
    }

    #[test]
    fn status_transitions() {
        assert!(MediaGenStatus::Pending.can_transition_to(MediaGenStatus::Claimed));
        assert!(MediaGenStatus::Claimed.can_transition_to(MediaGenStatus::Running));
        assert!(MediaGenStatus::Running.can_transition_to(MediaGenStatus::Completed));
        // A job cannot be claimed twice, completed without a claim, or leave
        // a terminal state.
        assert!(!MediaGenStatus::Claimed.can_transition_to(MediaGenStatus::Claimed));
        assert!(!MediaGenStatus::Pending.can_transition_to(MediaGenStatus::Completed));
        assert!(!MediaGenStatus::Completed.can_transition_to(MediaGenStatus::Failed));
        assert!(!MediaGenStatus::Cancelled.can_transition_to(MediaGenStatus::Claimed));
        // Cancellation is only available before a worker takes the job.
        assert!(!MediaGenStatus::Running.can_transition_to(MediaGenStatus::Cancelled));
    }

    #[test]
    fn serde_labels_match_display_labels() {
        for kind in [
            MediaGenKind::Text2Image,
            MediaGenKind::Image2Image,
            MediaGenKind::Text2Video,
            MediaGenKind::Image2Video,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, format!("\"{kind}\""));
            assert_eq!(MediaGenKind::from_str_lossy(&kind.to_string()), Some(kind));
        }
        for status in [MediaGenStatus::Pending, MediaGenStatus::Cancelled] {
            let json = serde_json::to_string(&status).unwrap();
            assert_eq!(json, format!("\"{status}\""));
        }
    }
}
