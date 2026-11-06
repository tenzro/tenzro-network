//! Generative media: the kinds, parameters and metering of a render.
//!
//! Scoped apart from the chat inference path by output modality, not by model
//! architecture: a render's output is a media artifact (image, video, audio,
//! 3D, actions or a simulated world). A diffusion model that emits text is
//! served on the chat path like any other language model.
//!
//! A node renders with the media models it loads, in process, through
//! `tenzro_mediaGen_render`, and meters the render in the units below against
//! its own rate card.

use crate::error::TenzroError;
use crate::primitives::Hash;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Largest output width or height, in pixels, a job may request.
pub const MAX_MEDIA_GEN_DIMENSION: u32 = 8192;

/// Largest step count a job may request: denoising steps for a diffusion
/// model, image tokens for an autoregressive one (Janus-Pro takes 576).
pub const MAX_MEDIA_GEN_STEPS: u32 = 1024;

/// Largest video frame count a job may request.
pub const MAX_MEDIA_GEN_FRAMES: u32 = 3600;

/// Largest number of action chunks one policy job may request.
pub const MAX_MEDIA_GEN_ACTION_CHUNKS: u32 = 256;

/// Longest interactive session hold, in seconds, one world-model job may book.
pub const MAX_MEDIA_GEN_SESSION_HOLD_SECS: u32 = 3600;

/// Largest prompt length, in bytes, a job may carry.
pub const MAX_MEDIA_GEN_PROMPT_BYTES: usize = 8192;

/// Largest number of inputs one job may carry.
pub const MAX_MEDIA_GEN_INPUTS: usize = 8;

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
    /// Reference image -> 3D asset (mesh with PBR materials).
    ///
    /// The output is a GLB, not frames. Kept a distinct kind rather than
    /// folded into `Image2Image` because almost nothing downstream is shared:
    /// the work scales with voxel resolution rather than pixels, the artifact
    /// is a mesh a viewer loads rather than something to decode, and a worker
    /// that can render video is not thereby able to produce geometry.
    #[serde(rename = "image23d")]
    Image23d,
    /// Text prompt -> audio clip (music, speech, sound).
    ///
    /// A fourth output class alongside pixels, frames and geometry. The work
    /// scales with duration rather than area, and the artifact is a waveform
    /// nothing downstream should try to decode as an image — which is why it
    /// is a kind rather than a flag on `Text2Image`.
    #[serde(rename = "text2audio")]
    Text2Audio,
    /// Text prompt -> 3D asset (mesh with PBR materials).
    #[serde(rename = "text23d")]
    Text23d,
    /// Observation frames + task instruction -> action chunks for a robot.
    ///
    /// A policy jointly denoises the observation canvas and a fixed-length
    /// chunk of future actions; the artifact is the action chunks, not the
    /// frames. Its own kind because the work is counted in chunks, the input
    /// is a camera observation rather than a reference picture, and a worker
    /// that renders video is not thereby able to drive an embodiment.
    #[serde(rename = "action_policy")]
    ActionPolicy,
    /// Prompt (+ optional first frame) + per-frame actions -> video rolled
    /// forward chunk by chunk by an interactive world model.
    ///
    /// Its own kind because the work is counted in simulated seconds, steps
    /// and held session time rather than in a fixed clip: the model keeps a
    /// bounded memory of the frames already produced and conditions each new
    /// chunk on it and on the actions supplied for it.
    #[serde(rename = "world_model")]
    WorldModel,
}

impl fmt::Display for MediaGenKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text2Image => write!(f, "text2image"),
            Self::Image2Image => write!(f, "image2image"),
            Self::Text2Video => write!(f, "text2video"),
            Self::Image2Video => write!(f, "image2video"),
            Self::Text2Audio => write!(f, "text2audio"),
            Self::Image23d => write!(f, "image23d"),
            Self::Text23d => write!(f, "text23d"),
            Self::ActionPolicy => write!(f, "action_policy"),
            Self::WorldModel => write!(f, "world_model"),
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
            // `text2music` and `music` are accepted because that is what a
            // caller reaching for a music model will type; the kind is the
            // broader "audio out" so speech and sound effects share it.
            "text2audio" | "text-to-audio" | "t2a" | "text2music" | "music" => {
                Some(Self::Text2Audio)
            }
            "image23d" | "image-to-3d" | "i23d" => Some(Self::Image23d),
            "action_policy" | "action-policy" | "policy" => Some(Self::ActionPolicy),
            "world_model" | "world-model" | "world" => Some(Self::WorldModel),
            "text23d" | "text-to-3d" | "t23d" => Some(Self::Text23d),
            _ => None,
        }
    }

    /// Whether this kind needs at least one conditioning input in
    /// [`MediaGenParams::inputs`] (a mask alone does not count).
    pub fn requires_input(&self) -> bool {
        matches!(
            self,
            Self::Image2Image | Self::Image2Video | Self::Image23d | Self::ActionPolicy
        )
    }

    /// The input roles this kind accepts. Empty for kinds conditioned on the
    /// prompt alone.
    pub fn input_roles(&self) -> &'static [MediaGenInputRole] {
        use MediaGenInputRole as R;
        match self {
            Self::Image2Image => &[R::EditSource, R::Reference, R::Mask],
            Self::Image2Video => &[R::FirstFrame, R::LastFrame, R::Reference],
            Self::Image23d => &[R::Reference],
            Self::ActionPolicy => &[R::Observation],
            Self::WorldModel => &[R::FirstFrame],
            Self::Text2Image | Self::Text2Video | Self::Text2Audio | Self::Text23d => &[],
        }
    }

    /// Whether a job of this kind is conditioned on its prompt. An
    /// image-to-3D job is conditioned on its reference image alone, so its
    /// prompt is empty.
    pub fn reads_prompt(&self) -> bool {
        !matches!(self, Self::Image23d)
    }

    /// Whether this kind produces a video (multi-frame) output.
    pub fn is_video(&self) -> bool {
        matches!(
            self,
            Self::Text2Video | Self::Image2Video | Self::WorldModel
        )
    }

    /// Whether this kind is an interactive world-model rollout.
    ///
    /// A world job is a video (`num_frames` / `fps` give its simulated
    /// length) billed in the world-model unit rather than per clip frame.
    pub fn is_world(&self) -> bool {
        matches!(self, Self::WorldModel)
    }

    /// Whether this kind produces geometry rather than pixels.
    ///
    /// The seam every kind-dependent branch should ask, so a third output
    /// class later is one arm here rather than a hunt for `== Image23d`
    /// comparisons scattered across the worker and the pricing table.
    pub fn is_3d(&self) -> bool {
        matches!(self, Self::Image23d | Self::Text23d)
    }

    /// Whether this kind produces a waveform rather than pixels or geometry.
    ///
    /// The same seam as [`Self::is_3d`], for the same reason: an audio job has
    /// no width, height or frames to reason about, and every branch that
    /// divides work by output class should ask here rather than testing for a
    /// specific variant.
    pub fn is_audio(&self) -> bool {
        matches!(self, Self::Text2Audio)
    }

    /// Whether this kind produces action chunks for an embodiment.
    ///
    /// The same seam as [`Self::is_3d`]: `width`/`height` describe the
    /// observation canvas, and the billed unit is the action chunk.
    pub fn is_action(&self) -> bool {
        matches!(self, Self::ActionPolicy)
    }

    /// The artifact's file extension, for the content-addressed store.
    ///
    /// 3D kinds return a GLB — a mesh with PBR materials — which nothing
    /// downstream should try to decode as frames.
    pub fn output_extension(&self) -> &'static str {
        if self.is_action() {
            // Action chunks are a numeric array per chunk; JSON keeps the
            // artifact readable by any controller without a tensor library.
            "json"
        } else if self.is_audio() {
            // WAV rather than a compressed container: the generators emit PCM,
            // and re-encoding in the worker would make the artifact hash
            // depend on an encoder version rather than on the model output.
            "wav"
        } else if self.is_3d() {
            "glb"
        } else if self.is_video() {
            "mp4"
        } else {
            "png"
        }
    }
}

// ---------------------------------------------------------------------------
// Media-gen inputs
// ---------------------------------------------------------------------------

/// What one job input is to the pipeline that renders the job.
///
/// The role is part of what the requester signs, so a relay cannot turn a
/// first frame into a last frame or a reference into an edit source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MediaGenInputRole {
    /// The frame a video starts on.
    #[serde(rename = "first_frame")]
    FirstFrame,
    /// The frame a video ends on.
    #[serde(rename = "last_frame")]
    LastFrame,
    /// An image whose subject or style the output follows, without being a
    /// frame of it.
    #[serde(rename = "reference")]
    Reference,
    /// An image the output edits. Several are read in order.
    #[serde(rename = "edit_source")]
    EditSource,
    /// The region of the edit source an edit may change.
    #[serde(rename = "mask")]
    Mask,
    /// A robot observation an action policy acts on.
    #[serde(rename = "observation")]
    Observation,
}

impl MediaGenInputRole {
    /// The wire label, identical to the serde label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FirstFrame => "first_frame",
            Self::LastFrame => "last_frame",
            Self::Reference => "reference",
            Self::EditSource => "edit_source",
            Self::Mask => "mask",
            Self::Observation => "observation",
        }
    }

    /// Parses the wire label.
    pub fn from_str_lossy(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "first_frame" => Some(Self::FirstFrame),
            "last_frame" => Some(Self::LastFrame),
            "reference" => Some(Self::Reference),
            "edit_source" => Some(Self::EditSource),
            "mask" => Some(Self::Mask),
            "observation" => Some(Self::Observation),
            _ => None,
        }
    }

    /// Whether a job may carry this role at most once.
    pub fn is_single(&self) -> bool {
        matches!(
            self,
            Self::FirstFrame | Self::LastFrame | Self::Mask | Self::Observation
        )
    }
}

impl fmt::Display for MediaGenInputRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One requester-supplied input: bytes published to the content-addressed
/// media store before the job is posted, named by their SHA-256 and the role
/// they play. The requester's signature covers every input's role and hash,
/// and their order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MediaGenInput {
    /// What the input is to the pipeline.
    pub role: MediaGenInputRole,
    /// SHA-256 of the input bytes.
    pub hash: Hash,
}

// ---------------------------------------------------------------------------
// Media-gen params
// ---------------------------------------------------------------------------

/// Diffusion sampling parameters. Field applicability depends on
/// [`MediaGenKind`]: `inputs` must name what the kind conditions on (see
/// [`MediaGenKind::input_roles`]); `num_frames` and `fps` are required for `Text2Video` /
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
    /// Voxel grid resolution for 3D kinds, e.g. `1536` for a 1536³ grid.
    ///
    /// Optional and ignored by every pixel kind, so an image or video job is
    /// unchanged by its existence. Present because a 3D job's cost and quality
    /// scale with this rather than with `width`/`height`, which for
    /// [`MediaGenKind::Image23d`] describe the *conditioning image* and say
    /// nothing about the asset produced.
    ///
    /// `default` but deliberately **not** `skip_serializing_if`: these params
    /// cross the gossip wire as bincode, which is positional and not
    /// self-describing. Skipping the field on write would leave the decoder
    /// reading a value that was never written — it fails as a truncated
    /// payload, not as a missing field. `default` still covers the JSON
    /// surfaces, where an older client simply omits it.
    #[serde(default)]
    pub voxel_resolution: Option<u32>,
    /// Requested audio length in seconds, for [`MediaGenKind::Text2Audio`].
    ///
    /// Seconds rather than frames because that is what the generators accept
    /// and what a caller means; the frame rate is a property of the model and
    /// is applied at pricing time. Ignored by every other kind. Absent means
    /// the model's own default.
    ///
    /// `default` but deliberately **not** `skip_serializing_if`, for the same
    /// reason as `voxel_resolution` above: these params cross the gossip wire
    /// as bincode, which is positional. Skipping the field on write leaves the
    /// decoder reading bytes that were never written.
    #[serde(default)]
    pub audio_duration_secs: Option<f32>,
    /// Number of action chunks to produce, for [`MediaGenKind::ActionPolicy`].
    ///
    /// The billed unit of a policy job. Each chunk is one joint denoise of the
    /// observation canvas and the next chunk of actions; the chunk length and
    /// action dimension are properties of the model's embodiment. Ignored by
    /// every other kind. Not `skip_serializing_if`, for the bincode reason
    /// given on `voxel_resolution`.
    #[serde(default)]
    pub action_chunks: Option<u32>,
    /// Seconds of interactive session hold booked, for
    /// [`MediaGenKind::WorldModel`]: the time the worker keeps the session
    /// (model, encoded prompt and frame memory) live between action inputs.
    /// Billed per second; ignored by every other kind. Not
    /// `skip_serializing_if`, for the bincode reason given on
    /// `voxel_resolution`.
    #[serde(default)]
    pub session_hold_secs: Option<u32>,
    /// Optional deterministic seed. When `None` the worker picks one and
    /// reports it back in the receipt.
    pub seed: Option<u64>,
    /// The job's inputs, in the order the pipeline reads them. Each one is
    /// published to the content-addressed media store before the job is
    /// posted. Empty for kinds conditioned on the prompt alone.
    #[serde(default)]
    pub inputs: Vec<MediaGenInput>,
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

        if kind.reads_prompt() && self.prompt.trim().is_empty() {
            return reject("prompt must not be empty");
        }
        if !kind.reads_prompt() && !self.prompt.is_empty() {
            return reject("this media-gen kind reads no prompt; leave it empty");
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
        if self.inputs.len() > MAX_MEDIA_GEN_INPUTS {
            return reject("inputs exceeds the maximum count");
        }
        let accepted = kind.input_roles();
        for (i, input) in self.inputs.iter().enumerate() {
            if !accepted.contains(&input.role) {
                return Err(TenzroError::InvalidInferenceParameters(format!(
                    "inputs: role '{}' is not accepted by {kind}",
                    input.role
                )));
            }
            if input.role.is_single() && self.inputs[..i].iter().any(|o| o.role == input.role) {
                return Err(TenzroError::InvalidInferenceParameters(format!(
                    "inputs: role '{}' may appear only once",
                    input.role
                )));
            }
        }
        if kind.requires_input()
            && !self
                .inputs
                .iter()
                .any(|i| i.role != MediaGenInputRole::Mask)
        {
            return reject("inputs must name what this media-gen kind conditions on");
        }
        if self
            .inputs
            .iter()
            .any(|i| i.role == MediaGenInputRole::Mask)
            && !self
                .inputs
                .iter()
                .any(|i| i.role == MediaGenInputRole::EditSource)
        {
            return reject("inputs: a mask needs an edit_source to apply to");
        }
        if kind.is_action() {
            match self.action_chunks {
                Some(0) | None => {
                    return reject("action_chunks is required and must be greater than zero");
                }
                Some(n) if n > MAX_MEDIA_GEN_ACTION_CHUNKS => {
                    return reject("action_chunks exceeds the maximum");
                }
                Some(_) => {}
            }
        }
        if kind.is_world()
            && self
                .session_hold_secs
                .is_some_and(|s| s > MAX_MEDIA_GEN_SESSION_HOLD_SECS)
        {
            return reject("session_hold_secs exceeds the maximum");
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
// Expert roles
// ---------------------------------------------------------------------------

/// Which half of a two-expert denoising schedule a worker serves.
///
/// Some pipelines carry two full transformers instead of one and switch between
/// them partway down the noise schedule — the high-noise expert denoises the
/// coarse early steps, the low-noise expert finishes. Because the switch
/// happens once, the whole handoff between them is a single latent tensor.
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

// ---------------------------------------------------------------------------
// Metering
// ---------------------------------------------------------------------------

/// Work units for a render: `width × height × steps × frames`.
///
/// `num_frames` is only counted for video kinds — an image job that carries a
/// stray frame count is still one frame of work, and must not be priced as if
/// it were a clip.
pub fn pixel_steps(kind: MediaGenKind, params: &MediaGenParams) -> u128 {
    // A 3D job has no pixels to charge for. `width`/`height` describe the
    // *conditioning image*, so pricing on them would charge for the input and
    // ignore the thing actually produced — two jobs from the same photo at
    // 512³ and 1536³ would cost the same while differing 27× in work.
    if kind.is_3d() {
        return voxel_steps(params);
    }

    // An audio job has no pixels either. `width`/`height` are untouched
    // defaults on a text-to-audio request, so pricing on them would quote
    // every clip identically regardless of length — a five-minute track and a
    // five-second one would cost the same while differing 60x in work.
    if kind.is_audio() {
        return audio_frame_steps(params);
    }

    // A policy job is billed per action chunk: each chunk is one joint
    // denoise of the observation canvas and the next chunk of actions.
    if kind.is_action() {
        return action_chunk_steps(params);
    }

    // A world-model job is billed in simulated seconds, denoising steps and
    // held session time, not per clip frame.
    if kind.is_world() {
        return world_model_units(params).total();
    }

    let frames = if kind.is_video() {
        u128::from(params.num_frames.unwrap_or(1).max(1))
    } else {
        1
    };
    u128::from(params.width)
        .saturating_mul(u128::from(params.height))
        .saturating_mul(u128::from(params.steps))
        .saturating_mul(frames)
}

/// Work units for an action-policy job, in the same unit as [`pixel_steps`].
///
/// The billed unit is the action chunk. One chunk costs one denoise of the
/// observation canvas (`width × height × steps`), the same quantity a still
/// image of that canvas would, so a policy and an image model are quoted
/// against one rate. Joint action tokens are a few dozen against thousands of
/// canvas tokens and are not counted separately.
pub fn action_chunk_steps(params: &MediaGenParams) -> u128 {
    u128::from(params.action_chunks.unwrap_or(1).max(1))
        .saturating_mul(u128::from(params.width))
        .saturating_mul(u128::from(params.height))
        .saturating_mul(u128::from(params.steps.max(1)))
}

/// Pixel frames per simulated second the world-model unit is priced at.
///
/// A pricing constant, not a model capability: one simulated second costs the
/// same whatever frame rate the caller asked for, so a world job is quoted on
/// how much world it simulates rather than on how finely it is sampled.
pub const WORLD_FRAMES_PER_SECOND: u128 = 24;

/// Pixel frames covered by one latent frame of a world model; each denoising
/// step runs once per latent frame.
pub const WORLD_FRAMES_PER_LATENT: u128 = 4;

/// The world-model unit of one job: its three priced components, each in the
/// same unit as [`pixel_steps`] over the job's `width × height` canvas, and
/// the quantities they are counted from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldModelUnits {
    /// Simulated video produced, in milliseconds (`num_frames / fps`, rounded up).
    pub simulated_ms: u64,
    /// Denoising steps run per latent frame.
    pub steps: u32,
    /// Interactive session hold booked, in seconds.
    pub session_hold_secs: u32,
    /// Per simulated second: one canvas per priced frame.
    pub simulated: u128,
    /// Per denoising step: one canvas per latent frame per step.
    pub denoising: u128,
    /// Per held second: one canvas per second the session is kept live.
    pub session_hold: u128,
}

impl WorldModelUnits {
    /// The job's work units: the sum of the three components.
    pub fn total(&self) -> u128 {
        self.simulated
            .saturating_add(self.denoising)
            .saturating_add(self.session_hold)
    }
}

/// The world-model unit of a job.
///
/// Three components against the one `per_pixel_step` rate, so a world job and
/// a clip settle through the same path:
///
/// - **simulated seconds**: `canvas × priced frames`, the frames being
///   [`WORLD_FRAMES_PER_SECOND`] per simulated second, rounded up;
/// - **denoising steps**: `canvas × latent frames × steps`, a latent frame
///   covering [`WORLD_FRAMES_PER_LATENT`] priced frames, rounded up;
/// - **session hold**: `canvas × session_hold_secs`, the memory and model
///   kept live between action inputs.
pub fn world_model_units(params: &MediaGenParams) -> WorldModelUnits {
    let frames = u128::from(params.num_frames.unwrap_or(1).max(1));
    let fps = u128::from(params.fps.unwrap_or(1).max(1));
    let simulated_ms = frames.saturating_mul(1000).div_ceil(fps);
    let priced_frames = frames
        .saturating_mul(WORLD_FRAMES_PER_SECOND)
        .div_ceil(fps)
        .max(1);
    let latent_frames = priced_frames.div_ceil(WORLD_FRAMES_PER_LATENT);
    let canvas = u128::from(params.width).saturating_mul(u128::from(params.height));
    let steps = params.steps.max(1);
    let hold = params.session_hold_secs.unwrap_or(0);
    WorldModelUnits {
        simulated_ms: simulated_ms.min(u128::from(u64::MAX)) as u64,
        steps,
        session_hold_secs: hold,
        simulated: canvas.saturating_mul(priced_frames),
        denoising: canvas
            .saturating_mul(latent_frames)
            .saturating_mul(u128::from(steps)),
        session_hold: canvas.saturating_mul(u128::from(hold)),
    }
}

/// Frames per second of generated audio, for pricing purposes.
///
/// 25 is what MiniMax-Music3 documents for its acoustic frames, and the
/// generators in this class are within a small factor of each other. It is a
/// pricing constant, not a model capability: it converts a duration a caller
/// asked for into work units comparable with a pixel job, and does not have to
/// match any particular decoder's internal rate to do that fairly.
pub const AUDIO_FRAMES_PER_SECOND: u128 = 25;

/// Default clip length when a request names none, in seconds.
const DEFAULT_AUDIO_SECONDS: u128 = 30;

/// Work units for an audio job, in the same unit as [`pixel_steps`].
///
/// Duration times step count, converted to frames so one second of audio is a
/// fixed quantity of work rather than a wall-clock measurement. Quoted against
/// the same `per_pixel_step` rate as pixels and voxels, for the same reason
/// `voxel_steps` is: a second rate would be a second thing to govern and keep
/// in step.
///
/// A 30-second clip at 30 steps is 22,500 units against a 1024x1024 image's
/// 31.4 million — audio is genuinely cheap next to pixels, and the rate should
/// not pretend otherwise.
pub fn audio_frame_steps(params: &MediaGenParams) -> u128 {
    // `audio_duration_secs` is an f32 from the wire; clamp before converting so
    // a negative, NaN or absurd value cannot become a huge or zero quote.
    let secs = params
        .audio_duration_secs
        .filter(|d| d.is_finite() && *d > 0.0)
        .map(|d| d.min(3600.0) as u128)
        .unwrap_or(DEFAULT_AUDIO_SECONDS)
        .max(1);

    secs.saturating_mul(AUDIO_FRAMES_PER_SECOND)
        .saturating_mul(u128::from(params.steps.max(1)))
}

/// Work units for a 3D job, in the same unit as [`pixel_steps`].
///
/// One occupied voxel of one step, so a 3D job and a pixel job are quoted
/// against the same `per_pixel_step` rate and settle through the same path —
/// a second rate would be a second thing to govern and to keep in step.
///
/// Charged on the **grid face** (`r²`) rather than the full cube. Generation
/// cost tracks the sparse occupied surface, not the empty interior; `r³` at
/// 1536 would be 3.6 billion units against a 1024×1024 image's 1.0 million and
/// price a mesh out of existence.
pub fn voxel_steps(params: &MediaGenParams) -> u128 {
    let r = u128::from(params.voxel_resolution.unwrap_or(512).max(1));
    r.saturating_mul(r)
        .saturating_mul(u128::from(params.steps.max(1)))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The enum doc promises "the same string wherever the kind is written or
    /// parsed". Serde, `Display` and `from_str_lossy` are three separate
    /// implementations of that promise, and nothing makes them agree except
    /// this test.
    ///
    /// `Text2Audio` shipped without its `#[serde(rename)]` and serialised as
    /// "Text2Audio" while displaying as "text2audio" — the Python worker parses
    /// the label, so a job posted by Rust would not have been readable by the
    /// thing meant to run it.
    #[test]
    fn every_kind_agrees_across_serde_display_and_parse() {
        let all = [
            MediaGenKind::Text2Image,
            MediaGenKind::Image2Image,
            MediaGenKind::Text2Video,
            MediaGenKind::Image2Video,
            MediaGenKind::Text2Audio,
            MediaGenKind::Image23d,
            MediaGenKind::Text23d,
            MediaGenKind::ActionPolicy,
            MediaGenKind::WorldModel,
        ];
        for kind in all {
            let displayed = kind.to_string();
            let encoded = serde_json::to_string(&kind).expect("serialize");
            let encoded = encoded.trim_matches('"');

            assert_eq!(
                encoded, displayed,
                "{kind:?}: serde writes {encoded:?} but Display writes {displayed:?}"
            );
            assert_eq!(
                MediaGenKind::from_str_lossy(&displayed),
                Some(kind),
                "{kind:?}: its own display label does not parse back"
            );
            let decoded: MediaGenKind =
                serde_json::from_str(&format!("\"{displayed}\"")).expect("deserialize");
            assert_eq!(
                decoded, kind,
                "{kind:?}: serde round-trip changed the value"
            );

            // Labels are lowercase by convention; a stray capital is how the
            // original defect looked.
            assert_eq!(
                displayed,
                displayed.to_ascii_lowercase(),
                "{kind:?}: label {displayed:?} is not lowercase"
            );
        }
    }

    fn sample_params(kind: MediaGenKind) -> MediaGenParams {
        MediaGenParams {
            prompt: if kind.reads_prompt() {
                "a fox in a diorama".to_string()
            } else {
                String::new()
            },
            negative_prompt: None,
            width: 1024,
            height: 1024,
            num_frames: if kind.is_video() { Some(81) } else { None },
            fps: if kind.is_video() { Some(16) } else { None },
            steps: 30,
            guidance_scale: 4.5,
            voxel_resolution: None,
            audio_duration_secs: None,
            action_chunks: if kind.is_action() { Some(4) } else { None },
            session_hold_secs: if kind.is_world() { Some(30) } else { None },
            seed: None,
            inputs: match kind.input_roles().first() {
                Some(&role) if kind.requires_input() => vec![MediaGenInput {
                    role,
                    hash: Hash::new([7u8; 32]),
                }],
                _ => Vec::new(),
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
        assert!(!MediaGenKind::Text2Image.requires_input());
        assert!(MediaGenKind::Image2Image.requires_input());
        assert!(!MediaGenKind::Text2Video.requires_input());
        assert!(MediaGenKind::Image2Video.requires_input());
        assert!(MediaGenKind::Text2Video.is_video());
        assert!(MediaGenKind::Image2Video.is_video());
        assert!(!MediaGenKind::Text2Image.is_video());
    }

    #[test]
    fn an_image_to_3d_job_carries_no_prompt() {
        let kind = MediaGenKind::Image23d;
        let mut p = sample_params(kind);
        assert!(p.validate_for(kind).is_ok());
        p.prompt = "a fox".into();
        assert!(p.validate_for(kind).is_err(), "a prompt nothing reads");
        p.prompt.clear();
        assert!(
            p.validate_for(MediaGenKind::Text2Image).is_err(),
            "an empty prompt conditions no prompted kind"
        );
    }

    #[test]
    fn params_validate_text2image() {
        let p = sample_params(MediaGenKind::Text2Image);
        assert!(p.validate_for(MediaGenKind::Text2Image).is_ok());
    }

    #[test]
    fn params_validate_rejects_missing_input_image() {
        let mut p = sample_params(MediaGenKind::Image2Image);
        p.inputs.clear();
        let err = p.validate_for(MediaGenKind::Image2Image).unwrap_err();
        assert!(err.to_string().contains("inputs"), "{err}");
    }

    #[test]
    fn inputs_are_checked_against_the_kind() {
        let input = |role| MediaGenInput {
            role,
            hash: Hash::new([1u8; 32]),
        };
        let kind = MediaGenKind::Image2Video;
        let mut p = sample_params(kind);
        p.inputs = vec![
            input(MediaGenInputRole::FirstFrame),
            input(MediaGenInputRole::LastFrame),
        ];
        assert!(p.validate_for(kind).is_ok());
        p.inputs.push(input(MediaGenInputRole::FirstFrame));
        assert!(
            p.validate_for(kind)
                .unwrap_err()
                .to_string()
                .contains("only once")
        );
        p.inputs = vec![input(MediaGenInputRole::EditSource)];
        assert!(
            p.validate_for(kind)
                .unwrap_err()
                .to_string()
                .contains("not accepted")
        );

        let kind = MediaGenKind::Image2Image;
        let mut p = sample_params(kind);
        p.inputs = vec![input(MediaGenInputRole::Mask)];
        assert!(
            p.validate_for(kind).is_err(),
            "a mask alone conditions nothing"
        );
        p.inputs = vec![
            input(MediaGenInputRole::EditSource),
            input(MediaGenInputRole::EditSource),
            input(MediaGenInputRole::Mask),
        ];
        assert!(p.validate_for(kind).is_ok());
        p.inputs = vec![input(MediaGenInputRole::Reference); MAX_MEDIA_GEN_INPUTS + 1];
        assert!(
            p.validate_for(kind)
                .unwrap_err()
                .to_string()
                .contains("maximum")
        );

        let mut p = sample_params(MediaGenKind::Text2Image);
        p.inputs = vec![input(MediaGenInputRole::Reference)];
        assert!(
            p.validate_for(MediaGenKind::Text2Image).is_err(),
            "a prompt-only kind takes no inputs"
        );

        for role in [
            MediaGenInputRole::FirstFrame,
            MediaGenInputRole::Mask,
            MediaGenInputRole::Observation,
        ] {
            let json = serde_json::to_string(&role).unwrap();
            assert_eq!(json, format!("\"{role}\""));
            assert_eq!(MediaGenInputRole::from_str_lossy(role.as_str()), Some(role));
        }
    }

    #[test]
    fn params_validate_rejects_missing_video_fields() {
        let mut p = sample_params(MediaGenKind::Text2Video);
        p.num_frames = None;
        let err = p.validate_for(MediaGenKind::Text2Video).unwrap_err();
        assert!(err.to_string().contains("num_frames"), "{err}");
    }

    #[test]
    fn a_world_job_is_a_video_with_a_bounded_session_hold() {
        let kind = MediaGenKind::WorldModel;
        assert!(kind.is_world() && kind.is_video() && !kind.requires_input());
        assert_eq!(MediaGenKind::from_str_lossy("world-model"), Some(kind));
        assert!(sample_params(kind).validate_for(kind).is_ok());

        let mut p = sample_params(kind);
        p.session_hold_secs = Some(MAX_MEDIA_GEN_SESSION_HOLD_SECS + 1);
        assert!(
            p.validate_for(kind)
                .unwrap_err()
                .to_string()
                .contains("session_hold_secs")
        );
        let mut p = sample_params(kind);
        p.num_frames = None;
        assert!(
            p.validate_for(kind)
                .unwrap_err()
                .to_string()
                .contains("num_frames")
        );
    }

    #[test]
    fn action_policy_needs_an_observation_and_a_chunk_count() {
        let kind = MediaGenKind::ActionPolicy;
        assert!(kind.is_action() && kind.requires_input() && !kind.is_video());
        assert_eq!(kind.output_extension(), "json");
        assert!(sample_params(kind).validate_for(kind).is_ok());

        let mut p = sample_params(kind);
        p.action_chunks = None;
        assert!(
            p.validate_for(kind)
                .unwrap_err()
                .to_string()
                .contains("action_chunks")
        );
        p.action_chunks = Some(MAX_MEDIA_GEN_ACTION_CHUNKS + 1);
        assert!(
            p.validate_for(kind)
                .unwrap_err()
                .to_string()
                .contains("action_chunks")
        );
        let mut p = sample_params(kind);
        p.inputs.clear();
        assert!(
            p.validate_for(kind)
                .unwrap_err()
                .to_string()
                .contains("inputs")
        );
    }

    /// An autoregressive image model takes one step per image token:
    /// Janus-Pro predicts 576 tokens for a 384x384 image, all of them steps.
    #[test]
    fn an_autoregressive_image_models_token_count_is_a_valid_step_count() {
        let mut p = sample_params(MediaGenKind::Text2Image);
        p.width = 384;
        p.height = 384;
        p.steps = 576;
        assert!(p.validate_for(MediaGenKind::Text2Image).is_ok());
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
    }

    fn image_params() -> MediaGenParams {
        MediaGenParams {
            prompt: "a plaster diorama".to_string(),
            negative_prompt: None,
            width: 1024,
            height: 1024,
            num_frames: None,
            fps: None,
            steps: 30,
            guidance_scale: 4.5,
            voxel_resolution: None,
            audio_duration_secs: None,
            action_chunks: None,
            session_hold_secs: None,
            seed: None,
            inputs: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    fn video_params() -> MediaGenParams {
        MediaGenParams {
            num_frames: Some(81),
            fps: Some(16),
            width: 832,
            height: 480,
            ..image_params()
        }
    }

    /// Audio must not be priced on pixels. A text-to-audio request leaves
    /// width/height at their defaults, so quoting on area would charge every
    /// clip the same regardless of length.
    #[test]
    fn audio_is_priced_on_duration_not_area() {
        let mut short = image_params();
        short.audio_duration_secs = Some(5.0);
        let mut long = short.clone();
        long.audio_duration_secs = Some(300.0);

        let s = pixel_steps(MediaGenKind::Text2Audio, &short);
        let l = pixel_steps(MediaGenKind::Text2Audio, &long);
        assert_eq!(l, s * 60, "60x the audio should cost 60x, not the same");

        // And the identical params priced as an image must differ, or the
        // dispatch is not actually happening.
        assert_ne!(pixel_steps(MediaGenKind::Text2Image, &short), s);
    }

    /// Steps scale audio the same way they scale pixels, so one rate governs
    /// both.
    #[test]
    fn audio_scales_with_steps() {
        let mut p = image_params();
        p.audio_duration_secs = Some(10.0);
        let base = pixel_steps(MediaGenKind::Text2Audio, &p);
        p.steps *= 3;
        assert_eq!(pixel_steps(MediaGenKind::Text2Audio, &p), base * 3);
    }

    /// Absent duration falls back to a default rather than quoting zero.
    #[test]
    fn an_absent_duration_uses_the_default() {
        let mut p = image_params();
        p.audio_duration_secs = None;
        assert!(pixel_steps(MediaGenKind::Text2Audio, &p) > 0);
    }

    #[test]
    fn pixel_steps_scale_with_resolution_and_steps() {
        let p = image_params();
        assert_eq!(pixel_steps(MediaGenKind::Text2Image, &p), 1024 * 1024 * 30);

        let mut double_steps = p.clone();
        double_steps.steps = 60;
        assert_eq!(
            pixel_steps(MediaGenKind::Text2Image, &double_steps),
            2 * pixel_steps(MediaGenKind::Text2Image, &p)
        );
    }

    #[test]
    fn frames_only_count_for_video_kinds() {
        let v = video_params();
        assert_eq!(
            pixel_steps(MediaGenKind::Text2Video, &v),
            832 * 480 * 30 * 81
        );
        // The same params posted as an image job are one frame of work.
        assert_eq!(pixel_steps(MediaGenKind::Text2Image, &v), 832 * 480 * 30);
    }

    fn params(width: u32, height: u32, steps: u32, voxels: Option<u32>) -> MediaGenParams {
        MediaGenParams {
            prompt: "a bronze teapot".to_string(),
            negative_prompt: None,
            width,
            height,
            num_frames: None,
            fps: None,
            steps,
            guidance_scale: 7.5,
            voxel_resolution: voxels,
            audio_duration_secs: None,
            action_chunks: None,
            session_hold_secs: None,
            seed: None,
            inputs: Vec::new(),
            metadata: Default::default(),
        }
    }

    /// A 3D job is priced on the asset it produces, not the photo it was
    /// conditioned on. Two jobs from the same image at different grids must
    /// not cost the same.
    #[test]
    fn a_3d_job_is_priced_on_the_grid_not_the_conditioning_image() {
        let small = pixel_steps(MediaGenKind::Image23d, &params(1024, 1024, 25, Some(512)));
        let large = pixel_steps(MediaGenKind::Image23d, &params(1024, 1024, 25, Some(1536)));
        assert!(
            large > small,
            "a finer grid must cost more: {small} vs {large}"
        );
        assert_eq!(large / small, 9, "cost scales on the grid face, r²");
    }

    /// The pixel path must be untouched by the existence of 3D — an image job
    /// prices exactly as it did before.
    #[test]
    fn the_pixel_path_is_unchanged() {
        let p = params(1024, 1024, 30, None);
        assert_eq!(
            pixel_steps(MediaGenKind::Text2Image, &p),
            1024u128 * 1024 * 30
        );
        let mut v = params(1280, 720, 40, None);
        v.num_frames = Some(81);
        assert_eq!(
            pixel_steps(MediaGenKind::Text2Video, &v),
            1280u128 * 720 * 40 * 81
        );
    }

    /// A 3D job with no grid stated still prices, on a documented default,
    /// rather than collapsing to zero and being served for free.
    #[test]
    fn a_3d_job_without_a_grid_is_not_free() {
        let n = pixel_steps(MediaGenKind::Image23d, &params(1024, 1024, 25, None));
        assert_eq!(n, 512u128 * 512 * 25);
    }
}
