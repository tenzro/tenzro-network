//! Multi-modal AI client — the ONNX-backed runtimes on a Tenzro node.
//!
//! Covers forecast (timeseries), vision encoders, text embeddings,
//! click-driven segmentation, text-promptable segmentation, detection, audio
//! (ASR), and video.
//!
//! Every modality has the same surface shape: `list_*_catalog()` to browse
//! curated models, `load_*_model()` to bring one online, `unload_*_model()` to
//! drop it, and one inference verb.
//! [`crate::InferenceClient::list_loaded_models`] lists what is loaded, of
//! every type.
//!
//! Every catalog loader takes the same [`LoadModelParams`]: the catalog model
//! id and an optional visibility. The node fetches and verifies the files the
//! signed catalog entry names; every shape comes from the entry. The loader
//! enforces the entry's licence tier: the node refuses with JSON-RPC `-32010`
//! when the operator has not accepted that entry's terms. Acceptance is a
//! node-operator startup flag, never a client parameter.
//!
//! The runtimes are feature-gated. A node built without the `onnx` feature
//! answers every load and inference call with JSON-RPC `-32011`.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// ─── Generic shapes ──────────────────────────────────────────────────────

/// Result of a `load_*_model` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadModelResult {
    /// Id the model was registered under
    pub model_id: String,
    /// Whether the runtime holds it now
    #[serde(default)]
    pub loaded: bool,
}

/// Result of an `unload_*_model` call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnloadModelResult {
    /// Id that was asked for
    pub model_id: String,
    /// `false` when the runtime was not holding it
    #[serde(default)]
    pub removed: bool,
}

// ─── Forecast (timeseries) ───────────────────────────────────────────────

/// Curated forecast catalog entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForecastCatalogEntry {
    /// Catalog id, passed as `catalog_id` to the loader
    pub id: String,
    /// Human-readable name
    #[serde(default)]
    pub name: String,
    /// Input context window the graph expects
    #[serde(default)]
    pub context_length: u32,
    /// Longest horizon the graph predicts
    #[serde(default)]
    pub max_horizon: u32,
    /// `Permissive` / `Attribution` / `CommercialCustom` / `NonCommercial`
    #[serde(default)]
    pub license_tier: String,
    /// Commercial-use conditions the licence attaches, when it has any
    #[serde(default)]
    pub license_conditions: Option<String>,
    /// Whether the licence allows serving this model for pay
    #[serde(default)]
    pub paid_serving: bool,
    /// Remaining catalog fields
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Parameters for every catalog model load (`load_forecast_model`,
/// `load_vision_model`, `load_text_embedding_model`, `load_segmentation_model`,
/// `load_text_segmentation_model`, `load_detection_model`, `load_audio_model`).
///
/// The node fetches and verifies the files the signed catalog entry names;
/// every shape comes from the entry.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoadModelParams {
    /// Catalog model id
    pub model_id: String,
    /// `public`, `gated` or `private`. Omit to follow the node's visibility
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
}

/// Parameters for [`MultimodalClient::forecast`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ForecastParams {
    /// Loaded model id
    pub model_id: String,
    /// Observed series, oldest first
    pub history: Vec<f64>,
    /// Steps to predict
    pub horizon: u32,
    /// Quantile levels to return alongside the point forecast
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quantiles: Option<Vec<f64>>,
    /// Sampling interval of `history`, used for billing and for labelling the
    /// returned steps
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_seconds: Option<u64>,
    /// Verification level and provider pin.
    #[serde(flatten)]
    pub routing: TaskRouting,
}

// ─── Vision encoders (CLIP / SigLIP2 / DINOv3) ───────────────────────────

/// Curated vision-encoder catalog entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisionCatalogEntry {
    /// Catalog id
    pub id: String,
    /// Human-readable name
    #[serde(default)]
    pub name: String,
    /// Square input resolution
    #[serde(default)]
    pub input_size: u32,
    /// Output vector width
    #[serde(default)]
    pub embedding_dim: u32,
    /// `clip` / `imagenet` / `siglip`
    #[serde(default)]
    pub normalization: String,
    /// License tier
    #[serde(default)]
    pub license_tier: String,
    /// Commercial-use conditions the licence attaches, when it has any
    #[serde(default)]
    pub license_conditions: Option<String>,
    /// Whether the licence allows serving this model for pay
    #[serde(default)]
    pub paid_serving: bool,
    /// Remaining catalog fields
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Parameters for [`MultimodalClient::image_embed`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImageEmbedParams {
    /// Loaded model id
    pub model_id: String,
    /// Base64-encoded PNG / JPEG / WebP bytes
    pub image_base64: String,
    /// L2-normalize the returned vector
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalize: Option<bool>,
    /// Verification level and provider pin.
    #[serde(flatten)]
    pub routing: TaskRouting,
}

/// An embedding vector plus its width.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedResult {
    /// The vector
    #[serde(default)]
    pub embedding: Vec<f32>,
    /// Vector width
    #[serde(default)]
    pub dim: u32,
}

/// Cosine similarity between an image embedding and a text embedding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageTextSimilarityResult {
    /// Cosine similarity in `[-1, 1]`
    #[serde(default)]
    pub similarity: f32,
    /// Width of the vectors compared
    #[serde(default)]
    pub dim: u32,
}

// ─── Text embeddings ─────────────────────────────────────────────────────

/// Curated text-embedding catalog entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextEmbeddingCatalogEntry {
    /// Catalog id
    pub id: String,
    /// Human-readable name
    #[serde(default)]
    pub name: String,
    /// Full output width, before any Matryoshka truncation
    #[serde(default)]
    pub embedding_dim: u32,
    /// Whether the model was trained for prefix truncation
    #[serde(default)]
    pub supports_matryoshka: bool,
    /// License tier
    #[serde(default)]
    pub license_tier: String,
    /// Commercial-use conditions the licence attaches, when it has any
    #[serde(default)]
    pub license_conditions: Option<String>,
    /// Whether the licence allows serving this model for pay
    #[serde(default)]
    pub paid_serving: bool,
    /// Remaining catalog fields
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// One input to embed: text, a picture, a video given as frames, or any of
/// them together as one item. Pictures and video need a vision-language
/// embedder; their visual tokens are billed as input tokens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum EmbedInput {
    /// Text.
    Text(String),
    /// Text, a picture and/or a video, embedded as one item.
    Media {
        /// Text embedded with the media.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        /// Base64 picture bytes (PNG, JPEG or WebP).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        image: Option<String>,
        /// Base64 frames, in order.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        video: Option<Vec<String>>,
    },
}

impl EmbedInput {
    /// A picture, from its encoded bytes.
    pub fn image(bytes: &[u8]) -> Self {
        use base64::Engine as _;
        Self::Media {
            text: None,
            image: Some(base64::engine::general_purpose::STANDARD.encode(bytes)),
            video: None,
        }
    }

    /// A video, from its encoded frames in order.
    pub fn video<B: AsRef<[u8]>>(frames: &[B]) -> Self {
        use base64::Engine as _;
        Self::Media {
            text: None,
            image: None,
            video: Some(
                frames
                    .iter()
                    .map(|f| base64::engine::general_purpose::STANDARD.encode(f.as_ref()))
                    .collect(),
            ),
        }
    }

    /// The same input with its text set to `with` (embedded alongside any
    /// picture or video).
    pub fn with_text(self, with: impl Into<String>) -> Self {
        match self {
            Self::Text(_) => Self::Text(with.into()),
            Self::Media { image, video, .. } => Self::Media {
                text: Some(with.into()),
                image,
                video,
            },
        }
    }
}

impl From<String> for EmbedInput {
    fn from(text: String) -> Self {
        Self::Text(text)
    }
}

impl From<&str> for EmbedInput {
    fn from(text: &str) -> Self {
        Self::Text(text.to_string())
    }
}

/// One option of a [`DecisionQuestion::choice`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionOption {
    /// The key the answer names.
    pub key: String,
    /// What the option means: text, or any JSON value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<serde_json::Value>,
}

impl DecisionOption {
    /// An option with a description.
    pub fn new(key: impl Into<String>, description: impl Into<serde_json::Value>) -> Self {
        Self {
            key: key.into(),
            description: Some(description.into()),
        }
    }

    /// An option that is only a key.
    pub fn key(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            description: None,
        }
    }
}

/// A typed question for a decision model: yes/no, one choice out of several,
/// or a score on an ordered scale. Serializes to the shape `tenzro_decide`
/// takes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecisionQuestion {
    /// The id the answer is returned under; distinct within a request.
    pub id: String,
    /// `choice`, `score` or `noul` (yes/no).
    #[serde(rename = "type")]
    pub kind: String,
    /// What is asked: text, or any JSON value.
    pub instructions: serde_json::Value,
    /// The options (choice), the level descriptions (score) or the
    /// descriptions of the two answers (yes/no).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub criteria: Option<serde_json::Value>,
}

impl DecisionQuestion {
    /// A yes/no question; the answer is the probability of yes.
    pub fn yes_no(id: impl Into<String>, instructions: impl Into<serde_json::Value>) -> Self {
        Self {
            id: id.into(),
            kind: "noul".into(),
            instructions: instructions.into(),
            criteria: None,
        }
    }

    /// One choice out of `options` (at most 255), listed in this order.
    pub fn choice(
        id: impl Into<String>,
        instructions: impl Into<serde_json::Value>,
        options: &[DecisionOption],
    ) -> Self {
        Self {
            id: id.into(),
            kind: "choice".into(),
            instructions: instructions.into(),
            criteria: Some(serde_json::json!(options)),
        }
    }

    /// A score on an ordered scale of 2 to 10 levels, level 0 first.
    pub fn score(
        id: impl Into<String>,
        instructions: impl Into<serde_json::Value>,
        levels: &[serde_json::Value],
    ) -> Self {
        Self {
            id: id.into(),
            kind: "score".into(),
            instructions: instructions.into(),
            criteria: Some(serde_json::Value::Array(levels.to_vec())),
        }
    }
}

/// How a modality call is verified and which provider serves it. A call for
/// a model the node does not serve is forwarded to a provider offering it;
/// an `optimistic` answer may be re-executed on another provider, and a
/// mismatch is filed as a fault refunding the caller.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskRouting {
    /// `none`, `receipt`, `optimistic` or `tee`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<String>,
    /// Serve on this provider's offer (its payee address, hex).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
}

/// The opening of a streamed transcription.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TranscribeStreamParams {
    /// ASR model served by the node
    pub model_id: String,
    /// Samples per second of the streamed audio (8000 to 48000; 16000 when unset)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sample_rate: Option<u32>,
    /// Language ISO code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// Verification level for each final segment: `none`, `receipt`,
    /// `optimistic` or `tee`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<String>,
}

/// One event of a streamed transcription: `partial`, `final`, `done` or
/// `error`, with its data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SttStreamEvent {
    pub event: String,
    pub data: serde_json::Value,
}

/// Parameters for [`MultimodalClient::text_embed`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TextEmbedParams {
    /// Loaded model id
    pub model_id: String,
    /// Inputs to embed, one vector returned per input
    pub inputs: Vec<EmbedInput>,
    /// Matryoshka truncation width (Qwen3-Embedding, EmbeddingGemma)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requested_dim: Option<u32>,
    /// L2-normalize each vector. Re-normalization after truncation is what
    /// makes a truncated vector comparable to a full-width one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalize: Option<bool>,
    /// Verification level and provider pin.
    #[serde(flatten)]
    pub routing: TaskRouting,
}

/// One vector per input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextEmbedResult {
    /// Vectors, in input order
    #[serde(default)]
    pub embeddings: Vec<Vec<f32>>,
    /// Width of each vector
    #[serde(default)]
    pub dim: u32,
}

// ─── Segmentation (SAM 2 / EdgeSAM / MobileSAM) ─────────────────────────

/// Curated segmentation catalog entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentationCatalogEntry {
    /// Catalog id
    pub id: String,
    /// Human-readable name
    #[serde(default)]
    pub name: String,
    /// Decoder ABI: `sam1` or `sam2`
    #[serde(default)]
    pub family: String,
    /// License tier
    #[serde(default)]
    pub license_tier: String,
    /// Commercial-use conditions the licence attaches, when it has any
    #[serde(default)]
    pub license_conditions: Option<String>,
    /// Whether the licence allows serving this model for pay
    #[serde(default)]
    pub paid_serving: bool,
    /// Remaining catalog fields
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// A point anchoring the mask to a pixel. `is_foreground` distinguishes "this
/// is the object" from "this is background".
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PointPrompt {
    /// Pixel column in the original image
    pub x: f32,
    /// Pixel row in the original image
    pub y: f32,
    /// `true` includes the point in the object, `false` excludes it
    pub is_foreground: bool,
}

/// Prompt for [`MultimodalClient::segment`]. Coordinates are original-image
/// pixels — the runtime scales them into encoder space itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SegmentPrompt {
    /// A single point
    Point {
        /// Pixel column
        x: f32,
        /// Pixel row
        y: f32,
        /// Foreground or background
        is_foreground: bool,
    },
    /// A corner-pair box
    Box {
        /// Left
        x0: f32,
        /// Top
        y0: f32,
        /// Right
        x1: f32,
        /// Bottom
        y1: f32,
    },
    /// Several points at once, mixing foreground and background
    Points {
        /// The points
        points: Vec<PointPrompt>,
    },
}

/// Parameters for [`MultimodalClient::segment`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SegmentParams {
    /// Loaded model id
    pub model_id: String,
    /// Base64-encoded PNG / JPEG / WebP bytes
    pub image_base64: String,
    /// Where to anchor the mask
    pub prompts: Vec<SegmentPrompt>,
    /// Verification level and provider pin.
    #[serde(flatten)]
    pub routing: TaskRouting,
}

// ─── Text-promptable segmentation (SAM 3 / SAM 3.1) ─────────────────────

/// Curated text-promptable segmentation catalog entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TextSegmentationCatalogEntry {
    /// Catalog id
    pub id: String,
    /// Human-readable name
    #[serde(default)]
    pub name: String,
    /// License tier
    #[serde(default)]
    pub license_tier: String,
    /// Commercial-use conditions the licence attaches, when it has any
    #[serde(default)]
    pub license_conditions: Option<String>,
    /// Whether the licence allows serving this model for pay
    #[serde(default)]
    pub paid_serving: bool,
    /// Remaining catalog fields
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Box prompt for [`MultimodalClient::text_segment`] — centre plus extent,
/// unlike the corner pairs the click-driven [`SegmentPrompt::Box`] takes.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TextSegmentBoxPrompt {
    /// Centre column
    pub cx: f32,
    /// Centre row
    pub cy: f32,
    /// Width
    pub w: f32,
    /// Height
    pub h: f32,
}

/// Parameters for [`MultimodalClient::text_segment`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TextSegmentParams {
    /// Loaded model id
    pub model_id: String,
    /// Base64-encoded PNG / JPEG / WebP bytes
    pub image_base64: String,
    /// Free-text label, e.g. `"dog"`. Pass `""` together with `box_prompt` to
    /// run box-only mode.
    pub text_prompt: String,
    /// Restrict the search to one region
    #[serde(skip_serializing_if = "Option::is_none")]
    pub box_prompt: Option<TextSegmentBoxPrompt>,
    /// Defaults to 0.5
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score_threshold: Option<f32>,
    /// Verification level and provider pin.
    #[serde(flatten)]
    pub routing: TaskRouting,
}

// ─── Detection (RF-DETR, D-FINE) ─────────────────────────────────────────

/// Curated detection catalog entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionCatalogEntry {
    /// Catalog id
    pub id: String,
    /// Human-readable name
    #[serde(default)]
    pub name: String,
    /// Post-processing ABI: `rf_detr` or `d_fine`
    #[serde(default)]
    pub family: String,
    /// Size of the label space the graph indexes
    #[serde(default)]
    pub num_classes: u32,
    /// Square input resolution
    #[serde(default)]
    pub input_size: u32,
    /// License tier
    #[serde(default)]
    pub license_tier: String,
    /// Commercial-use conditions the licence attaches, when it has any
    #[serde(default)]
    pub license_conditions: Option<String>,
    /// Whether the licence allows serving this model for pay
    #[serde(default)]
    pub paid_serving: bool,
    /// Remaining catalog fields
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Parameters for [`MultimodalClient::detect`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DetectParams {
    /// Loaded model id
    pub model_id: String,
    /// Base64-encoded PNG / JPEG / WebP bytes
    pub image_base64: String,
    /// Drop boxes scoring below this. Defaults to 0.25
    #[serde(skip_serializing_if = "Option::is_none")]
    pub score_threshold: Option<f32>,
    /// Verification level and provider pin.
    #[serde(flatten)]
    pub routing: TaskRouting,
}

/// One detected object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detection {
    /// `[x0, y0, x1, y1]` in original-image pixels
    pub bbox: [f32; 4],
    /// Index into the model's label space
    pub label_id: u32,
    /// Class label, when the model was loaded with a labels file
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Confidence in `[0, 1]`
    pub score: f32,
}

/// `tenzro_detect`: the objects found, with what the call cost.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectResult {
    /// The detections, best first
    pub detections: Vec<Detection>,
    /// Inference time, ms
    #[serde(default)]
    pub generation_time_ms: u64,
    /// What the call cost, wei, decimal string; absent when it was free
    #[serde(default)]
    pub cost_wei: Option<String>,
    /// Billed units
    #[serde(default)]
    pub units: Option<serde_json::Value>,
    /// How the cost settled
    #[serde(default)]
    pub settlement: Option<serde_json::Value>,
}

// ─── Audio ASR ───────────────────────────────────────────────────────────

/// Curated audio (ASR) catalog entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioCatalogEntry {
    /// Catalog id
    pub id: String,
    /// Human-readable name
    #[serde(default)]
    pub name: String,
    /// Decoder pipeline: `moonshine` / `whisper` / `parakeet` / `canary`
    #[serde(default)]
    pub family: String,
    /// Longest clip the graph accepts in one pass
    #[serde(default)]
    pub max_audio_seconds: u32,
    /// License tier
    #[serde(default)]
    pub license_tier: String,
    /// Commercial-use conditions the licence attaches, when it has any
    #[serde(default)]
    pub license_conditions: Option<String>,
    /// Whether the licence allows serving this model for pay
    #[serde(default)]
    pub paid_serving: bool,
    /// Remaining catalog fields
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Parameters for [`MultimodalClient::transcribe`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TranscribeParams {
    /// Loaded model id
    pub model_id: String,
    /// Base64-encoded WAV / FLAC / MP3 bytes
    pub audio_base64: String,
    /// BCP-47 hint for multilingual graphs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub language: Option<String>,
    /// Return per-segment timings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamps: Option<bool>,
    /// Decoding temperature
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    /// Verification level and provider pin.
    #[serde(flatten)]
    pub routing: TaskRouting,
}

// ─── Video ───────────────────────────────────────────────────────────────

/// Curated video catalog entry. These describe the reference clip encoders;
/// [`MultimodalClient::load_video_model`] composes over an image encoder
/// instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoCatalogEntry {
    /// Catalog id
    pub id: String,
    /// Human-readable name
    #[serde(default)]
    pub name: String,
    /// License tier
    #[serde(default)]
    pub license_tier: String,
    /// Commercial-use conditions the licence attaches, when it has any
    #[serde(default)]
    pub license_conditions: Option<String>,
    /// Whether the licence allows serving this model for pay
    #[serde(default)]
    pub paid_serving: bool,
    /// Remaining catalog fields
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Parameters for [`MultimodalClient::load_video_model`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoadVideoModelParams {
    /// Id to register the clip encoder under
    pub model_id: String,
    /// Id of an image encoder already online via
    /// [`MultimodalClient::load_vision_model`]
    pub vision_model_id: String,
    /// Frames to sample per clip. Defaults to 8, clamped to `1..=128`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_frames: Option<u32>,
    /// `public`, `gated` or `private`. Omit to follow the node's visibility
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visibility: Option<String>,
}

/// Parameters for [`MultimodalClient::video_embed`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VideoEmbedParams {
    /// Loaded clip-encoder id
    pub model_id: String,
    /// Base64-encoded video container bytes
    pub video_base64: String,
    /// L2-normalize the pooled vector
    #[serde(skip_serializing_if = "Option::is_none")]
    pub normalize: Option<bool>,
    /// Keep every `frame_stride`-th decoded frame instead of spreading the
    /// samples evenly across the clip. Still capped at the `num_frames` the
    /// clip encoder was registered with, so a tight stride surveys the opening
    /// of the clip rather than the whole of it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame_stride: Option<u32>,
    /// Verification level and provider pin.
    #[serde(flatten)]
    pub routing: TaskRouting,
}

// ─── Client ──────────────────────────────────────────────────────────────

/// Client for the ONNX-backed multi-modal runtimes on a Tenzro node.
///
/// # Example
///
/// ```no_run
/// # use tenzro_sdk::{TenzroClient, config::SdkConfig};
/// # use tenzro_sdk::multimodal::{LoadModelParams, ImageEmbedParams};
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
/// let mm = client.multimodal();
///
/// // Browse what the node curates, then bring one online by its catalog id.
/// // The node fetches and verifies the files the signed entry names.
/// let catalog = mm.list_vision_catalog().await?;
/// println!("{} vision encoders curated", catalog.models.len());
///
/// mm.load_vision_model(&LoadModelParams {
///     model_id: "clip-vit-b32".into(),
///     visibility: Some("gated".into()),
/// })
/// .await?;
///
/// let embedded = mm
///     .image_embed(&ImageEmbedParams {
///         model_id: "clip-vit-b32".into(),
///         image_base64: "<base64 png>".into(),
///         normalize: Some(true),
///         ..Default::default()
///     })
///     .await?;
/// println!("{}-dim vector", embedded.dim);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct MultimodalClient {
    rpc: Arc<RpcClient>,
}

/// Curated entries for one modality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogList<T> {
    /// The entries
    #[serde(default = "Vec::new")]
    pub models: Vec<T>,
}

impl MultimodalClient {
    /// Creates a new multi-modal client.
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    // ── Forecast ──

    /// Lists the curated forecast (timeseries) models.
    pub async fn list_forecast_catalog(&self) -> SdkResult<CatalogList<ForecastCatalogEntry>> {
        self.rpc
            .call("tenzro_listForecastCatalog", serde_json::json!([]))
            .await
    }

    /// Brings a catalog forecast model online.
    pub async fn load_forecast_model(
        &self,
        params: &LoadModelParams,
    ) -> SdkResult<LoadModelResult> {
        self.rpc
            .call("tenzro_loadForecastModel", serde_json::json!([params]))
            .await
    }

    /// Drops a forecast model from memory.
    pub async fn unload_forecast_model(&self, model_id: &str) -> SdkResult<UnloadModelResult> {
        self.rpc
            .call(
                "tenzro_unloadForecastModel",
                serde_json::json!([{ "model_id": model_id }]),
            )
            .await
    }

    /// Predicts `horizon` steps beyond the supplied `history`.
    pub async fn forecast(&self, params: &ForecastParams) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_forecast", serde_json::json!([params]))
            .await
    }

    // ── Vision ──

    /// Lists the curated vision encoders.
    pub async fn list_vision_catalog(&self) -> SdkResult<CatalogList<VisionCatalogEntry>> {
        self.rpc
            .call("tenzro_listVisionCatalog", serde_json::json!([]))
            .await
    }

    /// Brings a catalog vision encoder online.
    pub async fn load_vision_model(&self, params: &LoadModelParams) -> SdkResult<LoadModelResult> {
        self.rpc
            .call("tenzro_loadVisionModel", serde_json::json!([params]))
            .await
    }

    /// Drops a vision encoder from memory.
    pub async fn unload_vision_model(&self, model_id: &str) -> SdkResult<UnloadModelResult> {
        self.rpc
            .call(
                "tenzro_unloadVisionModel",
                serde_json::json!([{ "model_id": model_id }]),
            )
            .await
    }

    /// Embeds one image.
    pub async fn image_embed(&self, params: &ImageEmbedParams) -> SdkResult<EmbedResult> {
        self.rpc
            .call("tenzro_imageEmbed", serde_json::json!([params]))
            .await
    }

    /// Cosine similarity between an image embedding and a text embedding of
    /// the same dimension, as `{ similarity, dim }`. Embed the image with
    /// [`Self::image_embed`] and the text with [`Self::text_embed`] on a
    /// paired model (the CLIP and SigLIP2 entries); the node compares the
    /// vectors and runs no model.
    pub async fn image_text_similarity(
        &self,
        image_embedding: &[f32],
        text_embedding: &[f32],
    ) -> SdkResult<ImageTextSimilarityResult> {
        self.rpc
            .call(
                "tenzro_imageTextSimilarity",
                serde_json::json!({
                    "image_embedding": image_embedding,
                    "text_embedding": text_embedding,
                }),
            )
            .await
    }

    // ── Text embeddings ──

    /// Lists the curated text-embedding models.
    pub async fn list_text_embedding_catalog(
        &self,
    ) -> SdkResult<CatalogList<TextEmbeddingCatalogEntry>> {
        self.rpc
            .call("tenzro_listTextEmbeddingCatalog", serde_json::json!([]))
            .await
    }

    /// Brings a catalog text-embedding model online.
    pub async fn load_text_embedding_model(
        &self,
        params: &LoadModelParams,
    ) -> SdkResult<LoadModelResult> {
        self.rpc
            .call("tenzro_loadTextEmbeddingModel", serde_json::json!([params]))
            .await
    }

    /// Drops a text-embedding model from memory.
    pub async fn unload_text_embedding_model(
        &self,
        model_id: &str,
    ) -> SdkResult<UnloadModelResult> {
        self.rpc
            .call(
                "tenzro_unloadTextEmbeddingModel",
                serde_json::json!([{ "model_id": model_id }]),
            )
            .await
    }

    /// Embeds a batch of texts, one vector per input.
    pub async fn text_embed(&self, params: &TextEmbedParams) -> SdkResult<TextEmbedResult> {
        self.rpc
            .call("tenzro_textEmbed", serde_json::json!([params]))
            .await
    }

    // ── Segmentation ──

    /// Lists the curated click-driven segmentation models.
    pub async fn list_segmentation_catalog(
        &self,
    ) -> SdkResult<CatalogList<SegmentationCatalogEntry>> {
        self.rpc
            .call("tenzro_listSegmentationCatalog", serde_json::json!([]))
            .await
    }

    /// Brings a catalog segmentation model online.
    pub async fn load_segmentation_model(
        &self,
        params: &LoadModelParams,
    ) -> SdkResult<LoadModelResult> {
        self.rpc
            .call("tenzro_loadSegmentationModel", serde_json::json!([params]))
            .await
    }

    /// Drops a segmentation model from memory.
    pub async fn unload_segmentation_model(&self, model_id: &str) -> SdkResult<UnloadModelResult> {
        self.rpc
            .call(
                "tenzro_unloadSegmentationModel",
                serde_json::json!([{ "model_id": model_id }]),
            )
            .await
    }

    /// Produces masks for the prompted regions of an image.
    pub async fn segment(&self, params: &SegmentParams) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_segment", serde_json::json!([params]))
            .await
    }

    // ── Text-promptable segmentation ──

    /// Lists the curated text-promptable segmentation models.
    pub async fn list_text_segmentation_catalog(
        &self,
    ) -> SdkResult<CatalogList<TextSegmentationCatalogEntry>> {
        self.rpc
            .call("tenzro_listTextSegmentationCatalog", serde_json::json!([]))
            .await
    }

    /// Brings a catalog text-promptable segmentation model online.
    pub async fn load_text_segmentation_model(
        &self,
        params: &LoadModelParams,
    ) -> SdkResult<LoadModelResult> {
        self.rpc
            .call(
                "tenzro_loadTextSegmentationModel",
                serde_json::json!([params]),
            )
            .await
    }

    /// Drops a text-promptable segmentation model from memory.
    pub async fn unload_text_segmentation_model(
        &self,
        model_id: &str,
    ) -> SdkResult<UnloadModelResult> {
        self.rpc
            .call(
                "tenzro_unloadTextSegmentationModel",
                serde_json::json!([{ "model_id": model_id }]),
            )
            .await
    }

    /// Segments every instance matching a free-text label — open-vocabulary,
    /// so the label need not come from a fixed class list.
    pub async fn text_segment(&self, params: &TextSegmentParams) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_textSegment", serde_json::json!([params]))
            .await
    }

    // ── Detection ──

    /// Lists the curated detection models.
    pub async fn list_detection_catalog(&self) -> SdkResult<CatalogList<DetectionCatalogEntry>> {
        self.rpc
            .call("tenzro_listDetectionCatalog", serde_json::json!([]))
            .await
    }

    /// Brings a catalog detection model online.
    pub async fn load_detection_model(
        &self,
        params: &LoadModelParams,
    ) -> SdkResult<LoadModelResult> {
        self.rpc
            .call("tenzro_loadDetectionModel", serde_json::json!([params]))
            .await
    }

    /// Drops a detection model from memory.
    pub async fn unload_detection_model(&self, model_id: &str) -> SdkResult<UnloadModelResult> {
        self.rpc
            .call(
                "tenzro_unloadDetectionModel",
                serde_json::json!([{ "model_id": model_id }]),
            )
            .await
    }

    /// Locates objects in an image. Both families are NMS-free, so the boxes
    /// come back ready to use.
    pub async fn detect(&self, params: &DetectParams) -> SdkResult<DetectResult> {
        self.rpc
            .call("tenzro_detect", serde_json::json!([params]))
            .await
    }

    // ── Rerank ──

    /// Lists the reranker catalog.
    pub async fn list_rerank_catalog(&self) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_listRerankCatalog", serde_json::json!([]))
            .await
    }

    /// Brings a catalog reranker online.
    pub async fn load_rerank_model(&self, params: &LoadModelParams) -> SdkResult<LoadModelResult> {
        self.rpc
            .call("tenzro_loadRerankModel", serde_json::json!([params]))
            .await
    }

    /// Drops a reranker from memory.
    pub async fn unload_rerank_model(&self, model_id: &str) -> SdkResult<UnloadModelResult> {
        self.rpc
            .call(
                "tenzro_unloadRerankModel",
                serde_json::json!([{ "model_id": model_id }]),
            )
            .await
    }

    /// Scores `documents` against `query`, best first: `{ results: [{ index,
    /// relevance_score, document? }], units, cost_wei, settlement,
    /// tenzro_receipt }`. The query and every document take the embedding
    /// input shape ([`EmbedInput`]); pictures and video need a
    /// vision-language reranker. Billed per (query, document) pair.
    pub async fn rerank(
        &self,
        model_id: &str,
        query: &EmbedInput,
        documents: &[EmbedInput],
        top_n: Option<u64>,
        routing: &TaskRouting,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_rerank",
                serde_json::json!([{
                    "model_id": model_id,
                    "query": query,
                    "documents": documents,
                    "top_n": top_n,
                    "verification": routing.verification,
                    "provider": routing.provider,
                }]),
            )
            .await
    }

    // ── Decision ──

    /// Lists the decision-model catalog.
    pub async fn list_decision_catalog(&self) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_listDecisionCatalog", serde_json::json!([]))
            .await
    }

    /// Brings a catalog decision model online.
    pub async fn load_decision_model(
        &self,
        params: &LoadModelParams,
    ) -> SdkResult<LoadModelResult> {
        self.rpc
            .call("tenzro_loadDecisionModel", serde_json::json!([params]))
            .await
    }

    /// Drops a decision model from memory.
    pub async fn unload_decision_model(&self, model_id: &str) -> SdkResult<UnloadModelResult> {
        self.rpc
            .call(
                "tenzro_unloadDecisionModel",
                serde_json::json!([{ "model_id": model_id }]),
            )
            .await
    }

    /// Answers typed `questions` (1 to 64) about `state`, in one forward pass
    /// and without generating text: `{ answers: [{ id, type, choice?, score?,
    /// noul?, probabilities?, confidence?, legend? }], usage, units,
    /// cost_wei, settlement, tenzro_receipt }`, in request order. `state` is
    /// text or any JSON value. Billed per question answered.
    pub async fn decide(
        &self,
        model_id: &str,
        state: &serde_json::Value,
        questions: &[DecisionQuestion],
        routing: &TaskRouting,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_decide",
                serde_json::json!([{
                    "model_id": model_id,
                    "state": state,
                    "questions": questions,
                    "verification": routing.verification,
                    "provider": routing.provider,
                }]),
            )
            .await
    }

    // ── Training ──

    /// Loads a downloaded catalog language model for LoRA training on the
    /// node's CUDA device. Operator only.
    pub async fn load_training_model(&self, model_id: &str) -> SdkResult<LoadModelResult> {
        self.rpc
            .call(
                "tenzro_loadTrainingModel",
                serde_json::json!({ "model_id": model_id }),
            )
            .await
    }

    /// Drops a model loaded for training. Operator only.
    pub async fn unload_training_model(&self, model_id: &str) -> SdkResult<UnloadModelResult> {
        self.rpc
            .call(
                "tenzro_unloadTrainingModel",
                serde_json::json!({ "model_id": model_id }),
            )
            .await
    }

    /// Runs one supervised LoRA round. `params` is `{ model_id, recipe,
    /// records: [{ prompt, completion }], sample_seed, steps, adapter_seed,
    /// start?: { state_uri, start_root, steps_taken }, verification? }`.
    /// Answers with the round's commitment and roots, each step's loss, the
    /// adapter's SHA-256 and URI, `result_digest` with the machine's
    /// attestation, the units billed and the signed receipt. Operator only.
    pub async fn train_round(&self, params: &serde_json::Value) -> SdkResult<serde_json::Value> {
        self.rpc.call("tenzro_trainRound", params.clone()).await
    }

    // ── Speech synthesis ──

    /// Brings a catalog speech model online.
    pub async fn load_speech_model(&self, params: &LoadModelParams) -> SdkResult<LoadModelResult> {
        self.rpc
            .call("tenzro_loadSpeechModel", serde_json::json!([params]))
            .await
    }

    /// Drops a speech model from memory.
    pub async fn unload_speech_model(&self, model_id: &str) -> SdkResult<UnloadModelResult> {
        self.rpc
            .call(
                "tenzro_unloadSpeechModel",
                serde_json::json!([{ "model_id": model_id }]),
            )
            .await
    }

    /// Speaks `input`: `{ audio_base64 (WAV), audio_sha256, envelope (RMS
    /// of each 20 ms window), sample_rate, duration_ms, units, cost_wei,
    /// settlement, tenzro_receipt }`.
    pub async fn speak(
        &self,
        model_id: &str,
        input: &str,
        language: Option<&str>,
        seed: Option<u32>,
        routing: &TaskRouting,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_speak",
                serde_json::json!([{
                    "model_id": model_id,
                    "input": input,
                    "language": language,
                    "seed": seed,
                    "verification": routing.verification,
                    "provider": routing.provider,
                }]),
            )
            .await
    }

    // ── Audio ──

    /// Lists the curated audio (ASR) models.
    pub async fn list_audio_catalog(&self) -> SdkResult<CatalogList<AudioCatalogEntry>> {
        self.rpc
            .call("tenzro_listAudioCatalog", serde_json::json!([]))
            .await
    }

    /// Brings a catalog speech-recognition model online.
    pub async fn load_audio_model(&self, params: &LoadModelParams) -> SdkResult<LoadModelResult> {
        self.rpc
            .call("tenzro_loadAudioModel", serde_json::json!([params]))
            .await
    }

    /// Drops an ASR model from memory.
    pub async fn unload_audio_model(&self, model_id: &str) -> SdkResult<UnloadModelResult> {
        self.rpc
            .call(
                "tenzro_unloadAudioModel",
                serde_json::json!([{ "model_id": model_id }]),
            )
            .await
    }

    /// Transcribes audio to text.
    pub async fn transcribe(&self, params: &TranscribeParams) -> SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_transcribe", serde_json::json!([params]))
            .await
    }

    // ── Video ──

    /// Lists the V-JEPA 2 entries the node knows about. They describe the
    /// reference clip encoders; [`MultimodalClient::load_video_model`]
    /// composes over an image encoder instead.
    pub async fn list_video_catalog(&self) -> SdkResult<CatalogList<VideoCatalogEntry>> {
        self.rpc
            .call("tenzro_listVideoCatalog", serde_json::json!([]))
            .await
    }

    /// Registers a clip encoder over an image encoder that
    /// [`MultimodalClient::load_vision_model`] has already brought online.
    /// Each call samples `num_frames` frames, embeds them through that
    /// encoder, and mean-pools. The node answers JSON-RPC `-32004` when
    /// `vision_model_id` names an encoder it has not loaded.
    pub async fn load_video_model(
        &self,
        params: &LoadVideoModelParams,
    ) -> SdkResult<LoadModelResult> {
        self.rpc
            .call("tenzro_loadVideoModel", serde_json::json!([params]))
            .await
    }

    /// Drops a clip encoder from memory. The image encoder underneath it stays
    /// loaded.
    pub async fn unload_video_model(&self, model_id: &str) -> SdkResult<UnloadModelResult> {
        self.rpc
            .call(
                "tenzro_unloadVideoModel",
                serde_json::json!([{ "model_id": model_id }]),
            )
            .await
    }

    /// Transcribes live audio as it is captured, over the realtime
    /// transport (`/tenzro/realtime/transcribe`). `chunks` yields mono
    /// 16-bit samples at `params.sample_rate`. The returned stream carries
    /// `partial` transcripts of the open segment, `final` segments committed
    /// at pauses (each billed by the second of audio and receipted), then
    /// `done`. The node must serve the model.
    pub async fn transcribe_stream<S>(
        &self,
        params: &TranscribeStreamParams,
        chunks: S,
    ) -> SdkResult<impl futures::Stream<Item = SttStreamEvent> + use<S>>
    where
        S: futures::Stream<Item = Vec<i16>> + Send + 'static,
    {
        use base64::Engine as _;
        use futures::StreamExt;
        let mut opening = serde_json::to_vec(params).unwrap_or_default();
        opening.push(b'\n');
        let lines = futures::stream::once(async move { opening }).chain(chunks.map(|samples| {
            let bytes: Vec<u8> = samples.iter().flat_map(|s| s.to_le_bytes()).collect();
            let mut line = serde_json::to_vec(&serde_json::json!({
                "pcm_s16le_base64": base64::engine::general_purpose::STANDARD.encode(bytes),
            }))
            .unwrap_or_default();
            line.push(b'\n');
            line
        }));
        let body = reqwest::Body::wrap_stream(lines.map(Ok::<_, std::io::Error>));
        let response = self
            .rpc
            .post_body_stream("/tenzro/realtime/transcribe", body)
            .await?;
        let mut decoder = crate::sse::SseDecoder::new();
        Ok(response
            .bytes_stream()
            .map(move |chunk| match chunk {
                Ok(bytes) => decoder.push(&bytes),
                Err(e) => vec![crate::sse::SseEvent {
                    event: Some("error".to_string()),
                    data: serde_json::json!({ "message": e.to_string() }).to_string(),
                    id: None,
                }],
            })
            .flat_map(futures::stream::iter)
            .map(|e| SttStreamEvent {
                event: e.event.unwrap_or_else(|| "message".to_string()),
                data: serde_json::from_str(&e.data).unwrap_or(serde_json::Value::String(e.data)),
            }))
    }

    /// Embeds a video clip into a single pooled vector. Frames are decoded on
    /// the node, in process.
    pub async fn video_embed(&self, params: &VideoEmbedParams) -> SdkResult<EmbedResult> {
        self.rpc
            .call("tenzro_videoEmbed", serde_json::json!([params]))
            .await
    }
}

impl MultimodalClient {
    /// Calls `tenzro_listTtsCatalog`: list tts catalog.
    pub async fn list_tts_catalog(&self) -> crate::error::SdkResult<serde_json::Value> {
        self.rpc
            .call("tenzro_listTtsCatalog", serde_json::json!({}))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_prompt_tags_on_type() {
        let point = serde_json::to_value(SegmentPrompt::Point {
            x: 12.0,
            y: 34.0,
            is_foreground: true,
        })
        .unwrap();
        assert_eq!(point["type"], "point");
        assert_eq!(point["is_foreground"], true);

        let boxed = serde_json::to_value(SegmentPrompt::Box {
            x0: 1.0,
            y0: 2.0,
            x1: 3.0,
            y1: 4.0,
        })
        .unwrap();
        assert_eq!(boxed["type"], "box");
    }

    /// A load carries only the catalog id and, when set, the visibility: the
    /// node refuses any other parameter.
    #[test]
    fn a_load_sends_the_model_id_and_visibility_only() {
        let bare = serde_json::to_value(LoadModelParams {
            model_id: "clip-vit-b32".into(),
            visibility: None,
        })
        .unwrap();
        assert_eq!(bare, serde_json::json!({ "model_id": "clip-vit-b32" }));

        let gated = serde_json::to_value(LoadModelParams {
            model_id: "clip-vit-b32".into(),
            visibility: Some("gated".into()),
        })
        .unwrap();
        assert_eq!(
            gated,
            serde_json::json!({ "model_id": "clip-vit-b32", "visibility": "gated" })
        );
    }
}
