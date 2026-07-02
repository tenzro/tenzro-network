//! AI Model inference types for Tenzro Network
//!
//! This module defines types for AI model registration, inference requests,
//! and provider management.

use crate::primitives::{Address, Hash, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Information about an AI model on Tenzro Network
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelInfo {
    /// Unique model identifier
    pub model_id: String,
    /// Model name
    pub name: String,
    /// Model version
    pub version: String,
    /// Model description
    pub description: String,
    /// Model modality
    pub modality: ModelModality,
    /// Model architecture
    pub architecture: String,
    /// Model provider/creator
    pub provider: Address,
    /// Model hash for verification
    pub model_hash: Hash,
    /// Model parameters
    pub parameters: ModelParameters,
    /// Model pricing
    pub pricing: PricingConfig,
    /// Model status
    pub status: ModelStatus,
    /// Model metadata
    pub metadata: HashMap<String, String>,
    /// Mixture-of-Experts routing metadata (optional).
    ///
    /// Populated for MoE architectures (Mixtral, DeepSeek-V2/V3, Qwen2-MoE,
    /// OpenMythos RDT-MoE, etc.) to enable routing schedulers to reason
    /// about expert utilization, per-token expert selection cost, and
    /// specialization-aware dispatch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moe: Option<MoeMetadata>,
    /// Timeseries-specific parameters (forecast horizon, context length, …).
    /// Populated only when `modality == Timeseries`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeseries: Option<TimeseriesParameters>,
    /// Vision encoder parameters (input size, embedding dim, normalization).
    /// Populated for `Image` and image-bearing compound modalities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vision: Option<VisionParameters>,
    /// Audio model parameters (sample rate, encoder/decoder filenames, langs).
    /// Populated for `Audio` and audio-bearing compound modalities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio: Option<AudioParameters>,
    /// Video model parameters (frame size, num frames, fps, embedding dim).
    /// Populated for `Video` modality.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub video: Option<VideoParameters>,
}

impl ModelInfo {
    /// Creates a new model info
    pub fn new(
        model_id: String,
        name: String,
        version: String,
        modality: ModelModality,
        provider: Address,
    ) -> Self {
        Self {
            model_id,
            name,
            version,
            description: String::new(),
            modality,
            architecture: String::new(),
            provider,
            model_hash: Hash::zero(),
            parameters: ModelParameters::default(),
            pricing: PricingConfig::default(),
            status: ModelStatus::Pending,
            metadata: HashMap::new(),
            moe: None,
            timeseries: None,
            vision: None,
            audio: None,
            video: None,
        }
    }

    /// Declares the model as a Mixture-of-Experts architecture and
    /// attaches routing metadata.
    pub fn with_moe(mut self, moe: MoeMetadata) -> Self {
        self.moe = Some(moe);
        self
    }

    /// Attach timeseries-specific parameters (forecast horizon, context
    /// length, etc.). Should only be set when `modality == Timeseries`.
    pub fn with_timeseries(mut self, params: TimeseriesParameters) -> Self {
        self.timeseries = Some(params);
        self
    }

    /// Attach vision-encoder parameters (input size, embedding dim,
    /// normalization). Should be set for image and image-bearing compound
    /// modalities.
    pub fn with_vision(mut self, params: VisionParameters) -> Self {
        self.vision = Some(params);
        self
    }

    /// Attach audio-model parameters (sample rate, ONNX bundle filenames,
    /// supported languages). Should be set for `Audio` modality.
    pub fn with_audio(mut self, params: AudioParameters) -> Self {
        self.audio = Some(params);
        self
    }

    /// Attach video-model parameters (frame size, num frames, fps,
    /// embedding dim). Should be set for `Video` modality.
    pub fn with_video(mut self, params: VideoParameters) -> Self {
        self.video = Some(params);
        self
    }

    /// Returns `true` if this model is an MoE architecture with routing
    /// metadata available.
    pub fn is_moe(&self) -> bool {
        self.moe.is_some()
    }

    /// Sets the description
    pub fn with_description(mut self, description: String) -> Self {
        self.description = description;
        self
    }

    /// Sets the architecture
    pub fn with_architecture(mut self, architecture: String) -> Self {
        self.architecture = architecture;
        self
    }

    /// Sets the model hash
    pub fn with_hash(mut self, hash: Hash) -> Self {
        self.model_hash = hash;
        self
    }
}

/// AI model modality
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum ModelModality {
    /// Text-only model
    #[default]
    Text,
    /// Image-only model
    Image,
    /// Audio/speech model
    Audio,
    /// Timeseries forecasting model (numeric inputs/outputs)
    Timeseries,
    /// Video model
    Video,
    /// Text and image (multimodal)
    TextImage,
    /// Text and audio
    TextAudio,
    /// Multiple modalities
    Multimodal,
}

impl ModelModality {
    /// Returns true if this modality supports the requested capability.
    ///
    /// Compound modalities (TextImage, TextAudio, Multimodal) are treated as
    /// supersets of their component modalities. For example, a `TextImage`
    /// model supports both `Text` and `Image` queries, and a `Multimodal`
    /// model supports all modalities.
    ///
    /// This enables inclusive model filtering: searching for `Text` returns
    /// not just `Text` models but also `TextImage`, `TextAudio`, and
    /// `Multimodal` models.
    ///
    /// `Timeseries` is treated as a single-purpose modality — it does not
    /// participate in compound supersets and only matches itself.
    pub fn supports(&self, requested: ModelModality) -> bool {
        if *self == requested {
            return true;
        }
        match *self {
            ModelModality::Multimodal => !matches!(requested, ModelModality::Timeseries),
            ModelModality::TextImage => matches!(requested, ModelModality::Text | ModelModality::Image),
            ModelModality::TextAudio => matches!(requested, ModelModality::Text | ModelModality::Audio),
            _ => false,
        }
    }
}

/// Model parameters and capabilities
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelParameters {
    /// Number of parameters (e.g., 7B, 13B, 70B)
    pub parameter_count: Option<u64>,
    /// Context window size (tokens)
    pub context_window: u32,
    /// Maximum output tokens
    pub max_output_tokens: u32,
    /// Supported input formats
    pub input_formats: Vec<String>,
    /// Supported output formats
    pub output_formats: Vec<String>,
    /// Model capabilities/features
    pub capabilities: Vec<String>,
}

impl Default for ModelParameters {
    fn default() -> Self {
        Self {
            parameter_count: None,
            context_window: 4096,
            max_output_tokens: 2048,
            input_formats: vec!["text".to_string()],
            output_formats: vec!["text".to_string()],
            capabilities: Vec::new(),
        }
    }
}

/// Mixture-of-Experts routing metadata for MoE architectures.
///
/// Captures the parameters an inference router needs to reason about
/// per-token cost, expert utilization, and specialization-aware dispatch.
/// Designed to cover Mixtral 8x7B / 8x22B, DeepSeek-V2 / V3 (shared +
/// routed experts), Qwen2-MoE, and recurrent-depth MoE stacks such as
/// OpenMythos.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoeMetadata {
    /// Total number of routed experts in the model (e.g., 8 for Mixtral 8x7B,
    /// 64 for Qwen2-MoE).
    pub num_experts: u32,
    /// Number of experts activated per token (top-k routing). Typical
    /// values: 2 for Mixtral, 6 for DeepSeek-V2, 8 for Qwen2-MoE.
    pub experts_per_token: u8,
    /// Shared ("always-on") experts that process every token alongside
    /// the routed experts. Used by DeepSeekMoE-style architectures;
    /// zero for Mixtral-style models.
    #[serde(default)]
    pub shared_experts: u32,
    /// Parameters per expert (in billions, scaled x10 for fixed-point —
    /// e.g., 70 = 7.0B). `None` when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params_per_expert_x10: Option<u32>,
    /// Routing strategy used by the gating network.
    pub routing_strategy: MoeRoutingStrategy,
    /// Auxiliary load-balancing loss coefficient (x10000 fixed point).
    /// Helps schedulers estimate how evenly load spreads across experts.
    /// `None` when unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_balance_coef_x10000: Option<u32>,
    /// Attention mechanism variant (e.g., "mla" for Multi-head Latent
    /// Attention, "mha", "mqa", "gqa").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attention_type: Option<String>,
    /// Optional per-expert specialization labels (ordered by expert
    /// index). E.g., `["math", "code", "reasoning", ...]`. Routers can
    /// use these to bias toward specialized experts for known task
    /// categories.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expert_specialization: Option<Vec<String>>,
    /// Expert capacity factor (x100 fixed point — e.g., 125 = 1.25).
    /// Drives per-expert token budget: `capacity = ceil(tokens * top_k *
    /// capacity_factor / num_experts)`. `None` defaults to 1.0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capacity_factor_x100: Option<u32>,
}

impl MoeMetadata {
    /// Construct a minimal MoE metadata block from the required fields.
    pub fn new(
        num_experts: u32,
        experts_per_token: u8,
        routing_strategy: MoeRoutingStrategy,
    ) -> Self {
        Self {
            num_experts,
            experts_per_token,
            shared_experts: 0,
            params_per_expert_x10: None,
            routing_strategy,
            load_balance_coef_x10000: None,
            attention_type: None,
            expert_specialization: None,
            capacity_factor_x100: None,
        }
    }

    /// Declare shared ("always-on") experts.
    pub fn with_shared_experts(mut self, shared: u32) -> Self {
        self.shared_experts = shared;
        self
    }

    /// Declare parameters-per-expert in billions (scaled x10).
    pub fn with_params_per_expert_x10(mut self, params_x10: u32) -> Self {
        self.params_per_expert_x10 = Some(params_x10);
        self
    }

    /// Declare the attention variant (e.g., "mla", "gqa").
    pub fn with_attention_type(mut self, attn: impl Into<String>) -> Self {
        self.attention_type = Some(attn.into());
        self
    }

    /// Attach a per-expert specialization label list.
    pub fn with_expert_specialization(mut self, labels: Vec<String>) -> Self {
        self.expert_specialization = Some(labels);
        self
    }

    /// Declare the expert capacity factor as a x100 fixed-point value.
    pub fn with_capacity_factor_x100(mut self, cf_x100: u32) -> Self {
        self.capacity_factor_x100 = Some(cf_x100);
        self
    }

    /// Total activated experts per token (routed top-k + shared).
    pub fn active_experts_per_token(&self) -> u32 {
        self.experts_per_token as u32 + self.shared_experts
    }

    /// Total parameters across all routed experts, in billions scaled x10.
    /// Returns `None` if `params_per_expert_x10` is unset.
    pub fn total_routed_params_x10(&self) -> Option<u64> {
        self.params_per_expert_x10
            .map(|p| p as u64 * self.num_experts as u64)
    }

    /// Active parameters per token, in billions scaled x10. Useful for
    /// cost/latency estimation since MoE inference only pays for
    /// activated experts, not the total parameter count.
    pub fn active_params_per_token_x10(&self) -> Option<u64> {
        self.params_per_expert_x10
            .map(|p| p as u64 * self.active_experts_per_token() as u64)
    }
}

/// Gating-network routing strategy for an MoE model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MoeRoutingStrategy {
    /// Classic top-k expert selection (Mixtral, Qwen2-MoE).
    TopK,
    /// Top-p (nucleus) expert selection — dynamic experts-per-token
    /// based on cumulative gate probability.
    TopP,
    /// Expert-Choice routing — each expert picks its top-k tokens
    /// (Zhou et al., 2022).
    ExpertChoice,
    /// Switch Transformer single-expert routing (top-1).
    Switch,
    /// Soft routing (all experts weighted, no hard top-k).
    Soft,
    /// Sinkhorn / BASE-layer balanced assignment.
    Sinkhorn,
    /// Hash-based fixed routing (no learned gate).
    Hash,
    /// Custom / proprietary routing.
    Custom,
}

/// Timeseries forecasting model parameters.
///
/// Captures the shape contract of an ONNX timeseries model: how many
/// historical points it consumes (`context_length`), how many points it
/// emits (`max_horizon`), how many quantiles per step (`n_quantiles`,
/// `1` for point forecasts), and how many parallel input series it
/// accepts (`num_features`, `1` for univariate). Used by
/// `TimeseriesRuntime` and the catalog-driven loader to validate
/// inputs before invoking ORT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeseriesParameters {
    /// Number of historical points the model conditions on.
    pub context_length: u32,
    /// Maximum number of forecast steps the model can emit in one pass.
    pub max_horizon: u32,
    /// Number of quantiles emitted per step (1 = point forecast,
    /// >1 = quantile forecast).
    pub n_quantiles: u32,
    /// Number of input feature channels (1 = univariate;
    /// >1 = multivariate / covariate-aware).
    pub num_features: u32,
}

impl TimeseriesParameters {
    /// Construct univariate point-forecast parameters.
    pub fn univariate(context_length: u32, max_horizon: u32) -> Self {
        Self {
            context_length,
            max_horizon,
            n_quantiles: 1,
            num_features: 1,
        }
    }

    /// Construct quantile-forecast parameters.
    pub fn with_quantiles(mut self, n_quantiles: u32) -> Self {
        self.n_quantiles = n_quantiles;
        self
    }

    /// Construct multivariate parameters.
    pub fn with_features(mut self, num_features: u32) -> Self {
        self.num_features = num_features;
        self
    }
}

/// Vision encoder parameters.
///
/// Captures everything needed to feed an image into an ONNX vision
/// encoder: spatial input size, output embedding dimensionality, the
/// normalization recipe (e.g., "clip", "imagenet", "siglip"), and the
/// list of accepted image container formats. Used by `VisionRuntime`
/// and the catalog-driven loader.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VisionParameters {
    /// Square input edge in pixels (e.g., 224, 256, 336, 384).
    pub input_size: u32,
    /// Output embedding dimensionality (e.g., 512 for CLIP B/32,
    /// 1024 for DINOv2 large).
    pub embedding_dim: u32,
    /// Normalization recipe key — `"clip" | "imagenet" | "siglip"`.
    pub normalization: String,
    /// Accepted image container formats (e.g., `["png", "jpeg", "webp"]`).
    pub image_formats: Vec<String>,
}

/// Audio model parameters.
///
/// Audio ONNX models are typically multi-file bundles
/// (encoder + decoder + optional joiner for RNN-T style models). The
/// filenames map to entries inside the HuggingFace repo. Sample rate
/// is the canonical input rate the model expects; preprocessing
/// resamples to it. `languages` carries ISO-639 codes for ASR models
/// that advertise specific language coverage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudioParameters {
    /// Required input sample rate in Hz (typically 16000).
    pub sample_rate: u32,
    /// Encoder ONNX filename inside the HF repo bundle.
    pub encoder_filename: String,
    /// Decoder ONNX filename (Whisper-style, RNN-T joiner-decoder split).
    /// `None` for single-encoder models like Moonshine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoder_filename: Option<String>,
    /// Joiner ONNX filename (RNN-T architectures, e.g., Parakeet TDT).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joiner_filename: Option<String>,
    /// Maximum audio duration the model can process in one pass.
    pub max_audio_seconds: u32,
    /// Supported languages as ISO-639 codes (e.g., `["en", "de", "fr"]`).
    /// Empty for monolingual models or where docs don't specify.
    #[serde(default)]
    pub languages: Vec<String>,
}

/// Video model parameters.
///
/// Captures the spatio-temporal input contract for a video encoder:
/// per-frame spatial size, the number of frames consumed per inference,
/// the target frames-per-second the model was trained on (used for
/// stride during preprocessing), and the output embedding dimensionality.
/// Wave 1 ships the type but the catalog is empty until a permissive
/// + ONNX-shippable encoder lands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoParameters {
    /// Square frame edge in pixels.
    pub frame_size: u32,
    /// Number of frames consumed per inference (e.g., 16 for VideoMAE).
    pub num_frames: u32,
    /// Target FPS the model was trained on. Drives temporal stride
    /// during frame extraction.
    pub fps: u32,
    /// Output embedding dimensionality.
    pub embedding_dim: u32,
}

/// Model operational status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelStatus {
    /// Registration pending verification
    Pending,
    /// Active and available for inference
    Active,
    /// Temporarily inactive
    Inactive,
    /// Deprecated
    Deprecated,
}

/// An inference request to an AI model
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceRequest {
    /// Request ID
    pub request_id: String,
    /// Model to use
    pub model_id: String,
    /// Requester address
    pub requester: Address,
    /// Input data
    pub input: Vec<u8>,
    /// Inference parameters
    pub parameters: InferenceParameters,
    /// Maximum price willing to pay (in smallest TNZO unit)
    pub max_price: u64,
    /// Request timestamp
    pub timestamp: Timestamp,
    /// Optional callback address
    pub callback: Option<Address>,
}

impl InferenceRequest {
    /// Creates a new inference request
    pub fn new(
        model_id: String,
        requester: Address,
        input: Vec<u8>,
        max_price: u64,
    ) -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            model_id,
            requester,
            input,
            parameters: InferenceParameters::default(),
            max_price,
            timestamp: Timestamp::now(),
            callback: None,
        }
    }

    /// Sets inference parameters
    pub fn with_parameters(mut self, parameters: InferenceParameters) -> Self {
        self.parameters = parameters;
        self
    }

    /// Sets callback address
    pub fn with_callback(mut self, callback: Address) -> Self {
        self.callback = Some(callback);
        self
    }
}

/// Parameters for model inference
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceParameters {
    /// Temperature for sampling
    pub temperature: Option<u32>, // Stored as fixed-point (e.g., 100 = 1.0)
    /// Top-p sampling
    pub top_p: Option<u32>, // Stored as fixed-point
    /// Top-k sampling
    pub top_k: Option<u32>,
    /// Maximum tokens to generate
    pub max_tokens: Option<u32>,
    /// Stop sequences
    pub stop_sequences: Vec<String>,
    /// Additional custom parameters
    pub custom: HashMap<String, String>,
}

impl Default for InferenceParameters {
    fn default() -> Self {
        Self {
            temperature: Some(100), // 1.0
            top_p: None,
            top_k: None,
            max_tokens: None,
            stop_sequences: Vec::new(),
            custom: HashMap::new(),
        }
    }
}

/// Response from model inference
///
/// EU AI Act Article 50 (effective 2026-08-02) requires generative-AI outputs
/// to carry both (a) a machine-readable disclosure that the content is
/// AI-generated and (b) a verifiable provenance manifest. Both fields here
/// are always populated by `tenzro-model::routing` for real inferences:
/// `synthetic_content` is unconditionally `true` (every inference response is
/// AI-generated by definition) and `provenance` carries a signed
/// [`ProvenanceManifest`] when a `ProvenanceSigner` is wired into the router.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceResponse {
    /// Request ID this response is for
    pub request_id: String,
    /// Response ID
    pub response_id: String,
    /// Model that generated the response
    pub model_id: String,
    /// Provider that served the request
    pub provider: Address,
    /// Output data
    pub output: Vec<u8>,
    /// Response metadata
    pub metadata: InferenceMetadata,
    /// Actual price charged (in smallest TNZO unit)
    pub price: u64,
    /// Response timestamp
    pub timestamp: Timestamp,
    /// EU AI Act Article 50(2) — content is machine-generated. Always `true`
    /// for genuine inference responses; deserialized as `true` by default so
    /// integrations that build responses by hand cannot accidentally drop the
    /// disclosure.
    #[serde(default = "default_synthetic_content")]
    pub synthetic_content: bool,
    /// EU AI Act Article 50(2) — content provenance. `None` only for in-memory
    /// transient responses that haven't been signed yet (e.g. mid-router). All
    /// responses returned to RPC/MCP/A2A clients have this populated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ProvenanceManifest>,
}

fn default_synthetic_content() -> bool {
    true
}

impl InferenceResponse {
    /// Creates a new inference response. The result is marked as
    /// `synthetic_content = true` automatically per EU AI Act Article 50.
    /// Callers should attach a [`ProvenanceManifest`] via [`with_provenance`]
    /// before publishing the response off the node.
    ///
    /// [`with_provenance`]: InferenceResponse::with_provenance
    pub fn new(
        request_id: String,
        model_id: String,
        provider: Address,
        output: Vec<u8>,
        price: u64,
    ) -> Self {
        Self {
            request_id,
            response_id: uuid::Uuid::new_v4().to_string(),
            model_id,
            provider,
            output,
            metadata: InferenceMetadata::default(),
            price,
            timestamp: Timestamp::now(),
            synthetic_content: true,
            provenance: None,
        }
    }

    /// Builder helper to attach a signed provenance manifest before the
    /// response leaves the inference router.
    pub fn with_provenance(mut self, manifest: ProvenanceManifest) -> Self {
        self.provenance = Some(manifest);
        self
    }
}

/// Content provenance manifest — a C2PA-style attestation that an AI output
/// was produced on Tenzro Network by a specific model + provider, signed by
/// the provider's key. The manifest is small enough to embed in a JSON-RPC
/// response and self-contained enough to verify offline given the signer's
/// public key.
///
/// This is intentionally protocol-agnostic: when the C2PA Content Credentials
/// final spec under the EU AI Office Code of Practice (June 2026) is
/// finalized, the on-the-wire encoding can be swapped for a real `c2pa-rs`
/// manifest store while keeping this type as the in-memory representation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceManifest {
    /// SHA-256 of the inference output bytes (`InferenceResponse.output`).
    /// Acts as the lookup key for `tenzro_getProvenance(content_hash)`.
    pub content_hash: Hash,
    /// Model that produced the content (mirror of `InferenceResponse.model_id`).
    pub model_id: String,
    /// Provider that ran the inference (mirror of `InferenceResponse.provider`).
    pub provider: Address,
    /// Wall-clock timestamp at which the manifest was signed.
    pub signed_at: Timestamp,
    /// Content classification — `"ai-generated"` for ordinary inference
    /// outputs, `"deepfake"` for outputs that imitate a real person, place,
    /// or event (EU AI Act Art. 50(4) labeling).
    pub assertion: String,
    /// Signer's public key (raw bytes — Ed25519 = 32B, secp256k1 = 33B).
    pub signer_public_key: Vec<u8>,
    /// Detached signature over the canonical preimage:
    /// `content_hash || model_id (utf8) || provider (32B) || signed_at_ms (le_u64) || assertion (utf8)`.
    pub signature: Vec<u8>,
    /// Algorithm tag matching `signature` — `"ed25519"` or `"secp256k1"`.
    pub algorithm: String,
}

impl ProvenanceManifest {
    /// Canonical preimage used to verify [`signature`]. Recomputed by both
    /// the signer (in `tenzro-model::provenance`) and any third-party
    /// verifier — encoding here is the single source of truth.
    ///
    /// [`signature`]: ProvenanceManifest::signature
    pub fn canonical_preimage(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(
            self.content_hash.0.len()
                + self.model_id.len()
                + self.provider.0.len()
                + 8
                + self.assertion.len(),
        );
        buf.extend_from_slice(&self.content_hash.0);
        buf.extend_from_slice(self.model_id.as_bytes());
        buf.extend_from_slice(&self.provider.0);
        buf.extend_from_slice(&self.signed_at.as_millis().to_le_bytes());
        buf.extend_from_slice(self.assertion.as_bytes());
        buf
    }
}

/// Metadata about an inference response
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct InferenceMetadata {
    /// Tokens in the input
    pub input_tokens: u32,
    /// Tokens in the output
    pub output_tokens: u32,
    /// Inference latency (milliseconds)
    pub latency_ms: u64,
    /// Model version used
    pub model_version: Option<String>,
    /// Finish reason
    pub finish_reason: Option<String>,
}

/// Information about a model inference provider
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InferenceProvider {
    /// Provider address
    pub address: Address,
    /// Provider name
    pub name: String,
    /// OpenAI-compatible API endpoint URL (e.g., "http://192.168.1.10:8545/v1")
    pub endpoint_url: Option<String>,
    /// Models this provider serves
    pub models: Vec<String>,
    /// Provider capacity
    pub capacity: ProviderCapacity,
    /// Provider pricing
    pub pricing: PricingConfig,
    /// Provider reputation
    pub reputation: u64,
    /// Total inferences served
    pub total_inferences: u64,
    /// Provider status
    pub status: ProviderStatus,
    /// Registration timestamp
    pub registered_at: Timestamp,
    /// Registered Ed25519 response-signing public key. When set, the
    /// provider commits to attaching a `tenzro_provenance` manifest
    /// signed by this key to every inference response, and routers can
    /// verify manifests against it. `None` means the provider serves
    /// unsigned responses — it remains fully routable; response
    /// verification is strictly opt-in per request.
    #[serde(default)]
    pub signing_pubkey: Option<Vec<u8>>,
}

impl InferenceProvider {
    /// Creates a new inference provider
    pub fn new(address: Address, name: String) -> Self {
        Self {
            address,
            name,
            endpoint_url: None,
            models: Vec::new(),
            capacity: ProviderCapacity::default(),
            pricing: PricingConfig::default(),
            reputation: 0,
            total_inferences: 0,
            status: ProviderStatus::Pending,
            registered_at: Timestamp::now(),
            signing_pubkey: None,
        }
    }

    /// Sets the provider's OpenAI-compatible API endpoint URL
    pub fn with_endpoint_url(mut self, url: impl Into<String>) -> Self {
        self.endpoint_url = Some(url.into());
        self
    }

    /// Sets the provider's registered response-signing public key
    pub fn with_signing_pubkey(mut self, pubkey: Vec<u8>) -> Self {
        self.signing_pubkey = Some(pubkey);
        self
    }

    /// Adds a model to the provider
    pub fn add_model(&mut self, model_id: String) {
        if !self.models.contains(&model_id) {
            self.models.push(model_id);
        }
    }

    /// Checks if provider serves a model
    pub fn serves_model(&self, model_id: &str) -> bool {
        self.models.iter().any(|m| m == model_id)
    }
}

/// Provider capacity information
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderCapacity {
    /// Maximum concurrent requests
    pub max_concurrent_requests: u32,
    /// Current active requests
    pub active_requests: u32,
    /// Requests per second capacity
    pub requests_per_second: u32,
    /// Maximum batch size
    pub max_batch_size: u32,
    /// Multi-Token Prediction availability. Set by the provider at
    /// `tenzro_registerProvider` time when their serving runtime has
    /// the target's paired drafter co-loaded (`HfModelEntry.drafter_id`
    /// + `mtp_kind == DraftMtp` or `Generic`). When true, the
    /// `InferenceRouter` may route MTP-eligible requests preferentially
    /// to this provider; when false, it falls back to standard
    /// autoregressive providers.
    #[serde(default)]
    pub mtp_enabled: bool,
    /// VRAM headroom (GB) the provider has reserved for the speculative
    /// drafter alongside the target. Unsloth measures ~2 GB extra for
    /// Gemma 4 MTP heads. `None` means the provider hasn't declared a
    /// drafter footprint, which is fine when `mtp_enabled = false`.
    #[serde(default)]
    pub drafter_vram_gb: Option<f32>,
    /// MoE expert-shard declaration. When a provider can't fit an entire
    /// MoE model (e.g. Qwen 3.5 397B-A17B) on its hardware, it can host
    /// a subset of expert weights and serve as one peer in a
    /// decentralized expert-parallel dispatch. Empty `holdings` means
    /// the provider does not participate in MoE expert serving for any
    /// model and is treated as a full-model replica only.
    #[serde(default)]
    pub moe_holdings: Vec<MoeExpertHolding>,
    /// MoE-pipeline role this provider plays. `Replica` is the default —
    /// the provider holds the full model and serves single-peer
    /// inference. `Router` provides the gating-network step and fans
    /// out batched expert calls. `ExpertHolder` participates in the
    /// expert-shard pool. `PrefillDecode` runs both phases co-located
    /// (the centralized default). Providers can declare more than
    /// one role; the router picks the matching role per request.
    #[serde(default)]
    pub moe_roles: Vec<MoeProviderRole>,
    /// Iroh endpoint id of this provider. Used by the MoE router to
    /// dispatch batched expert calls over QUIC directly to the holder
    /// peer without going through the OpenAI-compatible HTTP endpoint.
    /// Required when `moe_roles` includes `Router` or `ExpertHolder`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iroh_endpoint_id: Option<String>,
    /// Local-network cluster this node belongs to, if any. When set, the
    /// node is one machine in a provider-owned LAN cluster that serves a
    /// model too large for any single member by splitting it into a
    /// layer-wise pipeline across members (see [`LanCluster`]). `None`
    /// means the node serves standalone.
    ///
    /// Why layer-pipeline and not expert-parallel on the LAN: expert
    /// all-to-all dispatch is a latency-bound collective that needs an
    /// NVLink/RDMA-class interconnect; over commodity Ethernet it
    /// collapses. Splitting by contiguous layer range sends only the
    /// boundary activation between stages — point-to-point, tolerant of
    /// millisecond LAN latency. This is the pattern llama.cpp's RPC
    /// backend implements, and it is why MoE serves well
    /// over a LAN: each layer's experts stay co-resident on the stage
    /// that owns the layer, so there is no cross-machine all-to-all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lan_cluster: Option<LanCluster>,
}

/// Provider's holding declaration for one MoE expert in one model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoeExpertHolding {
    /// Tenzro model id this holding covers.
    pub model_id: String,
    /// Transformer layer index.
    pub layer: u32,
    /// Expert index inside the layer's MoE block.
    pub expert: u32,
    /// Residency state — `Warm` (VRAM-resident), `Cold` (disk only),
    /// or `Evicting` (being unloaded). Schedulers prefer warm holdings.
    pub residency: MoeExpertResidency,
    /// Maximum tokens per second this provider commits to for this
    /// expert post-batch. `0` means "best effort" with no SLA.
    pub committed_tps: u32,
}

/// A provider-owned cluster of machines on one local network that jointly
/// serve a model too large for any single member.
///
/// The cluster presents to the wider Tenzro network as a *single logical
/// provider* — one public [`Address`] and endpoint, owned by the elected
/// [`head`](LanCluster::head). The network neither sees nor routes to the
/// individual member machines; the head fans the layer-pipeline across
/// them internally over the LAN. A member may also be exposed on its own
/// Address (the "both" model) — that is independent of cluster membership
/// and governed by its own `InferenceProvider` registration.
///
/// Membership is discovered automatically: members find each other via
/// mDNS / local-direct reachability on the same L2 segment, and the
/// layer-range assignment is computed deterministically from each
/// member's declared VRAM (a bin-packing over `pipeline_stage`s). Every
/// member computes the identical assignment with no coordinator round —
/// the determinism is deliberate, so two members never disagree on who
/// owns which layers (a split assignment would corrupt the pipeline).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LanCluster {
    /// Stable identifier shared by every member of this cluster. Members
    /// with the same `cluster_id` on the same local segment form one
    /// logical provider. Provider-chosen; opaque to the network.
    pub cluster_id: String,
    /// Address of the elected head — the member that owns the cluster's
    /// public registration and drives the pipeline. When this equals the
    /// node's own address, the node is the head. `None` during election
    /// (before a head is settled); members serve no traffic until a head
    /// is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<Address>,
    /// LAN-reachable endpoint of this member, used only for intra-cluster
    /// pipeline traffic between members — never advertised to the wider
    /// network. Typically a private-range address (e.g. `10.x`, `192.168.x`,
    /// or an mDNS `.local` name) on the cluster's serving port.
    pub local_endpoint: String,
    /// The contiguous layer range this member serves in the pipeline, once
    /// assignment has settled. `None` until the cluster has computed the
    /// layer→member assignment (or for the head before members report
    /// their VRAM).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipeline_stage: Option<PipelineStage>,
    /// VRAM this member contributes to the cluster, in GB. The layer
    /// assignment is a deterministic bin-packing weighted by this value,
    /// so a member with more VRAM is assigned proportionally more layers.
    pub vram_gb: f32,
}

/// One member's slice of a layer-wise pipeline: the half-open range of
/// transformer layers `[start_layer, end_layer)` it executes.
///
/// During decode, the stage receives the boundary activation from the
/// member owning the preceding range, runs its layers (all experts for
/// those layers stay co-resident here), and forwards the activation to
/// the next stage. The member owning the final range produces logits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipelineStage {
    /// First layer this stage owns (inclusive).
    pub start_layer: u32,
    /// One past the last layer this stage owns (exclusive).
    pub end_layer: u32,
}

impl PipelineStage {
    /// Number of layers this stage executes.
    pub fn layer_count(&self) -> u32 {
        self.end_layer.saturating_sub(self.start_layer)
    }

    /// Whether this stage owns the model's first layer range (the stage
    /// that accepts the embedded prompt).
    pub fn is_first(&self) -> bool {
        self.start_layer == 0
    }
}

/// MoE expert residency state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MoeExpertResidency {
    /// In VRAM, ready to dispatch.
    Warm,
    /// On disk / CPU RAM, eviction-eligible.
    Cold,
    /// Currently being unloaded.
    Evicting,
}

/// MoE pipeline roles a provider can play in distributed serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MoeProviderRole {
    /// Holds the full model; serves single-peer inference. The default.
    Replica,
    /// Runs the gating-network step and fans out batched expert calls
    /// to the appropriate expert holders.
    Router,
    /// Holds one or more experts declared in `moe_holdings`.
    ExpertHolder,
    /// Runs both prefill and decode phases co-located (the standard central
    /// pattern; the Tenzro fallback when only one provider can fit the
    /// model).
    PrefillDecode,
    /// Runs only the prefill phase; hands off KV cache to a decode
    /// peer over iroh. Pairs with `Decode`.
    Prefill,
    /// Runs only the decode phase; accepts KV cache from a prefill
    /// peer over iroh.
    Decode,
    /// Executes a contiguous layer range as one stage of a LAN
    /// layer-pipeline (see [`LanCluster`] / [`PipelineStage`]). Distinct
    /// from `ExpertHolder`: a pipeline stage owns *whole layers* (with all
    /// their experts co-resident) and exchanges only boundary activations
    /// with adjacent stages, rather than holding individual experts and
    /// participating in cross-machine all-to-all. This is the role members
    /// of a local-network cluster take.
    PipelineStage,
}

impl Default for ProviderCapacity {
    fn default() -> Self {
        Self {
            max_concurrent_requests: 10,
            active_requests: 0,
            requests_per_second: 100,
            max_batch_size: 1,
            mtp_enabled: false,
            drafter_vram_gb: None,
            moe_holdings: Vec::new(),
            moe_roles: Vec::new(),
            iroh_endpoint_id: None,
            lan_cluster: None,
        }
    }
}

impl ProviderCapacity {
    /// Checks if provider has capacity for a new request
    pub fn has_capacity(&self) -> bool {
        self.active_requests < self.max_concurrent_requests
    }

    /// Returns the utilization percentage (0-100)
    pub fn utilization(&self) -> u8 {
        if self.max_concurrent_requests == 0 {
            0
        } else {
            ((self.active_requests as f64 / self.max_concurrent_requests as f64) * 100.0) as u8
        }
    }
}

/// Provider operational status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderStatus {
    /// Registration pending
    Pending,
    /// Active and accepting requests
    Active,
    /// Temporarily inactive
    Inactive,
    /// Suspended
    Suspended,
}

/// Pricing configuration for models and providers
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PricingConfig {
    /// Price per input token (in smallest TNZO unit)
    pub price_per_input_token: u64,
    /// Price per output token (in smallest TNZO unit)
    pub price_per_output_token: u64,
    /// Minimum price per request (in smallest TNZO unit)
    pub minimum_price: u64,
    /// Pricing model
    pub pricing_model: PricingModel,
}

impl Default for PricingConfig {
    fn default() -> Self {
        Self {
            price_per_input_token: 10,
            price_per_output_token: 20,
            minimum_price: 100,
            pricing_model: PricingModel::PerToken,
        }
    }
}

/// Pricing models for inference
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PricingModel {
    /// Price per token (input and output priced separately)
    PerToken,
    /// Flat price per request
    PerRequest,
    /// Price based on compute time
    PerComputeTime,
    /// Dynamic pricing based on demand
    Dynamic,
}

// === Model Service Instances ===

/// A served model instance on the Tenzro network.
///
/// Each model that is actively served (locally or by a remote provider)
/// gets a unique UUID-based service instance with both API and MCP endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelServiceInstance {
    /// Unique service instance ID (UUID v4)
    pub instance_id: String,
    /// Catalog model ID (e.g., "qwen3-8b")
    pub model_id: String,
    /// Human-readable model name
    pub model_name: String,
    /// Provider's network address
    pub provider_address: Address,
    /// Human-readable provider name
    pub provider_name: String,
    /// Whether the model is local or on a remote network provider
    pub location: ModelLocation,
    /// OpenAI-compatible API endpoint (e.g., "http://host:8545/v1")
    pub api_endpoint: String,
    /// MCP server endpoint (e.g., "http://host:3001/mcp")
    pub mcp_endpoint: String,
    /// Current service status
    pub status: ServiceStatus,
    /// Model parameters (e.g., "8B")
    pub parameters: String,
    /// Pricing configuration
    pub pricing: PricingConfig,
    /// Timestamp when this instance was registered
    pub created_at: u64,
    /// Last time this endpoint was confirmed alive (Unix timestamp).
    /// Network endpoints expire after 5 minutes without heartbeat.
    #[serde(default)]
    pub last_seen: u64,
    /// Current load information (updated dynamically, only for local models)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_info: Option<ModelLoadInfo>,
}

/// Whether a model is served locally or by a remote network provider
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelLocation {
    /// Served on this node
    Local,
    /// Served by a remote provider on the Tenzro network
    Network,
}

impl std::fmt::Display for ModelLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Local => write!(f, "local"),
            Self::Network => write!(f, "network"),
        }
    }
}

/// Operational status of a model service instance
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceStatus {
    /// Online and accepting requests
    Online,
    /// Offline or unreachable
    Offline,
    /// Degraded performance
    Degraded,
}

impl std::fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Online => write!(f, "online"),
            Self::Offline => write!(f, "offline"),
            Self::Degraded => write!(f, "degraded"),
        }
    }
}

/// Dynamic load information for a model service instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelLoadInfo {
    /// Number of requests currently being processed or queued
    pub active_requests: u32,
    /// Maximum concurrent requests this instance can handle
    pub max_concurrent: u32,
    /// Utilization percentage (0-100)
    pub utilization_percent: u8,
    /// Human-readable load level
    pub load_level: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// Rich chat shape types
//
// These types support the "rich" call shape of `tenzro_chat` — multi-turn
// conversations, system prompts, tool calls, vision input, and structured
// assistant responses built from content blocks. The simple call shape
// (single `message` string) does not use these types and routes through
// `ModelChatMessage` in `tenzro-model::runtime`.
//
// Schema mirrors Anthropic's Messages API content-block format. See
// `docs/chat-api.md` for the public RPC contract.
// ─────────────────────────────────────────────────────────────────────────────

/// A content block — the atomic unit of structured chat content.
///
/// Tagged externally on `type` for wire compatibility with Anthropic's
/// Messages API (so SDKs that already speak that schema work unchanged).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    /// Plain text content. Both directions (user input, assistant output).
    Text {
        text: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
    /// Extended-thinking trace. Assistant-only.
    Thinking { thinking: String },
    /// A tool invocation by the assistant. Assistant-only.
    ToolUse {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    /// A tool execution result returned by the client. User-only.
    ToolResult {
        tool_use_id: String,
        /// Result content — either a plain string or a list of blocks
        /// (typically `text` blocks, or an `image` for vision tools).
        content: ToolResultContent,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        is_error: Option<bool>,
    },
    /// Vision input. User-only.
    Image { source: ImageSource },
}

/// Cache control marker — pins the prefix up to and including this block
/// as a cache breakpoint. Identical-prefix subsequent calls reuse the KV
/// cache and are billed at a discounted rate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CacheControl {
    /// Ephemeral cache (≤5 min lifetime).
    Ephemeral,
}

/// Tool-result payload. Either a single string (the common case) or a list
/// of content blocks (when the tool returns structured or visual content).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ToolResultContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

/// Image source — only base64 inline for now. URL sources may be added later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ImageSource {
    Base64 {
        media_type: String,
        data: String,
    },
}

/// A message in the rich shape. `content` is either a plain string (which
/// the handler normalizes to a single `text` block) or an explicit array
/// of blocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RichChatMessage {
    /// `"user"` or `"assistant"`. The simple/rich routing keeps the system
    /// prompt out of the messages array — see `RichChatRequest::system`.
    pub role: String,
    pub content: MessageContent,
}

/// Message content — string or block array. The wire format permits either
/// for user messages; assistant messages are always emitted as block arrays.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

impl MessageContent {
    /// Normalizes content to a vec of blocks. A plain string becomes a
    /// single `text` block.
    pub fn into_blocks(self) -> Vec<ContentBlock> {
        match self {
            MessageContent::Text(s) => vec![ContentBlock::Text {
                text: s,
                cache_control: None,
            }],
            MessageContent::Blocks(b) => b,
        }
    }

    /// Borrows content as a slice of blocks, allocating only when the
    /// content is a plain string. Useful for read-only passes (token
    /// counting, validation).
    pub fn as_blocks(&self) -> std::borrow::Cow<'_, [ContentBlock]> {
        match self {
            MessageContent::Text(s) => std::borrow::Cow::Owned(vec![ContentBlock::Text {
                text: s.clone(),
                cache_control: None,
            }]),
            MessageContent::Blocks(b) => std::borrow::Cow::Borrowed(b),
        }
    }
}

impl ContentBlock {
    /// Total byte length of the text-bearing payload of this block,
    /// including inline image data. Used to bound request size before a
    /// request reaches a provider's context window.
    pub fn payload_len(&self) -> usize {
        match self {
            ContentBlock::Text { text, .. } => text.len(),
            ContentBlock::Thinking { thinking } => thinking.len(),
            ContentBlock::ToolUse { name, input, .. } => {
                name.len() + input.to_string().len()
            }
            ContentBlock::ToolResult { content, .. } => match content {
                ToolResultContent::Text(s) => s.len(),
                ToolResultContent::Blocks(bs) => bs.iter().map(ContentBlock::payload_len).sum(),
            },
            ContentBlock::Image { source } => match source {
                ImageSource::Base64 { data, .. } => data.len(),
            },
        }
    }
}

impl RichChatMessage {
    /// Total byte length of this message's content payload across all blocks.
    pub fn payload_len(&self) -> usize {
        self.content.as_blocks().iter().map(ContentBlock::payload_len).sum()
    }
}

/// A tool the model may invoke. The model emits `ContentBlock::ToolUse`
/// blocks whose `input` validates against `input_schema`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolSchema {
    /// Tool name. Must match `^[a-zA-Z0-9_-]{1,64}$`.
    pub name: String,
    pub description: String,
    /// JSON Schema (draft 2020-12) describing the tool's input.
    pub input_schema: serde_json::Value,
}

/// Reasoning effort budget for extended-thinking models.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ReasoningEffort {
    Low,
    #[default]
    Medium,
    High,
}

/// System-prompt content — either a plain string or a block array (so
/// `cache_control` can be applied to system text).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SystemPrompt {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

impl SystemPrompt {
    /// Returns the system prompt as a single concatenated string, suitable
    /// for chat templates that take a flat system field.
    pub fn as_text(&self) -> String {
        match self {
            SystemPrompt::Text(s) => s.clone(),
            SystemPrompt::Blocks(blocks) => blocks
                .iter()
                .filter_map(|b| match b {
                    ContentBlock::Text { text, .. } => Some(text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join(""),
        }
    }
}

/// Why the assistant stopped generating.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// Model finished naturally.
    EndTurn,
    /// Hit the `max_tokens` limit.
    MaxTokens,
    /// Hit a sequence in `stop_sequences`.
    StopSequence,
    /// Model emitted one or more `tool_use` blocks; the client is expected
    /// to execute them and return `tool_result` blocks in the next turn.
    ToolUse,
}

/// Token usage and cache metrics on a rich-shape response.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RichUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    #[serde(default)]
    pub cache_creation_input_tokens: u32,
    #[serde(default)]
    pub cache_read_input_tokens: u32,
}

#[cfg(test)]
mod rich_chat_tests {
    use super::*;

    #[test]
    fn text_block_roundtrip() {
        let b = ContentBlock::Text {
            text: "hello".to_string(),
            cache_control: None,
        };
        let json = serde_json::to_string(&b).unwrap();
        assert_eq!(json, r#"{"type":"text","text":"hello"}"#);
        let decoded: ContentBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, b);
    }

    #[test]
    fn thinking_block_roundtrip() {
        let b = ContentBlock::Thinking {
            thinking: "let me check".to_string(),
        };
        let json = serde_json::to_string(&b).unwrap();
        assert!(json.contains(r#""type":"thinking""#));
        let decoded: ContentBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, b);
    }

    #[test]
    fn tool_use_block_roundtrip() {
        let b = ContentBlock::ToolUse {
            id: "tu_01".to_string(),
            name: "get_price".to_string(),
            input: serde_json::json!({"pair": "TNZO/USD"}),
        };
        let json = serde_json::to_string(&b).unwrap();
        assert!(json.contains(r#""type":"tool_use""#));
        let decoded: ContentBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, b);
    }

    #[test]
    fn tool_result_string_content() {
        let b = ContentBlock::ToolResult {
            tool_use_id: "tu_01".to_string(),
            content: ToolResultContent::Text("0.42".to_string()),
            is_error: None,
        };
        let json = serde_json::to_string(&b).unwrap();
        let decoded: ContentBlock = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, b);
    }

    #[test]
    fn message_content_string_normalizes_to_text_block() {
        let mc = MessageContent::Text("hello".to_string());
        let blocks = mc.into_blocks();
        assert_eq!(blocks.len(), 1);
        match &blocks[0] {
            ContentBlock::Text { text, .. } => assert_eq!(text, "hello"),
            _ => panic!("expected text block"),
        }
    }

    #[test]
    fn message_content_accepts_string_or_blocks() {
        let s: MessageContent = serde_json::from_str(r#""hello""#).unwrap();
        assert!(matches!(s, MessageContent::Text(_)));
        let b: MessageContent =
            serde_json::from_str(r#"[{"type":"text","text":"hi"}]"#).unwrap();
        assert!(matches!(b, MessageContent::Blocks(_)));
    }

    #[test]
    fn stop_reason_serializes_snake_case() {
        assert_eq!(serde_json::to_string(&StopReason::EndTurn).unwrap(), r#""end_turn""#);
        assert_eq!(serde_json::to_string(&StopReason::ToolUse).unwrap(), r#""tool_use""#);
        assert_eq!(
            serde_json::to_string(&StopReason::MaxTokens).unwrap(),
            r#""max_tokens""#
        );
    }

    #[test]
    fn reasoning_effort_serializes_lowercase() {
        assert_eq!(serde_json::to_string(&ReasoningEffort::Low).unwrap(), r#""low""#);
        assert_eq!(serde_json::to_string(&ReasoningEffort::High).unwrap(), r#""high""#);
    }

    #[test]
    fn system_prompt_blocks_concatenate() {
        let sp = SystemPrompt::Blocks(vec![
            ContentBlock::Text {
                text: "you are ".to_string(),
                cache_control: None,
            },
            ContentBlock::Text {
                text: "helpful".to_string(),
                cache_control: Some(CacheControl::Ephemeral),
            },
        ]);
        assert_eq!(sp.as_text(), "you are helpful");
    }

    #[test]
    fn full_rich_request_roundtrip() {
        let json = r#"{
            "role": "user",
            "content": [
                {"type": "text", "text": "What is TNZO trading at?"}
            ]
        }"#;
        let msg: RichChatMessage = serde_json::from_str(json).unwrap();
        assert_eq!(msg.role, "user");
        assert_eq!(msg.content.as_blocks().len(), 1);
    }

    #[test]
    fn assistant_with_thinking_and_tool_use() {
        let json = r#"{
            "role": "assistant",
            "content": [
                {"type": "thinking", "thinking": "I should query the price oracle."},
                {"type": "tool_use", "id": "tu_01", "name": "get_price", "input": {"pair": "TNZO/USD"}}
            ]
        }"#;
        let msg: RichChatMessage = serde_json::from_str(json).unwrap();
        let blocks = msg.content.as_blocks();
        assert_eq!(blocks.len(), 2);
        assert!(matches!(&blocks[0], ContentBlock::Thinking { .. }));
        assert!(matches!(&blocks[1], ContentBlock::ToolUse { .. }));
    }
}

#[cfg(test)]
mod moe_tests {
    use super::*;

    #[test]
    fn moe_metadata_mixtral_8x7b() {
        // Mixtral 8x7B: 8 routed experts, top-2 routing, no shared experts.
        let moe = MoeMetadata::new(8, 2, MoeRoutingStrategy::TopK)
            .with_params_per_expert_x10(70) // 7.0B per expert
            .with_attention_type("gqa");
        assert_eq!(moe.num_experts, 8);
        assert_eq!(moe.experts_per_token, 2);
        assert_eq!(moe.shared_experts, 0);
        assert_eq!(moe.active_experts_per_token(), 2);
        assert_eq!(moe.total_routed_params_x10(), Some(560)); // 56.0B total
        assert_eq!(moe.active_params_per_token_x10(), Some(140)); // 14.0B active
    }

    #[test]
    fn moe_metadata_deepseek_shared_experts() {
        // DeepSeek-V2-style: routed + shared (always-on) experts.
        let moe = MoeMetadata::new(64, 6, MoeRoutingStrategy::TopK)
            .with_shared_experts(2)
            .with_params_per_expert_x10(3); // 0.3B per expert
        assert_eq!(moe.active_experts_per_token(), 8); // 6 routed + 2 shared
        assert_eq!(moe.active_params_per_token_x10(), Some(24)); // 2.4B active
    }

    #[test]
    fn moe_metadata_specialization_roundtrip() {
        let labels = vec!["math".to_string(), "code".to_string(), "reasoning".to_string()];
        let moe = MoeMetadata::new(3, 1, MoeRoutingStrategy::Switch)
            .with_expert_specialization(labels.clone());
        assert_eq!(moe.expert_specialization.as_ref(), Some(&labels));
    }

    #[test]
    fn model_info_moe_wiring() {
        let info = ModelInfo::new(
            "mixtral-8x7b".to_string(),
            "Mixtral".to_string(),
            "0.1".to_string(),
            ModelModality::Text,
            Address::zero(),
        );
        assert!(!info.is_moe());
        let info = info.with_moe(MoeMetadata::new(8, 2, MoeRoutingStrategy::TopK));
        assert!(info.is_moe());
        assert_eq!(info.moe.as_ref().unwrap().num_experts, 8);
    }

    #[test]
    fn moe_metadata_serde_json_omits_when_absent() {
        let info = ModelInfo::new(
            "dense-7b".to_string(),
            "Dense".to_string(),
            "0.1".to_string(),
            ModelModality::Text,
            Address::zero(),
        );
        let json = serde_json::to_string(&info).unwrap();
        // `moe: None` is skipped via skip_serializing_if.
        assert!(!json.contains("\"moe\""));
    }

    #[test]
    fn moe_metadata_serde_roundtrip() {
        let info = ModelInfo::new(
            "mixtral-8x7b".to_string(),
            "Mixtral".to_string(),
            "0.1".to_string(),
            ModelModality::Text,
            Address::zero(),
        )
        .with_moe(
            MoeMetadata::new(8, 2, MoeRoutingStrategy::TopK)
                .with_params_per_expert_x10(70)
                .with_attention_type("gqa")
                .with_capacity_factor_x100(125),
        );
        let json = serde_json::to_string(&info).unwrap();
        let decoded: ModelInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.moe, info.moe);
    }
}
