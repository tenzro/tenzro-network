//! # tenzro-model
//!
//! AI model registry, inference routing, and provider management for Tenzro Network.
//!
//! This crate provides the core infrastructure for managing AI models and inference
//! providers on Tenzro Network. It includes:
//!
//! - **Model Registry**: Central catalog of all AI models available on the network
//! - **Provider Management**: Registration and health monitoring of inference providers
//! - **Request Routing**: Intelligent routing of inference requests to optimal providers
//! - **Pricing Engine**: Cost calculation and dynamic pricing for inference services
//! - **Model Library**: Curated library for browsing and discovering models
//!
//! ## Features
//!
//! `engine` (on by default) compiles the modules that load and run models:
//! the llama.cpp runtime, media generation, training, the ONNX runtimes and the
//! MoE expert executor. Without it the crate keeps the parts a node uses to
//! take part in the network without serving a model: the catalog, registry,
//! routing, admission, pricing, SLA, provenance, sealed-model records, TOPLOC
//! commitments, media fingerprints and the chat request and result types.
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use tenzro_model::{
//!     CatalogCell,
//!     registry::ModelRegistry,
//!     provider::ProviderManager,
//!     routing::{InferenceRouter, RoutingConfig, RoutingStrategy},
//!     pricing::PriceContext,
//! };
//! use tenzro_types::model::ModelInfo;
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create registry and register a model
//! let registry = ModelRegistry::new(CatalogCell::default());
//! // let model = ModelInfo::new(...);
//! // registry.register_model(model)?;
//!
//! // Set up provider management
//! let provider_manager = Arc::new(ProviderManager::new());
//! // provider_manager.register_provider(provider, has_tee)?;
//!
//! // Configure routing
//! let config = RoutingConfig::new()
//!     .with_strategy(RoutingStrategy::WeightedScore);
//!
//! let router = InferenceRouter::with_config(provider_manager.clone(), config);
//!
//! // Route an inference request
//! // let request = InferenceRequest::new(...);
//! // let provider_address = router.route_request(&request)?;
//!
//! // Price a call on its provider's card
//! let prices = PriceContext::genesis(0);
//! // let cost = prices.charge_wei(&provider.pricing, &units)?;
//!
//! # Ok(())
//! # }
//! ```
//!
//! ## Features
//!
//! ### Model Registry
//!
//! The [`registry`] module provides a centralized catalog of all AI models:
//!
//! - Register new models with metadata and pricing
//! - Search and filter models by various criteria
//! - Verify model hashes and metadata
//! - Track model status and updates
//!
//! ### Provider Management
//!
//! The [`provider`] module handles inference provider registration and monitoring:
//!
//! - Register and manage inference providers
//! - Track provider performance metrics
//! - Monitor provider health with heartbeats
//! - Rank providers based on performance
//!
//! ### Inference Routing
//!
//! The [`routing`] module intelligently routes requests to providers:
//!
//! - Multiple routing strategies (price, latency, reputation, weighted)
//! - Circuit breaker pattern for fault tolerance
//! - Automatic failover on provider failure
//! - TEE requirement support
//!
//! ### Pricing Engine
//!
//! The [`pricing`] module handles all pricing calculations:
//!
//! - Calculate inference costs based on tokens or compute time
//! - Estimate costs before execution
//! - Track market prices and trends
//! - Support for dynamic pricing
//!
//! ### Model Library
//!
//! The [`library`] module provides a curated model discovery experience:
//!
//! - Browse models by category
//! - Featured and trending models
//! - Compatibility checking
//! - Model ratings and downloads
//!

pub mod access;
#[cfg(feature = "engine")]
pub mod audio_runtime;
pub mod autotune;
/// The model catalog.
///
/// Lives in `tenzro-catalog` now, re-exported here so every existing
/// `tenzro_model::catalog::...` path still resolves. It moved because naming a
/// model and running one are different jobs: anything that wanted to read the
/// catalog was building llama.cpp to do it.
pub use tenzro_catalog as catalog;
pub mod chat;
pub mod cluster;
#[cfg(feature = "engine")]
pub mod decision_runtime;
#[cfg(feature = "engine")]
pub mod detection_runtime;
pub mod engine_config;
pub mod error;
pub mod freivalds;
pub mod gguf_shape;
pub mod ground;
pub mod hardware_policy;
pub mod hf_download;
pub mod jurisdiction;
pub mod latency;
#[cfg(feature = "engine")]
pub mod layer_pipeline;
pub mod library;
pub mod lifecycle;
pub mod load;
pub mod media_fingerprint;
#[cfg(feature = "engine")]
pub mod media_runtime;
pub mod memory_budget;
#[cfg(feature = "engine")]
pub mod model_host;
#[cfg(feature = "engine")]
pub mod moe_compute;
#[cfg(feature = "moe-cuda")]
pub mod moe_compute_cuda;
#[cfg(feature = "moe-wgpu")]
pub mod moe_compute_wgpu;
#[cfg(feature = "engine")]
pub mod moe_exec;
#[cfg(feature = "engine")]
pub mod moe_extract;
pub mod moe_prefetch;
pub mod moe_quant;
pub mod moe_receipt;
pub mod moe_router;
pub mod moe_shard;
#[cfg(feature = "mtmd")]
pub mod omni_runtime;
#[cfg(feature = "engine")]
pub mod onnx_session;
pub mod origin_credential;
#[cfg(feature = "engine")]
pub mod parse_jail;
#[cfg(feature = "engine")]
pub mod praecise_embedder;
pub mod prefix_affinity;
pub mod pricing;
#[cfg(feature = "engine")]
pub mod projector;
pub mod provenance;
pub mod provider;
pub mod provider_liveness;
pub mod quant;
pub mod registry;
#[cfg(feature = "engine")]
pub mod rerank_runtime;
pub mod routing;
#[cfg(feature = "engine")]
pub mod runtime;
pub mod sealed;
#[cfg(feature = "engine")]
pub mod segmentation_runtime;
pub mod serve_advisor;
/// What a batched serve allocates, part by part, before the engine takes it.
pub mod serve_memory;
pub mod sla;
/// Speech synthesis on the Praecise engine through an audio projector.
#[cfg(feature = "mtmd")]
pub mod speech_runtime;
#[cfg(feature = "engine")]
pub mod text_embedding_runtime;
#[cfg(feature = "engine")]
pub mod text_segmentation_runtime;
#[cfg(feature = "engine")]
pub(crate) mod tool_grammar;
pub mod toploc;
pub mod traffic;
#[cfg(feature = "engine")]
pub mod training_runtime;
#[cfg(feature = "engine")]
pub mod ts_runtime;
pub mod usage;
#[cfg(feature = "engine")]
pub mod video_runtime;
#[cfg(feature = "engine")]
pub mod vision_input;
#[cfg(feature = "engine")]
pub mod vision_runtime;

// Re-export commonly used types
#[cfg(feature = "engine")]
pub use audio_runtime::{
    AudioRuntime, MoonshineTranscriber, TranscribeConfig, TranscribeResult, Transcriber,
    TranscriptSegment, WhisperFamily, WhisperTranscriber,
};
// The batching engine lives in the Praecise engine; re-exported so existing callers
// (`tenzro_model::max_slots`, the node's capacity cap) keep working.
pub use catalog::{
    Catalog, CatalogCell, EmbedModelEntry, EmbeddingTemplate, HfModelEntry, LicenseTier,
    MediaGenExpertPair, MediaGenModelEntry, ModelArchitecture, MoeShape, MtpKind, OmniModelEntry,
    OnnxAudioEntry, OnnxDetectionEntry, OnnxForecastEntry, OnnxSegmentationEntry,
    OnnxTextEmbeddingEntry, OnnxTextSegmentationEntry, OnnxVideoEntry, OnnxVisionEntry,
    TtsModelEntry, VisionPreprocess, license_territory,
};
pub use chat::{
    ChatMessage, ChatWithToolsResult, GenerationConfig, InferenceResult, StopReason, ToolCall,
    ToolDefinition, media_marker,
};
#[cfg(feature = "engine")]
pub use detection_runtime::{
    DetectResult, Detection, DetectionRuntime, Detector, DetrFamily, GenericDetrDetector,
    StubDetector,
};
pub use engine_config::{EnergyConfig, EnginesConfig, EnvironmentPin, OnnxConfig, OnnxSettings};
pub use error::{ModelError, Result};
pub use hf_download::{
    ArtifactSpec, BlobFetcher, DownloadProgress, DownloadState, HfArtifactDownloader, HfDownloader,
    PeerHint, SourcePolicy,
};
pub use jurisdiction::{
    Ed25519JurisdictionSigner, IdentityKeyCheck, IdentityKeyJurisdictionSigner, JurisdictionError,
    JurisdictionSigner, SharedJurisdictionSigner, check_receipt_satisfies_pin, verify_receipt,
    verify_response_receipt,
};
pub use latency::LatencyTail;
pub use library::{
    CategoryType, CompatibilityRequirements, LibraryModelInfo, ModelCategory, ModelHighlight,
    ModelLibrary,
};
pub use load::{LoadGuard, LoadLevel, LoadTracker, ModelLoadSnapshot, estimate_max_concurrent};
#[cfg(feature = "engine")]
pub use media_runtime::{
    Latent, MediaModelInfo, MediaRuntime, NATIVE_PIPELINES, Output, RenderJob, Rendered,
};
#[cfg(feature = "engine")]
pub use model_host::ModelHost;
#[cfg(feature = "engine")]
pub use moe_compute::{BackendKind, ComputeBackend, CpuCompute, ExpertCompute, Weight};
#[cfg(feature = "engine")]
pub use moe_exec::{
    ExpertExecuteRequest, ExpertExecuteResponse, ExpertFfn, ExpertQuantPlan, ExpertTier,
    GatingNetwork, LatentProjection, MoeCombiner, MoeExecError, MoeExpertRuntime,
    MoeExpertRuntimeStatus, MoeLoadedExpert, MoeLoadedGate, PartialCombine, ResidencyConfig,
    RoutedSlot, RoutedToken, combine_expert_outputs, latent_moe_forward, quantize_expert_blob,
    to_token_routing,
};
#[cfg(feature = "engine")]
pub use moe_extract::{MoeExtractor, MoeTensorNaming};
pub use moe_quant::{QuantError, QuantKind, QuantMatrix};
pub use moe_receipt::{
    ActivationRow, ActivationVerification, DEFAULT_ACTIVATION_K, ExpertActivationCommitment,
    ExpertExecutionReceipt, PendingExpertReceipt, build_expert_receipt,
    expert_receipt_signing_payload, start_expert_receipt, verify_activation_commitment,
    verify_expert_receipt,
};
pub use moe_router::{
    DispatchPlan, ExpertBatch, HolderEndpoint, MoeDispatchError, TokenAssignment, TokenRouting,
    TokenSlot, plan_dispatch,
};
pub use moe_shard::{ExpertHolder, ExpertId, MoeShardView, ReplicationPolicy};
#[cfg(feature = "engine")]
pub use praecise_diffusion::Precision as MediaPrecision;
#[cfg(feature = "engine")]
pub use praecise_runtime::AdapterSpec;
#[cfg(feature = "engine")]
pub use praecise_runtime::batching::{BatchEngine, BatchRequest, max_slots};
pub use praecise_runtime::{ImportChain, KvBlob, ModelFingerprint};
pub use pricing::PriceContext;
pub use provenance::{
    ASSERTION_AI_GENERATED, ASSERTION_DEEPFAKE, HardwareProvenanceSigner, ProvenanceError,
    ProvenanceSigner, ProvenanceStore, SharedProvenanceSigner, hash_content, verify_manifest,
    verify_response_manifest,
};
pub use provider::{ProviderManager, ProviderMetrics, ProviderWithMetrics};
pub use registry::{ModelFilter, ModelRegistry, RegistryEvent};
pub use routing::{
    CircuitBreaker, CircuitBreakerState, InferenceRouter, ProviderTransport, RouterMetricsSnapshot,
    RoutingConfig, RoutingStrategy,
};
#[cfg(feature = "engine")]
pub use runtime::{
    ExportedDelta, HardwareInfo, ModelRuntime, SequenceEngine, SessionTurn, StandbyModel,
    TurnCheckpoint,
};
pub use sealed::{
    DEFAULT_SHARD_BYTES, RecipientEnclaveAttester, RecipientSpec, SEALED_WRAP_ALG,
    SealedModelManifest, SealedModelShard, SealedModelStore, SealedRecipient,
    compute_manifest_hash, compute_shard_ciphertext_hash, seal_model_file, unseal_model_to_file,
};
#[cfg(feature = "engine")]
pub use segmentation_runtime::{
    BoxPrompt, GenericSamSegmenter, PointPrompt, SamFamily, SegmentMask, SegmentPrompt,
    SegmentResult, SegmentationRuntime, Segmenter, StubSegmenter,
};
pub use sla::{
    BeaconProbe, CapacityResult, CapacityWork, MAX_POSSESSION_DEALS, MAX_PROBE_TOKENS,
    MAX_STATE_READS, MIN_SLA_RESPONSE_WINDOW_MS, PendingSlaResponse, PossessionDeal, ProbeBeacon,
    SLA_BEACON_TOPIC, SLA_PROBE_DOMAIN, SLA_RESPONSE_DOMAIN, STATE_READ_NAMESPACE, SlaEnvelope,
    SlaManager, SlaProbe, SlaResponse, SlaResult, SlaSignature, StateReadEntry, Verified,
    inference_prompt, possession_nonce, probe_wire,
    response_signing_payload as sla_response_signing_payload, state_read_keys,
};
#[cfg(feature = "engine")]
pub use text_embedding_runtime::{
    EmbedInput, EmbedRole, GenericTextEncoder, StubTextEncoder, TextEmbedConfig, TextEmbedResult,
    TextEmbeddingRuntime, TextEncoder, TextEncoderFamily, apply_embedding_template,
    chat_instruction,
};
#[cfg(feature = "engine")]
pub use text_segmentation_runtime::{
    Sam3Segmenter, StubTextSegmenter, TextPromptableSegmenter, TextSegmentBoxPrompt,
    TextSegmentConfig, TextSegmentResult, TextSegmentation, TextSegmentationRuntime,
};
pub use toploc::{
    DEFAULT_COMMITMENT_K, InferenceCommitment, MAX_COMMITMENT_K, MIN_INDEX_OVERLAP, StepComparison,
    StepRecord, Tolerance, TopKEntry, VerificationOutcome, compare_step, top_k_from_logits,
    verify_commitment_with,
};
#[cfg(feature = "engine")]
pub use ts_runtime::{
    ForecastConfig, ForecastModel, ForecastResult, GenericForecast, TimeseriesRuntime,
};
pub use usage::{GlobalUsageStats, ModelUsageStats, ProviderUsageStats, UsageRecord, UsageTracker};
#[cfg(feature = "engine")]
pub use video_runtime::{
    FramePooledVideoEncoder, StubVideoEncoder, VideoEmbedConfig, VideoEmbedResult, VideoEncoder,
    VideoRuntime,
};
#[cfg(feature = "engine")]
pub use vision_runtime::{
    GenericImageEncoder, ImageEmbedConfig, ImageEmbedResult, ImageEncoder, ImageNormalization,
    VisionRuntime, cosine_similarity, image_dimensions,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_module_imports() {
        // Simple test to verify all modules are accessible
        let _registry = ModelRegistry::new(CatalogCell::default());
        let _provider_manager = ProviderManager::new();
        let _prices = PriceContext::default();
        let _library = ModelLibrary::new();
    }
}
