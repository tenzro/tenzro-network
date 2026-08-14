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
//! - **Download Manager**: Model download management with progress tracking and verification
//!
//! ## Example Usage
//!
//! ```rust,no_run
//! use tenzro_model::{
//!     registry::ModelRegistry,
//!     provider::ProviderManager,
//!     routing::{InferenceRouter, RoutingConfig, RoutingStrategy},
//!     pricing::PricingEngine,
//! };
//! use tenzro_types::model::ModelInfo;
//! use std::sync::Arc;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create registry and register a model
//! let registry = ModelRegistry::new();
//! // let model = ModelInfo::new(...);
//! // registry.register_model(model)?;
//!
//! // Set up provider management
//! let provider_manager = Arc::new(ProviderManager::new());
//! // provider_manager.register_provider(provider, has_tee)?;
//!
//! // Configure routing
//! let config = RoutingConfig::new()
//!     .with_strategy(RoutingStrategy::WeightedScore)
//!     .with_tee_required(false);
//!
//! let router = InferenceRouter::with_config(provider_manager.clone(), config);
//!
//! // Route an inference request
//! // let request = InferenceRequest::new(...);
//! // let provider_address = router.route_request(&request)?;
//!
//! // Calculate pricing
//! let pricing_engine = PricingEngine::new();
//! // let cost = pricing_engine.calculate_cost(&model_id, &pricing_config, &metadata)?;
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
//! ### Download Manager
//!
//! The [`download`] module manages model downloads:
//!
//! - Download models with progress tracking
//! - Pause, resume, and cancel downloads
//! - Checksum verification
//! - Concurrent download management

pub mod audio_runtime;
pub mod autotune;
pub mod batching;
pub mod catalog;
pub mod cluster;
pub mod detection_runtime;
pub mod difficulty;
pub mod download;
pub mod error;
pub mod external_engine;
pub mod gguf_shape;
pub mod hf_download;
pub mod jurisdiction;
pub mod latency;
pub mod library;
pub mod lifecycle;
pub mod load;
pub mod memory_budget;
pub mod meta_router;
pub mod muse_harmony;
pub mod model_hash;
pub mod moe_compute;
#[cfg(all(feature = "moe-gpu", feature = "moe-cuda"))]
pub mod moe_compute_cuda;
#[cfg(all(feature = "moe-gpu", feature = "moe-wgpu"))]
pub mod moe_compute_wgpu;
pub mod moe_exec;
pub mod moe_extract;
pub mod moe_prefetch;
pub mod moe_quant;
pub mod moe_receipt;
pub mod moe_router;
pub mod moe_shard;
pub mod onnx_session;
pub mod pricing;
pub mod provenance;
pub mod provider;
pub mod provisioning;
pub mod quant;
pub mod registry;
pub mod routing;
pub mod runtime;
pub mod sealed;
pub mod segmentation_runtime;
pub mod serve_advisor;
pub mod sla;
pub mod text_embedding_runtime;
pub mod text_segmentation_runtime;
pub(crate) mod tool_grammar;
pub mod toploc;
pub mod traffic;
pub mod ts_runtime;
pub mod usage;
pub mod video_runtime;
pub mod vision_runtime;

// Re-export commonly used types
pub use audio_runtime::{
    AudioRuntime, MoonshineTranscriber, TranscribeConfig, TranscribeResult, Transcriber,
    TranscriptSegment, WhisperFamily, WhisperTranscriber,
};
pub use batching::{BatchEngine, BatchRequest, max_slots};
pub use catalog::{
    HfModelEntry, LicenseTier, MediaGenExpertPair, MediaGenModelEntry, ModelArchitecture, MoeShape,
    MtpKind, OnnxAudioEntry, OnnxDetectionEntry, OnnxForecastEntry, OnnxSegmentationEntry,
    OnnxTextEmbeddingEntry, OnnxTextSegmentationEntry, OnnxVideoEntry, OnnxVisionEntry,
    TtsModelEntry, custom_license_id, get_audio_catalog, get_audio_model_by_id,
    get_detection_catalog, get_detection_model_by_id, get_forecast_catalog,
    get_forecast_model_by_id, get_media_gen_catalog, get_media_gen_model_by_id,
    get_media_gen_models_for_kind, get_model_by_id, get_model_catalog, get_segmentation_catalog,
    get_segmentation_model_by_id, get_text_embedding_catalog, get_text_embedding_model_by_id,
    get_text_segmentation_catalog, get_text_segmentation_model_by_id, get_tts_catalog,
    get_tts_model_by_id, get_video_catalog, get_video_model_by_id, get_vision_catalog,
    get_vision_model_by_id, media_gen_model_splits,
};
pub use detection_runtime::{
    DetectResult, Detection, DetectionRuntime, Detector, DetrFamily, GenericDetrDetector,
    StubDetector,
};
pub use download::{DownloadManager, DownloadStatus, DownloadTask};
pub use error::{ModelError, Result};
pub use external_engine::{ExternalEngine, ExternalEngineKind};
pub use hf_download::{
    ArtifactSpec, BlobFetcher, DownloadProgress, DownloadState, HfArtifactDownloader, HfDownloader,
    PeerHint, SourcePolicy,
};
pub use jurisdiction::{
    Ed25519JurisdictionSigner, JurisdictionError, JurisdictionSigner, SharedJurisdictionSigner,
    check_receipt_satisfies_pin, verify_receipt, verify_response_receipt,
};
pub use latency::LatencyTail;
pub use library::{
    CategoryType, CompatibilityRequirements, LibraryModelInfo, ModelCategory, ModelHighlight,
    ModelLibrary,
};
pub use load::{LoadGuard, LoadLevel, LoadTracker, ModelLoadSnapshot, estimate_max_concurrent};
pub use model_hash::{
    CanonicalModelHash, MODEL_MANIFEST_DOMAIN, ModelFileRecord, ModelHashRegistry, ModelManifest,
    blake3_of_bytes, compute_model_manifest_hash,
};
pub use moe_compute::{BackendKind, ComputeBackend, CpuCompute, ExpertCompute, Weight};
pub use moe_exec::{
    ExpertExecuteRequest, ExpertExecuteResponse, ExpertFfn, ExpertQuantPlan, ExpertTier,
    GatingNetwork, MoeCombiner, MoeExecError, MoeExpertRuntime, MoeExpertRuntimeStatus,
    MoeLoadedExpert, MoeLoadedGate, PartialCombine, ResidencyConfig, RoutedSlot, RoutedToken,
    combine_expert_outputs, quantize_expert_blob, to_token_routing,
};
pub use moe_extract::{MoeExtractor, MoeTensorNaming};
pub use moe_quant::{QuantError, QuantKind, QuantMatrix};
pub use moe_receipt::{
    ActivationRow, ActivationVerification, DEFAULT_ACTIVATION_K, ExpertActivationCommitment,
    ExpertExecutionReceipt, build_expert_receipt, expert_receipt_signing_payload,
    verify_activation_commitment, verify_expert_receipt,
};
pub use moe_router::{
    DispatchPlan, ExpertBatch, HolderEndpoint, MoeDispatchError, TokenAssignment, TokenRouting,
    TokenSlot, plan_dispatch,
};
pub use moe_shard::{ExpertHolder, ExpertId, MoeShardView, RepairAssignment, ReplicationPolicy};
pub use pricing::{PriceEstimate, PricingEngine};
pub use provenance::{
    ASSERTION_AI_GENERATED, ASSERTION_DEEPFAKE, Ed25519ProvenanceSigner, ProvenanceError,
    ProvenanceSigner, ProvenanceStore, SharedProvenanceSigner, hash_content, verify_manifest,
    verify_response_manifest,
};
pub use provider::{ProviderManager, ProviderMetrics, ProviderWithMetrics};
pub use registry::{ModelFilter, ModelRegistry, RegistryEvent};
pub use routing::{
    CircuitBreaker, CircuitBreakerState, InferenceRouter, RouterMetricsSnapshot, RoutingConfig,
    RoutingStrategy,
};
pub use runtime::{
    ChatMessage, ChatWithToolsResult, GenerationConfig, HardwareInfo, InferenceResult,
    ModelRuntime, StopReason, ToolCall, ToolDefinition, media_marker,
};
pub use sealed::{
    DEFAULT_SHARD_BYTES, RecipientEnclaveAttester, RecipientSpec, SEALED_WRAP_ALG,
    SealedModelManifest, SealedModelShard, SealedModelStore, SealedRecipient,
    compute_manifest_hash, compute_shard_ciphertext_hash, seal_model_file, unseal_model_to_file,
};
pub use segmentation_runtime::{
    BoxPrompt, GenericSamSegmenter, PointPrompt, SamFamily, SegmentMask, SegmentPrompt,
    SegmentResult, SegmentationRuntime, Segmenter, StubSegmenter,
};
pub use sla::{
    DEFAULT_SLA_SLASH_AMOUNT, DEFAULT_SLA_SLASH_THRESHOLD, ProviderSlashingCallback,
    SLA_PROBE_DOMAIN, SLA_RESPONSE_DOMAIN, SlaEnvelope, SlaManager, SlaProbe, SlaResponse,
    SlaResult, response_signing_payload as sla_response_signing_payload,
};
pub use text_embedding_runtime::{
    GenericTextEncoder, StubTextEncoder, TextEmbedConfig, TextEmbedResult, TextEmbeddingRuntime,
    TextEncoder, TextEncoderFamily,
};
pub use text_segmentation_runtime::{
    Sam3Segmenter, StubTextSegmenter, TextPromptableSegmenter, TextSegmentBoxPrompt,
    TextSegmentConfig, TextSegmentResult, TextSegmentation, TextSegmentationRuntime,
};
pub use toploc::{
    DEFAULT_COMMITMENT_K, InferenceCommitment, MAX_COMMITMENT_K, MAX_MEAN_LOGIT_DELTA,
    MIN_INDEX_OVERLAP, MIN_PASSING_STEP_FRACTION, StepComparison, StepRecord, TopKEntry,
    VerificationOutcome, compare_step, top_k_from_logits, verify_commitment,
};
pub use ts_runtime::{
    ForecastConfig, ForecastModel, ForecastResult, GenericForecast, TimeseriesRuntime,
};
pub use usage::{GlobalUsageStats, ModelUsageStats, ProviderUsageStats, UsageRecord, UsageTracker};
pub use video_runtime::{
    StubVideoEncoder, VideoEmbedConfig, VideoEmbedResult, VideoEncoder, VideoRuntime,
    VisionFallbackVideoEncoder,
};
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
        let _registry = ModelRegistry::new();
        let _provider_manager = ProviderManager::new();
        let _pricing_engine = PricingEngine::new();
        let _library = ModelLibrary::new();
    }
}
