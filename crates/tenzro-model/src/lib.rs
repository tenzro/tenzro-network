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
//! // let cost = pricing_engine.calculate_cost(&pricing_config, &metadata)?;
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
pub mod catalog;
pub mod detection_runtime;
pub mod download;
pub mod error;
pub mod hf_download;
pub mod library;
pub mod load;
pub mod pricing;
pub mod provenance;
pub mod provider;
pub mod provisioning;
pub mod registry;
pub mod routing;
pub mod runtime;
pub mod segmentation_runtime;
pub mod sla;
pub mod text_embedding_runtime;
pub mod ts_runtime;
pub mod usage;
pub mod video_runtime;
pub mod vision_runtime;

// Re-export commonly used types
pub use error::{ModelError, Result};
pub use registry::{ModelFilter, ModelRegistry, RegistryEvent};
pub use provider::{ProviderManager, ProviderMetrics, ProviderWithMetrics};
pub use routing::{
    CircuitBreaker, CircuitBreakerState, InferenceRouter, RoutingConfig, RoutingStrategy,
};
pub use pricing::{PriceEstimate, PricingEngine};
pub use library::{
    CategoryType, CompatibilityRequirements, LibraryModelInfo, ModelCategory, ModelHighlight,
    ModelLibrary,
};
pub use download::{DownloadManager, DownloadStatus, DownloadTask};
pub use catalog::{
    HfModelEntry, LicenseTier, ModelArchitecture, OnnxAudioEntry, OnnxDetectionEntry,
    OnnxForecastEntry, OnnxSegmentationEntry, OnnxTextEmbeddingEntry, OnnxVideoEntry,
    OnnxVisionEntry, get_audio_catalog, get_audio_model_by_id, get_detection_catalog,
    get_detection_model_by_id, get_forecast_catalog, get_forecast_model_by_id, get_model_by_id,
    get_model_catalog, get_segmentation_catalog, get_segmentation_model_by_id,
    get_text_embedding_catalog, get_text_embedding_model_by_id, get_video_catalog,
    get_video_model_by_id, get_vision_catalog, get_vision_model_by_id,
};
pub use hf_download::{
    ArtifactSpec, BlobFetcher, DownloadProgress, DownloadState, HfArtifactDownloader,
    HfDownloader, PeerHint,
};
pub use runtime::{
    ChatMessage, ChatWithToolsResult, GenerationConfig, HardwareInfo, InferenceResult,
    ModelRuntime, ToolCall, ToolDefinition,
};
pub use usage::{
    UsageTracker, UsageRecord, ModelUsageStats, ProviderUsageStats, GlobalUsageStats,
};
pub use load::{LoadTracker, LoadGuard, LoadLevel, ModelLoadSnapshot, estimate_max_concurrent};
pub use ts_runtime::{
    ForecastConfig, ForecastModel, ForecastResult, GenericForecast, TimeseriesRuntime,
};
pub use vision_runtime::{
    GenericImageEncoder, ImageEmbedConfig, ImageEmbedResult, ImageEncoder, ImageNormalization,
    VisionRuntime, cosine_similarity,
};
pub use text_embedding_runtime::{
    GenericTextEncoder, StubTextEncoder, TextEmbedConfig, TextEmbedResult, TextEmbeddingRuntime,
    TextEncoder, TextEncoderFamily,
};
pub use segmentation_runtime::{
    BoxPrompt, GenericSamSegmenter, PointPrompt, SamFamily, SegmentMask, SegmentPrompt,
    SegmentResult, SegmentationRuntime, Segmenter, StubSegmenter,
};
pub use detection_runtime::{
    DetectResult, Detection, DetectionRuntime, Detector, DetrFamily, GenericDetrDetector,
    StubDetector,
};
pub use audio_runtime::{
    AudioRuntime, MoonshineTranscriber, TranscribeConfig, TranscribeResult, Transcriber,
    TranscriptSegment, WhisperFamily, WhisperTranscriber,
};
pub use video_runtime::{
    StubVideoEncoder, VideoEmbedConfig, VideoEmbedResult, VideoEncoder, VideoRuntime,
    VisionFallbackVideoEncoder,
};
pub use provenance::{
    hash_content, verify_manifest, Ed25519ProvenanceSigner, ProvenanceError, ProvenanceSigner,
    ProvenanceStore, SharedProvenanceSigner, ASSERTION_AI_GENERATED, ASSERTION_DEEPFAKE,
};
pub use sla::{
    response_signing_payload as sla_response_signing_payload, ProviderSlashingCallback, SlaManager,
    SlaProbe, SlaResponse, SlaResult, DEFAULT_SLA_SLASH_AMOUNT, DEFAULT_SLA_SLASH_THRESHOLD,
    SLA_PROBE_DOMAIN, SLA_RESPONSE_DOMAIN,
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
