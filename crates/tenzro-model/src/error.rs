//! Error types for the tenzro-model crate
//!
//! This module defines all error types that can occur during model registry,
//! provider management, routing, and inference operations.

use thiserror::Error;

/// Result type for model operations
pub type Result<T> = std::result::Result<T, ModelError>;

/// Errors that can occur in model operations
#[derive(Debug, Error)]
pub enum ModelError {
    /// Model not found in registry
    #[error("Model not found: {0}")]
    ModelNotFound(String),

    /// Model already exists in registry
    #[error("Model already exists: {0}")]
    ModelAlreadyExists(String),

    /// Provider not found
    #[error("Provider not found: {0}")]
    ProviderNotFound(String),

    /// Provider not available for inference
    #[error("Provider not available: {0}")]
    ProviderNotAvailable(String),

    /// No providers available for the requested model
    #[error("No providers available for model: {0}")]
    NoProvidersAvailable(String),

    /// Inference request failed
    #[error("Inference error: {0}")]
    InferenceError(String),

    /// Routing error
    #[error("Routing error: {0}")]
    RoutingError(String),

    /// Inference payload modality does not match the registered model's modality.
    ///
    /// Returned when a typed `InferencePayload` (e.g. `Forecast`, `VisionEmbed`)
    /// is dispatched to a model whose registered `ModelModality` doesn't support
    /// that payload kind — for example, sending a `Forecast` request to a `Text`
    /// model. Caught early in the router so we surface a typed error rather than
    /// a downstream parse failure inside a runtime.
    #[error("Modality mismatch: model '{model_id}' is {model_modality:?}, but payload is {payload_modality:?}")]
    ModalityMismatch {
        model_id: String,
        model_modality: tenzro_types::model::ModelModality,
        payload_modality: tenzro_types::model::ModelModality,
    },

    /// Pricing calculation error
    #[error("Pricing error: {0}")]
    PricingError(String),

    /// Model download error
    #[error("Download error: {0}")]
    DownloadError(String),

    /// Provider capacity exceeded
    #[error("Capacity exceeded for provider")]
    CapacityExceeded,

    /// The node does not have enough free memory to load the model. Raised by
    /// the load-time admission check before `LlamaModel::load_from_file`, so a
    /// provider fails cleanly with a typed error instead of OOM-killing the
    /// process mid-load.
    #[error("Insufficient memory to load '{model_id}': need ~{required_mb} MB, {available_mb} MB available")]
    InsufficientMemory {
        model_id: String,
        required_mb: u64,
        available_mb: u64,
    },

    /// A model's local inference queue is saturated. llama.cpp serializes
    /// decode on a single model context, so requests wait behind the one in
    /// flight. Past a bound we shed load with this typed error instead of
    /// letting the wait queue grow without limit and time every caller out.
    #[error("Inference queue full for '{model_id}': {waiting} requests already waiting (max {max})")]
    QueueFull {
        model_id: String,
        waiting: usize,
        max: usize,
    },

    /// Invalid model configuration
    #[error("Invalid model: {0}")]
    InvalidModel(String),

    /// Checksum verification failed
    #[error("Checksum mismatch: expected {expected}, got {actual}")]
    ChecksumMismatch { expected: String, actual: String },

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Binary serialization error (for storage)
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Storage error
    #[error("Storage error: {0}")]
    StorageError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Multi-Token Prediction was requested via `GenerationConfig.draft_n`
    /// but the running language runtime cannot satisfy it. The most common
    /// reason today is that the in-process `llama-cpp-2` binding doesn't
    /// yet expose llama.cpp's speculative-decoding API (`--spec-type
    /// draft-mtp`). Operators can still serve MTP GGUFs through a raw
    /// `llama-cli` / `llama-server` invocation outside the in-process
    /// runtime until the binding lands.
    #[error("Multi-Token Prediction unavailable: {reason}")]
    MtpUnavailable { reason: String },

    /// Runtime / catch-all error
    #[error("{0}")]
    Other(String),
}
