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

    /// Runtime / catch-all error
    #[error("{0}")]
    Other(String),
}
