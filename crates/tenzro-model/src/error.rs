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
    #[error(
        "Modality mismatch: model '{model_id}' is {model_modality:?}, but payload is {payload_modality:?}"
    )]
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

    /// The caller may not use this model: it is gated or private and the
    /// caller presented no credential that covers it.
    #[error("{0}")]
    AccessDenied(String),

    /// Provider capacity exceeded
    #[error("Capacity exceeded for provider")]
    CapacityExceeded,

    /// The node does not have enough free memory to load the model. Raised by
    /// the load-time admission check before `LlamaModel::load_from_file`, so a
    /// provider fails cleanly with a typed error instead of OOM-killing the
    /// process mid-load.
    #[error(
        "Insufficient memory to load '{model_id}': need ~{required_mb} MB, {available_mb} MB available"
    )]
    InsufficientMemory {
        model_id: String,
        required_mb: u64,
        available_mb: u64,
    },

    /// The node's admission layer turned the request away: every slot is
    /// busy and the queue is full, or the wait would pass the caller's
    /// budget. Carries when to retry.
    #[error("{}; retry after {} ms", .0.message(), .0.retry_after_ms())]
    Busy(crate::traffic::Refusal),

    /// A model is already loaded by another engine on this node. A model is
    /// served by one engine at a time; unload it before loading it elsewhere.
    #[error(
        "model '{model_id}' is already loaded by the {held_by} engine; unload it there before loading it with the {requested} engine"
    )]
    EngineConflict {
        model_id: String,
        held_by: String,
        requested: String,
    },

    /// The engine this node would serve the model with cannot serve it, for
    /// a reason that holds whatever the request. The load is refused with
    /// that reason instead of being attempted.
    #[error("model '{model_id}' cannot be served by this node: {reason}")]
    Unservable { model_id: String, reason: String },

    /// Invalid model configuration
    #[error("Invalid model: {0}")]
    InvalidModel(String),

    /// The caller's input cannot be served as given (an undecodable picture,
    /// a video whose frames differ in size, media sent to a text-only model).
    #[error("Invalid input: {0}")]
    InvalidInput(String),

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
    /// but the running language runtime cannot satisfy it for this model:
    /// no drafter is loaded beside it and the model carries no inline MTP
    /// head.
    #[error("Multi-Token Prediction unavailable: {reason}")]
    MtpUnavailable { reason: String },

    /// A model's license tier is not admitted by the operator's acceptance
    /// policy. NonCommercial models require `--accept-non-commercial`;
    /// CommercialCustom models require `--accept-license <id>` for their
    /// specific license id.
    #[error(
        "license not accepted for model '{model_id}': tier {tier:?}, license id {license_id:?}"
    )]
    LicenseNotAccepted {
        model_id: String,
        tier: tenzro_types::model::LicenseTier,
        license_id: Option<String>,
    },

    /// Sealed-model (encrypted shard) error: sealing, unsealing, manifest
    /// signature verification, recipient lookup, or shard integrity failure.
    #[error("Sealed model error: {0}")]
    SealedModel(String),

    /// A `Network` source policy was requested but no verified network
    /// provider currently holds the blob (or no peer hint / fetcher was
    /// wired), so there is no non-HuggingFace source to fetch from. The
    /// `Network` policy never falls back to the HuggingFace CDN, so this is
    /// terminal rather than a fallback trigger.
    #[error("No verified network provider holds '{0}' and the source policy forbids HuggingFace")]
    NoNetworkSource(String),

    /// Runtime / catch-all error
    #[error("{0}")]
    Other(String),
}

/// The engine's errors, in this crate's taxonomy.
///
/// Inference runs in the Praecise engine; this conversion is the one place
/// its errors enter this crate.
impl From<praecise_runtime::Error> for ModelError {
    fn from(e: praecise_runtime::Error) -> Self {
        ModelError::Other(e.to_string())
    }
}

#[cfg(feature = "engine")]
impl From<praecise_onnx::Error> for ModelError {
    fn from(e: praecise_onnx::Error) -> Self {
        use praecise_onnx::Error as E;
        match e {
            E::ModelNotFound(m) => Self::ModelNotFound(m),
            E::ProviderNotAvailable(m) => Self::ProviderNotAvailable(m),
            E::InferenceError(m) => Self::InferenceError(m),
            E::InvalidModel(m) => Self::InvalidModel(m),
            E::InvalidInput(m) => Self::InvalidInput(m),
        }
    }
}

/// A model of this crate that serves one of the engine's ONNX families
/// answers in the engine's errors.
#[cfg(feature = "engine")]
impl From<ModelError> for praecise_onnx::Error {
    fn from(e: ModelError) -> Self {
        match e {
            ModelError::ModelNotFound(m) => Self::ModelNotFound(m),
            ModelError::ProviderNotAvailable(m) => Self::ProviderNotAvailable(m),
            ModelError::InferenceError(m) => Self::InferenceError(m),
            ModelError::InvalidModel(m) => Self::InvalidModel(m),
            ModelError::InvalidInput(m) => Self::InvalidInput(m),
            other => Self::InferenceError(other.to_string()),
        }
    }
}
