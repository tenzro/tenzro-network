//! Error types for the Praecise inference runtime.
//!
//! These are the backend-agnostic inference errors. Platform-specific errors
//! (modality mismatch, license acceptance, registry/routing) belong to the
//! host application, which wraps these.

use thiserror::Error;

/// Result type for Praecise runtime operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur during inference on the Praecise runtime.
#[derive(Debug, Error)]
pub enum Error {
    /// Inference request failed.
    #[error("Inference error: {0}")]
    Inference(String),

    /// Not enough free memory to load the model. Raised by the load-time
    /// admission check before the backend loads the weights, so a load fails
    /// cleanly with a typed error instead of OOM-killing the process.
    #[error(
        "Insufficient memory to load '{model_id}': need ~{required_mb} MB, {available_mb} MB available"
    )]
    InsufficientMemory {
        /// The model whose load was refused.
        model_id: String,
        /// Estimated memory the load needs, in MB.
        required_mb: u64,
        /// Free memory available at the time of the check, in MB.
        available_mb: u64,
    },

    /// A model's local inference queue is saturated; load is being shed rather
    /// than queued without bound.
    #[error(
        "Inference queue full for '{model_id}': {waiting} requests already waiting (max {max})"
    )]
    QueueFull {
        /// The saturated model.
        model_id: String,
        /// Requests already waiting.
        waiting: usize,
        /// The waiting-queue bound.
        max: usize,
    },

    /// Speculative decoding (a paired drafter / MTP head) was requested but the
    /// backend cannot satisfy it for this model.
    #[error("Speculative decoding unavailable: {reason}")]
    SpeculativeUnavailable {
        /// Why speculative decoding could not run.
        reason: String,
    },

    /// JSON serialization error.
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Catch-all runtime error.
    #[error("{0}")]
    Other(String),
}
