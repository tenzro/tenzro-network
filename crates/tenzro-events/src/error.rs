//! Error types for tenzro-events

use thiserror::Error;

/// Result type alias for tenzro-events
pub type Result<T> = std::result::Result<T, EventError>;

/// Event system errors
#[derive(Debug, Error)]
pub enum EventError {
    #[error("storage error: {0}")]
    StorageError(String),

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("deserialization error: {0}")]
    DeserializationError(String),

    #[error("subscription not found: {0}")]
    SubscriptionNotFound(u64),

    #[error("webhook not found: {0}")]
    WebhookNotFound(String),

    #[error("capacity exceeded: {0}")]
    CapacityExceeded(String),

    #[error("rate limited: {0}")]
    RateLimited(String),

    #[error("delivery failed: {0}")]
    DeliveryFailed(String),

    #[error("invalid filter: {0}")]
    InvalidFilter(String),

    #[error("replay error: {0}")]
    ReplayError(String),

    #[error("bus error: {0}")]
    BusError(String),
}

impl From<serde_json::Error> for EventError {
    fn from(e: serde_json::Error) -> Self {
        EventError::SerializationError(e.to_string())
    }
}

impl From<bincode::Error> for EventError {
    fn from(e: bincode::Error) -> Self {
        EventError::SerializationError(e.to_string())
    }
}

impl From<tenzro_storage::StorageError> for EventError {
    fn from(e: tenzro_storage::StorageError) -> Self {
        EventError::StorageError(e.to_string())
    }
}
