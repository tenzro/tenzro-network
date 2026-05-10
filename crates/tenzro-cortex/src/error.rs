//! Cortex error type.

use thiserror::Error;

/// Errors returned by the Tenzro Cortex crate.
#[derive(Debug, Error)]
pub enum CortexError {
    #[error("invalid reasoning budget: {0}")]
    InvalidBudget(String),

    #[error("model {0} not registered as Cortex")]
    UnknownModel(String),

    #[error("worker rejected the request: {0}")]
    WorkerRejected(String),

    #[error("sidecar HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("sidecar returned non-success status {status}: {body}")]
    SidecarStatus { status: u16, body: String },

    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),

    #[error("cryptographic error: {0}")]
    Crypto(String),

    #[error("receipt verification failed: {0}")]
    InvalidReceipt(String),

    #[error("cost {cost} wei exceeds caller budget {budget} wei")]
    CostExceeded { cost: u128, budget: u128 },

    #[error("loops_used {loops_used} outside budget [{min},{max}]")]
    LoopsOutOfRange { loops_used: u32, min: u32, max: u32 },

    #[error("other: {0}")]
    Other(String),
}

/// Convenience `Result` alias used across the Cortex crate.
pub type Result<T> = std::result::Result<T, CortexError>;
