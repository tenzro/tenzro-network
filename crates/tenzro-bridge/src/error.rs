//! Bridge error types for Tenzro Network
//!
//! This module defines error types specific to cross-chain bridge operations.

use thiserror::Error;

/// Bridge-specific errors
#[derive(Debug, Error)]
pub enum BridgeError {
    /// Bridge protocol is not supported
    #[error("Bridge protocol not supported: {0}")]
    BridgeNotSupported(String),

    /// Chain is not supported by this bridge adapter
    #[error("Chain not supported: {0}")]
    ChainNotSupported(String),

    /// Transfer failed
    #[error("Transfer failed: {0}")]
    TransferFailed(String),

    /// Message delivery failed
    #[error("Message delivery failed: {0}")]
    MessageDeliveryFailed(String),

    /// Insufficient liquidity for the transfer
    #[error("Insufficient liquidity")]
    InsufficientLiquidity,

    /// Invalid proof provided
    #[error("Invalid proof")]
    InvalidProof,

    /// Adapter-specific error
    #[error("Adapter error: {0}")]
    AdapterError(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// Operation timed out
    #[error("Operation timed out")]
    Timeout,

    /// Asset is not supported for bridging
    #[error("Unsupported asset: {0}")]
    UnsupportedAsset(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// No route available for the requested transfer
    #[error("No route available from {0} to {1}")]
    NoRouteAvailable(String, String),

    /// Transfer not found
    #[error("Transfer not found: {0}")]
    TransferNotFound(String),

    /// Replay attack detected
    #[error("Replay attack detected: {0}")]
    ReplayAttack(String),

    /// Invalid message hash
    #[error("Invalid message hash")]
    InvalidMessageHash,

    /// Adapter not available
    #[error("Adapter not available: {0}")]
    AdapterNotAvailable(String),

    /// Network communication error
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Invalid parameter provided
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
}

/// Type alias for Result with BridgeError
pub type Result<T> = std::result::Result<T, BridgeError>;
