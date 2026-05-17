//! Settlement-specific errors

use thiserror::Error;

/// Result type for settlement operations
pub type Result<T> = std::result::Result<T, SettlementError>;

/// Errors that can occur during settlement operations
#[derive(Error, Debug, Clone)]
pub enum SettlementError {
    /// Insufficient funds for settlement
    #[error("Insufficient funds: required {required}, available {available}")]
    InsufficientFunds {
        /// Required amount
        required: u128,
        /// Available amount
        available: u128,
    },

    /// Settlement not found
    #[error("Settlement not found: {0}")]
    SettlementNotFound(String),

    /// Escrow account not found
    #[error("Escrow account not found: {0}")]
    EscrowNotFound(String),

    /// Escrow has expired
    #[error("Escrow has expired: {0}")]
    EscrowExpired(String),

    /// Escrow already released
    #[error("Escrow already released: {0}")]
    EscrowAlreadyReleased(String),

    /// ERC-7683 destination-side fill rejected because a prior fill is already
    /// recorded for this `order_id`. The 7683 spec requires destination
    /// settlers to enforce single-shot fills; the carried hex is the order ID.
    #[error("ERC-7683 order already filled: {0}")]
    OrderAlreadyFilled(String),

    /// Invalid proof provided
    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    /// Payment failed
    #[error("Payment failed: {0}")]
    PaymentFailed(String),

    /// Batch error
    #[error("Batch error: {0}")]
    BatchError(String),

    /// Unauthorized operation
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Invalid amount
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    /// Micropayment channel not found
    #[error("Channel not found: {0}")]
    ChannelNotFound(String),

    /// Micropayment channel closed
    #[error("Channel closed: {0}")]
    ChannelClosed(String),

    /// Invalid channel state
    #[error("Invalid channel state: {0}")]
    InvalidChannelState(String),

    /// Invalid signature
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Arithmetic overflow
    #[error("Arithmetic overflow: {0}")]
    ArithmeticOverflow(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Storage error
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Token operation error
    #[error("Token error: {0}")]
    TokenError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl From<tenzro_token::TokenError> for SettlementError {
    fn from(err: tenzro_token::TokenError) -> Self {
        Self::TokenError(err.to_string())
    }
}

impl From<tenzro_wallet::WalletError> for SettlementError {
    fn from(err: tenzro_wallet::WalletError) -> Self {
        Self::Internal(err.to_string())
    }
}

impl From<tenzro_storage::StorageError> for SettlementError {
    fn from(err: tenzro_storage::StorageError) -> Self {
        Self::StorageError(err.to_string())
    }
}
