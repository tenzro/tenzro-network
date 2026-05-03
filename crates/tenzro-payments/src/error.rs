//! Error types for payment protocols

use thiserror::Error;

/// Result type for payment operations
pub type Result<T> = std::result::Result<T, PaymentError>;

/// Errors that can occur during payment protocol operations
#[derive(Debug, Error)]
pub enum PaymentError {
    /// Payment challenge creation failed
    #[error("challenge error: {0}")]
    ChallengeError(String),

    /// Payment credential invalid or creation failed
    #[error("credential error: {0}")]
    CredentialError(String),

    /// Payment verification failed
    #[error("verification failed: {0}")]
    VerificationFailed(String),

    /// Settlement failed
    #[error("settlement error: {0}")]
    SettlementError(String),

    /// Identity binding error
    #[error("identity error: {0}")]
    IdentityError(String),

    /// Protocol not supported
    #[error("unsupported protocol: {0}")]
    UnsupportedProtocol(String),

    /// Configuration error
    #[error("configuration error: {0}")]
    ConfigError(String),

    /// Network/HTTP error
    #[error("network error: {0}")]
    NetworkError(String),

    /// Insufficient funds
    #[error("insufficient funds: {0}")]
    InsufficientFunds(String),

    /// Session error
    #[error("session error: {0}")]
    SessionError(String),

    /// Serialization error
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Cryptographic operation error (signing, key derivation)
    #[error("crypto error: {0}")]
    CryptoError(String),

    /// RFC 9421 HTTP message signature error
    #[error("RFC 9421 signature error: {0}")]
    Rfc9421Error(String),

    /// Visa Trusted Agent Protocol error
    #[error("Visa TAP error: {0}")]
    VisaTapError(String),

    /// Mastercard Agent Pay error
    #[error("Mastercard Agent Pay error: {0}")]
    MastercardError(String),

    /// Replay attack detected (nonce reuse)
    #[error("replay detected: {0}")]
    ReplayDetected(String),

    /// Agent registry lookup failed
    #[error("agent registry error: {0}")]
    AgentRegistryError(String),

    /// Know Your Agent (KYA) verification failed
    #[error("KYA verification failed: {0}")]
    KyaError(String),
}

impl From<tenzro_identity::IdentityError> for PaymentError {
    fn from(e: tenzro_identity::IdentityError) -> Self {
        PaymentError::IdentityError(e.to_string())
    }
}

impl From<serde_json::Error> for PaymentError {
    fn from(e: serde_json::Error) -> Self {
        PaymentError::SerializationError(e.to_string())
    }
}

impl From<reqwest::Error> for PaymentError {
    fn from(e: reqwest::Error) -> Self {
        PaymentError::NetworkError(e.to_string())
    }
}

impl From<tenzro_crypto::CryptoError> for PaymentError {
    fn from(e: tenzro_crypto::CryptoError) -> Self {
        PaymentError::CryptoError(e.to_string())
    }
}
