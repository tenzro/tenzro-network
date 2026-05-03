//! Error types for Tenzro Network wallet operations.

use thiserror::Error;

/// Wallet-specific errors for Tenzro Network.
#[derive(Debug, Error)]
pub enum WalletError {
    /// Wallet not found
    #[error("Wallet not found: {0}")]
    WalletNotFound(String),

    /// Invalid wallet ID
    #[error("Invalid wallet ID: {0}")]
    InvalidWalletId(String),

    /// Wallet already exists
    #[error("Wallet already exists: {0}")]
    WalletAlreadyExists(String),

    /// Insufficient balance
    #[error("Insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u128, need: u128 },

    /// Asset not supported
    #[error("Asset not supported: {0}")]
    AssetNotSupported(String),

    /// Invalid key share
    #[error("Invalid key share: {0}")]
    InvalidKeyShare(String),

    /// Threshold not met
    #[error("Threshold not met: got {got}, need {need}")]
    ThresholdNotMet { got: usize, need: usize },

    /// Signature generation failed
    #[error("Signature generation failed: {0}")]
    SignatureFailed(String),

    /// Keystore error
    #[error("Keystore error: {0}")]
    KeystoreError(String),

    /// Encryption error
    #[error("Encryption error: {0}")]
    EncryptionError(String),

    /// Decryption error
    #[error("Decryption error: {0}")]
    DecryptionError(String),

    /// Invalid password
    #[error("Invalid password")]
    InvalidPassword,

    /// Provisioning failed
    #[error("Provisioning failed: {0}")]
    ProvisioningFailed(String),

    /// Transaction validation failed
    #[error("Transaction validation failed: {0}")]
    TransactionValidationFailed(String),

    /// Signature verification failed
    #[error("Signature verification failed: {0}")]
    SignatureVerificationFailed(String),

    /// Contact not found
    #[error("Contact not found: {0}")]
    ContactNotFound(String),

    /// State sync error
    #[error("State sync error: {0}")]
    StateSyncError(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Cryptographic error
    #[error("Crypto error: {0}")]
    CryptoError(#[from] tenzro_crypto::CryptoError),

    /// IO error
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// Generic error
    #[error("{0}")]
    Other(String),
}

/// Result type for wallet operations in Tenzro Network.
pub type Result<T> = std::result::Result<T, WalletError>;
