//! Error types for Tenzro Network cryptographic operations.

use thiserror::Error;

/// Cryptographic errors for Tenzro Network.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Invalid key format or length
    #[error("Invalid key: {0}")]
    InvalidKey(String),

    /// Invalid signature format or verification failed
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// Signature verification failed
    #[error("Signature verification failed")]
    VerificationFailed,

    /// Invalid public key
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid secret key
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    /// Invalid ciphertext
    #[error("Invalid ciphertext: {0}")]
    InvalidCiphertext(String),

    /// Invalid nonce
    #[error("Invalid nonce: {0}")]
    InvalidNonce(String),

    /// Hash operation failed
    #[error("Hash operation failed: {0}")]
    HashError(String),

    /// MPC operation failed
    #[error("MPC operation failed: {0}")]
    MpcError(String),

    /// Threshold not met
    #[error("Threshold not met: got {got}, need {need}")]
    ThresholdNotMet { got: usize, need: usize },

    /// Invalid share
    #[error("Invalid share: {0}")]
    InvalidShare(String),

    /// Hex decoding error
    #[error("Hex decoding error: {0}")]
    HexError(#[from] hex::FromHexError),

    /// UTF-8 encoding error
    #[error("UTF-8 error: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    /// Generic error
    #[error("{0}")]
    Other(String),
}

/// Result type for cryptographic operations in Tenzro Network.
pub type Result<T> = std::result::Result<T, CryptoError>;
