//! Error types for the Tenzro Network ZK system

use thiserror::Error;

/// Result type for ZK operations
pub type Result<T> = std::result::Result<T, ZkError>;

/// Zero-knowledge proof errors
#[derive(Debug, Error)]
pub enum ZkError {
    /// Circuit synthesis error
    #[error("Circuit synthesis failed: {0}")]
    SynthesisError(String),

    /// Proof generation error
    #[error("Proof generation failed: {0}")]
    ProofGenerationError(String),

    /// Proof verification error
    #[error("Proof verification failed: {0}")]
    VerificationError(String),

    /// Invalid proof format
    #[error("Invalid proof format: {0}")]
    InvalidProofFormat(String),

    /// Invalid public inputs
    #[error("Invalid public inputs: {0}")]
    InvalidPublicInputs(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Deserialization error
    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    /// Setup/keygen error
    #[error("Setup/keygen failed: {0}")]
    SetupError(String),

    /// TEE attestation error
    #[error("TEE attestation error: {0}")]
    TeeAttestationError(String),

    /// TEE integration error
    #[error("TEE integration failed: {0}")]
    TeeIntegrationError(String),

    /// Invalid circuit constraints
    #[error("Invalid circuit constraints: {0}")]
    InvalidConstraints(String),

    /// Crypto error from tenzro-crypto
    #[error("Cryptographic error: {0}")]
    CryptoError(#[from] tenzro_crypto::CryptoError),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// JSON error
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),

    /// Hex decode error
    #[error("Hex decode error: {0}")]
    HexError(#[from] hex::FromHexError),

    /// Generic error
    #[error("{0}")]
    Other(String),
}

