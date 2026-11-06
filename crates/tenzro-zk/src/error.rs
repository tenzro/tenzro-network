//! Error types for the Tenzro Network ZK system

use thiserror::Error;

/// Result type for ZK operations
pub type Result<T> = std::result::Result<T, ZkError>;

/// Zero-knowledge proof errors
#[derive(Debug, Error)]
pub enum ZkError {
    /// The verifier rejected the proof.
    #[error("Proof rejected: {0}")]
    ProofRejected(String),

    /// The prover could not produce a proof.
    #[error("Proof generation failed: {0}")]
    ProofGenerationFailed(String),

    /// Proof bytes could not be encoded or decoded.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// The attestation does not carry, or does not bind, the proof.
    #[error("TEE attestation error: {0}")]
    TeeAttestationError(String),

    /// JSON error
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}
