//! Error types for the Tenzro Network TEE module.

use thiserror::Error;

/// Result type for TEE operations.
pub type Result<T> = std::result::Result<T, TeeError>;

/// Errors that can occur in TEE operations.
#[derive(Debug, Error)]
pub enum TeeError {
    /// TEE hardware is not available
    #[error("TEE hardware not available: {0}")]
    NotAvailable(String),

    /// Attestation generation failed
    #[error("Failed to generate attestation: {0}")]
    AttestationGenerationFailed(String),

    /// Attestation verification failed
    #[error("Attestation verification failed: {0}")]
    AttestationVerificationFailed(String),

    /// Invalid attestation report
    #[error("Invalid attestation report: {0}")]
    InvalidAttestationReport(String),

    /// Certificate chain validation failed
    #[error("Certificate chain validation failed: {0}")]
    CertificateValidationFailed(String),

    /// TCB (Trusted Computing Base) version is outdated
    #[error("TCB version outdated: current={current}, required={required}")]
    TcbOutdated { current: String, required: String },

    /// Enclave operation failed
    #[error("Enclave operation failed: {0}")]
    EnclaveOperationFailed(String),

    /// Key generation failed
    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    /// Cryptographic operation failed
    #[error("Cryptographic operation failed: {0}")]
    CryptoOperationFailed(String),

    /// Encryption failed
    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    /// Decryption failed
    #[error("Decryption failed: {0}")]
    DecryptionError(String),

    /// Invalid key handle
    #[error("Invalid key handle: {0}")]
    InvalidKeyHandle(String),

    /// Provider not found
    #[error("Provider not found: {0}")]
    ProviderNotFound(String),

    /// Provider registration failed
    #[error("Provider registration failed: {0}")]
    RegistrationFailed(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    /// I/O error
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// Cryptographic error
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl TeeError {
    /// Creates a new NotAvailable error.
    pub fn not_available(msg: impl Into<String>) -> Self {
        TeeError::NotAvailable(msg.into())
    }

    /// Creates a new AttestationVerificationFailed error.
    pub fn attestation_failed(msg: impl Into<String>) -> Self {
        TeeError::AttestationVerificationFailed(msg.into())
    }

    /// Creates a new Internal error.
    pub fn internal(msg: impl Into<String>) -> Self {
        TeeError::Internal(msg.into())
    }
}
