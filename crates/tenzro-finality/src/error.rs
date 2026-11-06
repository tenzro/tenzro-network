//! Why a finality check fails.

/// A finality check that did not pass.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FinalityError {
    /// A validator key is malformed.
    #[error("Invalid validator key: {0}")]
    InvalidValidatorKey(String),
    /// A committee is malformed.
    #[error("Invalid validator set: {0}")]
    InvalidValidatorSet(String),
    /// A certificate does not verify.
    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),
}

/// Result of a finality check.
pub type Result<T> = std::result::Result<T, FinalityError>;
