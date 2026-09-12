//! Errors for the Secure Enclave machine root.

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No Secure Enclave on this machine, or not an Apple target.
    ///
    /// Deliberately distinct from [`Self::Enclave`]: "this platform cannot do
    /// it" and "the enclave refused" lead to different operator actions, and
    /// collapsing them would send someone debugging hardware that isn't there.
    #[error("secure enclave unavailable: {0}")]
    Unavailable(String),

    /// The enclave is present but the operation failed.
    #[error("secure enclave error: {0}")]
    Enclave(String),
}
