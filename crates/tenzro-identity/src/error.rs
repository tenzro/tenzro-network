//! Error types for the Tenzro Decentralized Identity Protocol

use thiserror::Error;

/// Result type for identity operations
pub type Result<T> = std::result::Result<T, IdentityError>;

/// Errors that can occur during identity operations
#[derive(Debug, Error)]
pub enum IdentityError {
    /// DID could not be parsed
    #[error("invalid DID format: {0}")]
    InvalidDid(String),

    /// Identity not found in the registry
    #[error("identity not found: {0}")]
    NotFound(String),

    /// Identity already exists
    #[error("identity already exists: {0}")]
    AlreadyExists(String),

    /// Identity is not in the required state
    #[error("identity is not active: {0}")]
    NotActive(String),

    /// Operation not permitted
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// Delegation scope violated
    #[error("delegation scope violation: {0}")]
    DelegationViolation(String),

    /// Credential error
    #[error("credential error: {0}")]
    CredentialError(String),

    /// Verification failed
    #[error("verification failed: {0}")]
    VerificationFailed(String),

    /// Trust chain is broken — an issuer in the chain is not Active,
    /// is not in the registry, has no key the credential could verify
    /// against, or its signature does not verify (CRITICAL #41).
    #[error("trust chain broken at issuer {issuer}: {reason}")]
    TrustChainBroken {
        /// DID of the issuer where the chain broke
        issuer: String,
        /// Human-readable reason
        reason: String,
    },

    /// A cycle was detected during trust chain traversal (CRITICAL #41).
    /// Contains the DID that was revisited.
    #[error("trust chain cycle detected at issuer {issuer}")]
    TrustChainCycle {
        /// DID that completed the cycle
        issuer: String,
    },

    /// Trust chain exceeded the configured maximum traversal depth
    /// (CRITICAL #41). Acts as a DoS guard against arbitrarily long
    /// or maliciously crafted issuer chains.
    #[error("trust chain exceeded max depth of {max_depth}")]
    TrustChainTooDeep {
        /// Maximum depth allowed by the verifier configuration
        max_depth: usize,
    },

    /// Trust chain terminated without reaching a recognized trust root
    /// (CRITICAL #41). The credential chain is internally consistent but
    /// does not anchor to any DID the verifier was configured to trust.
    #[error("trust chain did not reach a recognized trust root")]
    NoTrustRoot,

    /// Invalid service endpoint URL (MEDIUM #128)
    #[error("invalid service endpoint: {0}")]
    InvalidServiceEndpoint(String),

    /// Credential already issued / replay attempt (MEDIUM #129)
    #[error("duplicate credential: {0}")]
    DuplicateCredential(String),

    /// Username is already taken by another identity
    #[error("username already taken: {0}")]
    UsernameTaken(String),

    /// Username does not meet validation requirements
    #[error("invalid username: {0}")]
    UsernameInvalid(String),

    /// Wallet provisioning or binding error
    #[error("wallet error: {0}")]
    WalletError(String),

    /// Caller-supplied public key was malformed (wrong length, wrong
    /// curve, etc.). Used by BYOK registration paths.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Cryptographic operation failed
    #[error("crypto error: {0}")]
    CryptoError(String),

    /// Serialization/deserialization error
    #[error("serialization error: {0}")]
    SerializationError(String),

    /// Revocation broadcast could not be dispatched to the network layer.
    /// Best-effort: `revoke()` logs this and keeps the local revocation.
    #[error("revocation broadcast error: {0}")]
    BroadcastError(String),

    /// Remote DID resolution backend failed (transport or upstream error).
    /// `IdentityRegistry::resolve()` logs this and falls through to
    /// `NotFound` — a broken upstream must not mask a local lookup.
    #[error("resolution backend error: {0}")]
    ResolutionError(String),
}

impl From<tenzro_crypto::CryptoError> for IdentityError {
    fn from(e: tenzro_crypto::CryptoError) -> Self {
        IdentityError::CryptoError(e.to_string())
    }
}

impl From<tenzro_wallet::WalletError> for IdentityError {
    fn from(e: tenzro_wallet::WalletError) -> Self {
        IdentityError::WalletError(e.to_string())
    }
}

impl From<serde_json::Error> for IdentityError {
    fn from(e: serde_json::Error) -> Self {
        IdentityError::SerializationError(e.to_string())
    }
}
