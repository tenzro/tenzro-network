//! Error types for the Tenzro Agent system.

use thiserror::Error;

/// Result type for agent operations
pub type Result<T> = std::result::Result<T, AgentError>;

/// Errors that can occur in the agent system
#[derive(Debug, Error, Clone)]
pub enum AgentError {
    /// Agent not found
    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    /// Agent is not in Active status
    #[error("Agent not active: {0}")]
    AgentNotActive(String),

    /// Agent already exists
    #[error("Agent already exists: {0}")]
    AgentAlreadyExists(String),

    /// Spending policy violation (transaction rejected by per-tx or daily limit)
    #[error("Spending policy violation: {0}")]
    SpendingPolicyViolation(String),

    /// Invalid capability
    #[error("Invalid capability: {0}")]
    InvalidCapability(String),

    /// Message delivery failed
    #[error("Message delivery failed: {0}")]
    MessageDeliveryFailed(String),

    /// Protocol error
    #[error("Protocol error: {0}")]
    ProtocolError(String),

    /// Permission denied
    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    /// Resource limit exceeded
    #[error("Resource limit exceeded: {0}")]
    ResourceLimitExceeded(String),

    /// Lifecycle error
    #[error("Lifecycle error: {0}")]
    LifecycleError(String),

    /// Wallet error
    #[error("Wallet error: {0}")]
    WalletError(String),

    /// Crypto error
    #[error("Crypto error: {0}")]
    CryptoError(String),

    /// Invalid state transition
    #[error("Invalid state transition from {from} to {to}")]
    InvalidStateTransition {
        /// Current state
        from: String,
        /// Attempted new state
        to: String,
    },

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// Serialization error
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Invalid agent ID
    #[error("Invalid agent ID: {0}")]
    InvalidAgentId(String),

    /// Caller-supplied argument is malformed (wrong length, wrong type,
    /// out of range, etc.). Used by BYOK paths to reject keys that are
    /// not exactly the expected size.
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// Message queue full
    #[error("Message queue full for agent {0}")]
    MessageQueueFull(String),

    /// Capability not found
    #[error("Capability not found: {0}")]
    CapabilityNotFound(String),

    /// Attestation failed
    #[error("Attestation failed: {0}")]
    AttestationFailed(String),

    /// Storage error
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Blockchain binding failed (HIGH #105)
    ///
    /// Returned when the optional TDIP `IdentityRegistry` binding fails for a
    /// reason other than insufficient gas — e.g. registry rejected the public
    /// key, link_tenzro_agent failed, or the registry returned an internal
    /// error. The local agent registration is rolled back before this is
    /// returned, so the manager is left in a consistent state.
    #[error("Blockchain binding failed: {0}")]
    BlockchainBindingFailed(String),

    /// Insufficient gas for blockchain binding (HIGH #105)
    ///
    /// Returned when the caller asked for blockchain-bound agent registration
    /// but the gas budget supplied via `GasPolicy::PayUpTo` is smaller than the
    /// `fee_required` reported by the TDIP registry. The error carries
    /// (required_fee, supplied_budget) so the caller can surface the gap.
    #[error("Insufficient gas for blockchain binding: required {required}, supplied {supplied}")]
    InsufficientGas {
        /// Fee in smallest TNZO unit that the registry requires
        required: u128,
        /// Gas budget in smallest TNZO unit that the caller authorised
        supplied: u128,
    },

    /// Credential expired (HIGH #106)
    ///
    /// Returned when a caller attempts to inherit, use, or verify a credential
    /// whose `expires_at` is in the past, or whose `issued_at` is in the
    /// future (clock skew / forged credential). The error carries the
    /// credential type label and the offending DID so the caller can surface
    /// which credential was rejected.
    #[error("Credential expired or not yet valid: {credential_type} on DID {did}")]
    CredentialExpired {
        /// Human-readable credential type label
        credential_type: String,
        /// DID that owns the offending credential
        did: String,
    },

    /// Rate limit exceeded (HIGH #107)
    ///
    /// Returned when an agent message is rejected because the sender, the
    /// recipient, or the global router has exhausted its rate-limit token
    /// bucket. The error carries the scope (sender/recipient/global), the
    /// offending agent id (empty for global), and the number of seconds the
    /// caller must wait before retrying so the caller can surface a
    /// backoff hint to the user or schedule a retry.
    #[error("Rate limit exceeded for {scope} {agent_id}: retry after {retry_after_secs}s")]
    RateLimitExceeded {
        /// Rate-limit scope: "sender", "recipient", or "global"
        scope: String,
        /// Agent id that triggered the limit (empty for "global")
        agent_id: String,
        /// Seconds the caller should wait before retrying
        retry_after_secs: u64,
    },

    /// Agent message signature verification failed (CRITICAL #54)
    ///
    /// Returned by the message router when an inbound `AgentMessage` either
    /// (a) carries no signature in a config that requires signing,
    /// (b) carries a signature that does not verify against the sender's
    ///     public key, or
    /// (c) is sent by an agent whose public key cannot be resolved.
    ///
    /// The error carries the offending sender's `agent_id` and a
    /// human-readable reason so callers can log/audit the rejection.
    #[error("Invalid message signature from agent {agent_id}: {reason}")]
    InvalidMessageSignature {
        /// Sender agent_id whose signature failed verification
        agent_id: String,
        /// Human-readable reason for rejection
        reason: String,
    },

    /// Capability attestation signature verification failed (CRITICAL #52)
    ///
    /// Returned by the `CapabilityRegistry` when an inbound attestation
    /// either (a) carries no signature in a config that requires signing,
    /// (b) carries a signature that does not verify against the attester's
    /// public key, (c) is self-attested when self-attestation is disabled,
    /// or (d) was issued by an attester whose address is not in the trusted
    /// attester whitelist.
    ///
    /// The error carries the attested-for agent_id and a human-readable
    /// reason so callers can log/audit the rejection. Unlike
    /// `AttestationFailed` (a generic catch-all string), this variant is
    /// strongly typed so callers can react programmatically — e.g. to
    /// surface "self-attestation rejected" to the user differently from
    /// "signature failed verification".
    #[error("Invalid attestation signature for agent {agent_id}: {reason}")]
    InvalidAttestationSignature {
        /// Agent id whose attestation was rejected
        agent_id: String,
        /// Human-readable reason for rejection
        reason: String,
    },
}

impl From<tenzro_wallet::WalletError> for AgentError {
    fn from(err: tenzro_wallet::WalletError) -> Self {
        AgentError::WalletError(err.to_string())
    }
}

impl From<tenzro_crypto::CryptoError> for AgentError {
    fn from(err: tenzro_crypto::CryptoError) -> Self {
        AgentError::CryptoError(err.to_string())
    }
}

impl From<serde_json::Error> for AgentError {
    fn from(err: serde_json::Error) -> Self {
        AgentError::SerializationError(err.to_string())
    }
}
