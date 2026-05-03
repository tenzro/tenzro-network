//! Error types for the consensus module

use thiserror::Error;
use tenzro_types::primitives::BlockHeight;

/// Result type for consensus operations
pub type Result<T> = std::result::Result<T, ConsensusError>;

/// Errors that can occur during consensus operations
#[derive(Debug, Error)]
pub enum ConsensusError {
    /// Invalid block proposal
    #[error("Invalid block proposal: {0}")]
    InvalidProposal(String),

    /// Invalid vote
    #[error("Invalid vote: {0}")]
    InvalidVote(String),

    /// Insufficient votes for quorum
    #[error("Insufficient votes for quorum: got {got}, need {need}")]
    InsufficientVotes { got: u64, need: u64 },

    /// Vote from non-validator
    #[error("Vote from non-validator: {0}")]
    NonValidator(String),

    /// Block already exists
    #[error("Block already exists at height {0}")]
    DuplicateBlock(BlockHeight),

    /// Block not found
    #[error("Block not found at height {0}")]
    BlockNotFound(BlockHeight),

    /// Invalid block height
    #[error("Invalid block height: expected {expected}, got {actual}")]
    InvalidHeight {
        expected: BlockHeight,
        actual: BlockHeight,
    },

    /// Invalid block hash
    #[error("Invalid block hash: expected {expected}, got {actual}")]
    InvalidHash { expected: String, actual: String },

    /// Invalid signature
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    /// View timeout
    #[error("View {0} timed out")]
    ViewTimeout(u64),

    /// Not the leader for current view
    #[error("Not the leader for view {0}")]
    NotLeader(u64),

    /// Already voted in this view
    #[error("Already voted in view {0}")]
    AlreadyVoted(u64),

    /// Invalid validator set
    #[error("Invalid validator set: {0}")]
    InvalidValidatorSet(String),

    /// Epoch transition error
    #[error("Epoch transition error: {0}")]
    EpochTransition(String),

    /// Mempool error
    #[error("Mempool error: {0}")]
    Mempool(String),

    /// Invalid TEE attestation
    #[error("Invalid TEE attestation: {0}")]
    InvalidAttestation(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),

    /// Cryptographic error
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),

    /// Not started
    #[error("Consensus engine not started")]
    NotStarted,

    /// Already started
    #[error("Consensus engine already started")]
    AlreadyStarted,

    /// Equivocation detected
    #[error("Equivocation detected: validator {validator} voted for multiple blocks in view {view}")]
    Equivocation { validator: String, view: u64 },
}

impl From<tenzro_crypto::CryptoError> for ConsensusError {
    fn from(err: tenzro_crypto::CryptoError) -> Self {
        ConsensusError::Crypto(err.to_string())
    }
}
