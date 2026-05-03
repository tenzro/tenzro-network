//! Error types for the token module

use thiserror::Error;

/// Result type for token operations
pub type Result<T> = std::result::Result<T, TokenError>;

/// Errors that can occur in token operations
#[derive(Debug, Error)]
pub enum TokenError {
    /// Insufficient balance for the operation
    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u128, available: u128 },

    /// Insufficient stake for the operation
    #[error("Insufficient stake: required {required}, available {available}")]
    InsufficientStake { required: u128, available: u128 },

    /// Stake is locked and cannot be withdrawn
    #[error("Stake is locked until {unlock_time}")]
    StakeLocked { unlock_time: i64 },

    /// Invalid amount (e.g., zero or negative)
    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    /// Proposal not found
    #[error("Proposal not found: {proposal_id}")]
    ProposalNotFound { proposal_id: String },

    /// Voting period has closed
    #[error("Voting has closed for proposal: {proposal_id}")]
    VotingClosed { proposal_id: String },

    /// User has already voted on this proposal
    #[error("Already voted on proposal: {proposal_id}")]
    AlreadyVoted { proposal_id: String },

    /// Quorum not met for proposal
    #[error("Quorum not met for proposal: {proposal_id}")]
    QuorumNotMet { proposal_id: String },

    /// Unauthorized operation
    #[error("Unauthorized: {reason}")]
    Unauthorized { reason: String },

    /// Treasury operation error
    #[error("Treasury error: {message}")]
    TreasuryError { message: String },

    /// Storage operation error
    #[error("Storage error: {0}")]
    StorageError(String),

    /// Invalid configuration
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Arithmetic overflow
    #[error("Arithmetic overflow in {operation}")]
    ArithmeticOverflow { operation: String },

    /// Invalid address
    #[error("Invalid address")]
    InvalidAddress,

    /// Asset not found
    #[error("Asset not found: {asset_id}")]
    AssetNotFound { asset_id: String },

    /// Stake not found
    #[error("Stake not found for address: {address}")]
    StakeNotFound { address: String },

    /// Minimum stake not met
    #[error("Minimum stake not met: required {required}, provided {provided}")]
    MinimumStakeNotMet { required: u128, provided: u128 },

    /// Invalid proposal type
    #[error("Invalid proposal type")]
    InvalidProposalType,

    /// Proposal already executed
    #[error("Proposal already executed: {proposal_id}")]
    ProposalAlreadyExecuted { proposal_id: String },

    /// Invalid voting power
    #[error("Invalid voting power: must have staked TNZO to vote")]
    InvalidVotingPower,
}

impl From<tenzro_storage::StorageError> for TokenError {
    fn from(err: tenzro_storage::StorageError) -> Self {
        TokenError::StorageError(err.to_string())
    }
}
