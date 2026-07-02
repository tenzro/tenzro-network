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

    /// A conflicting proposal for this view was already recorded and
    /// convicted — the offence is final and must not re-fire slashing
    #[error("Proposal equivocation already recorded for view {0}")]
    DuplicateProposal(u64),

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

    /// Per-DID admission lane bucket exhausted (Spec 2).
    ///
    /// `lane` carries the lane the controller was assigned to; `retry_after_ms`
    /// is the controller's best-effort hint for when one bucket token will be
    /// available; `current_rate` is the lane's per-second refill in tokens/sec.
    #[error("Rate limit exceeded for lane {lane}: retry after {retry_after_ms}ms (rate {current_rate}/s)")]
    RateLimited {
        lane: &'static str,
        retry_after_ms: u64,
        burst_remaining: u32,
        current_rate: f64,
    },

    /// Per-DID admission lane fee-floor not met (Spec 2).
    ///
    /// The lane multiplier is applied to the mempool's static minimum gas
    /// price (`mempool_min_gas_price`) at admission time. Verified-lane
    /// controllers pay `1.0×`, Delegated `1.5×`, Open `4.0×`. This makes
    /// unverified controllers strictly more expensive per-tx so they can't
    /// trivially crowd out verified traffic during congestion.
    #[error(
        "Fee floor not met for {lane} lane: gas_price {gas_price} < required {required} \
         (base {base} × {multiplier:.2})"
    )]
    FeeFloorTooLow {
        lane: &'static str,
        gas_price: u64,
        required: u64,
        base: u64,
        multiplier: f64,
    },

    /// Transaction nonce is below the sender's current account nonce —
    /// it can never execute and would only occupy mempool space.
    #[error("Nonce too low for {sender}: tx nonce {tx_nonce} < account nonce {account_nonce}")]
    NonceTooLow {
        sender: String,
        tx_nonce: u64,
        account_nonce: u64,
    },

    /// Transaction nonce is too far ahead of the sender's current account
    /// nonce. A bounded gap keeps future-nonce spam from parking
    /// unexecutable transactions in the mempool indefinitely.
    #[error(
        "Nonce gap too large for {sender}: tx nonce {tx_nonce} > account nonce \
         {account_nonce} + max gap {max_gap}"
    )]
    NonceGapTooLarge {
        sender: String,
        tx_nonce: u64,
        account_nonce: u64,
        max_gap: u64,
    },

    /// Sender balance cannot cover the transaction's worst-case cost
    /// (`gas_limit × gas_price + transfer value`).
    #[error("Insufficient balance for {sender}: balance {balance} < required {required}")]
    InsufficientBalance {
        sender: String,
        balance: u128,
        required: u128,
    },

    /// Sender already has the maximum number of pending transactions in
    /// the mempool.
    #[error("Sender {sender} has {pending} pending transactions (cap {cap})")]
    SenderCapExceeded {
        sender: String,
        pending: usize,
        cap: usize,
    },
}

impl From<tenzro_crypto::CryptoError> for ConsensusError {
    fn from(err: tenzro_crypto::CryptoError) -> Self {
        ConsensusError::Crypto(err.to_string())
    }
}

impl From<tenzro_crypto::bls::BlsError> for ConsensusError {
    fn from(err: tenzro_crypto::bls::BlsError) -> Self {
        ConsensusError::Crypto(err.to_string())
    }
}
