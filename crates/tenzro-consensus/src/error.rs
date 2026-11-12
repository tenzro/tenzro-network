//! Error types for the consensus module

use thiserror::Error;

/// Result type for consensus operations
pub type Result<T> = std::result::Result<T, ConsensusError>;

/// Errors that can occur during consensus operations
#[derive(Debug, Error)]
pub enum ConsensusError {
    /// A validator set or committee that cannot run consensus.
    #[error("Invalid validator set: {0}")]
    InvalidValidatorSet(String),

    /// A malformed validator key.
    #[error("Invalid validator key: {0}")]
    InvalidValidatorKey(String),

    /// This machine cannot hold a validator key.
    #[error("Validator key unavailable: {0}")]
    HardwareKeyUnavailable(String),

    /// A vertex that breaks a structural rule.
    #[error("Invalid vertex: {0}")]
    InvalidVertex(String),

    /// A checkpoint certificate that does not verify.
    #[error("Invalid certificate: {0}")]
    InvalidCertificate(String),

    /// A checkpoint vote this validator must not sign.
    #[error("Checkpoint vote refused: {0}")]
    VoteRefused(String),

    /// A consensus channel handshake or frame that fails authentication.
    #[error("Channel error: {0}")]
    Channel(String),

    /// A consensus message that does not decode.
    #[error("Malformed consensus message: {0}")]
    Malformed(String),

    /// Epoch transition failure.
    #[error("Epoch transition error: {0}")]
    EpochTransition(String),

    /// Persistent storage failure.
    #[error("Storage error: {0}")]
    Storage(String),

    /// Mempool error.
    #[error("Mempool error: {0}")]
    Mempool(String),

    /// Cryptographic error.
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Internal error.
    #[error("Internal error: {0}")]
    Internal(String),

    /// Already started.
    #[error("Consensus engine already started")]
    AlreadyStarted,

    /// Per-DID admission lane bucket exhausted.
    ///
    /// `lane` carries the lane the controller was assigned to; `retry_after_ms`
    /// is the controller's best-effort hint for when one bucket token will be
    /// available; `current_rate` is the lane's per-second refill in tokens/sec.
    #[error(
        "Rate limit exceeded for lane {lane}: retry after {retry_after_ms}ms (rate {current_rate}/s)"
    )]
    RateLimited {
        lane: &'static str,
        retry_after_ms: u64,
        burst_remaining: u32,
        current_rate: f64,
    },

    /// Per-DID admission lane fee-floor not met.
    ///
    /// Each lane's governed fee multiple (`admission.<lane>_fee_mult_bps`)
    /// applies to the base fee the next block charges, so a sender outside
    /// the verified and delegated lanes pays more per transaction and a
    /// flood of funded keys costs its owner in proportion.
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

    /// The sender has no registered identity (or its identity was revoked),
    /// so its transaction is not admitted. Node-local admission policy: the
    /// transaction is not invalid, this node will not pool it.
    #[error("Sender {sender} is not admitted: {reason}")]
    SenderNotRegistered {
        sender: String,
        reason: &'static str,
    },
}

impl From<tenzro_crypto::CryptoError> for ConsensusError {
    fn from(err: tenzro_crypto::CryptoError) -> Self {
        ConsensusError::Crypto(err.to_string())
    }
}

impl From<tenzro_finality::FinalityError> for ConsensusError {
    fn from(err: tenzro_finality::FinalityError) -> Self {
        use tenzro_finality::FinalityError as F;
        match err {
            F::InvalidValidatorKey(m) => ConsensusError::InvalidValidatorKey(m),
            F::InvalidValidatorSet(m) => ConsensusError::InvalidValidatorSet(m),
            F::InvalidCertificate(m) => ConsensusError::InvalidCertificate(m),
        }
    }
}
