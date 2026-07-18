//! Error types for the VM layer

use thiserror::Error;

/// Result type alias for VM operations
pub type Result<T> = std::result::Result<T, VmError>;

/// Errors that can occur during VM execution
#[derive(Debug, Error)]
pub enum VmError {
    /// Execution reverted with reason
    #[error("Execution reverted: {0}")]
    ExecutionReverted(String),

    /// Execution failed
    #[error("Execution failed: {0}")]
    ExecutionFailed(String),

    /// Out of gas during execution
    #[error("Out of gas")]
    OutOfGas,

    /// Invalid opcode encountered
    #[error("Invalid opcode: {0:#x}")]
    InvalidOpcode(u8),

    /// Stack underflow
    #[error("Stack underflow")]
    StackUnderflow,

    /// Stack overflow
    #[error("Stack overflow")]
    StackOverflow,

    /// Invalid jump destination
    #[error("Invalid jump destination: {0}")]
    InvalidJump(usize),

    /// Contract not found
    #[error("Contract not found at address: {0}")]
    ContractNotFound(String),

    /// Invalid contract bytecode
    #[error("Invalid contract bytecode")]
    InvalidBytecode,

    /// Insufficient balance
    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u128, available: u128 },

    /// Invalid address format
    #[error("Invalid address format: {0}")]
    InvalidAddress(String),

    /// Invalid transaction
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    /// Invalid nonce
    #[error("Invalid nonce: expected {expected}, got {got}")]
    InvalidNonce { expected: u64, got: u64 },

    /// Missing signature
    #[error("Transaction signature is required but missing")]
    MissingSignature,

    /// Invalid signature
    #[error("Transaction signature verification failed")]
    InvalidSignature,

    /// Precompile execution failed
    #[error("Precompile execution failed: {0}")]
    PrecompileFailed(String),

    /// State access error
    #[error("State access error: {0}")]
    StateError(String),

    /// Gas estimation failed
    #[error("Gas estimation failed: {0}")]
    GasEstimationFailed(String),

    /// Unsupported VM type
    #[error("Unsupported VM type: {0}")]
    UnsupportedVmType(String),

    /// VM not enabled
    #[error("VM not enabled: {0:?}")]
    VmNotEnabled(crate::VmType),

    /// TEE attestation verification failed
    #[error("TEE attestation verification failed: {0}")]
    TeeVerificationFailed(String),

    /// ZK proof verification failed
    #[error("ZK proof verification failed: {0}")]
    ZkVerificationFailed(String),

    /// Model inference failed
    #[error("Model inference failed: {0}")]
    ModelInferenceFailed(String),

    /// Settlement failed
    #[error("Settlement failed: {0}")]
    SettlementFailed(String),

    /// Canton execution failed
    #[error("Canton error: {0}")]
    CantonError(String),

    /// SBF/BPF program execution attempted without the `svm-full` feature.
    ///
    /// The SPL Token adapter, the `tenzro_cross_vm` native program, and PDA
    /// derivation run regardless of build features. Executing a stored SBF ELF
    /// program requires the embedded Anza `solana-svm` processor, which is
    /// compiled in only under the `svm-full` cargo feature.
    #[error("SVM full execution requires the `svm-full` feature")]
    SvmFullFeatureRequired,

    /// Storage error
    #[error("Storage error: {0}")]
    Storage(#[from] tenzro_storage::StorageError),

    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Internal error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl VmError {
    /// Create a new execution reverted error
    pub fn reverted(reason: impl Into<String>) -> Self {
        Self::ExecutionReverted(reason.into())
    }

    /// Create a new state error
    pub fn state(reason: impl Into<String>) -> Self {
        Self::StateError(reason.into())
    }

    /// Create a new internal error
    pub fn internal(reason: impl Into<String>) -> Self {
        Self::Internal(reason.into())
    }
}
