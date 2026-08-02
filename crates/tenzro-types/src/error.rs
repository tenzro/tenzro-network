//! Error types for Tenzro Network
//!
//! This module defines a comprehensive error type used throughout
//! the Tenzro Network ecosystem.

use thiserror::Error;

/// Comprehensive error type for Tenzro Network
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum TenzroError {
    // Primitive errors
    #[error("Invalid hash: {0}")]
    InvalidHash(String),

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    // Transaction errors
    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Transaction verification failed: {0}")]
    TransactionVerificationFailed(String),

    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u64, available: u64 },

    #[error("Invalid nonce: expected {expected}, got {actual}")]
    InvalidNonce { expected: u64, actual: u64 },

    #[error("Gas limit exceeded: limit {limit}, used {used}")]
    GasLimitExceeded { limit: u64, used: u64 },

    // Block errors
    #[error("Invalid block: {0}")]
    InvalidBlock(String),

    #[error("Block verification failed: {0}")]
    BlockVerificationFailed(String),

    #[error("Invalid block height: expected {expected}, got {actual}")]
    InvalidBlockHeight { expected: u64, actual: u64 },

    // Account errors
    #[error("Account not found: {0}")]
    AccountNotFound(String),

    #[error("Account already exists: {0}")]
    AccountAlreadyExists(String),

    #[error("Insufficient stake: required {required}, staked {staked}")]
    InsufficientStake { required: u128, staked: u128 },

    // Asset errors
    #[error("Asset not found: {0}")]
    AssetNotFound(String),

    #[error("Invalid asset: {0}")]
    InvalidAsset(String),

    #[error("Unsupported stablecoin: {0}")]
    UnsupportedStablecoin(String),

    // Network errors
    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Peer not found: {0}")]
    PeerNotFound(String),

    #[error("Connection failed: {0}")]
    ConnectionFailed(String),

    #[error("Protocol version mismatch: local {local}, remote {remote}")]
    ProtocolVersionMismatch { local: u32, remote: u32 },

    // TEE errors
    #[error("TEE attestation failed: {0}")]
    TeeAttestationFailed(String),

    #[error("Invalid attestation report: {0}")]
    InvalidAttestationReport(String),

    #[error("TEE provider not found: {0}")]
    TeeProviderNotFound(String),

    #[error("TEE capacity exceeded")]
    TeeCapacityExceeded,

    #[error("Unsupported TEE vendor: {0}")]
    UnsupportedTeeVendor(String),

    // Agent errors
    #[error("Agent not found: {0}")]
    AgentNotFound(String),

    #[error("Invalid agent configuration: {0}")]
    InvalidAgentConfig(String),

    #[error("Agent execution failed: {0}")]
    AgentExecutionFailed(String),

    #[error("Capability not supported: {0}")]
    CapabilityNotSupported(String),

    #[error("Agent resource limit exceeded: {0}")]
    AgentResourceLimitExceeded(String),

    // Model errors
    #[error("Model not found: {0}")]
    ModelNotFound(String),

    #[error("Invalid model: {0}")]
    InvalidModel(String),

    #[error("Model inference failed: {0}")]
    ModelInferenceFailed(String),

    #[error("Provider not found: {0}")]
    ProviderNotFound(String),

    #[error("Provider capacity exceeded")]
    ProviderCapacityExceeded,

    #[error("Invalid inference parameters: {0}")]
    InvalidInferenceParameters(String),

    // Settlement errors
    #[error("Settlement request not found: {0}")]
    SettlementRequestNotFound(String),

    #[error("Settlement failed: {0}")]
    SettlementFailed(String),

    #[error("Invalid service proof: {0}")]
    InvalidServiceProof(String),

    #[error("Settlement expired")]
    SettlementExpired,

    #[error("Payment failed: {0}")]
    PaymentFailed(String),

    // Token errors
    #[error("Invalid token configuration: {0}")]
    InvalidTokenConfig(String),

    #[error("Staking failed: {0}")]
    StakingFailed(String),

    #[error("Unstaking failed: {0}")]
    UnstakingFailed(String),

    #[error("Stake is locked until {0}")]
    StakeLocked(i64),

    #[error("Treasury operation failed: {0}")]
    TreasuryOperationFailed(String),

    // Governance errors
    #[error("Proposal not found: {0}")]
    ProposalNotFound(String),

    #[error("Invalid proposal: {0}")]
    InvalidProposal(String),

    #[error("Voting failed: {0}")]
    VotingFailed(String),

    #[error("Voting period ended")]
    VotingPeriodEnded,

    #[error("Voting period not started")]
    VotingPeriodNotStarted,

    #[error("Insufficient voting power: required {required}, available {available}")]
    InsufficientVotingPower { required: u64, available: u64 },

    #[error("Quorum not met")]
    QuorumNotMet,

    // Bridge errors
    #[error("Bridge message not found: {0}")]
    BridgeMessageNotFound(String),

    #[error("Bridge transfer failed: {0}")]
    BridgeTransferFailed(String),

    #[error("Invalid bridge proof: {0}")]
    InvalidBridgeProof(String),

    #[error("Unsupported chain: {0}")]
    UnsupportedChain(String),

    #[error("Bridge relayer not found: {0}")]
    BridgeRelayerNotFound(String),

    #[error("Route not supported: {source_chain} -> {destination}")]
    RouteNotSupported {
        source_chain: String,
        destination: String,
    },

    // Wallet errors
    #[error("Wallet not found: {0}")]
    WalletNotFound(String),

    #[error("Invalid wallet configuration: {0}")]
    InvalidWalletConfig(String),

    #[error("Multi-sig threshold not met: required {required}, got {actual}")]
    MultiSigThresholdNotMet { required: u32, actual: u32 },

    // Storage errors
    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Item not found in storage: {0}")]
    StorageItemNotFound(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    // Consensus errors
    #[error("Consensus error: {0}")]
    ConsensusError(String),

    #[error("Invalid consensus proof: {0}")]
    InvalidConsensusProof(String),

    #[error("Validator not found: {0}")]
    ValidatorNotFound(String),

    // VM errors
    #[error("VM execution failed: {0}")]
    VmExecutionFailed(String),

    #[error("Contract deployment failed: {0}")]
    ContractDeploymentFailed(String),

    #[error("Contract call failed: {0}")]
    ContractCallFailed(String),

    // Crypto errors
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    // Configuration errors
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("Configuration not found: {0}")]
    ConfigNotFound(String),

    // Generic errors
    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Not implemented: {0}")]
    NotImplemented(String),

    #[error("Operation not permitted: {0}")]
    OperationNotPermitted(String),

    #[error("Timeout: {0}")]
    Timeout(String),
}

impl TenzroError {
    /// Creates an internal error
    pub fn internal(msg: impl Into<String>) -> Self {
        Self::InternalError(msg.into())
    }

    /// Creates a not implemented error
    pub fn not_implemented(msg: impl Into<String>) -> Self {
        Self::NotImplemented(msg.into())
    }

    /// Creates an operation not permitted error
    pub fn not_permitted(msg: impl Into<String>) -> Self {
        Self::OperationNotPermitted(msg.into())
    }
}

// Implement From for common error types
impl From<serde_json::Error> for TenzroError {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError(err.to_string())
    }
}

impl From<std::io::Error> for TenzroError {
    fn from(err: std::io::Error) -> Self {
        Self::InternalError(err.to_string())
    }
}

impl From<hex::FromHexError> for TenzroError {
    fn from(err: hex::FromHexError) -> Self {
        Self::InvalidHash(err.to_string())
    }
}
