//! TNZO token, treasury management, staking, and governance for Tenzro Network
//!
//! This crate provides the core token economics functionality for Tenzro Network:
//!
//! - **TNZO Token**: Governance/utility token management with 18-decimal precision
//! - **Treasury**: Multi-asset treasury accumulating network fees
//! - **Staking**: Staking system for validators and service providers
//! - **Governance**: On-chain governance with proposals and voting
//! - **Rewards**: Reward distribution engine for stakers
//! - **Fee Distribution**: Network fee processing and distribution
//!
//! # Architecture
//!
//! The token economics system uses `u128` for all token amounts to handle 18-decimal
//! precision properly, and leverages `DashMap` for concurrent access patterns.
//!
//! # Example
//!
//! ```rust,no_run
//! use tenzro_token::{
//!     tnzo::TnzoToken,
//!     staking::StakingManager,
//!     governance::GovernanceEngine,
//! };
//! use tenzro_types::primitives::Address;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a TNZO token instance
//! let token = TnzoToken::new();
//!
//! // Create staking and governance managers
//! let staking = StakingManager::new();
//! let governance = GovernanceEngine::new();
//!
//! // Use the token economics system...
//! # Ok(())
//! # }
//! ```

pub mod error;
pub mod tnzo;
pub mod treasury;
pub mod staking;
pub mod governance;
pub mod rewards;
pub mod fee_distribution;
pub mod liquid_staking;
pub mod cross_vm;
pub mod registry;
pub mod erc7802;
pub mod erc3643;

// Re-export commonly used types
pub use error::{TokenError, Result};
pub use tnzo::{TnzoToken, TokenStats, CircuitBreaker};
pub use treasury::{NetworkTreasury, FeeDistributionConfig, TreasuryStats, TreasuryStorageBackend};
pub use staking::{
    StakingManager, StakeInfo, SlashEvent, RestoreEvent, StakeStatus,
    DEFAULT_MIN_STAKE, DEFAULT_UNBONDING_PERIOD_MS
};
pub use governance::{GovernanceEngine, VotingRecord};
pub use rewards::{RewardDistributor, EpochRewards, RewardClaim};
pub use fee_distribution::{FeeProcessor, FeeStats, DistributionHistory};
pub use liquid_staking::{LiquidStakingPool, LiquidStakingConfig, LiquidStakingStats};
pub use cross_vm::{
    TokenVmType, VmAddresses, TokenPermissions, TokenMetadata, TokenId,
    TokenType, TokenDefinition, CrossVmTransfer,
    NATIVE_DECIMALS, SPL_DECIMALS, NATIVE_UNIT, SPL_UNIT, DECIMAL_SHIFT,
    native_to_spl, spl_to_native, truncation_dust,
};
pub use registry::TokenRegistry;
pub use erc7802::{CrosschainTokenManager, CrosschainMintEvent, CrosschainBurnEvent, BridgeAuthorization, BridgeInfo};
pub use erc3643::{
    ComplianceRegistry, ComplianceRules, ComplianceCheckResult, ComplianceViolation,
    IdentityClaim, TrustedIssuer, FreezeInfo, RecoveryEvent, TransferRestrictions, SupplyLimits,
    CLAIM_TOPIC_KYC, CLAIM_TOPIC_ACCREDITED_INVESTOR, CLAIM_TOPIC_COUNTRY, CLAIM_TOPIC_QUALIFIED_PURCHASER,
};
