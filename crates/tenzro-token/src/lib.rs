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
pub mod bond;
pub mod burn_quota;
pub mod adaptive_burn;
pub mod seed_agent;

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
pub use bond::{
    BondManager, AgentBondState, BondLifecycle, BondEvent,
    ClaimRecord, ClaimStatus, InsurancePoolState,
    derive_bond_vault_address, derive_insurance_pool_address, derive_claim_id,
    DEFAULT_COOLDOWN_MS, DEFAULT_MIN_RESIDUAL, DEFAULT_MAX_SINGLE_SLASH_BPS,
};
pub use burn_quota::{
    BurnQuota, BurnQuotaManager, RefillReceipt,
    BURN_QUOTA_KEY, DEFAULT_DAILY_REFILL_TARGET, DEFAULT_CAP, DEFAULT_MIN_RESERVE_BPS,
};
pub use adaptive_burn::{
    compute_recommendation, BurnBreakdown, BurnRateConfig, BurnRateConfigManager,
    BurnRateRecommendation, EmissionBreakdown, RecommendationAction, SupplyMetricsSnapshot,
    SupplyTargets, BURN_RATE_CONFIG_KEY, DEFAULT_ALARM_FAST_TRACK_ENABLED,
    DEFAULT_ALARM_TIMELOCK_HOURS, DEFAULT_AUTO_PROPOSAL_MIN_MAGNITUDE_BPS,
    DEFAULT_BASE_FEE_BURN_BPS, DEFAULT_DEFLATION_ALARM_BPS, DEFAULT_GAIN_BPS_PER_PCT,
    DEFAULT_INFLATION_ALARM_BPS, DEFAULT_LOCAL_FEE_BURN_BPS,
    DEFAULT_MAGNITUDE_CAP_ALARM_BPS, DEFAULT_MAGNITUDE_CAP_NORMAL_BPS,
    DEFAULT_NEUTRAL_BAND_BPS, DEFAULT_PAYMASTER_BURN_BPS, DEFAULT_ROLLING_WINDOW_EPOCHS,
    DEFAULT_TARGET_ANNUAL_SUPPLY_BPS, SUPPLY_METRICS_KEY, SUPPLY_TARGETS_KEY,
};
pub use seed_agent::{
    Charter, CounterpartyFilter, DecayPoint, DecaySchedule, OperationKind,
    SeedAgentEarmarkManager, SeedAgentRecord, SeedAgentStatus, SpendCaps,
    TargetThroughput, TreasuryEarmark, DEFAULT_BOOTSTRAP_MONTHS,
    DEFAULT_SURPLUS_BURN_BPS, SEED_AGENT_PREFIX, SEED_CHARTER_PREFIX,
    SEED_EARMARK_KEY,
};
