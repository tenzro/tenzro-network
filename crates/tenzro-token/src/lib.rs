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
pub mod compute_bond;
pub mod burn_quota;
pub mod adaptive_burn;
pub mod seed_agent;
pub mod seed_agent_daemon;
pub mod seed_agent_gossip;
pub mod validator_registry;

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
pub use compute_bond::{
    ComputeBondManager, ComputeBondState, ComputeBondStatus, ComputeBondEvent,
    derive_compute_bond_vault_address,
    DEFAULT_COMPUTE_BOND_COOLDOWN_MS, DEFAULT_COMPUTE_BOND_MIN,
};
pub use burn_quota::{
    BurnQuota, BurnQuotaManager, RefillReceipt,
    BURN_QUOTA_KEY, DEFAULT_DAILY_REFILL_TARGET, DEFAULT_CAP, DEFAULT_MIN_RESERVE_BPS,
};
pub use adaptive_burn::{
    compute_recommendation, AutoProposalGenerator, AutoProposalGeneratorConfig, BurnBreakdown,
    BurnRateConfig, BurnRateConfigManager, BurnRateRecommendation, EmissionBreakdown,
    RecommendationAction, SupplyMetricsSnapshot, SupplyTargets, BURN_RATE_CONFIG_KEY,
    DEFAULT_ALARM_FAST_TRACK_ENABLED, DEFAULT_ALARM_TIMELOCK_HOURS,
    DEFAULT_AUTO_PROPOSAL_DEBOUNCE_SECS, DEFAULT_AUTO_PROPOSAL_MIN_MAGNITUDE_BPS,
    DEFAULT_AUTO_PROPOSAL_NORMAL_VOTING_HOURS, DEFAULT_AUTO_PROPOSAL_POLL_INTERVAL_SECS,
    DEFAULT_BASE_FEE_BURN_BPS, DEFAULT_DEFLATION_ALARM_BPS, DEFAULT_GAIN_BPS_PER_PCT,
    DEFAULT_INFLATION_ALARM_BPS, DEFAULT_LOCAL_FEE_BURN_BPS,
    DEFAULT_MAGNITUDE_CAP_ALARM_BPS, DEFAULT_MAGNITUDE_CAP_NORMAL_BPS,
    DEFAULT_NEUTRAL_BAND_BPS, DEFAULT_PAYMASTER_BURN_BPS, DEFAULT_ROLLING_WINDOW_EPOCHS,
    DEFAULT_TARGET_ANNUAL_SUPPLY_BPS, SUPPLY_METRICS_KEY, SUPPLY_TARGETS_KEY,
};
pub use seed_agent::{
    Charter, CounterpartyFilter, DecayPoint, DecaySchedule, OperationKind,
    RefillResult, SeedAgentEarmarkManager, SeedAgentRecord, SeedAgentStatus,
    SpendCaps, SurplusDisposition, TargetThroughput, TreasuryEarmark,
    WindDownReport, DEFAULT_BOOTSTRAP_MONTHS, DEFAULT_QUARANTINE_GRACE_MS,
    DEFAULT_SURPLUS_BURN_BPS, MONTH_MILLIS, SEED_AGENT_PREFIX,
    SEED_CHARTER_PREFIX, SEED_EARMARK_KEY,
};
pub use seed_agent_daemon::{
    SeedAgentDaemon, SeedAgentDaemonConfig, SurplusDispositionFn,
    TickAuthorityFn, TickOutcome, DEFAULT_DAEMON_POLL_INTERVAL_SECS,
    DEFAULT_DAEMON_QUARANTINE_GRACE_MS, DEFAULT_MIN_REFILL_INTERVAL_MS,
};
pub use seed_agent_gossip::{
    decode_for_topic as decode_seed_agent_for_topic, encode_agent_registered,
    encode_agent_status_changed, encode_charter_upserted, encode_earmark_updated,
    encode_monthly_refill_completed, SeedAgentGossipMessage, SEED_AGENTS_TOPIC,
};
pub use validator_registry::{
    EpochTransitionPlan, ValidatorRegistry, ValidatorRegistryConfig, ValidatorRegistryEntry,
    ValidatorRegistryStatus, ACTIVATION_EFFECTIVE_DELAY_BLOCKS, DEFAULT_ACTIVATION_CHURN_BPS,
    DEFAULT_EXIT_CHURN_BPS, DEFAULT_MIN_VALIDATOR_SELF_STAKE, DEFAULT_REENTRY_COOLDOWN_EPOCHS,
    MIN_CHURN_PER_EPOCH, VALIDATOR_CONFIG_KEY, VALIDATOR_INDEX_KEY, VALIDATOR_PREFIX,
};
