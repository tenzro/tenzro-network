//! TNZO token, treasury management, staking, and governance for Tenzro Network
//!
//! This crate provides the core token economics functionality for Tenzro Network:
//!
//! - **TNZO Token**: Governance/utility token management with 18-decimal precision
//! - **Treasury**: Multi-asset treasury accumulating network fees
//! - **Staking**: Staking system for validators and service providers
//! - **Governance**: On-chain governance with proposals and voting
//! - **Rewards**: Work-gated reward coupons minted against verified work
//! - **Vesting**: Reward, grant, and contributor vesting schedules
//! - **Sponsorship**: Foundation-delegated stake for qualifying operators
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

pub mod adaptive_burn;
pub mod bond;
pub mod burn_quota;
pub mod compute_bond;
pub mod cross_vm;
pub mod economic_policy;
pub mod erc3643;
pub mod erc7802;
pub mod error;
pub mod fee_distribution;
pub mod governance;
pub mod liquid_staking;
pub mod registry;
pub mod rewards;
pub mod seed_agent;
pub mod seed_agent_daemon;
pub mod seed_agent_gossip;
pub mod sponsorship;
pub mod staking;
pub mod tnzo;
pub mod treasury;
pub mod validator_registry;
pub mod vesting;

// Re-export commonly used types
pub use adaptive_burn::{
    AutoProposalGenerator, AutoProposalGeneratorConfig, BURN_RATE_CONFIG_KEY, BurnBreakdown,
    BurnRateConfig, BurnRateConfigManager, BurnRateRecommendation,
    DEFAULT_ALARM_FAST_TRACK_ENABLED, DEFAULT_ALARM_TIMELOCK_HOURS,
    DEFAULT_AUTO_PROPOSAL_DEBOUNCE_SECS, DEFAULT_AUTO_PROPOSAL_MIN_MAGNITUDE_BPS,
    DEFAULT_AUTO_PROPOSAL_NORMAL_VOTING_HOURS, DEFAULT_AUTO_PROPOSAL_POLL_INTERVAL_SECS,
    DEFAULT_BASE_FEE_BURN_BPS, DEFAULT_DEFLATION_ALARM_BPS, DEFAULT_GAIN_BPS_PER_PCT,
    DEFAULT_INFLATION_ALARM_BPS, DEFAULT_LOCAL_FEE_BURN_BPS, DEFAULT_MAGNITUDE_CAP_ALARM_BPS,
    DEFAULT_MAGNITUDE_CAP_NORMAL_BPS, DEFAULT_NEUTRAL_BAND_BPS, DEFAULT_PAYMASTER_BURN_BPS,
    DEFAULT_ROLLING_WINDOW_EPOCHS, DEFAULT_TARGET_ANNUAL_SUPPLY_BPS, EmissionBreakdown,
    RecommendationAction, SUPPLY_METRICS_KEY, SUPPLY_TARGETS_KEY, SupplyMetricsSnapshot,
    SupplyTargets, compute_recommendation,
};
pub use bond::{
    AgentBondState, BondEvent, BondLifecycle, BondManager, ClaimRecord, ClaimStatus,
    DEFAULT_COOLDOWN_MS, DEFAULT_MAX_SINGLE_SLASH_BPS, DEFAULT_MIN_RESIDUAL, InsurancePoolState,
    derive_bond_vault_address, derive_claim_id, derive_insurance_pool_address,
};
pub use burn_quota::{
    BURN_QUOTA_KEY, BurnQuota, BurnQuotaManager, DEFAULT_CAP, DEFAULT_DAILY_REFILL_TARGET,
    DEFAULT_MIN_RESERVE_BPS, RefillReceipt,
};
pub use compute_bond::{
    ComputeBondEvent, ComputeBondManager, ComputeBondState, ComputeBondStatus,
    DEFAULT_COMPUTE_BOND_COOLDOWN_MS, DEFAULT_COMPUTE_BOND_MIN, derive_compute_bond_vault_address,
};
pub use cross_vm::{
    CrossVmTransfer, DECIMAL_SHIFT, NATIVE_DECIMALS, NATIVE_UNIT, SPL_DECIMALS, SPL_UNIT,
    TokenDefinition, TokenId, TokenMetadata, TokenPermissions, TokenType, TokenVmType, VmAddresses,
    native_to_spl, spl_to_native, truncation_dust,
};
pub use economic_policy::{ECONOMIC_POLICY_KEY, EconomicPolicyManager};
pub use erc3643::{
    CLAIM_TOPIC_ACCREDITED_INVESTOR, CLAIM_TOPIC_COUNTRY, CLAIM_TOPIC_KYC,
    CLAIM_TOPIC_QUALIFIED_PURCHASER, ComplianceCheckResult, ComplianceRegistry, ComplianceRules,
    ComplianceViolation, FreezeInfo, IdentityClaim, RecoveryEvent, SupplyLimits,
    TransferRestrictions, TrustedIssuer,
};
pub use erc7802::{
    BridgeAuthorization, BridgeInfo, CrosschainBurnEvent, CrosschainMintEvent,
    CrosschainTokenManager,
};
pub use error::{Result, TokenError};
pub use fee_distribution::{DistributionHistory, FeeProcessor, FeeRecord, FeeSource, FeeStats};
pub use governance::{GovernanceEngine, VotingRecord};
pub use liquid_staking::{LiquidStakingConfig, LiquidStakingPool, LiquidStakingStats};
pub use registry::TokenRegistry;
pub use rewards::{
    CLAIM_WINDOW_EPOCHS, ClaimOutcome, CouponStatus, DEFAULT_EPOCHS_PER_YEAR, DEFAULT_LIQUID_BPS,
    EpochRewardSummary, MintingSchedule, NETWORK_REWARDS_POOL, ONE_TNZO, REWARD_COUPON_PREFIX,
    REWARD_EPOCH_PREFIX, REWARD_METER_PREFIX, REWARD_PENDING_PREFIX, REWARD_STATE_KEY,
    RewardCoupon, RewardEngine, RewardEngineState, RoleBucket, WorkClass,
};
pub use seed_agent::{
    Charter, CounterpartyFilter, DEFAULT_BOOTSTRAP_MONTHS, DEFAULT_QUARANTINE_GRACE_MS,
    DEFAULT_SURPLUS_BURN_BPS, DecayPoint, DecaySchedule, MONTH_MILLIS, OperationKind, RefillResult,
    SEED_AGENT_PREFIX, SEED_CHARTER_PREFIX, SEED_EARMARK_KEY, SeedAgentEarmarkManager,
    SeedAgentRecord, SeedAgentStatus, SpendCaps, SurplusDisposition, TargetThroughput,
    TreasuryEarmark, WindDownReport,
};
pub use seed_agent_daemon::{
    DEFAULT_DAEMON_POLL_INTERVAL_SECS, DEFAULT_DAEMON_QUARANTINE_GRACE_MS,
    DEFAULT_MIN_REFILL_INTERVAL_MS, SeedAgentDaemon, SeedAgentDaemonConfig, SurplusDispositionFn,
    TickAuthorityFn, TickOutcome,
};
pub use seed_agent_gossip::{
    SEED_AGENTS_TOPIC, SeedAgentGossipMessage, decode_for_topic as decode_seed_agent_for_topic,
    encode_agent_registered, encode_agent_status_changed, encode_charter_upserted,
    encode_earmark_updated, encode_monthly_refill_completed,
};
pub use sponsorship::{
    ConversionOutcome, MAX_ASN_SLOT_BPS, MAX_CONTROLLER_SLOT_BPS, MAX_SPONSORED_STAKE_BPS,
    REAPPLICATION_BAR_MS, RevocationReason, SLOT_EXPIRY_MS, SPONSOR_POOL_KEY, SPONSOR_SLOT_PREFIX,
    SPONSORSHIP_POOL, SponsorshipManager, SponsorshipPool, SponsorshipSlot, SponsorshipStatus,
    SponsorshipTrack, T2_DELEGATION, T2_JUNIOR_BOND, T3_DELEGATION, T3_JUNIOR_BOND,
};
pub use staking::{
    DEFAULT_MIN_STAKE, DEFAULT_UNBONDING_PERIOD_MS, RestoreEvent, SlashEvent, StakeInfo,
    StakeStatus, StakingManager,
};
pub use tnzo::{CircuitBreaker, TnzoToken, TokenStats};
pub use treasury::{
    FeeDistributionConfig, NetworkTreasury, PendingWithdrawal, TreasuryStats,
    TreasuryStorageBackend, withdrawal_approval_preimage,
};
pub use validator_registry::{
    ACTIVATION_EFFECTIVE_DELAY_BLOCKS, DEFAULT_ACTIVATION_CHURN_BPS, DEFAULT_EXIT_CHURN_BPS,
    DEFAULT_MIN_VALIDATOR_SELF_STAKE, DEFAULT_REENTRY_COOLDOWN_EPOCHS, EpochTransitionPlan,
    MIN_CHURN_PER_EPOCH, VALIDATOR_CONFIG_KEY, VALIDATOR_INDEX_KEY, VALIDATOR_PREFIX,
    ValidatorRegistry, ValidatorRegistryConfig, ValidatorRegistryEntry, ValidatorRegistryStatus,
};
pub use vesting::{
    CONTRIBUTOR_CLIFF_MS, CONTRIBUTOR_VESTING_MS, DAY_MILLIS, GRANT_VESTING_MS, REWARD_VESTING_MS,
    VESTING_PREFIX, VestingKind, VestingManager, VestingSchedule,
};
