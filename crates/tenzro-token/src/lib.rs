//! TNZO token and treasury management for Tenzro Network
//!
//! This crate provides the core token economics functionality for Tenzro Network:
//!
//! - **TNZO Token**: Governance/utility token management with 18-decimal precision
//! - **Treasury**: Multi-asset treasury accumulating network fees
//! - **Bonds**: read models of the agent and compute bonds held in consensus
//! - Network policy changes (economic policy, burn dial) are decided by
//!   on-chain governance in tenzro-vm and applied here by the node
//! - **Rewards**: Work-gated reward coupons minted against verified work
//! - **Vesting**: Reward, grant, and contributor vesting schedules
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
//! use std::sync::Arc;
//! use tenzro_token::tnzo::{RocksDbBackend, TnzoToken};
//!
//! # fn example(store: Arc<dyn tenzro_storage::KvStore>) {
//! // The native balances as block execution left them.
//! let token = TnzoToken::new(Arc::new(RocksDbBackend::new(store)));
//! let _supply = token.total_supply();
//! # }
//! ```

pub mod adaptive_burn;
pub mod bond;
pub mod cross_vm;
pub mod economic_policy;
pub mod error;
pub mod fee_distribution;
pub mod registry;
pub mod rewards;
pub mod tnzo;
pub mod treasury;
pub mod validator_registry;
pub mod vesting;

// Re-export commonly used types
pub use adaptive_burn::{
    AutoProposalGenerator, AutoProposalGeneratorConfig, BURN_RATE_CONFIG_KEY, BurnBreakdown,
    BurnRateConfig, BurnRateConfigManager, BurnRateRecommendation,
    DEFAULT_ALARM_FAST_TRACK_ENABLED, DEFAULT_AUTO_PROPOSAL_DEBOUNCE_SECS,
    DEFAULT_AUTO_PROPOSAL_MIN_MAGNITUDE_BPS, DEFAULT_AUTO_PROPOSAL_POLL_INTERVAL_SECS,
    DEFAULT_BASE_FEE_BURN_BPS, DEFAULT_DEFLATION_ALARM_BPS, DEFAULT_GAIN_BPS_PER_PCT,
    DEFAULT_INFLATION_ALARM_BPS, DEFAULT_LOCAL_FEE_BURN_BPS, DEFAULT_MAGNITUDE_CAP_ALARM_BPS,
    DEFAULT_MAGNITUDE_CAP_NORMAL_BPS, DEFAULT_NEUTRAL_BAND_BPS, DEFAULT_ROLLING_WINDOW_EPOCHS,
    DEFAULT_TARGET_ANNUAL_SUPPLY_BPS, EmissionBreakdown, RecommendationAction, SUPPLY_METRICS_KEY,
    SUPPLY_TARGETS_KEY, SupplyMetricsSnapshot, SupplyTargets, compute_recommendation,
};
pub use bond::{derive_bond_vault_address, derive_insurance_pool_address};
pub use cross_vm::{
    DECIMAL_SHIFT, NATIVE_DECIMALS, NATIVE_UNIT, SPL_DECIMALS, SPL_UNIT, TokenDefinition, TokenId,
    TokenMetadata, TokenPermissions, TokenType, TokenVmType, VmAddresses, native_to_spl,
    spl_to_native,
};
pub use economic_policy::{ECONOMIC_POLICY_KEY, EconomicPolicyManager};
pub use error::{Result, TokenError};
pub use fee_distribution::{DistributionHistory, FeeProcessor, FeeRecord, FeeSource, FeeStats};
pub use registry::TokenRegistry;
pub use rewards::{
    ClaimOutcome, CouponStatus, DEFAULT_CLAIM_WINDOW_EPOCHS, DEFAULT_LIQUID_BPS,
    DEFAULT_REVENUE_PEG_BPS, EpochRewardSummary, MINT_MULT_ONE_PPM, MintPolicy, MintingSchedule,
    NETWORK_REWARDS_POOL, ONE_TNZO, RewardCoupon, RewardEngineState, RoleBucket, SCHEDULE_YEAR_MS,
    WorkClass, WorkRecord, add_work, coupon_expired, next_mint_mult, rewards_pool_address,
    settle_epoch, split_claim,
};
pub use tnzo::{TnzoToken, TokenStats};
pub use treasury::{FeeDistributionConfig, NetworkTreasury, TreasuryStats, TreasuryStorageBackend};
pub use validator_registry::{
    ACTIVATION_EFFECTIVE_DELAY_BLOCKS, DEFAULT_ACTIVATION_CHURN_BPS, DEFAULT_EXIT_CHURN_BPS,
    DEFAULT_MIN_VALIDATOR_SELF_STAKE, DEFAULT_REENTRY_COOLDOWN_EPOCHS, EpochTransitionPlan,
    InactivityPolicy, MIN_CHURN_PER_EPOCH, RecoveryMember, VALIDATOR_CONFIG_KEY,
    VALIDATOR_INDEX_KEY, VALIDATOR_PREFIX, ValidatorRegistry, ValidatorRegistryConfig,
    ValidatorRegistryEntry, ValidatorRegistryStatus,
};
pub use vesting::{
    CONTRIBUTOR_CLIFF_MS, CONTRIBUTOR_VESTING_MS, DAY_MILLIS, GRANT_VESTING_MS, REWARD_VESTING_MS,
    VESTING_PREFIX, VestingKind, VestingSchedule, vesting_escrow_address, vesting_key,
};
