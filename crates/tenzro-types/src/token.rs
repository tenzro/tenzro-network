//! TNZO token economics and governance types
//!
//! This module defines types for the TNZO token, staking, treasury management,
//! and governance on Tenzro Network.

use crate::primitives::{Address, Timestamp};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// TNZO token configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenConfig {
    /// Token name
    pub name: String,
    /// Token symbol
    pub symbol: String,
    /// Number of decimals
    pub decimals: u8,
    /// Total supply (in smallest unit) - using u128 to prevent overflow
    pub total_supply: u128,
    /// Initial distribution
    pub initial_distribution: InitialDistribution,
    /// Token economics parameters
    pub economics: TokenEconomics,
}

impl Default for TokenConfig {
    fn default() -> Self {
        Self {
            name: "Tenzro Network Token".to_string(),
            symbol: "TNZO".to_string(),
            decimals: 18,
            total_supply: 1_000_000_000u128 * 10u128.pow(18), // 1 billion TNZO
            initial_distribution: InitialDistribution::default(),
            economics: TokenEconomics::default(),
        }
    }
}

/// Initial token distribution
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitialDistribution {
    /// Treasury allocation
    pub treasury: u128,
    /// Team allocation
    pub team: u128,
    /// Investors allocation
    pub investors: u128,
    /// Community allocation
    pub community: u128,
    /// Provider incentives
    pub provider_incentives: u128,
    /// Liquidity pool
    pub liquidity: u128,
}

impl Default for InitialDistribution {
    fn default() -> Self {
        let total = 1_000_000_000u128 * 10u128.pow(18); // 1 billion TNZO
        Self {
            treasury: (total * 25) / 100,          // 25% (network treasury & grants)
            team: (total * 10) / 100,              // 10% (4-year vest, 1-year cliff)
            investors: (total * 10) / 100,         // 10% (strategic rounds, vested)
            community: (total * 35) / 100,         // 35% (airdrops, incentives, ecosystem growth)
            provider_incentives: (total * 15) / 100, // 15% (TEE/compute/model providers)
            liquidity: (total * 5) / 100,          // 5% (DEX/CEX liquidity)
        }
    }
}

/// Token economics parameters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenEconomics {
    /// Inflation rate (basis points per year)
    pub inflation_rate: u32,
    /// Transaction fee percentage (basis points)
    pub transaction_fee_bps: u32,
    /// Staking reward rate (basis points per year)
    pub staking_reward_rate: u32,
    /// Burn rate for fees (basis points)
    pub burn_rate_bps: u32,
    /// Minimum stake amount (in smallest unit)
    pub min_stake: u128,
}

impl Default for TokenEconomics {
    fn default() -> Self {
        Self {
            inflation_rate: 200,         // 2% per year
            transaction_fee_bps: 10,     // 0.1%
            staking_reward_rate: 500,    // 5% per year
            burn_rate_bps: 5000,         // 50% of fees burned
            min_stake: 1000u128 * 10u128.pow(18), // 1000 TNZO minimum
        }
    }
}

/// Treasury management
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Treasury {
    /// Treasury address
    pub address: Address,
    /// Current balance (in smallest unit)
    pub balance: u128,
    /// Total allocated to grants
    pub allocated_grants: u128,
    /// Total spent on development
    pub spent_development: u128,
    /// Total spent on marketing
    pub spent_marketing: u128,
    /// Reserved for future use
    pub reserved: u128,
    /// Treasury parameters
    pub parameters: TreasuryParameters,
}

impl Treasury {
    /// Creates a new treasury
    pub fn new(address: Address, initial_balance: u128) -> Self {
        Self {
            address,
            balance: initial_balance,
            allocated_grants: 0,
            spent_development: 0,
            spent_marketing: 0,
            reserved: 0,
            parameters: TreasuryParameters::default(),
        }
    }

    /// Returns the available balance using checked arithmetic
    pub fn available_balance(&self) -> Option<u128> {
        self.balance
            .checked_sub(self.allocated_grants)?
            .checked_sub(self.reserved)
    }
}

/// Treasury parameters
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TreasuryParameters {
    /// Maximum grant amount per proposal
    pub max_grant_amount: u128,
    /// Minimum proposal threshold
    pub min_proposal_threshold: u128,
    /// Grant approval quorum (basis points)
    pub grant_approval_quorum: u32,
}

impl Default for TreasuryParameters {
    fn default() -> Self {
        Self {
            max_grant_amount: 1_000_000u128 * 10u128.pow(18), // 1M TNZO
            min_proposal_threshold: 10_000u128 * 10u128.pow(18), // 10K TNZO
            grant_approval_quorum: 5000,                  // 50%
        }
    }
}

/// Staking pool for validators and providers
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakingPool {
    /// Pool ID
    pub pool_id: String,
    /// Pool operator
    pub operator: Address,
    /// Pool type
    pub pool_type: PoolType,
    /// Total staked amount (in smallest unit)
    pub total_staked: u128,
    /// Number of stakers
    pub staker_count: u64,
    /// Pool commission rate (basis points)
    pub commission_rate: u32,
    /// Pool status
    pub status: PoolStatus,
    /// Pool metadata
    pub metadata: HashMap<String, String>,
}

impl StakingPool {
    /// Creates a new staking pool
    pub fn new(operator: Address, pool_type: PoolType) -> Self {
        Self {
            pool_id: uuid::Uuid::new_v4().to_string(),
            operator,
            pool_type,
            total_staked: 0,
            staker_count: 0,
            commission_rate: 1000, // 10%
            status: PoolStatus::Active,
            metadata: HashMap::new(),
        }
    }

    /// Adds stake to the pool using checked arithmetic
    pub fn add_stake(&mut self, amount: u128) -> Result<(), &'static str> {
        self.total_staked = self.total_staked
            .checked_add(amount)
            .ok_or("Stake addition would overflow")?;
        self.staker_count = self.staker_count
            .checked_add(1)
            .ok_or("Staker count would overflow")?;
        Ok(())
    }

    /// Removes stake from the pool using checked arithmetic
    pub fn remove_stake(&mut self, amount: u128) -> Result<(), &'static str> {
        self.total_staked = self.total_staked
            .checked_sub(amount)
            .ok_or("Insufficient stake to remove")?;
        self.staker_count = self.staker_count
            .checked_sub(1)
            .ok_or("Staker count underflow")?;
        Ok(())
    }
}

/// Type of staking pool
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PoolType {
    /// Validator staking pool
    Validator,
    /// TEE provider pool
    TeeProvider,
    /// Model provider pool
    ModelProvider,
    /// Storage provider pool
    StorageProvider,
    /// Tenzro Train: trainer (proposes outer gradients) bonding pool
    Trainer,
    /// Tenzro Train: syncer (aggregates outer gradients, publishes rounds) bonding pool
    Syncer,
}

/// Staking pool status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PoolStatus {
    /// Pool is active
    Active,
    /// Pool is full
    Full,
    /// Pool is paused
    Paused,
    /// Pool is closed
    Closed,
}

/// Provider stake information
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderStake {
    /// Provider address
    pub provider: Address,
    /// Provider type
    pub provider_type: ProviderType,
    /// Staked amount (in smallest unit)
    pub staked_amount: u128,
    /// Stake timestamp
    pub staked_at: Timestamp,
    /// Lock period end (if any)
    pub lock_until: Option<Timestamp>,
    /// Rewards earned (in smallest unit)
    pub rewards_earned: u128,
    /// Stake status
    pub status: StakeStatus,
}

impl ProviderStake {
    /// Creates a new provider stake
    pub fn new(provider: Address, provider_type: ProviderType, amount: u128) -> Self {
        Self {
            provider,
            provider_type,
            staked_amount: amount,
            staked_at: Timestamp::now(),
            lock_until: None,
            rewards_earned: 0,
            status: StakeStatus::Active,
        }
    }

    /// Sets a lock period
    pub fn with_lock_period(mut self, duration_ms: i64) -> Self {
        self.lock_until = Some(Timestamp::new(
            Timestamp::now().as_millis() + duration_ms,
        ));
        self
    }

    /// Checks if stake is locked
    pub fn is_locked(&self) -> bool {
        if let Some(lock_until) = self.lock_until {
            Timestamp::now() < lock_until
        } else {
            false
        }
    }

    /// Adds rewards using checked arithmetic
    pub fn add_rewards(&mut self, amount: u128) -> Result<(), &'static str> {
        self.rewards_earned = self.rewards_earned
            .checked_add(amount)
            .ok_or("Reward addition would overflow")?;
        Ok(())
    }
}

/// Type of provider
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProviderType {
    /// Validator
    Validator,
    /// TEE provider
    TeeProvider,
    /// Model provider
    ModelProvider,
    /// Storage provider
    StorageProvider,
    /// Tenzro Train trainer — proposes outer gradients for a fragment
    Trainer,
    /// Tenzro Train syncer — aggregates outer gradients and publishes rounds
    Syncer,
}

/// Stake status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StakeStatus {
    /// Stake is active
    Active,
    /// Stake is being unbonded
    Unbonding,
    /// Stake has been slashed
    Slashed,
    /// Stake has been withdrawn
    Withdrawn,
}

/// Governance proposal
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceProposal {
    /// Proposal ID
    pub proposal_id: String,
    /// Proposal title
    pub title: String,
    /// Proposal description
    pub description: String,
    /// Proposer address
    pub proposer: Address,
    /// Proposal type
    pub proposal_type: ProposalType,
    /// Voting start time
    pub voting_start: Timestamp,
    /// Voting end time
    pub voting_end: Timestamp,
    /// Current status
    pub status: ProposalStatus,
    /// Votes in favor
    pub votes_for: u128,
    /// Votes against
    pub votes_against: u128,
    /// Total voting power
    pub total_voting_power: u128,
    /// Execution data (if applicable)
    pub execution_data: Option<Vec<u8>>,
}

impl GovernanceProposal {
    /// Creates a new governance proposal
    pub fn new(
        title: String,
        description: String,
        proposer: Address,
        proposal_type: ProposalType,
        voting_duration_ms: i64,
    ) -> Self {
        let now = Timestamp::now();
        Self {
            proposal_id: uuid::Uuid::new_v4().to_string(),
            title,
            description,
            proposer,
            proposal_type,
            voting_start: now,
            voting_end: Timestamp::new(now.as_millis() + voting_duration_ms),
            status: ProposalStatus::Active,
            votes_for: 0,
            votes_against: 0,
            total_voting_power: 0,
            execution_data: None,
        }
    }

    /// Checks if voting is still open
    pub fn is_voting_open(&self) -> bool {
        let now = Timestamp::now();
        now >= self.voting_start && now < self.voting_end && self.status == ProposalStatus::Active
    }

    /// Returns the current approval percentage (basis points)
    pub fn approval_percentage(&self) -> u32 {
        if self.total_voting_power == 0 {
            0
        } else {
            ((self.votes_for as f64 / self.total_voting_power as f64) * 10000.0) as u32
        }
    }
}

/// Type of governance proposal
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalType {
    /// Parameter change proposal
    ParameterChange { parameter: String, new_value: String },
    /// Treasury grant proposal
    TreasuryGrant { recipient: Address, amount: u128 },
    /// Protocol upgrade proposal
    ProtocolUpgrade { version: String, code_hash: Vec<u8> },
    /// Adaptive-burn dial update (Spec 8). Sets the live `BurnRateConfig`
    /// applied by the EIP-1559 fee market and Spec 6 local-fee router.
    /// `paymaster_burn_bps` is invariant-locked to 10_000 (100%) — proposals
    /// that violate this are rejected at execution time.
    AdaptiveBurnConfigUpdate {
        base_fee_burn_bps: u16,
        local_fee_burn_bps: u16,
        paymaster_burn_bps: u16,
    },
    /// Adaptive-burn supply-targets update (Spec 8). Adjusts the rolling
    /// window, neutral band, alarm thresholds, gain, and magnitude caps
    /// the auto-proposal generator uses to draft `AdaptiveBurnConfigUpdate`
    /// proposals.
    SupplyTargetsUpdate {
        epoch_neutral_band_bps: u16,
        rolling_window_epochs: u32,
        inflation_alarm_bps: u16,
        deflation_alarm_bps: u16,
        target_annual_supply_bps: i32,
        gain_bps_per_pct: u16,
        magnitude_cap_normal_bps: u16,
        magnitude_cap_alarm_bps: u16,
        auto_proposal_min_magnitude_bps: u16,
        alarm_fast_track_enabled: bool,
        alarm_timelock_hours: u32,
    },
    /// Custom proposal
    Custom { proposal_data: Vec<u8> },
}

/// Status of a governance proposal
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalStatus {
    /// Proposal is active and accepting votes
    Active,
    /// Proposal passed
    Passed,
    /// Proposal failed
    Failed,
    /// Proposal was cancelled
    Cancelled,
    /// Proposal has been executed
    Executed,
}
