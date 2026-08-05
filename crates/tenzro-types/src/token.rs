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
    #[serde(with = "crate::primitives::u128_serde")]
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
    #[serde(with = "crate::primitives::u128_serde")]
    pub treasury: u128,
    /// Team allocation
    #[serde(with = "crate::primitives::u128_serde")]
    pub team: u128,
    /// Investors allocation
    #[serde(with = "crate::primitives::u128_serde")]
    pub investors: u128,
    /// Community allocation
    #[serde(with = "crate::primitives::u128_serde")]
    pub community: u128,
    /// Provider incentives
    #[serde(with = "crate::primitives::u128_serde")]
    pub provider_incentives: u128,
    /// Liquidity pool
    #[serde(with = "crate::primitives::u128_serde")]
    pub liquidity: u128,
}

impl Default for InitialDistribution {
    fn default() -> Self {
        let total = 1_000_000_000u128 * 10u128.pow(18); // 1 billion TNZO
        Self {
            treasury: (total * 25) / 100,  // 25% (network treasury & grants)
            team: (total * 10) / 100,      // 10% (4-year vest, 1-year cliff)
            investors: (total * 10) / 100, // 10% (strategic rounds, vested)
            community: (total * 35) / 100, // 35% (airdrops, incentives, ecosystem growth)
            provider_incentives: (total * 15) / 100, // 15% (TEE/compute/model providers)
            liquidity: (total * 5) / 100,  // 5% (DEX/CEX liquidity)
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
    #[serde(with = "crate::primitives::u128_serde")]
    pub min_stake: u128,
}

impl Default for TokenEconomics {
    fn default() -> Self {
        Self {
            inflation_rate: 200,                  // 2% per year
            transaction_fee_bps: 10,              // 0.1%
            staking_reward_rate: 500,             // 5% per year
            burn_rate_bps: 5000,                  // 50% of fees burned
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
    #[serde(with = "crate::primitives::u128_serde")]
    pub balance: u128,
    /// Total allocated to grants
    #[serde(with = "crate::primitives::u128_serde")]
    pub allocated_grants: u128,
    /// Total spent on development
    #[serde(with = "crate::primitives::u128_serde")]
    pub spent_development: u128,
    /// Total spent on marketing
    #[serde(with = "crate::primitives::u128_serde")]
    pub spent_marketing: u128,
    /// Reserved for future use
    #[serde(with = "crate::primitives::u128_serde")]
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
    #[serde(with = "crate::primitives::u128_serde")]
    pub max_grant_amount: u128,
    /// Minimum proposal threshold
    #[serde(with = "crate::primitives::u128_serde")]
    pub min_proposal_threshold: u128,
    /// Grant approval quorum (basis points)
    pub grant_approval_quorum: u32,
}

impl Default for TreasuryParameters {
    fn default() -> Self {
        Self {
            max_grant_amount: 1_000_000u128 * 10u128.pow(18), // 1M TNZO
            min_proposal_threshold: 10_000u128 * 10u128.pow(18), // 10K TNZO
            grant_approval_quorum: 5000,                      // 50%
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
    #[serde(with = "crate::primitives::u128_serde")]
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
        self.total_staked = self
            .total_staked
            .checked_add(amount)
            .ok_or("Stake addition would overflow")?;
        self.staker_count = self
            .staker_count
            .checked_add(1)
            .ok_or("Staker count would overflow")?;
        Ok(())
    }

    /// Removes stake from the pool using checked arithmetic
    pub fn remove_stake(&mut self, amount: u128) -> Result<(), &'static str> {
        self.total_staked = self
            .total_staked
            .checked_sub(amount)
            .ok_or("Insufficient stake to remove")?;
        self.staker_count = self
            .staker_count
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
    #[serde(with = "crate::primitives::u128_serde")]
    pub staked_amount: u128,
    /// Stake timestamp
    pub staked_at: Timestamp,
    /// Lock period end (if any)
    pub lock_until: Option<Timestamp>,
    /// Rewards earned (in smallest unit)
    #[serde(with = "crate::primitives::u128_serde")]
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
        self.lock_until = Some(Timestamp::new(Timestamp::now().as_millis() + duration_ms));
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
        self.rewards_earned = self
            .rewards_earned
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
    /// RPC operator — carries tenant traffic and mints tenant API keys
    RpcProvider,
    /// TEE provider
    TeeProvider,
    /// Model provider — serves inference from the model catalogue
    ModelProvider,
    /// Compute provider — rents accelerator capacity for fixed terms
    ComputeProvider,
    /// Storage provider
    StorageProvider,
    /// Cloud operator — hosted functions, sites, databases and machines
    CloudProvider,
    /// Tenzro Train trainer — proposes outer gradients for a fragment
    Trainer,
    /// Tenzro Train syncer — aggregates outer gradients and publishes rounds
    Syncer,
}

/// Class of a pledged accelerator, which sets its share of the compute bond.
///
/// Multipliers track the spread observed across per-GPU bonds in comparable
/// networks, where a datacentre card carries roughly five times the collateral
/// of a consumer card and integrated memory carries about half.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AcceleratorClass {
    /// Integrated or unified memory — Apple Silicon, iGPU
    Integrated,
    /// Consumer discrete card
    Consumer,
    /// Workstation or inference card
    Workstation,
    /// Datacentre training card
    Datacentre,
}

impl AcceleratorClass {
    /// Share of [`COMPUTE_STAKE_PER_ACCELERATOR`] this class carries, in basis
    /// points of that base.
    ///
    /// [`COMPUTE_STAKE_PER_ACCELERATOR`]: crate::constants::COMPUTE_STAKE_PER_ACCELERATOR
    pub const fn stake_multiplier_bps(&self) -> u32 {
        match self {
            Self::Integrated => 5_000,
            Self::Consumer => 10_000,
            Self::Workstation => 20_000,
            Self::Datacentre => 50_000,
        }
    }
}

/// Service class a cloud operator offers, which sets its bond.
///
/// Each rung is a superset of the one below, so an operator that offers
/// machines is also offering databases, functions and sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CloudTier {
    /// Request-scoped functions and static sites
    Functions,
    /// Adds managed databases
    Databases,
    /// Adds long-lived machines
    Machines,
}

/// Capacity a provider declares when bonding, for the roles whose bond scales.
///
/// Roles that collateralise a privilege rather than a quantity pass
/// [`StakeCapacity::None`] and take their flat bond.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum StakeCapacity {
    /// No capacity dimension — the role's flat bond applies.
    #[default]
    None,
    /// Accelerators pledged for rental.
    Accelerators(Vec<AcceleratorClass>),
    /// Whole terabytes of disk pledged.
    Terabytes(u32),
    /// Highest cloud service class offered.
    Cloud(CloudTier),
}

impl ProviderType {
    /// Bond this role requires for the declared `capacity`.
    ///
    /// Capacity is ignored by roles that do not scale, so passing
    /// [`StakeCapacity::None`] to a scaling role yields that role's floor
    /// rather than zero — bonding is never free.
    pub fn required_stake(&self, capacity: &StakeCapacity) -> u128 {
        use crate::constants::*;

        match self {
            Self::Validator => MIN_VALIDATOR_STAKE,
            Self::RpcProvider => MIN_RPC_OPERATOR_STAKE,
            Self::TeeProvider => MIN_TEE_PROVIDER_STAKE,
            Self::ModelProvider => MIN_MODEL_PROVIDER_STAKE,
            // Trainers and syncers contribute the same class of work as a
            // model provider, so they carry the same bond.
            Self::Trainer | Self::Syncer => MIN_MODEL_PROVIDER_STAKE,

            Self::ComputeProvider => {
                let pledged = match capacity {
                    StakeCapacity::Accelerators(classes) => classes
                        .iter()
                        .map(|c| {
                            COMPUTE_STAKE_PER_ACCELERATOR
                                .saturating_mul(c.stake_multiplier_bps() as u128)
                                / 10_000
                        })
                        .fold(0u128, |acc, v| acc.saturating_add(v)),
                    _ => 0,
                };
                pledged.max(MIN_COMPUTE_PROVIDER_STAKE)
            }

            Self::StorageProvider => {
                let pledged = match capacity {
                    StakeCapacity::Terabytes(tb) => {
                        STORAGE_STAKE_PER_TB.saturating_mul(*tb as u128)
                    }
                    _ => 0,
                };
                pledged.max(MIN_STORAGE_PROVIDER_STAKE)
            }

            Self::CloudProvider => match capacity {
                StakeCapacity::Cloud(CloudTier::Machines) => CLOUD_MACHINE_TIER_STAKE,
                StakeCapacity::Cloud(CloudTier::Databases) => CLOUD_DATABASE_TIER_STAKE,
                _ => MIN_CLOUD_PROVIDER_STAKE,
            },
        }
    }

    /// Canonical wire name for this role, as accepted by [`FromStr`].
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Validator => "validator",
            Self::RpcProvider => "rpc",
            Self::TeeProvider => "tee",
            Self::ModelProvider => "model",
            Self::ComputeProvider => "compute",
            Self::StorageProvider => "storage",
            Self::CloudProvider => "cloud",
            Self::Trainer => "trainer",
            Self::Syncer => "syncer",
        }
    }
}

impl std::fmt::Display for ProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ProviderType {
    type Err = String;

    /// Parse a role name. Matching is case-insensitive and tolerates the
    /// hyphenated and underscored spellings of the `-provider` suffix, so a
    /// caller may write `tee`, `tee-provider` or `TEE_PROVIDER` and get the
    /// same role. Anything else is an error — there is no default role,
    /// because guessing one would bond the caller to the wrong ladder rung.
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let normalised = s.trim().to_lowercase().replace('-', "_");
        let stem = normalised
            .strip_suffix("_provider")
            .or_else(|| normalised.strip_suffix("_operator"))
            .unwrap_or(&normalised);

        match stem {
            "validator" => Ok(Self::Validator),
            "rpc" => Ok(Self::RpcProvider),
            "tee" | "confidential" => Ok(Self::TeeProvider),
            "model" | "ai" | "inference" => Ok(Self::ModelProvider),
            "compute" | "gpu" | "accelerator" => Ok(Self::ComputeProvider),
            "storage" => Ok(Self::StorageProvider),
            "cloud" => Ok(Self::CloudProvider),
            "trainer" => Ok(Self::Trainer),
            "syncer" => Ok(Self::Syncer),
            _ => Err(format!(
                "unknown provider type '{s}' (expected one of: validator, rpc, tee, \
                 model, compute, storage, cloud, trainer, syncer)"
            )),
        }
    }
}

impl std::str::FromStr for CloudTier {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "functions" | "sites" | "functions_sites" => Ok(Self::Functions),
            "databases" | "database" => Ok(Self::Databases),
            "machines" | "machine" => Ok(Self::Machines),
            _ => Err(format!(
                "unknown cloud tier '{s}' (expected one of: functions, databases, machines)"
            )),
        }
    }
}

impl std::str::FromStr for AcceleratorClass {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "integrated" | "unified" | "igpu" => Ok(Self::Integrated),
            "consumer" => Ok(Self::Consumer),
            "workstation" => Ok(Self::Workstation),
            "datacentre" | "datacenter" => Ok(Self::Datacentre),
            _ => Err(format!(
                "unknown accelerator class '{s}' (expected one of: integrated, \
                 consumer, workstation, datacentre)"
            )),
        }
    }
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
    #[serde(with = "crate::primitives::u128_serde")]
    pub votes_for: u128,
    /// Votes against
    #[serde(with = "crate::primitives::u128_serde")]
    pub votes_against: u128,
    /// Total voting power
    #[serde(with = "crate::primitives::u128_serde")]
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
    ParameterChange {
        parameter: String,
        new_value: String,
    },
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
    /// SeedAgent earmark adjustment (Spec 10). Governs the master enable
    /// flag, allocation top-ups, and the sunset surplus disposition. Other
    /// fields on `TreasuryEarmark` (decay schedule, bootstrap window,
    /// charter id list, draw counters) are mutated by protocol code, not
    /// directly by proposal.
    SeedAgentEarmarkUpdate {
        /// Master enable flag. When `false`, no new SeedAgent provisioning
        /// is admitted and the daemon should wind down.
        enabled: bool,
        /// TNZO base units to *add* to `allocation_remaining_wei` (and to
        /// `initial_allocation_wei` if `is_initial_seed` is set). Zero
        /// leaves the balance unchanged.
        allocation_topup_wei: u128,
        /// If `true`, this proposal also sets `initial_allocation_wei`
        /// (genesis seeding). After genesis, top-ups should leave the
        /// initial figure intact for audit purposes.
        is_initial_seed: bool,
        /// New sunset surplus disposition in basis points to burn (the
        /// remainder returns to general treasury). `<= 10_000`.
        surplus_burn_bps: u16,
    },
    /// SeedAgent charter upsert/disable (Spec 10). The charter id is
    /// `Hash([u8; 32])` rendered as 32 raw bytes; downstream executor
    /// resolves it against the SeedAgentEarmarkManager. Disabling sets
    /// `enabled = false` on the existing charter without removing it,
    /// which signals existing agents under that charter to wind down.
    SeedAgentCharterUpsert {
        /// Bincode-serialized [`Charter`] payload. The executor decodes
        /// and runs `Charter::validate()` before applying.
        charter_blob: Vec<u8>,
    },
    /// SeedAgent per-agent status transition (Spec 10). Used by
    /// governance to Pause / Quarantine / Terminate a misbehaving agent
    /// without touching the charter under which it operates.
    SeedAgentStatusSet {
        agent_did: String,
        /// Target status as `SeedAgentStatus::as_str()`:
        /// `"active" | "paused" | "quarantined" | "terminated"`.
        status: String,
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
