//! Reward distribution engine
//!
//! This module implements reward calculation and distribution for stakers
//! based on stake amount, uptime, service quality, and provider type.

use crate::error::{Result, TokenError};
use dashmap::DashMap;
use dashmap::DashSet;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tenzro_types::primitives::{Address, BlockHeight, Timestamp};
use tenzro_types::token::ProviderType;
use tracing::{debug, info};

/// Epoch duration in blocks
pub const EPOCH_DURATION_BLOCKS: u64 = 14400; // ~1 day at 6s/block

/// Default staking reward rate (5% APY in basis points)
pub const DEFAULT_STAKING_REWARD_RATE_BPS: u32 = 500;

/// Epoch rewards tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochRewards {
    /// Epoch number
    pub epoch: u64,
    /// Start block height
    pub start_height: BlockHeight,
    /// End block height
    pub end_height: BlockHeight,
    /// Total rewards distributed
    pub total_rewards: u128,
    /// Rewards by provider type
    pub rewards_by_type: HashMap<ProviderType, u128>,
    /// Individual rewards (Address -> Amount)
    pub individual_rewards: HashMap<Address, u128>,
    /// Timestamp when calculated
    pub calculated_at: Timestamp,
}

impl EpochRewards {
    /// Creates a new epoch rewards record
    pub fn new(epoch: u64, start_height: BlockHeight, end_height: BlockHeight) -> Self {
        Self {
            epoch,
            start_height,
            end_height,
            total_rewards: 0,
            rewards_by_type: HashMap::new(),
            individual_rewards: HashMap::new(),
            calculated_at: Timestamp::now(),
        }
    }

    /// Adds a reward for an address
    pub fn add_reward(&mut self, address: Address, amount: u128, provider_type: ProviderType) {
        // Update individual rewards
        let current = self.individual_rewards.get(&address).copied().unwrap_or(0);
        self.individual_rewards.insert(
            address,
            current.saturating_add(amount),
        );

        // Update type totals
        let type_total = self.rewards_by_type.get(&provider_type).copied().unwrap_or(0);
        self.rewards_by_type.insert(
            provider_type,
            type_total.saturating_add(amount),
        );

        // Update total
        self.total_rewards = self.total_rewards.saturating_add(amount);
    }
}

/// Reward claim record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardClaim {
    /// Claimant address
    pub claimant: Address,
    /// Amount claimed
    pub amount: u128,
    /// Epochs claimed
    pub epochs: Vec<u64>,
    /// Timestamp of claim
    pub claimed_at: Timestamp,
}

impl RewardClaim {
    /// Creates a new reward claim
    pub fn new(claimant: Address, amount: u128, epochs: Vec<u64>) -> Self {
        Self {
            claimant,
            amount,
            epochs,
            claimed_at: Timestamp::now(),
        }
    }
}

/// Reward distributor
///
/// Calculates and distributes rewards to stakers based on multiple factors.
#[derive(Debug)]
pub struct RewardDistributor {
    /// Epoch rewards history (Epoch -> EpochRewards)
    epoch_rewards: DashMap<u64, EpochRewards>,
    /// Pending rewards per address (Address -> Amount)
    pending_rewards: DashMap<Address, u128>,
    /// Claimed rewards per address (Address -> Vec<RewardClaim>)
    claimed_rewards: DashMap<Address, Vec<RewardClaim>>,
    /// Set of epochs that have been distributed (prevents double-distribution)
    distributed_epochs: DashSet<u64>,
    /// Current epoch
    current_epoch: parking_lot::RwLock<u64>,
    /// Staking reward rate (basis points per year)
    reward_rate_bps: parking_lot::RwLock<u32>,
    /// Total reward pool
    reward_pool: parking_lot::RwLock<u128>,
}

impl RewardDistributor {
    /// Creates a new reward distributor
    pub fn new() -> Self {
        Self {
            epoch_rewards: DashMap::new(),
            pending_rewards: DashMap::new(),
            claimed_rewards: DashMap::new(),
            distributed_epochs: DashSet::new(),
            current_epoch: parking_lot::RwLock::new(0),
            reward_rate_bps: parking_lot::RwLock::new(DEFAULT_STAKING_REWARD_RATE_BPS),
            reward_pool: parking_lot::RwLock::new(0),
        }
    }

    /// Calculates rewards for an epoch
    ///
    /// # Arguments
    ///
    /// * `epoch` - Epoch number
    /// * `start_height` - Start block height
    /// * `end_height` - End block height
    /// * `stakes` - Active stakes (Address -> (Amount, ProviderType, Uptime%))
    pub fn calculate_epoch_rewards(
        &self,
        epoch: u64,
        start_height: BlockHeight,
        end_height: BlockHeight,
        stakes: Vec<(Address, u128, ProviderType, f64)>,
    ) -> Result<EpochRewards> {
        // Prevent duplicate epoch reward calculation
        if self.epoch_rewards.contains_key(&epoch) {
            return Err(TokenError::InvalidAmount(
                format!("Rewards already calculated for epoch {}", epoch)
            ));
        }

        // Ensure epochs are processed in order
        let current = *self.current_epoch.read();
        if epoch != 0 && epoch <= current {
            return Err(TokenError::InvalidAmount(
                format!("Epoch {} already processed (current: {})", epoch, current)
            ));
        }

        let mut epoch_rewards = EpochRewards::new(epoch, start_height, end_height);

        // Calculate total staked
        let total_staked: u128 = stakes.iter().map(|(_, amount, _, _)| amount).sum();
        if total_staked == 0 {
            return Ok(epoch_rewards);
        }

        // Get reward rate and pool
        let reward_rate = *self.reward_rate_bps.read();
        let pool = *self.reward_pool.read();

        // Calculate epoch reward budget
        // Simplified: divide annual rate by number of epochs per year
        let epochs_per_year = 365u128; // Assuming ~1 day epochs
        let epoch_budget = (total_staked as f64 * (reward_rate as f64 / 10000.0) / epochs_per_year as f64) as u128;
        let epoch_budget = epoch_budget.min(pool);

        // Distribute rewards proportionally
        for (address, stake_amount, provider_type, uptime) in stakes {
            // Calculate base reward based on stake proportion
            let stake_proportion = stake_amount as f64 / total_staked as f64;
            let base_reward = (epoch_budget as f64 * stake_proportion) as u128;

            // Apply uptime multiplier (0.0 to 1.0)
            let uptime_multiplier = uptime.clamp(0.0, 1.0);
            let adjusted_reward = (base_reward as f64 * uptime_multiplier) as u128;

            // Apply provider type multiplier
            let type_multiplier = self.get_provider_type_multiplier(provider_type);
            let final_reward = (adjusted_reward as f64 * type_multiplier) as u128;

            // Record reward
            epoch_rewards.add_reward(address, final_reward, provider_type);

            debug!(
                "Calculated reward for {}: {} (stake: {}, uptime: {:.2}, type: {:?})",
                address, final_reward, stake_amount, uptime, provider_type
            );
        }

        // Store epoch rewards
        self.epoch_rewards.insert(epoch, epoch_rewards.clone());

        // Update current epoch
        *self.current_epoch.write() = epoch;

        info!("Calculated rewards for epoch {}: total {}", epoch, epoch_rewards.total_rewards);
        Ok(epoch_rewards)
    }

    /// Distributes calculated rewards to pending balances
    ///
    /// # Arguments
    ///
    /// * `epoch` - Epoch to distribute
    pub fn distribute_rewards(&self, epoch: u64) -> Result<()> {
        let epoch_rewards = self.epoch_rewards.get(&epoch)
            .ok_or_else(|| TokenError::InvalidAmount(
                format!("No rewards calculated for epoch {}", epoch)
            ))?;

        // Atomically mark epoch as distributed (prevents double-distribution race condition).
        // DashSet::insert() returns false if the key already existed, making this both
        // the check AND the lock in a single atomic operation.
        if !self.distributed_epochs.insert(epoch) {
            return Err(TokenError::InvalidAmount(
                format!("Rewards already distributed for epoch {}", epoch)
            ));
        }

        // Deduct from reward pool
        let total_rewards = epoch_rewards.total_rewards;
        {
            let mut pool = self.reward_pool.write();
            if *pool < total_rewards {
                // Roll back the distributed mark since we can't actually distribute
                self.distributed_epochs.remove(&epoch);
                return Err(TokenError::InvalidAmount(
                    format!("Insufficient reward pool: need {}, have {}", total_rewards, *pool)
                ));
            }
            *pool = pool.checked_sub(total_rewards).unwrap_or(0);
        }

        // Add to pending rewards
        for (address, amount) in &epoch_rewards.individual_rewards {
            let mut pending = self.pending_rewards.entry(*address).or_insert(0);
            *pending = pending.checked_add(*amount).unwrap_or(u128::MAX);
        }

        info!("Distributed {} total rewards for epoch {}", total_rewards, epoch);
        Ok(())
    }

    /// Claims pending rewards for an address
    ///
    /// # Arguments
    ///
    /// * `claimant` - Address claiming rewards
    ///
    /// Returns the claimed amount
    pub fn claim_rewards(&self, claimant: &Address) -> Result<u128> {
        let amount = self.pending_rewards.get(claimant).map(|v| *v).unwrap_or(0);

        if amount == 0 {
            return Err(TokenError::InvalidAmount("No pending rewards".to_string()));
        }

        // Remove from pending
        self.pending_rewards.remove(claimant);

        // Record claim
        let epochs: Vec<u64> = self.epoch_rewards
            .iter()
            .filter_map(|entry| {
                if entry.value().individual_rewards.contains_key(claimant) {
                    Some(*entry.key())
                } else {
                    None
                }
            })
            .collect();

        let claim = RewardClaim::new(*claimant, amount, epochs);

        let mut claims = self.claimed_rewards.entry(*claimant).or_default();
        claims.push(claim);

        info!("Claimed {} rewards for {}", amount, claimant);
        Ok(amount)
    }

    /// Returns pending rewards for an address
    pub fn get_pending_rewards(&self, address: &Address) -> u128 {
        self.pending_rewards.get(address).map(|v| *v).unwrap_or(0)
    }

    /// Returns epoch rewards
    pub fn get_epoch_rewards(&self, epoch: u64) -> Option<EpochRewards> {
        self.epoch_rewards.get(&epoch).map(|v| v.clone())
    }

    /// Returns all claimed rewards for an address
    pub fn get_claimed_rewards(&self, address: &Address) -> Vec<RewardClaim> {
        self.claimed_rewards.get(address).map(|v| v.clone()).unwrap_or_default()
    }

    /// Adds to the reward pool
    pub fn add_to_reward_pool(&self, amount: u128) {
        let mut pool = self.reward_pool.write();
        *pool = pool.checked_add(amount).unwrap_or(u128::MAX);
        info!("Added {} to reward pool. New total: {}", amount, *pool);
    }

    /// Returns the current reward pool balance
    pub fn get_reward_pool_balance(&self) -> u128 {
        *self.reward_pool.read()
    }

    /// Updates the reward rate
    pub fn set_reward_rate(&self, rate_bps: u32) {
        *self.reward_rate_bps.write() = rate_bps;
        info!("Updated reward rate to {} bps", rate_bps);
    }

    /// Returns provider type multiplier for reward calculation
    fn get_provider_type_multiplier(&self, provider_type: ProviderType) -> f64 {
        match provider_type {
            ProviderType::Validator => 1.0,
            ProviderType::TeeProvider => 1.2,     // 20% bonus for TEE providers
            ProviderType::ModelProvider => 1.1,   // 10% bonus for model providers
            ProviderType::StorageProvider => 1.0,
            ProviderType::Trainer => 1.15,        // 15% bonus for trainers (Tenzro Train)
            ProviderType::Syncer => 1.25,         // 25% bonus for syncers (aggregation work)
        }
    }
}

impl Default for RewardDistributor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_epoch_rewards() {
        let distributor = RewardDistributor::new();
        distributor.add_to_reward_pool(1_000_000 * 1_000_000_000_000_000_000); // 1M TNZO

        let staker1 = Address::new([1u8; 32]);
        let staker2 = Address::new([2u8; 32]);

        let stakes = vec![
            (staker1, 100_000 * 1_000_000_000_000_000_000, ProviderType::Validator, 1.0),
            (staker2, 50_000 * 1_000_000_000_000_000_000, ProviderType::TeeProvider, 0.95),
        ];

        let rewards = distributor.calculate_epoch_rewards(
            1,
            BlockHeight::new(0),
            BlockHeight::new(EPOCH_DURATION_BLOCKS),
            stakes,
        ).unwrap();

        assert!(rewards.total_rewards > 0);
        assert_eq!(rewards.individual_rewards.len(), 2);
    }

    #[test]
    fn test_claim_rewards() {
        let distributor = RewardDistributor::new();
        let claimant = Address::new([1u8; 32]);

        // Add pending rewards
        distributor.pending_rewards.insert(claimant, 1000);

        let claimed = distributor.claim_rewards(&claimant).unwrap();
        assert_eq!(claimed, 1000);
        assert_eq!(distributor.get_pending_rewards(&claimant), 0);
    }

    #[test]
    fn test_no_double_epoch_calculation() {
        let distributor = RewardDistributor::new();
        distributor.add_to_reward_pool(1_000_000_000_000_000_000_000);

        let staker = Address::new([1u8; 32]);
        let stakes = vec![
            (staker, 100_000_000_000_000_000_000u128, ProviderType::Validator, 1.0),
        ];

        // First calculation should succeed
        distributor.calculate_epoch_rewards(
            1, BlockHeight::new(0), BlockHeight::new(EPOCH_DURATION_BLOCKS), stakes.clone(),
        ).unwrap();

        // Second calculation for same epoch should fail
        let result = distributor.calculate_epoch_rewards(
            1, BlockHeight::new(0), BlockHeight::new(EPOCH_DURATION_BLOCKS), stakes,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_no_double_distribution() {
        let distributor = RewardDistributor::new();
        distributor.add_to_reward_pool(1_000_000_000_000_000_000_000);

        let staker = Address::new([1u8; 32]);
        let stakes = vec![
            (staker, 100_000_000_000_000_000_000u128, ProviderType::Validator, 1.0),
        ];

        distributor.calculate_epoch_rewards(
            1, BlockHeight::new(0), BlockHeight::new(EPOCH_DURATION_BLOCKS), stakes,
        ).unwrap();

        // First distribution should succeed
        distributor.distribute_rewards(1).unwrap();

        // Second distribution for same epoch should fail
        let result = distributor.distribute_rewards(1);
        assert!(result.is_err());
    }
}
