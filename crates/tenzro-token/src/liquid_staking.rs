//! Liquid staking (stTNZO) implementation
//!
//! Implements native liquid staking for Tenzro Network, allowing stakers to receive
//! a liquid staking derivative token (stTNZO) that represents their staked position
//! plus accrued rewards.
//!
//! # Why Liquid Staking is Critical
//!
//! Without liquid staking, staked TNZO is "dead capital" — users must choose between
//! earning staking rewards and participating in DeFi. Every competitive PoS chain in
//! 2026 offers liquid staking (Ethereum's stETH, Solana's mSOL/jitoSOL, etc.).
//!
//! # stTNZO Token
//!
//! stTNZO is a rebasing token that represents a claim on staked TNZO plus accrued
//! rewards. The exchange rate between stTNZO and TNZO increases over time as
//! staking rewards accumulate.
//!
//! - **Mint**: Deposit TNZO → receive stTNZO at current exchange rate
//! - **Burn**: Return stTNZO → receive TNZO at current exchange rate (after unbonding)
//! - **Exchange rate**: `stTNZO_value = stTNZO_amount * exchange_rate`
//!   where `exchange_rate = total_underlying_tnzo / total_sttnzo_supply`
//!
//! # Architecture
//!
//! 1. User deposits TNZO into the liquid staking pool
//! 2. Pool stakes TNZO across multiple validators (diversification)
//! 3. User receives stTNZO at the current exchange rate
//! 4. Staking rewards flow into the pool, increasing the exchange rate
//! 5. A small fee (default 10%) is taken from rewards for the protocol treasury
//! 6. User can request withdrawal — starts unbonding period, then receives TNZO

use crate::error::{Result, TokenError};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tenzro_types::primitives::{Address, Timestamp};
use tracing::{debug, info};

/// stTNZO decimals (same as TNZO: 18)
pub const STTNZO_DECIMALS: u8 = 18;

/// One stTNZO in smallest unit
pub const ONE_STTNZO: u128 = 1_000_000_000_000_000_000;

/// Default protocol fee on staking rewards (basis points, 1000 = 10%)
pub const DEFAULT_PROTOCOL_FEE_BPS: u32 = 1000;

/// Liquid staking pool configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidStakingConfig {
    /// Protocol fee on rewards (basis points)
    pub protocol_fee_bps: u32,
    /// Minimum deposit amount (in TNZO smallest unit)
    pub min_deposit: u128,
    /// Maximum total deposits (pool cap, 0 = unlimited)
    pub max_total_deposits: u128,
    /// Unbonding period in milliseconds (mirrors native staking)
    pub unbonding_period_ms: i64,
    /// Maximum number of validators to delegate to
    pub max_validators: usize,
}

impl Default for LiquidStakingConfig {
    fn default() -> Self {
        Self {
            protocol_fee_bps: DEFAULT_PROTOCOL_FEE_BPS,
            min_deposit: ONE_STTNZO / 10, // 0.1 TNZO minimum
            max_total_deposits: 0, // Unlimited
            unbonding_period_ms: 7 * 24 * 60 * 60 * 1000, // 7 days
            max_validators: 50,
        }
    }
}

/// A pending withdrawal request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalRequest {
    /// Requester address
    pub requester: Address,
    /// stTNZO amount being burned
    pub sttnzo_amount: u128,
    /// TNZO amount to receive (calculated at request time using exchange rate)
    pub tnzo_amount: u128,
    /// Timestamp when unbonding completes
    pub unbonding_complete_at: Timestamp,
    /// Whether the withdrawal has been claimed
    pub claimed: bool,
    /// Request ID
    pub request_id: String,
}

/// Liquid staking pool manager
///
/// Manages the stTNZO liquid staking derivative for Tenzro Network.
#[derive(Debug)]
pub struct LiquidStakingPool {
    /// Configuration
    config: parking_lot::RwLock<LiquidStakingConfig>,

    /// stTNZO balances (holder address → stTNZO balance)
    sttnzo_balances: DashMap<Address, u128>,

    /// Total stTNZO supply
    total_sttnzo_supply: parking_lot::RwLock<u128>,

    /// Total underlying TNZO in the pool (staked + rewards - fees)
    total_underlying_tnzo: parking_lot::RwLock<u128>,

    /// Total protocol fees collected (TNZO)
    total_protocol_fees: parking_lot::RwLock<u128>,

    /// Pending withdrawal requests
    withdrawal_requests: DashMap<String, WithdrawalRequest>,

    /// Validators the pool delegates to (address → delegation amount)
    validator_delegations: DashMap<Address, u128>,

    /// Total rewards distributed through the pool
    total_rewards_distributed: parking_lot::RwLock<u128>,
}

impl LiquidStakingPool {
    /// Create a new liquid staking pool
    pub fn new(config: LiquidStakingConfig) -> Result<Self> {
        // Validate protocol fee (0-50%)
        if config.protocol_fee_bps > 5000 {
            return Err(TokenError::InvalidAmount(format!(
                "Protocol fee {} bps exceeds maximum 5000 bps (50%)",
                config.protocol_fee_bps
            )));
        }

        info!("Initializing stTNZO liquid staking pool (fee: {}bps)", config.protocol_fee_bps);

        Ok(Self {
            config: parking_lot::RwLock::new(config),
            sttnzo_balances: DashMap::new(),
            total_sttnzo_supply: parking_lot::RwLock::new(0),
            total_underlying_tnzo: parking_lot::RwLock::new(0),
            total_protocol_fees: parking_lot::RwLock::new(0),
            withdrawal_requests: DashMap::new(),
            validator_delegations: DashMap::new(),
            total_rewards_distributed: parking_lot::RwLock::new(0),
        })
    }

    /// Get the current exchange rate: TNZO per stTNZO.
    ///
    /// `exchange_rate = total_underlying_tnzo / total_sttnzo_supply`
    ///
    /// Returns the rate as a fixed-point number with 18 decimals.
    /// A rate of `1_000_000_000_000_000_000` (10^18) means 1:1.
    pub fn exchange_rate(&self) -> u128 {
        let supply = *self.total_sttnzo_supply.read();
        let underlying = *self.total_underlying_tnzo.read();

        if supply == 0 {
            // Initial rate is 1:1
            ONE_STTNZO
        } else {
            // rate = underlying * ONE_STTNZO / supply
            // To avoid overflow when underlying is large, split the division:
            // underlying / supply gives the integer TNZO-per-stTNZO ratio
            // (underlying % supply) * ONE_STTNZO / supply gives the fractional part
            let quotient = underlying / supply;
            let remainder = underlying % supply;
            quotient.saturating_mul(ONE_STTNZO)
                .saturating_add(
                    remainder.saturating_mul(ONE_STTNZO)
                        / supply
                )
        }
    }

    /// Deposit TNZO and receive stTNZO.
    ///
    /// The amount of stTNZO minted is calculated from the current exchange rate:
    /// `sttnzo_amount = tnzo_amount * 10^18 / exchange_rate`
    pub fn deposit(&self, depositor: Address, tnzo_amount: u128) -> Result<u128> {
        let config = self.config.read();

        // Validate minimum deposit
        if tnzo_amount < config.min_deposit {
            return Err(TokenError::InvalidAmount(format!(
                "Deposit below minimum: {} < {}",
                tnzo_amount, config.min_deposit
            )));
        }

        // Check pool cap
        if config.max_total_deposits > 0 {
            let current_total = *self.total_underlying_tnzo.read();
            if current_total + tnzo_amount > config.max_total_deposits {
                return Err(TokenError::InvalidAmount(
                    "Pool cap exceeded".to_string()
                ));
            }
        }
        drop(config);

        // Calculate stTNZO to mint
        // sttnzo = tnzo_amount * ONE_STTNZO / rate
        // To avoid overflow (both tnzo_amount and ONE_STTNZO can be ~10^18),
        // use: sttnzo = tnzo_amount / rate * ONE_STTNZO + (tnzo_amount % rate) * ONE_STTNZO / rate
        let rate = self.exchange_rate();
        let sttnzo_amount = if rate == 0 {
            tnzo_amount // First deposit: 1:1
        } else {
            let quotient = tnzo_amount / rate;
            let remainder = tnzo_amount % rate;
            quotient
                .checked_mul(ONE_STTNZO)
                .and_then(|q| {
                    remainder
                        .checked_mul(ONE_STTNZO)
                        .map(|r| q + r / rate)
                })
                .ok_or_else(|| TokenError::ArithmeticOverflow {
                    operation: "stTNZO mint calculation".to_string(),
                })?
        };

        if sttnzo_amount == 0 {
            return Err(TokenError::InvalidAmount(
                "Deposit too small to mint any stTNZO".to_string()
            ));
        }

        // Mint stTNZO to depositor
        let current_balance = self.sttnzo_balances.get(&depositor)
            .map(|v| *v)
            .unwrap_or(0);
        self.sttnzo_balances.insert(depositor, current_balance + sttnzo_amount);

        // Update totals
        *self.total_sttnzo_supply.write() += sttnzo_amount;
        *self.total_underlying_tnzo.write() += tnzo_amount;

        info!(
            "stTNZO: Deposited {} TNZO, minted {} stTNZO to {} (rate: {})",
            tnzo_amount, sttnzo_amount, depositor, rate
        );

        Ok(sttnzo_amount)
    }

    /// Request withdrawal: burn stTNZO and start unbonding.
    ///
    /// The TNZO amount is calculated from the current exchange rate at request time.
    /// User must wait the unbonding period before claiming.
    pub fn request_withdrawal(&self, requester: Address, sttnzo_amount: u128) -> Result<WithdrawalRequest> {
        // Check balance
        let balance = self.sttnzo_balances.get(&requester)
            .map(|v| *v)
            .unwrap_or(0);

        if balance < sttnzo_amount {
            return Err(TokenError::InsufficientBalance {
                required: sttnzo_amount,
                available: balance,
            });
        }

        // Calculate TNZO amount at current rate
        // tnzo = sttnzo_amount * rate / ONE_STTNZO
        // To avoid overflow, split: quotient * rate + remainder * rate / ONE_STTNZO
        let rate = self.exchange_rate();
        let quotient = sttnzo_amount / ONE_STTNZO;
        let remainder = sttnzo_amount % ONE_STTNZO;
        let tnzo_amount = quotient
            .checked_mul(rate)
            .and_then(|q| {
                remainder
                    .checked_mul(rate)
                    .map(|r| q + r / ONE_STTNZO)
            })
            .ok_or_else(|| TokenError::ArithmeticOverflow {
                operation: "stTNZO withdrawal calculation".to_string(),
            })?;

        // Burn stTNZO
        self.sttnzo_balances.insert(requester, balance - sttnzo_amount);
        *self.total_sttnzo_supply.write() -= sttnzo_amount;

        // Don't subtract from underlying yet — wait until claim

        // Create withdrawal request
        let config = self.config.read();
        let unbonding_ms = config.unbonding_period_ms;
        drop(config);

        let request = WithdrawalRequest {
            requester,
            sttnzo_amount,
            tnzo_amount,
            unbonding_complete_at: Timestamp::new(
                Timestamp::now().as_millis() + unbonding_ms,
            ),
            claimed: false,
            request_id: uuid::Uuid::new_v4().to_string(),
        };

        let request_id = request.request_id.clone();
        self.withdrawal_requests.insert(request_id.clone(), request.clone());

        info!(
            "stTNZO: Withdrawal requested: {} stTNZO -> {} TNZO, unbonding until {}",
            sttnzo_amount, tnzo_amount, request.unbonding_complete_at
        );

        Ok(request)
    }

    /// Claim a completed withdrawal after the unbonding period.
    ///
    /// Returns the TNZO amount to transfer to the user.
    pub fn claim_withdrawal(&self, request_id: &str) -> Result<(Address, u128)> {
        let mut request = self.withdrawal_requests.get_mut(request_id)
            .ok_or_else(|| TokenError::InvalidAmount(
                format!("Withdrawal request not found: {}", request_id)
            ))?;

        if request.claimed {
            return Err(TokenError::InvalidAmount(
                "Withdrawal already claimed".to_string()
            ));
        }

        // Check unbonding period
        if Timestamp::now() < request.unbonding_complete_at {
            return Err(TokenError::StakeLocked {
                unlock_time: request.unbonding_complete_at.as_millis(),
            });
        }

        // Mark as claimed
        request.claimed = true;
        let requester = request.requester;
        let tnzo_amount = request.tnzo_amount;

        // Subtract from underlying pool
        *self.total_underlying_tnzo.write() -= tnzo_amount.min(*self.total_underlying_tnzo.read());

        info!(
            "stTNZO: Withdrawal claimed: {} TNZO to {}",
            tnzo_amount, requester
        );

        Ok((requester, tnzo_amount))
    }

    /// Distribute staking rewards to the pool.
    ///
    /// This is called by the reward distributor when staking rewards are earned.
    /// The rewards increase the exchange rate (underlying TNZO goes up,
    /// stTNZO supply stays the same).
    pub fn distribute_rewards(&self, reward_amount: u128) -> Result<RewardDistribution> {
        if reward_amount == 0 {
            return Err(TokenError::InvalidAmount(
                "Reward amount must be greater than zero".to_string()
            ));
        }

        let config = self.config.read();
        let fee_bps = config.protocol_fee_bps;
        drop(config);

        // Calculate protocol fee
        let protocol_fee = reward_amount
            .checked_mul(fee_bps as u128)
            .unwrap_or(0)
            / 10000;
        let staker_reward = reward_amount - protocol_fee;

        // Add staker portion to underlying (increases exchange rate)
        *self.total_underlying_tnzo.write() += staker_reward;

        // Track protocol fees
        *self.total_protocol_fees.write() += protocol_fee;

        // Track total rewards
        *self.total_rewards_distributed.write() += reward_amount;

        let new_rate = self.exchange_rate();
        debug!(
            "stTNZO: Distributed {} TNZO rewards (staker: {}, protocol: {}), new rate: {}",
            reward_amount, staker_reward, protocol_fee, new_rate
        );

        Ok(RewardDistribution {
            total_reward: reward_amount,
            staker_share: staker_reward,
            protocol_fee,
            new_exchange_rate: new_rate,
        })
    }

    /// Get stTNZO balance for an address
    pub fn balance_of(&self, address: &Address) -> u128 {
        self.sttnzo_balances.get(address).map(|v| *v).unwrap_or(0)
    }

    /// Get the TNZO value of a stTNZO amount at the current exchange rate
    pub fn tnzo_value(&self, sttnzo_amount: u128) -> u128 {
        let rate = self.exchange_rate();
        // Avoid overflow: split into quotient and remainder
        let quotient = sttnzo_amount / ONE_STTNZO;
        let remainder = sttnzo_amount % ONE_STTNZO;
        quotient.saturating_mul(rate)
            .saturating_add(remainder.saturating_mul(rate) / ONE_STTNZO)
    }

    /// Get pool statistics
    pub fn stats(&self) -> LiquidStakingStats {
        LiquidStakingStats {
            total_sttnzo_supply: *self.total_sttnzo_supply.read(),
            total_underlying_tnzo: *self.total_underlying_tnzo.read(),
            exchange_rate: self.exchange_rate(),
            total_protocol_fees: *self.total_protocol_fees.read(),
            total_rewards_distributed: *self.total_rewards_distributed.read(),
            holder_count: self.sttnzo_balances.len() as u64,
            pending_withdrawals: self.withdrawal_requests.iter()
                .filter(|r| !r.claimed)
                .count() as u64,
        }
    }

    /// Add a validator delegation
    pub fn add_validator(&self, validator: Address, amount: u128) {
        let current = self.validator_delegations.get(&validator)
            .map(|v| *v)
            .unwrap_or(0);
        self.validator_delegations.insert(validator, current + amount);
    }

    /// Get all validator delegations
    pub fn validator_delegations(&self) -> Vec<(Address, u128)> {
        self.validator_delegations.iter()
            .map(|entry| (*entry.key(), *entry.value()))
            .collect()
    }

    /// Transfer stTNZO between addresses
    pub fn transfer(&self, from: &Address, to: &Address, amount: u128) -> Result<()> {
        let from_balance = self.balance_of(from);
        if from_balance < amount {
            return Err(TokenError::InsufficientBalance {
                required: amount,
                available: from_balance,
            });
        }

        self.sttnzo_balances.insert(*from, from_balance - amount);
        let to_balance = self.balance_of(to);
        self.sttnzo_balances.insert(*to, to_balance + amount);

        debug!("stTNZO: Transferred {} from {} to {}", amount, from, to);
        Ok(())
    }
}

impl Default for LiquidStakingPool {
    fn default() -> Self {
        Self::new(LiquidStakingConfig::default())
            .expect("Default config should always be valid")
    }
}

/// Reward distribution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardDistribution {
    /// Total reward amount
    pub total_reward: u128,
    /// Amount that went to stakers (increases exchange rate)
    pub staker_share: u128,
    /// Amount taken as protocol fee
    pub protocol_fee: u128,
    /// New exchange rate after distribution
    pub new_exchange_rate: u128,
}

/// Liquid staking pool statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidStakingStats {
    /// Total stTNZO in circulation
    pub total_sttnzo_supply: u128,
    /// Total TNZO underlying the pool
    pub total_underlying_tnzo: u128,
    /// Current exchange rate (TNZO per stTNZO, 18 decimals)
    pub exchange_rate: u128,
    /// Total protocol fees collected
    pub total_protocol_fees: u128,
    /// Total rewards distributed through the pool
    pub total_rewards_distributed: u128,
    /// Number of stTNZO holders
    pub holder_count: u64,
    /// Number of pending withdrawal requests
    pub pending_withdrawals: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one_tnzo() -> u128 {
        1_000_000_000_000_000_000 // 10^18
    }

    #[test]
    fn test_initial_exchange_rate() {
        let pool = LiquidStakingPool::default();
        assert_eq!(pool.exchange_rate(), ONE_STTNZO); // 1:1
    }

    #[test]
    fn test_deposit() {
        let pool = LiquidStakingPool::default();
        let user = Address::new([1u8; 32]);

        // First deposit: 1000 TNZO → should get 1000 stTNZO (1:1)
        let deposit_amount = 1000 * one_tnzo();
        let sttnzo = pool.deposit(user, deposit_amount).unwrap();

        assert_eq!(sttnzo, deposit_amount); // 1:1 initial rate
        assert_eq!(pool.balance_of(&user), deposit_amount);
        assert_eq!(*pool.total_sttnzo_supply.read(), deposit_amount);
        assert_eq!(*pool.total_underlying_tnzo.read(), deposit_amount);
    }

    #[test]
    fn test_deposit_below_minimum() {
        let pool = LiquidStakingPool::default();
        let user = Address::new([1u8; 32]);

        let result = pool.deposit(user, 1); // 1 wei, way below minimum
        assert!(result.is_err());
    }

    #[test]
    fn test_exchange_rate_increases_with_rewards() {
        let pool = LiquidStakingPool::default();
        let user = Address::new([1u8; 32]);

        // Deposit 1000 TNZO
        let deposit = 1000 * one_tnzo();
        pool.deposit(user, deposit).unwrap();

        let rate_before = pool.exchange_rate();

        // Distribute 100 TNZO in rewards (10% = 10 TNZO protocol fee)
        pool.distribute_rewards(100 * one_tnzo()).unwrap();

        let rate_after = pool.exchange_rate();
        assert!(rate_after > rate_before, "Exchange rate should increase after rewards");

        // User's stTNZO should now be worth more TNZO
        let value = pool.tnzo_value(pool.balance_of(&user));
        assert!(value > deposit, "stTNZO value should increase after rewards");
    }

    #[test]
    fn test_withdrawal_request() {
        let pool = LiquidStakingPool::default();
        let user = Address::new([1u8; 32]);

        // Deposit
        let deposit = 1000 * one_tnzo();
        pool.deposit(user, deposit).unwrap();

        // Request withdrawal of half
        let withdraw_sttnzo = 500 * one_tnzo();
        let request = pool.request_withdrawal(user, withdraw_sttnzo).unwrap();

        assert_eq!(request.sttnzo_amount, withdraw_sttnzo);
        assert_eq!(request.tnzo_amount, withdraw_sttnzo); // 1:1 rate
        assert!(!request.claimed);

        // Balance should be reduced
        assert_eq!(pool.balance_of(&user), deposit - withdraw_sttnzo);
    }

    #[test]
    fn test_insufficient_balance_withdrawal() {
        let pool = LiquidStakingPool::default();
        let user = Address::new([1u8; 32]);

        pool.deposit(user, 100 * one_tnzo()).unwrap();

        let result = pool.request_withdrawal(user, 200 * one_tnzo());
        assert!(result.is_err());
    }

    #[test]
    fn test_transfer() {
        let pool = LiquidStakingPool::default();
        let alice = Address::new([1u8; 32]);
        let bob = Address::new([2u8; 32]);

        pool.deposit(alice, 1000 * one_tnzo()).unwrap();
        pool.transfer(&alice, &bob, 300 * one_tnzo()).unwrap();

        assert_eq!(pool.balance_of(&alice), 700 * one_tnzo());
        assert_eq!(pool.balance_of(&bob), 300 * one_tnzo());
    }

    #[test]
    fn test_protocol_fee_collection() {
        let pool = LiquidStakingPool::default();
        let user = Address::new([1u8; 32]);

        pool.deposit(user, 1000 * one_tnzo()).unwrap();

        // 100 TNZO reward, 10% fee = 10 TNZO
        let dist = pool.distribute_rewards(100 * one_tnzo()).unwrap();
        assert_eq!(dist.protocol_fee, 10 * one_tnzo());
        assert_eq!(dist.staker_share, 90 * one_tnzo());
        assert_eq!(*pool.total_protocol_fees.read(), 10 * one_tnzo());
    }

    #[test]
    fn test_stats() {
        let pool = LiquidStakingPool::default();
        let user = Address::new([1u8; 32]);

        pool.deposit(user, 1000 * one_tnzo()).unwrap();

        let stats = pool.stats();
        assert_eq!(stats.total_sttnzo_supply, 1000 * one_tnzo());
        assert_eq!(stats.total_underlying_tnzo, 1000 * one_tnzo());
        assert_eq!(stats.holder_count, 1);
        assert_eq!(stats.exchange_rate, ONE_STTNZO);
    }

    #[test]
    fn test_multiple_depositors() {
        let pool = LiquidStakingPool::default();
        let alice = Address::new([1u8; 32]);
        let bob = Address::new([2u8; 32]);

        // Alice deposits first
        pool.deposit(alice, 1000 * one_tnzo()).unwrap();

        // Rewards come in
        pool.distribute_rewards(100 * one_tnzo()).unwrap();

        // Bob deposits now — should get less stTNZO per TNZO
        let bob_sttnzo = pool.deposit(bob, 1000 * one_tnzo()).unwrap();
        assert!(bob_sttnzo < 1000 * one_tnzo(), "Bob should get less stTNZO at higher rate");

        let stats = pool.stats();
        assert_eq!(stats.holder_count, 2);
    }
}
