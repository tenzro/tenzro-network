//! EIP-1559 dynamic fee market
//!
//! Each block has a **base fee**, the minimum gas price a transaction must
//! offer to be executed. It adjusts by up to 12.5% per block according to
//! whether the previous block used more or less than its gas target.
//!
//! The base fee a block charges is consensus state: it is computed by
//! [`next_base_fee`] when the previous block settles its fees (see
//! [`crate::ledger::settle_block`]) and stored in state, so every node prices
//! the next block identically. [`FeeMarket`] is the node's read model of that
//! value, kept for fee quotes, `eth_feeHistory` and admission. It is updated
//! only from the settlement a finalized block wrote, never computed on its
//! own.

use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::ledger::BlockFeeSettlement;

/// EIP-1559 fee market configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip1559Config {
    /// Initial base fee per gas (in wei-equivalent smallest unit)
    pub initial_base_fee: u128,
    /// Target gas per block (50% of max_gas_per_block)
    pub target_gas_per_block: u64,
    /// Maximum gas per block
    pub max_gas_per_block: u64,
    /// Base fee change denominator (8 = max 12.5% change per block)
    pub base_fee_change_denominator: u64,
    /// Elasticity multiplier (2 = blocks can be 2x target)
    pub elasticity_multiplier: u64,
    /// Minimum base fee (floor to prevent zero-fee attacks)
    pub min_base_fee: u128,
    /// Maximum base fee (ceiling to protect users during fee spikes)
    pub max_base_fee: u128,
}

impl Default for Eip1559Config {
    fn default() -> Self {
        Self {
            initial_base_fee: 1_000_000_000,  // 1 Gwei
            target_gas_per_block: 15_000_000, // 15M gas target
            max_gas_per_block: 30_000_000,    // 30M gas max
            base_fee_change_denominator: 8,   // 12.5% max change per block
            elasticity_multiplier: 2,         // 2x target = max
            min_base_fee: 100_000_000,        // 0.1 Gwei floor
            max_base_fee: 1_000_000_000_000,  // 1000 Gwei ceiling
        }
    }
}

/// Base fee of the block after one whose base fee was `current` and which
/// used `parent_gas_used` gas.
///
/// - above target: rises by up to 1/`base_fee_change_denominator`
/// - below target: falls by up to the same fraction
/// - at target: unchanged
///
/// Pure in its inputs, so every node that executed the same parent block
/// arrives at the same value.
pub fn next_base_fee(config: &Eip1559Config, current: u128, parent_gas_used: u64) -> u128 {
    let target = config.target_gas_per_block;
    let denominator = config.base_fee_change_denominator as u128;

    let next_fee = if parent_gas_used == target {
        current
    } else if parent_gas_used > target {
        let gas_delta = (parent_gas_used - target) as u128;
        let fee_delta = current.saturating_mul(gas_delta) / (target as u128) / denominator;
        // At least 1 wei of increase whenever the block was above target.
        current.saturating_add(fee_delta.max(1))
    } else {
        let gas_delta = (target - parent_gas_used) as u128;
        let fee_delta = current.saturating_mul(gas_delta) / (target as u128) / denominator;
        current.saturating_sub(fee_delta)
    };

    next_fee.clamp(config.min_base_fee, config.max_base_fee)
}

/// The node's read model of the fee market.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeMarket {
    /// Configuration
    config: Eip1559Config,
    /// Base fee the next block charges
    current_base_fee: u128,
    /// Gas used in the most recent block
    last_block_gas_used: u64,
    /// Blocks observed since this node started
    block_number: u64,
    /// TNZO burned from fees by the blocks observed since this node started
    total_burned: u128,
    /// TNZO credited to the treasury from fees by the blocks observed since
    /// this node started
    total_to_treasury: u128,
    /// Historical base fees (for analytics, last N blocks)
    base_fee_history: Vec<u128>,
    /// Maximum history entries to retain
    max_history: usize,
}

impl FeeMarket {
    /// Create a new EIP-1559 fee market
    pub fn new(config: Eip1559Config) -> Self {
        let initial_fee = config.initial_base_fee;
        Self {
            config,
            current_base_fee: initial_fee,
            last_block_gas_used: 0,
            block_number: 0,
            total_burned: 0,
            total_to_treasury: 0,
            base_fee_history: vec![initial_fee],
            max_history: 1024,
        }
    }

    /// Records the fee settlement a finalized block wrote to state.
    ///
    /// The next base fee is taken from the settlement, not recomputed, so
    /// this read model can never disagree with consensus.
    pub fn record_settled_block(&mut self, settled: &BlockFeeSettlement) {
        let previous = self.current_base_fee;
        self.current_base_fee = settled.next_base_fee;
        self.last_block_gas_used = settled.gas_used;
        self.block_number += 1;
        self.total_burned = self.total_burned.saturating_add(settled.burned);
        self.total_to_treasury = self.total_to_treasury.saturating_add(settled.to_treasury);

        self.base_fee_history.push(settled.next_base_fee);
        if self.base_fee_history.len() > self.max_history {
            self.base_fee_history.remove(0);
        }

        debug!(
            gas_used = settled.gas_used,
            base_fee = previous,
            next_base_fee = settled.next_base_fee,
            collected = %settled.collected,
            burned = %settled.burned,
            to_treasury = %settled.to_treasury,
            "Fee market advanced"
        );
    }

    /// Get the current base fee
    pub fn base_fee(&self) -> u128 {
        self.current_base_fee
    }

    /// TNZO burned from fees by the blocks this node has observed
    pub fn total_burned(&self) -> u128 {
        self.total_burned
    }

    /// TNZO credited to the treasury from fees by the blocks this node has
    /// observed
    pub fn total_to_treasury(&self) -> u128 {
        self.total_to_treasury
    }

    /// Get the current block number
    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    /// Get the gas used in the most recently finalized block
    pub fn last_block_gas_used(&self) -> u64 {
        self.last_block_gas_used
    }

    /// Get the fee market configuration (target/max gas, bounds)
    pub fn config(&self) -> &Eip1559Config {
        &self.config
    }

    /// Recent base-fee history (oldest → newest), bounded by `max_history`.
    ///
    /// Used by `eth_feeHistory` to surface a window of recent base fees so
    /// wallets and explorers can compute fee percentiles and anticipate
    /// upcoming base-fee adjustments.
    pub fn base_fee_history(&self) -> &[u128] {
        &self.base_fee_history
    }

    /// Get fee market statistics
    pub fn stats(&self) -> FeeMarketStats {
        let avg_base_fee = if self.base_fee_history.is_empty() {
            0
        } else {
            let sum: u128 = self.base_fee_history.iter().sum();
            sum / self.base_fee_history.len() as u128
        };

        let min_base_fee = self.base_fee_history.iter().copied().min().unwrap_or(0);
        let max_base_fee = self.base_fee_history.iter().copied().max().unwrap_or(0);

        FeeMarketStats {
            current_base_fee: self.current_base_fee,
            average_base_fee: avg_base_fee,
            min_base_fee_recent: min_base_fee,
            max_base_fee_recent: max_base_fee,
            total_burned: self.total_burned,
            total_to_treasury: self.total_to_treasury,
            block_number: self.block_number,
            last_block_gas_used: self.last_block_gas_used,
            target_gas_per_block: self.config.target_gas_per_block,
            utilization_rate: if self.config.target_gas_per_block > 0 {
                self.last_block_gas_used as f64 / self.config.target_gas_per_block as f64
            } else {
                0.0
            },
        }
    }

    /// Suggest priority fee based on recent block history
    pub fn suggest_priority_fee(&self, urgency: FeeUrgency) -> u128 {
        let base = self.current_base_fee;
        match urgency {
            FeeUrgency::Low => base / 10,   // 10% of base fee
            FeeUrgency::Medium => base / 5, // 20% of base fee
            FeeUrgency::High => base / 2,   // 50% of base fee
            FeeUrgency::Urgent => base,     // 100% of base fee
        }
    }
}

impl Default for FeeMarket {
    fn default() -> Self {
        Self::new(Eip1559Config::default())
    }
}

/// Fee urgency level for priority fee suggestions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeUrgency {
    /// Low priority — willing to wait several blocks
    Low,
    /// Medium priority — next few blocks
    Medium,
    /// High priority — next block
    High,
    /// Urgent — must be in the very next block
    Urgent,
}

/// Fee market statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeMarketStats {
    /// Current base fee per gas
    pub current_base_fee: u128,
    /// Average base fee over recent blocks
    pub average_base_fee: u128,
    /// Minimum base fee in recent history
    pub min_base_fee_recent: u128,
    /// Maximum base fee in recent history
    pub max_base_fee_recent: u128,
    /// TNZO burned from fees by the blocks this node has observed
    pub total_burned: u128,
    /// TNZO credited to the treasury from fees by the blocks this node has
    /// observed
    pub total_to_treasury: u128,
    /// Current block number
    pub block_number: u64,
    /// Gas used in the last block
    pub last_block_gas_used: u64,
    /// Target gas per block
    pub target_gas_per_block: u64,
    /// Current utilization rate (gas_used / target)
    pub utilization_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settled(
        next_base_fee: u128,
        gas_used: u64,
        burned: u128,
        to_treasury: u128,
    ) -> BlockFeeSettlement {
        BlockFeeSettlement {
            collected: burned + to_treasury,
            burned,
            to_treasury,
            to_insurance: 0,
            next_base_fee,
            gas_used,
        }
    }

    #[test]
    fn test_fee_market_creation() {
        let market = FeeMarket::default();
        assert_eq!(market.base_fee(), 1_000_000_000); // 1 Gwei
        assert_eq!(market.total_burned(), 0);
        assert_eq!(market.block_number(), 0);
    }

    #[test]
    fn test_base_fee_increase_on_full_block() {
        let config = Eip1559Config::default();
        let base = config.initial_base_fee;
        let next_fee = next_base_fee(&config, base, config.target_gas_per_block * 2);
        assert!(
            next_fee > base,
            "Base fee should increase when block is full"
        );
        assert!(
            next_fee <= base + base / 8,
            "Increase should not exceed 12.5%"
        );
    }

    #[test]
    fn test_base_fee_decrease_on_empty_block() {
        let config = Eip1559Config::default();
        let base = config.initial_base_fee;
        let next_fee = next_base_fee(&config, base, 0);
        assert!(next_fee < base, "Base fee should decrease on empty block");
        assert!(next_fee >= config.min_base_fee);
    }

    #[test]
    fn test_base_fee_stable_at_target() {
        let config = Eip1559Config::default();
        let base = config.initial_base_fee;
        assert_eq!(
            next_base_fee(&config, base, config.target_gas_per_block),
            base
        );
    }

    #[test]
    fn test_min_base_fee_floor() {
        let config = Eip1559Config {
            min_base_fee: 100_000_000,
            initial_base_fee: 100_000_000,
            ..Default::default()
        };
        assert!(next_base_fee(&config, config.initial_base_fee, 0) >= 100_000_000);
    }

    #[test]
    fn the_read_model_follows_the_settled_block() {
        let mut market = FeeMarket::default();
        market.record_settled_block(&settled(1_125_000_000, 30_000_000, 700, 300));

        assert_eq!(market.base_fee(), 1_125_000_000);
        assert_eq!(market.block_number(), 1);
        assert_eq!(market.last_block_gas_used(), 30_000_000);
        assert_eq!(market.total_burned(), 700);
        assert_eq!(market.total_to_treasury(), 300);
        assert_eq!(market.base_fee_history().last(), Some(&1_125_000_000));
    }

    #[test]
    fn test_fee_market_stats() {
        let mut market = FeeMarket::default();
        market.record_settled_block(&settled(1_000_000_000, 15_000_000, 0, 0));

        let stats = market.stats();
        assert_eq!(stats.block_number, 1);
        assert!(stats.current_base_fee > 0);
        assert!(stats.average_base_fee > 0);
    }

    #[test]
    fn test_priority_fee_suggestions() {
        let market = FeeMarket::default();

        let low = market.suggest_priority_fee(FeeUrgency::Low);
        let medium = market.suggest_priority_fee(FeeUrgency::Medium);
        let high = market.suggest_priority_fee(FeeUrgency::High);
        let urgent = market.suggest_priority_fee(FeeUrgency::Urgent);

        assert!(low < medium);
        assert!(medium < high);
        assert!(high < urgent);
    }
}
