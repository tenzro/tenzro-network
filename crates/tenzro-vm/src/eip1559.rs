//! EIP-1559 dynamic fee market implementation
//!
//! Implements the EIP-1559 fee mechanism (London hard fork), the universal standard
//! for transaction fee pricing in 2026. This replaces flat-fee pricing with a
//! dynamic base fee that adjusts per block based on network demand.
//!
//! # How EIP-1559 Works
//!
//! 1. Each block has a **base fee** — the minimum gas price for inclusion.
//! 2. The base fee adjusts up/down by up to 12.5% per block based on whether
//!    the previous block was above or below the target gas usage (50% of max).
//! 3. Users specify a **max fee** (max they'll pay) and **priority fee** (tip to validators).
//! 4. The effective gas price is `min(max_fee, base_fee + priority_fee)`.
//! 5. The base fee portion is **burned**, creating deflationary pressure on TNZO.
//! 6. The priority fee goes to validators/stakers.
//!
//! # Key Benefits
//!
//! - **Predictable fees**: Users know the base fee before submitting.
//! - **Deflationary**: Base fee burn reduces TNZO supply proportional to demand.
//! - **MEV reduction**: Uniform pricing reduces frontrunning incentive.
//! - **Better UX**: No more fee guessing or stuck transactions.

use serde::{Deserialize, Serialize};
use tracing::{debug, info};

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
            initial_base_fee: 1_000_000_000, // 1 Gwei
            target_gas_per_block: 15_000_000, // 15M gas target (same as Ethereum)
            max_gas_per_block: 30_000_000,    // 30M gas max
            base_fee_change_denominator: 8,   // 12.5% max change per block
            elasticity_multiplier: 2,         // 2x target = max
            min_base_fee: 100_000_000,        // 0.1 Gwei floor
            max_base_fee: 1_000_000_000_000,  // 1000 Gwei ceiling
        }
    }
}

/// EIP-1559 fee market state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeMarket {
    /// Configuration
    config: Eip1559Config,
    /// Current base fee per gas
    current_base_fee: u128,
    /// Gas used in the most recent block
    last_block_gas_used: u64,
    /// Current block number
    block_number: u64,
    /// Total base fees burned (deflationary mechanism). With the adaptive
    /// burn dial in place, this is `gross_fees * base_fee_burn_bps / 10_000`
    /// summed over all blocks. When the dial is 100% (genesis default), this
    /// equals total gross base fees.
    total_burned: u128,
    /// Total base-fee share routed to `NetworkTreasury` instead of burned.
    /// Complement of `total_burned` against gross base fees. Stays zero
    /// while `base_fee_burn_bps` remains at genesis 10_000.
    #[serde(default)]
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
        info!("Initializing EIP-1559 fee market (initial base fee: {} wei)", initial_fee);

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

    /// Calculate the base fee for the next block based on the previous block's gas usage.
    ///
    /// - If gas used > target: increase base fee (up to 12.5%)
    /// - If gas used < target: decrease base fee (up to 12.5%)
    /// - If gas used == target: no change
    pub fn calculate_next_base_fee(&self, parent_gas_used: u64) -> u128 {
        let target = self.config.target_gas_per_block;
        let denominator = self.config.base_fee_change_denominator as u128;
        let current = self.current_base_fee;

        let next_fee = if parent_gas_used == target {
            // Exactly at target — no change
            current
        } else if parent_gas_used > target {
            // Above target — increase base fee
            let gas_delta = (parent_gas_used - target) as u128;
            let fee_delta = (current * gas_delta) / (target as u128) / denominator;
            // Ensure at least 1 wei increase if above target
            current + fee_delta.max(1)
        } else {
            // Below target — decrease base fee
            let gas_delta = (target - parent_gas_used) as u128;
            let fee_delta = (current * gas_delta) / (target as u128) / denominator;
            current.saturating_sub(fee_delta)
        };

        // Clamp to configured bounds
        next_fee.clamp(self.config.min_base_fee, self.config.max_base_fee)
    }

    /// Update the fee market after a block is finalized.
    ///
    /// Default-burns 100% of the gross base fees. Equivalent to
    /// [`on_block_finalized_with_split`] called with `base_fee_burn_bps =
    /// 10_000`. Retained as the simple entry point for callers that don't
    /// yet wire the adaptive-burn dial (tests, single-node harnesses).
    pub fn on_block_finalized(&mut self, gas_used: u64) {
        self.on_block_finalized_with_split(gas_used, 10_000);
    }

    /// Update the fee market after a block is finalized, splitting the
    /// gross base-fee revenue between burn and treasury per the adaptive
    /// burn dial (Spec 8 — see `tenzro_token::adaptive_burn::BurnRateConfig`).
    ///
    /// `base_fee_burn_bps` is the share to burn in basis points (0..=10_000).
    /// Values outside the range are clamped. The complement
    /// `(10_000 - base_fee_burn_bps)` accrues to `total_to_treasury`.
    ///
    /// Note: this updates accounting counters only. Actual ledger movement
    /// of TNZO (burning supply, crediting `NetworkTreasury`) is handled by
    /// the executor layer when it consumes base-fee charges from payers.
    /// The split here is the authoritative basis for that movement, so the
    /// two stay in lockstep.
    pub fn on_block_finalized_with_split(&mut self, gas_used: u64, base_fee_burn_bps: u16) {
        let next_base_fee = self.calculate_next_base_fee(gas_used);
        let old_base_fee = self.current_base_fee;

        self.current_base_fee = next_base_fee;
        self.last_block_gas_used = gas_used;
        self.block_number += 1;

        // Track history
        self.base_fee_history.push(next_base_fee);
        if self.base_fee_history.len() > self.max_history {
            self.base_fee_history.remove(0);
        }

        // Gross base-fee revenue for this block, then split via the dial.
        let gross = old_base_fee.saturating_mul(gas_used as u128);
        let burn_bps = base_fee_burn_bps.min(10_000) as u128;
        let burned = gross.saturating_mul(burn_bps) / 10_000;
        let to_treasury = gross.saturating_sub(burned);
        self.total_burned = self.total_burned.saturating_add(burned);
        self.total_to_treasury = self.total_to_treasury.saturating_add(to_treasury);

        debug!(
            "EIP-1559: Block {} finalized, gas_used={}/{}, base_fee: {} -> {} ({:.1}% change), gross={}, burned={}, treasury={}, burn_bps={}",
            self.block_number,
            gas_used,
            self.config.target_gas_per_block,
            old_base_fee,
            next_base_fee,
            if old_base_fee > 0 {
                ((next_base_fee as f64 - old_base_fee as f64) / old_base_fee as f64) * 100.0
            } else {
                0.0
            },
            gross,
            burned,
            to_treasury,
            base_fee_burn_bps,
        );
    }

    /// Calculate the effective gas price for a transaction.
    ///
    /// The effective price is `min(max_fee_per_gas, base_fee + max_priority_fee)`.
    /// The priority fee actually paid is `effective_price - base_fee`.
    pub fn effective_gas_price(&self, max_fee_per_gas: u128, max_priority_fee_per_gas: u128) -> EffectiveGasPrice {
        let base_fee = self.current_base_fee;

        if max_fee_per_gas < base_fee {
            // Transaction cannot afford the base fee — it should not be included
            return EffectiveGasPrice {
                effective_price: 0,
                base_fee,
                priority_fee: 0,
                is_valid: false,
            };
        }

        let effective_price = max_fee_per_gas.min(base_fee + max_priority_fee_per_gas);
        let priority_fee = effective_price.saturating_sub(base_fee);

        EffectiveGasPrice {
            effective_price,
            base_fee,
            priority_fee,
            is_valid: true,
        }
    }

    /// Get the current base fee
    pub fn base_fee(&self) -> u128 {
        self.current_base_fee
    }

    /// Get total TNZO burned through base fees
    pub fn total_burned(&self) -> u128 {
        self.total_burned
    }

    /// Account additional burn from an out-of-band source (e.g. the
    /// hot-state local fee market surcharge — Spec 6). The base fee and
    /// block window are not affected; only the cumulative `total_burned`
    /// counter advances. This keeps `eth_feeHistory` reporting one
    /// authoritative burn figure even though local-fee surcharges are
    /// computed off the EIP-1559 path.
    ///
    /// Defaults the local-fee burn share to 100%. For non-default splits,
    /// call [`add_external_revenue_with_split`].
    pub fn add_external_burn(&mut self, amount: u128) {
        self.add_external_revenue_with_split(amount, 10_000);
    }

    /// Account additional revenue from an out-of-band source (Spec 6 local
    /// fee market) and split it between burn and treasury per the adaptive
    /// burn dial's `local_fee_burn_bps`.
    pub fn add_external_revenue_with_split(&mut self, amount: u128, burn_bps: u16) {
        if amount == 0 {
            return;
        }
        let bps = burn_bps.min(10_000) as u128;
        let burn = amount.saturating_mul(bps) / 10_000;
        let treasury = amount.saturating_sub(burn);
        self.total_burned = self.total_burned.saturating_add(burn);
        self.total_to_treasury = self.total_to_treasury.saturating_add(treasury);
    }

    /// Get total TNZO routed to the network treasury via the adaptive burn
    /// dial. Zero while the dial is at genesis 100%-burn.
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
            FeeUrgency::Low => base / 10,        // 10% of base fee
            FeeUrgency::Medium => base / 5,       // 20% of base fee
            FeeUrgency::High => base / 2,         // 50% of base fee
            FeeUrgency::Urgent => base,           // 100% of base fee
        }
    }
}

impl Default for FeeMarket {
    fn default() -> Self {
        Self::new(Eip1559Config::default())
    }
}

/// Effective gas price breakdown for a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EffectiveGasPrice {
    /// Total effective gas price (what the user pays per gas unit)
    pub effective_price: u128,
    /// Base fee component (burned)
    pub base_fee: u128,
    /// Priority fee component (goes to validators)
    pub priority_fee: u128,
    /// Whether the transaction can afford the current base fee
    pub is_valid: bool,
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
    /// Total TNZO burned through base fees
    pub total_burned: u128,
    /// Total TNZO routed to the network treasury (adaptive-burn split).
    #[serde(default)]
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

    #[test]
    fn test_fee_market_creation() {
        let market = FeeMarket::default();
        assert_eq!(market.base_fee(), 1_000_000_000); // 1 Gwei
        assert_eq!(market.total_burned(), 0);
        assert_eq!(market.block_number(), 0);
    }

    #[test]
    fn test_base_fee_increase_on_full_block() {
        let market = FeeMarket::default();
        let target = market.config.target_gas_per_block;

        // Block at 100% capacity (2x target = max)
        let next_fee = market.calculate_next_base_fee(target * 2);
        assert!(next_fee > market.base_fee(), "Base fee should increase when block is full");

        // Max increase should be 12.5%
        let max_expected = market.base_fee() + market.base_fee() / 8;
        assert!(next_fee <= max_expected, "Increase should not exceed 12.5%");
    }

    #[test]
    fn test_base_fee_decrease_on_empty_block() {
        let market = FeeMarket::default();

        // Empty block (0 gas used)
        let next_fee = market.calculate_next_base_fee(0);
        assert!(next_fee < market.base_fee(), "Base fee should decrease on empty block");

        // Should not go below minimum
        assert!(next_fee >= market.config.min_base_fee);
    }

    #[test]
    fn test_base_fee_stable_at_target() {
        let market = FeeMarket::default();
        let target = market.config.target_gas_per_block;

        // Exactly at target — no change
        let next_fee = market.calculate_next_base_fee(target);
        assert_eq!(next_fee, market.base_fee());
    }

    #[test]
    fn test_on_block_finalized() {
        let mut market = FeeMarket::default();
        let initial_fee = market.base_fee();

        // Finalize a full block
        market.on_block_finalized(market.config.max_gas_per_block);

        assert!(market.base_fee() > initial_fee);
        assert_eq!(market.block_number(), 1);
        assert!(market.total_burned() > 0);
    }

    #[test]
    fn test_effective_gas_price() {
        let market = FeeMarket::default();
        let base_fee = market.base_fee(); // 1 Gwei

        // User willing to pay 3 Gwei max, 1 Gwei priority
        let result = market.effective_gas_price(3_000_000_000, 1_000_000_000);
        assert!(result.is_valid);
        assert_eq!(result.base_fee, base_fee);
        assert_eq!(result.effective_price, base_fee + 1_000_000_000);
        assert_eq!(result.priority_fee, 1_000_000_000);

        // User max fee below base fee — invalid
        let result = market.effective_gas_price(500_000_000, 100_000_000);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_burn_accumulation() {
        let mut market = FeeMarket::default();
        let target = market.config.target_gas_per_block;

        // Process several blocks
        for _ in 0..10 {
            market.on_block_finalized(target);
        }

        assert!(market.total_burned() > 0);
        assert_eq!(market.block_number(), 10);
    }

    #[test]
    fn test_fee_market_stats() {
        let mut market = FeeMarket::default();
        market.on_block_finalized(market.config.target_gas_per_block);

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

    #[test]
    fn test_on_block_finalized_with_split_50_50() {
        let mut market = FeeMarket::default();
        let initial_fee = market.base_fee();
        let target = market.config.target_gas_per_block;

        // 50/50 split: burn 50%, treasury 50%
        market.on_block_finalized_with_split(target, 5_000);

        let gross = initial_fee.saturating_mul(target as u128);
        let expected_burn = gross / 2;
        let expected_treasury = gross - expected_burn;

        assert_eq!(market.total_burned(), expected_burn);
        assert_eq!(market.total_to_treasury(), expected_treasury);
    }

    #[test]
    fn test_on_block_finalized_with_split_100_burn_back_compat() {
        // The plain `on_block_finalized` must delegate to the split variant
        // with burn_bps=10_000 (100% burn) for back-compat.
        let mut a = FeeMarket::default();
        let mut b = FeeMarket::default();
        let target = a.config.target_gas_per_block;

        a.on_block_finalized(target);
        b.on_block_finalized_with_split(target, 10_000);

        assert_eq!(a.total_burned(), b.total_burned());
        assert_eq!(a.total_to_treasury(), 0);
        assert_eq!(b.total_to_treasury(), 0);
    }

    #[test]
    fn test_on_block_finalized_with_split_clamps_above_10000() {
        let mut market = FeeMarket::default();
        let initial_fee = market.base_fee();
        let target = market.config.target_gas_per_block;

        // burn_bps > 10_000 must clamp to 10_000 (100% burn)
        market.on_block_finalized_with_split(target, 50_000);

        let gross = initial_fee.saturating_mul(target as u128);
        assert_eq!(market.total_burned(), gross);
        assert_eq!(market.total_to_treasury(), 0);
    }

    #[test]
    fn test_add_external_revenue_with_split_70_30() {
        let mut market = FeeMarket::default();

        // 70% burn, 30% treasury
        market.add_external_revenue_with_split(1_000_000, 7_000);

        assert_eq!(market.total_burned(), 700_000);
        assert_eq!(market.total_to_treasury(), 300_000);
    }

    #[test]
    fn test_add_external_burn_back_compat() {
        // The plain `add_external_burn` must delegate to the split variant
        // with burn_bps=10_000 (100% burn) for back-compat.
        let mut market = FeeMarket::default();
        market.add_external_burn(1_000_000);

        assert_eq!(market.total_burned(), 1_000_000);
        assert_eq!(market.total_to_treasury(), 0);
    }

    #[test]
    fn test_add_external_revenue_zero_is_noop() {
        let mut market = FeeMarket::default();
        market.add_external_revenue_with_split(0, 5_000);

        assert_eq!(market.total_burned(), 0);
        assert_eq!(market.total_to_treasury(), 0);
    }

    #[test]
    fn test_min_base_fee_floor() {
        let config = Eip1559Config {
            min_base_fee: 100_000_000, // 0.1 Gwei
            initial_base_fee: 100_000_000, // Start at minimum
            ..Default::default()
        };
        let market = FeeMarket::new(config);

        // Empty block should not go below minimum
        let next_fee = market.calculate_next_base_fee(0);
        assert!(next_fee >= 100_000_000);
    }
}
