//! Gas accounting and pricing

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::{error::Result, VmError};

/// Gas price information
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GasPrice {
    /// Base fee per gas (EIP-1559)
    pub base_fee: u128,

    /// Priority fee per gas (tip)
    pub priority_fee: u128,

    /// Maximum fee per gas
    pub max_fee: u128,
}

impl GasPrice {
    /// Create a new gas price
    pub fn new(base_fee: u128, priority_fee: u128) -> Self {
        Self {
            base_fee,
            priority_fee,
            max_fee: base_fee + priority_fee,
        }
    }

    /// Get effective gas price
    pub fn effective_price(&self) -> u128 {
        self.base_fee + self.priority_fee
    }

    /// Calculate total cost for gas amount
    pub fn calculate_cost(&self, gas: u64) -> u128 {
        self.effective_price() * gas as u128
    }
}

impl Default for GasPrice {
    fn default() -> Self {
        Self {
            base_fee: 1_000_000_000,      // 1 Gwei
            priority_fee: 1_000_000_000,  // 1 Gwei
            max_fee: 2_000_000_000,       // 2 Gwei
        }
    }
}

/// Gas oracle for dynamic pricing
pub struct GasOracle {
    /// Current gas price
    current_price: Arc<RwLock<GasPrice>>,

    /// Historical gas prices (for analysis)
    history: Arc<RwLock<Vec<GasPrice>>>,

    /// Maximum history size
    max_history: usize,

    /// Optional reference to EIP-1559 fee market for dynamic pricing
    fee_market: Arc<RwLock<Option<crate::eip1559::FeeMarket>>>,

    /// Hot-state local fee market (Spec 6). Tracks per-account contention
    /// over a rolling 64-block window and exposes a multiplier on top of
    /// the EIP-1559 base fee for hot accounts. Cheap to clone — internally
    /// `Arc`-backed.
    hot_state: crate::hot_state::HotStateMarket,

    /// Optional adaptive-burn dial (Spec 8). When wired, the oracle reads
    /// `base_fee_burn_bps` + `local_fee_burn_bps` on every block finalize
    /// and routes the gross fees through the configured split. Absent
    /// (single-node test harness paths), the oracle defaults to 100% burn.
    burn_rate: Arc<RwLock<Option<Arc<tenzro_token::adaptive_burn::BurnRateConfigManager>>>>,
}

impl GasOracle {
    /// Create a new gas oracle
    pub fn new() -> Self {
        Self {
            current_price: Arc::new(RwLock::new(GasPrice::default())),
            history: Arc::new(RwLock::new(Vec::new())),
            max_history: 1000,
            fee_market: Arc::new(RwLock::new(None)),
            hot_state: crate::hot_state::HotStateMarket::new(),
            burn_rate: Arc::new(RwLock::new(None)),
        }
    }

    /// Wire the adaptive-burn dial. The oracle will read the live
    /// `BurnRateConfig` on every block finalize and route the gross base
    /// fees through the configured burn-vs-treasury split. If unset (or
    /// set to `None`), the oracle defaults to 100% burn (genesis behavior).
    pub async fn set_burn_rate_manager(
        &self,
        manager: Arc<tenzro_token::adaptive_burn::BurnRateConfigManager>,
    ) {
        *self.burn_rate.write().await = Some(manager);
    }

    /// Borrow the hot-state local fee market. Used by the node event
    /// loop to record per-account contention samples after each block,
    /// and by the RPC layer to expose [`tenzro_getAccountContention`].
    pub fn hot_state(&self) -> &crate::hot_state::HotStateMarket {
        &self.hot_state
    }

    /// Compute the effective per-gas base fee for a transaction touching
    /// the given write set. Returns `(effective_base_fee, surcharge)` —
    /// the surcharge is the burn delta, accounted into the FeeMarket
    /// `total_burned` counter by the executor.
    ///
    /// Multi-account writes use the **max** surcharge (Solana convention),
    /// not the sum. An empty write set returns the unmodified base fee.
    pub async fn effective_base_fee(
        &self,
        write_set: &[&[u8]],
    ) -> (u128, u128) {
        let base = self
            .fee_market
            .read()
            .await
            .as_ref()
            .map(|m| m.base_fee())
            .unwrap_or(GasPrice::default().base_fee);
        self.hot_state.surcharge_multi(write_set, base)
    }

    /// Wire the oracle to an EIP-1559 fee market for dynamic pricing
    pub async fn set_fee_market(&self, fee_market: crate::eip1559::FeeMarket) {
        let mut fm = self.fee_market.write().await;
        *fm = Some(fee_market);
    }

    /// Advance the fee market after a block is finalized.
    ///
    /// This is the per-block hook the node event loop calls once the block
    /// has been persisted and the chain tip published. It pushes a new
    /// entry onto the base-fee history (read by `eth_feeHistory`) and
    /// adjusts the next-block base fee per EIP-1559 §3.
    ///
    /// When the adaptive-burn dial is wired, the gross base-fee revenue is
    /// split between burn and treasury per `BurnRateConfig.base_fee_burn_bps`.
    /// Otherwise defaults to 100% burn.
    ///
    /// No-op when the fee market is not configured.
    pub async fn on_block_finalized(&self, gas_used: u64) {
        let burn_bps = self.current_base_fee_burn_bps().await;
        let mut fm = self.fee_market.write().await;
        if let Some(market) = fm.as_mut() {
            market.on_block_finalized_with_split(gas_used, burn_bps);
        }
    }

    /// Read the current `base_fee_burn_bps` from the wired adaptive-burn
    /// manager, defaulting to 10_000 (100% burn) when unwired.
    async fn current_base_fee_burn_bps(&self) -> u16 {
        match self.burn_rate.read().await.as_ref() {
            Some(mgr) => mgr.config().base_fee_burn_bps,
            None => 10_000,
        }
    }

    /// Read the current `local_fee_burn_bps` from the wired adaptive-burn
    /// manager, defaulting to 10_000 (100% burn) when unwired.
    async fn current_local_fee_burn_bps(&self) -> u16 {
        match self.burn_rate.read().await.as_ref() {
            Some(mgr) => mgr.config().local_fee_burn_bps,
            None => 10_000,
        }
    }

    /// Record a block's per-account contention samples into the hot-state
    /// local fee market. Called from the node event loop alongside
    /// [`on_block_finalized`] once Block-STM has finished executing the
    /// block and aggregated reexec/write counts per address.
    pub fn record_block_contention(
        &self,
        samples: std::collections::HashMap<Vec<u8>, crate::hot_state::AccountSample>,
    ) {
        self.hot_state.record_block(samples);
    }

    /// Account a hot-state surcharge as additional revenue into the FeeMarket
    /// counters. The executor calls this after every tx whose
    /// `effective_base_fee` exceeded the global base fee, passing
    /// `surcharge_per_gas * gas_used`.
    ///
    /// The surcharge is split between `total_burned` and `total_to_treasury`
    /// per the wired adaptive-burn dial's `local_fee_burn_bps`. Defaults to
    /// 100% burn when the dial is unwired (genesis behavior).
    ///
    /// No-op when the FeeMarket is not configured.
    pub async fn account_hot_state_burn(&self, surcharge_total: u128) {
        if surcharge_total == 0 {
            return;
        }
        let local_burn_bps = self.current_local_fee_burn_bps().await;
        let mut fm = self.fee_market.write().await;
        if let Some(market) = fm.as_mut() {
            market.add_external_revenue_with_split(surcharge_total, local_burn_bps);
        }
    }

    /// Read a snapshot of the current fee market state.
    ///
    /// Returns `None` when the oracle is running on a static fallback
    /// (no FeeMarket wired). Used by `eth_feeHistory` to render the
    /// recent base-fee window without exposing internal mutable state.
    pub async fn fee_market_snapshot(&self) -> Option<crate::eip1559::FeeMarket> {
        self.fee_market.read().await.clone()
    }

    /// Get current gas price (from FeeMarket if available, otherwise static)
    pub async fn current_price(&self) -> GasPrice {
        // Try to get price from fee market first
        let fee_market = self.fee_market.read().await;
        if let Some(ref market) = *fee_market {
            let base_fee = market.base_fee();
            let priority_fee = market.suggest_priority_fee(crate::eip1559::FeeUrgency::Medium);
            return GasPrice::new(base_fee, priority_fee);
        }

        // Fall back to static price
        *self.current_price.read().await
    }

    /// Update gas price based on network load
    pub async fn update_price(&self, new_price: GasPrice) {
        let mut current = self.current_price.write().await;
        *current = new_price;

        // Add to history
        let mut history = self.history.write().await;
        history.push(new_price);

        // Trim history if needed
        if history.len() > self.max_history {
            history.remove(0);
        }
    }

    /// Calculate suggested gas price based on target confirmation time
    pub async fn suggest_price(&self, target_blocks: u64) -> GasPrice {
        // Try to get price from fee market first
        let fee_market = self.fee_market.read().await;
        if let Some(ref market) = *fee_market {
            let base_fee = market.base_fee();
            let urgency = match target_blocks {
                1 => crate::eip1559::FeeUrgency::Urgent,
                2..=5 => crate::eip1559::FeeUrgency::High,
                6..=10 => crate::eip1559::FeeUrgency::Medium,
                _ => crate::eip1559::FeeUrgency::Low,
            };
            let priority_fee = market.suggest_priority_fee(urgency);
            return GasPrice::new(base_fee, priority_fee);
        }

        // Fall back to static multiplier approach
        let current = self.current_price().await;

        // Apply multiplier based on urgency
        let multiplier = match target_blocks {
            1 => 2.0,      // Next block - high priority
            2..=5 => 1.5,  // Within 5 blocks - medium priority
            _ => 1.0,      // No rush - normal priority
        };

        GasPrice::new(
            (current.base_fee as f64 * multiplier) as u128,
            (current.priority_fee as f64 * multiplier) as u128,
        )
    }

    /// Get historical average gas price
    pub async fn historical_average(&self, num_blocks: usize) -> Option<GasPrice> {
        let history = self.history.read().await;

        if history.is_empty() {
            return None;
        }

        let count = num_blocks.min(history.len());
        let recent = &history[history.len() - count..];

        let total_base: u128 = recent.iter().map(|p| p.base_fee).sum();
        let total_priority: u128 = recent.iter().map(|p| p.priority_fee).sum();

        Some(GasPrice::new(
            total_base / count as u128,
            total_priority / count as u128,
        ))
    }
}

impl Default for GasOracle {
    fn default() -> Self {
        Self::new()
    }
}

/// Gas estimator for transactions
pub struct GasEstimator;

impl GasEstimator {
    /// Estimate gas for a simple transfer
    pub fn estimate_transfer() -> u64 {
        21_000 // Standard Ethereum transfer cost
    }

    /// Estimate gas for contract deployment
    pub fn estimate_deployment(code_size: usize) -> u64 {
        // Base deployment cost + cost per byte
        let base_cost = 32_000u64;
        let per_byte_cost = 200u64;

        base_cost + (code_size as u64 * per_byte_cost)
    }

    /// Estimate gas for contract call
    pub fn estimate_call(data_size: usize, complex: bool) -> u64 {
        // Base call cost
        let base_cost = 21_000u64;

        // Data cost (non-zero bytes = 16 gas, zero bytes = 4 gas)
        // Approximate as 10 gas per byte on average
        let data_cost = data_size as u64 * 10;

        // Complexity multiplier for state changes, etc.
        let complexity_cost = if complex { 50_000 } else { 5_000 };

        base_cost + data_cost + complexity_cost
    }

    /// Add safety margin to estimate
    pub fn with_margin(estimate: u64, margin_percent: u64) -> u64 {
        estimate + (estimate * margin_percent / 100)
    }
}

/// Gas meter for tracking gas usage during execution
#[derive(Debug, Clone)]
pub struct GasMeter {
    /// Gas limit
    limit: u64,

    /// Gas used so far
    used: u64,

    /// Gas refunded
    refunded: u64,
}

impl GasMeter {
    /// Create a new gas meter
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            used: 0,
            refunded: 0,
        }
    }

    /// Consume gas
    pub fn consume(&mut self, amount: u64) -> Result<()> {
        let new_used = self.used.checked_add(amount)
            .ok_or_else(|| VmError::Internal("Gas overflow".to_string()))?;

        if new_used > self.limit {
            return Err(VmError::OutOfGas);
        }

        self.used = new_used;
        Ok(())
    }

    /// Refund gas
    pub fn refund(&mut self, amount: u64) {
        self.refunded = self.refunded.saturating_add(amount);
    }

    /// Get remaining gas
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    /// Get used gas
    pub fn used(&self) -> u64 {
        self.used
    }

    /// Get refunded gas
    pub fn refunded(&self) -> u64 {
        self.refunded
    }

    /// Get final gas used (after refunds, capped per EIP-3529)
    ///
    /// Per EIP-3529, gas refunds are capped at `used_gas / 5` (20% of gas used).
    /// This prevents refund exploits where users could get excessive refunds.
    pub fn final_used(&self) -> u64 {
        let max_refund = self.used / 5; // EIP-3529: refund capped at 20% of used gas
        let effective_refund = self.refunded.min(max_refund);
        self.used.saturating_sub(effective_refund)
    }

    /// Check if out of gas
    pub fn is_out_of_gas(&self) -> bool {
        self.used >= self.limit
    }
}

/// EVM gas costs (based on Ethereum)
pub mod evm_gas_costs {
    /// Base transaction cost
    pub const TRANSACTION: u64 = 21_000;

    /// Cost per zero byte of transaction data
    pub const TXDATA_ZERO: u64 = 4;

    /// Cost per non-zero byte of transaction data
    pub const TXDATA_NONZERO: u64 = 16;

    /// Cost of creating a contract
    pub const CREATE: u64 = 32_000;

    /// Cost per byte of contract code
    pub const CODE_DEPOSIT: u64 = 200;

    /// Cost of SLOAD opcode
    pub const SLOAD: u64 = 2_100;

    /// Cost of SSTORE (when setting non-zero value)
    pub const SSTORE_SET: u64 = 20_000;

    /// Cost of SSTORE (when updating non-zero value)
    pub const SSTORE_RESET: u64 = 5_000;

    /// Cost of CALL opcode
    pub const CALL: u64 = 700;

    /// Cost of LOG0 opcode
    pub const LOG: u64 = 375;

    /// Cost per topic in LOG
    pub const LOG_TOPIC: u64 = 375;

    /// Cost per byte of log data
    pub const LOG_DATA: u64 = 8;

    /// Memory expansion cost
    pub const MEMORY: u64 = 3;
}

/// SVM gas costs (Solana compute units)
pub mod svm_gas_costs {
    /// Base transaction cost
    pub const TRANSACTION: u64 = 5_000;

    /// Cost per signature verification
    pub const SIGNATURE: u64 = 1_000;

    /// Cost per byte of transaction data
    pub const DATA_BYTE: u64 = 1;

    /// Cost of account creation
    pub const CREATE_ACCOUNT: u64 = 10_000;

    /// Cost per BPF instruction
    pub const INSTRUCTION: u64 = 1;

    /// Maximum compute units per transaction
    pub const MAX_COMPUTE_UNITS: u64 = 1_400_000;
}

/// Gas normalizer for consistent metering across VMs (MEDIUM #122)
///
/// Different VMs use incompatible units:
/// - **EVM:** Gas (max 30,000,000 per block)
/// - **SVM:** Compute Units (max 1,400,000 per transaction)
/// - **DAML:** Fixed estimates (50k–200k, no real metering)
///
/// The normalizer converts all units to a common "Tenzro Gas" unit
/// (equivalent to EVM gas) so users see a unified gas cost regardless
/// of which VM executed their transaction.
///
/// Conversion ratios are derived from the maximum capacities:
/// - EVM max gas per block: 30,000,000
/// - SVM max compute units per tx: 1,400,000
/// - Ratio: ~21.4 EVM gas ≈ 1 SVM compute unit
///
/// We use integer arithmetic with a scaling factor to avoid FP imprecision.
pub mod gas_normalizer {
    use super::*;
    use crate::VmType;

    /// Scaling factor for integer arithmetic (1000 for 3 decimal places)
    const SCALE: u64 = 1000;

    /// EVM gas per SVM compute unit (scaled by SCALE).
    /// 30_000_000 / 1_400_000 ≈ 21.428 → 21_429 (rounded up)
    const EVM_GAS_PER_SVM_CU_SCALED: u64 = 21_429;

    /// DAML fixed cost → EVM gas multiplier (scaled by SCALE).
    /// DAML units are already in a gas-like range (50k–200k),
    /// so we use a 1:1 mapping.
    const EVM_GAS_PER_DAML_UNIT_SCALED: u64 = 1_000; // 1:1

    /// Converts native VM units to normalized Tenzro Gas (EVM-equivalent).
    pub fn to_tenzro_gas(native_units: u64, vm_type: VmType) -> u64 {
        match vm_type {
            VmType::Evm => native_units,
            VmType::Svm => {
                // SVM compute units → EVM gas
                // native_units * (EVM_GAS_PER_SVM_CU_SCALED / SCALE)
                let scaled = native_units as u128 * EVM_GAS_PER_SVM_CU_SCALED as u128;
                (scaled / SCALE as u128) as u64
            }
            VmType::Daml => {
                // DAML fixed estimates are already gas-like
                let scaled = native_units as u128 * EVM_GAS_PER_DAML_UNIT_SCALED as u128;
                (scaled / SCALE as u128) as u64
            }
            VmType::Tenzro => {
                // Native ops use EVM-equivalent gas
                native_units
            }
        }
    }

    /// Converts normalized Tenzro Gas back to native VM units.
    pub fn from_tenzro_gas(tenzro_gas: u64, vm_type: VmType) -> u64 {
        match vm_type {
            VmType::Evm => tenzro_gas,
            VmType::Svm => {
                // EVM gas → SVM compute units
                let scaled = tenzro_gas as u128 * SCALE as u128;
                (scaled / EVM_GAS_PER_SVM_CU_SCALED as u128) as u64
            }
            VmType::Daml => {
                let scaled = tenzro_gas as u128 * SCALE as u128;
                (scaled / EVM_GAS_PER_DAML_UNIT_SCALED as u128) as u64
            }
            VmType::Tenzro => tenzro_gas,
        }
    }

    /// Returns the maximum normalized gas for a given VM type.
    pub fn max_gas(vm_type: VmType) -> u64 {
        match vm_type {
            VmType::Evm => 30_000_000,
            VmType::Svm => to_tenzro_gas(svm_gas_costs::MAX_COMPUTE_UNITS, VmType::Svm),
            VmType::Daml => 200_000, // DAML max fixed estimate
            VmType::Tenzro => 30_000_000,
        }
    }

    /// Returns the native unit name for a VM type.
    pub fn unit_name(vm_type: VmType) -> &'static str {
        match vm_type {
            VmType::Evm => "gas",
            VmType::Svm => "compute units",
            VmType::Daml => "gas (estimated)",
            VmType::Tenzro => "gas",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gas_price() {
        let price = GasPrice::new(1_000_000_000, 500_000_000);
        assert_eq!(price.effective_price(), 1_500_000_000);
        assert_eq!(price.calculate_cost(21_000), 31_500_000_000_000);
    }

    #[test]
    fn test_gas_meter() {
        let mut meter = GasMeter::new(100_000);

        assert!(meter.consume(50_000).is_ok());
        assert_eq!(meter.used(), 50_000);
        assert_eq!(meter.remaining(), 50_000);

        assert!(meter.consume(60_000).is_err()); // Would exceed limit

        meter.refund(10_000);
        assert_eq!(meter.refunded(), 10_000);
        // EIP-3529: refund capped at 20% of used gas (50000 * 0.2 = 10000)
        // effective_refund = min(10000, 10000) = 10000
        assert_eq!(meter.final_used(), 40_000);

        // Test refund cap: even with large refund, capped at 20% of used
        let mut meter2 = GasMeter::new(100_000);
        meter2.consume(50_000).unwrap();
        meter2.refund(30_000); // Request 30k refund
        assert_eq!(meter2.refunded(), 30_000);
        // But only 20% of 50000 = 10000 is applied
        assert_eq!(meter2.final_used(), 40_000);
    }

    #[tokio::test]
    async fn test_gas_oracle() {
        let oracle = GasOracle::new();

        let current = oracle.current_price().await;
        assert_eq!(current.base_fee, 1_000_000_000);

        let new_price = GasPrice::new(2_000_000_000, 1_000_000_000);
        oracle.update_price(new_price).await;

        let updated = oracle.current_price().await;
        assert_eq!(updated.base_fee, 2_000_000_000);
    }

    #[test]
    fn test_gas_normalizer_evm_identity() {
        use gas_normalizer::*;
        use crate::VmType;

        // EVM gas should pass through unchanged
        assert_eq!(to_tenzro_gas(21_000, VmType::Evm), 21_000);
        assert_eq!(from_tenzro_gas(21_000, VmType::Evm), 21_000);
    }

    #[test]
    fn test_gas_normalizer_svm_conversion() {
        use gas_normalizer::*;
        use crate::VmType;

        // SVM compute units → EVM gas should scale up by ~21.4x
        let svm_units = 100_000u64;
        let tenzro_gas = to_tenzro_gas(svm_units, VmType::Svm);
        // 100_000 * 21.429 ≈ 2_142_900
        assert!(tenzro_gas > 2_000_000);
        assert!(tenzro_gas < 2_200_000);

        // Round-trip should be approximately equal (within integer rounding)
        let back = from_tenzro_gas(tenzro_gas, VmType::Svm);
        assert!((back as i64 - svm_units as i64).unsigned_abs() <= 1);
    }

    #[test]
    fn test_gas_normalizer_svm_max() {
        use gas_normalizer::*;
        use crate::VmType;

        // SVM max (1.4M compute units) should map to EVM max (30M gas)
        let svm_max = to_tenzro_gas(svm_gas_costs::MAX_COMPUTE_UNITS, VmType::Svm);
        assert!(svm_max >= 29_000_000);
        assert!(svm_max <= 31_000_000);
    }

    #[test]
    fn test_gas_normalizer_daml_identity() {
        use gas_normalizer::*;
        use crate::VmType;

        // DAML uses 1:1 mapping
        assert_eq!(to_tenzro_gas(100_000, VmType::Daml), 100_000);
        assert_eq!(from_tenzro_gas(100_000, VmType::Daml), 100_000);
    }

    #[test]
    fn test_gas_normalizer_unit_names() {
        use gas_normalizer::*;
        use crate::VmType;

        assert_eq!(unit_name(VmType::Evm), "gas");
        assert_eq!(unit_name(VmType::Svm), "compute units");
        assert_eq!(unit_name(VmType::Daml), "gas (estimated)");
        assert_eq!(unit_name(VmType::Tenzro), "gas");
    }

    #[test]
    fn test_gas_normalizer_max_gas() {
        use gas_normalizer::*;
        use crate::VmType;

        assert_eq!(max_gas(VmType::Evm), 30_000_000);
        assert_eq!(max_gas(VmType::Daml), 200_000);
        // SVM max should be close to 30M (derived from 1.4M CU * 21.4)
        assert!(max_gas(VmType::Svm) >= 29_000_000);
    }
}
