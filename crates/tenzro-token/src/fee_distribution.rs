//! Fee processing and distribution
//!
//! This module processes incoming fees from settlements, transactions,
//! and bridge operations, then distributes them according to the configured splits.

use crate::error::{Result, TokenError};
use crate::treasury::FeeDistributionConfig;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::Timestamp;
use tracing::{debug, info};

/// Fee source type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FeeSource {
    /// Transaction fee
    Transaction,
    /// Settlement fee
    Settlement,
    /// Bridge operation fee
    Bridge,
    /// Model inference fee
    ModelInference,
    /// Storage fee
    Storage,
    /// Other fee source
    Other,
}

/// Fee record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeRecord {
    /// Fee ID
    pub fee_id: String,
    /// Asset ID
    pub asset_id: AssetId,
    /// Total fee amount
    pub amount: u128,
    /// Fee source
    pub source: FeeSource,
    /// Treasury share
    pub treasury_share: u128,
    /// Burn share
    pub burn_share: u128,
    /// Staker share
    pub staker_share: u128,
    /// Timestamp
    pub timestamp: Timestamp,
}

impl FeeRecord {
    /// Creates a new fee record
    pub fn new(
        asset_id: AssetId,
        amount: u128,
        source: FeeSource,
        treasury_share: u128,
        burn_share: u128,
        staker_share: u128,
    ) -> Self {
        Self {
            fee_id: uuid::Uuid::new_v4().to_string(),
            asset_id,
            amount,
            source,
            treasury_share,
            burn_share,
            staker_share,
            timestamp: Timestamp::now(),
        }
    }
}

/// Fee statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[derive(Default)]
pub struct FeeStats {
    /// Total fees collected per asset
    pub total_collected: HashMap<AssetId, u128>,
    /// Total fees by source
    pub by_source: HashMap<FeeSource, u128>,
    /// Total to treasury
    pub total_to_treasury: u128,
    /// Total burned
    pub total_burned: u128,
    /// Total to stakers
    pub total_to_stakers: u128,
    /// Fee count
    pub fee_count: u64,
}


/// Distribution history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributionHistory {
    /// Time period start
    pub period_start: Timestamp,
    /// Time period end
    pub period_end: Timestamp,
    /// Total fees in period
    pub total_fees: u128,
    /// Fees per asset
    pub fees_by_asset: HashMap<AssetId, u128>,
    /// Treasury share
    pub treasury_share: u128,
    /// Burn share
    pub burn_share: u128,
    /// Staker share
    pub staker_share: u128,
}

impl DistributionHistory {
    /// Creates a new distribution history entry
    pub fn new(period_start: Timestamp, period_end: Timestamp) -> Self {
        Self {
            period_start,
            period_end,
            total_fees: 0,
            fees_by_asset: HashMap::new(),
            treasury_share: 0,
            burn_share: 0,
            staker_share: 0,
        }
    }

    /// Adds a fee record to the history
    pub fn add_fee(&mut self, record: &FeeRecord) {
        self.total_fees = self.total_fees.saturating_add(record.amount);

        let asset_total = self.fees_by_asset.get(&record.asset_id).copied().unwrap_or(0);
        self.fees_by_asset.insert(
            record.asset_id.clone(),
            asset_total.saturating_add(record.amount),
        );

        self.treasury_share = self.treasury_share.saturating_add(record.treasury_share);
        self.burn_share = self.burn_share.saturating_add(record.burn_share);
        self.staker_share = self.staker_share.saturating_add(record.staker_share);
    }
}

/// Fee processor
///
/// Processes incoming fees and distributes them according to configuration.
#[derive(Debug)]
pub struct FeeProcessor {
    /// Fee distribution configuration
    config: parking_lot::RwLock<FeeDistributionConfig>,
    /// Fee records (FeeId -> FeeRecord)
    fee_records: DashMap<String, FeeRecord>,
    /// Fee statistics
    stats: parking_lot::RwLock<FeeStats>,
    /// Distribution history (Period -> History)
    history: DashMap<String, DistributionHistory>,
    /// Current history period
    current_period: parking_lot::RwLock<Option<String>>,
}

impl FeeProcessor {
    /// Creates a new fee processor
    pub fn new() -> Self {
        Self {
            config: parking_lot::RwLock::new(FeeDistributionConfig::default()),
            fee_records: DashMap::new(),
            stats: parking_lot::RwLock::new(FeeStats::default()),
            history: DashMap::new(),
            current_period: parking_lot::RwLock::new(None),
        }
    }

    /// Processes a fee
    ///
    /// # Arguments
    ///
    /// * `asset_id` - Asset of the fee
    /// * `amount` - Fee amount
    /// * `source` - Source of the fee
    ///
    /// Returns the fee record
    pub fn process_fee(&self, asset_id: AssetId, amount: u128, source: FeeSource) -> Result<FeeRecord> {
        if amount == 0 {
            return Err(TokenError::InvalidAmount("Fee amount must be greater than zero".to_string()));
        }

        // Calculate distribution
        let config = self.config.read();
        let distribution = config.calculate_distribution(amount);
        drop(config);

        // Create fee record
        let record = FeeRecord::new(
            asset_id.clone(),
            amount,
            source,
            distribution.treasury_amount,
            distribution.burn_amount,
            distribution.staker_amount,
        );

        let fee_id = record.fee_id.clone();

        // Update statistics
        let mut stats = self.stats.write();

        // Update total collected
        let asset_total = stats.total_collected.get(&asset_id).copied().unwrap_or(0);
        stats.total_collected.insert(
            asset_id.clone(),
            asset_total.checked_add(amount)
                .ok_or_else(|| TokenError::ArithmeticOverflow {
                    operation: "fee total collected".to_string(),
                })?,
        );

        // Update by source
        let source_total = stats.by_source.get(&source).copied().unwrap_or(0);
        stats.by_source.insert(
            source,
            source_total.checked_add(amount)
                .ok_or_else(|| TokenError::ArithmeticOverflow {
                    operation: "fee by source".to_string(),
                })?,
        );

        // Update distribution totals
        stats.total_to_treasury = stats.total_to_treasury.checked_add(distribution.treasury_amount)
            .ok_or_else(|| TokenError::ArithmeticOverflow {
                operation: "fee total to treasury".to_string(),
            })?;
        stats.total_burned = stats.total_burned.checked_add(distribution.burn_amount)
            .ok_or_else(|| TokenError::ArithmeticOverflow {
                operation: "fee total burned".to_string(),
            })?;
        stats.total_to_stakers = stats.total_to_stakers.checked_add(distribution.staker_amount)
            .ok_or_else(|| TokenError::ArithmeticOverflow {
                operation: "fee total to stakers".to_string(),
            })?;
        stats.fee_count += 1;

        drop(stats);

        // Add to current history period
        self.add_to_history(&record);

        // Store fee record
        self.fee_records.insert(fee_id.clone(), record.clone());

        debug!(
            "Processed fee: {} of {} (treasury: {}, burn: {}, stakers: {})",
            amount, asset_id.as_str(),
            distribution.treasury_amount,
            distribution.burn_amount,
            distribution.staker_amount
        );

        Ok(record)
    }

    /// Returns fee statistics
    pub fn get_fee_stats(&self) -> FeeStats {
        self.stats.read().clone()
    }

    /// Returns distribution history for a period
    pub fn get_distribution_history(&self, period: &str) -> Option<DistributionHistory> {
        self.history.get(period).map(|h| h.clone())
    }

    /// Returns all distribution history
    pub fn get_all_history(&self) -> Vec<(String, DistributionHistory)> {
        self.history
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().clone()))
            .collect()
    }

    /// Starts a new history period
    pub fn start_new_period(&self, period_id: String, start_time: Timestamp) {
        // Close current period if exists
        if let Some(current) = self.current_period.read().as_ref() {
            if let Some(mut history) = self.history.get_mut(current) {
                history.period_end = Timestamp::now();
            }
        }

        // Create new period
        let history = DistributionHistory::new(start_time, Timestamp::now());
        self.history.insert(period_id.clone(), history);
        *self.current_period.write() = Some(period_id.clone());

        info!("Started new distribution period: {}", period_id);
    }

    /// Updates the fee distribution configuration
    pub fn update_config(&self, config: FeeDistributionConfig) -> Result<()> {
        config.validate()?;
        *self.config.write() = config;
        info!("Updated fee distribution configuration");
        Ok(())
    }

    /// Returns the current configuration
    pub fn get_config(&self) -> FeeDistributionConfig {
        self.config.read().clone()
    }

    /// Adds a fee record to the current history period
    fn add_to_history(&self, record: &FeeRecord) {
        let current_period = self.current_period.read().clone();

        if let Some(period_id) = current_period {
            if let Some(mut history) = self.history.get_mut(&period_id) {
                history.add_fee(record);
            }
        } else {
            // Auto-create a default period if none exists
            drop(current_period);
            let period_id = format!("period_{}", Timestamp::now().as_millis());
            self.start_new_period(period_id.clone(), Timestamp::now());

            if let Some(mut history) = self.history.get_mut(&period_id) {
                history.add_fee(record);
            }
        }
    }

    /// Returns a fee record by ID
    pub fn get_fee_record(&self, fee_id: &str) -> Option<FeeRecord> {
        self.fee_records.get(fee_id).map(|r| r.clone())
    }

    /// Returns all fee records
    pub fn get_all_fee_records(&self) -> Vec<FeeRecord> {
        self.fee_records
            .iter()
            .map(|entry| entry.value().clone())
            .collect()
    }
}

impl Default for FeeProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_fee() {
        let processor = FeeProcessor::new();
        let asset_id = AssetId::tnzo();

        let record = processor.process_fee(asset_id.clone(), 10000, FeeSource::Transaction).unwrap();

        assert_eq!(record.amount, 10000);
        assert_eq!(record.treasury_share, 4000); // 40%
        assert_eq!(record.burn_share, 3000); // 30%
        assert_eq!(record.staker_share, 3000); // 30%

        let stats = processor.get_fee_stats();
        assert_eq!(stats.fee_count, 1);
        assert_eq!(stats.total_to_treasury, 4000);
    }

    #[test]
    fn test_fee_stats() {
        let processor = FeeProcessor::new();
        let asset_id = AssetId::tnzo();

        processor.process_fee(asset_id.clone(), 10000, FeeSource::Transaction).unwrap();
        processor.process_fee(asset_id.clone(), 5000, FeeSource::Settlement).unwrap();

        let stats = processor.get_fee_stats();
        assert_eq!(stats.fee_count, 2);
        assert_eq!(*stats.total_collected.get(&asset_id).unwrap(), 15000);
    }

    #[test]
    fn test_history_periods() {
        let processor = FeeProcessor::new();
        let asset_id = AssetId::tnzo();

        processor.start_new_period("period1".to_string(), Timestamp::now());
        processor.process_fee(asset_id.clone(), 10000, FeeSource::Transaction).unwrap();

        let history = processor.get_distribution_history("period1").unwrap();
        assert_eq!(history.total_fees, 10000);
    }
}
