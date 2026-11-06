//! Fee processing and distribution
//!
//! This module processes incoming fees from settlements, transactions,
//! and bridge operations, then distributes them according to the configured splits.
//!
//! Storage layout (`CF_TOKENS`):
//!
//! | Key | Value |
//! |---|---|
//! | `fee_stats` | cumulative [`FeeStats`] |
//! | `fee_config` | active [`FeeDistributionConfig`] |
//! | `fee_current_period` | id of the open history period |
//! | `fee_period:<id>` | one [`DistributionHistory`] per period |
//! | `fee_recent` | bounded window of the most recent [`FeeRecord`]s |

use crate::error::{Result, TokenError};
use crate::treasury::FeeDistributionConfig;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tenzro_storage::{CF_TOKENS, KvStore, WriteOp};
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::Timestamp;
use tracing::{debug, info, warn};

/// Cumulative statistics across every period.
pub const FEE_STATS_KEY: &[u8] = b"fee_stats";
/// Active distribution split.
pub const FEE_CONFIG_KEY: &[u8] = b"fee_config";
/// Id of the period currently accepting fees.
pub const FEE_CURRENT_PERIOD_KEY: &[u8] = b"fee_current_period";
/// One `DistributionHistory` per period.
pub const FEE_PERIOD_PREFIX: &[u8] = b"fee_period:";
/// The recent-record window.
pub const FEE_RECENT_KEY: &[u8] = b"fee_recent";

/// How many individual fee records stay queryable.
///
/// Gas fees accrue on every block, so the record list is a window rather
/// than an archive — the cumulative truth lives in [`FeeStats`] and the
/// per-period [`DistributionHistory`], both of which are unbounded.
pub const MAX_RECENT_FEE_RECORDS: usize = 1024;

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
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

        let asset_total = self
            .fees_by_asset
            .get(&record.asset_id)
            .copied()
            .unwrap_or(0);
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
pub struct FeeProcessor {
    /// Fee distribution configuration
    config: parking_lot::RwLock<FeeDistributionConfig>,
    /// Most recent fee records, newest last, capped at
    /// [`MAX_RECENT_FEE_RECORDS`]
    recent: parking_lot::RwLock<VecDeque<FeeRecord>>,
    /// Fee statistics
    stats: parking_lot::RwLock<FeeStats>,
    /// Distribution history (Period -> History)
    history: DashMap<String, DistributionHistory>,
    /// Current history period
    current_period: parking_lot::RwLock<Option<String>>,
    /// Write-through target; `None` for stand-alone instances
    storage: Option<Arc<dyn KvStore>>,
}

impl std::fmt::Debug for FeeProcessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeeProcessor")
            .field("config", &self.config)
            .field("recent", &self.recent.read().len())
            .field("stats", &self.stats)
            .field("history", &self.history.len())
            .field("current_period", &self.current_period)
            .field("storage", &self.storage.as_ref().map(|_| "Some(..)"))
            .finish()
    }
}

impl FeeProcessor {
    /// Creates a new fee processor
    pub fn new() -> Self {
        Self {
            config: parking_lot::RwLock::new(FeeDistributionConfig::default()),
            recent: parking_lot::RwLock::new(VecDeque::new()),
            stats: parking_lot::RwLock::new(FeeStats::default()),
            history: DashMap::new(),
            current_period: parking_lot::RwLock::new(None),
            storage: None,
        }
    }

    /// Creates a fee processor with RocksDB write-through, restoring the
    /// cumulative statistics, the configured split, every period's history,
    /// and the recent-record window from `CF_TOKENS`.
    ///
    /// Unreadable records are dropped and deleted rather than failing the
    /// boot — a corrupt period entry must not stop the node from collecting
    /// fees, and the cumulative counters live under their own key.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self> {
        let config = read_json(storage.as_ref(), FEE_CONFIG_KEY)?
            .unwrap_or_else(FeeDistributionConfig::default);
        let stats: FeeStats = read_json(storage.as_ref(), FEE_STATS_KEY)?.unwrap_or_default();
        let recent: VecDeque<FeeRecord> =
            read_json(storage.as_ref(), FEE_RECENT_KEY)?.unwrap_or_default();
        let current_period: Option<String> = storage
            .get(CF_TOKENS, FEE_CURRENT_PERIOD_KEY)?
            .and_then(|bytes| String::from_utf8(bytes).ok());

        let history: DashMap<String, DistributionHistory> = DashMap::new();
        let mut drops: Vec<WriteOp> = Vec::new();
        for key in storage.get_keys_with_prefix(CF_TOKENS, FEE_PERIOD_PREFIX)? {
            let parsed = key
                .strip_prefix(FEE_PERIOD_PREFIX)
                .and_then(|id| String::from_utf8(id.to_vec()).ok())
                .zip(
                    storage
                        .get(CF_TOKENS, &key)?
                        .and_then(|b| serde_json::from_slice::<DistributionHistory>(&b).ok()),
                );
            match parsed {
                Some((period_id, entry)) => {
                    history.insert(period_id, entry);
                }
                None => {
                    warn!(
                        key = %String::from_utf8_lossy(&key),
                        "dropping unreadable fee distribution period"
                    );
                    drops.push(WriteOp::Delete {
                        cf: CF_TOKENS.to_string(),
                        key,
                    });
                }
            }
        }
        if !drops.is_empty() {
            storage.write_batch_sync(drops)?;
        }

        info!(
            periods = history.len(),
            fee_count = stats.fee_count,
            recent = recent.len(),
            "fee processor hydrated"
        );

        Ok(Self {
            config: parking_lot::RwLock::new(config),
            recent: parking_lot::RwLock::new(recent),
            stats: parking_lot::RwLock::new(stats),
            history,
            current_period: parking_lot::RwLock::new(current_period),
            storage: Some(storage),
        })
    }

    /// Writes a batch through to storage, if any is attached.
    fn persist(&self, ops: Vec<WriteOp>) -> Result<()> {
        if let Some(storage) = &self.storage {
            storage.write_batch_sync(ops)?;
        }
        Ok(())
    }

    /// Builds the write op for a single period's history.
    fn period_op(period_id: &str, entry: &DistributionHistory) -> Result<WriteOp> {
        Ok(WriteOp::Put {
            cf: CF_TOKENS.to_string(),
            key: period_key(period_id),
            value: serde_json::to_vec(entry)
                .map_err(|e| TokenError::StorageError(e.to_string()))?,
        })
    }

    /// Records a fee whose split is already decided.
    ///
    /// The shares are taken verbatim rather than re-derived from
    /// [`Self::get_config`], because the layer that moved the tokens is the
    /// authority on where they went. Gas fees, for instance, are split by the
    /// fee market's adaptive burn dial before they reach the ledger; deriving
    /// a second split here would make the statistics disagree with balances.
    ///
    /// Callers whose fees follow the configured split should compute it with
    /// `get_config().calculate_distribution(amount)` and pass the result.
    ///
    /// Returns the fee record.
    pub fn process_fee(
        &self,
        asset_id: AssetId,
        source: FeeSource,
        treasury_share: u128,
        burn_share: u128,
        staker_share: u128,
    ) -> Result<FeeRecord> {
        let amount = treasury_share
            .checked_add(burn_share)
            .and_then(|v| v.checked_add(staker_share))
            .ok_or_else(|| TokenError::ArithmeticOverflow {
                operation: "fee amount".to_string(),
            })?;
        if amount == 0 {
            return Err(TokenError::InvalidAmount(
                "Fee amount must be greater than zero".to_string(),
            ));
        }

        // Create fee record
        let record = FeeRecord::new(
            asset_id.clone(),
            amount,
            source,
            treasury_share,
            burn_share,
            staker_share,
        );

        // Update statistics
        let mut stats = self.stats.write();

        // Update total collected
        let asset_total = stats.total_collected.get(&asset_id).copied().unwrap_or(0);
        stats.total_collected.insert(
            asset_id.clone(),
            asset_total
                .checked_add(amount)
                .ok_or_else(|| TokenError::ArithmeticOverflow {
                    operation: "fee total collected".to_string(),
                })?,
        );

        // Update by source
        let source_total = stats.by_source.get(&source).copied().unwrap_or(0);
        stats.by_source.insert(
            source,
            source_total
                .checked_add(amount)
                .ok_or_else(|| TokenError::ArithmeticOverflow {
                    operation: "fee by source".to_string(),
                })?,
        );

        // Update distribution totals
        stats.total_to_treasury = stats
            .total_to_treasury
            .checked_add(treasury_share)
            .ok_or_else(|| TokenError::ArithmeticOverflow {
                operation: "fee total to treasury".to_string(),
            })?;
        stats.total_burned = stats.total_burned.checked_add(burn_share).ok_or_else(|| {
            TokenError::ArithmeticOverflow {
                operation: "fee total burned".to_string(),
            }
        })?;
        stats.total_to_stakers = stats
            .total_to_stakers
            .checked_add(staker_share)
            .ok_or_else(|| TokenError::ArithmeticOverflow {
                operation: "fee total to stakers".to_string(),
            })?;
        stats.fee_count += 1;

        let stats_op = WriteOp::Put {
            cf: CF_TOKENS.to_string(),
            key: FEE_STATS_KEY.to_vec(),
            value: serde_json::to_vec(&*stats)
                .map_err(|e| TokenError::StorageError(e.to_string()))?,
        };
        drop(stats);

        // Add to current history period
        let mut ops = self.add_to_history(&record)?;
        ops.push(stats_op);

        // Store fee record in the recent window, evicting the oldest.
        let mut recent = self.recent.write();
        recent.push_back(record.clone());
        while recent.len() > MAX_RECENT_FEE_RECORDS {
            recent.pop_front();
        }
        ops.push(WriteOp::Put {
            cf: CF_TOKENS.to_string(),
            key: FEE_RECENT_KEY.to_vec(),
            value: serde_json::to_vec(&*recent)
                .map_err(|e| TokenError::StorageError(e.to_string()))?,
        });
        drop(recent);

        self.persist(ops)?;

        debug!(
            "Processed fee: {} of {} (treasury: {}, burn: {}, stakers: {})",
            amount,
            asset_id.as_str(),
            treasury_share,
            burn_share,
            staker_share
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
    pub fn start_new_period(&self, period_id: String, start_time: Timestamp) -> Result<()> {
        let mut ops = Vec::new();

        // Close current period if exists
        if let Some(current) = self.current_period.read().as_ref()
            && let Some(mut history) = self.history.get_mut(current)
        {
            history.period_end = Timestamp::now();
            ops.push(Self::period_op(current, &history)?);
        }

        // Create new period
        let history = DistributionHistory::new(start_time, Timestamp::now());
        ops.push(Self::period_op(&period_id, &history)?);
        self.history.insert(period_id.clone(), history);
        *self.current_period.write() = Some(period_id.clone());
        ops.push(WriteOp::Put {
            cf: CF_TOKENS.to_string(),
            key: FEE_CURRENT_PERIOD_KEY.to_vec(),
            value: period_id.clone().into_bytes(),
        });

        self.persist(ops)?;

        info!("Started new distribution period: {}", period_id);
        Ok(())
    }

    /// Updates the fee distribution configuration
    pub fn update_config(&self, config: FeeDistributionConfig) -> Result<()> {
        config.validate()?;
        let value =
            serde_json::to_vec(&config).map_err(|e| TokenError::StorageError(e.to_string()))?;
        *self.config.write() = config;
        self.persist(vec![WriteOp::Put {
            cf: CF_TOKENS.to_string(),
            key: FEE_CONFIG_KEY.to_vec(),
            value,
        }])?;
        info!("Updated fee distribution configuration");
        Ok(())
    }

    /// Returns the current configuration
    pub fn get_config(&self) -> FeeDistributionConfig {
        self.config.read().clone()
    }

    /// Adds a fee record to the current history period, returning the write
    /// ops that persist the updated period.
    fn add_to_history(&self, record: &FeeRecord) -> Result<Vec<WriteOp>> {
        // Guard is scoped out before start_new_period takes the write lock.
        let current = { self.current_period.read().clone() };

        let period_id = match current {
            Some(id) => id,
            None => {
                // Auto-create a default period if none exists
                let id = format!("period_{}", Timestamp::now().as_millis());
                self.start_new_period(id.clone(), Timestamp::now())?;
                id
            }
        };

        match self.history.get_mut(&period_id) {
            Some(mut history) => {
                history.add_fee(record);
                Ok(vec![Self::period_op(&period_id, &history)?])
            }
            None => Ok(Vec::new()),
        }
    }

    /// Returns a fee record by ID, if it is still inside the recent window
    pub fn get_fee_record(&self, fee_id: &str) -> Option<FeeRecord> {
        self.recent
            .read()
            .iter()
            .find(|r| r.fee_id == fee_id)
            .cloned()
    }

    /// Returns the recent fee records, oldest first
    pub fn get_all_fee_records(&self) -> Vec<FeeRecord> {
        self.recent.read().iter().cloned().collect()
    }
}

/// Key for one distribution period.
fn period_key(period_id: &str) -> Vec<u8> {
    let mut key = FEE_PERIOD_PREFIX.to_vec();
    key.extend_from_slice(period_id.as_bytes());
    key
}

/// Reads and decodes a JSON value from `CF_TOKENS`.
fn read_json<T: serde::de::DeserializeOwned>(store: &dyn KvStore, key: &[u8]) -> Result<Option<T>> {
    match store.get(CF_TOKENS, key)? {
        Some(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
        None => Ok(None),
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

    /// Records a fee split the way a caller governed by the configured
    /// distribution would.
    fn process_by_config(
        processor: &FeeProcessor,
        asset_id: AssetId,
        amount: u128,
        source: FeeSource,
    ) -> FeeRecord {
        let split = processor.get_config().calculate_distribution(amount);
        processor
            .process_fee(
                asset_id,
                source,
                split.treasury_amount,
                split.burn_amount,
                split.staker_amount,
            )
            .unwrap()
    }

    #[test]
    fn test_process_fee() {
        let processor = FeeProcessor::new();
        let asset_id = AssetId::tnzo();

        let record = process_by_config(&processor, asset_id, 10000, FeeSource::Transaction);

        assert_eq!(record.amount, 10000);
        assert_eq!(record.treasury_share, 4000); // 40%
        assert_eq!(record.burn_share, 3000); // 30%
        assert_eq!(record.staker_share, 3000); // 30%

        let stats = processor.get_fee_stats();
        assert_eq!(stats.fee_count, 1);
        assert_eq!(stats.total_to_treasury, 4000);
    }

    #[test]
    fn test_process_fee_records_the_split_it_is_given() {
        let processor = FeeProcessor::new();

        // A caller with an authoritative split — gas fees carry no staker
        // share — must see it recorded verbatim, not re-derived from config.
        let record = processor
            .process_fee(AssetId::tnzo(), FeeSource::Transaction, 700, 300, 0)
            .unwrap();

        assert_eq!(record.amount, 1000);
        assert_eq!(record.treasury_share, 700);
        assert_eq!(record.burn_share, 300);
        assert_eq!(record.staker_share, 0);

        let stats = processor.get_fee_stats();
        assert_eq!(stats.total_to_treasury, 700);
        assert_eq!(stats.total_burned, 300);
        assert_eq!(stats.total_to_stakers, 0);
    }

    #[test]
    fn test_fee_stats() {
        let processor = FeeProcessor::new();
        let asset_id = AssetId::tnzo();

        process_by_config(&processor, asset_id.clone(), 10000, FeeSource::Transaction);
        process_by_config(&processor, asset_id.clone(), 5000, FeeSource::Settlement);

        let stats = processor.get_fee_stats();
        assert_eq!(stats.fee_count, 2);
        assert_eq!(*stats.total_collected.get(&asset_id).unwrap(), 15000);
    }

    #[test]
    fn test_history_periods() {
        let processor = FeeProcessor::new();
        let asset_id = AssetId::tnzo();

        processor
            .start_new_period("period1".to_string(), Timestamp::now())
            .unwrap();
        process_by_config(&processor, asset_id, 10000, FeeSource::Transaction);

        let history = processor.get_distribution_history("period1").unwrap();
        assert_eq!(history.total_fees, 10000);
    }
}
