//! Network fee collection and routing to treasury

use crate::error::{Result, SettlementError};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tenzro_token::NetworkTreasury;
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::Timestamp;
use tracing::{debug, info, warn};

/// Record of a collected fee
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeRecord {
    /// Stable per-record identifier (UUID v4). Used as the storage key
    /// `fee:<id>` and lets a single settlement legitimately have multiple
    /// fee records.
    pub record_id: String,
    /// Fee amount
    pub amount: u128,
    /// Asset ID
    pub asset_id: AssetId,
    /// Source settlement ID
    pub source_settlement: String,
    /// Timestamp when fee was collected
    pub timestamp: Timestamp,
}

impl FeeRecord {
    /// Creates a new fee record with a fresh UUID identifier.
    pub fn new(amount: u128, asset_id: AssetId, source_settlement: String) -> Self {
        Self {
            record_id: uuid::Uuid::new_v4().to_string(),
            amount,
            asset_id,
            source_settlement,
            timestamp: Timestamp::now(),
        }
    }
}

/// Network fee collector
///
/// Collects fees from settlements and routes them to the network treasury.
/// Supports multi-asset fee collection (USDC, USDT, TNZO, etc.)
pub struct FeeCollector {
    /// Network treasury for depositing fees
    treasury: Arc<NetworkTreasury>,
    /// Total fees collected per asset
    total_collected: RwLock<HashMap<AssetId, u128>>,
    /// Fee collection history
    collection_history: RwLock<Vec<FeeRecord>>,
    /// Collection count per asset
    collection_counts: RwLock<HashMap<AssetId, u64>>,
    /// Optional persistent storage for fee records and per-asset totals/counts.
    storage: Option<Arc<dyn tenzro_storage::KvStore>>,
}

impl std::fmt::Debug for FeeCollector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FeeCollector")
            .field("treasury", &self.treasury)
            .field("total_collected", &*self.total_collected.read())
            .field("collection_history_len", &self.collection_history.read().len())
            .field("collection_counts", &*self.collection_counts.read())
            .field("storage", &self.storage.as_ref().map(|_| "<dyn KvStore>"))
            .finish()
    }
}

impl FeeCollector {
    /// Per-fee record key prefix
    const FEE_PREFIX: &'static [u8] = b"fee:";
    /// Per-asset total key prefix
    const FEE_TOTAL_PREFIX: &'static [u8] = b"fee_total:";
    /// Per-asset count key prefix
    const FEE_COUNT_PREFIX: &'static [u8] = b"fee_count:";

    fn fee_key(record_id: &str) -> Vec<u8> {
        [Self::FEE_PREFIX, record_id.as_bytes()].concat()
    }

    fn fee_total_key(asset: &AssetId) -> Vec<u8> {
        [Self::FEE_TOTAL_PREFIX, asset.as_str().as_bytes()].concat()
    }

    fn fee_count_key(asset: &AssetId) -> Vec<u8> {
        [Self::FEE_COUNT_PREFIX, asset.as_str().as_bytes()].concat()
    }

    /// Creates a new fee collector with no persistent storage.
    pub fn new(treasury: Arc<NetworkTreasury>) -> Self {
        Self {
            treasury,
            total_collected: RwLock::new(HashMap::new()),
            collection_history: RwLock::new(Vec::new()),
            collection_counts: RwLock::new(HashMap::new()),
            storage: None,
        }
    }

    /// Creates a fee collector backed by RocksDB storage. Records, per-asset
    /// totals, and per-asset counts are written through to `CF_SETTLEMENTS`
    /// on every collection and rehydrated on startup.
    pub fn with_storage(
        treasury: Arc<NetworkTreasury>,
        storage: Arc<dyn tenzro_storage::KvStore>,
    ) -> Self {
        let collector = Self {
            treasury,
            total_collected: RwLock::new(HashMap::new()),
            collection_history: RwLock::new(Vec::new()),
            collection_counts: RwLock::new(HashMap::new()),
            storage: Some(storage),
        };

        if let Err(e) = collector.hydrate() {
            warn!("FeeCollector hydration failed: {}", e);
        }

        collector
    }

    /// Hydrates in-memory state from persistent storage.
    fn hydrate(&self) -> Result<()> {
        let storage = match &self.storage {
            Some(s) => s,
            None => return Ok(()),
        };

        // Records.
        let record_keys = storage
            .get_keys_with_prefix(tenzro_storage::CF_SETTLEMENTS, Self::FEE_PREFIX)
            .map_err(|e| SettlementError::StorageError(e.to_string()))?;

        let mut history: Vec<FeeRecord> = Vec::with_capacity(record_keys.len());
        for key in record_keys {
            if let Some(bytes) = storage
                .get(tenzro_storage::CF_SETTLEMENTS, &key)
                .map_err(|e| SettlementError::StorageError(e.to_string()))?
            {
                match serde_json::from_slice::<FeeRecord>(&bytes) {
                    Ok(r) => history.push(r),
                    Err(e) => warn!("skip undecodable fee record: {}", e),
                }
            }
        }
        // Sort by timestamp so prune/recent_history behave as before.
        history.sort_by_key(|r| r.timestamp);
        *self.collection_history.write() = history;

        // Per-asset totals.
        let total_keys = storage
            .get_keys_with_prefix(tenzro_storage::CF_SETTLEMENTS, Self::FEE_TOTAL_PREFIX)
            .map_err(|e| SettlementError::StorageError(e.to_string()))?;

        let mut totals: HashMap<AssetId, u128> = HashMap::new();
        for key in total_keys {
            if let Some(bytes) = storage
                .get(tenzro_storage::CF_SETTLEMENTS, &key)
                .map_err(|e| SettlementError::StorageError(e.to_string()))?
            {
                let suffix = &key[Self::FEE_TOTAL_PREFIX.len()..];
                let asset_str = match std::str::from_utf8(suffix) {
                    Ok(s) => s,
                    Err(_) => {
                        warn!("skip non-utf8 fee_total key");
                        continue;
                    }
                };
                if bytes.len() != 16 {
                    warn!("skip malformed fee_total value (len={})", bytes.len());
                    continue;
                }
                let mut arr = [0u8; 16];
                arr.copy_from_slice(&bytes);
                totals.insert(AssetId::new(asset_str), u128::from_le_bytes(arr));
            }
        }
        *self.total_collected.write() = totals;

        // Per-asset counts.
        let count_keys = storage
            .get_keys_with_prefix(tenzro_storage::CF_SETTLEMENTS, Self::FEE_COUNT_PREFIX)
            .map_err(|e| SettlementError::StorageError(e.to_string()))?;

        let mut counts: HashMap<AssetId, u64> = HashMap::new();
        for key in count_keys {
            if let Some(bytes) = storage
                .get(tenzro_storage::CF_SETTLEMENTS, &key)
                .map_err(|e| SettlementError::StorageError(e.to_string()))?
            {
                let suffix = &key[Self::FEE_COUNT_PREFIX.len()..];
                let asset_str = match std::str::from_utf8(suffix) {
                    Ok(s) => s,
                    Err(_) => {
                        warn!("skip non-utf8 fee_count key");
                        continue;
                    }
                };
                if bytes.len() != 8 {
                    warn!("skip malformed fee_count value (len={})", bytes.len());
                    continue;
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                counts.insert(AssetId::new(asset_str), u64::from_le_bytes(arr));
            }
        }
        *self.collection_counts.write() = counts;

        info!(
            "Hydrated FeeCollector: {} records, {} asset totals, {} asset counts",
            self.collection_history.read().len(),
            self.total_collected.read().len(),
            self.collection_counts.read().len()
        );
        Ok(())
    }

    /// Atomically persists a collected fee + updated asset total + count.
    fn persist_collection(
        &self,
        record: &FeeRecord,
        new_total: u128,
        new_count: u64,
    ) -> Result<()> {
        let storage = match &self.storage {
            Some(s) => s,
            None => return Ok(()),
        };

        let record_bytes = serde_json::to_vec(record).map_err(|e| {
            SettlementError::StorageError(format!("serialize fee record: {}", e))
        })?;

        let ops = vec![
            tenzro_storage::WriteOp::Put {
                cf: tenzro_storage::CF_SETTLEMENTS.to_string(),
                key: Self::fee_key(&record.record_id),
                value: record_bytes,
            },
            tenzro_storage::WriteOp::Put {
                cf: tenzro_storage::CF_SETTLEMENTS.to_string(),
                key: Self::fee_total_key(&record.asset_id),
                value: new_total.to_le_bytes().to_vec(),
            },
            tenzro_storage::WriteOp::Put {
                cf: tenzro_storage::CF_SETTLEMENTS.to_string(),
                key: Self::fee_count_key(&record.asset_id),
                value: new_count.to_le_bytes().to_vec(),
            },
        ];

        storage
            .write_batch_sync(ops)
            .map_err(|e| SettlementError::StorageError(e.to_string()))
    }

    /// Collects a fee from a settlement and deposits it to treasury
    ///
    /// # Arguments
    ///
    /// * `settlement_id` - ID of the settlement this fee is from
    /// * `asset_id` - Asset type of the fee
    /// * `amount` - Fee amount
    pub fn collect_fee(
        &self,
        settlement_id: &str,
        asset_id: &AssetId,
        amount: u128,
    ) -> Result<()> {
        if amount == 0 {
            return Err(SettlementError::InvalidAmount(
                "Fee amount must be greater than zero".to_string(),
            ));
        }

        // Deposit fee to treasury
        self.treasury.deposit_fee(asset_id, amount)?;

        // Update total collected
        let new_total: u128;
        {
            let mut total = self.total_collected.write();
            let current = total.get(asset_id).copied().unwrap_or(0);
            new_total = current
                .checked_add(amount)
                .ok_or_else(|| SettlementError::ArithmeticOverflow("Fee overflow".to_string()))?;
            total.insert(asset_id.clone(), new_total);
        }

        // Update collection count
        let new_count: u64;
        {
            let mut counts = self.collection_counts.write();
            let count = counts.get(asset_id).copied().unwrap_or(0);
            new_count = count + 1;
            counts.insert(asset_id.clone(), new_count);
        }

        // Record in history
        let record = FeeRecord::new(amount, asset_id.clone(), settlement_id.to_string());
        self.collection_history.write().push(record.clone());

        // Atomic write-through after the in-memory mutations succeed.
        self.persist_collection(&record, new_total, new_count)?;

        debug!(
            "Collected fee: {} {} from settlement {}",
            amount,
            asset_id.as_str(),
            settlement_id
        );

        Ok(())
    }

    /// Extracts fee from settlement amount
    ///
    /// # Arguments
    ///
    /// * `settlement_id` - Settlement ID
    /// * `asset_id` - Asset type
    /// * `total_amount` - Total settlement amount
    /// * `fee_bps` - Fee in basis points (e.g., 50 = 0.5%)
    ///
    /// Returns (net_amount, fee_amount)
    pub fn extract_fee(
        &self,
        settlement_id: &str,
        asset_id: &AssetId,
        total_amount: u128,
        fee_bps: u32,
    ) -> Result<(u128, u128)> {
        if fee_bps > 10000 {
            return Err(SettlementError::InvalidConfig(
                "Fee cannot exceed 100% (10000 bps)".to_string(),
            ));
        }

        let fee_amount = (total_amount * fee_bps as u128) / 10000;
        let net_amount = total_amount
            .checked_sub(fee_amount)
            .ok_or_else(|| SettlementError::ArithmeticOverflow("Fee calculation".to_string()))?;

        // Collect the fee
        if fee_amount > 0 {
            self.collect_fee(settlement_id, asset_id, fee_amount)?;
        }

        Ok((net_amount, fee_amount))
    }

    /// Returns total fees collected for all assets
    pub fn get_total_collected(&self) -> HashMap<AssetId, u128> {
        self.total_collected.read().clone()
    }

    /// Returns total fees collected for a specific asset
    pub fn get_fees_by_asset(&self, asset_id: &AssetId) -> u128 {
        self.total_collected
            .read()
            .get(asset_id)
            .copied()
            .unwrap_or(0)
    }

    /// Returns collection statistics
    pub fn get_collection_stats(&self) -> CollectionStats {
        let total_collected = self.total_collected.read().clone();
        let collection_counts = self.collection_counts.read().clone();
        let total_collections: u64 = collection_counts.values().sum();

        // Calculate total value across all assets
        let total_value: u128 = total_collected.values().sum();

        // Get recent history (last 100 records)
        let history = self.collection_history.read();
        let recent_history = if history.len() > 100 {
            history[history.len() - 100..].to_vec()
        } else {
            history.clone()
        };
        drop(history);

        CollectionStats {
            total_collected,
            collection_counts,
            total_collections,
            total_value,
            recent_history,
        }
    }

    /// Returns collection history
    pub fn get_history(&self) -> Vec<FeeRecord> {
        self.collection_history.read().clone()
    }

    /// Clears old history (keeps last N records). When persistent storage is
    /// configured, the dropped records are also removed from the backing
    /// store so that hydration after restart sees the same pruned set —
    /// otherwise pruning would silently re-grow on next startup.
    pub fn prune_history(&self, keep_last: usize) {
        let mut history = self.collection_history.write();
        if history.len() <= keep_last {
            return;
        }

        let start = history.len() - keep_last;
        let dropped: Vec<FeeRecord> = history[..start].to_vec();
        *history = history[start..].to_vec();
        drop(history);

        if let Some(storage) = &self.storage {
            let ops: Vec<tenzro_storage::WriteOp> = dropped
                .iter()
                .map(|r| tenzro_storage::WriteOp::Delete {
                    cf: tenzro_storage::CF_SETTLEMENTS.to_string(),
                    key: Self::fee_key(&r.record_id),
                })
                .collect();

            if !ops.is_empty() {
                if let Err(e) = storage.write_batch_sync(ops) {
                    warn!("Failed to delete pruned fee records from storage: {}", e);
                }
            }
        }

        info!("Pruned fee collection history to {} records", keep_last);
    }

    /// Returns statistics by time period
    pub fn get_stats_by_period(&self, start: Timestamp, end: Timestamp) -> PeriodStats {
        let history = self.collection_history.read();

        let mut period_collected: HashMap<AssetId, u128> = HashMap::new();
        let mut period_count = 0u64;

        for record in history.iter() {
            if record.timestamp >= start && record.timestamp <= end {
                let current = period_collected
                    .get(&record.asset_id)
                    .copied()
                    .unwrap_or(0);
                period_collected.insert(record.asset_id.clone(), current + record.amount);
                period_count += 1;
            }
        }

        let period_value: u128 = period_collected.values().sum();

        PeriodStats {
            start,
            end,
            period_collected,
            period_count,
            period_value,
        }
    }
}

/// Collection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionStats {
    /// Total fees collected per asset
    pub total_collected: HashMap<AssetId, u128>,
    /// Number of collections per asset
    pub collection_counts: HashMap<AssetId, u64>,
    /// Total number of fee collections
    pub total_collections: u64,
    /// Total value across all assets
    pub total_value: u128,
    /// Recent collection history
    pub recent_history: Vec<FeeRecord>,
}

/// Statistics for a specific time period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeriodStats {
    /// Period start
    pub start: Timestamp,
    /// Period end
    pub end: Timestamp,
    /// Fees collected in period per asset
    pub period_collected: HashMap<AssetId, u128>,
    /// Number of collections in period
    pub period_count: u64,
    /// Total value collected in period
    pub period_value: u128,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::primitives::Address;

    #[test]
    fn test_fee_collection() {
        let treasury = Arc::new(NetworkTreasury::new(Address::default()));
        let collector = FeeCollector::new(treasury);

        let asset_id = AssetId::tnzo();

        // Collect fee
        collector
            .collect_fee("settlement-1", &asset_id, 100)
            .unwrap();

        // Verify total collected
        assert_eq!(collector.get_fees_by_asset(&asset_id), 100);

        // Collect another fee
        collector
            .collect_fee("settlement-2", &asset_id, 50)
            .unwrap();

        assert_eq!(collector.get_fees_by_asset(&asset_id), 150);
    }

    #[test]
    fn test_fee_extraction() {
        let treasury = Arc::new(NetworkTreasury::new(Address::default()));
        let collector = FeeCollector::new(treasury);

        let asset_id = AssetId::tnzo();

        // Extract 0.5% fee from 10000
        let (net, fee) = collector
            .extract_fee("settlement-1", &asset_id, 10000, 50)
            .unwrap();

        assert_eq!(fee, 50); // 0.5% of 10000
        assert_eq!(net, 9950);
        assert_eq!(collector.get_fees_by_asset(&asset_id), 50);
    }

    #[test]
    fn test_multi_asset_collection() {
        let treasury = Arc::new(NetworkTreasury::new(Address::default()));
        let collector = FeeCollector::new(treasury);

        let tnzo = AssetId::tnzo();
        let usdc = AssetId::new("USDC");

        collector.collect_fee("settlement-1", &tnzo, 100).unwrap();
        collector.collect_fee("settlement-2", &usdc, 200).unwrap();

        assert_eq!(collector.get_fees_by_asset(&tnzo), 100);
        assert_eq!(collector.get_fees_by_asset(&usdc), 200);

        let stats = collector.get_collection_stats();
        assert_eq!(stats.total_collections, 2);
        assert_eq!(stats.total_value, 300);
    }

    #[test]
    fn test_collection_history() {
        let treasury = Arc::new(NetworkTreasury::new(Address::default()));
        let collector = FeeCollector::new(treasury);

        let asset_id = AssetId::tnzo();

        collector.collect_fee("settlement-1", &asset_id, 100).unwrap();
        collector.collect_fee("settlement-2", &asset_id, 50).unwrap();

        let history = collector.get_history();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].amount, 100);
        assert_eq!(history[1].amount, 50);
    }
}
