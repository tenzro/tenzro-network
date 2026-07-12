//! Per-query pricing and usage metering for managed databases.
//!
//! A [`crate::DatabaseDescriptor`] carries a [`DatabasePricing`] declaring what
//! a non-owner caller pays per query. The node layer gates
//! `tenzro_databaseQuery` on it with the payment-gateway 402 flow (challenge →
//! credential → settle) and records every served query in a
//! [`DatabaseUsageMeter`], which persists per-database counters to
//! `CF_DATABASES` and hydrates them on boot.
//!
//! Pricing is per-query only. Storage rent would require byte-size reporting
//! from every engine backend, which none of the five engines expose through
//! the [`crate::runtime::DatabaseEngine`] seam — a size-based price would be a
//! number nobody measures.

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tenzro_storage::{KvStore, WriteOp, CF_DATABASES};

use crate::error::{DatabaseError, Result};

const USAGE_PREFIX: &[u8] = b"usage/";

/// What a non-owner caller pays per query against a database. The owner always
/// queries free; a zero `price_per_query` makes the database free for every
/// authorized caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabasePricing {
    /// Asset the price is denominated in (`"TNZO"` for native settlement).
    pub asset_id: String,
    /// Price per query in the asset's base units. Zero = free.
    pub price_per_query: u128,
}

impl DatabasePricing {
    /// Free-for-authorized-callers pricing (the default for a new database).
    pub fn free() -> Self {
        Self { asset_id: "TNZO".to_string(), price_per_query: 0 }
    }

    /// Whether authorized non-owner callers query without payment.
    pub fn is_free(&self) -> bool {
        self.price_per_query == 0
    }
}

impl Default for DatabasePricing {
    fn default() -> Self {
        Self::free()
    }
}

/// Cumulative usage counters for one database, maintained by the holder that
/// serves its queries.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatabaseUsageStats {
    /// Database these counters belong to.
    pub database_id: String,
    /// Total queries served (reads and writes).
    pub query_count: u64,
    /// Subset of `query_count` that were writes.
    pub write_count: u64,
    /// Total request-payload bytes received.
    pub bytes_in: u64,
    /// Total response-payload bytes returned.
    pub bytes_out: u64,
    /// Total settled payment across all billed queries, in the pricing asset's
    /// base units.
    pub billed_total: u128,
    /// Unix-millis timestamp of the most recent query.
    pub last_query_ms: u64,
}

/// Write-through per-database usage meter. Counters live in a `DashMap` and
/// persist to `CF_DATABASES` under `usage/<database_id>`; a node restores them
/// on boot so billing history survives restarts.
pub struct DatabaseUsageMeter {
    stats: DashMap<String, DatabaseUsageStats>,
    storage: Option<Arc<dyn KvStore>>,
}

impl DatabaseUsageMeter {
    /// An in-memory meter with no persistence. Use [`Self::with_storage`] for a
    /// durable one.
    pub fn new() -> Self {
        Self { stats: DashMap::new(), storage: None }
    }

    /// A meter backed by `storage`, hydrating previously-persisted counters
    /// from `CF_DATABASES`.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self> {
        let meter = Self { stats: DashMap::new(), storage: Some(storage.clone()) };
        for (_, value) in storage
            .scan_prefix(CF_DATABASES, USAGE_PREFIX)
            .map_err(|e| DatabaseError::Persistence(e.to_string()))?
        {
            if let Ok(s) = serde_json::from_slice::<DatabaseUsageStats>(&value) {
                meter.stats.insert(s.database_id.clone(), s);
            }
        }
        Ok(meter)
    }

    fn storage_key(database_id: &str) -> Vec<u8> {
        let mut k = USAGE_PREFIX.to_vec();
        k.extend_from_slice(database_id.as_bytes());
        k
    }

    /// Records one served query, returning the updated counters. `billed` is
    /// the settled payment amount for this query (zero for free databases and
    /// owner queries).
    pub fn record_query(
        &self,
        database_id: &str,
        write: bool,
        bytes_in: u64,
        bytes_out: u64,
        billed: u128,
        now_ms: u64,
    ) -> Result<DatabaseUsageStats> {
        let updated = {
            let mut entry = self
                .stats
                .entry(database_id.to_string())
                .or_insert_with(|| DatabaseUsageStats {
                    database_id: database_id.to_string(),
                    ..Default::default()
                });
            let s = entry.value_mut();
            s.query_count = s.query_count.saturating_add(1);
            if write {
                s.write_count = s.write_count.saturating_add(1);
            }
            s.bytes_in = s.bytes_in.saturating_add(bytes_in);
            s.bytes_out = s.bytes_out.saturating_add(bytes_out);
            s.billed_total = s.billed_total.saturating_add(billed);
            s.last_query_ms = now_ms;
            s.clone()
        };
        if let Some(ref storage) = self.storage {
            storage
                .write_batch_sync(vec![WriteOp::Put {
                    cf: CF_DATABASES.to_string(),
                    key: Self::storage_key(database_id),
                    value: serde_json::to_vec(&updated)
                        .map_err(|e| DatabaseError::Persistence(e.to_string()))?,
                }])
                .map_err(|e| DatabaseError::Persistence(e.to_string()))?;
        }
        Ok(updated)
    }

    /// The current counters for a database, if any query was ever recorded.
    pub fn get(&self, database_id: &str) -> Option<DatabaseUsageStats> {
        self.stats.get(database_id).map(|r| r.value().clone())
    }

    /// Removes a database's counters — the drop-database companion so a dropped
    /// database leaves no orphaned usage row.
    pub fn remove(&self, database_id: &str) -> Result<()> {
        self.stats.remove(database_id);
        if let Some(ref storage) = self.storage {
            storage
                .write_batch_sync(vec![WriteOp::Delete {
                    cf: CF_DATABASES.to_string(),
                    key: Self::storage_key(database_id),
                }])
                .map_err(|e| DatabaseError::Persistence(e.to_string()))?;
        }
        Ok(())
    }
}

impl Default for DatabaseUsageMeter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_pricing_is_free_tnzo() {
        let p = DatabasePricing::default();
        assert!(p.is_free());
        assert_eq!(p.asset_id, "TNZO");
    }

    #[test]
    fn record_query_accumulates() {
        let m = DatabaseUsageMeter::new();
        m.record_query("db", false, 100, 200, 0, 1_000).unwrap();
        let s = m.record_query("db", true, 50, 25, 42, 2_000).unwrap();
        assert_eq!(s.query_count, 2);
        assert_eq!(s.write_count, 1);
        assert_eq!(s.bytes_in, 150);
        assert_eq!(s.bytes_out, 225);
        assert_eq!(s.billed_total, 42);
        assert_eq!(s.last_query_ms, 2_000);
    }

    #[test]
    fn persistence_hydrates_on_reopen() {
        let storage: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        {
            let m = DatabaseUsageMeter::with_storage(storage.clone()).unwrap();
            m.record_query("db-p", true, 10, 20, 7, 5_000).unwrap();
        }
        let m2 = DatabaseUsageMeter::with_storage(storage).unwrap();
        let s = m2.get("db-p").unwrap();
        assert_eq!(s.query_count, 1);
        assert_eq!(s.billed_total, 7);
    }

    #[test]
    fn remove_clears_counters_and_row() {
        let storage: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        let m = DatabaseUsageMeter::with_storage(storage.clone()).unwrap();
        m.record_query("db-x", false, 1, 1, 0, 1).unwrap();
        m.remove("db-x").unwrap();
        assert!(m.get("db-x").is_none());
        let m2 = DatabaseUsageMeter::with_storage(storage).unwrap();
        assert!(m2.get("db-x").is_none());
    }
}
