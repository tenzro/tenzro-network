//! Per-tenant Chainlink/bridge-fee analytics + GCRA rate limiter.
//!
//! Mirror of [`crate::canton_analytics`] for the `chainlink` API-key scope.
//! Two-layer design:
//!
//! - **Authorization (sync hot path):** in-memory GCRA state per key,
//!   sub-µs atomic-update. Reject early on rate-limit hit with the
//!   `-32005` JSON-RPC error envelope carrying `retry_after_ms`. Reject
//!   early on insufficient scope.
//! - **Metering (write-through cold path):** RocksDB `CF_BRIDGE_ANALYTICS`
//!   keyed by `bridge_analytics:<key_id>` with per-method call counters
//!   plus a `cu_consumed_total` compute-unit aggregate.
//!
//! Each `chainlink`-scoped RPC call increments:
//!   - `calls_total`
//!   - `calls_by_method[method]`
//!   - `cu_consumed_total += method_cu_cost(method)`

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tenzro_storage::{KvStore, CF_BRIDGE_ANALYTICS};

use crate::error::{NodeError, Result};

/// Per-API-key bridge usage aggregate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeKeyAnalytics {
    pub key_id: String,
    /// Total successful chainlink-scoped RPC calls.
    pub calls_total: u64,
    /// Total chainlink-scoped calls that returned an error.
    pub errors_total: u64,
    /// Per-method call counts (success path).
    pub calls_by_method: HashMap<String, u64>,
    /// Per-method error counts.
    pub errors_by_method: HashMap<String, u64>,
    /// Total Alchemy-style Compute Units consumed (sum of per-method CU
    /// costs on the success path). Operators use this to attribute
    /// upstream RPC cost to each tenant.
    pub cu_consumed_total: u64,
    /// First call timestamp (unix seconds).
    pub first_seen_at: Option<i64>,
    /// Most recent call timestamp (unix seconds).
    pub last_called_at: Option<i64>,
    /// Number of requests that hit the rate-limit gate (429).
    pub rate_limit_rejections: u64,
}

impl BridgeKeyAnalytics {
    fn empty(key_id: String) -> Self {
        Self {
            key_id,
            calls_total: 0,
            errors_total: 0,
            calls_by_method: HashMap::new(),
            errors_by_method: HashMap::new(),
            cu_consumed_total: 0,
            first_seen_at: None,
            last_called_at: None,
            rate_limit_rejections: 0,
        }
    }
}

/// Compute Unit cost table. Each `chainlink`-scoped RPC method has an
/// integer weight; the per-tenant `cu_consumed_total` aggregate is the
/// sum of weights for successful calls. Used by the operator to
/// attribute upstream RPC quota cost.
///
/// For methods not in the table we default to 10 CU (a typical cached/
/// read-only RPC weight).
pub fn method_cu_cost(method: &str) -> u64 {
    match method {
        "tenzro_quoteBridgeFeeInTnzo" => 26,        // 1 × eth_call to AggregatorV3
        "tenzro_sponsorBridgeFee" => 5,             // pure in-memory write
        "tenzro_listBridgeSponsorshipPools" => 5,   // in-memory snapshot
        "tenzro_listBridgeFeeFeeds" => 5,
        "tenzro_getBridgeFeeFeed" => 5,
        "tenzro_getBridgeAnalytics" => 5,
        // EVM read methods (when gated under `chainlink` scope for
        // bridge-fee operators):
        "eth_call" => 26,
        "eth_getBlockByNumber" => 20,
        "eth_blockNumber" => 10,
        _ => 10,
    }
}

/// In-memory + persistent per-tenant bridge call counter.
pub struct BridgeAnalyticsManager {
    storage: Arc<dyn KvStore>,
    cache: RwLock<HashMap<String, BridgeKeyAnalytics>>,
}

impl std::fmt::Debug for BridgeAnalyticsManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgeAnalyticsManager")
            .field("cached", &self.cache.read().len())
            .finish()
    }
}

impl BridgeAnalyticsManager {
    pub fn new(storage: Arc<dyn KvStore>) -> Result<Arc<Self>> {
        let mgr = Self {
            storage,
            cache: RwLock::new(HashMap::new()),
        };
        mgr.hydrate()?;
        Ok(Arc::new(mgr))
    }

    fn hydrate(&self) -> Result<()> {
        let entries = self
            .storage
            .scan_prefix(CF_BRIDGE_ANALYTICS, b"bridge_analytics:")
            .map_err(|e| {
                NodeError::Internal(format!("bridge_analytics hydrate scan failed: {}", e))
            })?;
        let mut cache = self.cache.write();
        for (key, value) in entries {
            let key_id = match std::str::from_utf8(&key) {
                Ok(k) => k.trim_start_matches("bridge_analytics:").to_string(),
                Err(_) => continue,
            };
            let record: BridgeKeyAnalytics = match serde_json::from_slice(&value) {
                Ok(r) => r,
                Err(_) => continue,
            };
            cache.insert(key_id, record);
        }
        Ok(())
    }

    /// Record one chainlink-scoped RPC call.
    pub fn record_call(&self, key_id: &str, method: &str, success: bool) -> Result<()> {
        let now = chrono::Utc::now().timestamp();
        let cu_cost = method_cu_cost(method);
        let record = {
            let mut cache = self.cache.write();
            let entry = cache
                .entry(key_id.to_string())
                .or_insert_with(|| BridgeKeyAnalytics::empty(key_id.to_string()));
            if entry.first_seen_at.is_none() {
                entry.first_seen_at = Some(now);
            }
            entry.last_called_at = Some(now);
            if success {
                entry.calls_total = entry.calls_total.saturating_add(1);
                entry.cu_consumed_total = entry.cu_consumed_total.saturating_add(cu_cost);
                *entry.calls_by_method.entry(method.to_string()).or_insert(0) += 1;
            } else {
                entry.errors_total = entry.errors_total.saturating_add(1);
                *entry.errors_by_method.entry(method.to_string()).or_insert(0) += 1;
            }
            entry.clone()
        };
        let storage_key = format!("bridge_analytics:{}", key_id);
        let value = serde_json::to_vec(&record)
            .map_err(|e| NodeError::Internal(format!("bridge_analytics serialize: {}", e)))?;
        self.storage
            .put(CF_BRIDGE_ANALYTICS, storage_key.as_bytes(), &value)
            .map_err(|e| NodeError::Internal(format!("bridge_analytics put: {}", e)))?;
        Ok(())
    }

    /// Record one rate-limit rejection (separate counter so operators
    /// can spot misbehaving tenants).
    pub fn record_rate_limit_rejection(&self, key_id: &str) {
        let mut cache = self.cache.write();
        let entry = cache
            .entry(key_id.to_string())
            .or_insert_with(|| BridgeKeyAnalytics::empty(key_id.to_string()));
        entry.rate_limit_rejections = entry.rate_limit_rejections.saturating_add(1);
        // Don't persist on every rejection — the next successful call's
        // record_call write will flush; rejection counts are best-effort.
    }

    pub fn get(&self, key_id: &str) -> Option<BridgeKeyAnalytics> {
        self.cache.read().get(key_id).cloned()
    }

    pub fn list_all(&self) -> Vec<BridgeKeyAnalytics> {
        self.cache.read().values().cloned().collect()
    }
}

// ----------------------------- GCRA rate limiter -----------------------------

/// Generic Cell Rate Algorithm (GCRA) rate limiter. One TAT
/// (Theoretical Arrival Time) value per key; one atomic write per
/// request; no background refill task.
///
/// `period` is the inverse rate: time-between-cells when traffic is
/// perfectly paced. `burst` is the max number of "borrowed" future cells
/// the key can consume in one go before being throttled to the steady
/// rate. Default config (1 cell per 100ms, burst 100) admits ~10 req/sec
/// sustained with bursts of 100 — appropriate for a per-tenant
/// Chainlink-quote rate limit.
#[derive(Debug, Clone, Copy)]
pub struct GcraConfig {
    pub period: Duration,
    pub burst: u32,
}

impl GcraConfig {
    /// Default: ~10 req/sec sustained, bursts of 100.
    pub const fn default_chainlink() -> Self {
        Self {
            period: Duration::from_millis(100),
            burst: 100,
        }
    }
}

impl Default for GcraConfig {
    fn default() -> Self {
        Self::default_chainlink()
    }
}

/// One per-key GCRA gate decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcraDecision {
    /// Request admitted. `remaining_burst` is the current burst budget
    /// after this admission.
    Admit { remaining_burst: u32 },
    /// Request denied. `retry_after` is the minimum wait before the next
    /// attempt should be retried.
    Deny { retry_after: Duration },
}

/// In-memory GCRA limiter keyed on `String` (the API key id).
pub struct GcraLimiter {
    cfg: GcraConfig,
    /// `tat` per key — the Theoretical Arrival Time of the next cell
    /// such that the bucket is full.
    tat: dashmap::DashMap<String, Instant>,
}

impl GcraLimiter {
    pub fn new(cfg: GcraConfig) -> Self {
        Self {
            cfg,
            tat: dashmap::DashMap::new(),
        }
    }

    /// Returns the current gate decision for `key_id`. On admit, updates
    /// the TAT in-place (no extra round trip).
    ///
    /// Canonical GCRA: a cell is admitted when `tat - burst_window <=
    /// now`, equivalently `tat <= now + burst_window`. On admit, TAT
    /// advances by one `period`. We initialize `tat = now - burst_window`
    /// so a fresh key has a full burst of credit.
    pub fn check(&self, key_id: &str) -> GcraDecision {
        let now = Instant::now();
        let burst_window = self.cfg.period.saturating_mul(self.cfg.burst);

        let mut entry = self
            .tat
            .entry(key_id.to_string())
            .or_insert_with(|| now.checked_sub(burst_window).unwrap_or(now));
        let tat = *entry.value();

        // The "increment" — by how much would this cell advance TAT?
        let new_tat_if_admitted = tat.max(now) + self.cfg.period;
        // The deny threshold — TAT after this admit would be too far in
        // the future (more than burst_window past now).
        let allowed_after = now + burst_window;
        if new_tat_if_admitted > allowed_after {
            let retry_after = new_tat_if_admitted.saturating_duration_since(allowed_after);
            return GcraDecision::Deny { retry_after };
        }

        // Admit and persist.
        *entry.value_mut() = new_tat_if_admitted;
        let remaining_burst = allowed_after
            .saturating_duration_since(new_tat_if_admitted)
            .as_millis()
            / self.cfg.period.as_millis().max(1);
        GcraDecision::Admit {
            remaining_burst: remaining_burst as u32,
        }
    }

    /// Returns the current configured limit (cells per second).
    pub fn rate_per_second(&self) -> f64 {
        1000.0 / self.cfg.period.as_millis() as f64
    }

    pub fn burst(&self) -> u32 {
        self.cfg.burst
    }
}

impl Default for GcraLimiter {
    fn default() -> Self {
        Self::new(GcraConfig::default())
    }
}

impl std::fmt::Debug for GcraLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcraLimiter")
            .field("cfg", &self.cfg)
            .field("active_keys", &self.tat.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::MemoryStore;

    fn mem_store() -> Arc<dyn KvStore> {
        Arc::new(MemoryStore::new())
    }

    #[test]
    fn analytics_round_trip_through_storage() {
        let storage = mem_store();
        let mgr = BridgeAnalyticsManager::new(storage.clone()).unwrap();
        mgr.record_call("k1", "tenzro_quoteBridgeFeeInTnzo", true).unwrap();
        mgr.record_call("k1", "tenzro_quoteBridgeFeeInTnzo", true).unwrap();
        mgr.record_call("k1", "tenzro_sponsorBridgeFee", false).unwrap();
        let r = mgr.get("k1").unwrap();
        assert_eq!(r.calls_total, 2);
        assert_eq!(r.errors_total, 1);
        // 2 × 26 CU for the quote calls; errors don't count CUs.
        assert_eq!(r.cu_consumed_total, 52);
        assert_eq!(
            r.calls_by_method["tenzro_quoteBridgeFeeInTnzo"], 2
        );
    }

    #[test]
    fn analytics_persistence_survives_restart() {
        let storage = mem_store();
        {
            let mgr = BridgeAnalyticsManager::new(storage.clone()).unwrap();
            mgr.record_call("k2", "tenzro_quoteBridgeFeeInTnzo", true).unwrap();
        }
        let mgr2 = BridgeAnalyticsManager::new(storage).unwrap();
        let r = mgr2.get("k2").unwrap();
        assert_eq!(r.calls_total, 1);
        assert_eq!(r.cu_consumed_total, 26);
    }

    #[test]
    fn gcra_admits_within_burst() {
        let limiter = GcraLimiter::new(GcraConfig {
            period: Duration::from_millis(100),
            burst: 5,
        });
        // First 5 calls should admit instantly.
        for i in 0..5 {
            match limiter.check("burst-test") {
                GcraDecision::Admit { .. } => {}
                GcraDecision::Deny { .. } => panic!("denied at i={}", i),
            }
        }
    }

    #[test]
    fn gcra_denies_after_burst_exhausted() {
        let limiter = GcraLimiter::new(GcraConfig {
            period: Duration::from_millis(100),
            burst: 3,
        });
        // First 3 admit, 4th denies.
        for _ in 0..3 {
            assert!(matches!(limiter.check("k"), GcraDecision::Admit { .. }));
        }
        assert!(matches!(limiter.check("k"), GcraDecision::Deny { .. }));
    }

    #[test]
    fn gcra_keys_are_isolated() {
        let limiter = GcraLimiter::new(GcraConfig {
            period: Duration::from_millis(100),
            burst: 2,
        });
        // Exhaust k1.
        limiter.check("k1");
        limiter.check("k1");
        assert!(matches!(limiter.check("k1"), GcraDecision::Deny { .. }));
        // k2 still has full budget.
        assert!(matches!(limiter.check("k2"), GcraDecision::Admit { .. }));
    }

    #[test]
    fn cu_cost_table_canonical() {
        assert_eq!(method_cu_cost("eth_call"), 26);
        assert_eq!(method_cu_cost("eth_blockNumber"), 10);
        assert_eq!(method_cu_cost("eth_getBlockByNumber"), 20);
        assert_eq!(method_cu_cost("tenzro_quoteBridgeFeeInTnzo"), 26);
        assert_eq!(method_cu_cost("unknown_method"), 10);
    }
}
