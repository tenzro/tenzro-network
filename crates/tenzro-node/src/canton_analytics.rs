//! Per-tenant Canton analytics.
//!
//! Each API key with the `canton` scope gets a single
//! [`CantonKeyAnalytics`] record in `CF_CANTON_ANALYTICS`, keyed by
//! `canton_analytics:<key_id>`. Every canton-scoped RPC call increments
//! the counters (total + per-method) and updates `last_called_at`. The
//! aggregate is the answer to: "how many DAML transactions has the
//! tenzro-labs team submitted this month, and which methods are they
//! hitting?" — exactly what an RPC operator needs for per-tenant
//! visibility on a shared Canton participant.
//!
//! The bind from key → tenant is `ApiKeyRecord::canton_user_id` (set
//! at issuance). When a key has no bound user id the counter still
//! moves (we still want the operator's own usage rolled up), so we
//! key on `key_id` rather than `canton_user_id`.
//!
//! Writes are write-through to RocksDB; reads serve from an
//! in-memory cache rebuilt from `CF_CANTON_ANALYTICS` at startup.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tenzro_storage::{KvStore, CF_CANTON_ANALYTICS};

use crate::error::{NodeError, Result};

/// Per-API-key Canton usage aggregate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CantonKeyAnalytics {
    /// API key's non-secret handle (8-byte hex prefix of the SHA-256 of
    /// the plaintext key).
    pub key_id: String,
    /// Bound Canton User Management Service user id, if any
    /// (`<client_id>@clients` or per-tenant user id). When `None`, this
    /// key uses the operator's primary party — common pre-multi-tenant.
    pub canton_user_id: Option<String>,
    /// Total successful canton-scoped RPC calls.
    pub calls_total: u64,
    /// Total canton-scoped calls that returned an error.
    pub errors_total: u64,
    /// Per-method call counts. Keys are the JSON-RPC method names
    /// (e.g. `tenzro_canton_submitCommand`, `tenzro_canton_listContracts`).
    /// Unbounded in principle, but bounded in practice by the canton
    /// surface (~20 methods).
    pub calls_by_method: HashMap<String, u64>,
    /// Per-method error counts.
    pub errors_by_method: HashMap<String, u64>,
    /// First time this key was observed making a canton call (unix
    /// seconds). `None` until the first increment.
    pub first_seen_at: Option<i64>,
    /// Most recent canton call (unix seconds). `None` if no calls yet.
    pub last_called_at: Option<i64>,
}

impl CantonKeyAnalytics {
    fn empty(key_id: String, canton_user_id: Option<String>) -> Self {
        Self {
            key_id,
            canton_user_id,
            calls_total: 0,
            errors_total: 0,
            calls_by_method: HashMap::new(),
            errors_by_method: HashMap::new(),
            first_seen_at: None,
            last_called_at: None,
        }
    }
}

/// In-memory + persistent per-tenant canton-call counter.
///
/// Cheap to construct (one prefix scan), cheap to increment (RwLock
/// write + one `KvStore::put`). Hot path is single-key so contention is
/// minimal.
pub struct CantonAnalyticsManager {
    storage: Arc<dyn KvStore>,
    cache: RwLock<HashMap<String, CantonKeyAnalytics>>,
}

impl std::fmt::Debug for CantonAnalyticsManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CantonAnalyticsManager")
            .field("cached", &self.cache.read().len())
            .finish()
    }
}

impl CantonAnalyticsManager {
    /// Hydrates from `CF_CANTON_ANALYTICS` so historical counters
    /// survive node restarts.
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
            .scan_prefix(CF_CANTON_ANALYTICS, b"canton_analytics:")
            .map_err(|e| {
                NodeError::Internal(format!("canton_analytics hydrate scan failed: {}", e))
            })?;

        let mut cache = self.cache.write();
        for (key, value) in entries {
            let key_id = match std::str::from_utf8(&key) {
                Ok(k) => k.trim_start_matches("canton_analytics:").to_string(),
                Err(_) => continue,
            };
            let record: CantonKeyAnalytics = match serde_json::from_slice(&value) {
                Ok(r) => r,
                Err(_) => continue,
            };
            cache.insert(key_id, record);
        }
        Ok(())
    }

    /// Record one canton-scoped RPC call against `key_id`. `success`
    /// distinguishes ok-path from error-path counters. `canton_user_id`
    /// is the bound tenant; it's set on first contact and never
    /// overwritten on subsequent calls (so a re-binding has to flow
    /// through the API-key path).
    pub fn record_call(
        &self,
        key_id: &str,
        canton_user_id: Option<&str>,
        method: &str,
        success: bool,
    ) -> Result<()> {
        let now = chrono::Utc::now().timestamp();

        let record = {
            let mut cache = self.cache.write();
            let entry = cache.entry(key_id.to_string()).or_insert_with(|| {
                CantonKeyAnalytics::empty(
                    key_id.to_string(),
                    canton_user_id.map(|s| s.to_string()),
                )
            });

            if entry.canton_user_id.is_none() {
                if let Some(uid) = canton_user_id {
                    entry.canton_user_id = Some(uid.to_string());
                }
            }

            if entry.first_seen_at.is_none() {
                entry.first_seen_at = Some(now);
            }
            entry.last_called_at = Some(now);

            if success {
                entry.calls_total = entry.calls_total.saturating_add(1);
                *entry
                    .calls_by_method
                    .entry(method.to_string())
                    .or_insert(0) += 1;
            } else {
                entry.errors_total = entry.errors_total.saturating_add(1);
                *entry
                    .errors_by_method
                    .entry(method.to_string())
                    .or_insert(0) += 1;
            }

            entry.clone()
        };

        let storage_key = format!("canton_analytics:{}", key_id);
        let value = serde_json::to_vec(&record)
            .map_err(|e| NodeError::Internal(format!("canton_analytics serialize: {}", e)))?;
        self.storage
            .put(CF_CANTON_ANALYTICS, storage_key.as_bytes(), &value)
            .map_err(|e| NodeError::Internal(format!("canton_analytics put: {}", e)))?;

        Ok(())
    }

    /// Looks up the aggregate for one key.
    pub fn get(&self, key_id: &str) -> Option<CantonKeyAnalytics> {
        self.cache.read().get(key_id).cloned()
    }

    /// Snapshot every aggregate. The caller is responsible for any
    /// pagination — there are at most as many records as issued API
    /// keys with the canton scope.
    pub fn list_all(&self) -> Vec<CantonKeyAnalytics> {
        self.cache.read().values().cloned().collect()
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
    fn record_call_increments_counters() {
        let store = mem_store();
        let mgr = CantonAnalyticsManager::new(store).unwrap();

        mgr.record_call("k1", Some("tenzro-labs@clients"), "tenzro_canton_listContracts", true)
            .unwrap();
        mgr.record_call("k1", Some("tenzro-labs@clients"), "tenzro_canton_listContracts", true)
            .unwrap();
        mgr.record_call("k1", Some("tenzro-labs@clients"), "tenzro_canton_submitCommand", false)
            .unwrap();

        let agg = mgr.get("k1").unwrap();
        assert_eq!(agg.calls_total, 2);
        assert_eq!(agg.errors_total, 1);
        assert_eq!(agg.canton_user_id.as_deref(), Some("tenzro-labs@clients"));
        assert_eq!(
            agg.calls_by_method.get("tenzro_canton_listContracts"),
            Some(&2)
        );
        assert_eq!(
            agg.errors_by_method.get("tenzro_canton_submitCommand"),
            Some(&1)
        );
        assert!(agg.first_seen_at.is_some());
        assert!(agg.last_called_at.is_some());
    }

    #[test]
    fn hydrate_restores_counters() {
        let store = mem_store();
        let mgr = CantonAnalyticsManager::new(store.clone()).unwrap();
        mgr.record_call("k1", Some("tenzro-labs@clients"), "tenzro_canton_listContracts", true)
            .unwrap();
        mgr.record_call("k2", Some("acme@clients"), "tenzro_canton_listContracts", true)
            .unwrap();
        drop(mgr);

        let mgr2 = CantonAnalyticsManager::new(store).unwrap();
        assert_eq!(mgr2.list_all().len(), 2);
        let k1 = mgr2.get("k1").unwrap();
        assert_eq!(k1.calls_total, 1);
        assert_eq!(k1.canton_user_id.as_deref(), Some("tenzro-labs@clients"));
    }

    #[test]
    fn bind_canton_user_id_lazily_on_first_call_with_user() {
        let store = mem_store();
        let mgr = CantonAnalyticsManager::new(store).unwrap();
        mgr.record_call("k1", None, "tenzro_canton_listContracts", true)
            .unwrap();
        assert!(mgr.get("k1").unwrap().canton_user_id.is_none());
        mgr.record_call("k1", Some("tenzro-labs@clients"), "tenzro_canton_listContracts", true)
            .unwrap();
        assert_eq!(
            mgr.get("k1").unwrap().canton_user_id.as_deref(),
            Some("tenzro-labs@clients")
        );
    }
}
