//! Liveness sweeper for model service endpoints.
//!
//! A provider that serves a model writes its endpoint under
//! `CF_MODEL_SERVICES` and refreshes it with heartbeats. Without a liveness
//! layer an endpoint whose provider has gone away keeps showing as active.
//! The sweeper flips a silent endpoint to `Inactive` after `stale_after` and
//! deletes it after `purge_after`.
//!
//! Each cycle scans the column family once, decodes each row and rewrites
//! only the rows that change; listing and heartbeat RPCs keep serving
//! concurrently.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use tenzro_storage::kv::{CF_MODEL_SERVICES, KvStore};

const DEFAULT_SWEEP_INTERVAL_SECS: u64 = 300; // 5 minutes

/// Liveness timings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LivenessConfig {
    /// How often the sweeper task wakes up.
    pub sweep_interval_secs: u64,
    /// Model service endpoint silent past this → marked Inactive.
    pub model_service_stale_after_secs: u64,
    /// Inactive model service endpoint row deleted after this.
    pub model_service_purge_after_secs: u64,
}

impl Default for LivenessConfig {
    fn default() -> Self {
        Self {
            sweep_interval_secs: DEFAULT_SWEEP_INTERVAL_SECS,
            // 5min silent → Inactive, 1h → purged.
            model_service_stale_after_secs: 5 * 60,
            model_service_purge_after_secs: 60 * 60,
        }
    }
}

/// A single sweep cycle's results, for the `tenzro_livenessStats` RPC and
/// tracing logs.
#[derive(Debug, Clone, Default, Serialize)]
pub struct SweepStats {
    pub model_services_marked_inactive: u64,
    pub model_services_purged: u64,
}

impl SweepStats {
    fn total_changes(&self) -> u64 {
        self.model_services_marked_inactive + self.model_services_purged
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Owns the periodic sweeper task. Drop the handle on shutdown to stop it.
pub struct LivenessSweeper {
    pub config: LivenessConfig,
    handle: Option<JoinHandle<()>>,
}

impl LivenessSweeper {
    /// Stops the background task by aborting the JoinHandle. Idempotent.
    pub fn stop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

impl Drop for LivenessSweeper {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Spawns the sweeper task. It runs until aborted; the returned
/// [`LivenessSweeper`] is held by the node so shutdown drops it.
pub fn spawn_liveness_sweeper(
    storage: Arc<dyn KvStore>,
    config: LivenessConfig,
) -> LivenessSweeper {
    let interval = config.sweep_interval_secs.max(10);
    let cfg = config.clone();

    let handle = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(interval));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        // Skip the immediate first tick — give the rest of startup a moment
        // before we start scanning.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            match run_sweep(&storage, &cfg) {
                Ok(stats) => {
                    if stats.total_changes() > 0 {
                        info!(
                            target: "liveness",
                            "Sweep complete: {:?}", stats
                        );
                    } else {
                        debug!(target: "liveness", "Sweep clean — no stale resources");
                    }
                }
                Err(e) => warn!(target: "liveness", "Sweep error: {}", e),
            }
        }
    });

    LivenessSweeper {
        config,
        handle: Some(handle),
    }
}

/// Runs one sweep. Synchronous because `KvStore` operations are blocking.
pub fn run_sweep(storage: &Arc<dyn KvStore>, cfg: &LivenessConfig) -> Result<SweepStats, String> {
    let mut stats = SweepStats::default();
    sweep_model_services(storage, cfg, now_secs(), &mut stats)?;
    Ok(stats)
}

// ─────────────────── Model service endpoints ───────────────────

fn sweep_model_services(
    storage: &Arc<dyn KvStore>,
    cfg: &LivenessConfig,
    now: u64,
    stats: &mut SweepStats,
) -> Result<(), String> {
    // Model service rows are written by tenzro_serveModel under
    // CF_MODEL_SERVICES with provider-scoped keys. We treat any row whose
    // last_seen_at is older than stale_after as Inactive, and purge after
    // purge_after. The exact field name varies — try a small struct that
    // captures the common shape; rows that don't decode are left alone.
    #[derive(Serialize, Deserialize)]
    struct ServiceShadow {
        #[serde(default)]
        status: serde_json::Value,
        #[serde(default)]
        last_seen_at: u64,
        #[serde(default)]
        last_heartbeat: Option<u64>,
        #[serde(flatten)]
        _rest: serde_json::Value,
    }

    let keys = storage
        .get_keys_with_prefix(CF_MODEL_SERVICES, b"")
        .map_err(|e| format!("CF_MODEL_SERVICES scan: {}", e))?;
    for key in keys {
        let bytes = match storage.get(CF_MODEL_SERVICES, &key) {
            Ok(Some(b)) => b,
            _ => continue,
        };
        let svc: ServiceShadow = match serde_json::from_slice(&bytes) {
            Ok(s) => s,
            Err(_) => continue,
        };
        // Prefer last_seen_at; fall back to last_heartbeat.
        let last = if svc.last_seen_at > 0 {
            svc.last_seen_at
        } else {
            svc.last_heartbeat.unwrap_or(0)
        };
        if last == 0 {
            // No liveness signal at all — leave alone (charitable).
            continue;
        }
        let age = now.saturating_sub(last);
        let status_str = svc
            .status
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| svc.status.to_string());

        if status_str.contains("Inactive") && age >= cfg.model_service_purge_after_secs {
            let _ = storage.delete(CF_MODEL_SERVICES, &key);
            stats.model_services_purged += 1;
            continue;
        }
        if !status_str.contains("Inactive") && age >= cfg.model_service_stale_after_secs {
            // Surgical mutation: re-encode the original JSON with status
            // overridden to "Inactive". Avoids losing fields we don't model.
            if let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&bytes)
                && let Some(obj) = value.as_object_mut()
            {
                obj.insert(
                    "status".to_string(),
                    serde_json::Value::String("Inactive".to_string()),
                );
                if let Ok(updated) = serde_json::to_vec(&value) {
                    let _ = storage.put(CF_MODEL_SERVICES, &key, &updated);
                    stats.model_services_marked_inactive += 1;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::kv::MemoryStore;

    fn fast_config() -> LivenessConfig {
        LivenessConfig {
            sweep_interval_secs: 10,
            model_service_stale_after_secs: 10,
            model_service_purge_after_secs: 100,
        }
    }

    #[test]
    fn a_silent_endpoint_goes_inactive_then_is_purged() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let row = serde_json::json!({ "status": "Active", "last_seen_at": now_secs() - 50, "model_id": "m" });
        storage
            .put(
                CF_MODEL_SERVICES,
                b"p:m",
                &serde_json::to_vec(&row).unwrap(),
            )
            .unwrap();
        let stats = run_sweep(&storage, &fast_config()).unwrap();
        assert_eq!(stats.model_services_marked_inactive, 1);
        let after: serde_json::Value =
            serde_json::from_slice(&storage.get(CF_MODEL_SERVICES, b"p:m").unwrap().unwrap())
                .unwrap();
        assert_eq!(after["status"], "Inactive");
        assert_eq!(after["model_id"], "m");

        let old = serde_json::json!({ "status": "Inactive", "last_seen_at": now_secs() - 500 });
        storage
            .put(
                CF_MODEL_SERVICES,
                b"p:m",
                &serde_json::to_vec(&old).unwrap(),
            )
            .unwrap();
        assert_eq!(
            run_sweep(&storage, &fast_config())
                .unwrap()
                .model_services_purged,
            1
        );
        assert!(storage.get(CF_MODEL_SERVICES, b"p:m").unwrap().is_none());
    }

    #[test]
    fn a_fresh_endpoint_is_left_alone() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let row = serde_json::json!({ "status": "Active", "last_seen_at": now_secs() });
        storage
            .put(
                CF_MODEL_SERVICES,
                b"p:m",
                &serde_json::to_vec(&row).unwrap(),
            )
            .unwrap();
        assert_eq!(
            run_sweep(&storage, &fast_config()).unwrap().total_changes(),
            0
        );
    }
}
