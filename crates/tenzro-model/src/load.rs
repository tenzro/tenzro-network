//! Load tracking and capacity estimation for inference providers.
//!
//! Provides per-model active request tracking with RAII guards, hardware-based
//! capacity estimation, and load level classification.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};

/// Load level for a model service instance, derived from utilization percentage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoadLevel {
    /// 0% utilization -- idle, no requests
    Idle,
    /// 1-50% utilization -- accepting requests freely
    Available,
    /// 51-80% utilization -- accepting requests but load is notable
    Busy,
    /// 81-99% utilization -- near capacity, may experience queuing
    NearCapacity,
    /// 100% utilization -- at max, new requests will be rejected
    AtCapacity,
}

impl std::fmt::Display for LoadLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "idle"),
            Self::Available => write!(f, "available"),
            Self::Busy => write!(f, "busy"),
            Self::NearCapacity => write!(f, "near_capacity"),
            Self::AtCapacity => write!(f, "at_capacity"),
        }
    }
}

impl LoadLevel {
    /// Derive load level from utilization percentage (0-100).
    pub fn from_utilization(percent: u8) -> Self {
        match percent {
            0 => Self::Idle,
            1..=50 => Self::Available,
            51..=80 => Self::Busy,
            81..=99 => Self::NearCapacity,
            _ => Self::AtCapacity,
        }
    }
}

/// Snapshot of load state for a single model, suitable for serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelLoadSnapshot {
    pub model_id: String,
    pub active_requests: u32,
    pub max_concurrent: u32,
    pub utilization_percent: u8,
    pub load_level: LoadLevel,
}

/// Per-model atomic request counter.
struct ModelLoadState {
    active: AtomicU32,
    max_concurrent: u32,
}

/// Tracks active inference load across all served models on this node.
///
/// Uses atomic counters and RAII guards to ensure request counts are always
/// accurate, even in the face of panics or early returns.
pub struct LoadTracker {
    models: Arc<DashMap<String, Arc<ModelLoadState>>>,
}

impl LoadTracker {
    /// Create a new load tracker.
    pub fn new() -> Self {
        Self {
            models: Arc::new(DashMap::new()),
        }
    }

    /// Register a model with its computed max concurrent requests.
    pub fn register_model(&self, model_id: &str, max_concurrent: u32) {
        self.models.insert(
            model_id.to_string(),
            Arc::new(ModelLoadState {
                active: AtomicU32::new(0),
                max_concurrent,
            }),
        );
    }

    /// Unregister a model (when stopped serving).
    pub fn unregister_model(&self, model_id: &str) {
        self.models.remove(model_id);
    }

    /// Try to acquire a load slot for a model.
    ///
    /// Returns `Ok(LoadGuard)` if capacity is available. The guard automatically
    /// decrements the active count when dropped. Returns `Err(())` if the model
    /// is at capacity or not tracked.
    #[allow(clippy::result_unit_err)]
    pub fn try_acquire(&self, model_id: &str) -> Result<LoadGuard, ()> {
        if let Some(state) = self.models.get(model_id) {
            let prev = state.active.fetch_add(1, Ordering::SeqCst);
            if prev >= state.max_concurrent {
                // Roll back -- we exceeded capacity
                state.active.fetch_sub(1, Ordering::SeqCst);
                return Err(());
            }
            Ok(LoadGuard {
                state: state.value().clone(),
            })
        } else {
            Err(())
        }
    }

    /// Get a snapshot of load state for a specific model.
    pub fn snapshot(&self, model_id: &str) -> Option<ModelLoadSnapshot> {
        self.models.get(model_id).map(|state| {
            let active = state.active.load(Ordering::SeqCst);
            let max = state.max_concurrent;
            let util = if max == 0 {
                0
            } else {
                ((active as f64 / max as f64) * 100.0).min(100.0) as u8
            };
            ModelLoadSnapshot {
                model_id: model_id.to_string(),
                active_requests: active,
                max_concurrent: max,
                utilization_percent: util,
                load_level: LoadLevel::from_utilization(util),
            }
        })
    }

    /// Get snapshots for all tracked models.
    pub fn all_snapshots(&self) -> Vec<ModelLoadSnapshot> {
        self.models
            .iter()
            .map(|entry| {
                let model_id = entry.key().clone();
                let active = entry.value().active.load(Ordering::SeqCst);
                let max = entry.value().max_concurrent;
                let util = if max == 0 {
                    0
                } else {
                    ((active as f64 / max as f64) * 100.0).min(100.0) as u8
                };
                ModelLoadSnapshot {
                    model_id,
                    active_requests: active,
                    max_concurrent: max,
                    utilization_percent: util,
                    load_level: LoadLevel::from_utilization(util),
                }
            })
            .collect()
    }
}

impl Default for LoadTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard that decrements the active request count on drop.
///
/// This ensures that the count is always correct, even if the inference
/// call panics or returns early.
pub struct LoadGuard {
    state: Arc<ModelLoadState>,
}

impl Drop for LoadGuard {
    fn drop(&mut self) {
        self.state.active.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Estimate max concurrent requests for a model on given hardware.
///
/// For CPU-only inference with llama.cpp (which holds a Mutex per model context),
/// true parallelism is 1. The concurrent limit represents how many requests can
/// be queued/in-flight (mutex waiters + 1 running).
///
/// For GPU inference, each request needs a separate context in VRAM.
pub fn estimate_max_concurrent(
    model_min_ram_gb: u32,
    total_ram_gb: f64,
    gpu_vram_gb: f64,
    has_gpu: bool,
) -> u32 {
    if has_gpu && gpu_vram_gb > 0.0 {
        // GPU: model weights on VRAM, each concurrent request needs ~model_size * 0.1 for KV cache
        let kv_cache_per_request_gb = (model_min_ram_gb as f64) * 0.1;
        let available_for_kv = (gpu_vram_gb - model_min_ram_gb as f64).max(0.0);
        let gpu_concurrent = if kv_cache_per_request_gb > 0.0 {
            (available_for_kv / kv_cache_per_request_gb).floor() as u32
        } else {
            1
        };
        gpu_concurrent.clamp(1, 8)
    } else {
        // CPU-only: llama.cpp holds a Mutex so only 1 runs at a time.
        // Allow queueing based on RAM headroom.
        let ram_ratio = total_ram_gb / model_min_ram_gb.max(1) as f64;
        if ram_ratio >= 4.0 {
            4
        } else if ram_ratio >= 2.0 {
            2
        } else {
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_level_from_utilization() {
        assert_eq!(LoadLevel::from_utilization(0), LoadLevel::Idle);
        assert_eq!(LoadLevel::from_utilization(1), LoadLevel::Available);
        assert_eq!(LoadLevel::from_utilization(50), LoadLevel::Available);
        assert_eq!(LoadLevel::from_utilization(51), LoadLevel::Busy);
        assert_eq!(LoadLevel::from_utilization(80), LoadLevel::Busy);
        assert_eq!(LoadLevel::from_utilization(81), LoadLevel::NearCapacity);
        assert_eq!(LoadLevel::from_utilization(99), LoadLevel::NearCapacity);
        assert_eq!(LoadLevel::from_utilization(100), LoadLevel::AtCapacity);
        assert_eq!(LoadLevel::from_utilization(255), LoadLevel::AtCapacity);
    }

    #[test]
    fn test_load_level_display() {
        assert_eq!(LoadLevel::Idle.to_string(), "idle");
        assert_eq!(LoadLevel::Available.to_string(), "available");
        assert_eq!(LoadLevel::Busy.to_string(), "busy");
        assert_eq!(LoadLevel::NearCapacity.to_string(), "near_capacity");
        assert_eq!(LoadLevel::AtCapacity.to_string(), "at_capacity");
    }

    #[test]
    fn test_load_tracker_register_and_snapshot() {
        let tracker = LoadTracker::new();
        tracker.register_model("gemma3-270m", 2);

        let snap = tracker.snapshot("gemma3-270m").unwrap();
        assert_eq!(snap.model_id, "gemma3-270m");
        assert_eq!(snap.active_requests, 0);
        assert_eq!(snap.max_concurrent, 2);
        assert_eq!(snap.utilization_percent, 0);
        assert_eq!(snap.load_level, LoadLevel::Idle);
    }

    #[test]
    fn test_snapshot_nonexistent_model() {
        let tracker = LoadTracker::new();
        assert!(tracker.snapshot("nonexistent").is_none());
    }

    #[test]
    fn test_try_acquire_within_capacity() {
        let tracker = LoadTracker::new();
        tracker.register_model("test-model", 2);

        let guard1 = tracker.try_acquire("test-model");
        assert!(guard1.is_ok());

        let snap = tracker.snapshot("test-model").unwrap();
        assert_eq!(snap.active_requests, 1);
        assert_eq!(snap.utilization_percent, 50);
        assert_eq!(snap.load_level, LoadLevel::Available);

        let guard2 = tracker.try_acquire("test-model");
        assert!(guard2.is_ok());

        let snap = tracker.snapshot("test-model").unwrap();
        assert_eq!(snap.active_requests, 2);
        assert_eq!(snap.utilization_percent, 100);
        assert_eq!(snap.load_level, LoadLevel::AtCapacity);
    }

    #[test]
    fn test_try_acquire_at_capacity_rejected() {
        let tracker = LoadTracker::new();
        tracker.register_model("test-model", 1);

        let _guard = tracker.try_acquire("test-model").unwrap();
        let result = tracker.try_acquire("test-model");
        assert!(result.is_err());

        // Active count should still be 1, not 2
        let snap = tracker.snapshot("test-model").unwrap();
        assert_eq!(snap.active_requests, 1);
    }

    #[test]
    fn test_load_guard_drops_correctly() {
        let tracker = LoadTracker::new();
        tracker.register_model("test-model", 2);

        {
            let _guard = tracker.try_acquire("test-model").unwrap();
            let snap = tracker.snapshot("test-model").unwrap();
            assert_eq!(snap.active_requests, 1);
        }
        // Guard dropped here

        let snap = tracker.snapshot("test-model").unwrap();
        assert_eq!(snap.active_requests, 0);
        assert_eq!(snap.load_level, LoadLevel::Idle);
    }

    #[test]
    fn test_unregister_model() {
        let tracker = LoadTracker::new();
        tracker.register_model("test-model", 2);
        assert!(tracker.snapshot("test-model").is_some());

        tracker.unregister_model("test-model");
        assert!(tracker.snapshot("test-model").is_none());
    }

    #[test]
    fn test_all_snapshots() {
        let tracker = LoadTracker::new();
        tracker.register_model("model-a", 2);
        tracker.register_model("model-b", 4);

        let snaps = tracker.all_snapshots();
        assert_eq!(snaps.len(), 2);
    }

    #[test]
    fn test_estimate_max_concurrent_cpu_only() {
        // Tight: 2GB model, 4GB total -> ratio 2.0 -> 2 concurrent
        assert_eq!(estimate_max_concurrent(2, 4.0, 0.0, false), 2);

        // Comfortable: 2GB model, 8GB total -> ratio 4.0 -> 4 concurrent
        assert_eq!(estimate_max_concurrent(2, 8.0, 0.0, false), 4);

        // Very tight: 4GB model, 4GB total -> ratio 1.0 -> 1 concurrent
        assert_eq!(estimate_max_concurrent(4, 4.0, 0.0, false), 1);

        // Small model on big machine: 1GB model, 16GB total -> ratio 16.0 -> 4 concurrent
        assert_eq!(estimate_max_concurrent(1, 16.0, 0.0, false), 4);
    }

    #[test]
    fn test_estimate_max_concurrent_gpu() {
        // 2GB model, 8GB VRAM -> available 6GB, KV cache 0.2GB per req -> 30, clamped to 8
        assert_eq!(estimate_max_concurrent(2, 16.0, 8.0, true), 8);

        // 4GB model, 6GB VRAM -> available 2GB, KV cache 0.4GB per req -> 5
        assert_eq!(estimate_max_concurrent(4, 16.0, 6.0, true), 5);

        // 8GB model, 8GB VRAM -> available 0GB -> min 1
        assert_eq!(estimate_max_concurrent(8, 16.0, 8.0, true), 1);
    }

    #[test]
    fn test_try_acquire_nonexistent_model() {
        let tracker = LoadTracker::new();
        assert!(tracker.try_acquire("nonexistent").is_err());
    }
}
