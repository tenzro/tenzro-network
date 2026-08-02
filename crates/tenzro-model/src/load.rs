//! Load tracking and capacity estimation for inference providers.
//!
//! Provides per-model active request tracking with RAII guards, hardware-based
//! capacity estimation, and load level classification.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

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
#[derive(Debug)]
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
#[derive(Debug)]
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
/// Ceiling on per-model concurrency, whatever the memory arithmetic says.
///
/// Matched to the batching engine's sequence-slot pool: a request past the
/// last KV slot cannot be interleaved into a decode however much memory is
/// free, so admitting more only deepens a queue. Keeping the two numbers
/// equal means the per-model cap and the engine agree about what "full"
/// means instead of one silently binding before the other.
///
/// The previous ceiling of 8 predates the batching engine and was the reason
/// a 0.6B model on a 121 GiB machine served two requests at a time.
pub const MAX_CONCURRENT_CEILING: u32 = 32;

pub fn estimate_max_concurrent(
    model_min_ram_gb: u32,
    total_ram_gb: f64,
    gpu_vram_gb: f64,
    has_gpu: bool,
) -> u32 {
    // One formula over whichever memory pool the weights land in.
    //
    // The GPU and CPU cases were previously two different calculations, which
    // is how a unified-memory machine — where they are the same pool — ended
    // up with an answer that depended on which branch happened to be taken.
    // The question is the same either way: after the weights, how many
    // requests' worth of KV cache is there room for?
    //
    // The old CPU branch also carried a comment that llama.cpp holds a mutex
    // so only one request runs at a time. The batching engine replaced that:
    // requests are interleaved through one context across a slot pool, so
    // memory headroom is the real bound.
    let pool_gb = if has_gpu && gpu_vram_gb > 0.0 {
        gpu_vram_gb
    } else {
        total_ram_gb
    };

    // Per-request KV cost as a fraction of the model's footprint. Rough — the
    // real cost scales with context length, which this signature does not see
    // — but the right order of magnitude, and it errs high for small models.
    let kv_per_request_gb = (model_min_ram_gb as f64) * 0.1;
    let headroom_gb = (pool_gb - model_min_ram_gb as f64).max(0.0);
    let by_memory = if kv_per_request_gb > 0.0 {
        (headroom_gb / kv_per_request_gb).floor() as u32
    } else {
        MAX_CONCURRENT_CEILING
    };
    by_memory.clamp(1, MAX_CONCURRENT_CEILING)
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
    fn concurrency_scales_with_memory_headroom_not_with_the_branch_taken() {
        // The unified-memory bug this replaced: GPU and CPU were two separate
        // formulas, so a machine where VRAM *is* system RAM got an answer that
        // depended on which branch detection happened to pick. Same pool, same
        // headroom, same answer.
        let as_gpu = estimate_max_concurrent(2, 121.0, 121.0, true);
        let as_cpu = estimate_max_concurrent(2, 121.0, 0.0, false);
        assert_eq!(as_gpu, as_cpu, "one pool must give one answer");
    }

    #[test]
    fn a_small_model_on_a_large_machine_is_not_throttled_to_a_handful() {
        // The concrete regression from bring-up: qwen3-0.6b (min_ram 2 GiB) on
        // a 121 GiB box served TWO concurrent requests. It should saturate the
        // batching engine's slot pool instead.
        assert_eq!(
            estimate_max_concurrent(2, 121.0, 121.0, true),
            MAX_CONCURRENT_CEILING
        );
        assert_eq!(
            estimate_max_concurrent(1, 121.0, 0.0, false),
            MAX_CONCURRENT_CEILING
        );
    }

    #[test]
    fn a_model_that_barely_fits_gets_a_single_slot() {
        // No headroom for KV means no room for a second sequence, whichever
        // pool it is in.
        assert_eq!(estimate_max_concurrent(8, 16.0, 8.0, true), 1);
        assert_eq!(estimate_max_concurrent(4, 4.0, 0.0, false), 1);
    }

    #[test]
    fn concurrency_never_exceeds_the_batching_engines_slot_pool() {
        // Past the last KV slot a request cannot be interleaved into a decode
        // however much memory is free, so admitting more only deepens a queue.
        for (model_gb, pool_gb) in [(1u32, 1024.0), (2, 512.0), (4, 4096.0)] {
            assert!(estimate_max_concurrent(model_gb, pool_gb, pool_gb, true) <= 32);
        }
    }

    #[test]
    fn headroom_translates_into_slots_proportionally() {
        // 4 GiB model, 6 GiB pool -> 2 GiB headroom at 0.4 GiB per request.
        assert_eq!(estimate_max_concurrent(4, 16.0, 6.0, true), 5);
        // Double the headroom, double the slots.
        assert_eq!(estimate_max_concurrent(4, 16.0, 8.0, true), 10);
    }

    #[test]
    fn test_try_acquire_nonexistent_model() {
        let tracker = LoadTracker::new();
        assert!(tracker.try_acquire("nonexistent").is_err());
    }
}
