//! What the node gives back when memory or swap runs short.
//!
//! The load monitor calls each [`Reclaimer`] once when the node enters HIGH
//! or CRITICAL with memory as the reason, and calls [`Reclaimer::relax`] when
//! the level falls below HIGH again. The reclaimers drop only what the node
//! can rebuild: the store's block cache refills from disk, and an unloaded
//! model loads again on its next request. Pinned models are not touched; a
//! pin is an operator's or a renter's guarantee.

use std::sync::Arc;

use crate::load_monitor::{LoadLevel, Reclaimer};

/// Share of its normal size the store's block cache keeps at HIGH.
pub const CACHE_KEEP_HIGH_PERCENT: u8 = 25;
/// Share of its normal size the store's block cache keeps at CRITICAL.
pub const CACHE_KEEP_CRITICAL_PERCENT: u8 = 10;

/// Shrinks the store's block cache while memory is short.
pub struct StoreCache {
    store: Arc<dyn tenzro_storage::KvStore>,
}

impl StoreCache {
    /// A reclaimer over `store`.
    pub fn reclaimer(store: Arc<dyn tenzro_storage::KvStore>) -> Arc<dyn Reclaimer> {
        Arc::new(Self { store })
    }
}

impl Reclaimer for StoreCache {
    fn name(&self) -> &'static str {
        "store block cache"
    }

    fn reclaim(&self, level: LoadLevel) -> u64 {
        let keep = if level >= LoadLevel::Critical {
            CACHE_KEEP_CRITICAL_PERCENT
        } else {
            CACHE_KEEP_HIGH_PERCENT
        };
        self.store.shrink_caches(keep)
    }

    fn relax(&self) {
        self.store.restore_caches();
    }
}

/// Unloads idle models that are not pinned.
#[cfg(feature = "inference")]
pub struct IdleModels {
    runtime: Arc<tenzro_model::runtime::ModelRuntime>,
    lifecycle: Arc<tenzro_model::lifecycle::ModelLifecycle>,
}

#[cfg(feature = "inference")]
impl IdleModels {
    /// A reclaimer over the node's model runtime.
    pub fn reclaimer(
        runtime: Arc<tenzro_model::runtime::ModelRuntime>,
        lifecycle: Arc<tenzro_model::lifecycle::ModelLifecycle>,
    ) -> Arc<dyn Reclaimer> {
        Arc::new(Self { runtime, lifecycle })
    }
}

#[cfg(feature = "inference")]
impl Reclaimer for IdleModels {
    fn name(&self) -> &'static str {
        "idle models"
    }

    fn reclaim(&self, _level: LoadLevel) -> u64 {
        let (runtime, lifecycle) = (self.runtime.clone(), self.lifecycle.clone());
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return 0;
        };
        handle.spawn(async move {
            for id in runtime.list_loaded() {
                if lifecycle.is_pinned(&id) || !lifecycle.begin_evict(&id) {
                    continue;
                }
                match runtime.unload_model(&id).await {
                    Ok(()) => lifecycle.finish_evict(&id),
                    Err(_) => lifecycle.finish_warm(&id, std::time::Duration::ZERO),
                }
            }
        });
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::load_monitor::{
        ENTER_SAMPLES, LoadLadder, LoadMonitor, LoadThresholds, current_level,
    };
    use std::sync::Mutex;

    /// Memory the test holds and gives back when asked.
    struct Ballast(Mutex<Vec<Vec<u8>>>);

    impl Reclaimer for Ballast {
        fn name(&self) -> &'static str {
            "test ballast"
        }
        fn reclaim(&self, _: LoadLevel) -> u64 {
            let mut held = self.0.lock().unwrap();
            let freed: usize = held.iter().map(Vec::len).sum();
            held.clear();
            held.shrink_to_fit();
            freed as u64
        }
    }

    fn oom_kills() -> Option<u64> {
        let rel = std::fs::read_to_string("/proc/self/cgroup")
            .ok()?
            .lines()
            .find_map(|l| l.strip_prefix("0::"))?
            .trim()
            .to_string();
        let events = std::fs::read_to_string(
            std::path::Path::new("/sys/fs/cgroup")
                .join(rel.trim_start_matches('/'))
                .join("memory.events"),
        )
        .ok()?;
        events
            .lines()
            .find_map(|l| l.strip_prefix("oom_kill "))?
            .trim()
            .parse()
            .ok()
    }

    /// Run by `scripts/launch/load-gate.sh` inside a cgroup with
    /// `MemoryHigh` and `MemoryMax` set and `TENZRO_SQUEEZE=1`: the process
    /// allocates until the cgroup's use crosses the HIGH threshold, the
    /// memory guard gives the ballast back, and the process must not be
    /// OOM-killed. Without the variable the test does nothing.
    #[test]
    fn squeeze_a_real_cgroup_and_survive() {
        if std::env::var("TENZRO_SQUEEZE").is_err() {
            eprintln!(
                "squeeze: not under a cgroup limit, skipped (the fixture test covers the logic)"
            );
            return;
        }
        let monitor = LoadMonitor::new(None);
        let ballast = Arc::new(Ballast(Mutex::new(Vec::new())));
        monitor.register(ballast.clone());
        let mut ladder = LoadLadder::new(LoadThresholds::default());
        let mut reached = false;
        for _ in 0..4096 {
            ballast.0.lock().unwrap().push(vec![1u8; 4 << 20]);
            let s = monitor.sample(None);
            let used = s
                .cgroup_used_pct
                .expect("run under a cgroup with MemoryHigh set");
            monitor.apply(&mut ladder, s);
            if used >= 93.0 {
                // One more sample confirms the level, as the node's own
                // sampler would.
                for _ in 0..ENTER_SAMPLES {
                    let s = monitor.sample(None);
                    monitor.apply(&mut ladder, s);
                }
                reached = true;
                break;
            }
        }
        assert!(reached, "the cgroup limit was never approached");
        assert!(current_level() >= LoadLevel::High);
        assert!(
            ballast.0.lock().unwrap().is_empty(),
            "the guard did not give memory back"
        );
        assert_eq!(oom_kills().unwrap_or(0), 0, "the process was OOM killed");
        // With the memory returned the level falls back.
        for _ in 0..16 {
            let s = monitor.sample(None);
            monitor.apply(&mut ladder, s);
        }
        assert!(current_level() < LoadLevel::High);
    }
}
