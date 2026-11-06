//! Model lifecycle: a bounded warm set over an unbounded catalog.
//!
//! # Why this exists
//!
//! The catalog holds far more models than the machine can hold at once. The
//! naive responses to that are both bad: refusing everything that is not
//! preloaded makes most of the catalog unreachable, and loading on demand
//! with no bound thrashes the machine until it dies.
//!
//! This module takes the third path. Every catalog model is *servable*; a
//! bounded subset is *warm*. A request for a cold model triggers a load and
//! the caller is told so, rather than being left on a socket until it times
//! out. Which models stay warm is decided by recency, with operator pins for
//! the ones that must never go cold.
//!
//! # Telling the frontend the truth
//!
//! A cold model takes tens of seconds to load. Three ways to handle that:
//!
//! 1. Block the request until the model is ready. The client sees a stall it
//!    cannot distinguish from a hang, and its timeout — not ours — decides
//!    the outcome.
//! 2. Fail with a generic error. The client cannot tell "retry in 20s and
//!    this will work" from "this will never work".
//! 3. Say what is happening: the model is loading, here is roughly how long,
//!    here is when to retry.
//!
//! Only the third lets a frontend render something honest. It is what the
//! HuggingFace Inference API does (`{"error": "Model is currently loading",
//! "estimated_time": 20.0}`), and [`WarmingStatus`] is the same idea with the
//! fields a caller actually needs to act on.
//!
//! The estimate comes from *measured* load times for that specific model
//! ([`LoadHistory`]), not a constant. A 2 GB ASR model and a 35 GB MoE do not
//! take the same time to load, and telling a caller otherwise trains them to
//! ignore the number.
//!
//! # What this module does not do
//!
//! It tracks state and decides eviction order. It does not load or unload
//! anything — the caller owns the runtime handles and does the work, then
//! reports back. Keeping the policy separate from the mechanism is what lets
//! one lifecycle govern llama.cpp models, ONNX sessions, and out-of-process
//! diffusion pipelines, which have nothing else in common.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// Fallback used to estimate a load nobody has measured yet, in bytes per
/// second.
///
/// Deliberately pessimistic. An estimate that is too long makes a caller wait
/// slightly longer than needed; one that is too short makes them retry into a
/// model that is still loading, which looks like a broken API. 300 MB/s is
/// roughly what a cold page-cache read from NVMe plus GGUF parse achieves;
/// a warm page cache beats it comfortably, so first loads are the worst case
/// and that is the case worth quoting.
pub const COLD_LOAD_BYTES_PER_SEC: u64 = 300 * 1024 * 1024;

/// Floor on any quoted estimate. Even a tiny model has fixed setup cost, and
/// quoting "ready in 200ms" invites an immediate retry that arrives too early.
pub const MIN_ESTIMATE_MS: u64 = 1_000;

/// Weight given to the newest measurement when folding it into the running
/// average, in percent. The remainder is carried from history.
///
/// 30% adapts within a few loads when conditions change (page cache warm vs
/// cold, another model competing for I/O) without letting one slow outlier
/// dominate the estimate a caller sees.
pub const HISTORY_EWMA_PCT: u64 = 30;

/// Where a model is in its lifecycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum ModelState {
    /// Not loaded. Servable, but the first request pays the load.
    Cold,
    /// A load is in progress. Concurrent callers join this rather than
    /// starting a second load of the same model.
    Warming {
        /// Milliseconds since the load began.
        elapsed_ms: u64,
        /// Best estimate of milliseconds remaining, from measured history.
        remaining_ms: u64,
        /// How many callers are waiting on this load.
        waiters: usize,
    },
    /// Loaded and serving.
    Warm {
        /// Milliseconds since this model last served a request.
        idle_ms: u64,
        /// Requests currently executing against it.
        in_flight: usize,
    },
    /// Being unloaded. Requests must not be routed here; the caller should
    /// treat it as cold and let it re-warm.
    Evicting,
}

/// What a caller should do about a request for this model.
///
/// Deliberately **not** `Clone`: a cloned [`InFlightGuard`] would decrement
/// the in-flight count twice for one increment, and that counter is the only
/// thing stopping a model being evicted mid-generation.
#[derive(Debug, PartialEq, Eq)]
pub enum Admission {
    /// Serve it now. Holds an in-flight count that blocks eviction until the
    /// returned guard is dropped.
    Ready(InFlightGuard),
    /// The model is loading. Tell the caller, do not block.
    Warming(WarmingStatus),
    /// The caller has been elected to perform the load. It must call
    /// [`ModelLifecycle::finish_warm`] or [`ModelLifecycle::abandon_warm`]
    /// when done, or the model is stuck warming forever.
    LoadRequired(WarmingStatus),
}

/// The wire shape a frontend receives when a model is not ready.
///
/// Serialised into the body of an HTTP 503 alongside a `Retry-After` header,
/// or emitted as an SSE `warming` event on streaming endpoints. Consistent
/// across every modality so one SDK backoff path covers all of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WarmingStatus {
    /// Always `"warming"`, so a client can branch on it without inspecting
    /// the HTTP status.
    pub status: &'static str,
    /// Which model is loading.
    pub model: String,
    /// Best estimate of milliseconds until it can serve.
    pub estimated_ready_ms: u64,
    /// When to retry. Held slightly above the estimate so a well-behaved
    /// client does not arrive before the load finishes.
    pub retry_after_ms: u64,
    /// How many callers are waiting on this same load, this one included.
    pub waiters: usize,
}

impl WarmingStatus {
    fn new(model: &str, remaining_ms: u64, waiters: usize) -> Self {
        Self {
            status: "warming",
            model: model.to_string(),
            estimated_ready_ms: remaining_ms,
            // A 25% margin. Retrying exactly at the estimate means half of
            // all clients arrive early by construction, and an early retry
            // costs a whole round trip plus another wait.
            retry_after_ms: remaining_ms + remaining_ms / 4,
            waiters,
        }
    }

    /// Seconds for a `Retry-After` header, which is integer-valued and must
    /// never round down to zero.
    pub fn retry_after_secs(&self) -> u64 {
        self.retry_after_ms.div_ceil(1000).max(1)
    }
}

/// Blocks eviction of a model while a request runs against it.
///
/// Evicting a model mid-generation would free the context out from under a
/// running decode. The guard makes that structurally impossible: eviction
/// only considers models whose in-flight count is zero, and the count cannot
/// reach zero while any guard is alive.
#[derive(Debug)]
pub struct InFlightGuard {
    model_id: String,
    inner: Arc<Mutex<Inner>>,
}

impl PartialEq for InFlightGuard {
    fn eq(&self, other: &Self) -> bool {
        self.model_id == other.model_id
    }
}

impl Eq for InFlightGuard {}

impl InFlightGuard {
    /// Which model this guard holds.
    pub fn model_id(&self) -> &str {
        &self.model_id
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        let mut inner = self.inner.lock();
        if let Some(entry) = inner.entries.get_mut(&self.model_id) {
            entry.in_flight = entry.in_flight.saturating_sub(1);
            entry.last_used = Some(Instant::now());
        }
    }
}

/// Running average of how long a model takes to load.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LoadHistory {
    mean_ms: u64,
    samples: u32,
}

impl LoadHistory {
    fn observe(&mut self, ms: u64) {
        // First real measurement replaces the estimate outright rather than
        // averaging against a guess.
        if self.samples == 0 {
            self.mean_ms = ms;
        } else {
            self.mean_ms = (ms * HISTORY_EWMA_PCT + self.mean_ms * (100 - HISTORY_EWMA_PCT)) / 100;
        }
        self.samples = self.samples.saturating_add(1);
    }
}

#[derive(Debug)]
struct Entry {
    /// `None` until the model has ever been loaded.
    size_bytes: Option<u64>,
    warming_since: Option<Instant>,
    waiters: usize,
    warm: bool,
    evicting: bool,
    in_flight: usize,
    last_used: Option<Instant>,
    history: LoadHistory,
}

impl Entry {
    fn new(size_bytes: Option<u64>) -> Self {
        Self {
            size_bytes,
            warming_since: None,
            waiters: 0,
            warm: false,
            evicting: false,
            in_flight: 0,
            last_used: None,
            history: LoadHistory {
                mean_ms: 0,
                samples: 0,
            },
        }
    }

    /// Estimated total load time: measured if we have it, size-derived
    /// otherwise.
    fn estimate_total_ms(&self) -> u64 {
        if self.history.samples > 0 {
            return self.history.mean_ms.max(MIN_ESTIMATE_MS);
        }
        let bytes = self.size_bytes.unwrap_or(0);
        let ms = bytes.saturating_mul(1000) / COLD_LOAD_BYTES_PER_SEC.max(1);
        ms.max(MIN_ESTIMATE_MS)
    }

    /// Estimated milliseconds still to go on an in-progress load.
    ///
    /// Never returns zero: a load that has already overrun its estimate is
    /// still not finished, and quoting zero would send the caller straight
    /// back to be told the same thing.
    fn remaining_ms(&self, now: Instant) -> u64 {
        let total = self.estimate_total_ms();
        match self.warming_since {
            Some(started) => {
                let elapsed = now.duration_since(started).as_millis() as u64;
                total.saturating_sub(elapsed).max(MIN_ESTIMATE_MS)
            }
            None => total,
        }
    }
}

#[derive(Debug)]
struct Inner {
    entries: HashMap<String, Entry>,
    pinned: HashMap<String, ()>,
}

/// Tracks which models are warm and decides which to evict.
#[derive(Debug, Clone)]
pub struct ModelLifecycle {
    inner: Arc<Mutex<Inner>>,
}

impl Default for ModelLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

impl ModelLifecycle {
    /// An empty lifecycle: every model cold.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                entries: HashMap::new(),
                pinned: HashMap::new(),
            })),
        }
    }

    /// Record a model's on-disk size so cold-load estimates can be quoted
    /// before it has ever been loaded.
    ///
    /// Without this the first caller for a never-loaded model gets the
    /// [`MIN_ESTIMATE_MS`] floor, which badly under-quotes a large model.
    pub fn declare_size(&self, model_id: &str, size_bytes: u64) {
        let mut inner = self.inner.lock();
        inner
            .entries
            .entry(model_id.to_string())
            .or_insert_with(|| Entry::new(Some(size_bytes)))
            .size_bytes = Some(size_bytes);
    }

    /// Pin a model so it is never chosen for eviction.
    ///
    /// The operator's way of saying "this one is the product". A pinned model
    /// still has to be loaded once; pinning only exempts it from eviction.
    pub fn pin(&self, model_id: &str) {
        self.inner.lock().pinned.insert(model_id.to_string(), ());
    }

    /// Remove a pin, returning the model to eviction candidacy.
    pub fn unpin(&self, model_id: &str) {
        self.inner.lock().pinned.remove(model_id);
    }

    /// Whether `model_id` is pinned.
    pub fn is_pinned(&self, model_id: &str) -> bool {
        self.inner.lock().pinned.contains_key(model_id)
    }

    /// Decide what to do with a request for `model_id`.
    ///
    /// Exactly one concurrent caller for a cold model receives
    /// [`Admission::LoadRequired`]; the rest receive [`Admission::Warming`].
    /// That single-flight property is why this is a lifecycle rather than a
    /// status map — without it, ten simultaneous requests for a cold 35 GB
    /// model start ten loads and the machine dies.
    pub fn admit(&self, model_id: &str) -> Admission {
        let now = Instant::now();
        let mut inner = self.inner.lock();
        let entry = inner
            .entries
            .entry(model_id.to_string())
            .or_insert_with(|| Entry::new(None));

        // Mid-eviction: report as warming rather than ready. The context is
        // going away, so serving from it is not safe.
        if entry.evicting {
            let remaining = entry.estimate_total_ms();
            entry.waiters += 1;
            let waiters = entry.waiters;
            return Admission::Warming(WarmingStatus::new(model_id, remaining, waiters));
        }

        if entry.warm {
            entry.in_flight += 1;
            entry.last_used = Some(now);
            return Admission::Ready(InFlightGuard {
                model_id: model_id.to_string(),
                inner: Arc::clone(&self.inner),
            });
        }

        if entry.warming_since.is_some() {
            entry.waiters += 1;
            let remaining = entry.remaining_ms(now);
            let waiters = entry.waiters;
            return Admission::Warming(WarmingStatus::new(model_id, remaining, waiters));
        }

        // Cold, and nobody else is loading it: this caller does the work.
        entry.warming_since = Some(now);
        entry.waiters += 1;
        let remaining = entry.estimate_total_ms();
        let waiters = entry.waiters;
        Admission::LoadRequired(WarmingStatus::new(model_id, remaining, waiters))
    }

    /// Report a completed load, folding its duration into the estimate future
    /// callers are quoted.
    pub fn finish_warm(&self, model_id: &str, took: Duration) {
        let mut inner = self.inner.lock();
        if let Some(entry) = inner.entries.get_mut(model_id) {
            entry.history.observe(took.as_millis() as u64);
            entry.warming_since = None;
            entry.waiters = 0;
            entry.warm = true;
            entry.evicting = false;
            entry.last_used = Some(Instant::now());
        }
    }

    /// Adopt a model that some other path already loaded.
    ///
    /// Models reach memory by more than one route: an explicit serve call, a
    /// holder's lazy load on first inference, a preload at startup. None of
    /// those go through [`admit`](Self::admit), so without reconciliation the
    /// lifecycle would report a genuinely resident model as cold, schedule a
    /// redundant warm, and answer the caller with a spurious 503.
    ///
    /// Does nothing if the model is already warm, currently loading, or being
    /// evicted — in each of those the lifecycle's own view is authoritative
    /// and must not be overwritten by an observation that may be stale.
    /// Returns whether it adopted.
    pub fn adopt_if_loaded(&self, model_id: &str) -> bool {
        let mut inner = self.inner.lock();
        let entry = inner
            .entries
            .entry(model_id.to_string())
            .or_insert_with(|| Entry::new(None));
        if entry.warm || entry.evicting || entry.warming_since.is_some() {
            return false;
        }
        entry.warm = true;
        entry.last_used = Some(Instant::now());
        true
    }

    /// Report a failed or abandoned load, returning the model to cold.
    ///
    /// Without this a failed load leaves the model warming forever and every
    /// subsequent caller is told to wait for a load that is not happening.
    pub fn abandon_warm(&self, model_id: &str) {
        let mut inner = self.inner.lock();
        if let Some(entry) = inner.entries.get_mut(model_id) {
            entry.warming_since = None;
            entry.waiters = 0;
            entry.warm = false;
        }
    }

    /// Choose a model to evict, in least-recently-used order.
    ///
    /// Skips models that are pinned, already cold, mid-eviction, or serving a
    /// request. Returns `None` when nothing can be freed — the caller must
    /// then refuse the load rather than evict something unsafe.
    ///
    /// A model that is warm but has never been used sorts oldest, so a
    /// speculative preload is reclaimed before anything that has served
    /// traffic.
    pub fn evict_candidate(&self) -> Option<String> {
        let inner = self.inner.lock();
        inner
            .entries
            .iter()
            .filter(|(id, e)| {
                e.warm && !e.evicting && e.in_flight == 0 && !inner.pinned.contains_key(*id)
            })
            .min_by_key(|(_, e)| e.last_used)
            .map(|(id, _)| id.clone())
    }

    /// Mark a model as being unloaded. Returns `false` if it is not evictable
    /// right now, in which case the caller must not proceed.
    ///
    /// Checking and marking under one lock is what stops two evictions racing
    /// on the same model, and stops a request being admitted to a model that
    /// is about to be torn down.
    pub fn begin_evict(&self, model_id: &str) -> bool {
        let mut inner = self.inner.lock();
        let pinned = inner.pinned.contains_key(model_id);
        match inner.entries.get_mut(model_id) {
            Some(entry) if entry.warm && !entry.evicting && entry.in_flight == 0 && !pinned => {
                entry.evicting = true;
                true
            }
            _ => false,
        }
    }

    /// Report an eviction as complete: the model is now cold.
    pub fn finish_evict(&self, model_id: &str) {
        let mut inner = self.inner.lock();
        if let Some(entry) = inner.entries.get_mut(model_id) {
            entry.warm = false;
            entry.evicting = false;
            entry.last_used = None;
        }
    }

    /// Current state of `model_id`.
    pub fn state(&self, model_id: &str) -> ModelState {
        let now = Instant::now();
        let inner = self.inner.lock();
        let Some(entry) = inner.entries.get(model_id) else {
            return ModelState::Cold;
        };
        if entry.evicting {
            return ModelState::Evicting;
        }
        if entry.warm {
            return ModelState::Warm {
                idle_ms: entry
                    .last_used
                    .map(|t| now.duration_since(t).as_millis() as u64)
                    .unwrap_or(0),
                in_flight: entry.in_flight,
            };
        }
        match entry.warming_since {
            Some(started) => ModelState::Warming {
                elapsed_ms: now.duration_since(started).as_millis() as u64,
                remaining_ms: entry.remaining_ms(now),
                waiters: entry.waiters,
            },
            None => ModelState::Cold,
        }
    }

    /// Every model currently warm, for operator reporting.
    pub fn warm_models(&self) -> Vec<String> {
        let inner = self.inner.lock();
        let mut out: Vec<String> = inner
            .entries
            .iter()
            .filter(|(_, e)| e.warm)
            .map(|(id, _)| id.clone())
            .collect();
        out.sort();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready(a: Admission) -> InFlightGuard {
        match a {
            Admission::Ready(g) => g,
            other => panic!("expected Ready, got {other:?}"),
        }
    }

    /// Drive a model to warm the way a caller would.
    fn warm_up(lc: &ModelLifecycle, id: &str, took_ms: u64) {
        match lc.admit(id) {
            Admission::LoadRequired(_) => lc.finish_warm(id, Duration::from_millis(took_ms)),
            other => panic!("expected LoadRequired for a cold model, got {other:?}"),
        }
    }

    #[test]
    fn a_cold_model_elects_exactly_one_loader() {
        // The property that stops ten requests for one cold model starting
        // ten loads.
        let lc = ModelLifecycle::new();
        let first = lc.admit("qwen3.6-35b-a3b");
        assert!(matches!(first, Admission::LoadRequired(_)));

        for _ in 0..9 {
            let next = lc.admit("qwen3.6-35b-a3b");
            assert!(
                matches!(next, Admission::Warming(_)),
                "only the first caller may load"
            );
        }

        match lc.state("qwen3.6-35b-a3b") {
            ModelState::Warming { waiters, .. } => assert_eq!(waiters, 10),
            other => panic!("expected Warming, got {other:?}"),
        }
    }

    #[test]
    fn a_warm_model_serves_immediately() {
        let lc = ModelLifecycle::new();
        warm_up(&lc, "timesfm-2.5", 800);
        let _guard = ready(lc.admit("timesfm-2.5"));
        match lc.state("timesfm-2.5") {
            ModelState::Warm { in_flight, .. } => assert_eq!(in_flight, 1),
            other => panic!("expected Warm, got {other:?}"),
        }
    }

    #[test]
    fn a_model_serving_a_request_cannot_be_evicted() {
        // Evicting mid-generation would free the context under a running
        // decode.
        let lc = ModelLifecycle::new();
        warm_up(&lc, "llm", 5_000);
        let guard = ready(lc.admit("llm"));

        assert_eq!(
            lc.evict_candidate(),
            None,
            "in-flight model is not a candidate"
        );
        assert!(!lc.begin_evict("llm"), "eviction must be refused outright");

        drop(guard);
        assert_eq!(lc.evict_candidate().as_deref(), Some("llm"));
        assert!(lc.begin_evict("llm"));
    }

    #[test]
    fn a_pinned_model_is_never_evicted() {
        let lc = ModelLifecycle::new();
        warm_up(&lc, "pinned-llm", 5_000);
        warm_up(&lc, "spare", 1_000);
        lc.pin("pinned-llm");

        // Even though `pinned-llm` was used first and so is least-recently
        // used, the candidate must be `spare`.
        assert_eq!(lc.evict_candidate().as_deref(), Some("spare"));
        assert!(!lc.begin_evict("pinned-llm"));

        lc.unpin("pinned-llm");
        assert!(lc.begin_evict("pinned-llm"), "unpinning restores candidacy");
    }

    #[test]
    fn eviction_picks_the_least_recently_used() {
        let lc = ModelLifecycle::new();
        for id in ["a", "b", "c"] {
            warm_up(&lc, id, 1_000);
        }
        // Touch `a` and `b`, leaving `c` oldest.
        drop(ready(lc.admit("a")));
        drop(ready(lc.admit("b")));
        assert_eq!(lc.evict_candidate().as_deref(), Some("c"));
    }

    #[test]
    fn a_failed_load_returns_the_model_to_cold() {
        // Otherwise every later caller waits on a load that is not running.
        let lc = ModelLifecycle::new();
        assert!(matches!(lc.admit("broken"), Admission::LoadRequired(_)));
        lc.abandon_warm("broken");
        assert_eq!(lc.state("broken"), ModelState::Cold);
        assert!(
            matches!(lc.admit("broken"), Admission::LoadRequired(_)),
            "the next caller must be free to retry the load"
        );
    }

    #[test]
    fn an_evicting_model_is_not_served_from() {
        let lc = ModelLifecycle::new();
        warm_up(&lc, "going-away", 1_000);
        assert!(lc.begin_evict("going-away"));
        assert_eq!(lc.state("going-away"), ModelState::Evicting);
        assert!(
            matches!(lc.admit("going-away"), Admission::Warming(_)),
            "must not hand out a context that is being torn down"
        );
        lc.finish_evict("going-away");
        assert_eq!(lc.state("going-away"), ModelState::Cold);
    }

    #[test]
    fn the_estimate_comes_from_the_models_own_size_before_it_is_measured() {
        // A 35 GB MoE and a 1 GB forecaster must not be quoted the same wait.
        let lc = ModelLifecycle::new();
        lc.declare_size("big", 35 * 1024 * 1024 * 1024);
        lc.declare_size("small", 1024 * 1024 * 1024);

        let big = match lc.admit("big") {
            Admission::LoadRequired(s) => s,
            other => panic!("{other:?}"),
        };
        let small = match lc.admit("small") {
            Admission::LoadRequired(s) => s,
            other => panic!("{other:?}"),
        };
        assert!(
            big.estimated_ready_ms > small.estimated_ready_ms * 10,
            "big {} vs small {}",
            big.estimated_ready_ms,
            small.estimated_ready_ms
        );
    }

    #[test]
    fn a_measured_load_replaces_the_size_guess() {
        // The size heuristic is a stand-in. Once we have measured the real
        // thing, callers should be quoted that instead.
        let lc = ModelLifecycle::new();
        lc.declare_size("m", 35 * 1024 * 1024 * 1024);
        warm_up(&lc, "m", 4_000);
        assert!(lc.begin_evict("m"));
        lc.finish_evict("m");

        match lc.admit("m") {
            Admission::LoadRequired(s) => assert_eq!(
                s.estimated_ready_ms, 4_000,
                "first measurement should replace the guess outright"
            ),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn repeated_loads_converge_without_one_outlier_dominating() {
        let lc = ModelLifecycle::new();
        warm_up(&lc, "m", 1_000);
        // One pathological load — a cold page cache, say — must move the
        // estimate but not become it.
        for _ in 0..3 {
            assert!(lc.begin_evict("m"));
            lc.finish_evict("m");
            warm_up(&lc, "m", 20_000);
        }
        assert!(lc.begin_evict("m"));
        lc.finish_evict("m");
        match lc.admit("m") {
            Admission::LoadRequired(s) => {
                assert!(
                    s.estimated_ready_ms > 1_000 && s.estimated_ready_ms < 20_000,
                    "estimate {} should sit between the extremes",
                    s.estimated_ready_ms
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn retry_after_never_tells_a_client_to_come_back_immediately() {
        // A zero or sub-second Retry-After produces a hot retry loop that
        // hurts most exactly when the node is busiest.
        let lc = ModelLifecycle::new();
        lc.declare_size("tiny", 1024);
        let status = match lc.admit("tiny") {
            Admission::LoadRequired(s) => s,
            other => panic!("{other:?}"),
        };
        assert!(status.retry_after_ms >= MIN_ESTIMATE_MS);
        assert!(status.retry_after_secs() >= 1);
        assert!(
            status.retry_after_ms > status.estimated_ready_ms,
            "retry must sit after the estimate, not on it"
        );
    }

    #[test]
    fn an_overrunning_load_still_quotes_a_future_time() {
        // If a load takes longer than estimated, remaining must not collapse
        // to zero and send the caller straight back.
        let lc = ModelLifecycle::new();
        lc.declare_size("slow", 1024);
        assert!(matches!(lc.admit("slow"), Admission::LoadRequired(_)));
        std::thread::sleep(Duration::from_millis(20));
        match lc.admit("slow") {
            Admission::Warming(s) => assert!(s.estimated_ready_ms >= MIN_ESTIMATE_MS),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn nothing_is_evictable_when_everything_is_pinned_or_busy() {
        // The caller must be able to tell "free something" from "nothing can
        // be freed", because the second means refuse the load.
        let lc = ModelLifecycle::new();
        warm_up(&lc, "pinned", 1_000);
        warm_up(&lc, "busy", 1_000);
        lc.pin("pinned");
        let _guard = ready(lc.admit("busy"));
        assert_eq!(lc.evict_candidate(), None);
    }

    #[test]
    fn warm_models_reports_what_is_actually_resident() {
        let lc = ModelLifecycle::new();
        warm_up(&lc, "b", 1_000);
        warm_up(&lc, "a", 1_000);
        assert!(matches!(lc.admit("cold-one"), Admission::LoadRequired(_)));
        assert_eq!(lc.warm_models(), vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn concurrent_admits_elect_one_loader_under_real_threads() {
        // The single-flight guarantee has to hold under actual contention,
        // not just sequential calls.
        use std::sync::atomic::{AtomicUsize, Ordering};

        let lc = ModelLifecycle::new();
        let loaders = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|s| {
            for _ in 0..32 {
                let lc = lc.clone();
                let loaders = Arc::clone(&loaders);
                s.spawn(move || {
                    if matches!(lc.admit("contended"), Admission::LoadRequired(_)) {
                        loaders.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });
        assert_eq!(
            loaders.load(Ordering::SeqCst),
            1,
            "exactly one thread may be told to load"
        );
    }
}
