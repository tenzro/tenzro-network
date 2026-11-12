//! Bounded, paced announcement of an inventory.
//!
//! A node has to tell the network what it holds — models it serves, agents it
//! runs, blobs it stores. Every one of those heartbeats was written the same
//! way: enumerate everything, publish one message per item, spawn each send,
//! repeat every 60 seconds forever. That shape has three faults, and they
//! compound.
//!
//! **The cost grows with the inventory.** A node holding a hundred thousand
//! blob hashes publishes hundreds of gossip messages a minute; one running many agents
//! publishes one per agent. Storing more, or doing more, should not mean
//! talking more — but under that shape the most useful node on the network is
//! also the loudest.
//!
//! **It arrives as a burst.** Everything went out at the instant of the tick,
//! into the per-neighbour send queue every gossip topic shares, where a burst
//! crowds out `tenzro/blocks`: a node saying what it stored would cost
//! everyone the blocks they need.
//!
//! **Nothing applied backpressure.** Each message was `tokio::spawn`ed, so a
//! slow peer did not slow the announcer down — it just meant more concurrent
//! sends racing into a queue that was already full.
//!
//! # What this does instead
//!
//! One rotation per inventory. Each tick takes a bounded slice and continues
//! from where the last one stopped, so a full pass takes as many ticks as the
//! inventory needs while any single tick costs the same. The slice is emitted
//! from one task, paced across the interval rather than at its start, and each
//! send is awaited so a slow peer slows the announcer rather than displacing
//! anything.
//!
//! This is the shape IPFS arrived at for provider records, for the same
//! reason: their Provide Sweep caps work "regardless of how many CIDs you're
//! providing" and spreads it across the reprovide interval to avoid peaks,
//! rather than reproviding everything at the start of each cycle.
//!
//! # The TTL is derived, not chosen
//!
//! Every announcement carries a lifetime, and a consumer forgets the entry
//! when it lapses. With a rotation, an item is re-announced once per full
//! pass — so a fixed TTL that was fine when every tick re-sent everything
//! becomes a silent expiry the moment the rotation is longer than it. The TTL
//! is therefore computed from how long a pass actually takes, with the same
//! margin IPFS uses between reproviding and expiry: refresh well inside the
//! lifetime, never at its edge.

use std::ops::Range;
use std::time::Duration;

use tenzro_network::NetworkService as _;

/// How much longer an announcement lives than the rotation that refreshes it.
///
/// IPFS reprovides at 22 hours against a 48-hour expiry — a refresh at about
/// 46% of the lifetime, validated against a record-liveness study. Three is
/// the more conservative side of that: a pass may be missed entirely and the
/// entry still survives to the next one.
const TTL_ROTATIONS: u64 = 3;

/// Shortest lifetime an announcement may claim.
///
/// Below this a consumer that polls at any sane interval would see entries
/// flicker in and out.
const MIN_TTL_SECS: u64 = 180;

/// Longest lifetime an announcement may claim.
///
/// An inventory big enough to need a rotation longer than a day has a problem
/// a TTL cannot fix, and a lifetime that long keeps dead providers cached well
/// past the point they are useful.
const MAX_TTL_SECS: u64 = 86_400;

/// What to announce this tick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Indices into the inventory to announce now.
    pub range: Range<usize>,
    /// Lifetime to stamp on each announcement, derived from the rotation.
    pub ttl_secs: u64,
    /// Pause between messages, so the slice is spread across the interval
    /// rather than emitted at its start.
    pub pace: Duration,
}

impl Plan {
    /// Whether this plan announces anything.
    pub fn is_empty(&self) -> bool {
        self.range.is_empty()
    }
}

/// A cursor over an inventory that is announced a slice at a time.
#[derive(Debug, Clone)]
pub struct Rotation {
    cursor: usize,
    per_tick: usize,
    interval: Duration,
}

impl Rotation {
    /// A rotation announcing at most `per_tick` items every `interval`.
    ///
    /// `per_tick` is the whole budget: it is what makes the cost independent
    /// of the inventory, so it is a constant of the announcement and never
    /// derived from how much there is to say.
    pub fn new(per_tick: usize, interval: Duration) -> Self {
        Self {
            cursor: 0,
            per_tick: per_tick.max(1),
            interval,
        }
    }

    /// The slice to announce now, advancing the cursor past it.
    ///
    /// Callers must iterate the inventory in a stable order. An order that
    /// changed between ticks would let the cursor step over items
    /// indefinitely, which is the one way a bounded tick could be worse than
    /// the flood it replaces.
    pub fn plan(&mut self, total: usize) -> Plan {
        // A cursor past the end means the inventory shrank. Starting over is
        // right; returning an empty slice forever would silently stop
        // announcing.
        if self.cursor >= total {
            self.cursor = 0;
        }
        let start = self.cursor;
        let end = (start + self.per_tick).min(total);
        self.cursor = if end >= total { 0 } else { end };

        let ticks_per_rotation = total.div_ceil(self.per_tick).max(1) as u64;
        let rotation_secs = ticks_per_rotation.saturating_mul(self.interval.as_secs().max(1));
        let ttl_secs = rotation_secs
            .saturating_mul(TTL_ROTATIONS)
            .clamp(MIN_TTL_SECS, MAX_TTL_SECS);

        // Spread the slice over most of the interval. Leaving a margin means
        // the last message of a tick lands before the next tick fires, so two
        // slices are never in flight at once.
        //
        // The gaps are between messages, so n messages have n-1 of them. A
        // single message has none: there is nothing to spread it against, and
        // delaying it most of a minute would be pacing for its own sake.
        let emitted = end.saturating_sub(start);
        let pace = if emitted <= 1 {
            Duration::ZERO
        } else {
            self.interval.mul_f32(0.8) / (emitted - 1) as u32
        };

        Plan {
            range: start..end,
            ttl_secs,
            pace,
        }
    }

    /// Where the rotation currently stands, for logging and tests.
    pub fn cursor(&self) -> usize {
        self.cursor
    }
}

/// Emit a planned slice from one task, paced.
///
/// One task rather than one per message: spawning per message made every send
/// race the others into a queue that was already full, and left the number of
/// concurrent sends proportional to the inventory. One task also means a slice
/// cannot overlap itself when a peer is slow — it falls behind instead, which
/// is what a heartbeat should do.
///
/// Not awaited by the caller, because the caller is the node's event loop and
/// a slow peer must not stop it servicing everything else.
pub fn emit_paced(
    network: std::sync::Arc<tenzro_network::TenzroNetworkService>,
    topic: &'static str,
    messages: Vec<tenzro_network::NetworkMessage>,
    pace: Duration,
) {
    if messages.is_empty() {
        return;
    }
    tokio::spawn(async move {
        let last = messages.len() - 1;
        for (i, message) in messages.into_iter().enumerate() {
            if let Err(e) = network.broadcast(topic, message).await {
                tracing::debug!(error = %e, topic, "Failed to broadcast announcement");
            }
            // No trailing pause: a gap belongs between messages, and sleeping
            // after the last one only delays the task's exit.
            if i < last && !pace.is_zero() {
                tokio::time::sleep(pace).await;
            }
        }
    });
}

/// Work to run on a signing lane: sign what was built, then emit it.
pub type SigningJob = Box<dyn FnOnce() + Send + 'static>;

/// A thread that runs signing jobs one after another, off the event loop.
///
/// Signing an announcement waits for a hardware batch (the flush interval plus
/// the TPM's time), which must never happen inside the event loop: it also
/// services blocks and certificates. The loop builds the unsigned message and
/// hands it here; the lane signs it and emits it. The queue is bounded and
/// drops its oldest job when full, so a stalled hardware leaves the newest
/// heartbeat to go out instead of a backlog of stale ones.
pub struct SigningLane {
    name: String,
    shared: std::sync::Arc<(
        std::sync::Mutex<(std::collections::VecDeque<SigningJob>, bool)>,
        std::sync::Condvar,
    )>,
    capacity: usize,
    /// False once the worker thread has ended or never started.
    alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
    reported_dead: std::sync::atomic::AtomicBool,
}

impl SigningLane {
    pub fn new(name: &str, capacity: usize) -> Self {
        use std::sync::atomic::{AtomicBool, Ordering};
        let shared = std::sync::Arc::new((
            std::sync::Mutex::new((std::collections::VecDeque::new(), false)),
            std::sync::Condvar::new(),
        ));
        let alive = std::sync::Arc::new(AtomicBool::new(true));
        let (worker, flag, lane) = (shared.clone(), alive.clone(), name.to_string());
        let spawned = std::thread::Builder::new()
            .name(format!("sign-{name}"))
            .spawn(move || {
                // However the thread ends, the lane is marked dead; an end
                // that was not a close is reported once, with the lane name.
                struct Ending(std::sync::Arc<AtomicBool>, String, std::sync::Arc<(
                    std::sync::Mutex<(std::collections::VecDeque<SigningJob>, bool)>,
                    std::sync::Condvar,
                )>);
                impl Drop for Ending {
                    fn drop(&mut self) {
                        self.0.store(false, Ordering::SeqCst);
                        let closed = self.2 .0.lock().unwrap_or_else(|e| e.into_inner()).1;
                        if !closed {
                            tracing::error!(lane = %self.1, "announcement signing lane ended; its announcements are no longer sent");
                        }
                    }
                }
                let _ending = Ending(flag, lane.clone(), worker.clone());
                loop {
                    let job = {
                        let (lock, cv) = &*worker;
                        let mut st = lock.lock().unwrap_or_else(|e| e.into_inner());
                        loop {
                            if let Some(job) = st.0.pop_front() {
                                break Some(job);
                            }
                            if st.1 {
                                break None;
                            }
                            st = cv.wait(st).unwrap_or_else(|e| e.into_inner());
                        }
                    };
                    match job {
                        Some(job) => {
                            // A job that panics costs that announcement, not
                            // the lane.
                            if std::panic::catch_unwind(std::panic::AssertUnwindSafe(job)).is_err() {
                                tracing::error!(lane = %lane, "an announcement signing job panicked");
                            }
                        }
                        None => return,
                    }
                }
            });
        let reported_dead = AtomicBool::new(false);
        if let Err(e) = spawned {
            tracing::error!(lane = name, error = %e, "announcement signing lane did not start; its announcements are not sent");
            alive.store(false, Ordering::SeqCst);
            reported_dead.store(true, Ordering::SeqCst);
        }
        Self {
            name: name.to_string(),
            shared,
            capacity: capacity.max(1),
            alive,
            reported_dead,
        }
    }

    /// Whether the worker thread is running.
    pub fn is_alive(&self) -> bool {
        self.alive.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// Queues `job`; when the lane is full the oldest waiting job is dropped.
    /// Must be called inside the tokio runtime: the job runs with that
    /// runtime entered, so it can spawn the emission. On a lane whose thread
    /// is gone the job is dropped (reported once), not queued.
    pub fn submit(&self, job: impl FnOnce() + Send + 'static) {
        use std::sync::atomic::Ordering;
        if !self.is_alive() {
            if !self.reported_dead.swap(true, Ordering::SeqCst) {
                tracing::error!(lane = %self.name, "announcement signing lane is not running; announcements are dropped");
            }
            return;
        }
        let handle = tokio::runtime::Handle::current();
        let wrapped: SigningJob = Box::new(move || {
            let _entered = handle.enter();
            job();
        });
        let (lock, cv) = &*self.shared;
        let mut st = lock.lock().unwrap_or_else(|e| e.into_inner());
        if st.0.len() >= self.capacity {
            st.0.pop_front();
            tracing::debug!(lane = %self.name, "signing lane full: dropped the oldest announcement");
        }
        st.0.push_back(wrapped);
        cv.notify_one();
    }
}

impl Drop for SigningLane {
    fn drop(&mut self) {
        let (lock, cv) = &*self.shared;
        lock.lock().unwrap_or_else(|e| e.into_inner()).1 = true;
        cv.notify_all();
    }
}

/// One lane per kind of announcement, so a slow kind does not hold up the
/// others and a newer heartbeat replaces an older one of the same kind.
pub struct SigningLanes {
    pub models: SigningLane,
    pub providers: SigningLane,
    pub liveness: SigningLane,
    pub blobs: SigningLane,
}

impl SigningLanes {
    pub fn new() -> Self {
        Self {
            models: SigningLane::new("models", 1),
            providers: SigningLane::new("providers", 1),
            liveness: SigningLane::new("liveness", 1),
            blobs: SigningLane::new("blobs", 1),
        }
    }
}

impl Default for SigningLanes {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test(flavor = "multi_thread")]
    async fn a_lane_job_signs_through_the_runtime_signer_on_the_lane_thread() {
        use tenzro_crypto::batch::RecordSigner;
        let signer = crate::batch_signing::RuntimeSigner::new(std::sync::Arc::new(
            crate::batch_signing::test_support::Immediate::new(21),
        ));
        let lane = SigningLane::new("signer", 1);
        let (tx, rx) = std::sync::mpsc::channel();
        lane.submit(move || {
            let _ = tx.send(signer.sign_record(b"announcement").is_ok());
        });
        let ok =
            tokio::task::spawn_blocking(move || rx.recv_timeout(std::time::Duration::from_secs(5)))
                .await
                .unwrap();
        assert_eq!(ok, Ok(true));
        assert!(lane.is_alive());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stalled_batch_signer_does_not_hold_up_the_loops_other_work() {
        use tenzro_crypto::batch::{RecordSignature, RecordSigner};
        // A record signer whose hardware takes two seconds, as a stalled TPM.
        struct Stalled(crate::batch_signing::test_support::Immediate);
        impl RecordSigner for Stalled {
            fn identity(&self) -> &tenzro_crypto::composite::CompositePublicKey {
                self.0.identity()
            }
            fn sign_record(&self, m: &[u8]) -> tenzro_crypto::Result<RecordSignature> {
                std::thread::sleep(std::time::Duration::from_secs(2));
                self.0.sign_record(m)
            }
        }
        let signer = std::sync::Arc::new(Stalled(
            crate::batch_signing::test_support::Immediate::new(22),
        ));
        let lanes = SigningLanes::new();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        // The loop's shape: a select over heartbeat ticks and consensus
        // messages, where a heartbeat submits to the lane and goes on.
        let (msg_tx, mut msg_rx) = tokio::sync::mpsc::channel::<std::time::Instant>(8);
        let mut tick = tokio::time::interval(std::time::Duration::from_millis(10));
        let mut sent = false;
        let started = std::time::Instant::now();
        let handled_late = loop {
            tokio::select! {
                _ = tick.tick() => {
                    let s = signer.clone();
                    let tx = done_tx.clone();
                    lanes.liveness.submit(move || {
                        let _ = tx.send(s.sign_record(b"heartbeat").is_ok());
                    });
                    if !sent && started.elapsed() > std::time::Duration::from_millis(100) {
                        sent = true;
                        msg_tx.send(std::time::Instant::now()).await.unwrap();
                    }
                }
                Some(sent_at) = msg_rx.recv() => {
                    break sent_at.elapsed();
                }
            }
        };
        // The consensus stand-in was handled promptly while the heartbeat
        // signature was still waiting on the stalled hardware.
        assert!(
            handled_late < std::time::Duration::from_millis(50),
            "{handled_late:?}"
        );
        assert!(
            done_rx.try_recv().is_err(),
            "the heartbeat is still waiting on the hardware"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_lane_that_panicked_keeps_running_and_a_dead_lane_drops_jobs() {
        let lane = SigningLane::new("panics", 1);
        lane.submit(|| panic!("a job panics"));
        let (tx, rx) = std::sync::mpsc::channel();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        lane.submit(move || {
            let _ = tx.send(());
        });
        let got =
            tokio::task::spawn_blocking(move || rx.recv_timeout(std::time::Duration::from_secs(5)))
                .await
                .unwrap();
        assert!(got.is_ok());
        // A lane whose thread is gone does not queue.
        lane.alive.store(false, std::sync::atomic::Ordering::SeqCst);
        lane.submit(|| {});
        assert!(lane.shared.0.lock().unwrap().0.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_signing_lane_never_makes_the_submitter_wait_and_drops_the_oldest() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        let lane = SigningLane::new("test", 1);
        let ran = Arc::new(AtomicUsize::new(0));
        let (gate_tx, gate_rx) = std::sync::mpsc::channel::<()>();
        let r = ran.clone();
        // A job that blocks the worker, as a hardware batch does.
        let (started_tx, started_rx) = std::sync::mpsc::channel::<()>();
        lane.submit(move || {
            let _ = started_tx.send(());
            let _ = gate_rx.recv();
            r.fetch_add(1, Ordering::SeqCst);
        });
        // The worker has taken the blocking job before the queue is tested.
        tokio::task::spawn_blocking(move || {
            started_rx.recv_timeout(std::time::Duration::from_secs(5))
        })
        .await
        .unwrap()
        .unwrap();
        let started = std::time::Instant::now();
        for tag in [10usize, 100, 1000] {
            let r = ran.clone();
            lane.submit(move || {
                r.fetch_add(tag, Ordering::SeqCst);
            });
        }
        assert!(started.elapsed() < std::time::Duration::from_millis(200));
        gate_tx.send(()).unwrap();
        for _ in 0..100 {
            if ran.load(Ordering::SeqCst) >= 1001 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        // The blocked job ran, the two older queued jobs were dropped, the
        // newest ran.
        assert_eq!(ran.load(Ordering::SeqCst), 1001);
    }

    use super::*;

    fn rotation(per_tick: usize) -> Rotation {
        Rotation::new(per_tick, Duration::from_secs(60))
    }

    /// Walk a rotation to completion, counting how often each item was
    /// announced and how many ticks it took.
    fn full_rotation(total: usize, per_tick: usize) -> (Vec<usize>, usize) {
        let mut r = rotation(per_tick);
        let mut counts = vec![0usize; total];
        let mut ticks = 0;
        loop {
            let plan = r.plan(total);
            for slot in counts
                .iter_mut()
                .take(plan.range.end)
                .skip(plan.range.start)
            {
                *slot += 1;
            }
            ticks += 1;
            if r.cursor() == 0 || ticks > total + 10 {
                break;
            }
        }
        (counts, ticks)
    }

    /// **The property a bounded tick must not cost us.** Every item is still
    /// announced. A rotation that quietly skipped some would leave models,
    /// agents or blobs permanently undiscoverable — worse than the flood.
    #[test]
    fn every_item_is_announced_exactly_once_per_rotation() {
        for (total, per_tick) in [(1, 16), (15, 16), (16, 16), (17, 16), (112_000, 8_192)] {
            let (counts, _) = full_rotation(total, per_tick);
            assert!(
                counts.iter().all(|&n| n == 1),
                "total={total} per_tick={per_tick}: counts {:?}",
                counts.iter().collect::<std::collections::BTreeSet<_>>()
            );
        }
    }

    /// **The regression.** A tick costs the same whatever the node holds.
    /// This is the whole point: the most useful node must not be the loudest.
    #[test]
    fn a_tick_costs_the_same_whatever_the_inventory() {
        for total in [8_192, 112_000, 10_000_000] {
            let plan = rotation(8_192).plan(total);
            assert_eq!(plan.range.len(), 8_192, "total={total}");
        }
    }

    /// An inventory smaller than one tick goes out whole.
    #[test]
    fn a_small_inventory_is_announced_in_one_tick() {
        let plan = rotation(16).plan(3);
        assert_eq!(plan.range, 0..3);
    }

    /// An empty inventory announces nothing, and does not panic building a
    /// range to do it.
    #[test]
    fn an_empty_inventory_announces_nothing() {
        let plan = rotation(16).plan(0);
        assert!(plan.is_empty());
        assert_eq!(plan.ttl_secs, MIN_TTL_SECS);
    }

    /// **The TTL must outlast a full rotation.** Otherwise an item expires on
    /// consumers before its turn comes round again and the announcement buys
    /// nothing — the failure a fixed TTL acquires the moment you stop
    /// re-sending everything every tick.
    #[test]
    fn the_ttl_outlasts_a_full_rotation() {
        for (total, per_tick) in [(1, 16), (16, 16), (112_000, 8_192), (1_000_000, 8_192)] {
            let plan = rotation(per_tick).plan(total);
            let (_, ticks) = full_rotation(total, per_tick);
            let rotation_secs = ticks as u64 * 60;
            assert!(
                plan.ttl_secs >= rotation_secs,
                "total={total}: ttl {}s expires inside a {rotation_secs}s rotation",
                plan.ttl_secs
            );
        }
    }

    /// And it is bounded above, so a pathological inventory cannot pin dead
    /// entries in consumers' caches for a week.
    #[test]
    fn the_ttl_is_capped() {
        let plan = rotation(1).plan(usize::MAX / 4);
        assert_eq!(plan.ttl_secs, MAX_TTL_SECS);
    }

    /// A cursor left past the end — the inventory shrank between ticks —
    /// starts over rather than announcing nothing for ever.
    #[test]
    fn a_shrunken_inventory_restarts_the_rotation() {
        let mut r = rotation(16);
        let _ = r.plan(100);
        let _ = r.plan(100);
        let plan = r.plan(5);
        assert_eq!(plan.range, 0..5);
    }

    /// **What stops the burst.** The slice is paced across the interval, and
    /// the last message lands before the next tick fires — so two slices are
    /// never in flight at once.
    #[test]
    fn a_slice_is_spread_across_the_interval_and_finishes_before_the_next() {
        let plan = rotation(16).plan(112_000);
        let span = plan.pace * (plan.range.len() - 1) as u32;
        assert!(
            span < Duration::from_secs(60),
            "span {span:?} overruns the tick"
        );
        assert!(
            span > Duration::from_secs(30),
            "span {span:?} is still a burst"
        );
    }

    /// A single item is not made to wait for no reason. Pacing exists to put
    /// space between messages; with one message there is no space to make.
    #[test]
    fn one_item_is_sent_at_once() {
        assert_eq!(rotation(16).plan(1).pace, Duration::ZERO);
        assert_eq!(rotation(16).plan(0).pace, Duration::ZERO);
    }

    /// `per_tick` of zero would divide by zero and announce nothing. It is
    /// clamped rather than trusted, because it comes from a constant someone
    /// may edit.
    #[test]
    fn a_zero_budget_is_clamped_rather_than_dividing_by_zero() {
        let plan = Rotation::new(0, Duration::from_secs(60)).plan(10);
        assert_eq!(plan.range, 0..1);
    }
}
