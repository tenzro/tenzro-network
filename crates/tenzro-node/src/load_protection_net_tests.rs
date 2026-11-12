//! The load gate on a network of four validators in one process: the public
//! listener and the CPU are saturated, and consensus must keep certifying
//! within a stated bound, skip no more leader slots than it does idle, and
//! the node must return to GREEN once the load stops.
//!
//! The level during the flood is driven by real host readings plus one
//! fixture reading: on a large host with many idle cores, a few spinning
//! threads do not raise the kernel's CPU pressure, so the test adds the
//! pressure a saturated small host would report. Everything else (the flood,
//! the spinners, the shed gate, the consensus network) is real.

use std::sync::atomic::AtomicBool;

use super::*;
use crate::load_monitor::{LoadLevel, LoadMonitor, LoadSample, WorkClass, current_level};
use crate::load_shed::{ShedGate, load_shed};

/// The longest the certified checkpoint may stand still while the node is
/// saturated, milliseconds, unless three times the quiet window's longest
/// gap is more. This is a liveness bound: it separates a chain that keeps
/// certifying under load from one that has stopped. On an idle 28-core host
/// ten runs showed saturated gaps of 3.5 to 5.5 s (median about 4 s) and
/// quiet gaps of 2.3 to 2.5 s; one skipped leader slot costs a leader
/// timeout, 0.7 to 1 s, so 8 s is about twice the median and 1.5 times the
/// worst of the ten.
const CERTIFY_GAP_BOUND_MS: u64 = 8_000;

struct Observed {
    max_gap_ms: u64,
    advanced: u64,
    /// Leader slots skipped, each counted once.
    skipped: u64,
    /// Leader slots decided, skipped or committed, each counted once.
    slots: u64,
}

impl Observed {
    /// The share of leader slots that were skipped.
    fn skip_rate(&self) -> f64 {
        self.skipped as f64 / self.slots.max(1) as f64
    }
}

/// Leader slots decided and skipped, counted once for the committee.
///
/// Every validator decides the same slots in the same order, so a skipped
/// slot raises the counter of each of them by one, and each epoch runs on a
/// core that counts from zero. The committee's count for an epoch is
/// therefore the highest count of any of its validators in that epoch, and
/// the window's is the sum over the epochs it touched.
struct Slots {
    /// Each validator's epoch, committed and skipped counters at the start.
    first: Vec<Option<(u64, u64, u64)>>,
    /// Per epoch and validator: (committed, skipped) since the start of the
    /// window, or since the core started for an epoch begun inside it.
    seen: std::collections::BTreeMap<u64, Vec<(u64, u64)>>,
}

impl Slots {
    fn new(net: &Net) -> Self {
        let mut s = Slots {
            first: vec![None; 4],
            seen: Default::default(),
        };
        for i in 0..4 {
            if let Some(m) = net.node(i).consensus.metrics() {
                s.first[i] = Some((m.epoch, m.leaders_committed, m.leaders_skipped));
            }
        }
        s.sample(net);
        s
    }

    fn sample(&mut self, net: &Net) {
        for i in 0..4 {
            let Some(m) = net.node(i).consensus.metrics() else {
                continue;
            };
            let (committed0, skipped0) = match self.first[i] {
                Some((epoch, c, k)) if epoch == m.epoch => (c, k),
                _ => (0, 0),
            };
            let entry = self.seen.entry(m.epoch).or_insert_with(|| vec![(0, 0); 4]);
            let now = (
                m.leaders_committed.saturating_sub(committed0),
                m.leaders_skipped.saturating_sub(skipped0),
            );
            if now.1 > entry[i].1 {
                eprintln!(
                    "skip seen: validator {i}, epoch {}, round {} (slot {} of the epoch)",
                    m.epoch, m.round, now.1
                );
            }
            entry[i] = now;
        }
    }

    /// (skipped, decided) leader slots, each counted once.
    fn totals(&self) -> (u64, u64) {
        self.seen
            .values()
            .fold((0, 0), |(skipped, slots), per_validator| {
                let k = per_validator.iter().map(|(_, k)| *k).max().unwrap_or(0);
                let all = per_validator.iter().map(|(c, k)| c + k).max().unwrap_or(0);
                (skipped + k, slots + all)
            })
    }
}

/// Watches validator 0's certified checkpoint for `window`.
async fn observe(net: &Net, window: Duration) -> Observed {
    let start = Instant::now();
    let mut slots = Slots::new(net);
    let first = net.certified(0).1;
    let mut last = first;
    let mut last_change = Instant::now();
    let mut max_gap = Duration::ZERO;
    while start.elapsed() < window {
        tokio::time::sleep(Duration::from_millis(100)).await;
        slots.sample(net);
        let now = net.certified(0).1;
        if now != last {
            max_gap = max_gap.max(last_change.elapsed());
            last = now;
            last_change = Instant::now();
        }
    }
    max_gap = max_gap.max(last_change.elapsed());
    let (skipped, decided) = slots.totals();
    Observed {
        max_gap_ms: max_gap.as_millis() as u64,
        advanced: last - first,
        skipped,
        slots: decided,
    }
}

#[test]
fn a_four_validator_net_keeps_certifying_while_cpu_and_public_rpc_are_saturated() {
    network_test(async {
        const N: usize = 4;
        let feeder_account = tenzro_crypto::composite::testing::TestHybridSigner::hybrid(1);
        let net = Net::start_with(N, vec![feeder_account.address()], time_rules()).await;
        let feeder = feed_transfers(
            (0..N).map(|i| net.node(i).consensus.clone()).collect(),
            net.machines[0].storage.clone() as Arc<dyn KvStore>,
        );
        net.wait_for("the chain advances", Duration::from_secs(180), |n| {
            (0..N).all(|i| n.height(i) >= 6)
        })
        .await;

        let quiet = observe(&net, Duration::from_secs(10)).await;
        eprintln!(
            "quiet: max gap {} ms, {} checkpoints, {} of {} leader slots skipped",
            quiet.max_gap_ms, quiet.advanced, quiet.skipped, quiet.slots
        );
        assert!(quiet.advanced > 0, "the quiet chain did not advance");

        // Saturation: spinning threads on every core up to sixteen, and a
        // flood of requests through the shed gate to a handler that costs
        // CPU, far more in flight than the gate admits at HIGH, the level
        // host CPU pressure alone can raise.
        let stop = Arc::new(AtomicBool::new(false));
        let spinners: Vec<_> = (0..std::thread::available_parallelism()
            .map_or(4, |n| n.get())
            .min(16))
            .map(|_| {
                let stop = stop.clone();
                std::thread::spawn(move || {
                    while !stop.load(Ordering::Relaxed) {
                        std::hint::spin_loop();
                    }
                })
            })
            .collect();
        let gate = ShedGate::new();
        let app = axum::Router::new()
            .route(
                "/",
                axum::routing::post(|| async {
                    let t = Instant::now();
                    while t.elapsed() < Duration::from_micros(500) {
                        std::hint::spin_loop();
                    }
                    // A request waits on storage or a peer while it holds
                    // its place in flight, as a public call does; without
                    // the wait no more requests are ever in flight than
                    // the runtime has threads, and the gate cannot fill.
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    "ok"
                }),
            )
            .layer(axum::middleware::from_fn_with_state(gate, load_shed));
        let served = Arc::new(AtomicU64::new(0));
        let refused = Arc::new(AtomicU64::new(0));
        let flood_size = ShedGate::limit(WorkClass::PublicRpc, LoadLevel::High) + 400;
        let flood: Vec<_> = (0..flood_size)
            .map(|_| {
                let (app, stop, served, refused) =
                    (app.clone(), stop.clone(), served.clone(), refused.clone());
                tokio::spawn(async move {
                    use tower::ServiceExt;
                    while !stop.load(Ordering::Relaxed) {
                        let req = axum::http::Request::post("/")
                            .body(axum::body::Body::empty())
                            .unwrap();
                        match app.clone().oneshot(req).await {
                            Ok(r) if r.status() == 503 => {
                                assert!(r.headers().contains_key("retry-after"));
                                refused.fetch_add(1, Ordering::Relaxed);
                                tokio::time::sleep(Duration::from_millis(20)).await;
                            }
                            Ok(_) => {
                                served.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(_) => {}
                        }
                        tokio::task::yield_now().await;
                    }
                })
            })
            .collect();
        // The monitor runs on its own thread on the real readings, with
        // the saturated host's CPU pressure added while the load lasts. It
        // starts with the flood, so it has to raise the level while the
        // runtime is saturated.
        let saturated = Arc::new(AtomicBool::new(true));
        let monitor = LoadMonitor::new(None).spawn_with(Duration::from_millis(50), {
            let saturated = saturated.clone();
            move |s: &mut LoadSample| {
                if saturated.load(Ordering::Relaxed) {
                    s.cpu_psi = Some(90.0);
                } else {
                    // Once the load stops, the ten-second CPU pressure of
                    // a shared host keeps reporting the earlier load, and
                    // other work on the host feeds it too, so the fixture
                    // reports the quiet value; the other readings stay real.
                    s.cpu_psi = Some(0.0);
                }
            }
        });
        let loaded = observe(&net, Duration::from_secs(20)).await;
        eprintln!(
            "saturated: max gap {} ms, {} checkpoints, {} of {} leader slots skipped; public requests served {} refused {}",
            loaded.max_gap_ms,
            loaded.advanced,
            loaded.skipped,
            loaded.slots,
            served.load(Ordering::Relaxed),
            refused.load(Ordering::Relaxed)
        );

        stop.store(true, Ordering::Relaxed);
        saturated.store(false, Ordering::Relaxed);
        for t in spinners {
            let _ = t.join();
        }
        for f in flood {
            let _ = f.await;
        }
        // The node returns to GREEN once the load stops.
        let recover_by = Instant::now() + Duration::from_secs(60);
        while current_level() != LoadLevel::Green {
            assert!(
                Instant::now() < recover_by,
                "the node did not return to GREEN within 60 s of the load stopping: {:?}",
                crate::load_monitor::latest_report()
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let peak = monitor.peak();
        monitor.stop();
        assert_eq!(current_level(), LoadLevel::Green);
        assert!(
            peak >= LoadLevel::High,
            "the saturation never raised the level: {peak:?}"
        );
        feeder.abort();

        let gap_bound = CERTIFY_GAP_BOUND_MS.max(quiet.max_gap_ms * 3);
        assert!(
            loaded.max_gap_ms <= gap_bound,
            "the certified checkpoint stood still {} ms under load (bound {gap_bound}, {} ms when quiet)",
            loaded.max_gap_ms,
            quiet.max_gap_ms
        );
        assert!(loaded.advanced > 0, "consensus did not advance under load");
        // Load must not cost leader slots: the share skipped stays under a
        // stated bound, and over the quiet run's share by no more than it.
        // A slot is skipped when its leader's vertex arrives after the
        // leader timeout, which a stalled disk sync alone can cause, so a
        // quiet run has some.
        const SKIP_RATE_BOUND: f64 = 0.10;
        assert!(
            loaded.skip_rate() <= SKIP_RATE_BOUND
                && loaded.skip_rate() <= quiet.skip_rate() + SKIP_RATE_BOUND,
            "load skipped {} of {} leader slots against {} of {} when quiet (bound {SKIP_RATE_BOUND})",
            loaded.skipped,
            loaded.slots,
            quiet.skipped,
            quiet.slots
        );
        assert!(
            refused.load(Ordering::Relaxed) > 0,
            "the flood was never shed"
        );
    });
}
