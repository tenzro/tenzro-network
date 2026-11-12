//! A runtime of its own for consensus and signing.
//!
//! Consensus engines, their timers and their signing calls run here and not
//! on the runtime that serves RPC, the API and model traffic, so a saturated
//! public listener cannot delay a vote or a proposal: the two runtimes do not
//! share worker threads or a task queue. Code that starts consensus tasks from
//! the main runtime calls [`scoped`], which makes `tokio::spawn` inside it
//! land here.
//!
//! The runtime is created once, by [`enable`], on validator nodes. Where it
//! is not enabled (tests, light nodes) [`scoped`] runs its closure unchanged
//! and tasks stay on the caller's runtime.

use std::sync::OnceLock;

use tokio::runtime::{Builder, Handle, Runtime};

static RUNTIME: OnceLock<Runtime> = OnceLock::new();

/// Worker threads of the consensus runtime for a machine with `cores` cores:
/// a quarter of them, at least two and at most four. Consensus work is many
/// small tasks and signing waits, not bulk computation.
pub fn worker_threads(cores: usize) -> usize {
    (cores / 4).clamp(2, 4)
}

/// Builds a consensus runtime for a machine with `cores` cores.
pub fn build(cores: usize) -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(worker_threads(cores))
        // Signing and storage calls made from consensus tasks block; this
        // pool is theirs alone and bounded.
        .max_blocking_threads(32)
        .thread_name("tenzro-consensus")
        .enable_all()
        .build()
        .expect("the consensus runtime starts")
}

/// Starts the consensus runtime if it is not running and returns its handle.
/// `cores` is the machine's core count.
pub fn enable(cores: usize) -> Handle {
    RUNTIME.get_or_init(|| build(cores)).handle().clone()
}

/// The consensus runtime's handle, if it is enabled.
pub fn handle() -> Option<Handle> {
    RUNTIME.get().map(|r| r.handle().clone())
}

/// Runs `f` with the consensus runtime entered, so tasks it spawns with
/// `tokio::spawn` run there. Without an enabled runtime, runs `f` as it is.
pub fn scoped<R>(f: impl FnOnce() -> R) -> R {
    match RUNTIME.get() {
        Some(rt) => {
            let _entered = rt.handle().enter();
            f()
        }
        None => f(),
    }
}

/// Raises the niceness of the calling thread by `by`. Raising needs no
/// privilege; lowering does, so the node lowers nothing and instead keeps
/// consensus at the unit's priority and moves everything else down.
pub fn deprioritize_current_thread(by: i32) {
    #[cfg(target_os = "linux")]
    // SAFETY: gettid and setpriority take plain integers and write nothing
    // of ours; a failure only leaves the priority as it was.
    unsafe {
        let tid = libc::syscall(libc::SYS_gettid) as libc::id_t;
        let cur = libc::getpriority(libc::PRIO_PROCESS, tid);
        let _ = libc::setpriority(libc::PRIO_PROCESS, tid, (cur + by).min(19));
    }
    #[cfg(not(target_os = "linux"))]
    let _ = by;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_count_is_a_quarter_of_the_cores_between_two_and_four() {
        assert_eq!(worker_threads(1), 2);
        assert_eq!(worker_threads(8), 2);
        assert_eq!(worker_threads(16), 4);
        assert_eq!(worker_threads(56), 4);
    }

    #[test]
    fn scoped_without_a_runtime_runs_the_closure() {
        assert_eq!(scoped(|| 7), 7);
    }

    #[test]
    fn tasks_spawned_on_the_consensus_runtime_run_on_its_threads() {
        let consensus = build(8);
        let name = consensus.block_on(async {
            tokio::spawn(async { std::thread::current().name().map(str::to_string) })
                .await
                .unwrap()
        });
        assert_eq!(name.as_deref(), Some("tenzro-consensus"));
    }

    /// Latency of handling a stream of small messages on `rt` while `flood`
    /// keeps the main runtime's workers busy: (p99, max) in milliseconds.
    fn handling_latency(rt: &Runtime, main: &Runtime, flood_ms: u64) -> (u64, u64) {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::{Duration, Instant};

        let stop = Arc::new(AtomicBool::new(false));
        // Public requests: each handler holds a worker for 3 ms of CPU, and
        // far more of them are in flight than the runtime has workers.
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(|| async {
                let t = Instant::now();
                while t.elapsed() < Duration::from_millis(3) {
                    std::hint::spin_loop();
                }
                "ok"
            }),
        );
        for _ in 0..256 {
            let (app, stop) = (app.clone(), stop.clone());
            main.spawn(async move {
                use tower::ServiceExt;
                while !stop.load(Ordering::Relaxed) {
                    let req = axum::http::Request::post("/")
                        .body(axum::body::Body::empty())
                        .unwrap();
                    let _ = app.clone().oneshot(req).await;
                    tokio::task::yield_now().await;
                }
            });
        }
        // The consensus side: a bounded queue of messages stamped when sent,
        // handled by a task on `rt`.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<Instant>(1024);
        let handled = rt.spawn(async move {
            let mut delays = Vec::new();
            while let Some(sent) = rx.recv().await {
                delays.push(sent.elapsed().as_millis() as u64);
            }
            delays
        });
        let producer = std::thread::spawn(move || {
            let until = Instant::now() + Duration::from_millis(flood_ms);
            while Instant::now() < until {
                let _ = tx.try_send(Instant::now());
                std::thread::sleep(Duration::from_millis(2));
            }
        });
        producer.join().unwrap();
        stop.store(true, Ordering::Relaxed);
        let mut delays = rt.block_on(handled).unwrap();
        delays.sort_unstable();
        let p99 = delays[delays.len() * 99 / 100];
        (p99, *delays.last().unwrap())
    }

    /// The stated bound: with the public listener saturated, consensus
    /// messages are handled within this many milliseconds at the 99th
    /// percentile.
    const FLOOD_P99_BOUND_MS: u64 = 100;
    /// And no message waits longer than this.
    const FLOOD_MAX_BOUND_MS: u64 = 500;

    #[test]
    fn a_flood_of_public_requests_cannot_delay_consensus_messages_beyond_the_bound() {
        let main = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let consensus = build(8);
        let (p99, max) = handling_latency(&consensus, &main, 3_000);
        eprintln!("consensus runtime under flood: p99 {p99} ms, max {max} ms");
        assert!(
            p99 <= FLOOD_P99_BOUND_MS,
            "p99 {p99} ms over {FLOOD_P99_BOUND_MS}"
        );
        assert!(
            max <= FLOOD_MAX_BOUND_MS,
            "max {max} ms over {FLOOD_MAX_BOUND_MS}"
        );
        // The same handler on the saturated runtime itself, for comparison.
        let (shared_p99, shared_max) = handling_latency(&main, &main, 3_000);
        eprintln!("shared runtime under flood: p99 {shared_p99} ms, max {shared_max} ms");
    }
}
