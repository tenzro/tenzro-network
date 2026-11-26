//! The node inside an Android app's process. The app's foreground service
//! calls [`run`] on a thread of its own and [`request_stop`] when it is
//! destroyed; the node then shuts down as it does on SIGTERM.

use std::sync::atomic::{AtomicBool, Ordering};

static RUNNING: AtomicBool = AtomicBool::new(false);
static STOP_ASKED: AtomicBool = AtomicBool::new(false);
static STOP: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// Runs the node with `args` (the command line after the program name) until
/// it is stopped or fails. One node per process: a second run while one is
/// running is refused.
pub fn run(args: Vec<String>) -> Result<(), String> {
    if RUNNING.swap(true, Ordering::SeqCst) {
        return Err("a node is already running in this process".into());
    }
    STOP_ASKED.store(false, Ordering::SeqCst);
    let out = crate::node_main::run_embedded(args).map_err(|e| e.to_string());
    RUNNING.store(false, Ordering::SeqCst);
    out
}

/// Asks the running node to stop. A request that comes before the node
/// waits for one is kept for it; one with no node running does nothing.
pub fn request_stop() {
    if RUNNING.load(Ordering::SeqCst) {
        STOP_ASKED.store(true, Ordering::SeqCst);
        STOP.notify_waiters();
    }
}

/// Resolves when the app has asked the running node to stop.
pub(crate) async fn stop_requested() {
    loop {
        // Made before the flag is read, so a request between the two wakes it.
        let woken = STOP.notified();
        if STOP_ASKED.load(Ordering::SeqCst) {
            return;
        }
        woken.await;
    }
}
