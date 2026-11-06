//! Panic diagnostics for exit paths Tauri's normal hooks don't cover.
//!
//! Tauri 2.11 + macOS arm64 has several documented ways for the parent
//! process to die WITHOUT firing `RunEvent::ExitRequested`,
//! `RunEvent::Exit`, `WindowEvent::CloseRequested`, or the Unix-signal
//! listener:
//!
//! 1. **Non-unwinding panic in wry's WKWebView callbacks**
//!    (tauri-apps/tauri#12338) — `wry` wraps callbacks in
//!    `AssertUnwindSafe`, so a panic there becomes `thread caused
//!    non-unwinding panic. aborting.` and the process abort()s without
//!    unwinding. No Rust panic hook runs.
//! 2. **Silent panic in `tauri::async_runtime::spawn`** — tokio catches
//!    panics into the JoinHandle. If nothing `.await`s the handle, the
//!    panic is lost when the handle drops.
//! 3. **Double-panic during Drop** — the first panic fires the hook, the
//!    second triggers `abort()` often with no extra message.
//! 4. **Cmd-Q / quit-from-Dock on macOS** — `RunEvent::ExitRequested` is
//!    not always fired (tauri-apps/tauri#9198) because Tauri 2.11 doesn't
//!    hook `applicationShouldTerminate:`.
//!
//! The embedded node runs in-process, so there is no orphaned child to
//! reap on any of these paths — the node dies with the process. What is
//! still lost is the diagnosis, because classes 1 and 3 leave no stderr
//! panic line and no `.ips` report. This module installs a panic hook
//! that captures the payload, location and backtrace into the rolling
//! log file before the process goes down.
//!
//! Sources:
//! - <https://github.com/tauri-apps/tauri/issues/12338>
//! - <https://github.com/tauri-apps/tauri/issues/9198>

use std::backtrace::Backtrace;
use std::sync::OnceLock;

/// One-time slot guarding `install_safety_net` against a double-call,
/// which would chain hook closures forever.
static INSTALLED: OnceLock<()> = OnceLock::new();

/// Install the panic hook. Call ONCE at the very start of `run()`, before
/// any other initialisation, so it is armed before anything that could
/// panic. Subsequent calls are no-ops.
pub fn install_safety_net() {
    if INSTALLED.set(()).is_err() {
        return;
    }

    // Force backtraces even if the user didn't set RUST_BACKTRACE.
    if std::env::var_os("RUST_BACKTRACE").is_none() {
        // SAFETY: env mutation at startup, before any thread is spawned.
        unsafe {
            std::env::set_var("RUST_BACKTRACE", "full");
        }
    }

    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let bt = Backtrace::force_capture();
        let thread = std::thread::current();
        let thread_name = thread.name().unwrap_or("<unnamed>");
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<unknown>".into());
        let payload = info.payload();
        let msg = payload
            .downcast_ref::<&'static str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
            .unwrap_or("<non-string panic payload>");

        tracing::error!(
            target: "panic",
            thread = thread_name,
            location = %location,
            backtrace = %bt,
            "PANIC: {}", msg
        );

        // Defensive stderr in case the tracing appender is already gone.
        eprintln!(
            "\n=== PANIC in thread '{}' at {} ===\npayload: {}\nbacktrace:\n{}",
            thread_name, location, msg, bt
        );

        default_hook(info);

        // Hard exit so a poisoned runtime can't keep limping.
        std::process::exit(101);
    }));
}
