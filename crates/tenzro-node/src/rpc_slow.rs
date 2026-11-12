//! Slow-request warning for the JSON-RPC dispatcher.
//!
//! Every RPC call, whichever transport it arrives on (HTTP, the gateway,
//! the admin-audit path, the embedded client), runs through
//! [`crate::rpc::handle_request`], which wraps the dispatch in
//! [`warn_if_slow`]. A call that takes longer than [`SLOW_RPC`] to finish
//! logs one `warn!` with the method and the measured duration. The wrapper
//! only measures: it does not change the result, the timing, or any decision.
//! A call whose caller gives up before it finishes (the future is dropped)
//! logs nothing.

use std::future::Future;
use std::time::{Duration, Instant};

/// An RPC call that takes longer than this to complete is logged.
pub(crate) const SLOW_RPC: Duration = Duration::from_millis(500);

/// Await `fut`; if it took longer than `threshold`, warn with `method` and
/// the actual duration. Returns `fut`'s output untouched.
pub(crate) async fn warn_if_slow<F: Future>(
    method: &str,
    threshold: Duration,
    fut: F,
) -> F::Output {
    let started = Instant::now();
    let output = fut.await;
    let took = started.elapsed();
    if took > threshold {
        tracing::warn!(
            method,
            duration_ms = took.as_millis() as u64,
            threshold_ms = threshold.as_millis() as u64,
            "slow RPC request"
        );
    }
    output
}

#[cfg(test)]
pub(crate) mod test_capture {
    //! Captures what `tracing` logs on the current thread.
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    pub(crate) struct Buf(pub(crate) Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for Buf {
        type Writer = Buf;
        fn make_writer(&'a self) -> Buf {
            self.clone()
        }
    }

    impl Buf {
        pub(crate) fn text(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    /// Route this thread's logs into the returned buffer until the guard drops.
    pub(crate) fn capture() -> (Buf, tracing::subscriber::DefaultGuard) {
        let buf = Buf::default();
        let sub = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::DEBUG)
            .finish();
        (buf, tracing::subscriber::set_default(sub))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn a_call_slower_than_the_threshold_warns_with_method_and_duration() {
        let (log, _guard) = test_capture::capture();
        let out = warn_if_slow("tenzro_slowThing", Duration::from_millis(50), async {
            tokio::time::sleep(Duration::from_millis(120)).await;
            7
        })
        .await;
        assert_eq!(out, 7, "the result passes through untouched");
        let text = log.text();
        println!("{text}");
        assert!(text.contains("WARN"), "{text}");
        assert!(text.contains("slow RPC request"), "{text}");
        assert!(text.contains("method=\"tenzro_slowThing\""), "{text}");
        let at = text.find("duration_ms=").expect(&text) + "duration_ms=".len();
        let ms: u64 = text[at..]
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!((120..1_000).contains(&ms), "duration {ms}ms in {text}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_fast_call_does_not_warn() {
        let (log, _guard) = test_capture::capture();
        let out = warn_if_slow("tenzro_fastThing", SLOW_RPC, async { "ok" }).await;
        assert_eq!(out, "ok");
        assert!(log.text().is_empty(), "{}", log.text());
    }

    #[test]
    fn the_threshold_is_500_ms() {
        assert_eq!(SLOW_RPC, Duration::from_millis(500));
    }
}
