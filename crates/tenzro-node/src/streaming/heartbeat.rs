//! Per-stream heartbeat watchdog.
//!
//! An SSE proxy stream that's still TCP-healthy but has produced no tokens
//! for tens of seconds is a stuck provider — the upstream's generator
//! deadlocked, the model is OOM, the GPU is wedged, anything. The
//! transport layer (libp2p keepalive, TCP, QUIC) can't see this: as far as
//! it knows the connection is fine. So we lift detection up to the
//! application layer: every chunk we observe resets a watchdog; if the
//! watchdog fires twice in a row without a chunk, we treat the stream as
//! unhealthy and tear it down.
//!
//! The detection budget — `interval * missed_threshold` — is the time
//! between "everything looks fine" and "this provider is stuck". With the
//! defaults (5 s × 2) that's 10 s, which matches the acceptance criterion
//! in `project_roadmap_streaming_stability.md` P1.1.
//!
//! This module is **stream-agnostic** — it works over any
//! `Stream<Item = Result<T, E>>`. The proxy SSE handler in `rpc.rs` wraps
//! `reqwest::Response::bytes_stream()`; future call sites (local-model
//! token stream, A2A stream, ...) can plug in directly.

use std::time::Duration;

/// How often the watchdog ticks. Each tick that elapses without a chunk
/// increments a "missed" counter.
pub const DEFAULT_HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// How many consecutive missed ticks trigger a stall. Two ticks at the
/// default interval = a 10 s budget between last chunk and stall, which
/// is short enough that operators notice but long enough that a slow
/// long-prompt generation (first-token latency 6-8 s on big models) isn't
/// misclassified.
pub const DEFAULT_MISSED_THRESHOLD: u32 = 2;

/// Watchdog configuration.
#[derive(Debug, Clone, Copy)]
pub struct HeartbeatConfig {
    pub interval: Duration,
    pub missed_threshold: u32,
}

impl Default for HeartbeatConfig {
    fn default() -> Self {
        Self {
            interval: DEFAULT_HEARTBEAT_INTERVAL,
            missed_threshold: DEFAULT_MISSED_THRESHOLD,
        }
    }
}

impl HeartbeatConfig {
    /// Total detection budget: `interval * missed_threshold`.
    pub fn stall_budget(&self) -> Duration {
        self.interval
            .saturating_mul(self.missed_threshold.max(1))
    }
}

/// One event from a heartbeated stream.
#[derive(Debug)]
pub enum HeartbeatedChunk<T, E> {
    /// A real upstream chunk (or per-chunk error from the underlying
    /// stream).
    Chunk(Result<T, E>),
    /// The watchdog fired `missed_threshold` consecutive times without
    /// seeing a chunk. The caller should treat the stream as failed.
    Stalled { silent_for_ms: u64 },
}

/// Wrap a `Stream<Item = Result<T, E>>` in a heartbeat watchdog.
///
/// The returned stream yields `HeartbeatedChunk::Chunk` for every upstream
/// item. If `cfg.interval * cfg.missed_threshold` elapses with no item, it
/// yields exactly one `HeartbeatedChunk::Stalled { .. }` and then ends.
///
/// The stream also ends naturally when the underlying stream ends (no
/// trailing event after the last `Chunk`).
pub fn with_heartbeat<S, T, E>(
    inner: S,
    cfg: HeartbeatConfig,
) -> impl futures::Stream<Item = HeartbeatedChunk<T, E>>
where
    S: futures::Stream<Item = Result<T, E>> + Unpin,
{
    let budget = cfg.stall_budget();
    async_stream::stream! {
        use futures::StreamExt;
        let mut stream = inner;
        let mut last_activity = std::time::Instant::now();
        loop {
            match tokio::time::timeout(budget, stream.next()).await {
                Ok(Some(item)) => {
                    last_activity = std::time::Instant::now();
                    yield HeartbeatedChunk::Chunk(item);
                }
                Ok(None) => {
                    // Underlying stream ended — terminate without
                    // emitting a stall (clean close).
                    break;
                }
                Err(_elapsed) => {
                    // Budget elapsed without a chunk. Emit one stall and
                    // terminate; the caller charges the provider and
                    // closes the SSE.
                    let silent_for_ms = last_activity.elapsed().as_millis() as u64;
                    yield HeartbeatedChunk::Stalled { silent_for_ms };
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::StreamExt;
    use tokio::time::Duration as TDuration;

    #[tokio::test]
    async fn passes_through_chunks_under_budget() {
        let cfg = HeartbeatConfig {
            interval: TDuration::from_millis(50),
            missed_threshold: 2,
        };
        // Inner stream yields three items quickly, then ends.
        let inner = futures::stream::iter(vec![
            Ok::<u32, ()>(1),
            Ok(2),
            Ok(3),
        ]);
        let mut out = Box::pin(with_heartbeat(inner, cfg));
        let mut seen = Vec::new();
        let mut stalled = false;
        while let Some(ev) = out.next().await {
            match ev {
                HeartbeatedChunk::Chunk(Ok(v)) => seen.push(v),
                HeartbeatedChunk::Chunk(Err(())) => panic!("unexpected err"),
                HeartbeatedChunk::Stalled { .. } => stalled = true,
            }
        }
        assert_eq!(seen, vec![1, 2, 3]);
        assert!(!stalled, "should not stall on a fast stream");
    }

    #[tokio::test]
    async fn emits_stall_when_inner_goes_silent() {
        // Inner stream yields one item then sleeps forever.
        let inner = async_stream::stream! {
            yield Ok::<u32, ()>(1);
            // Sleep well past the budget.
            tokio::time::sleep(TDuration::from_secs(60)).await;
            yield Ok(2);
        };
        let cfg = HeartbeatConfig {
            interval: TDuration::from_millis(30),
            missed_threshold: 2,
        };
        let mut out = Box::pin(with_heartbeat(Box::pin(inner), cfg));
        // First event is the real chunk.
        match out.next().await {
            Some(HeartbeatedChunk::Chunk(Ok(1))) => {}
            other => panic!("expected Chunk(1), got {other:?}"),
        }
        // Second event is the stall — should fire within ~budget = 60ms,
        // not 60s. Give a generous outer timeout for CI slowness.
        let stall = tokio::time::timeout(TDuration::from_secs(2), out.next())
            .await
            .expect("watchdog did not fire within outer timeout");
        match stall {
            Some(HeartbeatedChunk::Stalled { silent_for_ms }) => {
                assert!(
                    silent_for_ms >= 30,
                    "silent_for_ms={silent_for_ms} should be >= one interval"
                );
            }
            other => panic!("expected Stalled, got {other:?}"),
        }
        // Stream should be done after one stall.
        assert!(out.next().await.is_none(), "stream must end after stall");
    }

    #[tokio::test]
    async fn clean_termination_does_not_stall() {
        // Inner stream yields nothing and ends immediately.
        let inner = futures::stream::iter(Vec::<Result<u32, ()>>::new());
        let cfg = HeartbeatConfig {
            interval: TDuration::from_millis(30),
            missed_threshold: 2,
        };
        let mut out = Box::pin(with_heartbeat(inner, cfg));
        assert!(out.next().await.is_none(), "empty stream ends cleanly");
    }

    #[test]
    fn stall_budget_multiplies_interval_by_threshold() {
        let cfg = HeartbeatConfig {
            interval: Duration::from_secs(5),
            missed_threshold: 2,
        };
        assert_eq!(cfg.stall_budget(), Duration::from_secs(10));
    }

    #[test]
    fn stall_budget_min_one_tick() {
        let cfg = HeartbeatConfig {
            interval: Duration::from_secs(5),
            missed_threshold: 0,
        };
        // missed_threshold=0 would be a degenerate "always stall" — clamp
        // to one tick so callers can't accidentally configure a stream
        // that always reports unhealthy.
        assert_eq!(cfg.stall_budget(), Duration::from_secs(5));
    }
}
