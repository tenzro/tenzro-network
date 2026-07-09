//! Stream cursor — SSE resume + backpressure observability.

use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long a completed stream remains queryable after its final chunk.
///
/// 5 minutes covers the typical client reconnect window (mobile flap +
/// retry-with-backoff) without retaining state long enough to be a memory
/// or audit-trail concern.
pub const DEFAULT_TTL: Duration = Duration::from_secs(300);

/// How long an *in-flight* stream is kept since its last activity. If a
/// generation runs hot for a long time, this keeps it alive; if the
/// generator stalls and the client never reconnects, the stream eventually
/// gets GC'd.
pub const IN_FLIGHT_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Per-stream chunk-buffer ceiling. Beyond this many chunks the oldest
/// chunks get evicted from the head of the ring — a client that hasn't
/// reconnected by then will receive a partial replay. Sized to comfortably
/// hold a Claude-class 4 KB completion at ~4 chars/token granularity.
pub const MAX_BUFFERED_CHUNKS: usize = 4096;

/// Backpressure signal emitted by the producer side. Surfaced to logs and
/// (in future) metrics so operators can distinguish a genuinely slow
/// generation from a stalled consumer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackpressureSignal {
    /// Send completed within the soft deadline.
    Ok,
    /// Send took longer than the soft deadline but eventually completed.
    /// The producer was effectively blocked on the consumer channel.
    Slow { elapsed_ms: u64 },
}

/// One emitted SSE chunk's recorded state.
#[derive(Debug, Clone)]
pub struct RecordedChunk {
    pub seq: u64,
    /// The raw event payload (JSON, no `data:` framing — axum's
    /// `Event::data()` adds the SSE line framing). Storing the exact
    /// payload the live path emitted means replay is a verbatim copy —
    /// no risk of re-serialization drift between live and replay paths.
    pub encoded: String,
    /// Optional named SSE event type (e.g. "content_block_delta"). For
    /// the OpenAI-shape stream this is `None`.
    pub event: Option<String>,
}

/// In-memory state for a single in-flight or recently-completed stream.
#[derive(Debug)]
pub struct StreamCursor {
    /// Stable request id (the completion id we already emit). Used as
    /// the prefix of every SSE `id:` value and as the key in the store.
    pub request_id: String,
    /// Ring buffer of recorded chunks. Oldest at head.
    pub chunks: VecDeque<RecordedChunk>,
    /// Highest `seq` we've recorded. Always equals
    /// `chunks.back().seq` when chunks is non-empty.
    pub last_seq: u64,
    /// Set once the producer finalizes the stream. After this, a
    /// reconnect replays the tail and closes with no further live
    /// emission.
    pub finished: bool,
    /// Last time we recorded or replayed activity. Drives the GC.
    pub last_activity: Instant,
    /// When the cursor was first created.
    pub created_at: Instant,
}

impl StreamCursor {
    pub fn new(request_id: String) -> Self {
        Self {
            request_id,
            chunks: VecDeque::new(),
            last_seq: 0,
            finished: false,
            last_activity: Instant::now(),
            created_at: Instant::now(),
        }
    }

    /// Record a chunk. Returns the assigned `seq`. `event` is the named
    /// SSE event type if any (Anthropic-shape) — for OpenAI-shape leave it
    /// `None`.
    pub fn record(&mut self, encoded: String, event: Option<String>) -> u64 {
        // First chunk is seq=0, subsequent +1. We initialize last_seq=0
        // and chunks empty, so we use chunks.len() as the seq for the
        // first chunk and last_seq+1 thereafter — handle uniformly with
        // an explicit counter.
        let seq = if self.chunks.is_empty() {
            0
        } else {
            self.last_seq + 1
        };
        self.chunks.push_back(RecordedChunk {
            seq,
            encoded,
            event,
        });
        // Cap the ring.
        while self.chunks.len() > MAX_BUFFERED_CHUNKS {
            self.chunks.pop_front();
        }
        self.last_seq = seq;
        self.last_activity = Instant::now();
        seq
    }

    /// Mark this stream as fully emitted. Subsequent reconnects replay
    /// whatever's left in the ring and then close.
    pub fn finish(&mut self) {
        self.finished = true;
        self.last_activity = Instant::now();
    }

    /// Return every recorded chunk with `seq` strictly greater than
    /// `after_seq`. Used during the replay leg of a reconnect.
    pub fn replay_after(&self, after_seq: u64) -> Vec<RecordedChunk> {
        self.chunks
            .iter()
            .filter(|c| c.seq > after_seq)
            .cloned()
            .collect()
    }
}

/// Concurrent store of active and recently-completed cursors. Cheap to
/// `clone()` (it's an `Arc<DashMap>`).
#[derive(Debug, Clone, Default)]
pub struct StreamCursorStore {
    inner: Arc<DashMap<String, StreamCursor>>,
}

impl StreamCursorStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a fresh cursor for `request_id`. If one already exists with
    /// the same id it is *replaced* — request_ids are UUIDs so a true
    /// collision is impossible; the replace branch only fires if the
    /// same handler is invoked twice for the same uuid, which is a bug
    /// upstream and is left as a no-op-overwrite rather than an error.
    pub fn create(&self, request_id: &str) {
        self.inner
            .insert(request_id.to_string(), StreamCursor::new(request_id.to_string()));
    }

    /// Record a chunk against `request_id`. Returns the assigned `seq`,
    /// or `None` if the cursor doesn't exist (the caller should `create`
    /// first).
    pub fn record(&self, request_id: &str, encoded: String, event: Option<String>) -> Option<u64> {
        let mut entry = self.inner.get_mut(request_id)?;
        Some(entry.record(encoded, event))
    }

    /// Mark a stream as fully emitted.
    pub fn finish(&self, request_id: &str) {
        if let Some(mut entry) = self.inner.get_mut(request_id) {
            entry.finish();
        }
    }

    /// Replay chunks with seq > `after_seq`. Returns `(chunks, finished)`
    /// where `finished` indicates the producer already closed the stream
    /// (so the reconnect handler should send the replay and then close).
    /// Returns `None` if no cursor for that request_id exists (either
    /// already GC'd or never created — the reconnecting client should be
    /// told the resume is no longer possible).
    pub fn replay(&self, request_id: &str, after_seq: u64) -> Option<(Vec<RecordedChunk>, bool)> {
        let mut entry = self.inner.get_mut(request_id)?;
        let chunks = entry.replay_after(after_seq);
        entry.last_activity = Instant::now();
        Some((chunks, entry.finished))
    }

    /// Total number of tracked streams.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Drop streams whose last activity is older than the appropriate
    /// per-state idle timeout. Returns the number evicted. Safe to call
    /// concurrently with live traffic — DashMap shards under the hood.
    pub fn gc(&self, now: Instant) -> usize {
        let mut to_remove: Vec<String> = Vec::new();
        for entry in self.inner.iter() {
            let idle = now.saturating_duration_since(entry.last_activity);
            let limit = if entry.finished {
                DEFAULT_TTL
            } else {
                IN_FLIGHT_IDLE_TIMEOUT
            };
            if idle > limit {
                to_remove.push(entry.key().clone());
            }
        }
        let removed = to_remove.len();
        for k in to_remove {
            self.inner.remove(&k);
        }
        removed
    }

    /// Spawn the GC loop. Returns the join handle for the caller to keep
    /// alive (or drop, which aborts the task).
    pub fn spawn_gc(self: &Self, period: Duration) -> tokio::task::JoinHandle<()> {
        let store = self.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(period);
            // First tick fires immediately; skip it so we don't churn at startup.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let n = store.gc(Instant::now());
                if n > 0 {
                    tracing::debug!(evicted = n, total = store.len(),
                        "stream cursor gc");
                }
            }
        })
    }
}

/// Parse an SSE `Last-Event-ID` header value of the shape
/// `<request_id>:<seq>` into its parts. Tolerates `request_id` containing
/// hyphens (uuid v4 with dashes is the canonical shape) — splits on the
/// **last** colon only.
pub fn parse_last_event_id(value: &str) -> Option<(String, u64)> {
    let (rid, seq_str) = value.rsplit_once(':')?;
    if rid.is_empty() {
        return None;
    }
    let seq: u64 = seq_str.parse().ok()?;
    Some((rid.to_string(), seq))
}

/// Permit-based send with backpressure observation. Acquires a slot
/// first (this is where the natural wait happens on a full bounded
/// channel), times the wait, then writes the value. The value is never
/// consumed by a timed-out future, so we can safely both signal and
/// deliver.
pub async fn observe_and_send<T>(
    tx: &tokio::sync::mpsc::Sender<T>,
    item: T,
    soft_deadline: Duration,
) -> std::result::Result<BackpressureSignal, tokio::sync::mpsc::error::SendError<T>> {
    let start = Instant::now();
    let permit = match tokio::time::timeout(soft_deadline, tx.reserve()).await {
        Ok(Ok(permit)) => {
            permit.send(item);
            return Ok(BackpressureSignal::Ok);
        }
        Ok(Err(_closed)) => {
            return Err(tokio::sync::mpsc::error::SendError(item));
        }
        Err(_) => {
            // Deadline elapsed before a permit was available — wait the
            // rest of the way, but flag the stall.
            match tx.reserve().await {
                Ok(p) => p,
                Err(_) => return Err(tokio::sync::mpsc::error::SendError(item)),
            }
        }
    };
    permit.send(item);
    let elapsed_ms = start.elapsed().as_millis() as u64;
    Ok(BackpressureSignal::Slow { elapsed_ms })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_records_monotonic_seqs() {
        let mut c = StreamCursor::new("rid".into());
        assert_eq!(c.record("a".into(), None), 0);
        assert_eq!(c.record("b".into(), None), 1);
        assert_eq!(c.record("c".into(), None), 2);
        assert_eq!(c.last_seq, 2);
        assert_eq!(c.chunks.len(), 3);
    }

    #[test]
    fn cursor_replay_filters_after_seq() {
        let mut c = StreamCursor::new("rid".into());
        for i in 0..5 {
            c.record(format!("d{i}"), None);
        }
        let replay = c.replay_after(2);
        assert_eq!(replay.len(), 2);
        assert_eq!(replay[0].seq, 3);
        assert_eq!(replay[1].seq, 4);
    }

    #[test]
    fn cursor_replay_from_zero_returns_all_after_first() {
        let mut c = StreamCursor::new("rid".into());
        for i in 0..3 {
            c.record(format!("d{i}"), None);
        }
        // after_seq=0 means client got chunk seq 0; replay 1..=2.
        let replay = c.replay_after(0);
        assert_eq!(replay.len(), 2);
    }

    #[test]
    fn cursor_ring_caps_at_max_buffered() {
        let mut c = StreamCursor::new("rid".into());
        for i in 0..(MAX_BUFFERED_CHUNKS + 10) {
            c.record(format!("d{i}"), None);
        }
        assert_eq!(c.chunks.len(), MAX_BUFFERED_CHUNKS);
        // The 10 oldest should have been evicted; the front seq should
        // be the 10th recorded (== 10).
        assert_eq!(c.chunks.front().unwrap().seq, 10);
        assert_eq!(c.last_seq, MAX_BUFFERED_CHUNKS as u64 + 9);
    }

    #[test]
    fn store_create_record_replay_roundtrip() {
        let s = StreamCursorStore::new();
        s.create("rid");
        assert_eq!(s.record("rid", "a".into(), None), Some(0));
        assert_eq!(s.record("rid", "b".into(), None), Some(1));
        let (chunks, finished) = s.replay("rid", 0).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0].seq, 1);
        assert!(!finished);
        s.finish("rid");
        let (_, finished) = s.replay("rid", 1).unwrap();
        assert!(finished);
    }

    #[test]
    fn store_unknown_request_id_replays_none() {
        let s = StreamCursorStore::new();
        assert!(s.replay("nope", 0).is_none());
        assert_eq!(s.record("nope", "x".into(), None), None);
    }

    #[test]
    fn store_gc_evicts_finished_streams_past_ttl() {
        let s = StreamCursorStore::new();
        s.create("a");
        s.record("a", "chunk".into(), None);
        s.finish("a");
        // Force last_activity into the past.
        {
            let mut entry = s.inner.get_mut("a").unwrap();
            entry.last_activity = Instant::now() - DEFAULT_TTL - Duration::from_secs(1);
        }
        let removed = s.gc(Instant::now());
        assert_eq!(removed, 1);
        assert!(s.replay("a", 0).is_none());
    }

    #[test]
    fn store_gc_evicts_stalled_in_flight_past_idle_timeout() {
        let s = StreamCursorStore::new();
        s.create("a");
        s.record("a", "chunk".into(), None);
        // NOT finished — should use IN_FLIGHT_IDLE_TIMEOUT (10 min), not TTL.
        {
            let mut entry = s.inner.get_mut("a").unwrap();
            entry.last_activity = Instant::now() - DEFAULT_TTL - Duration::from_secs(1);
        }
        // Within in-flight window — should NOT evict.
        let removed = s.gc(Instant::now());
        assert_eq!(removed, 0);
        // Push past the in-flight window.
        {
            let mut entry = s.inner.get_mut("a").unwrap();
            entry.last_activity =
                Instant::now() - IN_FLIGHT_IDLE_TIMEOUT - Duration::from_secs(1);
        }
        let removed = s.gc(Instant::now());
        assert_eq!(removed, 1);
    }

    #[test]
    fn parse_last_event_id_basic() {
        let (rid, seq) = parse_last_event_id("chatcmpl-abc-def:42").unwrap();
        assert_eq!(rid, "chatcmpl-abc-def");
        assert_eq!(seq, 42);
    }

    #[test]
    fn parse_last_event_id_rejects_malformed() {
        assert!(parse_last_event_id("no_colon").is_none());
        assert!(parse_last_event_id(":12").is_none());
        assert!(parse_last_event_id("rid:notanumber").is_none());
    }

    #[tokio::test]
    async fn observe_and_send_signals_ok_under_deadline() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<u32>(8);
        let sig = observe_and_send(&tx, 1, Duration::from_millis(100))
            .await
            .unwrap();
        assert_eq!(sig, BackpressureSignal::Ok);
        assert_eq!(rx.recv().await, Some(1));
    }

    #[tokio::test]
    async fn observe_and_send_signals_slow_when_blocked() {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<u32>(1);
        // Fill the channel.
        tx.send(1).await.unwrap();
        // Spawn a consumer that drains after a delay.
        let drain = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(80)).await;
            assert_eq!(rx.recv().await, Some(1));
            assert_eq!(rx.recv().await, Some(2));
        });
        let sig = observe_and_send(&tx, 2, Duration::from_millis(20))
            .await
            .unwrap();
        match sig {
            BackpressureSignal::Slow { elapsed_ms } => {
                assert!(elapsed_ms >= 20, "elapsed_ms = {elapsed_ms}");
            }
            other => panic!("expected Slow, got {other:?}"),
        }
        drain.await.unwrap();
    }
}
