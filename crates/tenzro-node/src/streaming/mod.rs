//! Application-layer streaming primitives for inference SSE.
//!
//! Today's chat-completions SSE handler emits a sequence of tokens to the
//! client over `text/event-stream`. If the transport drops (mobile network
//! flap, TLS reset, proxy timeout) the client loses the in-flight
//! completion. The natural retry — re-issuing the same prompt — duplicates
//! billing and re-generates already-emitted tokens.
//!
//! [`cursor::StreamCursorStore`] solves this by recording every emitted
//! chunk in a short-lived, bounded, in-memory ring keyed by the
//! completion's `request_id`. When a client reconnects with the SSE
//! standard `Last-Event-ID` header set to `<request_id>:<seq>`, the
//! handler replays any chunks with seq > `seq` and then continues live
//! emission. Idempotent at the chunk level, time-bounded at the store
//! level (TTL eviction), memory-bounded at the per-stream level
//! (`MAX_BUFFERED_CHUNKS`).
//!
//! When the drop is on the *provider* leg — the `/v1/chat/completions`
//! handler is proxying to a remote provider and that provider dies
//! mid-generation — [`failover::SamplingState`] captures the sampling
//! parameters and the assistant text emitted so far so a different provider
//! deterministically re-prefills the emitted prefix and continues the same
//! SSE without a visible restart. No KV-cache bytes cross the wire; the
//! receiving provider re-computes the prefix from the emitted text.
//!
//! Out of scope:
//! - KV-cache resume on the model side — the cursor stores text only,
//!   which is enough for client message-reconstruction but not for
//!   skipping regeneration cost on long completions.

pub mod cursor;
pub mod failover;
pub mod heartbeat;
pub mod sla_metrics;

pub use cursor::{
    parse_last_event_id, BackpressureSignal, StreamCursor, StreamCursorStore,
    DEFAULT_TTL, MAX_BUFFERED_CHUNKS,
};
pub use failover::{extract_delta_content, ChatTurn, SamplingState};
pub use heartbeat::{
    with_heartbeat, HeartbeatConfig, HeartbeatedChunk, DEFAULT_HEARTBEAT_INTERVAL,
    DEFAULT_MISSED_THRESHOLD,
};
pub use sla_metrics::{StreamSloMetrics, INTERTOKEN_BUCKETS_S, TTFT_BUCKETS_S};
