//! Cursor-based historical replay engine
//!
//! Seamlessly blends stored historical events with live streaming
//! (hybrid replay model). Detects gaps in the sequence and reports
//! them so the caller can decide whether to fill or skip.

use crate::store::EventStore;
use crate::types::EventEnvelope;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::debug;

/// Describes a gap in the event sequence (missing events between two
/// stored events).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayGap {
    /// First missing sequence number.
    pub from: u64,
    /// Last missing sequence number (inclusive).
    pub to: u64,
}

impl ReplayGap {
    /// Number of missing events in this gap.
    pub fn len(&self) -> u64 {
        self.to.saturating_sub(self.from) + 1
    }

    /// Whether this gap is empty (should not happen in practice).
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Replay engine for cursor-based historical event retrieval.
pub struct ReplayEngine {
    store: Arc<EventStore>,
}

impl ReplayEngine {
    /// Create a new replay engine backed by the given event store.
    pub fn new(store: Arc<EventStore>) -> Self {
        Self { store }
    }

    /// Replay events from `from_sequence` up to `limit` events.
    pub fn replay(
        &self,
        from_sequence: u64,
        limit: usize,
    ) -> Result<Vec<EventEnvelope>, crate::error::EventError> {
        debug!(from = from_sequence, limit, "replaying events");
        self.store.query_from(from_sequence, limit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_gap_len() {
        let gap = ReplayGap { from: 5, to: 10 };
        assert_eq!(gap.len(), 6);
        assert!(!gap.is_empty());
    }
}
