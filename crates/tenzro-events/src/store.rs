//! Persistent event storage backed by RocksDB
//!
//! Stores EventEnvelopes keyed by sequence number for durable replay.
//! Uses the CF_EVENTS column family in the shared KvStore.

use crate::error::{EventError, Result};
use crate::types::EventEnvelope;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tenzro_storage::KvStore;
use tracing::{debug, info};

/// Persistent event store
pub struct EventStore {
    storage: Arc<dyn KvStore>,
    max_sequence: AtomicU64,
}

impl EventStore {
    /// Create a new EventStore backed by the given KvStore.
    /// Scans existing events to find the max sequence number.
    pub fn new(storage: Arc<dyn KvStore>) -> Result<Self> {
        let mut max_seq = 0u64;
        let existing = storage
            .scan_prefix(crate::CF_EVENTS, b"")
            .map_err(|e| EventError::StorageError(e.to_string()))?;
        for (key, _) in &existing {
            if key.len() == 8 {
                let seq = u64::from_be_bytes(key[..8].try_into().unwrap());
                if seq > max_seq {
                    max_seq = seq;
                }
            }
        }
        info!(max_sequence = max_seq, events_count = existing.len(), "event store initialized");
        Ok(Self {
            storage,
            max_sequence: AtomicU64::new(max_seq),
        })
    }

    /// Store an event envelope.
    pub fn store(&self, event: &EventEnvelope) -> Result<()> {
        let key = event.sequence.to_be_bytes();
        let value = serde_json::to_vec(event)?;
        self.storage
            .put(crate::CF_EVENTS, &key, &value)
            .map_err(|e| EventError::StorageError(e.to_string()))?;
        let _ = self.max_sequence.fetch_max(event.sequence, Ordering::SeqCst);
        debug!(sequence = event.sequence, "event stored");
        Ok(())
    }

    /// Get an event by sequence number.
    pub fn get(&self, sequence: u64) -> Result<Option<EventEnvelope>> {
        let key = sequence.to_be_bytes();
        match self
            .storage
            .get(crate::CF_EVENTS, &key)
            .map_err(|e| EventError::StorageError(e.to_string()))?
        {
            Some(bytes) => {
                let event: EventEnvelope = serde_json::from_slice(&bytes)?;
                Ok(Some(event))
            }
            None => Ok(None),
        }
    }

    /// Query events from a starting sequence, up to limit.
    pub fn query_from(&self, from_sequence: u64, limit: usize) -> Result<Vec<EventEnvelope>> {
        let max = self.max_sequence.load(Ordering::SeqCst);
        let mut results = Vec::with_capacity(limit.min(1024));
        let mut seq = from_sequence;
        while seq <= max && results.len() < limit {
            if let Some(event) = self.get(seq)? {
                results.push(event);
            }
            seq += 1;
        }
        Ok(results)
    }

    /// Get the current maximum sequence number.
    pub fn max_sequence(&self) -> u64 {
        self.max_sequence.load(Ordering::SeqCst)
    }

    /// Get the total number of stored events (approximate).
    pub fn count(&self) -> Result<usize> {
        let keys = self
            .storage
            .get_keys_with_prefix(crate::CF_EVENTS, b"")
            .map_err(|e| EventError::StorageError(e.to_string()))?;
        Ok(keys.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{TenzroEvent, VmType};
    use tenzro_storage::MemoryStore;

    fn make_store() -> EventStore {
        let mem = Arc::new(MemoryStore::new());
        EventStore::new(mem).unwrap()
    }

    fn make_envelope(seq: u64, height: u64) -> EventEnvelope {
        EventEnvelope {
            sequence: seq,
            timestamp: 1700000000 + seq as i64,
            block_height: Some(height),
            vm_type: Some(VmType::Native),
            event: TenzroEvent::NewBlock {
                block_hash: [seq as u8; 32],
                parent_hash: [0u8; 32],
                height,
                tx_count: 1,
                proposer: [0u8; 20],
            },
        }
    }

    #[test]
    fn test_store_and_get() {
        let store = make_store();
        let env = make_envelope(1, 10);
        store.store(&env).unwrap();
        let retrieved = store.get(1).unwrap().unwrap();
        assert_eq!(retrieved.sequence, 1);
    }

    #[test]
    fn test_query_from() {
        let store = make_store();
        for i in 1..=5 {
            store.store(&make_envelope(i, i * 10)).unwrap();
        }
        let results = store.query_from(3, 100).unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].sequence, 3);
    }

    #[test]
    fn test_get_nonexistent() {
        let store = make_store();
        assert!(store.get(999).unwrap().is_none());
    }

    #[test]
    fn test_max_sequence() {
        let store = make_store();
        assert_eq!(store.max_sequence(), 0);
        store.store(&make_envelope(5, 50)).unwrap();
        assert_eq!(store.max_sequence(), 5);
    }
}
