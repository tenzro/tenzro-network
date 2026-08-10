//! Event filtering logic
//!
//! Provides a standalone `matches` function that delegates to
//! `EventFilter::matches()` for use by the subscription and streaming layers.

use crate::types::{EventEnvelope, EventFilter};

/// Returns `true` if the envelope passes all filter predicates.
///
/// This is a convenience wrapper around [`EventFilter::matches`] for use
/// in contexts where a free function is preferred (e.g., iterator adapters).
pub fn matches(filter: &EventFilter, envelope: &EventEnvelope) -> bool {
    filter.matches(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EventType, TenzroEvent, VmType};

    fn make_envelope() -> EventEnvelope {
        EventEnvelope {
            sequence: 1,
            timestamp: 1700000000,
            block_height: Some(10),
            vm_type: Some(VmType::Evm),
            event: TenzroEvent::NewBlock {
                block_hash: [0u8; 32],
                parent_hash: [0u8; 32],
                height: 10,
                tx_count: 1,
                proposer: [0u8; 20],
            },
        }
    }

    #[test]
    fn test_matches_empty_filter() {
        let filter = EventFilter::new();
        assert!(matches(&filter, &make_envelope()));
    }

    #[test]
    fn test_matches_event_type_filter() {
        let filter = EventFilter::new().with_event_types(vec![EventType::Transfer]);
        assert!(!matches(&filter, &make_envelope()));
    }

    #[test]
    fn test_matches_block_range_filter() {
        let mut filter = EventFilter::new();
        filter.from_block = Some(5);
        filter.to_block = Some(15);
        assert!(matches(&filter, &make_envelope()));

        let mut filter_above = EventFilter::new();
        filter_above.from_block = Some(20);
        assert!(!matches(&filter_above, &make_envelope()));
    }
}
