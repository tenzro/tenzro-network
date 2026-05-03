//! Real-time event streaming, subscriptions, and webhook delivery for Tenzro Network
//!
//! This crate provides a unified event model across all VMs and subsystems
//! with monotonic sequencing, cursor-based replay, and rich filtering.
//!
//! # Architecture
//!
//! ```text
//! VM Executors / Consensus / Token / Identity
//!     | in-process callbacks
//!     v
//! EventBus (ring buffer, broadcast channels)
//!     +-- Subscribers (unfiltered or filtered)
//!     +-- Future: gRPC, WebSocket, Webhook, Persistence
//! ```

pub mod types;
pub mod bus;

// Re-export commonly used types
pub use types::{
    TenzroEvent, EventEnvelope, EventFilter, EventType, VmType,
    SubscriptionId, SubscriptionConfig, event_type_name,
};
pub use bus::{
    EventBus, EventBusConfig, EventBusStats, EventBusError,
    EventSubscriber, FilteredEventSubscriber, StatsSnapshot,
};

/// Event streaming crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default event bus capacity (number of events in ring buffer)
pub const DEFAULT_BUS_CAPACITY: usize = 65536;

/// Default event store retention (7 days in seconds)
pub const DEFAULT_RETENTION_SECS: u64 = 604_800;

/// RocksDB column family for event storage
pub const CF_EVENTS: &str = "events";

/// RocksDB column family for event index
pub const CF_EVENT_INDEX: &str = "event_index";

/// RocksDB column family for webhook configuration
pub const CF_WEBHOOKS: &str = "webhooks";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_BUS_CAPACITY, 65536);
        assert_eq!(DEFAULT_RETENTION_SECS, 604_800);
    }
}
