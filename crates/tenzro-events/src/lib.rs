//! Event streaming for Tenzro Network.
//!
//! Two streams, one filter vocabulary:
//!
//! - The chain's events ([`tenzro_types::chain_event::ChainEvent`]): every
//!   outcome and log a block's execution emitted, committed in the block
//!   header, kept in the durable [`log::EventLog`] under cursors, and
//!   provable against a certified checkpoint.
//! - The node's live events ([`TenzroEvent`]): what this node observes as it
//!   serves (inference streams, workflows), broadcast on the [`EventBus`].
//!   An event about a resource reaches a reader only as the resource's
//!   visibility allows ([`types::delivers`]).
//!
//! ```text
//! block execution --> header event root --> checkpoint certificate
//!        |
//!        v
//!    EventLog (cursor-keyed, durable) --> subscribe from a cursor, range query with proofs
//!
//! node subsystems --> EventBus (ring buffer) --> live subscribers, visibility-gated
//! ```

pub mod bus;
pub mod log;
pub mod types;

// Re-export commonly used types
pub use bus::{
    EventBus, EventBusConfig, EventBusError, EventBusStats, EventSubscriber,
    FilteredEventSubscriber, StatsSnapshot,
};
pub use log::{EventLog, Page};
pub use types::{
    EventEnvelope, EventFilter, EventResource, EventType, StreamReader, SubscriptionConfig,
    SubscriptionId, TenzroEvent, VmType, delivers, event_type_name,
};

/// Event streaming crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default event bus capacity (number of events in ring buffer)
pub const DEFAULT_BUS_CAPACITY: usize = 65536;

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
    }
}
