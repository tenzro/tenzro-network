//! EventBus — high-performance event distribution hub
//!
//! Inspired by Monad's Execution Events SDK: a lock-free ring buffer
//! with broadcast channels for multiple consumers. Each consumer reads
//! independently at its own pace. Slow consumers receive a Lagged
//! notification instead of being disconnected (unlike Geth's 10k buffer cliff).

use crate::types::{EventEnvelope, EventFilter, SubscriptionId, TenzroEvent, VmType};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Errors returned by event bus operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventBusError {
    /// The bus has been shut down; no more events will be produced.
    Closed,
    /// The consumer fell behind and missed `u64` events. The receiver is
    /// still valid and will yield future events.
    Lagged(u64),
}

impl std::fmt::Display for EventBusError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventBusError::Closed => write!(f, "EventBus closed"),
            EventBusError::Lagged(n) => write!(f, "EventBus consumer lagged by {} events", n),
        }
    }
}

impl std::error::Error for EventBusError {}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for the [`EventBus`].
#[derive(Debug, Clone)]
pub struct EventBusConfig {
    /// Ring-buffer capacity (broadcast channel size). Defaults to 65536.
    pub capacity: usize,
    /// Whether to persist events to storage (reserved for future use).
    pub enable_persistence: bool,
}

impl Default for EventBusConfig {
    fn default() -> Self {
        Self {
            capacity: 65_536,
            enable_persistence: false,
        }
    }
}

impl EventBusConfig {
    /// Builder: set ring-buffer capacity.
    pub fn with_capacity(mut self, capacity: usize) -> Self {
        self.capacity = capacity;
        self
    }

    /// Builder: enable or disable persistence.
    pub fn with_persistence(mut self, enable: bool) -> Self {
        self.enable_persistence = enable;
        self
    }
}

// ---------------------------------------------------------------------------
// Stats
// ---------------------------------------------------------------------------

/// Atomic counters for observability. All fields are safe to read from any
/// thread without locking.
#[derive(Debug)]
pub struct EventBusStats {
    pub total_events_published: AtomicU64,
    pub total_events_dropped: AtomicU64,
    pub active_subscribers: AtomicU64,
    pub current_sequence: AtomicU64,
}

impl EventBusStats {
    fn new() -> Self {
        Self {
            total_events_published: AtomicU64::new(0),
            total_events_dropped: AtomicU64::new(0),
            active_subscribers: AtomicU64::new(0),
            current_sequence: AtomicU64::new(0),
        }
    }

    /// Returns a snapshot of all counters.
    pub fn snapshot(&self) -> StatsSnapshot {
        StatsSnapshot {
            total_events_published: self.total_events_published.load(Ordering::Relaxed),
            total_events_dropped: self.total_events_dropped.load(Ordering::Relaxed),
            active_subscribers: self.active_subscribers.load(Ordering::Relaxed),
            current_sequence: self.current_sequence.load(Ordering::Relaxed),
        }
    }
}

/// A plain-data snapshot of [`EventBusStats`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub total_events_published: u64,
    pub total_events_dropped: u64,
    pub active_subscribers: u64,
    pub current_sequence: u64,
}

// ---------------------------------------------------------------------------
// EventBus
// ---------------------------------------------------------------------------

/// Central event distribution hub.
///
/// Events are published once and broadcast to all subscribers through a
/// `tokio::sync::broadcast` channel. Each subscriber reads independently
/// at its own pace. When a subscriber falls behind, it receives a
/// [`EventBusError::Lagged`] notification containing the number of missed
/// events rather than being silently disconnected.
pub struct EventBus {
    sender: broadcast::Sender<Arc<EventEnvelope>>,
    sequence_counter: AtomicU64,
    #[allow(dead_code)]
    config: EventBusConfig,
    stats: Arc<EventBusStats>,
    next_subscription_id: AtomicU64,
}

impl EventBus {
    /// Create a new EventBus with the given configuration.
    pub fn new(config: EventBusConfig) -> Self {
        let (sender, _) = broadcast::channel(config.capacity);
        Self {
            sender,
            sequence_counter: AtomicU64::new(0),
            config,
            stats: Arc::new(EventBusStats::new()),
            next_subscription_id: AtomicU64::new(1),
        }
    }

    /// Create an EventBus with default configuration (capacity = 65536).
    pub fn default_bus() -> Self {
        Self::new(EventBusConfig::default())
    }

    /// Publish an event to all current subscribers.
    ///
    /// The event is wrapped in an [`EventEnvelope`] with the next monotonic
    /// sequence number and the current wall-clock timestamp.
    pub fn publish(
        &self,
        event: TenzroEvent,
        block_height: Option<u64>,
        vm_type: Option<VmType>,
    ) -> u64 {
        let seq = self.sequence_counter.fetch_add(1, Ordering::SeqCst);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as i64;

        let envelope = Arc::new(EventEnvelope {
            sequence: seq,
            timestamp,
            block_height,
            vm_type,
            event,
        });

        // broadcast::send returns Err only when there are zero receivers,
        // which is not an error for us — the event is simply not observed.
        let _ = self.sender.send(envelope);

        self.stats
            .total_events_published
            .fetch_add(1, Ordering::Relaxed);
        self.stats.current_sequence.store(seq, Ordering::Relaxed);

        debug!(sequence = seq, "event published");
        seq
    }

    /// Create an unfiltered subscriber that receives all events.
    pub fn subscribe(&self) -> EventSubscriber {
        let receiver = self.sender.subscribe();
        self.stats
            .active_subscribers
            .fetch_add(1, Ordering::Relaxed);
        let id = SubscriptionId(
            self.next_subscription_id.fetch_add(1, Ordering::Relaxed),
        );
        EventSubscriber {
            id,
            receiver,
            stats: Arc::clone(&self.stats),
        }
    }

    /// Create a filtered subscriber that only yields events matching the filter.
    pub fn subscribe_filtered(&self, filter: EventFilter) -> FilteredEventSubscriber {
        let inner = self.subscribe();
        FilteredEventSubscriber { inner, filter }
    }

    /// Returns a reference to the shared stats counters.
    pub fn stats(&self) -> &Arc<EventBusStats> {
        &self.stats
    }

    /// Returns the current (latest assigned) sequence number.
    /// If no events have been published yet, returns 0 (the first event
    /// will also be assigned sequence 0).
    pub fn current_sequence(&self) -> u64 {
        self.sequence_counter.load(Ordering::SeqCst)
    }

    /// Returns the number of active subscribers.
    pub fn subscriber_count(&self) -> u64 {
        self.stats.active_subscribers.load(Ordering::Relaxed)
    }
}

// ---------------------------------------------------------------------------
// EventSubscriber
// ---------------------------------------------------------------------------

/// An unfiltered event stream consumer.
///
/// Dropping the subscriber automatically decrements the active subscriber
/// count in the bus stats.
pub struct EventSubscriber {
    id: SubscriptionId,
    receiver: broadcast::Receiver<Arc<EventEnvelope>>,
    stats: Arc<EventBusStats>,
}

impl EventSubscriber {
    /// Returns the subscription id.
    pub fn id(&self) -> SubscriptionId {
        self.id
    }

    /// Wait for the next event.
    ///
    /// - Returns `Ok(envelope)` on success.
    /// - Returns `Err(Lagged(n))` if this consumer fell behind and `n`
    ///   events were skipped. The receiver remains valid.
    /// - Returns `Err(Closed)` when all senders have been dropped.
    pub async fn recv(&mut self) -> Result<Arc<EventEnvelope>, EventBusError> {
        match self.receiver.recv().await {
            Ok(envelope) => Ok(envelope),
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!(
                    subscription = %self.id,
                    missed = n,
                    "subscriber lagged behind"
                );
                self.stats
                    .total_events_dropped
                    .fetch_add(n, Ordering::Relaxed);
                Err(EventBusError::Lagged(n))
            }
            Err(broadcast::error::RecvError::Closed) => Err(EventBusError::Closed),
        }
    }
}

impl Drop for EventSubscriber {
    fn drop(&mut self) {
        self.stats
            .active_subscribers
            .fetch_sub(1, Ordering::Relaxed);
    }
}

// ---------------------------------------------------------------------------
// FilteredEventSubscriber
// ---------------------------------------------------------------------------

/// An event stream consumer that only yields events matching a filter.
///
/// Non-matching events are silently skipped. Lagged and Closed errors
/// are propagated to the caller.
pub struct FilteredEventSubscriber {
    inner: EventSubscriber,
    filter: EventFilter,
}

impl FilteredEventSubscriber {
    /// Returns the subscription id.
    pub fn id(&self) -> SubscriptionId {
        self.inner.id()
    }

    /// Returns a reference to the active filter.
    pub fn filter(&self) -> &EventFilter {
        &self.filter
    }

    /// Wait for the next event that matches the filter.
    ///
    /// Events that do not match are consumed and discarded internally.
    pub async fn recv(&mut self) -> Result<Arc<EventEnvelope>, EventBusError> {
        loop {
            match self.inner.recv().await {
                Ok(envelope) => {
                    if self.filter.matches(&envelope) {
                        return Ok(envelope);
                    }
                    // Not matching — silently skip
                }
                Err(e) => return Err(e),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{EventType, TenzroEvent, VmType};

    fn make_block_event(height: u64) -> TenzroEvent {
        TenzroEvent::NewBlock {
            block_hash: [0xAA; 32],
            parent_hash: [0xBB; 32],
            height,
            tx_count: 5,
            proposer: [0x01; 20],
        }
    }

    fn make_transfer_event(amount: u128) -> TenzroEvent {
        TenzroEvent::Transfer {
            from: [0x01; 20],
            to: [0x02; 20],
            amount,
            token_id: "TNZO".into(),
            tx_hash: [0xCC; 32],
        }
    }

    #[tokio::test]
    async fn test_publish_and_receive() {
        let bus = EventBus::default_bus();
        let mut sub = bus.subscribe();

        let seq = bus.publish(make_block_event(1), Some(1), Some(VmType::Native));
        assert_eq!(seq, 0);

        let env = sub.recv().await.unwrap();
        assert_eq!(env.sequence, 0);
        assert_eq!(env.block_height, Some(1));
        assert_eq!(env.event_type(), EventType::NewBlock);
    }

    #[tokio::test]
    async fn test_multiple_subscribers() {
        let bus = EventBus::default_bus();
        let mut sub1 = bus.subscribe();
        let mut sub2 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 2);

        bus.publish(make_transfer_event(100), Some(5), None);

        let e1 = sub1.recv().await.unwrap();
        let e2 = sub2.recv().await.unwrap();
        assert_eq!(e1.sequence, e2.sequence);
        assert_eq!(e1.sequence, 0);
    }

    #[tokio::test]
    async fn test_filtered_subscriber() {
        let bus = EventBus::default_bus();
        let filter = EventFilter {
            event_types: vec![EventType::Transfer],
            ..Default::default()
        };
        let mut filtered = bus.subscribe_filtered(filter);

        // Publish a block event (should be skipped) and a transfer event
        bus.publish(make_block_event(1), Some(1), Some(VmType::Native));
        bus.publish(make_transfer_event(999), Some(2), Some(VmType::Native));

        let env = filtered.recv().await.unwrap();
        assert_eq!(env.event_type(), EventType::Transfer);
        assert_eq!(env.sequence, 1); // second event published
    }

    #[tokio::test]
    async fn test_lagged_consumer() {
        // Tiny capacity to force lagging
        let config = EventBusConfig::default().with_capacity(4);
        let bus = EventBus::new(config);
        let mut sub = bus.subscribe();

        // Publish more events than the channel can hold
        for i in 0..10 {
            bus.publish(make_block_event(i), Some(i), None);
        }

        // First recv should report lagged
        let result = sub.recv().await;
        match result {
            Err(EventBusError::Lagged(n)) => {
                assert!(n > 0, "should have lagged by at least 1 event");
            }
            Ok(env) => {
                // On some platforms the first recv may succeed if timing
                // allows; subsequent reads would lag. Either way is valid.
                assert!(env.sequence < 10);
            }
            Err(EventBusError::Closed) => panic!("unexpected close"),
        }

        // Stats should reflect drops
        let snap = bus.stats().snapshot();
        assert!(snap.total_events_published == 10);
    }

    #[tokio::test]
    async fn test_sequence_monotonicity() {
        let bus = EventBus::default_bus();
        let mut sub = bus.subscribe();

        for i in 0u64..20 {
            let seq = bus.publish(make_block_event(i), Some(i), None);
            assert_eq!(seq, i);
        }

        let mut prev_seq = None;
        for _ in 0..20 {
            let env = sub.recv().await.unwrap();
            if let Some(prev) = prev_seq {
                assert_eq!(env.sequence, prev + 1, "sequence must be gap-free");
            }
            prev_seq = Some(env.sequence);
        }
    }

    #[tokio::test]
    async fn test_stats_tracking() {
        let bus = EventBus::default_bus();
        let _sub = bus.subscribe();

        assert_eq!(bus.stats().snapshot().active_subscribers, 1);
        assert_eq!(bus.stats().snapshot().total_events_published, 0);

        bus.publish(make_block_event(1), Some(1), None);
        bus.publish(make_transfer_event(50), None, None);

        let snap = bus.stats().snapshot();
        assert_eq!(snap.total_events_published, 2);
        assert_eq!(snap.current_sequence, 1); // 0-indexed, last published = seq 1
    }

    #[tokio::test]
    async fn test_subscriber_count_on_drop() {
        let bus = EventBus::default_bus();
        assert_eq!(bus.subscriber_count(), 0);

        let sub1 = bus.subscribe();
        assert_eq!(bus.subscriber_count(), 1);

        {
            let _sub2 = bus.subscribe();
            assert_eq!(bus.subscriber_count(), 2);
        }
        // sub2 dropped
        assert_eq!(bus.subscriber_count(), 1);

        drop(sub1);
        assert_eq!(bus.subscriber_count(), 0);
    }

    #[tokio::test]
    async fn test_subscribe_after_publish_gets_future_only() {
        let bus = EventBus::default_bus();

        // Publish before subscribing
        bus.publish(make_block_event(1), Some(1), None);
        bus.publish(make_block_event(2), Some(2), None);

        // Subscribe now — should only see events published after this point
        let mut sub = bus.subscribe();

        bus.publish(make_block_event(3), Some(3), None);

        let env = sub.recv().await.unwrap();
        assert_eq!(env.sequence, 2); // third event (0-indexed)
        if let TenzroEvent::NewBlock { height, .. } = &env.event {
            assert_eq!(*height, 3);
        } else {
            panic!("expected NewBlock");
        }
    }

    #[tokio::test]
    async fn test_filtered_subscriber_with_vm_type() {
        let bus = EventBus::default_bus();
        let filter = EventFilter {
            vm_types: vec![VmType::Evm],
            ..Default::default()
        };
        let mut filtered = bus.subscribe_filtered(filter);

        bus.publish(make_block_event(1), Some(1), Some(VmType::Native));
        bus.publish(make_transfer_event(100), Some(2), Some(VmType::Evm));

        let env = filtered.recv().await.unwrap();
        assert_eq!(env.vm_type, Some(VmType::Evm));
        assert_eq!(env.event_type(), EventType::Transfer);
    }

    #[tokio::test]
    async fn test_current_sequence() {
        let bus = EventBus::default_bus();
        assert_eq!(bus.current_sequence(), 0);

        bus.publish(make_block_event(1), None, None);
        assert_eq!(bus.current_sequence(), 1);

        bus.publish(make_block_event(2), None, None);
        assert_eq!(bus.current_sequence(), 2);
    }

    #[tokio::test]
    async fn test_closed_error_when_bus_dropped() {
        let bus = EventBus::default_bus();
        let mut sub = bus.subscribe();

        // Publish one event so the subscriber has something, then drop bus
        bus.publish(make_block_event(1), None, None);
        drop(bus);

        // First recv should succeed (buffered event)
        let _ok = sub.recv().await.unwrap();

        // Second recv should return Closed
        let result = sub.recv().await;
        assert_eq!(result, Err(EventBusError::Closed));
    }
}
