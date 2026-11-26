//! Prometheus metrics for Tenzro Network gossip.
//!
//! All counters are `u64` and monotonically increasing. Metrics are
//! registered into a shared `Registry` that the node exposes via its
//! `/metrics` HTTP endpoint.
//!
//! # Metric Naming Convention
//!
//! All metrics are prefixed with `tenzro_network_` and use `snake_case`.
//! Labels follow the Prometheus best-practice: low-cardinality, no free-form
//! strings.

use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::histogram::{Histogram, exponential_buckets};
use prometheus_client::registry::Registry;
use std::sync::Arc;

/// Gossip metrics bundle.
///
/// Wrapped in `Arc` so the gossip tasks can emit metrics while the RPC
/// `/metrics` handler reads the registry concurrently without contention.
#[derive(Clone)]
pub struct NetworkMetrics {
    /// Gossip messages rejected by structural validation.
    pub gossip_rejected_invalid: Counter,
    /// Gossip messages dropped as already seen.
    pub gossip_rejected_duplicate: Counter,
    /// Gossip messages shed because their neighbour had spent its budget
    /// for the topic's traffic class.
    pub gossip_shed_over_budget: Counter,
    /// Consensus-class gossip shed because no verified endpoint record
    /// names the neighbour that delivered it.
    pub gossip_shed_unidentified: Counter,
    /// Gossip shed because the neighbour that delivered it has no
    /// registered identity (the identity gate; see
    /// `GossipGuard::set_registered_only`).
    pub gossip_shed_unregistered: Counter,
    /// Gossip messages successfully published.
    pub gossip_published: Counter,
    /// Gossip messages received and accepted.
    pub gossip_accepted: Counter,
    /// Blocks this node published on the blocks topic, and their bytes.
    pub blocks_gossip_published: Counter,
    /// See [`Self::blocks_gossip_published`].
    pub blocks_gossip_published_bytes: Counter,
    /// Block messages delivered to this node for the first time, and their
    /// bytes.
    pub blocks_gossip_delivered: Counter,
    /// See [`Self::blocks_gossip_delivered`].
    pub blocks_gossip_delivered_bytes: Counter,
    /// Block messages delivered to this node that it had already seen,
    /// byte for byte, and their bytes.
    pub blocks_gossip_duplicate: Counter,
    /// See [`Self::blocks_gossip_duplicate`].
    pub blocks_gossip_duplicate_bytes: Counter,
    /// Milliseconds from a block's own timestamp to its first delivery to
    /// this node by gossip, by this node's clock.
    pub blocks_gossip_held_delay_ms: Histogram,
}

/// Topic blocks are gossiped on.
pub const BLOCKS_TOPIC: &str = "tenzro/blocks";

impl NetworkMetrics {
    /// Registers all metrics into the given `Registry` under the
    /// `tenzro_network` subsystem and returns the metrics bundle wrapped
    /// in `Arc` for shared access.
    pub fn register(registry: &mut Registry) -> Arc<Self> {
        let sub = registry.sub_registry_with_prefix("tenzro_network");

        let gossip_rejected_invalid = Counter::default();
        sub.register(
            "gossip_rejected_invalid",
            "Gossip messages rejected by structural validation",
            gossip_rejected_invalid.clone(),
        );

        let gossip_rejected_duplicate = Counter::default();
        sub.register(
            "gossip_rejected_duplicate",
            "Gossip messages dropped as already seen",
            gossip_rejected_duplicate.clone(),
        );

        let gossip_shed_over_budget = Counter::default();
        sub.register(
            "gossip_shed_over_budget",
            "Gossip messages shed because their neighbour was over its budget",
            gossip_shed_over_budget.clone(),
        );

        let gossip_shed_unidentified = Counter::default();
        sub.register(
            "gossip_shed_unidentified",
            "Consensus gossip shed because no endpoint record names its neighbour",
            gossip_shed_unidentified.clone(),
        );

        let gossip_shed_unregistered = Counter::default();
        sub.register(
            "gossip_shed_unregistered",
            "Gossip shed because its neighbour has no registered identity",
            gossip_shed_unregistered.clone(),
        );

        let gossip_published = Counter::default();
        sub.register(
            "gossip_published",
            "Gossip messages successfully published",
            gossip_published.clone(),
        );

        let gossip_accepted = Counter::default();
        sub.register(
            "gossip_accepted",
            "Gossip messages received and accepted",
            gossip_accepted.clone(),
        );

        let mut counter = |name: &str, help: &str| {
            let c = Counter::default();
            sub.register(name, help, c.clone());
            c
        };
        let blocks_gossip_published = counter(
            "blocks_gossip_published",
            "Blocks this node published on the blocks topic",
        );
        let blocks_gossip_published_bytes = counter(
            "blocks_gossip_published_bytes",
            "Bytes of the blocks this node published on the blocks topic",
        );
        let blocks_gossip_delivered = counter(
            "blocks_gossip_delivered",
            "Block messages delivered to this node for the first time",
        );
        let blocks_gossip_delivered_bytes = counter(
            "blocks_gossip_delivered_bytes",
            "Bytes of the block messages delivered to this node for the first time",
        );
        let blocks_gossip_duplicate = counter(
            "blocks_gossip_duplicate",
            "Block messages delivered to this node that it had already seen",
        );
        let blocks_gossip_duplicate_bytes = counter(
            "blocks_gossip_duplicate_bytes",
            "Bytes of the block messages delivered to this node that it had already seen",
        );
        // 5 ms to about 80 s.
        let blocks_gossip_held_delay_ms = Histogram::new(exponential_buckets(5.0, 2.0, 15));
        sub.register(
            "blocks_gossip_held_delay_ms",
            "Milliseconds from a block's timestamp to its first delivery by gossip",
            blocks_gossip_held_delay_ms.clone(),
        );

        Arc::new(Self {
            gossip_rejected_invalid,
            gossip_rejected_duplicate,
            gossip_shed_over_budget,
            gossip_shed_unidentified,
            gossip_shed_unregistered,
            gossip_published,
            gossip_accepted,
            blocks_gossip_published,
            blocks_gossip_published_bytes,
            blocks_gossip_delivered,
            blocks_gossip_delivered_bytes,
            blocks_gossip_duplicate,
            blocks_gossip_duplicate_bytes,
            blocks_gossip_held_delay_ms,
        })
    }

    /// Counts a block of `bytes` this node published.
    pub fn block_published(&self, bytes: usize) {
        self.blocks_gossip_published.inc();
        self.blocks_gossip_published_bytes.inc_by(bytes as u64);
    }

    /// Counts the first delivery, at `now_ms`, of a block message of
    /// `bytes` whose block is dated `block_ms`. The block's time is whatever
    /// the sender put there, so the delay saturates rather than overflows,
    /// and a block dated after `now_ms` counts as no delay.
    pub fn block_delivered(&self, bytes: usize, now_ms: i64, block_ms: i64) {
        self.blocks_gossip_delivered.inc();
        self.blocks_gossip_delivered_bytes.inc_by(bytes as u64);
        let delay_ms = now_ms.saturating_sub(block_ms).max(0);
        self.blocks_gossip_held_delay_ms.observe(delay_ms as f64);
    }

    /// Counts a delivery of `bytes` on `topic` that this node had already
    /// seen.
    pub fn duplicate(&self, topic: &str, bytes: usize) {
        self.gossip_rejected_duplicate.inc();
        if topic == BLOCKS_TOPIC {
            self.blocks_gossip_duplicate.inc();
            self.blocks_gossip_duplicate_bytes.inc_by(bytes as u64);
        }
    }

    /// Creates an unregistered metrics bundle — useful for tests and
    /// embedded environments where a Prometheus `/metrics` endpoint is
    /// not exposed. All counters are still functional.
    pub fn unregistered() -> Arc<Self> {
        let mut registry = Registry::default();
        Self::register(&mut registry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_all_metrics() {
        let mut registry = Registry::default();
        let metrics = NetworkMetrics::register(&mut registry);

        assert_eq!(metrics.gossip_published.get(), 0);
        metrics.gossip_published.inc();
        assert_eq!(metrics.gossip_published.get(), 1);
    }

    /// A block published, delivered once and delivered again is counted
    /// with its bytes under each heading; a repeat on another topic counts
    /// as a duplicate but not as a block, and the counters are exported
    /// under the names a scrape reads.
    #[test]
    fn block_gossip_is_counted_with_its_bytes() {
        let mut registry = Registry::default();
        let m = NetworkMetrics::register(&mut registry);
        m.block_published(1_000);
        m.block_delivered(1_000, 1_040, 1_000);
        m.block_delivered(700, 1_000, 1_005);
        m.duplicate(BLOCKS_TOPIC, 1_000);
        m.duplicate("tenzro/transactions", 300);
        assert_eq!(m.blocks_gossip_published.get(), 1);
        assert_eq!(m.blocks_gossip_published_bytes.get(), 1_000);
        assert_eq!(m.blocks_gossip_delivered.get(), 2);
        assert_eq!(m.blocks_gossip_delivered_bytes.get(), 1_700);
        assert_eq!(m.blocks_gossip_duplicate.get(), 1);
        assert_eq!(m.blocks_gossip_duplicate_bytes.get(), 1_000);
        assert_eq!(m.gossip_rejected_duplicate.get(), 2);

        let mut text = String::new();
        prometheus_client::encoding::text::encode(&mut text, &registry).unwrap();
        for name in [
            "tenzro_network_blocks_gossip_published_total 1",
            "tenzro_network_blocks_gossip_published_bytes_total 1000",
            "tenzro_network_blocks_gossip_delivered_total 2",
            "tenzro_network_blocks_gossip_delivered_bytes_total 1700",
            "tenzro_network_blocks_gossip_duplicate_total 1",
            "tenzro_network_blocks_gossip_duplicate_bytes_total 1000",
            "tenzro_network_blocks_gossip_held_delay_ms_count 2",
        ] {
            assert!(text.contains(name), "{name} is not exported:\n{text}");
        }
    }

    /// A block dated as far in the past or the future as its type allows is
    /// counted without overflowing, its delay at the histogram's ends.
    #[test]
    fn a_block_dated_at_either_extreme_is_counted_without_overflow() {
        let m = NetworkMetrics::unregistered();
        let now = 1_800_000_000_000;
        m.block_delivered(10, now, i64::MIN);
        m.block_delivered(10, now, i64::MAX);
        m.block_delivered(10, i64::MIN, i64::MAX);
        m.block_delivered(10, i64::MAX, i64::MIN);
        assert_eq!(m.blocks_gossip_delivered.get(), 4);
    }

    #[test]
    fn test_metrics_clone_shares_state() {
        // NetworkMetrics::Clone means the Counter handles are shared —
        // mutations through one clone are visible via another.
        let metrics = NetworkMetrics::unregistered();
        let metrics_clone = metrics.clone();

        metrics.gossip_accepted.inc();
        metrics.gossip_accepted.inc();

        assert_eq!(metrics_clone.gossip_accepted.get(), 2);
    }
}
