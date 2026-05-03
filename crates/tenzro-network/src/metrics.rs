//! Prometheus metrics for Tenzro Network — A+++ production observability.
//!
//! All counters are `u64` and monotonically increasing. Gauges are `i64`.
//! Metrics are registered into a shared `Registry` that the node exposes
//! via its `/metrics` HTTP endpoint.
//!
//! # Metric Naming Convention
//!
//! All metrics are prefixed with `tenzro_network_` and use `snake_case`.
//! Labels follow the Prometheus best-practice: low-cardinality, no free-form
//! strings. Topic labels are restricted to the known `VALIDATOR_ONLY_TOPICS`
//! set to prevent label explosion.

use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use std::sync::Arc;

/// Network-layer metrics bundle.
///
/// Wrapped in `Arc` so the service task can emit metrics while the RPC
/// `/metrics` handler reads the registry concurrently without contention.
#[derive(Clone)]
pub struct NetworkMetrics {
    /// Total swarm events dropped due to back-pressure (event channel full).
    pub events_dropped: Counter,
    /// Dials rejected because the remote IP exceeded per-IP rate limit.
    pub dials_rejected_per_ip: Counter,
    /// Dials rejected because global dial rate limit was exceeded.
    pub dials_rejected_global: Counter,
    /// Gossip messages rejected because the publisher is not an authorized validator.
    pub gossip_rejected_validator_only: Counter,
    /// Gossip messages rejected by structural validation (malformed, oversized).
    pub gossip_rejected_invalid: Counter,
    /// Gossip messages rejected as application-level duplicates.
    pub gossip_rejected_duplicate: Counter,
    /// Gossip messages published successfully.
    pub gossip_published: Counter,
    /// Gossip messages received and accepted.
    pub gossip_accepted: Counter,
    /// Current number of established connections (inbound + outbound).
    pub connections_established: Gauge,
    /// Total inbound connections ever accepted (monotonic).
    pub connections_inbound_total: Counter,
    /// Total outbound connections ever established (monotonic).
    pub connections_outbound_total: Counter,
    /// Peers currently banned.
    pub peers_banned: Gauge,
    /// Peers currently connected.
    pub peers_connected: Gauge,
    /// Kademlia routing table entries.
    pub kad_routing_table_size: Gauge,
    /// Gossipsub mesh size for validator-only topics (aggregated).
    pub gossipsub_mesh_size: Gauge,
}

impl NetworkMetrics {
    /// Registers all metrics into the given `Registry` under the
    /// `tenzro_network` subsystem and returns the metrics bundle wrapped
    /// in `Arc` for shared access from the service event loop.
    pub fn register(registry: &mut Registry) -> Arc<Self> {
        let sub = registry.sub_registry_with_prefix("tenzro_network");

        let events_dropped = Counter::default();
        sub.register(
            "events_dropped",
            "Swarm events dropped due to event channel back-pressure",
            events_dropped.clone(),
        );

        let dials_rejected_per_ip = Counter::default();
        sub.register(
            "dials_rejected_per_ip",
            "Inbound dials rejected due to per-IP rate limit",
            dials_rejected_per_ip.clone(),
        );

        let dials_rejected_global = Counter::default();
        sub.register(
            "dials_rejected_global",
            "Inbound dials rejected due to global dial rate limit",
            dials_rejected_global.clone(),
        );

        let gossip_rejected_validator_only = Counter::default();
        sub.register(
            "gossip_rejected_validator_only",
            "Gossip messages rejected because publisher is not a known validator",
            gossip_rejected_validator_only.clone(),
        );

        let gossip_rejected_invalid = Counter::default();
        sub.register(
            "gossip_rejected_invalid",
            "Gossip messages rejected by structural validation",
            gossip_rejected_invalid.clone(),
        );

        let gossip_rejected_duplicate = Counter::default();
        sub.register(
            "gossip_rejected_duplicate",
            "Gossip messages rejected as application-level duplicates",
            gossip_rejected_duplicate.clone(),
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

        let connections_established = Gauge::default();
        sub.register(
            "connections_established",
            "Current established libp2p connections",
            connections_established.clone(),
        );

        let connections_inbound_total = Counter::default();
        sub.register(
            "connections_inbound_total",
            "Total inbound libp2p connections accepted",
            connections_inbound_total.clone(),
        );

        let connections_outbound_total = Counter::default();
        sub.register(
            "connections_outbound_total",
            "Total outbound libp2p connections established",
            connections_outbound_total.clone(),
        );

        let peers_banned = Gauge::default();
        sub.register(
            "peers_banned",
            "Peers currently in the banned state",
            peers_banned.clone(),
        );

        let peers_connected = Gauge::default();
        sub.register(
            "peers_connected",
            "Peers currently connected",
            peers_connected.clone(),
        );

        let kad_routing_table_size = Gauge::default();
        sub.register(
            "kad_routing_table_size",
            "Entries in the Kademlia k-bucket routing table",
            kad_routing_table_size.clone(),
        );

        let gossipsub_mesh_size = Gauge::default();
        sub.register(
            "gossipsub_mesh_size",
            "Aggregate gossipsub mesh peer count across all subscribed topics",
            gossipsub_mesh_size.clone(),
        );

        Arc::new(Self {
            events_dropped,
            dials_rejected_per_ip,
            dials_rejected_global,
            gossip_rejected_validator_only,
            gossip_rejected_invalid,
            gossip_rejected_duplicate,
            gossip_published,
            gossip_accepted,
            connections_established,
            connections_inbound_total,
            connections_outbound_total,
            peers_banned,
            peers_connected,
            kad_routing_table_size,
            gossipsub_mesh_size,
        })
    }

    /// Creates an unregistered metrics bundle — useful for tests and
    /// embedded environments where a Prometheus `/metrics` endpoint is
    /// not exposed. All counters/gauges are still functional.
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

        // All counters should start at 0
        assert_eq!(metrics.events_dropped.get(), 0);
        assert_eq!(metrics.dials_rejected_per_ip.get(), 0);
        assert_eq!(metrics.gossip_published.get(), 0);

        // Incrementing should work
        metrics.events_dropped.inc();
        assert_eq!(metrics.events_dropped.get(), 1);
    }

    #[test]
    fn test_unregistered_metrics() {
        let metrics = NetworkMetrics::unregistered();
        metrics.gossip_published.inc();
        metrics.peers_connected.set(42);

        assert_eq!(metrics.gossip_published.get(), 1);
        assert_eq!(metrics.peers_connected.get(), 42);
    }

    #[test]
    fn test_metrics_clone_shares_state() {
        // NetworkMetrics::Clone means the Counter/Gauge handles are shared —
        // mutations through one clone are visible via another.
        let metrics = NetworkMetrics::unregistered();
        let metrics_clone = metrics.clone();

        metrics.events_dropped.inc();
        metrics.events_dropped.inc();

        assert_eq!(metrics_clone.events_dropped.get(), 2);
    }
}
