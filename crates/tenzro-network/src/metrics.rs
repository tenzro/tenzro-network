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
    /// Gossip messages successfully published.
    pub gossip_published: Counter,
    /// Gossip messages received and accepted.
    pub gossip_accepted: Counter,
}

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

        Arc::new(Self {
            gossip_rejected_invalid,
            gossip_rejected_duplicate,
            gossip_shed_over_budget,
            gossip_shed_unidentified,
            gossip_published,
            gossip_accepted,
        })
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
