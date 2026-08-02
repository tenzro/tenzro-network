//! Metrics collection for node monitoring

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

/// Metrics collector for node operations
#[derive(Clone)]
pub struct MetricsCollector {
    inner: Arc<MetricsInner>,
}

struct MetricsInner {
    blocks_processed: AtomicU64,
    transactions_processed: AtomicU64,
    inference_requests: AtomicU64,
    settlements: AtomicU64,
    peer_count: AtomicU64,
    start_time: Instant,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            inner: Arc::new(MetricsInner {
                blocks_processed: AtomicU64::new(0),
                transactions_processed: AtomicU64::new(0),
                inference_requests: AtomicU64::new(0),
                settlements: AtomicU64::new(0),
                peer_count: AtomicU64::new(0),
                start_time: Instant::now(),
            }),
        }
    }

    /// Record a processed block
    pub fn record_block(&self) {
        self.inner.blocks_processed.fetch_add(1, Ordering::Relaxed);
    }

    /// Record processed transactions
    pub fn record_transaction(&self, count: u64) {
        self.inner
            .transactions_processed
            .fetch_add(count, Ordering::Relaxed);
    }

    /// Record an inference request
    pub fn record_inference(&self) {
        self.inner
            .inference_requests
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a settlement
    pub fn record_settlement(&self) {
        self.inner.settlements.fetch_add(1, Ordering::Relaxed);
    }

    /// Update peer count
    pub fn set_peer_count(&self, count: u64) {
        self.inner.peer_count.store(count, Ordering::Relaxed);
    }

    /// Get current metrics snapshot
    pub fn get_metrics(&self) -> NodeMetrics {
        let uptime_secs = self.inner.start_time.elapsed().as_secs();

        NodeMetrics {
            blocks_processed: self.inner.blocks_processed.load(Ordering::Relaxed),
            transactions_processed: self.inner.transactions_processed.load(Ordering::Relaxed),
            inference_requests: self.inner.inference_requests.load(Ordering::Relaxed),
            settlements: self.inner.settlements.load(Ordering::Relaxed),
            peer_count: self.inner.peer_count.load(Ordering::Relaxed),
            uptime_secs,
        }
    }

    /// Reset all metrics (useful for testing)
    #[cfg(test)]
    pub fn reset(&self) {
        self.inner.blocks_processed.store(0, Ordering::Relaxed);
        self.inner
            .transactions_processed
            .store(0, Ordering::Relaxed);
        self.inner.inference_requests.store(0, Ordering::Relaxed);
        self.inner.settlements.store(0, Ordering::Relaxed);
        self.inner.peer_count.store(0, Ordering::Relaxed);
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of node metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMetrics {
    /// Total blocks processed
    pub blocks_processed: u64,

    /// Total transactions processed
    pub transactions_processed: u64,

    /// Total inference requests handled
    pub inference_requests: u64,

    /// Total settlements processed
    pub settlements: u64,

    /// Current peer count
    pub peer_count: u64,

    /// Node uptime in seconds
    pub uptime_secs: u64,
}

impl NodeMetrics {
    /// Calculate blocks per second (average over uptime)
    pub fn blocks_per_second(&self) -> f64 {
        if self.uptime_secs == 0 {
            0.0
        } else {
            self.blocks_processed as f64 / self.uptime_secs as f64
        }
    }

    /// Calculate transactions per second (average over uptime)
    pub fn transactions_per_second(&self) -> f64 {
        if self.uptime_secs == 0 {
            0.0
        } else {
            self.transactions_processed as f64 / self.uptime_secs as f64
        }
    }

    /// Format uptime as human-readable string
    pub fn uptime_human(&self) -> String {
        let days = self.uptime_secs / 86400;
        let hours = (self.uptime_secs % 86400) / 3600;
        let minutes = (self.uptime_secs % 3600) / 60;
        let seconds = self.uptime_secs % 60;

        if days > 0 {
            format!("{}d {}h {}m {}s", days, hours, minutes, seconds)
        } else if hours > 0 {
            format!("{}h {}m {}s", hours, minutes, seconds)
        } else if minutes > 0 {
            format!("{}m {}s", minutes, seconds)
        } else {
            format!("{}s", seconds)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collection() {
        let metrics = MetricsCollector::new();

        metrics.record_block();
        metrics.record_block();
        metrics.record_transaction(5);
        metrics.record_inference();
        metrics.record_settlement();
        metrics.set_peer_count(10);

        let snapshot = metrics.get_metrics();
        assert_eq!(snapshot.blocks_processed, 2);
        assert_eq!(snapshot.transactions_processed, 5);
        assert_eq!(snapshot.inference_requests, 1);
        assert_eq!(snapshot.settlements, 1);
        assert_eq!(snapshot.peer_count, 10);
    }

    #[test]
    fn test_metrics_reset() {
        let metrics = MetricsCollector::new();

        metrics.record_block();
        metrics.record_transaction(5);

        metrics.reset();

        let snapshot = metrics.get_metrics();
        assert_eq!(snapshot.blocks_processed, 0);
        assert_eq!(snapshot.transactions_processed, 0);
    }

    #[test]
    fn test_uptime_formatting() {
        let metrics = NodeMetrics {
            blocks_processed: 0,
            transactions_processed: 0,
            inference_requests: 0,
            settlements: 0,
            peer_count: 0,
            uptime_secs: 90061, // 1 day, 1 hour, 1 minute, 1 second
        };

        let uptime = metrics.uptime_human();
        assert_eq!(uptime, "1d 1h 1m 1s");
    }

    #[test]
    fn test_rates_calculation() {
        let metrics = NodeMetrics {
            blocks_processed: 100,
            transactions_processed: 1000,
            inference_requests: 0,
            settlements: 0,
            peer_count: 0,
            uptime_secs: 10,
        };

        assert_eq!(metrics.blocks_per_second(), 10.0);
        assert_eq!(metrics.transactions_per_second(), 100.0);
    }
}
