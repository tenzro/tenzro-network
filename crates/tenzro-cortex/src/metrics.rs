//! Prometheus-compatible metrics for Cortex workers.
//!
//! Tracks the economically-meaningful signals a Cortex worker emits while
//! serving [`CortexRequest`](tenzro_types::cortex::CortexRequest)s:
//!
//! - **Loops executed** — the cumulative recurrent-depth compute a worker
//!   has performed. This is the fundamental unit Cortex meters.
//! - **Cost in TNZO** — cumulative settlement value (in smallest TNZO
//!   units) billed to callers. Useful for operators sizing stake and
//!   provider revenue dashboards.
//! - **Latency** — per-request end-to-end wall-clock duration, recorded
//!   as a histogram fallback: `sum + count + per-bucket counters` in ms.
//! - **Rejections** — budget violations, attestation misconfiguration,
//!   and cost-exceeded errors broken down by reason.
//! - **Attestations** — TEE quotes and ZK proofs produced, for operators
//!   monitoring the hardware-backed / cryptographically-verifiable share
//!   of traffic.
//!
//! The collector is a lightweight atomic-counter set (no `prometheus`
//! crate dependency, matching the `tenzro-node` style) that can be
//! rendered to Prometheus text exposition format via
//! [`CortexMetrics::encode_prometheus`] or snapshotted to a serializable
//! struct via [`CortexMetrics::snapshot`] for JSON endpoints.
//!
//! A [`CortexMetrics`] handle is `Clone` (cheap `Arc` bump) and
//! thread-safe; workers hold one, dashboards can hold another.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tenzro_types::cortex::{AttestationRequirement, ReasoningTier};

/// Fixed set of histogram buckets in milliseconds for
/// `cortex_request_latency_ms_bucket`. Chosen to span the expected
/// sidecar-model range (a few ms for Fast tier, several seconds for
/// Deep/Institutional with attestation).
pub const LATENCY_BUCKETS_MS: &[f64] = &[
    5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1_000.0, 2_500.0, 5_000.0, 10_000.0, 30_000.0,
];

/// Reason why a request was rejected before finalizing the receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectionReason {
    /// Caller's budget was internally inconsistent (min > max, tier unsupported, etc.).
    InvalidBudget,
    /// Backend reported a cost that exceeded the caller's `max_cost_tnzo`.
    CostExceeded,
    /// Request required attestation but the worker has no provider configured
    /// for the requested mode.
    AttestationMissing,
    /// Backend returned any other error (sidecar unreachable, serialization failure, ...).
    BackendError,
}

impl RejectionReason {
    /// Lowercase label used as a Prometheus label value.
    pub fn label(&self) -> &'static str {
        match self {
            Self::InvalidBudget => "invalid_budget",
            Self::CostExceeded => "cost_exceeded",
            Self::AttestationMissing => "attestation_missing",
            Self::BackendError => "backend_error",
        }
    }
}

/// Bucketed latency histogram, one slot per entry in
/// [`LATENCY_BUCKETS_MS`] plus a `+Inf` overflow bucket.
#[derive(Debug)]
struct LatencyHistogram {
    buckets: Vec<AtomicU64>,
    sum_ms: AtomicU64,
    count: AtomicU64,
}

impl LatencyHistogram {
    fn new() -> Self {
        let mut buckets = Vec::with_capacity(LATENCY_BUCKETS_MS.len() + 1);
        for _ in 0..=LATENCY_BUCKETS_MS.len() {
            buckets.push(AtomicU64::new(0));
        }
        Self {
            buckets,
            sum_ms: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    fn observe(&self, ms: f64) {
        let rounded = ms.round().max(0.0);
        // Clamp to u64 range without panicking on absurd values.
        let add = if rounded.is_finite() {
            rounded as u64
        } else {
            0
        };
        self.sum_ms.fetch_add(add, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);

        for (idx, upper) in LATENCY_BUCKETS_MS.iter().enumerate() {
            if ms <= *upper {
                self.buckets[idx].fetch_add(1, Ordering::Relaxed);
            }
        }
        // +Inf bucket always increments
        self.buckets[LATENCY_BUCKETS_MS.len()].fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> LatencyHistogramSnapshot {
        LatencyHistogramSnapshot {
            buckets: self
                .buckets
                .iter()
                .map(|b| b.load(Ordering::Relaxed))
                .collect(),
            sum_ms: self.sum_ms.load(Ordering::Relaxed),
            count: self.count.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of latency histogram state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyHistogramSnapshot {
    /// Cumulative bucket counts; one entry per `LATENCY_BUCKETS_MS`
    /// upper bound plus a final `+Inf` bucket.
    pub buckets: Vec<u64>,
    /// Total observed latency in milliseconds.
    pub sum_ms: u64,
    /// Total number of observations.
    pub count: u64,
}

/// Per-tier accumulators.
#[derive(Debug)]
struct TierBucket {
    requests: AtomicU64,
    loops_total: AtomicU64,
    cost_tnzo_total: AtomicU64,
}

impl TierBucket {
    fn new() -> Self {
        Self {
            requests: AtomicU64::new(0),
            loops_total: AtomicU64::new(0),
            cost_tnzo_total: AtomicU64::new(0),
        }
    }
}

/// Cheap-to-clone handle over a shared Cortex metrics registry.
///
/// Hold one on the worker, hand additional clones to dashboard / HTTP
/// exporters. All operations are atomic and lock-free.
#[derive(Clone)]
pub struct CortexMetrics {
    inner: Arc<CortexMetricsInner>,
}

struct CortexMetricsInner {
    // Global counters
    requests_total: AtomicU64,
    requests_success_total: AtomicU64,
    loops_executed_total: AtomicU64,
    cost_tnzo_total: AtomicU64,
    tokens_in_total: AtomicU64,
    tokens_out_total: AtomicU64,
    tee_attestations_total: AtomicU64,
    zk_proofs_total: AtomicU64,
    // Per-tier accumulators
    tier_fast: TierBucket,
    tier_standard: TierBucket,
    tier_deep: TierBucket,
    tier_institutional: TierBucket,
    // Per-rejection-reason counters
    rejected_invalid_budget: AtomicU64,
    rejected_cost_exceeded: AtomicU64,
    rejected_attestation_missing: AtomicU64,
    rejected_backend_error: AtomicU64,
    // Latency histogram
    latency: LatencyHistogram,
}

impl CortexMetrics {
    /// Fresh zeroed metrics registry.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(CortexMetricsInner {
                requests_total: AtomicU64::new(0),
                requests_success_total: AtomicU64::new(0),
                loops_executed_total: AtomicU64::new(0),
                cost_tnzo_total: AtomicU64::new(0),
                tokens_in_total: AtomicU64::new(0),
                tokens_out_total: AtomicU64::new(0),
                tee_attestations_total: AtomicU64::new(0),
                zk_proofs_total: AtomicU64::new(0),
                tier_fast: TierBucket::new(),
                tier_standard: TierBucket::new(),
                tier_deep: TierBucket::new(),
                tier_institutional: TierBucket::new(),
                rejected_invalid_budget: AtomicU64::new(0),
                rejected_cost_exceeded: AtomicU64::new(0),
                rejected_attestation_missing: AtomicU64::new(0),
                rejected_backend_error: AtomicU64::new(0),
                latency: LatencyHistogram::new(),
            }),
        }
    }

    fn bucket_for(&self, tier: ReasoningTier) -> &TierBucket {
        match tier {
            ReasoningTier::Fast => &self.inner.tier_fast,
            ReasoningTier::Standard => &self.inner.tier_standard,
            ReasoningTier::Deep => &self.inner.tier_deep,
            ReasoningTier::Institutional => &self.inner.tier_institutional,
        }
    }

    /// Record that a request was accepted for execution (counted
    /// whether it later succeeds or is rejected).
    pub fn record_request_accepted(&self, tier: ReasoningTier) {
        self.inner.requests_total.fetch_add(1, Ordering::Relaxed);
        self.bucket_for(tier)
            .requests
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a fully-successful execution: loops consumed, cost billed,
    /// tokens processed, latency, and attestations produced.
    #[allow(clippy::too_many_arguments)]
    pub fn record_success(
        &self,
        tier: ReasoningTier,
        loops_used: u32,
        cost_tnzo: u64,
        tokens_in: u32,
        tokens_out: u32,
        latency_ms: f64,
        attestation: AttestationRequirement,
    ) {
        self.inner
            .requests_success_total
            .fetch_add(1, Ordering::Relaxed);
        self.inner
            .loops_executed_total
            .fetch_add(loops_used as u64, Ordering::Relaxed);
        self.inner
            .cost_tnzo_total
            .fetch_add(cost_tnzo, Ordering::Relaxed);
        self.inner
            .tokens_in_total
            .fetch_add(tokens_in as u64, Ordering::Relaxed);
        self.inner
            .tokens_out_total
            .fetch_add(tokens_out as u64, Ordering::Relaxed);

        let b = self.bucket_for(tier);
        b.loops_total
            .fetch_add(loops_used as u64, Ordering::Relaxed);
        b.cost_tnzo_total
            .fetch_add(cost_tnzo, Ordering::Relaxed);

        match attestation {
            AttestationRequirement::None => {}
            AttestationRequirement::Tee => {
                self.inner
                    .tee_attestations_total
                    .fetch_add(1, Ordering::Relaxed);
            }
            AttestationRequirement::TeeAndZk => {
                self.inner
                    .tee_attestations_total
                    .fetch_add(1, Ordering::Relaxed);
                self.inner.zk_proofs_total.fetch_add(1, Ordering::Relaxed);
            }
        }

        self.inner.latency.observe(latency_ms);
    }

    /// Record that a request was rejected. Caller should still have
    /// invoked [`record_request_accepted`](Self::record_request_accepted)
    /// first so the denominator in success-rate dashboards stays correct.
    pub fn record_rejection(&self, reason: RejectionReason) {
        let counter = match reason {
            RejectionReason::InvalidBudget => &self.inner.rejected_invalid_budget,
            RejectionReason::CostExceeded => &self.inner.rejected_cost_exceeded,
            RejectionReason::AttestationMissing => &self.inner.rejected_attestation_missing,
            RejectionReason::BackendError => &self.inner.rejected_backend_error,
        };
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Serializable snapshot suitable for JSON dashboards.
    pub fn snapshot(&self) -> CortexMetricsSnapshot {
        let mk = |t: &TierBucket| TierSnapshot {
            requests: t.requests.load(Ordering::Relaxed),
            loops_total: t.loops_total.load(Ordering::Relaxed),
            cost_tnzo_total: t.cost_tnzo_total.load(Ordering::Relaxed),
        };

        CortexMetricsSnapshot {
            requests_total: self.inner.requests_total.load(Ordering::Relaxed),
            requests_success_total: self.inner.requests_success_total.load(Ordering::Relaxed),
            loops_executed_total: self.inner.loops_executed_total.load(Ordering::Relaxed),
            cost_tnzo_total: self.inner.cost_tnzo_total.load(Ordering::Relaxed),
            tokens_in_total: self.inner.tokens_in_total.load(Ordering::Relaxed),
            tokens_out_total: self.inner.tokens_out_total.load(Ordering::Relaxed),
            tee_attestations_total: self.inner.tee_attestations_total.load(Ordering::Relaxed),
            zk_proofs_total: self.inner.zk_proofs_total.load(Ordering::Relaxed),
            tier_fast: mk(&self.inner.tier_fast),
            tier_standard: mk(&self.inner.tier_standard),
            tier_deep: mk(&self.inner.tier_deep),
            tier_institutional: mk(&self.inner.tier_institutional),
            rejected_invalid_budget: self.inner.rejected_invalid_budget.load(Ordering::Relaxed),
            rejected_cost_exceeded: self.inner.rejected_cost_exceeded.load(Ordering::Relaxed),
            rejected_attestation_missing: self
                .inner
                .rejected_attestation_missing
                .load(Ordering::Relaxed),
            rejected_backend_error: self.inner.rejected_backend_error.load(Ordering::Relaxed),
            latency: self.inner.latency.snapshot(),
        }
    }

    /// Render metrics in Prometheus text exposition format
    /// (`text/plain; version=0.0.4`), compatible with the
    /// `tenzro-node` `/metrics` endpoint.
    pub fn encode_prometheus(&self, out: &mut String) {
        let s = self.snapshot();

        // Totals
        push_counter(
            out,
            "cortex_requests_total",
            "Total Cortex requests accepted for execution",
            s.requests_total,
        );
        push_counter(
            out,
            "cortex_requests_success_total",
            "Total Cortex requests that produced a signed receipt",
            s.requests_success_total,
        );
        push_counter(
            out,
            "cortex_loops_executed_total",
            "Total recurrent-depth loops executed across all requests",
            s.loops_executed_total,
        );
        push_counter(
            out,
            "cortex_cost_tnzo_total",
            "Total billed cost in smallest TNZO unit across all requests",
            s.cost_tnzo_total,
        );
        push_counter(
            out,
            "cortex_tokens_in_total",
            "Total input tokens processed by Cortex backends",
            s.tokens_in_total,
        );
        push_counter(
            out,
            "cortex_tokens_out_total",
            "Total output tokens produced by Cortex backends",
            s.tokens_out_total,
        );
        push_counter(
            out,
            "cortex_tee_attestations_total",
            "Total TEE attestations produced for Cortex requests",
            s.tee_attestations_total,
        );
        push_counter(
            out,
            "cortex_zk_proofs_total",
            "Total Plonky3 STARK inference-verification proofs produced for Cortex requests",
            s.zk_proofs_total,
        );

        // Per-tier
        out.push_str("# HELP cortex_requests_by_tier_total Cortex requests per reasoning tier\n");
        out.push_str("# TYPE cortex_requests_by_tier_total counter\n");
        for (tier, v) in tier_pairs(&s) {
            out.push_str(&format!(
                "cortex_requests_by_tier_total{{tier=\"{}\"}} {}\n",
                tier, v.requests
            ));
        }
        out.push('\n');

        out.push_str(
            "# HELP cortex_loops_by_tier_total Recurrent loops executed per reasoning tier\n",
        );
        out.push_str("# TYPE cortex_loops_by_tier_total counter\n");
        for (tier, v) in tier_pairs(&s) {
            out.push_str(&format!(
                "cortex_loops_by_tier_total{{tier=\"{}\"}} {}\n",
                tier, v.loops_total
            ));
        }
        out.push('\n');

        out.push_str(
            "# HELP cortex_cost_tnzo_by_tier_total Billed TNZO (smallest unit) per reasoning tier\n",
        );
        out.push_str("# TYPE cortex_cost_tnzo_by_tier_total counter\n");
        for (tier, v) in tier_pairs(&s) {
            out.push_str(&format!(
                "cortex_cost_tnzo_by_tier_total{{tier=\"{}\"}} {}\n",
                tier, v.cost_tnzo_total
            ));
        }
        out.push('\n');

        // Rejections
        out.push_str(
            "# HELP cortex_requests_rejected_total Cortex requests rejected before finalization\n",
        );
        out.push_str("# TYPE cortex_requests_rejected_total counter\n");
        out.push_str(&format!(
            "cortex_requests_rejected_total{{reason=\"invalid_budget\"}} {}\n",
            s.rejected_invalid_budget
        ));
        out.push_str(&format!(
            "cortex_requests_rejected_total{{reason=\"cost_exceeded\"}} {}\n",
            s.rejected_cost_exceeded
        ));
        out.push_str(&format!(
            "cortex_requests_rejected_total{{reason=\"attestation_missing\"}} {}\n",
            s.rejected_attestation_missing
        ));
        out.push_str(&format!(
            "cortex_requests_rejected_total{{reason=\"backend_error\"}} {}\n",
            s.rejected_backend_error
        ));
        out.push('\n');

        // Histogram
        out.push_str(
            "# HELP cortex_request_latency_ms Cortex request end-to-end latency in milliseconds\n",
        );
        out.push_str("# TYPE cortex_request_latency_ms histogram\n");
        for (idx, upper) in LATENCY_BUCKETS_MS.iter().enumerate() {
            out.push_str(&format!(
                "cortex_request_latency_ms_bucket{{le=\"{}\"}} {}\n",
                upper, s.latency.buckets[idx]
            ));
        }
        out.push_str(&format!(
            "cortex_request_latency_ms_bucket{{le=\"+Inf\"}} {}\n",
            s.latency.buckets[LATENCY_BUCKETS_MS.len()]
        ));
        out.push_str(&format!(
            "cortex_request_latency_ms_sum {}\n",
            s.latency.sum_ms
        ));
        out.push_str(&format!(
            "cortex_request_latency_ms_count {}\n\n",
            s.latency.count
        ));
    }
}

impl Default for CortexMetrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Serializable snapshot of all Cortex metrics at a given instant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CortexMetricsSnapshot {
    pub requests_total: u64,
    pub requests_success_total: u64,
    pub loops_executed_total: u64,
    pub cost_tnzo_total: u64,
    pub tokens_in_total: u64,
    pub tokens_out_total: u64,
    pub tee_attestations_total: u64,
    pub zk_proofs_total: u64,
    pub tier_fast: TierSnapshot,
    pub tier_standard: TierSnapshot,
    pub tier_deep: TierSnapshot,
    pub tier_institutional: TierSnapshot,
    pub rejected_invalid_budget: u64,
    pub rejected_cost_exceeded: u64,
    pub rejected_attestation_missing: u64,
    pub rejected_backend_error: u64,
    pub latency: LatencyHistogramSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TierSnapshot {
    pub requests: u64,
    pub loops_total: u64,
    pub cost_tnzo_total: u64,
}

fn tier_pairs(s: &CortexMetricsSnapshot) -> [(&'static str, &TierSnapshot); 4] {
    [
        ("fast", &s.tier_fast),
        ("standard", &s.tier_standard),
        ("deep", &s.tier_deep),
        ("institutional", &s.tier_institutional),
    ]
}

fn push_counter(out: &mut String, name: &str, help: &str, value: u64) {
    out.push_str(&format!("# HELP {} {}\n", name, help));
    out.push_str(&format!("# TYPE {} counter\n", name));
    out.push_str(&format!("{} {}\n\n", name, value));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_success_and_tier_buckets() {
        let m = CortexMetrics::new();
        m.record_request_accepted(ReasoningTier::Standard);
        m.record_success(
            ReasoningTier::Standard,
            8,
            1_000_000,
            12,
            42,
            120.0,
            AttestationRequirement::None,
        );
        let s = m.snapshot();
        assert_eq!(s.requests_total, 1);
        assert_eq!(s.requests_success_total, 1);
        assert_eq!(s.loops_executed_total, 8);
        assert_eq!(s.cost_tnzo_total, 1_000_000);
        assert_eq!(s.tokens_in_total, 12);
        assert_eq!(s.tokens_out_total, 42);
        assert_eq!(s.tier_standard.requests, 1);
        assert_eq!(s.tier_standard.loops_total, 8);
        assert_eq!(s.tier_standard.cost_tnzo_total, 1_000_000);
        assert_eq!(s.tier_deep.requests, 0);
        assert_eq!(s.latency.count, 1);
        assert_eq!(s.latency.sum_ms, 120);
    }

    #[test]
    fn records_attestation_counters() {
        let m = CortexMetrics::new();
        m.record_request_accepted(ReasoningTier::Institutional);
        m.record_success(
            ReasoningTier::Institutional,
            32,
            5_000_000,
            10,
            20,
            1_500.0,
            AttestationRequirement::TeeAndZk,
        );
        let s = m.snapshot();
        assert_eq!(s.tee_attestations_total, 1);
        assert_eq!(s.zk_proofs_total, 1);
        assert_eq!(s.tier_institutional.loops_total, 32);
    }

    #[test]
    fn records_rejections_by_reason() {
        let m = CortexMetrics::new();
        m.record_request_accepted(ReasoningTier::Fast);
        m.record_rejection(RejectionReason::InvalidBudget);
        m.record_request_accepted(ReasoningTier::Fast);
        m.record_rejection(RejectionReason::CostExceeded);
        m.record_rejection(RejectionReason::CostExceeded);
        m.record_rejection(RejectionReason::AttestationMissing);
        m.record_rejection(RejectionReason::BackendError);
        let s = m.snapshot();
        assert_eq!(s.requests_total, 2);
        assert_eq!(s.rejected_invalid_budget, 1);
        assert_eq!(s.rejected_cost_exceeded, 2);
        assert_eq!(s.rejected_attestation_missing, 1);
        assert_eq!(s.rejected_backend_error, 1);
    }

    #[test]
    fn latency_buckets_are_cumulative() {
        let m = CortexMetrics::new();
        m.record_request_accepted(ReasoningTier::Fast);
        m.record_success(
            ReasoningTier::Fast,
            2,
            100,
            5,
            5,
            7.0,
            AttestationRequirement::None,
        );
        m.record_request_accepted(ReasoningTier::Fast);
        m.record_success(
            ReasoningTier::Fast,
            2,
            100,
            5,
            5,
            42.0,
            AttestationRequirement::None,
        );
        let s = m.snapshot();
        // buckets: [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000, +Inf]
        //          idx 0 1   2   3   4    5    6    7     8     9     10     11    12
        // 7ms falls into idx>=1; 42ms falls into idx>=3
        assert_eq!(s.latency.buckets[0], 0); // <= 5ms: neither
        assert_eq!(s.latency.buckets[1], 1); // <= 10ms: only the 7ms
        assert_eq!(s.latency.buckets[3], 2); // <= 50ms: both
        assert_eq!(s.latency.buckets[12], 2); // +Inf
        assert_eq!(s.latency.count, 2);
        assert_eq!(s.latency.sum_ms, 49);
    }

    #[test]
    fn prometheus_encoding_includes_core_series() {
        let m = CortexMetrics::new();
        m.record_request_accepted(ReasoningTier::Deep);
        m.record_success(
            ReasoningTier::Deep,
            16,
            250_000,
            8,
            16,
            750.0,
            AttestationRequirement::Tee,
        );
        let mut out = String::new();
        m.encode_prometheus(&mut out);
        assert!(out.contains("cortex_requests_total 1"));
        assert!(out.contains("cortex_loops_executed_total 16"));
        assert!(out.contains("cortex_cost_tnzo_total 250000"));
        assert!(out.contains("cortex_tee_attestations_total 1"));
        assert!(out.contains("cortex_zk_proofs_total 0"));
        assert!(out.contains("cortex_requests_by_tier_total{tier=\"deep\"} 1"));
        assert!(out.contains("cortex_loops_by_tier_total{tier=\"deep\"} 16"));
        assert!(out.contains("cortex_request_latency_ms_bucket{le=\"1000\"}"));
        assert!(out.contains("cortex_request_latency_ms_count 1"));
        // TYPE lines present for each series
        assert!(out.contains("# TYPE cortex_requests_total counter"));
        assert!(out.contains("# TYPE cortex_request_latency_ms histogram"));
    }
}
