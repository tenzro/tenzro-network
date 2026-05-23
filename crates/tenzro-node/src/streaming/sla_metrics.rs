//! Stream-level SLO metrics.
//!
//! Three signals matter for inference streaming health:
//!
//! - **TTFT** (time to first token) — how long after the request landed
//!   did the user see *something*? This is the perceived-latency metric.
//! - **Inter-token latency** — once tokens start flowing, how jittery is
//!   the stream? A provider with low TTFT but high inter-token variance
//!   is the worst kind of degraded — the user thinks it works, then it
//!   sticks.
//! - **Completion rate** — what fraction of streams the provider opens
//!   actually finish cleanly versus drop / stall? This is the
//!   reputation-feeding signal.
//!
//! All three are labeled by `(provider_address, model_id)` because routing
//! decisions are per-(provider, model) and dashboards need that
//! granularity. Lock-free atomic histograms; one `(provider, model)` pair
//! lives in a `DashMap` entry. No per-scrape walk over all streams — every
//! observation hits a fixed-size atomic counter set.
//!
//! Output format follows Prometheus text exposition. Bucket choices match
//! the typical inference range: TTFT 100 ms - 30 s, inter-token 5 ms - 5 s.

use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// TTFT bucket upper bounds in seconds. Spans the realistic range from a
/// hot-cached local model (~100 ms) to a cold cloud GPU with attestation
/// (~30 s).
pub const TTFT_BUCKETS_S: &[f64] = &[
    0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 30.0,
];

/// Inter-token latency bucket upper bounds in seconds. A healthy local
/// 7B-class model at fp16 generates ~30-100 tok/s (10-33 ms/token); cloud
/// providers float around 20-50 tok/s (20-50 ms/token). The upper buckets
/// catch degraded providers approaching the stall budget.
pub const INTERTOKEN_BUCKETS_S: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
];

/// Fixed-bucket histogram with `+Inf` overflow.
#[derive(Debug)]
struct Histogram {
    /// One slot per bucket upper-bound, plus a trailing `+Inf` slot.
    buckets: Vec<AtomicU64>,
    sum_us: AtomicU64,
    count: AtomicU64,
    upper_bounds_s: &'static [f64],
}

impl Histogram {
    fn new(upper_bounds_s: &'static [f64]) -> Self {
        let mut buckets = Vec::with_capacity(upper_bounds_s.len() + 1);
        for _ in 0..=upper_bounds_s.len() {
            buckets.push(AtomicU64::new(0));
        }
        Self {
            buckets,
            sum_us: AtomicU64::new(0),
            count: AtomicU64::new(0),
            upper_bounds_s,
        }
    }

    fn observe(&self, seconds: f64) {
        let v = if seconds.is_finite() && seconds >= 0.0 {
            seconds
        } else {
            0.0
        };
        let us = (v * 1_000_000.0).round();
        let us_u64 = if us.is_finite() && us >= 0.0 {
            us.min(u64::MAX as f64) as u64
        } else {
            0
        };
        self.sum_us.fetch_add(us_u64, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
        for (i, upper) in self.upper_bounds_s.iter().enumerate() {
            if v <= *upper {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        // +Inf always increments.
        self.buckets[self.upper_bounds_s.len()].fetch_add(1, Ordering::Relaxed);
    }
}

/// Per-(provider, model) accumulator.
#[derive(Debug)]
struct StreamSloRow {
    ttft: Histogram,
    intertoken: Histogram,
    streams_started: AtomicU64,
    streams_completed: AtomicU64,
    streams_failed: AtomicU64,
}

impl StreamSloRow {
    fn new() -> Self {
        Self {
            ttft: Histogram::new(TTFT_BUCKETS_S),
            intertoken: Histogram::new(INTERTOKEN_BUCKETS_S),
            streams_started: AtomicU64::new(0),
            streams_completed: AtomicU64::new(0),
            streams_failed: AtomicU64::new(0),
        }
    }
}

/// Cheap-to-clone handle over stream SLO metrics. `Arc<DashMap<…>>`
/// internally; safe to share across the proxy + local-model code paths
/// and the `/metrics` exporter.
#[derive(Clone, Default)]
pub struct StreamSloMetrics {
    inner: Arc<DashMap<(String, String), Arc<StreamSloRow>>>,
}

impl StreamSloMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    fn row(&self, provider: &str, model: &str) -> Arc<StreamSloRow> {
        // Use the entry API to avoid allocating a key if the row exists.
        if let Some(r) = self.inner.get(&(provider.to_string(), model.to_string())) {
            return r.clone();
        }
        self.inner
            .entry((provider.to_string(), model.to_string()))
            .or_insert_with(|| Arc::new(StreamSloRow::new()))
            .clone()
    }

    /// Count a new stream opened against `(provider, model)`.
    pub fn record_stream_started(&self, provider: &str, model: &str) {
        let r = self.row(provider, model);
        r.streams_started.fetch_add(1, Ordering::Relaxed);
    }

    /// Observe TTFT — call exactly once per stream, on the first token.
    pub fn record_first_token(&self, provider: &str, model: &str, ttft_s: f64) {
        let r = self.row(provider, model);
        r.ttft.observe(ttft_s);
    }

    /// Observe one inter-token interval — call on every token except the
    /// first.
    pub fn record_intertoken(&self, provider: &str, model: &str, gap_s: f64) {
        let r = self.row(provider, model);
        r.intertoken.observe(gap_s);
    }

    /// Mark a stream finished. `success = true` means natural termination
    /// (upstream closed cleanly after emitting at least one chunk);
    /// `false` covers both mid-stream drops and watchdog stalls — the
    /// reputation-feeding signal treats them the same.
    pub fn record_stream_completed(&self, provider: &str, model: &str, success: bool) {
        let r = self.row(provider, model);
        if success {
            r.streams_completed.fetch_add(1, Ordering::Relaxed);
        } else {
            r.streams_failed.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Number of distinct (provider, model) rows currently tracked.
    pub fn rows(&self) -> usize {
        self.inner.len()
    }

    /// Render in Prometheus text-exposition format. Output is deterministic
    /// across runs only modulo `DashMap` iteration order — for tests we
    /// collect-and-sort the keys first.
    pub fn encode_prometheus(&self, out: &mut String) {
        use std::fmt::Write as _;

        // Stable key ordering for deterministic output.
        let mut keys: Vec<(String, String)> = self
            .inner
            .iter()
            .map(|e| e.key().clone())
            .collect();
        keys.sort();

        // TTFT histogram
        let _ = writeln!(
            out,
            "# HELP tenzro_inference_ttft_seconds Time to first token of a streamed inference, by provider and model."
        );
        let _ = writeln!(out, "# TYPE tenzro_inference_ttft_seconds histogram");
        for k in &keys {
            let row = match self.inner.get(k) {
                Some(r) => r.clone(),
                None => continue,
            };
            emit_histogram(
                out,
                "tenzro_inference_ttft_seconds",
                &k.0,
                &k.1,
                &row.ttft,
            );
        }

        // Intertoken histogram
        let _ = writeln!(
            out,
            "# HELP tenzro_inference_intertoken_seconds Gap between consecutive tokens of a streamed inference, by provider and model."
        );
        let _ = writeln!(
            out,
            "# TYPE tenzro_inference_intertoken_seconds histogram"
        );
        for k in &keys {
            let row = match self.inner.get(k) {
                Some(r) => r.clone(),
                None => continue,
            };
            emit_histogram(
                out,
                "tenzro_inference_intertoken_seconds",
                &k.0,
                &k.1,
                &row.intertoken,
            );
        }

        // Counters
        let _ = writeln!(
            out,
            "# HELP tenzro_inference_streams_started_total Streams opened, by provider and model."
        );
        let _ = writeln!(
            out,
            "# TYPE tenzro_inference_streams_started_total counter"
        );
        for k in &keys {
            let row = match self.inner.get(k) {
                Some(r) => r.clone(),
                None => continue,
            };
            let _ = writeln!(
                out,
                "tenzro_inference_streams_started_total{{provider=\"{}\",model=\"{}\"}} {}",
                escape_label(&k.0),
                escape_label(&k.1),
                row.streams_started.load(Ordering::Relaxed)
            );
        }

        let _ = writeln!(
            out,
            "# HELP tenzro_inference_streams_completed_total Streams that ended cleanly after emitting at least one chunk."
        );
        let _ = writeln!(
            out,
            "# TYPE tenzro_inference_streams_completed_total counter"
        );
        for k in &keys {
            let row = match self.inner.get(k) {
                Some(r) => r.clone(),
                None => continue,
            };
            let _ = writeln!(
                out,
                "tenzro_inference_streams_completed_total{{provider=\"{}\",model=\"{}\"}} {}",
                escape_label(&k.0),
                escape_label(&k.1),
                row.streams_completed.load(Ordering::Relaxed)
            );
        }

        let _ = writeln!(
            out,
            "# HELP tenzro_inference_streams_failed_total Streams that mid-stream errored or stalled (watchdog)."
        );
        let _ = writeln!(
            out,
            "# TYPE tenzro_inference_streams_failed_total counter"
        );
        for k in &keys {
            let row = match self.inner.get(k) {
                Some(r) => r.clone(),
                None => continue,
            };
            let _ = writeln!(
                out,
                "tenzro_inference_streams_failed_total{{provider=\"{}\",model=\"{}\"}} {}",
                escape_label(&k.0),
                escape_label(&k.1),
                row.streams_failed.load(Ordering::Relaxed)
            );
        }
    }
}

fn escape_label(s: &str) -> String {
    // Prometheus label-value escaping: backslash, double-quote, newline.
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            _ => out.push(c),
        }
    }
    out
}

fn emit_histogram(
    out: &mut String,
    metric: &str,
    provider: &str,
    model: &str,
    hist: &Histogram,
) {
    use std::fmt::Write as _;
    let prov = escape_label(provider);
    let mdl = escape_label(model);
    let mut cumulative: u64;
    // Cumulative-count buckets are already cumulative in `observe()`
    // (each observation increments every bucket whose upper bound it
    // satisfies). So we emit raw values directly.
    for (i, upper) in hist.upper_bounds_s.iter().enumerate() {
        cumulative = hist.buckets[i].load(Ordering::Relaxed);
        let _ = writeln!(
            out,
            "{}_bucket{{provider=\"{}\",model=\"{}\",le=\"{}\"}} {}",
            metric, prov, mdl, format_le(*upper), cumulative
        );
    }
    let inf = hist.buckets[hist.upper_bounds_s.len()].load(Ordering::Relaxed);
    let _ = writeln!(
        out,
        "{}_bucket{{provider=\"{}\",model=\"{}\",le=\"+Inf\"}} {}",
        metric, prov, mdl, inf
    );
    let sum_s = (hist.sum_us.load(Ordering::Relaxed) as f64) / 1_000_000.0;
    let _ = writeln!(
        out,
        "{}_sum{{provider=\"{}\",model=\"{}\"}} {}",
        metric, prov, mdl, sum_s
    );
    let _ = writeln!(
        out,
        "{}_count{{provider=\"{}\",model=\"{}\"}} {}",
        metric, prov, mdl, hist.count.load(Ordering::Relaxed)
    );
}

fn format_le(v: f64) -> String {
    // Prometheus convention: trim trailing zeros, no scientific notation
    // for the bucket values we use (all small fixed decimals).
    if v.fract() == 0.0 {
        format!("{:.1}", v)
    } else {
        // 3 decimal places is enough for sub-millisecond buckets (0.005)
        // and won't expand integer values pointlessly.
        let s = format!("{:.3}", v);
        // Trim trailing zeros, but keep at least one digit after the dot.
        let trimmed = s.trim_end_matches('0');
        let trimmed = trimmed.trim_end_matches('.');
        trimmed.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_and_render_basic() {
        let m = StreamSloMetrics::new();
        m.record_stream_started("provA", "qwen3-0.6b");
        m.record_first_token("provA", "qwen3-0.6b", 0.3);
        m.record_intertoken("provA", "qwen3-0.6b", 0.02);
        m.record_intertoken("provA", "qwen3-0.6b", 0.04);
        m.record_stream_completed("provA", "qwen3-0.6b", true);

        let mut out = String::new();
        m.encode_prometheus(&mut out);

        assert!(out.contains("tenzro_inference_ttft_seconds_bucket"));
        assert!(out.contains("tenzro_inference_intertoken_seconds_bucket"));
        assert!(out.contains(
            "tenzro_inference_streams_started_total{provider=\"provA\",model=\"qwen3-0.6b\"} 1"
        ));
        assert!(out.contains(
            "tenzro_inference_streams_completed_total{provider=\"provA\",model=\"qwen3-0.6b\"} 1"
        ));
        // count for intertoken should be 2
        assert!(out.contains(
            "tenzro_inference_intertoken_seconds_count{provider=\"provA\",model=\"qwen3-0.6b\"} 2"
        ));
    }

    #[test]
    fn buckets_are_cumulative() {
        let m = StreamSloMetrics::new();
        // Three TTFTs at 0.3, 0.7, 1.5 seconds.
        m.record_first_token("p", "m", 0.3);
        m.record_first_token("p", "m", 0.7);
        m.record_first_token("p", "m", 1.5);
        let mut out = String::new();
        m.encode_prometheus(&mut out);
        // le=0.5 captures 0.3 only → 1
        assert!(out.contains(
            "tenzro_inference_ttft_seconds_bucket{provider=\"p\",model=\"m\",le=\"0.5\"} 1"
        ));
        // le=1 captures 0.3 + 0.7 → 2
        assert!(out.contains(
            "tenzro_inference_ttft_seconds_bucket{provider=\"p\",model=\"m\",le=\"1.0\"} 2"
        ));
        // le=2 captures all three → 3
        assert!(out.contains(
            "tenzro_inference_ttft_seconds_bucket{provider=\"p\",model=\"m\",le=\"2.0\"} 3"
        ));
        // +Inf → 3
        assert!(out.contains(
            "tenzro_inference_ttft_seconds_bucket{provider=\"p\",model=\"m\",le=\"+Inf\"} 3"
        ));
    }

    #[test]
    fn separate_rows_per_provider_model() {
        let m = StreamSloMetrics::new();
        m.record_stream_started("p1", "m1");
        m.record_stream_started("p2", "m1");
        m.record_stream_started("p1", "m2");
        assert_eq!(m.rows(), 3);
    }

    #[test]
    fn failed_stream_increments_failed_counter_only() {
        let m = StreamSloMetrics::new();
        m.record_stream_completed("p", "m", false);
        let mut out = String::new();
        m.encode_prometheus(&mut out);
        assert!(out.contains(
            "tenzro_inference_streams_failed_total{provider=\"p\",model=\"m\"} 1"
        ));
        assert!(out.contains(
            "tenzro_inference_streams_completed_total{provider=\"p\",model=\"m\"} 0"
        ));
    }

    #[test]
    fn label_values_are_escaped() {
        let m = StreamSloMetrics::new();
        m.record_stream_started("prov\"weird\\name", "model\nwith newline");
        let mut out = String::new();
        m.encode_prometheus(&mut out);
        assert!(out.contains("prov\\\"weird\\\\name"));
        assert!(out.contains("model\\nwith newline"));
    }

    #[test]
    fn format_le_trims_trailing_zeros() {
        assert_eq!(format_le(0.5), "0.5");
        assert_eq!(format_le(1.0), "1.0");
        assert_eq!(format_le(0.005), "0.005");
        assert_eq!(format_le(30.0), "30.0");
    }

    #[test]
    fn render_empty_metrics_is_valid() {
        let m = StreamSloMetrics::new();
        let mut out = String::new();
        m.encode_prometheus(&mut out);
        // Only HELP/TYPE lines; no observations.
        assert!(out.contains("# TYPE tenzro_inference_ttft_seconds histogram"));
        assert!(out.contains(
            "# TYPE tenzro_inference_streams_started_total counter"
        ));
    }
}
