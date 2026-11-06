//! Demand read from a population market trace.
//!
//! A trace is JSON lines: an optional `# market-trace {...}` header, then
//! one payment per line with `t_ms`, `buyer`, `provider`, `service`,
//! `amount_milli` (thousandths of a USD) and `delivered`. The trace's span
//! is laid over `span_days` calendar days, as the population replay lays it,
//! and repeats after that. From it come the payments per day, their mean
//! size, the share delivered, the share of each service, and the spread of
//! revenue across providers.

use std::collections::BTreeMap;

use serde::Serialize;

/// Demand derived from one trace.
#[derive(Debug, Clone, Serialize)]
pub struct TraceDemand {
    /// File the trace came from.
    pub source: String,
    /// Calendar days the trace's span is laid over.
    pub span_days: f64,
    /// Payments in the trace.
    pub payments: u64,
    /// Payments per calendar day, averaged over the span.
    pub payments_per_day: f64,
    /// Mean payment, USD.
    pub mean_usd: f64,
    /// Share of payments whose service was delivered.
    pub delivered_share: f64,
    /// Share of payment value by service.
    pub service_share: BTreeMap<String, f64>,
    /// Payments on each day of the span over the mean.
    pub day_multiple: Vec<f64>,
    /// Providers paid at least once.
    pub providers: u64,
    /// Delivered revenue of each provider over the span, USD, ascending.
    pub provider_revenue_usd: Vec<f64>,
    /// Buyers that paid at least once.
    pub buyers: u64,
}

#[derive(serde::Deserialize)]
struct Line {
    t_ms: i64,
    #[serde(default)]
    provider: u64,
    #[serde(default)]
    buyer: u64,
    #[serde(default)]
    service: String,
    amount_milli: f64,
    #[serde(default = "yes")]
    delivered: bool,
}

fn yes() -> bool {
    true
}

impl TraceDemand {
    /// Reads a trace laid over `span_days` days.
    pub fn load(path: &str, span_days: f64) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        Self::parse(path, &text, span_days)
    }

    /// Parses a trace's text.
    pub fn parse(source: &str, text: &str, span_days: f64) -> Result<Self, String> {
        let mut lines = Vec::new();
        for (i, l) in text.lines().enumerate() {
            let l = l.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            let p: Line =
                serde_json::from_str(l).map_err(|e| format!("{source} line {}: {e}", i + 1))?;
            lines.push(p);
        }
        if lines.is_empty() {
            return Err(format!("{source}: no payments"));
        }
        let t0 = lines.iter().map(|p| p.t_ms).min().unwrap_or(0);
        let t1 = lines.iter().map(|p| p.t_ms).max().unwrap_or(0);
        let span_ms = (t1 - t0).max(1) as f64;
        let days = span_days.max(1.0);
        let bins = days.ceil() as usize;
        let mut per_day = vec![0.0; bins];
        let mut value = 0.0;
        let mut delivered = 0u64;
        let mut by_service: BTreeMap<String, f64> = BTreeMap::new();
        let mut by_provider: BTreeMap<u64, f64> = BTreeMap::new();
        let mut buyers = std::collections::BTreeSet::new();
        for p in &lines {
            let at = (p.t_ms - t0) as f64 / span_ms * days;
            per_day[(at as usize).min(bins - 1)] += 1.0;
            let usd = p.amount_milli / 1_000.0;
            value += usd;
            *by_service.entry(p.service.clone()).or_default() += usd;
            buyers.insert(p.buyer);
            if p.delivered {
                delivered += 1;
                *by_provider.entry(p.provider).or_default() += usd;
            }
        }
        let n = lines.len() as f64;
        let mean = n / bins as f64;
        for s in by_service.values_mut() {
            *s /= value.max(1e-12);
        }
        let mut provider_revenue_usd: Vec<f64> = by_provider.values().copied().collect();
        provider_revenue_usd.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        Ok(Self {
            source: source.to_string(),
            span_days: days,
            payments: lines.len() as u64,
            payments_per_day: n / days,
            mean_usd: value / n,
            delivered_share: delivered as f64 / n,
            service_share: by_service,
            day_multiple: per_day.iter().map(|c| c / mean.max(1e-12)).collect(),
            providers: by_provider.len() as u64,
            provider_revenue_usd,
            buyers: buyers.len() as u64,
        })
    }

    /// Payments on `day` over the mean; the span repeats.
    pub fn multiple(&self, day: f64) -> f64 {
        if self.day_multiple.is_empty() {
            return 1.0;
        }
        let i = (day.max(0.0) as usize) % self.day_multiple.len();
        self.day_multiple[i]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_trace_gives_its_rate_size_and_shares() {
        let text = "# market-trace {}\n\
            {\"t_ms\":0,\"buyer\":1,\"provider\":7,\"service\":\"compute\",\"amount_milli\":2000,\"delivered\":true}\n\
            {\"t_ms\":500,\"buyer\":2,\"provider\":8,\"service\":\"search\",\"amount_milli\":1000,\"delivered\":false}\n\
            {\"t_ms\":1000,\"buyer\":1,\"provider\":7,\"service\":\"compute\",\"amount_milli\":3000,\"delivered\":true}\n";
        let t = TraceDemand::parse("t", text, 2.0).expect("parses");
        assert_eq!(t.payments, 3);
        assert!((t.payments_per_day - 1.5).abs() < 1e-12);
        assert!((t.mean_usd - 2.0).abs() < 1e-12);
        assert!((t.delivered_share - 2.0 / 3.0).abs() < 1e-12);
        assert!((t.service_share["compute"] - 5.0 / 6.0).abs() < 1e-12);
        assert_eq!(t.providers, 1);
        assert_eq!(t.provider_revenue_usd, vec![5.0]);
        // The first payment lands on day 0; the midpoint and the last
        // instant on day 1.
        assert_eq!(t.day_multiple, vec![1.0 / 1.5, 2.0 / 1.5]);
        assert_eq!(t.multiple(3.0), t.day_multiple[1]);
    }
}
