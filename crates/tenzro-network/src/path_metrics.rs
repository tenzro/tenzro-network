//! The endpoint's path measurements on `/metrics`.
//!
//! [`PathMetrics`] is a collector: the registry calls it on each scrape and
//! it reads the endpoint's report then, so nothing is kept up to date between
//! scrapes. The families, all under `tenzro_network_`:
//!
//! - `path_holepunch_attempts_total`, `path_connections_opened_total`,
//!   `path_connections_direct_total`: the share of connections that reach a
//!   direct path is direct over opened;
//! - `path_received_bytes_total{path}` and `path_sent_bytes_total{path}`
//!   with `path` one of `relay`, `direct`, `custom`: the relays' share of
//!   the traffic;
//! - `path_time_to_direct_seconds`: a histogram of the time accepted
//!   connections took to reach a direct path.

use prometheus_client::collector::Collector;
use prometheus_client::encoding::{DescriptorEncoder, EncodeMetric, NoLabelSet};
use prometheus_client::metrics::MetricType;
use prometheus_client::metrics::counter::ConstCounter;
use tenzro_iroh::{PathReport, TIME_TO_DIRECT_BUCKETS};

/// Reads the endpoint's path report when the registry is scraped.
pub struct PathMetrics {
    report: Box<dyn Fn() -> PathReport + Send + Sync>,
}

impl PathMetrics {
    /// A collector over `report`, called once per scrape.
    pub fn new(report: impl Fn() -> PathReport + Send + Sync + 'static) -> Self {
        Self {
            report: Box::new(report),
        }
    }
}

impl std::fmt::Debug for PathMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PathMetrics").finish_non_exhaustive()
    }
}

fn counter(
    encoder: &mut DescriptorEncoder,
    name: &str,
    help: &str,
    value: u64,
) -> Result<(), std::fmt::Error> {
    let counter = ConstCounter::new(value);
    counter.encode(encoder.encode_descriptor(name, help, None, counter.metric_type())?)
}

fn counters_by_path(
    encoder: &mut DescriptorEncoder,
    name: &str,
    help: &str,
    values: &[(&str, u64)],
) -> Result<(), std::fmt::Error> {
    let mut family = encoder.encode_descriptor(name, help, None, MetricType::Counter)?;
    for (path, value) in values {
        let labels = [("path", *path)];
        ConstCounter::new(*value).encode(family.encode_family(&labels)?)?;
    }
    Ok(())
}

impl Collector for PathMetrics {
    fn encode(&self, mut encoder: DescriptorEncoder) -> Result<(), std::fmt::Error> {
        let report = (self.report)();
        counter(
            &mut encoder,
            "path_holepunch_attempts",
            "Times hole punching was started, on the dialing side",
            report.holepunch_attempts,
        )?;
        counter(
            &mut encoder,
            "path_connections_opened",
            "Connections whose handshake completed",
            report.connections_opened,
        )?;
        counter(
            &mut encoder,
            "path_connections_direct",
            "Connections that had a direct path at some time",
            report.connections_direct,
        )?;
        counters_by_path(
            &mut encoder,
            "path_received_bytes",
            "Bytes received, by kind of path",
            &[
                ("relay", report.received_bytes.relay),
                ("direct", report.received_bytes.direct),
                ("custom", report.received_bytes.custom),
            ],
        )?;
        counters_by_path(
            &mut encoder,
            "path_sent_bytes",
            "Bytes sent, by kind of path",
            &[
                ("relay", report.sent_bytes.relay),
                ("direct", report.sent_bytes.direct),
            ],
        )?;
        let timed = report.time_to_direct;
        let mut buckets: Vec<(f64, u64)> = TIME_TO_DIRECT_BUCKETS
            .iter()
            .copied()
            .zip(timed.buckets)
            .collect();
        // Nothing is counted past the last bound; the encoder still wants
        // the open-ended bucket.
        buckets.push((f64::MAX, 0));
        encoder
            .encode_descriptor(
                "path_time_to_direct_seconds",
                "Time accepted connections took to reach a direct path",
                None,
                MetricType::Histogram,
            )?
            .encode_histogram::<NoLabelSet>(timed.sum_seconds, timed.count(), &buckets, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus_client::registry::Registry;
    use tenzro_iroh::path_metrics::{ReceivedBytes, SentBytes, TimeToDirect};

    #[test]
    fn a_scrape_reads_the_report_and_names_every_family() {
        let mut registry = Registry::default();
        registry
            .sub_registry_with_prefix("tenzro_network")
            .register_collector(Box::new(PathMetrics::new(|| PathReport {
                holepunch_attempts: 7,
                connections_opened: 10,
                connections_direct: 6,
                received_bytes: ReceivedBytes {
                    relay: 100,
                    direct: 900,
                    custom: 5,
                },
                sent_bytes: SentBytes {
                    relay: 40,
                    direct: 800,
                },
                time_to_direct: TimeToDirect {
                    buckets: [1, 0, 2, 0, 0, 0, 0, 0, 0],
                    sum_seconds: 0.5,
                },
            })));
        let mut text = String::new();
        prometheus_client::encoding::text::encode(&mut text, &registry).unwrap();
        for line in [
            "tenzro_network_path_holepunch_attempts_total 7",
            "tenzro_network_path_connections_opened_total 10",
            "tenzro_network_path_connections_direct_total 6",
            "tenzro_network_path_received_bytes_total{path=\"relay\"} 100",
            "tenzro_network_path_received_bytes_total{path=\"direct\"} 900",
            "tenzro_network_path_received_bytes_total{path=\"custom\"} 5",
            "tenzro_network_path_sent_bytes_total{path=\"relay\"} 40",
            "tenzro_network_path_sent_bytes_total{path=\"direct\"} 800",
            "tenzro_network_path_time_to_direct_seconds_sum 0.5",
            "tenzro_network_path_time_to_direct_seconds_count 3",
            "tenzro_network_path_time_to_direct_seconds_bucket{le=\"0.05\"} 1",
            "tenzro_network_path_time_to_direct_seconds_bucket{le=\"0.25\"} 3",
            "tenzro_network_path_time_to_direct_seconds_bucket{le=\"+Inf\"} 3",
        ] {
            assert!(
                text.lines().any(|l| l == line),
                "no line `{line}` in:\n{text}"
            );
        }
    }
}
