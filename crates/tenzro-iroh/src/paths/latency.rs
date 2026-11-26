//! Latency and jitter of every open path, so routing and applications can
//! choose between peers and paths by what they measured.
//!
//! Every connection the endpoint opens or accepts is watched from its
//! handshake until it closes. Once a second each of its paths that has
//! received anything is sampled: its round-trip time, the smoothed estimate
//! QUIC keeps (RFC 9002), which moves within a few packets of a change. A
//! path that has received nothing still carries the initial estimate and is
//! not sampled. Over the last minute of samples [`PathLatency::report`] gives
//! each path's median, its worst, and its jitter: the mean difference between
//! consecutive samples. Samples of several connections to one remote over one
//! path go into the same window.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use iroh::endpoint::{AfterHandshakeOutcome, Connection, EndpointHooks};
use iroh::{EndpointId, TransportAddr};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

/// How often each open path is sampled.
const SAMPLE_EVERY: Duration = Duration::from_secs(1);

/// How far back a report reaches. A path with no sample in it is forgotten.
const WINDOW: Duration = Duration::from_secs(60);

/// The samples of one path to one remote, oldest first.
type Samples = VecDeque<(Instant, Duration)>;

#[derive(Debug, Default)]
struct Windows {
    paths: HashMap<(EndpointId, TransportAddr), Samples>,
    pruned: Option<Instant>,
}

impl Windows {
    fn record(&mut self, key: (EndpointId, TransportAddr), rtt: Duration, now: Instant) {
        self.paths.entry(key).or_default().push_back((now, rtt));
        // Paths of closed connections stop getting samples; once a sample
        // period, every window drops what fell out of it.
        if self
            .pruned
            .is_none_or(|t| now.duration_since(t) >= SAMPLE_EVERY)
        {
            self.prune(now);
        }
    }

    fn prune(&mut self, now: Instant) {
        self.paths.retain(|_, samples| {
            while samples
                .front()
                .is_some_and(|(t, _)| now.duration_since(*t) > WINDOW)
            {
                samples.pop_front();
            }
            !samples.is_empty()
        });
        self.pruned = Some(now);
    }
}

/// The latency of every open path of an endpoint. Installed on the endpoint
/// as a hook ([`crate::paths::Paths::install`]), it watches each connection.
#[derive(Debug, Clone, Default)]
pub struct PathLatency {
    windows: Arc<Mutex<Windows>>,
}

/// What one path measured over the last minute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathLatencyReport {
    /// The remote endpoint.
    pub remote: String,
    /// How the path reaches it: `ip`, `relay` or `peer relay`.
    pub kind: String,
    /// Where the path goes: an IP address, a relay URL, or the custom
    /// address of a path through a forwarder.
    pub addr: String,
    /// Samples in the window.
    pub samples: usize,
    /// Median round-trip time, in microseconds.
    pub median_us: u64,
    /// Highest round-trip time, in microseconds.
    pub worst_us: u64,
    /// Mean difference between consecutive samples, in microseconds.
    pub jitter_us: u64,
}

impl PathLatency {
    /// Samples the paths of `conn` once a second until it closes.
    pub fn watch(&self, conn: &Connection) {
        let weak = conn.weak_handle();
        let remote = conn.remote_id();
        let windows = self.windows.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(SAMPLE_EVERY);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                // Held only while sampling: a watched connection still
                // closes when its owners drop it.
                let Some(conn) = weak.upgrade() else { break };
                if conn.close_reason().is_some() {
                    break;
                }
                let now = Instant::now();
                let sampled: Vec<(TransportAddr, Duration)> = conn
                    .paths()
                    .iter()
                    .filter_map(|path| {
                        let stats = path.stats();
                        (stats.udp_rx.datagrams > 0)
                            .then(|| (path.remote_addr().clone(), stats.rtt))
                    })
                    .collect();
                drop(conn);
                let mut windows = windows.lock();
                for (addr, rtt) in sampled {
                    windows.record((remote, addr), rtt, now);
                }
            }
        });
    }

    /// How much the queue on the path to `remote` delays it now: the latest
    /// round-trip time of a path less the lowest of its window, taken from
    /// the path that shows the least. `None` until a path to `remote` has two
    /// samples.
    pub fn queueing_delay(&self, remote: &EndpointId) -> Option<Duration> {
        self.windows
            .lock()
            .paths
            .iter()
            .filter(|((r, _), samples)| r == remote && samples.len() >= 2)
            .filter_map(|(_, samples)| {
                let latest = samples.back()?.1;
                let lowest = samples.iter().map(|(_, rtt)| *rtt).min()?;
                Some(latest - lowest)
            })
            .min()
    }

    #[cfg(test)]
    pub(crate) fn record_sample(
        &self,
        remote: EndpointId,
        addr: TransportAddr,
        rtt: Duration,
        at: Instant,
    ) {
        self.windows.lock().record((remote, addr), rtt, at);
    }

    /// Every path sampled in the last minute, by remote and then by path.
    pub fn report(&self) -> Vec<PathLatencyReport> {
        let mut windows = self.windows.lock();
        windows.prune(Instant::now());
        let mut reports: Vec<PathLatencyReport> = windows
            .paths
            .iter()
            .map(|((remote, addr), samples)| {
                let rtts: Vec<Duration> = samples.iter().map(|(_, rtt)| *rtt).collect();
                let (kind, addr) = describe(addr);
                PathLatencyReport {
                    remote: remote.to_string(),
                    kind,
                    addr,
                    samples: rtts.len(),
                    median_us: micros(median(&rtts)),
                    worst_us: micros(rtts.iter().copied().max().unwrap_or_default()),
                    jitter_us: micros(jitter(&rtts)),
                }
            })
            .collect();
        reports.sort_by(|a, b| (&a.remote, &a.kind, &a.addr).cmp(&(&b.remote, &b.kind, &b.addr)));
        reports
    }
}

impl EndpointHooks for PathLatency {
    #[allow(clippy::manual_async_fn)] // the trait's signature carries the lifetime and the Send bound
    fn after_handshake<'a>(
        &'a self,
        conn: &'a Connection,
    ) -> impl Future<Output = AfterHandshakeOutcome> + Send + 'a {
        async move {
            self.watch(conn);
            AfterHandshakeOutcome::accept()
        }
    }
}

fn describe(addr: &TransportAddr) -> (String, String) {
    match addr {
        TransportAddr::Ip(ip) => ("ip".into(), ip.to_string()),
        TransportAddr::Relay(url) => ("relay".into(), url.to_string()),
        TransportAddr::Custom(custom) => ("peer relay".into(), format!("{custom:?}")),
        other => ("other".into(), format!("{other:?}")),
    }
}

fn micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

/// The middle sample, or the mean of the two middle ones.
fn median(rtts: &[Duration]) -> Duration {
    let mut sorted = rtts.to_vec();
    sorted.sort();
    match sorted.len() {
        0 => Duration::ZERO,
        n if n % 2 == 1 => sorted[n / 2],
        n => (sorted[n / 2 - 1] + sorted[n / 2]) / 2,
    }
}

/// The mean absolute difference between consecutive samples.
fn jitter(rtts: &[Duration]) -> Duration {
    if rtts.len() < 2 {
        return Duration::ZERO;
    }
    let total: Duration = rtts.windows(2).map(|w| w[0].abs_diff(w[1])).sum();
    total / (rtts.len() as u32 - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    #[test]
    fn median_worst_and_jitter_of_a_window() {
        let rtts = [ms(10), ms(30), ms(20), ms(40)];
        assert_eq!(median(&rtts), ms(25));
        assert_eq!(jitter(&rtts), ms(50) / 3);
        assert_eq!(median(&rtts[..3]), ms(20));
        assert_eq!(jitter(&rtts[..1]), Duration::ZERO);
        assert_eq!(median(&[]), Duration::ZERO);
    }

    #[test]
    fn samples_older_than_the_window_are_dropped_and_empty_paths_forgotten() {
        let remote = iroh::SecretKey::from_bytes(&[7; 32]).public();
        let old = TransportAddr::Ip("192.0.2.1:1".parse().unwrap());
        let new = TransportAddr::Ip("192.0.2.2:1".parse().unwrap());
        let start = Instant::now();
        let mut w = Windows::default();
        w.record((remote, old.clone()), ms(10), start);
        w.record((remote, new.clone()), ms(20), start + WINDOW / 2);
        w.record(
            (remote, new.clone()),
            ms(30),
            start + WINDOW + SAMPLE_EVERY * 2,
        );
        assert!(
            !w.paths.contains_key(&(remote, old)),
            "a path with no recent sample is forgotten"
        );
        assert_eq!(w.paths[&(remote, new)].len(), 2);
    }

    #[test]
    fn the_queueing_delay_is_the_least_any_path_to_the_remote_shows() {
        let remote = iroh::SecretKey::from_bytes(&[7; 32]).public();
        let other = iroh::SecretKey::from_bytes(&[8; 32]).public();
        let ip = TransportAddr::Ip("192.0.2.1:1".parse().unwrap());
        let relay = TransportAddr::Relay("https://relay.example.org/".parse().unwrap());
        let latency = PathLatency::default();
        let t = Instant::now();
        latency.record_sample(remote, ip.clone(), ms(10), t);
        assert_eq!(
            latency.queueing_delay(&remote),
            None,
            "one sample is no baseline"
        );
        latency.record_sample(remote, ip, ms(70), t + SAMPLE_EVERY);
        latency.record_sample(remote, relay.clone(), ms(40), t);
        latency.record_sample(remote, relay, ms(50), t + SAMPLE_EVERY);
        latency.record_sample(
            other,
            TransportAddr::Ip("192.0.2.9:1".parse().unwrap()),
            ms(5),
            t,
        );
        assert_eq!(latency.queueing_delay(&remote), Some(ms(10)));
        assert_eq!(latency.queueing_delay(&other), None);
    }

    /// Two endpoints on one machine: each sees the other's path within a few
    /// samples, with a round-trip time and the remote it belongs to.
    #[tokio::test(flavor = "multi_thread")]
    async fn both_ends_of_a_connection_report_its_path() {
        let server_latency = PathLatency::default();
        let client_latency = PathLatency::default();
        let server =
            crate::identity_transport::on_loopback(crate::identity_transport::base_builder())
                .hooks(server_latency.clone())
                .alpns(vec![b"latency-test".to_vec()])
                .bind()
                .await
                .unwrap();
        let client =
            crate::identity_transport::on_loopback(crate::identity_transport::base_builder())
                .hooks(client_latency.clone())
                .bind()
                .await
                .unwrap();
        let accept = {
            let server = server.clone();
            tokio::spawn(async move {
                let conn = server.accept().await.unwrap().await.unwrap();
                let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                let got = recv.read_to_end(64).await.unwrap();
                send.write_all(&got).await.unwrap();
                send.finish().unwrap();
                conn.closed().await;
            })
        };
        let conn = crate::bounded::connect(
            &client,
            server.addr(),
            b"latency-test",
            crate::bounded::BACKSTOP,
        )
        .await
        .unwrap();
        let (mut send, mut recv) = crate::bounded::open_bi(&conn, crate::bounded::BACKSTOP)
            .await
            .unwrap();
        send.write_all(b"ping").await.unwrap();
        send.finish().unwrap();
        assert_eq!(recv.read_to_end(64).await.unwrap(), b"ping");
        let reported = async {
            loop {
                let c = client_latency.report();
                let s = server_latency.report();
                if c.iter().any(|r| r.samples >= 2) && s.iter().any(|r| r.samples >= 2) {
                    return (c, s);
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        };
        let (c, s) = tokio::time::timeout(Duration::from_secs(15), reported)
            .await
            .expect("both ends sample the path within a few seconds");
        let path = c.iter().find(|r| r.samples >= 2).unwrap();
        assert_eq!(path.remote, server.id().to_string());
        assert_eq!(path.kind, "ip");
        assert!(path.median_us > 0 && path.worst_us >= path.median_us);
        assert!(s.iter().any(|r| r.remote == client.id().to_string()));
        conn.close(0u32.into(), b"done");
        accept.await.unwrap();
        client.close().await;
        server.close().await;
    }
}
