//! Path measurements of the node's endpoint.
//!
//! Three questions a relay operator and a routing decision both ask:
//!
//! - how often hole punching is tried and how many connections end up on a
//!   direct path ([`PathReport::holepunch_attempts`],
//!   [`PathReport::connections_direct`] of
//!   [`PathReport::connections_opened`]);
//! - how much of the traffic the relays carry ([`PathReport::received_bytes`]
//!   and [`PathReport::sent_bytes`], by kind of path);
//! - how long a connection takes to reach a direct path
//!   ([`PathReport::time_to_direct`]).
//!
//! The first two are counters the endpoint keeps anyway; [`path_report`]
//! reads them when asked and costs nothing in between. The third is measured
//! by [`PathTimings::observe`], on each connection the endpoint accepts.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use futures::StreamExt;
use iroh::Endpoint;
use iroh::endpoint::Connection;

/// Upper bounds, in seconds, of the buckets [`TimeToDirect`] counts in.
pub const TIME_TO_DIRECT_BUCKETS: [f64; 9] = [0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0];

/// How long a connection is watched for its first direct path. One that is
/// still on a relay after this is not counted.
const WATCH: Duration = Duration::from_secs(30);

/// How long accepted connections took to reach a direct path.
#[derive(Debug, Default)]
pub struct PathTimings {
    buckets: [AtomicU64; TIME_TO_DIRECT_BUCKETS.len()],
    micros: AtomicU64,
}

impl PathTimings {
    /// Watches `conn` until it sends on a direct path, closes, or has been
    /// watched for thirty seconds, and counts the time the first took. A
    /// connection that starts on a direct path counts as taking no time.
    pub async fn observe(&self, conn: &Connection) {
        let started = Instant::now();
        // Subscribed before the first look, so a path selected in between is
        // seen by one or the other.
        let mut events = std::pin::pin!(conn.path_events());
        let direct = async {
            loop {
                if conn.paths().iter().any(|p| p.is_selected() && p.is_ip()) {
                    return true;
                }
                if events.next().await.is_none() {
                    return false;
                }
            }
        };
        if let Ok(true) = tokio::time::timeout(WATCH, direct).await {
            self.record(started.elapsed());
        }
    }

    fn record(&self, took: Duration) {
        let secs = took.as_secs_f64();
        let bucket = TIME_TO_DIRECT_BUCKETS
            .iter()
            .position(|bound| secs <= *bound)
            .unwrap_or(TIME_TO_DIRECT_BUCKETS.len() - 1);
        self.buckets[bucket].fetch_add(1, Ordering::Relaxed);
        self.micros.fetch_add(
            u64::try_from(took.as_micros()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    /// The times counted so far.
    pub fn snapshot(&self) -> TimeToDirect {
        TimeToDirect {
            buckets: std::array::from_fn(|i| self.buckets[i].load(Ordering::Relaxed)),
            sum_seconds: self.micros.load(Ordering::Relaxed) as f64 / 1e6,
        }
    }
}

/// Connections that reached a direct path, by how long it took.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct TimeToDirect {
    /// Connections per bucket of [`TIME_TO_DIRECT_BUCKETS`], each counted in
    /// the first bucket whose bound it fits under.
    pub buckets: [u64; TIME_TO_DIRECT_BUCKETS.len()],
    /// The times added up, in seconds.
    pub sum_seconds: f64,
}

impl TimeToDirect {
    /// Connections counted.
    pub fn count(&self) -> u64 {
        self.buckets.iter().sum()
    }
}

/// Bytes received, by the kind of path that carried them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReceivedBytes {
    /// Through a relay server.
    pub relay: u64,
    /// Over a direct IPv4 or IPv6 path.
    pub direct: u64,
    /// Over a path the node adds itself (through a forwarding peer).
    pub custom: u64,
}

/// Bytes sent, by the kind of path that carried them. The endpoint does not
/// count what it sends over the paths the node adds itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SentBytes {
    /// Through a relay server.
    pub relay: u64,
    /// Over a direct IPv4 or IPv6 path.
    pub direct: u64,
}

/// What the endpoint has counted about its paths since it was bound.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct PathReport {
    /// Times hole punching was started. Counted on the dialing side only,
    /// and more than once for a connection that needed several attempts.
    pub holepunch_attempts: u64,
    /// Connections whose handshake completed.
    pub connections_opened: u64,
    /// Of those, connections that had a direct path at some time.
    pub connections_direct: u64,
    /// Bytes received, by kind of path.
    pub received_bytes: ReceivedBytes,
    /// Bytes sent, by kind of path.
    pub sent_bytes: SentBytes,
    /// How long accepted connections took to reach a direct path.
    pub time_to_direct: TimeToDirect,
}

/// Reads `endpoint`'s path counters and `timings`.
pub fn path_report(endpoint: &Endpoint, timings: &PathTimings) -> PathReport {
    let socket = &endpoint.metrics().socket;
    PathReport {
        holepunch_attempts: socket.holepunch_attempts.get(),
        connections_opened: socket.num_conns_opened.get(),
        connections_direct: socket.num_conns_direct.get(),
        received_bytes: ReceivedBytes {
            relay: socket.recv_data_relay.get(),
            direct: socket
                .recv_data_ipv4
                .get()
                .saturating_add(socket.recv_data_ipv6.get()),
            custom: socket.recv_data_custom.get(),
        },
        sent_bytes: SentBytes {
            relay: socket.send_relay.get(),
            direct: socket
                .send_ipv4
                .get()
                .saturating_add(socket.send_ipv6.get()),
        },
        time_to_direct: timings.snapshot(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_time_is_counted_in_the_first_bucket_it_fits_and_added_to_the_sum() {
        let timings = PathTimings::default();
        timings.record(Duration::from_millis(40));
        timings.record(Duration::from_millis(50));
        timings.record(Duration::from_millis(700));
        timings.record(Duration::from_secs(31));
        let seen = timings.snapshot();
        assert_eq!(seen.buckets, [2, 0, 0, 0, 1, 0, 0, 0, 1]);
        assert_eq!(seen.count(), 4);
        assert!(
            (seen.sum_seconds - 31.79).abs() < 1e-9,
            "{}",
            seen.sum_seconds
        );
    }
}
