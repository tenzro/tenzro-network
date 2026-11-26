//! Blob uploads yield to the traffic that shares their path.
//!
//! Consensus, gossip and real-time streams run on their own connections, but
//! they share the path, and its bottleneck queue, with the blobs this node
//! serves. A blob upload fills that queue, and everything behind it waits.
//! Following LEDBAT (RFC 6817), the provider paces its uploads to each peer
//! by the queueing delay it sees on the path to that peer: the round-trip
//! time now, less the lowest of the last minute ([`PathLatency`]). While the
//! queueing delay stays above [`TARGET`], the upload rate to the peer is
//! halved every [`ADJUST_EVERY`], down to a floor that keeps every transfer
//! moving. While it stays below half the target, the rate grows by a quarter,
//! and once the rate is no longer what holds the upload back, the limit is
//! lifted. A peer whose path shows queueing before its first chunk starts at
//! the floor.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use iroh::EndpointId;
use parking_lot::Mutex;

use crate::paths::PathLatency;

/// Queueing delay the uploads may add to their path (RFC 6817's target).
pub const TARGET: Duration = Duration::from_millis(25);

/// How often the rate to a peer is reconsidered.
pub const ADJUST_EVERY: Duration = Duration::from_secs(1);

/// The lowest rate, in bytes per second, an upload to one peer is held to.
pub const FLOOR_BYTES_PER_SEC: f64 = 256.0 * 1024.0;

/// A peer whose uploads ended this long ago is forgotten.
const IDLE: Duration = Duration::from_secs(60);

#[derive(Debug)]
struct Peer {
    /// The upload rate in bytes per second, or `None` while unlimited.
    rate: Option<f64>,
    /// When the next chunk may go, while limited.
    next_at: Instant,
    /// Bytes sent since `since`.
    sent: u64,
    since: Instant,
}

/// Paces blob uploads per peer by the queueing delay on the path to it.
#[derive(Debug)]
pub struct BulkPacer {
    latency: PathLatency,
    floor: f64,
    peers: Mutex<HashMap<EndpointId, Peer>>,
}

impl BulkPacer {
    /// A pacer that reads the queueing delay from `latency`.
    pub fn new(latency: PathLatency) -> Self {
        Self::with_floor(latency, FLOOR_BYTES_PER_SEC)
    }

    fn with_floor(latency: PathLatency, floor: f64) -> Self {
        Self {
            latency,
            floor,
            peers: Mutex::new(HashMap::new()),
        }
    }

    /// Holds a chunk of `size` bytes to `peer` until the peer's rate lets it
    /// go.
    pub async fn pace(&self, peer: EndpointId, size: u64) {
        let hold = self.hold(peer, size, Instant::now());
        if !hold.is_zero() {
            tokio::time::sleep(hold).await;
        }
    }

    /// How long a chunk of `size` bytes to `peer` waits, counting it as sent
    /// at the end of the wait.
    fn hold(&self, peer: EndpointId, size: u64, now: Instant) -> Duration {
        let queueing = self.latency.queueing_delay(&peer);
        let mut peers = self.peers.lock();
        peers.retain(|_, p| now.saturating_duration_since(p.next_at.max(p.since)) < IDLE);
        let floor = self.floor;
        let p = peers.entry(peer).or_insert_with(|| Peer {
            rate: queueing.is_some_and(|q| q > TARGET).then_some(floor),
            next_at: now,
            sent: 0,
            since: now,
        });
        p.sent += size;
        let elapsed = now.saturating_duration_since(p.since);
        if elapsed >= ADJUST_EVERY {
            let sent = p.sent as f64 / elapsed.as_secs_f64();
            p.rate = next_rate(p.rate, sent, queueing, floor);
            p.sent = 0;
            p.since = now;
        }
        match p.rate {
            None => Duration::ZERO,
            Some(rate) => {
                let start = p.next_at.max(now);
                p.next_at = start + Duration::from_secs_f64(size as f64 / rate);
                start - now
            }
        }
    }
}

/// The rate after one [`ADJUST_EVERY`], given the rate before, the rate
/// actually sent and the queueing delay on the path.
fn next_rate(rate: Option<f64>, sent: f64, queueing: Option<Duration>, floor: f64) -> Option<f64> {
    match queueing {
        Some(q) if q > TARGET => Some((rate.unwrap_or(f64::MAX).min(sent) / 2.0).max(floor)),
        Some(q) if q > TARGET / 2 => rate,
        _ => {
            let up = rate? * 1.25;
            // A limit well above what is sent no longer holds anything back.
            (up < 2.0 * sent).then_some(up)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::TransportAddr;

    const KIB: f64 = 1024.0;

    fn peer() -> EndpointId {
        iroh::SecretKey::from_bytes(&[9; 32]).public()
    }

    fn latency_with(queueing: Duration) -> PathLatency {
        let latency = PathLatency::default();
        let addr = TransportAddr::Ip("192.0.2.1:1".parse().unwrap());
        let t = Instant::now();
        latency.record_sample(peer(), addr.clone(), Duration::from_millis(10), t);
        latency.record_sample(peer(), addr, Duration::from_millis(10) + queueing, t);
        latency
    }

    #[test]
    fn queueing_above_the_target_halves_the_rate_down_to_the_floor() {
        let q = Some(Duration::from_millis(80));
        assert_eq!(
            next_rate(None, 4000.0 * KIB, q, 256.0 * KIB),
            Some(2000.0 * KIB)
        );
        assert_eq!(
            next_rate(Some(1000.0 * KIB), 900.0 * KIB, q, 256.0 * KIB),
            Some(450.0 * KIB)
        );
        assert_eq!(
            next_rate(Some(300.0 * KIB), 300.0 * KIB, q, 256.0 * KIB),
            Some(256.0 * KIB)
        );
    }

    #[test]
    fn a_short_queue_holds_the_rate_and_no_queue_lifts_it_once_it_no_longer_binds() {
        let floor = 256.0 * KIB;
        let held = Some(Duration::from_millis(20));
        assert_eq!(
            next_rate(Some(500.0 * KIB), 500.0 * KIB, held, floor),
            Some(500.0 * KIB)
        );
        let clear = Some(Duration::from_millis(2));
        assert_eq!(
            next_rate(Some(400.0 * KIB), 400.0 * KIB, clear, floor),
            Some(500.0 * KIB)
        );
        assert_eq!(
            next_rate(Some(400.0 * KIB), 100.0 * KIB, clear, floor),
            None
        );
        assert_eq!(next_rate(None, 400.0 * KIB, None, floor), None);
    }

    #[test]
    fn a_limited_peer_gets_chunks_spaced_by_its_rate() {
        let pacer = BulkPacer::with_floor(latency_with(Duration::from_millis(100)), 64.0 * KIB);
        let now = Instant::now();
        assert_eq!(pacer.hold(peer(), 16 * 1024, now), Duration::ZERO);
        assert_eq!(
            pacer.hold(peer(), 16 * 1024, now),
            Duration::from_millis(250)
        );
        assert_eq!(
            pacer.hold(peer(), 16 * 1024, now),
            Duration::from_millis(500)
        );
    }

    #[test]
    fn a_path_with_no_queue_is_not_paced() {
        let pacer = BulkPacer::with_floor(latency_with(Duration::ZERO), 64.0 * KIB);
        let now = Instant::now();
        for _ in 0..8 {
            assert_eq!(pacer.hold(peer(), 16 * 1024, now), Duration::ZERO);
        }
    }
}
