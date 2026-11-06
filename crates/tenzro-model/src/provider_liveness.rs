//! Fast provider failure detection.
//!
//! Providers gossip a signed heartbeat every [`HEARTBEAT_INTERVAL`]. A
//! provider whose heartbeats stop for [`MISSED_BEATS`] intervals is down, and
//! so is one whose latest heartbeat carries its own forecaster's anomaly
//! evidence (its latency or queue above the forecast band). The router skips
//! down providers when it selects, hedges and fails over; the next clean
//! heartbeat restores the provider at once. A provider never heard from is
//! not judged here: the circuit breakers cover it.
//!
//! Between a provider going silent and the window closing, hedged dispatch
//! covers the gap: a request whose primary does not answer within the hedge
//! delay is raced against another provider.

use std::time::{Duration, Instant};

use dashmap::DashMap;
use tenzro_types::primitives::Address;

/// How often a serving node gossips its heartbeat.
pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(2);

/// Heartbeat intervals without a beat after which a provider is down.
pub const MISSED_BEATS: u32 = 3;

#[derive(Debug, Clone, Copy)]
struct Beat {
    /// When this node received it.
    at: Instant,
    /// The provider's own send time, for ordering.
    sent_ms: i64,
    degraded: bool,
}

/// Liveness of the providers this node has heard heartbeats from.
#[derive(Debug)]
pub struct ProviderLiveness {
    window: Duration,
    beats: DashMap<Address, Beat>,
}

impl Default for ProviderLiveness {
    fn default() -> Self {
        Self::new(HEARTBEAT_INTERVAL * MISSED_BEATS)
    }
}

impl ProviderLiveness {
    /// Liveness with a detection `window`: silence longer than it is down.
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            beats: DashMap::new(),
        }
    }

    /// The detection window.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Records a verified heartbeat `provider` sent at `sent_ms`, carrying
    /// anomaly evidence when `degraded`. A heartbeat no newer than the last
    /// one recorded is ignored, so a replay cannot undo a newer state.
    pub fn heartbeat(&self, provider: Address, sent_ms: i64, degraded: bool) {
        self.heartbeat_at(provider, sent_ms, degraded, Instant::now());
    }

    pub(crate) fn heartbeat_at(
        &self,
        provider: Address,
        sent_ms: i64,
        degraded: bool,
        at: Instant,
    ) {
        let mut entry = self.beats.entry(provider).or_insert(Beat {
            at,
            sent_ms,
            degraded,
        });
        if sent_ms > entry.sent_ms {
            *entry = Beat {
                at,
                sent_ms,
                degraded,
            };
        }
    }

    /// Whether `provider` is down: silent past the window, or its latest
    /// heartbeat carried anomaly evidence.
    pub fn is_down(&self, provider: &Address) -> bool {
        self.is_down_at(provider, Instant::now())
    }

    fn is_down_at(&self, provider: &Address, now: Instant) -> bool {
        self.beats
            .get(provider)
            .is_some_and(|b| b.degraded || now.saturating_duration_since(b.at) > self.window)
    }

    /// Forgets `provider`, once it is no longer routable at all.
    pub fn forget(&self, provider: &Address) {
        self.beats.remove(provider);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn silence_past_the_window_is_down_and_a_beat_restores() {
        let l = ProviderLiveness::new(Duration::from_secs(6));
        let p = Address::new([1; 32]);
        let t0 = Instant::now();
        assert!(!l.is_down_at(&p, t0), "never heard from: not judged");
        l.heartbeat_at(p, 1, false, t0);
        assert!(!l.is_down_at(&p, t0 + Duration::from_secs(6)));
        assert!(l.is_down_at(&p, t0 + Duration::from_millis(6_001)));
        l.heartbeat_at(p, 2, false, t0 + Duration::from_secs(7));
        assert!(!l.is_down_at(&p, t0 + Duration::from_secs(7)));
    }

    #[test]
    fn anomaly_evidence_is_down_until_a_newer_clean_beat() {
        let l = ProviderLiveness::new(Duration::from_secs(6));
        let p = Address::new([2; 32]);
        let t0 = Instant::now();
        l.heartbeat_at(p, 10, true, t0);
        assert!(l.is_down_at(&p, t0));
        l.heartbeat_at(p, 9, false, t0 + Duration::from_secs(1));
        assert!(
            l.is_down_at(&p, t0 + Duration::from_secs(1)),
            "an older beat replayed changes nothing"
        );
        l.heartbeat_at(p, 11, false, t0 + Duration::from_secs(2));
        assert!(!l.is_down_at(&p, t0 + Duration::from_secs(2)));
    }
}
