//! Peer status / chain-tip tracker.
//!
//! Records the latest height each peer has advertised via `StatusMessage` on
//! `tenzro/status`. Used by `eth_syncing` / `tenzro_syncing` to report a
//! real network-tip estimate so external clients (block explorers, MetaMask,
//! lagging validators) can tell whether the local node is caught up.
//!
//! # Freshness policy
//!
//! Entries older than `freshness` (default 60s) are treated as stale and
//! ignored by `network_tip()`. `prune_stale()` may be called periodically to
//! keep the map bounded; without it the map stays bounded by the peer count
//! anyway since every entry is keyed on `PeerId`.
//!
//! # Trust model
//!
//! `network_tip()` returns the **maximum** of fresh peer heights. A malicious
//! peer can therefore inflate the reported tip and make `eth_syncing` falsely
//! report `syncing: true`. This is acceptable for testnet; mainnet should use
//! median or cap by `local_tip + window`. Documented in TODO at the call site.
//!
//! # Concurrency
//!
//! Backed by a `DashMap<PeerId, PeerStatus>` so updates are lock-free and the
//! tracker can be shared via `Arc`.

use dashmap::DashMap;
use libp2p::PeerId;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Default freshness window — entries older than this are ignored by `network_tip()`.
pub const DEFAULT_FRESHNESS: Duration = Duration::from_secs(60);

/// Latest known status for a single peer.
#[derive(Debug, Clone, Copy)]
pub struct PeerStatus {
    /// Peer's reported chain-tip height.
    pub height: u64,
    /// Peer's reported chain id (sanity check — entries from a different
    /// chain are never recorded).
    pub chain_id: u64,
    /// When the status was last received.
    pub last_seen: Instant,
}

/// Tracks the latest `StatusMessage` height per peer.
///
/// Construct via [`PeerStatusTracker::new`] (default 60s freshness) or
/// [`PeerStatusTracker::with_freshness`] for tests / custom windows.
pub struct PeerStatusTracker {
    statuses: DashMap<PeerId, PeerStatus>,
    freshness: Duration,
    /// Local chain id — incoming status messages from a different chain are
    /// dropped silently.
    chain_id: u64,
}

impl PeerStatusTracker {
    /// Creates a new tracker with the default 60s freshness window.
    pub fn new(chain_id: u64) -> Arc<Self> {
        Arc::new(Self {
            statuses: DashMap::new(),
            freshness: DEFAULT_FRESHNESS,
            chain_id,
        })
    }

    /// Creates a new tracker with a custom freshness window — for tests.
    pub fn with_freshness(chain_id: u64, freshness: Duration) -> Arc<Self> {
        Arc::new(Self {
            statuses: DashMap::new(),
            freshness,
            chain_id,
        })
    }

    /// Records the latest status for a peer.
    ///
    /// Drops the message silently if `chain_id` does not match the local
    /// chain — a status from another chain is meaningless for sync detection.
    pub fn record(&self, peer_id: PeerId, height: u64, chain_id: u64) {
        if chain_id != self.chain_id {
            tracing::debug!(
                peer = %peer_id,
                got = chain_id,
                expected = self.chain_id,
                "Dropping StatusMessage from peer on different chain"
            );
            return;
        }
        self.statuses.insert(
            peer_id,
            PeerStatus {
                height,
                chain_id,
                last_seen: Instant::now(),
            },
        );
    }

    /// Returns the maximum fresh peer height, or `None` if no fresh status
    /// is recorded.
    ///
    /// "Fresh" = `last_seen` within `freshness` of `Instant::now()`. Stale
    /// entries are ignored but not removed (call `prune_stale()` to free
    /// memory). The cost of the freshness check is O(peers); for testnet with
    /// a few dozen peers this is irrelevant.
    pub fn network_tip(&self) -> Option<u64> {
        let now = Instant::now();
        self.statuses
            .iter()
            .filter(|entry| {
                now.checked_duration_since(entry.last_seen)
                    .map(|d| d <= self.freshness)
                    .unwrap_or(true)
            })
            .map(|entry| entry.height)
            .max()
    }

    /// Returns the number of fresh entries — for diagnostics / metrics.
    pub fn fresh_peer_count(&self) -> usize {
        let now = Instant::now();
        self.statuses
            .iter()
            .filter(|entry| {
                now.checked_duration_since(entry.last_seen)
                    .map(|d| d <= self.freshness)
                    .unwrap_or(true)
            })
            .count()
    }

    /// Removes entries older than `freshness`. Safe to call from a periodic
    /// background task (or skip — the map stays bounded by the peer count).
    pub fn prune_stale(&self) {
        let now = Instant::now();
        let stale: Vec<PeerId> = self
            .statuses
            .iter()
            .filter(|entry| {
                now.checked_duration_since(entry.last_seen)
                    .map(|d| d > self.freshness)
                    .unwrap_or(false)
            })
            .map(|entry| *entry.key())
            .collect();
        for peer_id in stale {
            self.statuses.remove(&peer_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_tracker_has_no_tip() {
        let tracker = PeerStatusTracker::new(1337);
        assert_eq!(tracker.network_tip(), None);
        assert_eq!(tracker.fresh_peer_count(), 0);
    }

    #[test]
    fn records_and_returns_max_height() {
        let tracker = PeerStatusTracker::new(1337);
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        let p3 = PeerId::random();

        tracker.record(p1, 100, 1337);
        tracker.record(p2, 250, 1337);
        tracker.record(p3, 175, 1337);

        assert_eq!(tracker.network_tip(), Some(250));
        assert_eq!(tracker.fresh_peer_count(), 3);
    }

    #[test]
    fn drops_status_from_other_chain() {
        let tracker = PeerStatusTracker::new(1337);
        let p1 = PeerId::random();

        tracker.record(p1, 9999, 9999);
        assert_eq!(tracker.network_tip(), None);
    }

    #[test]
    fn updates_overwrite_per_peer() {
        let tracker = PeerStatusTracker::new(1337);
        let p1 = PeerId::random();

        tracker.record(p1, 100, 1337);
        tracker.record(p1, 200, 1337);
        tracker.record(p1, 150, 1337);

        // Latest write wins, even if not the maximum.
        assert_eq!(tracker.network_tip(), Some(150));
        assert_eq!(tracker.fresh_peer_count(), 1);
    }

    #[test]
    fn stale_entries_are_ignored_and_pruned() {
        let tracker = PeerStatusTracker::with_freshness(1337, Duration::from_millis(50));
        let p1 = PeerId::random();
        let p2 = PeerId::random();

        tracker.record(p1, 100, 1337);
        std::thread::sleep(Duration::from_millis(80));
        tracker.record(p2, 200, 1337);

        // p1 is now stale; only p2 counts.
        assert_eq!(tracker.network_tip(), Some(200));
        assert_eq!(tracker.fresh_peer_count(), 1);

        tracker.prune_stale();
        // After pruning, p1's entry is gone; p2 still present.
        assert_eq!(tracker.network_tip(), Some(200));
    }
}
