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
//! [`PeerStatusTracker::network_tip_capped`] returns the **median** of fresh
//! peer heights, capped at `local_tip + MAX_TIP_LEAD`. The median tolerates a
//! minority of malicious peers reporting bogus heights; the cap is
//! defence-in-depth against an attack on the median itself (collusion of
//! >50% peers within the freshness window).
//!
//! [`PeerStatusTracker::network_tip`] is retained as a diagnostic accessor —
//! it returns the maximum advertised fresh height. RPC handlers MUST use
//! `network_tip_capped` for sync detection.
//!
//! # Concurrency
//!
//! Backed by a `DashMap<PeerId, PeerStatus>` so updates are lock-free and the
//! tracker can be shared via `Arc`.

use dashmap::DashMap;
use libp2p::PeerId;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tenzro_types::tee::TeeVendor;

/// Default freshness window — entries older than this are ignored by `network_tip()`.
pub const DEFAULT_FRESHNESS: Duration = Duration::from_secs(60);

/// Maximum amount by which `network_tip_capped` may exceed the local tip.
/// Defence-in-depth on top of the median filter: even a >50% Sybil
/// majority claiming fake heights cannot push the reported network tip
/// further than this many blocks past the local tip, so an attacker
/// cannot drag a fresh node into multi-day-long fake syncs.
pub const MAX_TIP_LEAD: u64 = 1024;

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
    /// Whether the peer advertises TEE capability — routing hint for
    /// confidential-compute / custodial workloads.
    pub tee_capable: bool,
    /// Peer's TEE vendor, if any. `None` on commodity hardware.
    pub tee_vendor: Option<TeeVendor>,
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

    /// Records the latest status for a peer, including TEE capability.
    ///
    /// Drops the message silently if `chain_id` does not match the local
    /// chain — a status from another chain is meaningless for sync detection.
    pub fn record(
        &self,
        peer_id: PeerId,
        height: u64,
        chain_id: u64,
        tee_capable: bool,
        tee_vendor: Option<TeeVendor>,
    ) {
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
                tee_capable,
                tee_vendor,
            },
        );
    }

    /// Returns all fresh peers that advertise TEE capability.
    ///
    /// If `vendor` is `Some`, only peers reporting that exact vendor are
    /// returned; if `None`, any TEE-capable peer matches. Used by routing
    /// logic that needs to dispatch confidential-compute / custodial
    /// workloads to a TEE-equipped peer.
    pub fn find_tee_peers(&self, vendor: Option<TeeVendor>) -> Vec<(PeerId, PeerStatus)> {
        let now = Instant::now();
        self.statuses
            .iter()
            .filter(|entry| {
                let s = entry.value();
                s.tee_capable
                    && vendor.is_none_or(|v| s.tee_vendor == Some(v))
                    && now
                        .checked_duration_since(s.last_seen)
                        .is_none_or(|d| d <= self.freshness)
            })
            .map(|entry| (*entry.key(), *entry.value()))
            .collect()
    }

    /// Returns the maximum fresh peer height, or `None` if no fresh status
    /// is recorded. **Diagnostic only** — RPC handlers should call
    /// [`Self::network_tip_capped`] instead. A single malicious peer can
    /// inflate the value returned here.
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

    /// Robust network-tip estimator. Returns the **median** of fresh
    /// peer heights, capped at `local_tip + MAX_TIP_LEAD`. Returns
    /// `None` if there are no fresh peers (RPC callers report
    /// `syncing: false` in that case — there is nothing to compare
    /// against).
    ///
    /// Median filtering tolerates a minority of malicious peers
    /// reporting bogus heights. The cap is defence-in-depth against a
    /// collusion attack on the median itself.
    pub fn network_tip_capped(&self, local_tip: u64) -> Option<u64> {
        let now = Instant::now();
        let mut heights: Vec<u64> = self
            .statuses
            .iter()
            .filter(|entry| {
                now.checked_duration_since(entry.last_seen)
                    .map(|d| d <= self.freshness)
                    .unwrap_or(true)
            })
            .map(|entry| entry.height)
            .collect();
        if heights.is_empty() {
            return None;
        }
        heights.sort_unstable();
        let median = heights[heights.len() / 2];
        let cap = local_tip.saturating_add(MAX_TIP_LEAD);
        Some(median.min(cap))
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

        tracker.record(p1, 100, 1337, false, None);
        tracker.record(p2, 250, 1337, false, None);
        tracker.record(p3, 175, 1337, false, None);

        assert_eq!(tracker.network_tip(), Some(250));
        assert_eq!(tracker.fresh_peer_count(), 3);
    }

    #[test]
    fn drops_status_from_other_chain() {
        let tracker = PeerStatusTracker::new(1337);
        let p1 = PeerId::random();

        tracker.record(p1, 9999, 9999, false, None);
        assert_eq!(tracker.network_tip(), None);
    }

    #[test]
    fn updates_overwrite_per_peer() {
        let tracker = PeerStatusTracker::new(1337);
        let p1 = PeerId::random();

        tracker.record(p1, 100, 1337, false, None);
        tracker.record(p1, 200, 1337, false, None);
        tracker.record(p1, 150, 1337, false, None);

        // Latest write wins, even if not the maximum.
        assert_eq!(tracker.network_tip(), Some(150));
        assert_eq!(tracker.fresh_peer_count(), 1);
    }

    #[test]
    fn stale_entries_are_ignored_and_pruned() {
        let tracker = PeerStatusTracker::with_freshness(1337, Duration::from_millis(50));
        let p1 = PeerId::random();
        let p2 = PeerId::random();

        tracker.record(p1, 100, 1337, false, None);
        std::thread::sleep(Duration::from_millis(80));
        tracker.record(p2, 200, 1337, false, None);

        // p1 is now stale; only p2 counts.
        assert_eq!(tracker.network_tip(), Some(200));
        assert_eq!(tracker.fresh_peer_count(), 1);

        tracker.prune_stale();
        // After pruning, p1's entry is gone; p2 still present.
        assert_eq!(tracker.network_tip(), Some(200));
    }

    #[test]
    fn finds_tee_capable_peers() {
        let tracker = PeerStatusTracker::new(1337);
        let p_sev = PeerId::random();
        let p_tdx = PeerId::random();
        let p_none = PeerId::random();

        tracker.record(p_sev, 100, 1337, true, Some(TeeVendor::AmdSevSnp));
        tracker.record(p_tdx, 100, 1337, true, Some(TeeVendor::IntelTdx));
        tracker.record(p_none, 100, 1337, false, None);

        // Any TEE-capable peer.
        let any = tracker.find_tee_peers(None);
        assert_eq!(any.len(), 2);
        assert!(any.iter().all(|(_, s)| s.tee_capable));

        // Vendor-specific filter.
        let sev = tracker.find_tee_peers(Some(TeeVendor::AmdSevSnp));
        assert_eq!(sev.len(), 1);
        assert_eq!(sev[0].0, p_sev);

        // No match for vendor not present.
        let nitro = tracker.find_tee_peers(Some(TeeVendor::AwsNitro));
        assert_eq!(nitro.len(), 0);
    }

    #[test]
    fn stale_tee_peers_excluded_from_find() {
        let tracker = PeerStatusTracker::with_freshness(1337, Duration::from_millis(50));
        let p_sev = PeerId::random();

        tracker.record(p_sev, 100, 1337, true, Some(TeeVendor::AmdSevSnp));
        std::thread::sleep(Duration::from_millis(80));

        assert_eq!(tracker.find_tee_peers(None).len(), 0);
    }

    #[test]
    fn network_tip_capped_returns_median_of_fresh_peers() {
        let tracker = PeerStatusTracker::new(1337);
        for (i, h) in [100u64, 101, 102, 103, 104].iter().enumerate() {
            tracker.record(PeerId::random(), *h, 1337, false, None);
            let _ = i;
        }
        // local_tip below all peer heights, no cap binding
        assert_eq!(tracker.network_tip_capped(50), Some(102));
    }

    #[test]
    fn network_tip_capped_tolerates_one_malicious_high_height() {
        // Three honest peers at 100..102 plus one malicious peer at
        // u64::MAX. The median (101) is unaffected; the maximum-based
        // accessor would return u64::MAX.
        let tracker = PeerStatusTracker::new(1337);
        for h in [100u64, 101, 102] {
            tracker.record(PeerId::random(), h, 1337, false, None);
        }
        tracker.record(PeerId::random(), u64::MAX, 1337, false, None);
        // median of [100, 101, 102, MAX] sorted = element at index 2 = 102.
        // Cap doesn't bind: local_tip + MAX_TIP_LEAD >> 102 when local_tip=50.
        assert_eq!(tracker.network_tip_capped(50), Some(102));
        // The legacy max-based accessor is poisoned by the attacker.
        assert_eq!(tracker.network_tip(), Some(u64::MAX));
    }

    #[test]
    fn network_tip_capped_caps_at_local_tip_plus_lead() {
        // All peers report u64::MAX. Median is u64::MAX, but the
        // local_tip + MAX_TIP_LEAD cap binds: returns local_tip + MAX_TIP_LEAD.
        let tracker = PeerStatusTracker::new(1337);
        for _ in 0..5 {
            tracker.record(PeerId::random(), u64::MAX, 1337, false, None);
        }
        let local_tip = 1000u64;
        assert_eq!(
            tracker.network_tip_capped(local_tip),
            Some(local_tip + MAX_TIP_LEAD)
        );
    }

    #[test]
    fn network_tip_capped_returns_none_when_no_fresh_peers() {
        let tracker = PeerStatusTracker::with_freshness(1337, Duration::from_millis(50));
        tracker.record(PeerId::random(), 1000, 1337, false, None);
        std::thread::sleep(Duration::from_millis(80));
        assert_eq!(tracker.network_tip_capped(0), None);
    }
}
