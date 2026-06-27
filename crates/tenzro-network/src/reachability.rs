//! Sustained connectivity reachability tracking.
//!
//! A node may sit anywhere on the connectivity spectrum — a cloud VM with a
//! static public IP, a home machine behind NAT that hole-punches through to
//! peers, a node that only ever reaches the network through a relay, or one
//! that cannot be reached at all. Whether a node can be relied on to *serve*
//! AI inference, hold data, or rent out compute depends on that reachability
//! being stable, not momentarily true.
//!
//! Peer churn in open P2P networks runs high — roughly half the peer set can
//! turn over within an hour — so a single dial-back success is weak evidence.
//! This tracker turns the stream of transient reachability signals (AutoNAT
//! probe-backs, confirmed/expired external addresses, relay reservations) into
//! a *sustained* verdict using a confidence counter with hysteresis: it takes
//! repeated confirmation to become trusted, and a single failure decrements
//! rather than flipping the verdict. That asymmetry is what stops the tier
//! from flapping while a node's NAT mapping briefly lapses and re-forms.
//!
//! The scheme mirrors the confidence model libp2p's own AutoNAT uses
//! (confidence saturates at 3; a contrary observation decrements toward 0
//! before the status changes), applied here to a coarser three-tier verdict
//! the service roles can gate on.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::RwLock;

/// How many corroborating direct-reachability observations it takes before a
/// node is trusted as durably reachable, and the floor a contrary observation
/// decrements toward before the tier actually drops. Matches libp2p AutoNAT's
/// steady-state confidence ceiling.
pub const CONFIDENCE_THRESHOLD: u8 = 3;

/// The connectivity tier a node currently occupies. Ordered worst-to-best so
/// callers can compare with `>=` (e.g. "at least relay-reachable").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReachabilityTier {
    /// No confirmed path to this node from the outside. Not eligible to
    /// advertise a serving role — work routed here would silently fail.
    Unreachable,
    /// Reachable only through a circuit relay; no direct address has held.
    /// Eligible to serve, but relay paths are latency-added and deliberately
    /// resource-limited, so the request router should prefer direct peers and
    /// treat these as a fallback tier.
    RelayOnly,
    /// A directly dialable external address has been confirmed and has held
    /// across enough observations to be trusted. Full serving tier.
    Direct,
}

impl ReachabilityTier {
    /// Whether a node at this tier may advertise a role that serves traffic
    /// (AI inference, storage, compute, TEE). Unreachable nodes may still
    /// participate as clients; they just cannot take on serve obligations.
    pub fn can_serve(self) -> bool {
        matches!(self, ReachabilityTier::RelayOnly | ReachabilityTier::Direct)
    }

    /// Lowercase wire/CLI token.
    pub fn as_str(self) -> &'static str {
        match self {
            ReachabilityTier::Unreachable => "unreachable",
            ReachabilityTier::RelayOnly => "relay_only",
            ReachabilityTier::Direct => "direct",
        }
    }
}

/// A discrete reachability observation fed in from the swarm event loop.
#[derive(Debug, Clone, Copy)]
pub enum ReachabilityEvent {
    /// A direct external address was confirmed reachable (AutoNAT probe-back
    /// succeeded, or libp2p emitted `ExternalAddrConfirmed`).
    DirectConfirmed,
    /// A previously-confirmed direct external address expired, or an AutoNAT
    /// probe reported the address unreachable. Contrary evidence — decrements
    /// confidence rather than flipping the tier.
    DirectLost,
    /// A circuit-relay reservation was accepted: the node is reachable via a
    /// relay even if no direct path holds.
    RelayReserved,
    /// All relay reservations dropped.
    RelayLost,
    /// A peer on the same local network segment was discovered (mDNS). The
    /// node is directly reachable *to that peer* even if it has no public
    /// path at all. This is orthogonal to the WAN tier: a node behind CGNAT
    /// can be `Unreachable` on the public lane yet serve its LAN.
    LocalDirectConfirmed,
    /// A local-network peer's mDNS record expired — one fewer corroborating
    /// local-direct observation.
    LocalDirectLost,
}

/// Tracks sustained reachability from the stream of swarm reachability events.
///
/// Lock-free: the event loop writes via `record`, any number of readers (role
/// admission, the request router, RPC status) read via `tier`. Shared as an
/// `Arc`, mirroring how the metrics bundle is shared out of the service.
#[derive(Debug)]
pub struct ReachabilityTracker {
    /// Confidence that a direct address is durably reachable. Saturates at
    /// `CONFIDENCE_THRESHOLD`; a `DirectLost` decrements it. The tier reports
    /// `Direct` only once this reaches the threshold.
    direct_confidence: AtomicU8,
    /// Whether at least one relay reservation is currently held. 0 = none.
    relay_reserved: AtomicU8,
    /// Confidence that at least one local-network peer is directly reachable.
    /// Saturates at `CONFIDENCE_THRESHOLD`, decrements on `LocalDirectLost`.
    /// Tracked separately from `direct_confidence` because local reachability
    /// is orthogonal to the WAN tier — it gates serving on the LAN lane, not
    /// the public mesh.
    local_direct_confidence: AtomicU8,
}

impl Default for ReachabilityTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ReachabilityTracker {
    pub fn new() -> Self {
        Self {
            direct_confidence: AtomicU8::new(0),
            relay_reserved: AtomicU8::new(0),
            local_direct_confidence: AtomicU8::new(0),
        }
    }

    /// Folds one observation into the tracker.
    pub fn record(&self, event: ReachabilityEvent) {
        match event {
            ReachabilityEvent::DirectConfirmed => {
                // Saturating increment toward the threshold. Repeated
                // confirmation is what earns trust.
                let _ = self.direct_confidence.fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |c| Some((c + 1).min(CONFIDENCE_THRESHOLD)),
                );
            }
            ReachabilityEvent::DirectLost => {
                // Decrement, don't flip. One lapse shouldn't drop a long-stable
                // node out of the Direct tier; only sustained loss does.
                let _ = self.direct_confidence.fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |c| Some(c.saturating_sub(1)),
                );
            }
            ReachabilityEvent::RelayReserved => {
                self.relay_reserved.store(1, Ordering::SeqCst);
            }
            ReachabilityEvent::RelayLost => {
                self.relay_reserved.store(0, Ordering::SeqCst);
            }
            ReachabilityEvent::LocalDirectConfirmed => {
                let _ = self.local_direct_confidence.fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |c| Some((c + 1).min(CONFIDENCE_THRESHOLD)),
                );
            }
            ReachabilityEvent::LocalDirectLost => {
                let _ = self.local_direct_confidence.fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |c| Some(c.saturating_sub(1)),
                );
            }
        }
    }

    /// Current confidence that a direct address is durably reachable (0..=3).
    pub fn direct_confidence(&self) -> u8 {
        self.direct_confidence.load(Ordering::SeqCst)
    }

    /// Whether at least one local-network peer is currently directly reachable.
    /// Orthogonal to [`tier`](Self::tier): a node behind CGNAT can be
    /// `Unreachable` on the public lane yet still serve peers on its own L2.
    /// A single corroborating observation is enough — local discovery (mDNS)
    /// is itself proof of a working bidirectional path, so the high bar the
    /// WAN tier demands isn't warranted here.
    pub fn has_local_direct(&self) -> bool {
        self.local_direct_confidence.load(Ordering::SeqCst) > 0
    }

    /// Whether this node can serve traffic on *some* lane — either it is
    /// reachable on the public mesh ([`ReachabilityTier::can_serve`]) or it has
    /// a confirmed local-network peer. Role admission uses this so a
    /// LAN-only cluster isn't soft-gated out of serving its own segment.
    pub fn can_serve_anywhere(&self) -> bool {
        self.tier().can_serve() || self.has_local_direct()
    }

    /// The node's current connectivity tier. Direct trust requires confidence
    /// at the threshold; otherwise relay reachability (if any) is the verdict;
    /// otherwise unreachable.
    pub fn tier(&self) -> ReachabilityTier {
        if self.direct_confidence.load(Ordering::SeqCst) >= CONFIDENCE_THRESHOLD {
            ReachabilityTier::Direct
        } else if self.relay_reserved.load(Ordering::SeqCst) > 0 {
            ReachabilityTier::RelayOnly
        } else {
            ReachabilityTier::Unreachable
        }
    }
}

/// The set of peer IDs currently reachable on this node's local network
/// segment, as discovered by mDNS. Distinct from the reachability *tier*
/// (which is about this node's own public reachability): this answers "which
/// other peers share my LAN", so the request router can prefer a same-segment
/// provider — no public internet, no relay budget, lowest latency — over any
/// WAN provider serving the same model.
///
/// mDNS records expire when a peer stops announcing, so membership is
/// add-on-discover / remove-on-expire, mirroring the mDNS event stream.
#[derive(Debug, Default)]
pub struct LocalPeerSet {
    peers: RwLock<HashSet<String>>,
}

impl LocalPeerSet {
    /// A fresh, empty set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that `peer_id` was discovered on the local segment.
    pub fn insert(&self, peer_id: impl Into<String>) {
        self.peers.write().unwrap().insert(peer_id.into());
    }

    /// Drop `peer_id` after its mDNS record expired.
    pub fn remove(&self, peer_id: &str) {
        self.peers.write().unwrap().remove(peer_id);
    }

    /// Whether `peer_id` is currently on the local segment.
    pub fn contains(&self, peer_id: &str) -> bool {
        self.peers.read().unwrap().contains(peer_id)
    }

    /// Number of local-segment peers currently known.
    pub fn len(&self) -> usize {
        self.peers.read().unwrap().len()
    }

    /// Whether no local-segment peers are currently known.
    pub fn is_empty(&self) -> bool {
        self.peers.read().unwrap().is_empty()
    }

    /// A cloned list of the peer IDs currently on the local segment. The order
    /// is unspecified (it is backed by a hash set); callers that need a stable
    /// order sort the result. Lets readers enumerate the set without holding
    /// the internal lock.
    pub fn snapshot(&self) -> Vec<String> {
        self.peers.read().unwrap().iter().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn starts_unreachable() {
        let t = ReachabilityTracker::new();
        assert_eq!(t.tier(), ReachabilityTier::Unreachable);
        assert!(!t.tier().can_serve());
    }

    #[test]
    fn relay_reservation_reaches_relay_only_tier() {
        let t = ReachabilityTracker::new();
        t.record(ReachabilityEvent::RelayReserved);
        assert_eq!(t.tier(), ReachabilityTier::RelayOnly);
        assert!(t.tier().can_serve());
    }

    #[test]
    fn direct_tier_requires_sustained_confirmation() {
        let t = ReachabilityTracker::new();
        // A single confirmation is not enough to be trusted as Direct.
        t.record(ReachabilityEvent::DirectConfirmed);
        assert_ne!(t.tier(), ReachabilityTier::Direct);
        t.record(ReachabilityEvent::DirectConfirmed);
        assert_ne!(t.tier(), ReachabilityTier::Direct);
        // Threshold reached.
        t.record(ReachabilityEvent::DirectConfirmed);
        assert_eq!(t.tier(), ReachabilityTier::Direct);
    }

    #[test]
    fn confidence_saturates_at_threshold() {
        let t = ReachabilityTracker::new();
        for _ in 0..10 {
            t.record(ReachabilityEvent::DirectConfirmed);
        }
        assert_eq!(t.direct_confidence(), CONFIDENCE_THRESHOLD);
    }

    #[test]
    fn single_loss_does_not_flip_a_stable_direct_node() {
        let t = ReachabilityTracker::new();
        for _ in 0..CONFIDENCE_THRESHOLD {
            t.record(ReachabilityEvent::DirectConfirmed);
        }
        assert_eq!(t.tier(), ReachabilityTier::Direct);
        // A single lapse decrements by one, not a reset to zero — so a
        // long-stable node climbs back to Direct with one confirmation.
        t.record(ReachabilityEvent::DirectLost);
        assert_eq!(t.direct_confidence(), CONFIDENCE_THRESHOLD - 1);
    }

    #[test]
    fn sustained_loss_drops_below_direct_then_falls_to_relay_or_unreachable() {
        let t = ReachabilityTracker::new();
        for _ in 0..CONFIDENCE_THRESHOLD {
            t.record(ReachabilityEvent::DirectConfirmed);
        }
        t.record(ReachabilityEvent::RelayReserved);
        assert_eq!(t.tier(), ReachabilityTier::Direct); // direct wins while confident
        for _ in 0..CONFIDENCE_THRESHOLD {
            t.record(ReachabilityEvent::DirectLost);
        }
        // Direct confidence gone, but relay reservation still held.
        assert_eq!(t.tier(), ReachabilityTier::RelayOnly);
        t.record(ReachabilityEvent::RelayLost);
        assert_eq!(t.tier(), ReachabilityTier::Unreachable);
    }

    #[test]
    fn confidence_floors_at_zero() {
        let t = ReachabilityTracker::new();
        t.record(ReachabilityEvent::DirectLost);
        t.record(ReachabilityEvent::DirectLost);
        assert_eq!(t.direct_confidence(), 0);
    }

    #[test]
    fn tier_ordering_supports_at_least_comparisons() {
        assert!(ReachabilityTier::Direct > ReachabilityTier::RelayOnly);
        assert!(ReachabilityTier::RelayOnly > ReachabilityTier::Unreachable);
    }

    #[test]
    fn local_direct_is_orthogonal_to_wan_tier() {
        let t = ReachabilityTracker::new();
        // No public path at all: WAN tier stays Unreachable...
        assert_eq!(t.tier(), ReachabilityTier::Unreachable);
        assert!(!t.tier().can_serve());
        // ...yet a single local-network discovery makes the node serveable on
        // its own segment. One observation is enough for the local lane.
        t.record(ReachabilityEvent::LocalDirectConfirmed);
        assert!(t.has_local_direct());
        assert!(t.can_serve_anywhere());
        // The WAN tier is untouched by local observations.
        assert_eq!(t.tier(), ReachabilityTier::Unreachable);
    }

    #[test]
    fn local_direct_clears_only_after_sustained_loss() {
        let t = ReachabilityTracker::new();
        for _ in 0..CONFIDENCE_THRESHOLD {
            t.record(ReachabilityEvent::LocalDirectConfirmed);
        }
        assert!(t.has_local_direct());
        // A single expiry shouldn't drop a stable local peer.
        t.record(ReachabilityEvent::LocalDirectLost);
        assert!(t.has_local_direct());
        for _ in 0..CONFIDENCE_THRESHOLD {
            t.record(ReachabilityEvent::LocalDirectLost);
        }
        assert!(!t.has_local_direct());
        assert!(!t.can_serve_anywhere());
    }

    #[test]
    fn local_peer_set_tracks_membership() {
        let set = LocalPeerSet::new();
        assert!(set.is_empty());
        set.insert("peer-a");
        set.insert("peer-b");
        assert!(set.contains("peer-a"));
        assert!(set.contains("peer-b"));
        assert!(!set.contains("peer-c"));
        assert_eq!(set.len(), 2);
        // Expiry drops only the named peer.
        set.remove("peer-a");
        assert!(!set.contains("peer-a"));
        assert!(set.contains("peer-b"));
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn local_peer_set_insert_is_idempotent() {
        let set = LocalPeerSet::new();
        set.insert("peer-a");
        set.insert("peer-a");
        assert_eq!(set.len(), 1);
    }

    #[test]
    fn local_peer_set_snapshot_enumerates_members() {
        let set = LocalPeerSet::new();
        assert!(set.snapshot().is_empty());
        set.insert("peer-a");
        set.insert("peer-b");
        let mut snap = set.snapshot();
        snap.sort();
        assert_eq!(snap, vec!["peer-a".to_string(), "peer-b".to_string()]);
        // The snapshot is a clone: dropping a peer afterwards does not mutate it.
        set.remove("peer-a");
        assert_eq!(snap.len(), 2);
        assert_eq!(set.snapshot(), vec!["peer-b".to_string()]);
    }
}
