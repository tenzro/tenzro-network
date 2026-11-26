//! The relayer's transaction nonces: unknown until read from the chain, then
//! counted locally, with every nonce handed out tracked until the chain or
//! the node's answer settles it.
//!
//! The count and its bookkeeping are one value behind one lock. Kept as two
//! (a flag and a counter), a sender could reserve from the counter in the
//! gap between another sender setting the flag and storing the chain's value,
//! and two transactions would go out under nonces the chain was not at.
//!
//! A handed-out nonce ends in one of three ways:
//! - its transaction never reached the node ([`NonceLane::release`]): the
//!   nonce is free again. The top one lowers the count; one below a nonce
//!   still out is a gap, given to the next sender or filled by the signer;
//! - the node may have it ([`NonceLane::unknown`]: a timeout or a broken
//!   connection after the body was sent): it stays held, because a different
//!   transaction under it could replace one already in the pool, and only
//!   the chain's pending nonce settles it ([`NonceLane::resync`]);
//! - the node took it: nothing to record, the count already passed it.
//!
//! [`NonceLane::resync`] takes the chain's pending nonce as a floor: every
//! nonce below it is used, so nothing below it is ever handed out again, and
//! a hand-back that arrives late for a nonce below it is ignored.

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

#[cfg(feature = "loom")]
use loom::sync::Mutex;
#[cfg(not(feature = "loom"))]
use std::sync::Mutex;

/// The count, once known.
#[derive(Debug)]
struct Count {
    /// The next new nonce.
    next: u64,
    /// The chain's highest pending nonce seen: every nonce below it is used.
    floor: u64,
    /// Nonces handed back unused, each below one still out (gaps).
    free: BTreeSet<u64>,
    /// Nonces whose transaction the node may hold, with when that became so.
    unknown: BTreeMap<u64, Instant>,
}

impl Count {
    /// Lowers the count while its top nonce is free, so `free` holds only gaps.
    fn trim(&mut self) {
        while self.next > self.floor && self.free.remove(&(self.next - 1)) {
            self.next -= 1;
        }
    }
}

/// The relayer's nonces, once known.
#[derive(Debug, Default)]
pub(crate) struct NonceLane(Mutex<Option<Count>>);

impl NonceLane {
    fn count(&self) -> impl std::ops::DerefMut<Target = Option<Count>> + '_ {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether the next reservation needs the chain's value.
    pub(crate) fn unsynced(&self) -> bool {
        self.count().is_none()
    }

    /// Whether a nonce waits on the chain to say if it was used.
    pub(crate) fn has_unknown(&self) -> bool {
        self.count().as_ref().is_some_and(|c| !c.unknown.is_empty())
    }

    /// Reserves the lowest gap, else the next new nonce. `chain` is the
    /// chain's pending nonce, read by a caller that found the lane unsynced:
    /// the first such caller installs it and a concurrent one reserves after
    /// it. `None` when the count is unknown and no chain value was given; the
    /// caller reads the chain and asks again.
    pub(crate) fn reserve(&self, chain: Option<u64>) -> Option<u64> {
        let mut count = self.count();
        if count.is_none() {
            let chain = chain?;
            *count = Some(Count {
                next: chain,
                floor: chain,
                free: BTreeSet::new(),
                unknown: BTreeMap::new(),
            });
        }
        let count = count.as_mut().expect("set above");
        if let Some(nonce) = count.free.pop_first() {
            return Some(nonce);
        }
        let nonce = count.next;
        count.next += 1;
        Some(nonce)
    }

    /// Takes the lowest gap for a filler transaction, if there is one.
    pub(crate) fn take_gap(&self) -> Option<u64> {
        self.count().as_mut()?.free.pop_first()
    }

    /// Hands back `nonce`, whose transaction never reached the node. Ignored
    /// for a nonce the chain already passed or the count never reached.
    pub(crate) fn release(&self, nonce: u64) {
        if let Some(count) = self.count().as_mut()
            && count.floor <= nonce
            && nonce < count.next
        {
            count.unknown.remove(&nonce);
            count.free.insert(nonce);
            count.trim();
        }
    }

    /// Records that the node may hold `nonce`'s transaction: it stays out of
    /// every reservation until [`NonceLane::resync`] settles it.
    pub(crate) fn unknown(&self, nonce: u64, now: Instant) {
        if let Some(count) = self.count().as_mut()
            && count.floor <= nonce
            && nonce < count.next
        {
            count.unknown.insert(nonce, now);
        }
    }

    /// Brings the count to the chain's pending nonce `chain`, read at `now`.
    /// Every nonce below it is used and dropped. An unknown nonce equal to
    /// it, recorded at least `settle` before `now` (so no request carrying it
    /// can still be on its way), is free: the pool holds no transaction under
    /// it, since every nonce below it is accounted for. Unknown nonces above
    /// it wait, as a pool may hold them behind a gap.
    pub(crate) fn resync(&self, chain: u64, now: Instant, settle: Duration) {
        let mut count = self.count();
        let Some(count) = count.as_mut() else {
            return;
        };
        count.floor = count.floor.max(chain);
        count.next = count.next.max(count.floor);
        let floor = count.floor;
        count.free.retain(|&n| n >= floor);
        count.unknown.retain(|&n, _| n >= floor);
        if let Some(&at) = count.unknown.get(&floor)
            && now.saturating_duration_since(at) >= settle
        {
            count.unknown.remove(&floor);
            count.free.insert(floor);
        }
        count.trim();
    }
}

#[cfg(all(test, not(feature = "loom")))]
mod tests {
    use super::*;

    const SETTLE: Duration = Duration::from_secs(60);

    #[test]
    fn the_first_reservation_takes_the_chain_value_and_later_ones_count_on() {
        let lane = NonceLane::default();
        assert!(lane.unsynced());
        assert_eq!(lane.reserve(None), None);
        assert_eq!(lane.reserve(Some(41)), Some(41));
        assert!(!lane.unsynced());
        // A second sender that read the chain at the same time reserves after.
        assert_eq!(lane.reserve(Some(41)), Some(42));
        assert_eq!(lane.reserve(None), Some(43));
    }

    /// Sender A's send fails while sender B's is in flight: the next sender
    /// takes A's nonce, never B's, and the count goes on after B's.
    #[test]
    fn a_failed_send_hands_its_nonce_to_the_next_sender_and_never_reissues_one_in_flight() {
        let lane = NonceLane::default();
        let a = lane.reserve(Some(10)).unwrap();
        let b = lane.reserve(None).unwrap();
        assert_eq!((a, b), (10, 11));
        lane.release(a);
        assert_eq!(lane.reserve(None), Some(10));
        assert_eq!(lane.reserve(None), Some(12));
        // A nonce never reserved is not taken back.
        lane.release(40);
        assert_eq!(lane.reserve(None), Some(13));
    }

    #[test]
    fn a_top_nonce_handed_back_lowers_the_count_and_leaves_no_gap() {
        let lane = NonceLane::default();
        assert_eq!(lane.reserve(Some(3)), Some(3));
        assert_eq!(lane.reserve(None), Some(4));
        assert_eq!(lane.reserve(None), Some(5));
        lane.release(4);
        assert_eq!(lane.take_gap(), Some(4));
        lane.release(4);
        lane.release(5);
        // 5 was the top: the count drops to 5, then 4 is the top: to 4.
        assert_eq!(lane.take_gap(), None);
        assert_eq!(lane.reserve(None), Some(4));
    }

    #[test]
    fn a_nonce_the_node_may_hold_is_never_handed_out_until_the_chain_settles_it() {
        let lane = NonceLane::default();
        let t0 = Instant::now();
        assert_eq!(lane.reserve(Some(7)), Some(7));
        assert_eq!(lane.reserve(None), Some(8));
        lane.unknown(7, t0);
        assert!(lane.has_unknown());
        assert_eq!(lane.reserve(None), Some(9));
        // The chain still waits on 7, but a request carrying it may be on
        // its way: it stays held.
        lane.resync(7, t0, SETTLE);
        assert_eq!(lane.take_gap(), None);
        // Once settled, the chain waiting on 7 means the pool has no 7.
        lane.resync(7, t0 + SETTLE, SETTLE);
        assert!(!lane.has_unknown());
        assert_eq!(lane.take_gap(), Some(7));
    }

    #[test]
    fn an_unknown_nonce_the_chain_passed_is_used() {
        let lane = NonceLane::default();
        let t0 = Instant::now();
        assert_eq!(lane.reserve(Some(7)), Some(7));
        lane.unknown(7, t0);
        lane.resync(8, t0, SETTLE);
        assert!(!lane.has_unknown());
        assert_eq!(lane.take_gap(), None);
        assert_eq!(lane.reserve(None), Some(8));
    }

    #[test]
    fn an_unknown_nonce_above_the_chain_waits_as_the_pool_may_hold_it_behind_a_gap() {
        let lane = NonceLane::default();
        let t0 = Instant::now();
        assert_eq!(lane.reserve(Some(7)), Some(7));
        assert_eq!(lane.reserve(None), Some(8));
        lane.release(7);
        lane.unknown(8, t0);
        lane.resync(7, t0 + SETTLE, SETTLE);
        assert_eq!(lane.take_gap(), Some(7));
        assert!(lane.has_unknown());
    }

    #[test]
    fn a_resync_raises_the_count_and_a_late_hand_back_below_it_is_ignored() {
        let lane = NonceLane::default();
        let t0 = Instant::now();
        assert_eq!(lane.reserve(Some(5)), Some(5));
        assert_eq!(lane.reserve(None), Some(6));
        // Another holder of the key used up to 9.
        lane.resync(10, t0, SETTLE);
        lane.release(5);
        assert_eq!(lane.take_gap(), None);
        assert_eq!(lane.reserve(None), Some(10));
        // A resync never lowers the count under a nonce still out.
        lane.resync(4, t0, SETTLE);
        assert_eq!(lane.reserve(None), Some(11));
    }
}

/// Run with `cargo test -p tenzro-bridge --features loom --lib loom_`: every
/// interleaving of the lock is explored. The read of the chain between
/// `unsynced` and `reserve` is a network call in the signer and a constant
/// here; its timing is not modelled beyond the interleavings around it.
#[cfg(all(test, feature = "loom"))]
mod loom_tests {
    use super::*;
    use loom::sync::Arc;

    #[test]
    fn loom_senders_that_sync_together_reserve_consecutive_nonces() {
        loom::model(|| {
            let lane = Arc::new(NonceLane::default());
            let senders: Vec<_> = (0..3)
                .map(|_| {
                    let lane = lane.clone();
                    loom::thread::spawn(move || {
                        let chain = lane.unsynced().then_some(7);
                        lane.reserve(chain).expect("a synced lane reserves")
                    })
                })
                .collect();
            let mut got: Vec<u64> = senders.into_iter().map(|s| s.join().unwrap()).collect();
            got.sort_unstable();
            assert_eq!(got, vec![7, 8, 9]);
        });
    }

    #[test]
    fn loom_a_released_nonce_goes_to_exactly_one_sender() {
        loom::model(|| {
            let lane = Arc::new(NonceLane::default());
            assert_eq!(lane.reserve(Some(7)), Some(7));
            assert_eq!(lane.reserve(None), Some(8));
            let releaser = {
                let lane = lane.clone();
                loom::thread::spawn(move || lane.release(7))
            };
            let senders: Vec<_> = (0..2)
                .map(|_| {
                    let lane = lane.clone();
                    loom::thread::spawn(move || lane.reserve(None).unwrap())
                })
                .collect();
            releaser.join().unwrap();
            let mut got: Vec<u64> = senders.into_iter().map(|s| s.join().unwrap()).collect();
            got.sort_unstable();
            // Two senders and one hand-back: never 8 again, never one nonce twice.
            assert!(got == vec![7, 9] || got == vec![9, 10], "{got:?}");
        });
    }

    /// A send refused while the chain moved on: its hand-back and the resync
    /// to the chain's nonce race. In either order the chain's used nonce is
    /// never handed out again and the in-flight one is never reissued.
    #[test]
    fn loom_a_release_racing_a_resync_never_reissues_a_used_nonce() {
        loom::model(|| {
            let lane = Arc::new(NonceLane::default());
            let t0 = Instant::now();
            assert_eq!(lane.reserve(Some(7)), Some(7));
            assert_eq!(lane.reserve(None), Some(8));
            let releaser = {
                let lane = lane.clone();
                loom::thread::spawn(move || lane.release(7))
            };
            let resyncer = {
                let lane = lane.clone();
                // The chain has seen nonce 7, so it answers 8.
                loom::thread::spawn(move || lane.resync(8, t0, Duration::ZERO))
            };
            releaser.join().unwrap();
            resyncer.join().unwrap();
            assert_eq!(lane.take_gap(), None);
            assert_eq!(lane.reserve(None), Some(9));
        });
    }
}
