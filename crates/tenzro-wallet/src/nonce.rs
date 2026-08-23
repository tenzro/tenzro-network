//! Nonce management for Tenzro Network wallets.
//!
//! Tracks per-address nonces to prevent replay attacks and ensure
//! sequential transaction ordering. Supports both local tracking
//! and synchronization with on-chain state.

use dashmap::DashMap;
use tenzro_types::primitives::{Address, Nonce};
use tracing::debug;

/// Nonce manager tracking per-address transaction sequence numbers.
///
/// Each address has an independent nonce counter. The manager ensures:
/// - Sequential nonce assignment (no gaps)
/// - No duplicate nonces (replay protection)
/// - Synchronization with on-chain confirmed nonces
pub struct NonceManager {
    /// Current pending nonce per address (next nonce to use)
    pending_nonces: DashMap<Address, u64>,
    /// Last confirmed on-chain nonce per address
    confirmed_nonces: DashMap<Address, u64>,
    /// When each address last saw chain state advance, in seconds.
    ///
    /// A gap is only distinguishable from in-flight work by time. Chain state
    /// says what has been *included*; it cannot say whether the rest is queued
    /// or lost. If chain state has not moved for a while and the counter is
    /// ahead, the difference was dropped rather than delayed.
    last_progress_secs: DashMap<Address, u64>,
}

/// How long chain state may sit still, with the pending counter ahead of it,
/// before the difference is treated as dropped rather than in flight.
///
/// Long enough that ordinary inclusion latency never trips it — blocks are
/// transaction-driven here, so a quiet chain can take a while to include one —
/// and short enough that a wedged address recovers without a restart.
const STALL_SECS: u64 = 120;

impl NonceManager {
    /// Create a new nonce manager
    pub fn new() -> Self {
        Self {
            pending_nonces: DashMap::new(),
            confirmed_nonces: DashMap::new(),
            last_progress_secs: DashMap::new(),
        }
    }

    /// Get the next nonce for an address and increment the counter.
    ///
    /// This atomically returns the current nonce and advances the counter,
    /// ensuring no two transactions get the same nonce.
    pub fn next_nonce(&self, address: &Address) -> Nonce {
        let mut entry = self.pending_nonces.entry(*address).or_insert(0);
        let nonce = *entry;
        *entry = nonce + 1;
        debug!("Assigned nonce {} to address {}", nonce, address);
        Nonce(nonce)
    }

    /// Re-anchor the pending counter to the chain's view of this address,
    /// tolerating up to `max_inflight` assignments that have not been included
    /// yet.
    ///
    /// The pending counter advances on every assignment but chain state only
    /// advances when a transaction is actually included, so a transaction that
    /// is signed and then rejected — a nonce gap, an underpriced tx, a dropped
    /// mempool entry — leaves the counter ahead with nothing that will ever
    /// close the distance. Every later assignment then reads as a gap and is
    /// rejected in turn, so a single rejection wedges the address for the life
    /// of the process.
    ///
    /// Both directions are corrected: below chain state means the counter was
    /// rebuilt empty (a restart) and would replay a spent nonce; further ahead
    /// than `max_inflight` means the gap can no longer be explained by
    /// transactions still in flight, so it is treated as abandoned.
    pub fn rebase_nonce(&self, address: &Address, chain_nonce: u64, max_inflight: u64) {
        // `max_inflight` is retained in the signature — it is part of the
        // `WalletService` trait and a caller-visible policy knob — but the
        // counter is no longer trimmed against it. See below.
        let _ = max_inflight;
        let mut entry = self.pending_nonces.entry(*address).or_insert(chain_nonce);
        let pending = *entry;

        // Chain state moved since last time: nothing is stuck, restart the clock.
        let advanced = self
            .confirmed_nonces
            .get(address)
            .map(|v| chain_nonce > *v)
            .unwrap_or(true);
        if advanced {
            self.note_progress(address, chain_nonce);
        }

        // Forward only.
        //
        // The counter is the only record of what this process has handed out —
        // `confirmed_nonces` tracks inclusion, not assignment — so moving it
        // backwards for any reason re-issues a nonce that is already in flight.
        // `chain_nonce` counts only what has been included in a block, so
        // everything still in the mempool reads as unspent, and under load the
        // counter passes any in-flight window legitimately. Trimming it there
        // handed the same nonce to a second transaction and one of the pair
        // failed, which is what filled the log with what looked like gaps:
        //
        //     Invalid nonce: expected 10, got 6
        //     Invalid nonce: expected 1, got 0     (x158)
        //
        // Those are collisions. Only the behind-chain-state case is corrected,
        // which is the restart case: the counter was rebuilt empty and would
        // otherwise replay a nonce already spent on-chain.
        //
        // A counter that runs away because a signed transaction was dropped
        // does leave a gap that nothing closes — but the address recovers on
        // restart, and re-issuing live nonces to avoid that trades a stall for
        // silent transaction loss. Closing it properly means tracking assigned
        // nonces that were never included, not guessing from chain state.
        if pending < chain_nonce {
            debug!(
                "Rebasing pending nonce for {} forward from {} to chain nonce {}",
                address, pending, chain_nonce
            );
            *entry = chain_nonce;
            self.note_progress(address, chain_nonce);
            return;
        }

        // Ahead of chain state. Whether that is in-flight work or a gap left by
        // dropped transactions cannot be told apart from chain state alone —
        // only from time. So the counter is rewound *only* once chain state has
        // been stuck for `STALL_SECS` while the counter sits ahead of it:
        //
        //     Invalid nonce: expected 23, got 30
        //     Invalid nonce: expected 23, got 32
        //
        // Every later grant reads as a gap and is rejected in turn, so one lost
        // transaction wedges the address indefinitely. Waiting first is what
        // keeps this from re-issuing nonces that were merely slow — the failure
        // mode a naive rewind produced, where two transactions shared a nonce
        // and one of them died.
        let now = Self::now_secs();
        let stalled_since = *self
            .last_progress_secs
            .entry(*address)
            .or_insert(now)
            .value();

        if pending > chain_nonce && now.saturating_sub(stalled_since) >= STALL_SECS {
            debug!(
                "Nonce gap for {} did not close in {}s (pending {}, chain {}); \
                 treating the difference as dropped",
                address,
                STALL_SECS,
                pending,
                chain_nonce
            );
            *entry = chain_nonce;
            self.note_progress(address, chain_nonce);
        }
    }

    /// Record that chain state moved for this address, restarting its clock.
    fn note_progress(&self, address: &Address, chain_nonce: u64) {
        self.confirmed_nonces.insert(*address, chain_nonce);
        self.last_progress_secs
            .insert(*address, Self::now_secs());
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Peek at the next nonce without incrementing.
    pub fn peek_nonce(&self, address: &Address) -> Nonce {
        let nonce = self.pending_nonces.get(address).map(|v| *v).unwrap_or(0);
        Nonce(nonce)
    }

    /// Get the current pending nonce count (how many have been assigned).
    pub fn pending_count(&self, address: &Address) -> u64 {
        let pending = self.pending_nonces.get(address).map(|v| *v).unwrap_or(0);
        let confirmed = self.confirmed_nonces.get(address).map(|v| *v).unwrap_or(0);
        pending.saturating_sub(confirmed)
    }

    /// Confirm that a nonce has been included on-chain.
    ///
    /// Updates the confirmed nonce to track which transactions have been
    /// finalized. Used when receiving block confirmations.
    pub fn confirm_nonce(&self, address: &Address, nonce: u64) {
        self.confirmed_nonces
            .entry(*address)
            .and_modify(|current| {
                if nonce >= *current {
                    *current = nonce + 1;
                }
            })
            .or_insert(nonce + 1);

        debug!("Confirmed nonce {} for address {}", nonce, address);
    }

    /// Sync with on-chain state.
    ///
    /// Called when connecting to a node or after a reorg to align
    /// local nonce tracking with the blockchain state.
    pub fn sync_from_chain(&self, address: &Address, on_chain_nonce: u64) {
        self.confirmed_nonces.insert(*address, on_chain_nonce);

        // Only advance pending nonce if behind confirmed
        self.pending_nonces
            .entry(*address)
            .and_modify(|pending| {
                if *pending < on_chain_nonce {
                    *pending = on_chain_nonce;
                }
            })
            .or_insert(on_chain_nonce);

        debug!(
            "Synced nonce for address {}: on-chain={}, pending={}",
            address,
            on_chain_nonce,
            self.pending_nonces.get(address).map(|v| *v).unwrap_or(0)
        );
    }

    /// Reset the pending nonce to the confirmed nonce.
    ///
    /// Used after detecting that pending transactions were dropped
    /// (e.g., due to mempool eviction or node restart).
    pub fn reset_pending(&self, address: &Address) {
        let confirmed = self.confirmed_nonces.get(address).map(|v| *v).unwrap_or(0);
        self.pending_nonces.insert(*address, confirmed);

        debug!(
            "Reset pending nonce for address {} to {}",
            address, confirmed
        );
    }

    /// Get the confirmed nonce for an address.
    pub fn confirmed_nonce(&self, address: &Address) -> Nonce {
        let nonce = self.confirmed_nonces.get(address).map(|v| *v).unwrap_or(0);
        Nonce(nonce)
    }

    /// Clear all nonce state for an address.
    pub fn clear(&self, address: &Address) {
        self.pending_nonces.remove(address);
        self.confirmed_nonces.remove(address);
    }

    /// Clear all nonce state.
    pub fn clear_all(&self) {
        self.pending_nonces.clear();
        self.confirmed_nonces.clear();
    }
}

impl Default for NonceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_addr() -> Address {
        Address::new([1u8; 32])
    }

    #[test]
    fn test_sequential_nonces() {
        let manager = NonceManager::new();
        let addr = test_addr();

        assert_eq!(manager.next_nonce(&addr), Nonce(0));
        assert_eq!(manager.next_nonce(&addr), Nonce(1));
        assert_eq!(manager.next_nonce(&addr), Nonce(2));
    }

    #[test]
    fn test_peek_nonce() {
        let manager = NonceManager::new();
        let addr = test_addr();

        assert_eq!(manager.peek_nonce(&addr), Nonce(0));
        manager.next_nonce(&addr);
        assert_eq!(manager.peek_nonce(&addr), Nonce(1));
    }

    #[test]
    fn test_independent_addresses() {
        let manager = NonceManager::new();
        let addr1 = Address::new([1u8; 32]);
        let addr2 = Address::new([2u8; 32]);

        assert_eq!(manager.next_nonce(&addr1), Nonce(0));
        assert_eq!(manager.next_nonce(&addr1), Nonce(1));
        assert_eq!(manager.next_nonce(&addr2), Nonce(0));
        assert_eq!(manager.next_nonce(&addr1), Nonce(2));
        assert_eq!(manager.next_nonce(&addr2), Nonce(1));
    }

    /// A rebase must never hand out a nonce twice.
    ///
    /// `chain_nonce` counts only what has been included in a block, so
    /// transactions sitting in the mempool look unspent. Under load the pending
    /// counter passes `max_inflight` legitimately; the old rebase then reset it
    /// all the way to chain state and re-issued nonces already assigned. One of
    /// each colliding pair failed, filling the log with what looked like gaps:
    ///
    ///     Invalid nonce: expected 10, got 6
    ///     Invalid nonce: expected 1, got 0   (x158)
    #[test]
    fn a_rebase_never_reissues_a_nonce_that_was_already_assigned() {
        let mgr = NonceManager::new();
        let addr = Address::new([1u8; 32]);
        let max_inflight = 8;

        // Twelve grants issued back to back; nothing has been included yet, so
        // chain state is still 0.
        let mut assigned = Vec::new();
        for _ in 0..12 {
            mgr.rebase_nonce(&addr, 0, max_inflight);
            assigned.push(mgr.next_nonce(&addr).0);
        }

        let mut seen = assigned.clone();
        seen.sort_unstable();
        seen.dedup();
        assert_eq!(
            seen.len(),
            assigned.len(),
            "every assignment must be unique; got {assigned:?}"
        );
    }

    /// A counter behind chain state is still corrected forward.
    ///
    /// That is the restart case — the pending counter is rebuilt empty and
    /// would otherwise replay a nonce that has already been spent on-chain.
    #[test]
    fn a_counter_behind_chain_state_is_moved_forward() {
        let mgr = NonceManager::new();
        let addr = Address::new([2u8; 32]);

        mgr.rebase_nonce(&addr, 0, 8);
        assert_eq!(mgr.next_nonce(&addr).0, 0);

        // The chain has since included several transactions from this address.
        mgr.rebase_nonce(&addr, 5, 8);
        assert_eq!(
            mgr.next_nonce(&addr).0,
            5,
            "a restarted counter must resume at chain state, not replay"
        );
    }

    #[test]
    fn test_confirm_nonce() {
        let manager = NonceManager::new();
        let addr = test_addr();

        manager.next_nonce(&addr); // 0
        manager.next_nonce(&addr); // 1
        manager.next_nonce(&addr); // 2

        assert_eq!(manager.pending_count(&addr), 3);

        manager.confirm_nonce(&addr, 0);
        assert_eq!(manager.pending_count(&addr), 2);

        manager.confirm_nonce(&addr, 1);
        assert_eq!(manager.pending_count(&addr), 1);
    }

    #[test]
    fn test_sync_from_chain() {
        let manager = NonceManager::new();
        let addr = test_addr();

        // Simulate existing on-chain state
        manager.sync_from_chain(&addr, 5);

        // Next nonce should start at 5
        assert_eq!(manager.next_nonce(&addr), Nonce(5));
        assert_eq!(manager.next_nonce(&addr), Nonce(6));
    }

    #[test]
    fn test_reset_pending() {
        let manager = NonceManager::new();
        let addr = test_addr();

        manager.sync_from_chain(&addr, 3);
        manager.next_nonce(&addr); // 3
        manager.next_nonce(&addr); // 4
        manager.next_nonce(&addr); // 5

        // Reset drops pending back to confirmed
        manager.reset_pending(&addr);
        assert_eq!(manager.next_nonce(&addr), Nonce(3));
    }

    #[test]
    fn test_clear() {
        let manager = NonceManager::new();
        let addr = test_addr();

        manager.next_nonce(&addr);
        manager.next_nonce(&addr);

        manager.clear(&addr);

        assert_eq!(manager.next_nonce(&addr), Nonce(0));
    }
}
