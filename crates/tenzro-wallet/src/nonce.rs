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
}

impl NonceManager {
    /// Create a new nonce manager
    pub fn new() -> Self {
        Self {
            pending_nonces: DashMap::new(),
            confirmed_nonces: DashMap::new(),
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

    /// Peek at the next nonce without incrementing.
    pub fn peek_nonce(&self, address: &Address) -> Nonce {
        let nonce = self
            .pending_nonces
            .get(address)
            .map(|v| *v)
            .unwrap_or(0);
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

        debug!(
            "Confirmed nonce {} for address {}",
            nonce, address
        );
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
        let confirmed = self
            .confirmed_nonces
            .get(address)
            .map(|v| *v)
            .unwrap_or(0);
        self.pending_nonces.insert(*address, confirmed);

        debug!(
            "Reset pending nonce for address {} to {}",
            address, confirmed
        );
    }

    /// Get the confirmed nonce for an address.
    pub fn confirmed_nonce(&self, address: &Address) -> Nonce {
        let nonce = self
            .confirmed_nonces
            .get(address)
            .map(|v| *v)
            .unwrap_or(0);
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
