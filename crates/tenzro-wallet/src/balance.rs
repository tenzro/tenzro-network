//! Balance tracking for MPC wallets in Tenzro Network.
//!
//! This module tracks balances across multiple assets (TNZO, USDC, USDT, etc.)
//! for wallet addresses.

use crate::error::{Result, WalletError};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tenzro_types::AssetId;
use tenzro_types::primitives::Address;

/// Trait for balance providers in Tenzro Network.
///
/// This trait defines the interface for querying and updating balances
/// across multiple assets. Implementations can be in-memory, database-backed,
/// or connected to on-chain state.
pub trait BalanceProvider: Send + Sync {
    /// Get the balance for an address and asset
    fn get_balance(&self, address: &Address, asset_id: &AssetId) -> Balance;

    /// Set the balance for an address and asset
    fn set_balance(&self, address: &Address, asset_id: &AssetId, balance: Balance);

    /// Get all balances for an address
    fn get_all_balances(&self, address: &Address) -> HashMap<AssetId, Balance>;

    /// Add to balance
    fn add_balance(&self, address: &Address, asset_id: &AssetId, amount: u128);

    /// Subtract from balance
    fn subtract_balance(&self, address: &Address, asset_id: &AssetId, amount: u128) -> Result<()>;

    /// Lock an amount
    fn lock_balance(&self, address: &Address, asset_id: &AssetId, amount: u128) -> Result<()>;

    /// Unlock an amount
    fn unlock_balance(&self, address: &Address, asset_id: &AssetId, amount: u128) -> Result<()>;

    /// Transfer between addresses
    fn transfer(
        &self,
        from: &Address,
        to: &Address,
        asset_id: &AssetId,
        amount: u128,
    ) -> Result<()>;
}

/// Balance information for a specific asset
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Balance {
    /// Available balance (in smallest unit, e.g., wei for TNZO)
    pub available: u128,
    /// Locked/staked balance
    pub locked: u128,
    /// Pending incoming transactions
    pub pending_in: u128,
    /// Pending outgoing transactions
    pub pending_out: u128,
}

impl Balance {
    /// Create a new balance with zero amounts
    pub fn zero() -> Self {
        Self {
            available: 0,
            locked: 0,
            pending_in: 0,
            pending_out: 0,
        }
    }

    /// Create a balance with a specific available amount
    pub fn new(available: u128) -> Self {
        Self {
            available,
            locked: 0,
            pending_in: 0,
            pending_out: 0,
        }
    }

    /// Get the total balance (available + locked + pending_in)
    pub fn total(&self) -> u128 {
        self.available
            .saturating_add(self.locked)
            .saturating_add(self.pending_in)
    }

    /// Get the spendable balance (available - pending_out)
    pub fn spendable(&self) -> u128 {
        self.available.saturating_sub(self.pending_out)
    }

    /// Check if balance is zero
    pub fn is_zero(&self) -> bool {
        self.available == 0 && self.locked == 0 && self.pending_in == 0 && self.pending_out == 0
    }

    /// Add to available balance
    pub fn add_available(&mut self, amount: u128) {
        self.available = self.available.saturating_add(amount);
    }

    /// Subtract from available balance
    pub fn sub_available(&mut self, amount: u128) -> Result<()> {
        if self.available < amount {
            return Err(WalletError::InsufficientBalance {
                have: self.available,
                need: amount,
            });
        }
        self.available = self.available.saturating_sub(amount);
        Ok(())
    }

    /// Lock an amount
    pub fn lock(&mut self, amount: u128) -> Result<()> {
        if self.available < amount {
            return Err(WalletError::InsufficientBalance {
                have: self.available,
                need: amount,
            });
        }
        self.available = self.available.saturating_sub(amount);
        self.locked = self.locked.saturating_add(amount);
        Ok(())
    }

    /// Unlock an amount
    pub fn unlock(&mut self, amount: u128) -> Result<()> {
        if self.locked < amount {
            return Err(WalletError::Other(format!(
                "Insufficient locked balance: have {}, need {}",
                self.locked, amount
            )));
        }
        self.locked = self.locked.saturating_sub(amount);
        self.available = self.available.saturating_add(amount);
        Ok(())
    }

    /// Add pending incoming transaction
    pub fn add_pending_in(&mut self, amount: u128) {
        self.pending_in = self.pending_in.saturating_add(amount);
    }

    /// Confirm pending incoming transaction
    pub fn confirm_pending_in(&mut self, amount: u128) {
        self.pending_in = self.pending_in.saturating_sub(amount);
        self.available = self.available.saturating_add(amount);
    }

    /// Add pending outgoing transaction
    pub fn add_pending_out(&mut self, amount: u128) {
        self.pending_out = self.pending_out.saturating_add(amount);
    }

    /// Confirm pending outgoing transaction
    pub fn confirm_pending_out(&mut self, amount: u128) -> Result<()> {
        self.pending_out = self.pending_out.saturating_sub(amount);
        self.sub_available(amount)
    }
}

/// Multi-asset balance tracker for Tenzro Network wallets.
pub struct BalanceTracker {
    /// Map of (address, asset_id) -> Balance
    balances: DashMap<(Address, AssetId), Balance>,
}

impl BalanceTracker {
    /// Create a new balance tracker
    pub fn new() -> Self {
        Self {
            balances: DashMap::new(),
        }
    }

    /// Get the balance for an address and asset
    pub fn get_balance(&self, address: &Address, asset_id: &AssetId) -> Balance {
        self.balances
            .get(&(*address, asset_id.clone()))
            .map(|entry| *entry.value())
            .unwrap_or_else(Balance::zero)
    }

    /// Set the balance for an address and asset
    pub fn set_balance(&self, address: &Address, asset_id: &AssetId, balance: Balance) {
        self.balances.insert((*address, asset_id.clone()), balance);
    }

    /// Get all balances for an address
    pub fn get_all_balances(&self, address: &Address) -> HashMap<AssetId, Balance> {
        let mut balances = HashMap::new();
        for entry in self.balances.iter() {
            let (addr, asset_id) = entry.key();
            if addr == address {
                balances.insert(asset_id.clone(), *entry.value());
            }
        }
        balances
    }

    /// Add to balance
    pub fn add_balance(&self, address: &Address, asset_id: &AssetId, amount: u128) {
        self.balances
            .entry((*address, asset_id.clone()))
            .and_modify(|balance| balance.add_available(amount))
            .or_insert_with(|| Balance::new(amount));
    }

    /// Subtract from balance
    pub fn subtract_balance(
        &self,
        address: &Address,
        asset_id: &AssetId,
        amount: u128,
    ) -> Result<()> {
        let mut entry = self
            .balances
            .entry((*address, asset_id.clone()))
            .or_insert_with(Balance::zero);

        entry.sub_available(amount)
    }

    /// Lock an amount
    pub fn lock_balance(&self, address: &Address, asset_id: &AssetId, amount: u128) -> Result<()> {
        let mut entry = self
            .balances
            .entry((*address, asset_id.clone()))
            .or_insert_with(Balance::zero);

        entry.lock(amount)
    }

    /// Unlock an amount
    pub fn unlock_balance(
        &self,
        address: &Address,
        asset_id: &AssetId,
        amount: u128,
    ) -> Result<()> {
        let mut entry = self
            .balances
            .entry((*address, asset_id.clone()))
            .or_insert_with(Balance::zero);

        entry.unlock(amount)
    }

    /// Transfer between addresses
    pub fn transfer(
        &self,
        from: &Address,
        to: &Address,
        asset_id: &AssetId,
        amount: u128,
    ) -> Result<()> {
        // Subtract from sender
        self.subtract_balance(from, asset_id, amount)?;

        // Add to recipient
        self.add_balance(to, asset_id, amount);

        Ok(())
    }

    /// Add a pending incoming transaction
    pub fn add_pending_deposit(&self, address: &Address, asset_id: &AssetId, amount: u128) {
        self.balances
            .entry((*address, asset_id.clone()))
            .and_modify(|balance| balance.add_pending_in(amount))
            .or_insert_with(|| {
                let mut balance = Balance::zero();
                balance.add_pending_in(amount);
                balance
            });
    }

    /// Confirm a pending deposit
    pub fn confirm_deposit(&self, address: &Address, asset_id: &AssetId, amount: u128) {
        self.balances
            .entry((*address, asset_id.clone()))
            .and_modify(|balance| balance.confirm_pending_in(amount));
    }

    /// Add a pending withdrawal
    pub fn add_pending_withdrawal(&self, address: &Address, asset_id: &AssetId, amount: u128) {
        self.balances
            .entry((*address, asset_id.clone()))
            .and_modify(|balance| balance.add_pending_out(amount))
            .or_insert_with(|| {
                let mut balance = Balance::zero();
                balance.add_pending_out(amount);
                balance
            });
    }

    /// Confirm a pending withdrawal
    pub fn confirm_withdrawal(
        &self,
        address: &Address,
        asset_id: &AssetId,
        amount: u128,
    ) -> Result<()> {
        let mut entry = self
            .balances
            .entry((*address, asset_id.clone()))
            .or_insert_with(Balance::zero);

        entry.confirm_pending_out(amount)
    }

    /// Clear all balances (for testing)
    pub fn clear(&self) {
        self.balances.clear();
    }
}

impl Default for BalanceTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl BalanceProvider for BalanceTracker {
    fn get_balance(&self, address: &Address, asset_id: &AssetId) -> Balance {
        self.get_balance(address, asset_id)
    }

    fn set_balance(&self, address: &Address, asset_id: &AssetId, balance: Balance) {
        self.set_balance(address, asset_id, balance)
    }

    fn get_all_balances(&self, address: &Address) -> HashMap<AssetId, Balance> {
        self.get_all_balances(address)
    }

    fn add_balance(&self, address: &Address, asset_id: &AssetId, amount: u128) {
        self.add_balance(address, asset_id, amount)
    }

    fn subtract_balance(&self, address: &Address, asset_id: &AssetId, amount: u128) -> Result<()> {
        self.subtract_balance(address, asset_id, amount)
    }

    fn lock_balance(&self, address: &Address, asset_id: &AssetId, amount: u128) -> Result<()> {
        self.lock_balance(address, asset_id, amount)
    }

    fn unlock_balance(&self, address: &Address, asset_id: &AssetId, amount: u128) -> Result<()> {
        self.unlock_balance(address, asset_id, amount)
    }

    fn transfer(
        &self,
        from: &Address,
        to: &Address,
        asset_id: &AssetId,
        amount: u128,
    ) -> Result<()> {
        self.transfer(from, to, asset_id, amount)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_address() -> Address {
        Address::new([1u8; 32])
    }

    #[test]
    fn test_balance_operations() {
        let mut balance = Balance::new(1000);

        assert_eq!(balance.available, 1000);
        assert_eq!(balance.total(), 1000);
        assert_eq!(balance.spendable(), 1000);

        // Add balance
        balance.add_available(500);
        assert_eq!(balance.available, 1500);

        // Subtract balance
        balance.sub_available(300).unwrap();
        assert_eq!(balance.available, 1200);

        // Lock balance
        balance.lock(200).unwrap();
        assert_eq!(balance.available, 1000);
        assert_eq!(balance.locked, 200);
        assert_eq!(balance.total(), 1200);

        // Unlock balance
        balance.unlock(100).unwrap();
        assert_eq!(balance.available, 1100);
        assert_eq!(balance.locked, 100);
    }

    #[test]
    fn test_insufficient_balance() {
        let mut balance = Balance::new(100);
        let result = balance.sub_available(200);
        assert!(result.is_err());
    }

    #[test]
    fn test_balance_tracker() {
        let tracker = BalanceTracker::new();
        let address = create_test_address();
        let asset = AssetId::tnzo();

        // Initially zero
        let balance = tracker.get_balance(&address, &asset);
        assert_eq!(balance.available, 0);

        // Add balance
        tracker.add_balance(&address, &asset, 1000);
        let balance = tracker.get_balance(&address, &asset);
        assert_eq!(balance.available, 1000);

        // Subtract balance
        tracker.subtract_balance(&address, &asset, 300).unwrap();
        let balance = tracker.get_balance(&address, &asset);
        assert_eq!(balance.available, 700);
    }

    #[test]
    fn test_transfer() {
        let tracker = BalanceTracker::new();
        let from = Address::new([1u8; 32]);
        let to = Address::new([2u8; 32]);
        let asset = AssetId::tnzo();

        // Give sender some balance
        tracker.add_balance(&from, &asset, 1000);

        // Transfer
        tracker.transfer(&from, &to, &asset, 400).unwrap();

        let from_balance = tracker.get_balance(&from, &asset);
        let to_balance = tracker.get_balance(&to, &asset);

        assert_eq!(from_balance.available, 600);
        assert_eq!(to_balance.available, 400);
    }

    #[test]
    fn test_pending_transactions() {
        let tracker = BalanceTracker::new();
        let address = create_test_address();
        let asset = AssetId::tnzo();

        // Add initial balance
        tracker.add_balance(&address, &asset, 1000);

        // Add pending deposit
        tracker.add_pending_deposit(&address, &asset, 500);
        let balance = tracker.get_balance(&address, &asset);
        assert_eq!(balance.available, 1000);
        assert_eq!(balance.pending_in, 500);
        assert_eq!(balance.total(), 1500);

        // Confirm deposit
        tracker.confirm_deposit(&address, &asset, 500);
        let balance = tracker.get_balance(&address, &asset);
        assert_eq!(balance.available, 1500);
        assert_eq!(balance.pending_in, 0);

        // Add pending withdrawal
        tracker.add_pending_withdrawal(&address, &asset, 300);
        let balance = tracker.get_balance(&address, &asset);
        assert_eq!(balance.available, 1500);
        assert_eq!(balance.pending_out, 300);
        assert_eq!(balance.spendable(), 1200);

        // Confirm withdrawal
        tracker.confirm_withdrawal(&address, &asset, 300).unwrap();
        let balance = tracker.get_balance(&address, &asset);
        assert_eq!(balance.available, 1200);
        assert_eq!(balance.pending_out, 0);
    }

    #[test]
    fn test_get_all_balances() {
        let tracker = BalanceTracker::new();
        let address = create_test_address();

        tracker.add_balance(&address, &AssetId::tnzo(), 1000);
        tracker.add_balance(&address, &AssetId::from("USDT"), 500);
        tracker.add_balance(&address, &AssetId::from("USDC"), 750);

        let balances = tracker.get_all_balances(&address);
        assert_eq!(balances.len(), 3);
        assert_eq!(balances.get(&AssetId::tnzo()).unwrap().available, 1000);
        assert_eq!(balances.get(&AssetId::from("USDT")).unwrap().available, 500);
        assert_eq!(balances.get(&AssetId::from("USDC")).unwrap().available, 750);
    }
}
