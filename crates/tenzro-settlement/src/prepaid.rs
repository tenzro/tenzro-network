//! Prepaid balance ledger for streaming settlement.
//!
//! Streaming services — capacity [`rental`](crate::rental) and per-byte storage
//! [`metering`](../../tenzro_storage_provider/metering) — bill against a renter's
//! *prepaid* TNZO balance rather than debiting the on-chain account each epoch.
//! Booking locks the full term inside this balance; each epoch streams one slice
//! out to the provider (or refunds it on a miss). That shared balance map is the
//! ledger this module owns.
//!
//! # Why a dedicated ledger
//!
//! The [`EscrowManager`](crate::escrow) and [`RentalManager`](crate::rental)
//! both take a shared `Arc<DashMap<(Address, AssetId), u128>>` and move value
//! within it, but neither *funds* it from a renter's real balance nor persists
//! it. This type closes both gaps:
//!
//! - **Funding.** [`deposit`](PrepaidLedger::deposit) debits the renter's real
//!   on-chain TNZO through the [`AccountLedger`] seam and credits the prepaid
//!   balance; [`withdraw`](PrepaidLedger::withdraw) reverses it for the unspent
//!   remainder. The settlement crate never depends on `tenzro-token` directly —
//!   the node wires a concrete `AccountLedger` at startup.
//! - **Durability.** Every mutation writes through to `CF_SETTLEMENTS` under the
//!   `prepaid_balance:` prefix, and the ledger hydrates on construction, so
//!   locked deposits and accrued provider credit survive a restart.
//!
//! The inner map is handed to the managers via [`inner`](PrepaidLedger::inner);
//! their in-map moves (lock, stream, refund) are picked up by the ledger's
//! [`persist`](PrepaidLedger::persist) sweep at each settlement epoch, keeping
//! the durable copy in step with the managers' epoch mutations.

use crate::error::{Result, SettlementError};
use dashmap::DashMap;
use std::sync::Arc;
use tenzro_storage::{KvStore, CF_SETTLEMENTS};
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::Address;
use tracing::warn;

/// Storage key prefix for persisted prepaid balances in `CF_SETTLEMENTS`.
const PREPAID_KEY_PREFIX: &[u8] = b"prepaid_balance:";

/// The on-chain account ledger a [`PrepaidLedger`] funds from. Implemented at
/// the node layer over the token subsystem so this crate stays decoupled from
/// `tenzro-token`.
pub trait AccountLedger: Send + Sync {
    /// Withdrawable on-chain balance of `account` for `asset`.
    fn balance_of(&self, account: &Address, asset: &AssetId) -> u128;

    /// Moves `amount` of `asset` from `account` into the network's prepaid
    /// escrow (a locked, non-spendable state on-chain). Returns an error if the
    /// account cannot cover it.
    fn lock(&self, account: &Address, asset: &AssetId, amount: u128) -> Result<()>;

    /// Reverses a [`lock`](AccountLedger::lock): returns `amount` of `asset`
    /// from prepaid escrow to `account`'s withdrawable balance.
    fn unlock(&self, account: &Address, asset: &AssetId, amount: u128) -> Result<()>;
}

/// A persistent prepaid-balance ledger over a shared balances map.
pub struct PrepaidLedger {
    /// The shared balance map handed to the escrow/rental managers.
    balances: Arc<DashMap<(Address, AssetId), u128>>,
    /// On-chain account ledger deposits draw from.
    accounts: Arc<dyn AccountLedger>,
    /// Durable backing for the prepaid balances.
    storage: Arc<dyn KvStore>,
}

impl std::fmt::Debug for PrepaidLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrepaidLedger")
            .field("entries", &self.balances.len())
            .finish()
    }
}

impl PrepaidLedger {
    /// Builds a ledger over a fresh balance map, hydrating any persisted
    /// balances from `CF_SETTLEMENTS`.
    pub fn new(accounts: Arc<dyn AccountLedger>, storage: Arc<dyn KvStore>) -> Self {
        let balances = Arc::new(DashMap::new());
        let ledger = Self {
            balances,
            accounts,
            storage,
        };
        ledger.hydrate();
        ledger
    }

    /// The shared balance map to hand to [`EscrowManager`](crate::escrow) /
    /// [`RentalManager`](crate::rental) / the storage meter, so they lock and
    /// stream against the same durable balances.
    pub fn inner(&self) -> Arc<DashMap<(Address, AssetId), u128>> {
        self.balances.clone()
    }

    /// Prepaid balance of `renter` for `asset`.
    pub fn balance(&self, renter: &Address, asset: &AssetId) -> u128 {
        self.balances
            .get(&(*renter, asset.clone()))
            .map(|e| *e.value())
            .unwrap_or(0)
    }

    /// Funds `renter`'s prepaid balance by `amount`, locking it out of their
    /// on-chain account. Persists the new prepaid balance.
    pub fn deposit(&self, renter: Address, asset: AssetId, amount: u128) -> Result<u128> {
        if amount == 0 {
            return Err(SettlementError::InvalidAmount(
                "deposit amount must be non-zero".to_string(),
            ));
        }
        self.accounts.lock(&renter, &asset, amount)?;
        let key = (renter, asset);
        let new_balance = {
            let mut entry = self.balances.entry(key.clone()).or_insert(0);
            *entry = entry.saturating_add(amount);
            *entry
        };
        self.persist_key(&key, new_balance);
        Ok(new_balance)
    }

    /// Withdraws up to `amount` of `renter`'s *unlocked* prepaid balance back to
    /// their on-chain account. Returns the amount actually withdrawn (capped at
    /// the available prepaid balance).
    pub fn withdraw(&self, renter: Address, asset: AssetId, amount: u128) -> Result<u128> {
        if amount == 0 {
            return Err(SettlementError::InvalidAmount(
                "withdraw amount must be non-zero".to_string(),
            ));
        }
        let key = (renter, asset.clone());
        let (debited, new_balance) = {
            let mut entry = self.balances.entry(key.clone()).or_insert(0);
            let debited = amount.min(*entry);
            *entry = entry.saturating_sub(debited);
            (debited, *entry)
        };
        if debited == 0 {
            return Ok(0);
        }
        self.accounts.unlock(&renter, &asset, debited)?;
        self.persist_key(&key, new_balance);
        Ok(debited)
    }

    /// Writes every current prepaid balance through to durable storage. Called
    /// once per settlement epoch after the managers have moved value within the
    /// shared map (lock / stream / refund), so the durable copy tracks their
    /// in-map mutations.
    pub fn persist(&self) {
        for entry in self.balances.iter() {
            self.persist_key(entry.key(), *entry.value());
        }
    }

    fn hydrate(&self) {
        match self
            .storage
            .get_keys_with_prefix(CF_SETTLEMENTS, PREPAID_KEY_PREFIX)
        {
            Ok(keys) => {
                let mut n = 0usize;
                for key in keys {
                    let Some((addr, asset)) = decode_key(&key) else {
                        warn!("Skipping unparseable prepaid-balance key");
                        continue;
                    };
                    let value = match self.storage.get(CF_SETTLEMENTS, &key) {
                        Ok(Some(v)) => v,
                        Ok(None) => continue,
                        Err(e) => {
                            warn!("Failed to read prepaid balance: {}", e);
                            continue;
                        }
                    };
                    if value.len() != 16 {
                        warn!("Skipping prepaid-balance with malformed value length");
                        continue;
                    }
                    let mut buf = [0u8; 16];
                    buf.copy_from_slice(&value);
                    let bal = u128::from_be_bytes(buf);
                    if bal > 0 {
                        self.balances.insert((addr, asset), bal);
                        n += 1;
                    }
                }
                tracing::info!("Hydrated {} prepaid balance(s)", n);
            }
            Err(e) => warn!("Failed to hydrate prepaid balances: {}", e),
        }
    }

    fn persist_key(&self, key: &(Address, AssetId), balance: u128) {
        let storage_key = encode_key(&key.0, &key.1);
        if let Err(e) =
            self.storage
                .put(CF_SETTLEMENTS, &storage_key, &balance.to_be_bytes())
        {
            warn!("Failed to persist prepaid balance: {}", e);
        }
    }
}

/// `prepaid_balance:<addr-hex>:<asset-hex>` → storage key bytes.
fn encode_key(addr: &Address, asset: &AssetId) -> Vec<u8> {
    let mut key = PREPAID_KEY_PREFIX.to_vec();
    key.extend_from_slice(hex::encode(addr.as_bytes()).as_bytes());
    key.push(b':');
    key.extend_from_slice(hex::encode(asset_bytes(asset)).as_bytes());
    key
}

fn decode_key(key: &[u8]) -> Option<(Address, AssetId)> {
    let rest = key.strip_prefix(PREPAID_KEY_PREFIX)?;
    let sep = rest.iter().position(|&b| b == b':')?;
    let addr_hex = std::str::from_utf8(&rest[..sep]).ok()?;
    let asset_hex = std::str::from_utf8(&rest[sep + 1..]).ok()?;
    let addr_bytes = hex::decode(addr_hex).ok()?;
    let mut addr = [0u8; 32];
    if addr_bytes.len() != 32 {
        return None;
    }
    addr.copy_from_slice(&addr_bytes);
    let asset_bytes = hex::decode(asset_hex).ok()?;
    let asset = asset_from_bytes(&asset_bytes)?;
    Some((Address::new(addr), asset))
}

/// Canonical byte encoding of an [`AssetId`] for the storage key.
fn asset_bytes(asset: &AssetId) -> Vec<u8> {
    serde_json::to_vec(asset).unwrap_or_default()
}

fn asset_from_bytes(bytes: &[u8]) -> Option<AssetId> {
    serde_json::from_slice(bytes).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::MemoryStore;

    /// Test account ledger: a plain on-chain balance map with lock/unlock.
    #[derive(Default)]
    struct TestAccounts {
        chain: DashMap<(Address, AssetId), u128>,
    }

    impl TestAccounts {
        fn with(addr: Address, asset: AssetId, amount: u128) -> Arc<Self> {
            let a = Self::default();
            a.chain.insert((addr, asset), amount);
            Arc::new(a)
        }
    }

    impl AccountLedger for TestAccounts {
        fn balance_of(&self, account: &Address, asset: &AssetId) -> u128 {
            self.chain
                .get(&(*account, asset.clone()))
                .map(|e| *e.value())
                .unwrap_or(0)
        }
        fn lock(&self, account: &Address, asset: &AssetId, amount: u128) -> Result<()> {
            let mut e = self.chain.entry((*account, asset.clone())).or_insert(0);
            if *e < amount {
                return Err(SettlementError::InsufficientFunds {
                    required: amount,
                    available: *e,
                });
            }
            *e -= amount;
            Ok(())
        }
        fn unlock(&self, account: &Address, asset: &AssetId, amount: u128) -> Result<()> {
            let mut e = self.chain.entry((*account, asset.clone())).or_insert(0);
            *e += amount;
            Ok(())
        }
    }

    fn addr(b: u8) -> Address {
        Address::new([b; 32])
    }

    #[test]
    fn deposit_locks_onchain_and_credits_prepaid() {
        let renter = addr(1);
        let asset = AssetId::tnzo();
        let accounts = TestAccounts::with(renter, asset.clone(), 10_000);
        let storage = Arc::new(MemoryStore::new());
        let ledger = PrepaidLedger::new(accounts.clone(), storage);

        let bal = ledger.deposit(renter, asset.clone(), 4_000).unwrap();
        assert_eq!(bal, 4_000);
        assert_eq!(ledger.balance(&renter, &asset), 4_000);
        assert_eq!(accounts.balance_of(&renter, &asset), 6_000);
    }

    #[test]
    fn deposit_rejected_when_onchain_short() {
        let renter = addr(2);
        let asset = AssetId::tnzo();
        let accounts = TestAccounts::with(renter, asset.clone(), 100);
        let storage = Arc::new(MemoryStore::new());
        let ledger = PrepaidLedger::new(accounts, storage);
        assert!(ledger.deposit(renter, asset, 4_000).is_err());
    }

    #[test]
    fn withdraw_returns_to_onchain_capped_at_prepaid() {
        let renter = addr(3);
        let asset = AssetId::tnzo();
        let accounts = TestAccounts::with(renter, asset.clone(), 10_000);
        let storage = Arc::new(MemoryStore::new());
        let ledger = PrepaidLedger::new(accounts.clone(), storage);
        ledger.deposit(renter, asset.clone(), 4_000).unwrap();

        let out = ledger.withdraw(renter, asset.clone(), 9_999).unwrap();
        assert_eq!(out, 4_000);
        assert_eq!(ledger.balance(&renter, &asset), 0);
        assert_eq!(accounts.balance_of(&renter, &asset), 10_000);
    }

    #[test]
    fn balances_survive_rehydration() {
        let renter = addr(4);
        let asset = AssetId::tnzo();
        let accounts = TestAccounts::with(renter, asset.clone(), 10_000);
        let storage = Arc::new(MemoryStore::new());
        {
            let ledger = PrepaidLedger::new(accounts.clone(), storage.clone());
            ledger.deposit(renter, asset.clone(), 3_500).unwrap();
        }
        // A fresh ledger over the same storage rehydrates the balance.
        let ledger2 = PrepaidLedger::new(accounts, storage);
        assert_eq!(ledger2.balance(&renter, &asset), 3_500);
    }
}
