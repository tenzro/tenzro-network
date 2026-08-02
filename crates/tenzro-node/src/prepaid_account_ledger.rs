//! Concrete [`AccountLedger`] over the node's TNZO token.
//!
//! [`PrepaidLedger`] (in `tenzro-settlement`) funds prepaid streaming-service
//! balances by *locking* value out of a renter's on-chain account through the
//! [`AccountLedger`] seam, staying decoupled from `tenzro-token`. This module
//! provides the node-side implementation of that seam.
//!
//! # Lock model
//!
//! There is no dedicated freeze bit on a TNZO balance, so a lock is a transfer
//! of the amount from the renter to a single canonical, key-less **prepaid
//! vault** address ([`prepaid_vault_address`]). Locked value leaves the
//! renter's spendable balance but stays inside the token supply; an unlock is
//! the reverse transfer. The vault address is derived by hashing a fixed domain
//! tag, so no private key controls it — value only moves in and out through
//! this ledger's `lock` / `unlock`.
//!
//! Only TNZO is streamable today; a non-TNZO [`AssetId`] is rejected.

use std::sync::Arc;

use sha2::{Digest, Sha256};
use tenzro_settlement::error::{Result, SettlementError};
use tenzro_settlement::prepaid::AccountLedger;
use tenzro_token::TnzoToken;
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::Address;

/// Domain tag for deriving the canonical prepaid-vault address.
const PREPAID_VAULT_DOMAIN: &[u8] = b"tenzro/prepaid/vault";

/// The single canonical, key-less address that holds all locked prepaid TNZO.
///
/// Derived as `Address(SHA-256("tenzro/prepaid/vault"))` — no private key
/// controls it; value moves only through [`TnzoAccountLedger::lock`] /
/// [`unlock`](TnzoAccountLedger::unlock).
pub fn prepaid_vault_address() -> Address {
    let mut hasher = Sha256::new();
    hasher.update(PREPAID_VAULT_DOMAIN);
    let digest = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&digest);
    Address::new(bytes)
}

/// [`AccountLedger`] backed by the node's [`TnzoToken`].
pub struct TnzoAccountLedger {
    token: Arc<TnzoToken>,
    vault: Address,
}

impl std::fmt::Debug for TnzoAccountLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TnzoAccountLedger")
            .field("vault", &self.vault)
            .finish()
    }
}

impl TnzoAccountLedger {
    /// Builds a ledger over the node's TNZO token.
    pub fn new(token: Arc<TnzoToken>) -> Self {
        Self {
            token,
            vault: prepaid_vault_address(),
        }
    }

    /// Rejects any asset that is not native TNZO — only TNZO streams today.
    fn require_tnzo(asset: &AssetId) -> Result<()> {
        if asset.as_str() == AssetId::tnzo().as_str() {
            Ok(())
        } else {
            Err(SettlementError::InvalidAmount(format!(
                "prepaid streaming supports only TNZO, got {}",
                asset.as_str()
            )))
        }
    }
}

impl AccountLedger for TnzoAccountLedger {
    fn balance_of(&self, account: &Address, asset: &AssetId) -> u128 {
        if Self::require_tnzo(asset).is_err() {
            return 0;
        }
        self.token.balance_of(account)
    }

    fn lock(&self, account: &Address, asset: &AssetId, amount: u128) -> Result<()> {
        Self::require_tnzo(asset)?;
        self.token
            .transfer(account, &self.vault, amount)
            .map_err(|e| SettlementError::TokenError(e.to_string()))
    }

    fn unlock(&self, account: &Address, asset: &AssetId, amount: u128) -> Result<()> {
        Self::require_tnzo(asset)?;
        self.token
            .transfer(&self.vault, account, amount)
            .map_err(|e| SettlementError::TokenError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        Address::new([b; 32])
    }

    #[test]
    fn lock_moves_to_vault_unlock_reverses() {
        let token = Arc::new(TnzoToken::new());
        let treasury = addr(9);
        token.set_treasury_address(treasury);
        let renter = addr(1);
        token.mint(&renter, 10_000, &treasury).unwrap();

        let ledger = TnzoAccountLedger::new(token.clone());
        let asset = AssetId::tnzo();
        let vault = prepaid_vault_address();

        ledger.lock(&renter, &asset, 4_000).unwrap();
        assert_eq!(token.balance_of(&renter), 6_000);
        assert_eq!(token.balance_of(&vault), 4_000);

        ledger.unlock(&renter, &asset, 4_000).unwrap();
        assert_eq!(token.balance_of(&renter), 10_000);
        assert_eq!(token.balance_of(&vault), 0);
    }

    #[test]
    fn lock_rejects_non_tnzo() {
        let token = Arc::new(TnzoToken::new());
        let ledger = TnzoAccountLedger::new(token);
        let err = ledger.lock(&addr(1), &AssetId::new("USDT"), 1).unwrap_err();
        assert!(matches!(err, SettlementError::InvalidAmount(_)));
    }

    #[test]
    fn lock_rejects_when_balance_short() {
        let token = Arc::new(TnzoToken::new());
        let ledger = TnzoAccountLedger::new(token);
        assert!(ledger.lock(&addr(1), &AssetId::tnzo(), 5_000).is_err());
    }
}
