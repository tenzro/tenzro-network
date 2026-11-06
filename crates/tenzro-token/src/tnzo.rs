//! The native TNZO balance read model.
//!
//! Balances and the supply counters live in CF_ACCOUNTS under the keys the
//! VM's state adapter writes during block execution. Only block execution
//! moves TNZO: this type reads what consensus wrote and has no writer, so
//! nothing outside a transaction can change a balance or the supply.

use crate::error::{Result, TokenError};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_storage::kv::{CF_ACCOUNTS, KvStore};
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::Address;
use tracing::warn;

/// Decimals for TNZO token (18 decimal places)
pub const TNZO_DECIMALS: u8 = 18;

/// One TNZO token in smallest unit (10^18)
pub const ONE_TNZO: u128 = 1_000_000_000_000_000_000;

/// Maximum supply of TNZO (1 billion tokens)
pub const MAX_SUPPLY: u128 = 1_000_000_000 * ONE_TNZO;

/// CF_ACCOUNTS key of the native TNZO total supply counter.
pub const TOTAL_SUPPLY_KEY: &[u8] = b"total_supply";

/// CF_ACCOUNTS key of the cumulative amount of native TNZO burned.
pub const TOTAL_BURNED_KEY: &[u8] = b"total_burned";

/// Checks a genesis allocation against the fixed supply.
///
/// The allocations may never exceed [`MAX_SUPPLY`]: nothing mints after
/// genesis (rewards are paid from a genesis-funded pool), so the genesis
/// allocation is the upper bound on every later supply.
pub fn check_genesis_supply(total: u128) -> Result<()> {
    if total > MAX_SUPPLY {
        return Err(TokenError::InvalidConfig(format!(
            "genesis allocates {total}, above the maximum supply {MAX_SUPPLY}"
        )));
    }
    Ok(())
}

/// CF_ACCOUNTS key of an address's native TNZO balance.
pub fn balance_key(address: &Address) -> Vec<u8> {
    let mut key = b"balance:".to_vec();
    key.extend_from_slice(address.as_bytes());
    key
}

/// Where the read model reads balances and the supply counters.
pub trait StorageBackend: Send + Sync {
    /// The balance of an address, if one was ever written.
    fn get_balance(&self, address: &Address) -> Result<Option<u128>>;

    /// The total supply.
    fn get_total_supply(&self) -> Result<u128>;

    /// The cumulative amount burned.
    fn get_total_burned(&self) -> Result<u128>;
}

/// Reads CF_ACCOUNTS of a key-value store.
pub struct RocksDbBackend {
    store: Arc<dyn KvStore>,
}

impl RocksDbBackend {
    /// A backend reading `store`.
    pub fn new(store: Arc<dyn KvStore>) -> Self {
        Self { store }
    }

    fn get_u128(&self, key: &[u8]) -> Result<Option<u128>> {
        match self.store.get(CF_ACCOUNTS, key)? {
            Some(bytes) if bytes.len() == 16 => {
                let mut array = [0u8; 16];
                array.copy_from_slice(&bytes);
                Ok(Some(u128::from_le_bytes(array)))
            }
            Some(bytes) => {
                warn!(
                    "invalid u128 length for {}: {}",
                    String::from_utf8_lossy(key),
                    bytes.len()
                );
                Ok(None)
            }
            None => Ok(None),
        }
    }
}

impl StorageBackend for RocksDbBackend {
    fn get_balance(&self, address: &Address) -> Result<Option<u128>> {
        self.get_u128(&balance_key(address))
    }

    fn get_total_supply(&self) -> Result<u128> {
        Ok(self.get_u128(TOTAL_SUPPLY_KEY)?.unwrap_or(0))
    }

    fn get_total_burned(&self) -> Result<u128> {
        Ok(self.get_u128(TOTAL_BURNED_KEY)?.unwrap_or(0))
    }
}

/// The native TNZO balances and supply, as block execution left them.
pub struct TnzoToken {
    /// Asset ID for TNZO token
    pub asset_id: AssetId,
    storage: Arc<dyn StorageBackend>,
}

impl std::fmt::Debug for TnzoToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TnzoToken")
            .field("asset_id", &self.asset_id)
            .field("total_supply", &self.total_supply())
            .field("total_burned", &self.total_burned())
            .finish()
    }
}

impl TnzoToken {
    /// The read model over `storage`.
    pub fn new(storage: Arc<dyn StorageBackend>) -> Self {
        Self {
            asset_id: AssetId::tnzo(),
            storage,
        }
    }

    /// The balance of an address. Reads always go to storage: block
    /// execution writes the same keys, and a cached copy would shadow them.
    pub fn balance_of(&self, address: &Address) -> u128 {
        match self.storage.get_balance(address) {
            Ok(balance) => balance.unwrap_or(0),
            Err(e) => {
                warn!("Failed to load balance from storage: {}", e);
                0
            }
        }
    }

    /// Returns the total supply of TNZO
    pub fn total_supply(&self) -> u128 {
        self.storage.get_total_supply().unwrap_or_else(|e| {
            warn!("Failed to load total supply from storage: {}", e);
            0
        })
    }

    /// Returns the circulating supply. Burned tokens are already out of
    /// total supply, so the two are the same figure.
    pub fn circulating_supply(&self) -> u128 {
        self.total_supply()
    }

    /// Returns the total amount burned
    pub fn total_burned(&self) -> u128 {
        self.storage.get_total_burned().unwrap_or_else(|e| {
            warn!("Failed to load total burned from storage: {}", e);
            0
        })
    }

    /// Returns token statistics
    pub fn stats(&self) -> TokenStats {
        TokenStats {
            total_supply: self.total_supply(),
            circulating_supply: self.circulating_supply(),
            total_burned: self.total_burned(),
        }
    }
}

/// TNZO token statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenStats {
    /// Total supply of TNZO
    pub total_supply: u128,
    /// Circulating supply
    pub circulating_supply: u128,
    /// Total burned
    pub total_burned: u128,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_over(store: &Arc<dyn KvStore>) -> TnzoToken {
        TnzoToken::new(Arc::new(RocksDbBackend::new(store.clone())))
    }

    fn put(store: &Arc<dyn KvStore>, key: &[u8], value: u128) {
        store.put(CF_ACCOUNTS, key, &value.to_le_bytes()).unwrap();
    }

    #[test]
    fn an_empty_store_reads_zero() {
        let store: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        let token = token_over(&store);
        assert_eq!(token.asset_id, AssetId::tnzo());
        assert_eq!(token.total_supply(), 0);
        assert_eq!(token.total_burned(), 0);
        assert_eq!(token.balance_of(&Address::new([1u8; 32])), 0);
    }

    #[test]
    fn genesis_supply_never_exceeds_the_fixed_supply() {
        assert!(check_genesis_supply(MAX_SUPPLY).is_ok());
        assert!(check_genesis_supply(MAX_SUPPLY + 1).is_err());
        assert!(check_genesis_supply(crate::rewards::NETWORK_REWARDS_POOL).is_ok());
    }

    /// Balances and counters written by block execution are what the next
    /// read returns; nothing is cached across the two.
    #[test]
    fn reads_follow_what_block_execution_wrote() {
        let store: Arc<dyn KvStore> = Arc::new(tenzro_storage::MemoryStore::new());
        let token = token_over(&store);
        let holder = Address::new([0xAB; 32]);

        put(&store, &balance_key(&holder), 5_000 * ONE_TNZO);
        put(&store, TOTAL_SUPPLY_KEY, 300 * ONE_TNZO);
        put(&store, TOTAL_BURNED_KEY, 200 * ONE_TNZO);
        assert_eq!(token.balance_of(&holder), 5_000 * ONE_TNZO);
        assert_eq!(token.total_supply(), 300 * ONE_TNZO);
        assert_eq!(token.total_burned(), 200 * ONE_TNZO);

        put(&store, &balance_key(&holder), ONE_TNZO);
        assert_eq!(token.balance_of(&holder), ONE_TNZO);
    }
}
