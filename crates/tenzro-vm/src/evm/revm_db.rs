//! revm Database adapter for StateAdapter
//!
//! This module provides a bridge between our StateAdapter and revm's Database trait,
//! allowing revm to read and write state through our storage layer.

use revm::Database;
use revm::primitives::{AccountInfo, Address as RevmAddress, B256, Bytecode, U256};
use sha3::{Digest, Keccak256};
use tenzro_storage::CF_BLOCKS;
use tenzro_types::{BlockHeight, Hash};

use crate::state_adapter::StateAdapter;
use crate::traits::VmState;

/// Adapter that bridges our StateAdapter to revm's Database trait
///
/// This adapter implements revm's Database trait using our StateAdapter as the backend.
/// It handles the conversion between revm's types (U256, B256, etc.) and our internal
/// representation (Vec<u8>, u128, etc.).
pub struct RevmStateAdapter<'a> {
    state: &'a mut StateAdapter,
}

impl<'a> RevmStateAdapter<'a> {
    /// Create a new revm database adapter wrapping the given state
    pub fn new(state: &'a mut StateAdapter) -> Self {
        Self { state }
    }
}

impl<'a> Database for RevmStateAdapter<'a> {
    type Error = String;

    fn basic(&mut self, address: RevmAddress) -> Result<Option<AccountInfo>, Self::Error> {
        let addr_bytes = address.as_slice();
        let balance = self.state.get_balance(addr_bytes);
        let nonce = self.state.get_nonce(addr_bytes);
        let code = self.state.get_code(addr_bytes);

        // Compute code hash (Keccak256 for EVM compatibility)
        let code_hash = if let Some(ref c) = code {
            let hash = Keccak256::digest(c);
            B256::from_slice(&hash)
        } else {
            revm::primitives::KECCAK_EMPTY
        };

        // Convert code to Bytecode if present
        let bytecode = code
            .map(|c| Bytecode::new_raw(c.into()))
            .unwrap_or_default();

        Ok(Some(AccountInfo {
            balance: U256::from(balance),
            nonce,
            code_hash,
            code: Some(bytecode),
        }))
    }

    fn code_by_hash(&mut self, _code_hash: B256) -> Result<Bytecode, Self::Error> {
        // We store code directly by address, not by hash
        // This is called for optimization in some cases, but we can return empty
        Ok(Bytecode::default())
    }

    fn storage(&mut self, address: RevmAddress, index: U256) -> Result<U256, Self::Error> {
        let addr_bytes = address.as_slice();
        let key = index.to_be_bytes::<32>();

        match self.state.get_storage(addr_bytes, &key) {
            Some(value) if value.len() == 32 => {
                Ok(U256::from_be_bytes::<32>(value.try_into().unwrap()))
            }
            _ => Ok(U256::ZERO),
        }
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        // Query the block hash from persistent storage if available.
        // The block store indexes hashes by height under the key
        // "height_hash:{height_be_bytes}" in the CF_BLOCKS column family.
        if let Some(store) = self.state.kv_store() {
            let height = BlockHeight::new(number);
            let mut key = b"height_hash:".to_vec();
            key.extend_from_slice(&height.0.to_be_bytes());

            match store.get(CF_BLOCKS, &key) {
                Ok(Some(hash_bytes)) => {
                    if let Some(hash) = Hash::from_bytes(&hash_bytes) {
                        return Ok(B256::from_slice(hash.as_bytes()));
                    }
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!(
                        block_number = number,
                        error = %e,
                        "Failed to query block hash from storage, returning zero"
                    );
                }
            }
        }

        // Fallback: no storage configured or block not found
        Ok(B256::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::traits::VmState;

    #[test]
    fn test_revm_adapter_basic() {
        let mut state = StateAdapter::new();
        let address_bytes = vec![1u8; 20];

        // Set some initial state
        state.set_balance(&address_bytes, 1000);
        state.set_nonce(&address_bytes, 5);
        state.set_code(&address_bytes, vec![0x60, 0x80, 0x60, 0x40, 0x52]);

        // Create revm adapter
        let mut adapter = RevmStateAdapter::new(&mut state);

        // Convert to revm address
        let address = RevmAddress::from_slice(&address_bytes);

        // Query basic account info
        let info = adapter.basic(address).unwrap().unwrap();
        assert_eq!(info.balance, U256::from(1000));
        assert_eq!(info.nonce, 5);
        assert!(info.code.is_some());
    }

    #[test]
    fn test_revm_adapter_storage() {
        let mut state = StateAdapter::new();
        let address_bytes = vec![1u8; 20];

        // Set storage value
        let key = [0u8; 32];
        let mut value = [0u8; 32];
        value[31] = 42; // Value = 42
        state.set_storage(&address_bytes, &key, value.to_vec());

        // Create revm adapter
        let mut adapter = RevmStateAdapter::new(&mut state);

        let address = RevmAddress::from_slice(&address_bytes);
        let storage_key = U256::from(0);

        // Query storage
        let storage_value = adapter.storage(address, storage_key).unwrap();
        assert_eq!(storage_value, U256::from(42));
    }

    #[test]
    fn test_revm_adapter_empty_account() {
        let mut state = StateAdapter::new();
        let address_bytes = vec![1u8; 20];

        let mut adapter = RevmStateAdapter::new(&mut state);
        let address = RevmAddress::from_slice(&address_bytes);

        // Query non-existent account
        let info = adapter.basic(address).unwrap().unwrap();
        assert_eq!(info.balance, U256::ZERO);
        assert_eq!(info.nonce, 0);
        assert_eq!(info.code_hash, revm::primitives::KECCAK_EMPTY);
    }
}
