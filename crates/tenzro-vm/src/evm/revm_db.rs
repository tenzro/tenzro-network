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
    /// Whether the EVM runs under Prague alone ([`super::PRAGUE_ONLY_KEY`]):
    /// stored code that opens with the EOF magic is then legacy code.
    prague_only: bool,
}

impl<'a> RevmStateAdapter<'a> {
    /// Create a new revm database adapter wrapping the given state
    pub fn new(state: &'a mut StateAdapter) -> Self {
        let prague_only = super::rule_set(state) == revm::primitives::SpecId::PRAGUE;
        Self { state, prague_only }
    }
}

impl super::precompile_host::NativeSupplySource for RevmStateAdapter<'_> {
    fn native_total_supply(&mut self) -> Result<u128, String> {
        Ok(self.state.total_supply())
    }

    fn system_storage(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        self.state.get_storage(&crate::native::SYSTEM_ADDRESS, key)
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
        // Under Prague alone an EOF container deployed earlier is not a
        // container: its bytes are legacy code, read whole by the code
        // opcodes and halting on their first byte when called.
        let bytecode = code
            .map(|c| {
                if self.prague_only && c.starts_with(&[0xEF, 0x00]) {
                    Bytecode::new_legacy(c.into())
                } else {
                    Bytecode::new_raw(c.into())
                }
            })
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
        Ok(B256::from(stored_block_hash(self.state, number)))
    }
}

/// The hash of the block at height `number` as the block store holds it
/// (`height_hash:{height_be_bytes}` in `CF_BLOCKS`), or zero when there is
/// no store or no such block.
pub(super) fn stored_block_hash(state: &StateAdapter, number: u64) -> [u8; 32] {
    if let Some(store) = state.kv_store() {
        let height = BlockHeight::new(number);
        let mut key = b"height_hash:".to_vec();
        key.extend_from_slice(&height.0.to_be_bytes());

        match store.get(CF_BLOCKS, &key) {
            Ok(Some(hash_bytes)) => {
                if let Some(hash) = Hash::from_bytes(&hash_bytes)
                    && let Ok(hash) = <[u8; 32]>::try_from(hash.as_bytes())
                {
                    return hash;
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
    [0u8; 32]
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
