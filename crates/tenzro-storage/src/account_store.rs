//! Account state storage implementation for Tenzro Network
//!
//! This module provides storage and retrieval of account state data.

use crate::error::{Result, StorageError};
use crate::kv::{KvStore, CF_ACCOUNTS};
use crate::traits::AccountStore;
use async_trait::async_trait;
use std::sync::Arc;
use tenzro_types::{Account, Address, Nonce};

/// Account storage implementation using a key-value store
pub struct AccountStoreImpl<K: KvStore> {
    kv_store: Arc<K>,
}

impl<K: KvStore> AccountStoreImpl<K> {
    /// Creates a new account store
    pub fn new(kv_store: Arc<K>) -> Self {
        Self { kv_store }
    }

    /// Generates a key for storing an account
    fn account_key(address: &Address) -> Vec<u8> {
        let mut key = b"account:".to_vec();
        key.extend_from_slice(address.as_bytes());
        key
    }

    /// Generates a key for storing account balance
    fn balance_key(address: &Address) -> Vec<u8> {
        let mut key = b"balance:".to_vec();
        key.extend_from_slice(address.as_bytes());
        key
    }

    /// Generates a key for storing account nonce
    fn nonce_key(address: &Address) -> Vec<u8> {
        let mut key = b"nonce:".to_vec();
        key.extend_from_slice(address.as_bytes());
        key
    }
}

#[async_trait]
impl<K: KvStore + 'static> AccountStore for AccountStoreImpl<K> {
    async fn get_account(&self, address: &Address) -> Result<Option<Account>> {
        let key = Self::account_key(address);
        if let Some(data) = self.kv_store.get(CF_ACCOUNTS, &key)? {
            let account: Account = bincode::deserialize(&data)?;
            Ok(Some(account))
        } else {
            Ok(None)
        }
    }

    async fn put_account(&mut self, account: &Account) -> Result<()> {
        let key = Self::account_key(&account.address);
        let data = bincode::serialize(account)?;
        self.kv_store.put(CF_ACCOUNTS, &key, &data)?;

        // Also update balance and nonce indexes
        let balance_key = Self::balance_key(&account.address);
        let balance_data = bincode::serialize(&account.balance)?;
        self.kv_store.put(CF_ACCOUNTS, &balance_key, &balance_data)?;

        let nonce_key = Self::nonce_key(&account.address);
        let nonce_data = bincode::serialize(&account.nonce.0)?;
        self.kv_store.put(CF_ACCOUNTS, &nonce_key, &nonce_data)?;

        Ok(())
    }

    async fn delete_account(&mut self, address: &Address) -> Result<()> {
        let key = Self::account_key(address);
        self.kv_store.delete(CF_ACCOUNTS, &key)?;

        // Also delete indexes
        let balance_key = Self::balance_key(address);
        self.kv_store.delete(CF_ACCOUNTS, &balance_key)?;

        let nonce_key = Self::nonce_key(address);
        self.kv_store.delete(CF_ACCOUNTS, &nonce_key)?;

        Ok(())
    }

    async fn get_balance(&self, address: &Address) -> Result<u128> {
        let key = Self::balance_key(address);
        if let Some(data) = self.kv_store.get(CF_ACCOUNTS, &key)? {
            let balance: u128 = bincode::deserialize(&data)?;
            Ok(balance)
        } else {
            Ok(0)
        }
    }

    async fn update_nonce(&mut self, address: &Address, nonce: Nonce) -> Result<()> {
        // Get the account, update nonce, and save
        if let Some(mut account) = self.get_account(address).await? {
            account.nonce = nonce;
            self.put_account(&account).await?;
        } else {
            return Err(StorageError::AccountNotFound(address.to_string()));
        }
        Ok(())
    }

    async fn get_nonce(&self, address: &Address) -> Result<Nonce> {
        let key = Self::nonce_key(address);
        if let Some(data) = self.kv_store.get(CF_ACCOUNTS, &key)? {
            let nonce: u64 = bincode::deserialize(&data)?;
            Ok(Nonce::new(nonce))
        } else {
            Ok(Nonce::initial())
        }
    }
}

/// Combined state store that manages accounts with Merkle trie support
pub struct StateStoreImpl<K: KvStore> {
    account_store: AccountStoreImpl<K>,
}

impl<K: KvStore> StateStoreImpl<K> {
    /// Creates a new state store
    pub fn new(kv_store: Arc<K>) -> Self {
        Self {
            account_store: AccountStoreImpl::new(kv_store),
        }
    }

    /// Gets the underlying account store
    pub fn account_store(&self) -> &AccountStoreImpl<K> {
        &self.account_store
    }

    /// Gets the mutable underlying account store
    pub fn account_store_mut(&mut self) -> &mut AccountStoreImpl<K> {
        &mut self.account_store
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv::MemoryStore;

    #[tokio::test]
    async fn test_account_store() {
        let kv_store = Arc::new(MemoryStore::new());
        let mut account_store = AccountStoreImpl::new(kv_store);

        let address = Address::new([1u8; 32]);
        let mut account = Account::new(address);
        account.balance = 1000;
        account.nonce = Nonce::new(5);

        // Store account
        account_store.put_account(&account).await.unwrap();

        // Retrieve account
        let retrieved = account_store.get_account(&address).await.unwrap();
        assert_eq!(retrieved, Some(account.clone()));

        // Get balance
        let balance = account_store.get_balance(&address).await.unwrap();
        assert_eq!(balance, 1000);

        // Get nonce
        let nonce = account_store.get_nonce(&address).await.unwrap();
        assert_eq!(nonce, Nonce::new(5));

        // Update nonce
        account_store
            .update_nonce(&address, Nonce::new(6))
            .await
            .unwrap();
        let updated_nonce = account_store.get_nonce(&address).await.unwrap();
        assert_eq!(updated_nonce, Nonce::new(6));

        // Delete account
        account_store.delete_account(&address).await.unwrap();
        let deleted = account_store.get_account(&address).await.unwrap();
        assert_eq!(deleted, None);
    }

    #[tokio::test]
    async fn test_nonexistent_account() {
        let kv_store = Arc::new(MemoryStore::new());
        let account_store = AccountStoreImpl::new(kv_store);

        let address = Address::new([1u8; 32]);

        // Get nonexistent account
        let account = account_store.get_account(&address).await.unwrap();
        assert_eq!(account, None);

        // Get balance of nonexistent account
        let balance = account_store.get_balance(&address).await.unwrap();
        assert_eq!(balance, 0);

        // Get nonce of nonexistent account
        let nonce = account_store.get_nonce(&address).await.unwrap();
        assert_eq!(nonce, Nonce::initial());
    }

    #[tokio::test]
    async fn test_multiple_accounts() {
        let kv_store = Arc::new(MemoryStore::new());
        let mut account_store = AccountStoreImpl::new(kv_store);

        let addr1 = Address::new([1u8; 32]);
        let addr2 = Address::new([2u8; 32]);

        let mut account1 = Account::with_balance(addr1, 1000);
        account1.nonce = Nonce::new(1);

        let mut account2 = Account::with_balance(addr2, 2000);
        account2.nonce = Nonce::new(2);

        account_store.put_account(&account1).await.unwrap();
        account_store.put_account(&account2).await.unwrap();

        assert_eq!(
            account_store.get_balance(&addr1).await.unwrap(),
            1000
        );
        assert_eq!(
            account_store.get_balance(&addr2).await.unwrap(),
            2000
        );

        assert_eq!(
            account_store.get_nonce(&addr1).await.unwrap(),
            Nonce::new(1)
        );
        assert_eq!(
            account_store.get_nonce(&addr2).await.unwrap(),
            Nonce::new(2)
        );
    }
}
