//! Storage trait definitions for Tenzro Network
//!
//! This module defines the core storage traits that provide abstractions
//! for state management, block storage, and account management.

use crate::error::Result;
use async_trait::async_trait;
use tenzro_types::{Account, Address, Block, BlockHeight, Hash, Nonce};

/// State store trait for managing blockchain state
///
/// Provides operations for reading and writing state data with
/// Merkle tree support for state root computation.
#[async_trait]
pub trait StateStore: Send + Sync {
    /// Gets a value from the state store
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Puts a value into the state store
    async fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()>;

    /// Deletes a value from the state store
    async fn delete(&mut self, key: &[u8]) -> Result<()>;

    /// Returns the current state root hash
    async fn state_root(&self) -> Result<Hash>;

    /// Commits pending changes to the store
    async fn commit(&mut self) -> Result<Hash>;

    /// Rolls back pending changes
    async fn rollback(&mut self) -> Result<()>;

    /// Checks if a key exists
    async fn contains(&self, key: &[u8]) -> Result<bool> {
        Ok(self.get(key).await?.is_some())
    }
}

/// Block store trait for managing blockchain blocks
///
/// Provides operations for storing and retrieving blocks by hash and height.
#[async_trait]
pub trait BlockStore: Send + Sync {
    /// Gets a block by its hash
    async fn get_block(&self, hash: &Hash) -> Result<Option<Block>>;

    /// Gets a block by its height
    async fn get_block_by_height(&self, height: BlockHeight) -> Result<Option<Block>>;

    /// Stores a block
    async fn put_block(&mut self, block: &Block) -> Result<()>;

    /// Gets the latest block
    async fn latest_block(&self) -> Result<Option<Block>>;

    /// Gets the latest block height
    async fn latest_height(&self) -> Result<Option<BlockHeight>>;

    /// Gets blocks in a height range (inclusive)
    async fn blocks_by_height_range(
        &self,
        start: BlockHeight,
        end: BlockHeight,
    ) -> Result<Vec<Block>>;

    /// Checks if a block exists by hash
    async fn has_block(&self, hash: &Hash) -> Result<bool> {
        Ok(self.get_block(hash).await?.is_some())
    }

    /// Gets the block hash at a specific height
    async fn get_block_hash(&self, height: BlockHeight) -> Result<Option<Hash>>;
}

/// Account store trait for managing account state
///
/// Provides operations for reading and writing account data.
#[async_trait]
pub trait AccountStore: Send + Sync {
    /// Gets an account by address
    async fn get_account(&self, address: &Address) -> Result<Option<Account>>;

    /// Stores or updates an account
    async fn put_account(&mut self, account: &Account) -> Result<()>;

    /// Deletes an account
    async fn delete_account(&mut self, address: &Address) -> Result<()>;

    /// Gets the balance of an account
    async fn get_balance(&self, address: &Address) -> Result<u128> {
        Ok(self
            .get_account(address)
            .await?
            .map(|acc| acc.balance)
            .unwrap_or(0))
    }

    /// Updates the nonce of an account
    async fn update_nonce(&mut self, address: &Address, nonce: Nonce) -> Result<()> {
        if let Some(mut account) = self.get_account(address).await? {
            account.nonce = nonce;
            self.put_account(&account).await?;
        }
        Ok(())
    }

    /// Checks if an account exists
    async fn has_account(&self, address: &Address) -> Result<bool> {
        Ok(self.get_account(address).await?.is_some())
    }

    /// Gets the nonce of an account
    async fn get_nonce(&self, address: &Address) -> Result<Nonce> {
        Ok(self
            .get_account(address)
            .await?
            .map(|acc| acc.nonce)
            .unwrap_or_else(Nonce::initial))
    }
}
