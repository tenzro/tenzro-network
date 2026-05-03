//! Basic storage operations example
//!
//! This example demonstrates basic usage of the tenzro-storage crate.

use std::sync::Arc;
use tenzro_storage::{
    account_store::AccountStoreImpl,
    block_store::BlockStoreImpl,
    kv::MemoryStore,
    merkle::MerklePatriciaTrie,
    traits::{AccountStore, BlockStore},
};
use tenzro_types::{
    Account, Address, Block, BlockHeader, BlockHeight, ConsensusProof, Hash,
    Nonce,
};
use tenzro_types::block::ConsensusAlgorithm;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Tenzro Storage - Basic Example\n");

    // Create in-memory store for this example
    let kv_store = Arc::new(MemoryStore::new());

    // Example 1: Block Storage
    println!("=== Block Storage ===");
    demo_block_storage(kv_store.clone()).await?;

    // Example 2: Account Storage
    println!("\n=== Account Storage ===");
    demo_account_storage(kv_store.clone()).await?;

    // Example 3: Merkle Trie
    println!("\n=== Merkle Patricia Trie ===");
    demo_merkle_trie()?;

    Ok(())
}

async fn demo_block_storage(kv_store: Arc<MemoryStore>) -> Result<(), Box<dyn std::error::Error>> {
    let mut block_store = BlockStoreImpl::new(kv_store)?;

    // Create a test block
    let header = BlockHeader::new(
        BlockHeight::new(1),
        Hash::zero(),
        Hash::zero(),
        Hash::zero(),
        Address::zero(),
        ConsensusProof::new(ConsensusAlgorithm::PoS, vec![]),
    );
    let block = Block::new(header, vec![]);

    println!("Storing block at height {}...", block.height());
    block_store.put_block(&block).await?;

    // Retrieve the block
    let retrieved = block_store.get_block(&block.hash()).await?;
    println!("Retrieved block: {:?}", retrieved.is_some());

    // Get latest block
    let latest = block_store.latest_block().await?;
    println!("Latest block height: {:?}", latest.map(|b| b.height()));

    Ok(())
}

async fn demo_account_storage(
    kv_store: Arc<MemoryStore>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut account_store = AccountStoreImpl::new(kv_store);

    // Create a test account
    let address = Address::new([1u8; 32]);
    let mut account = Account::new(address);
    account.balance = 1000;
    account.nonce = Nonce::new(0);

    println!("Storing account with address {}...", address);
    account_store.put_account(&account).await?;

    // Retrieve the account
    let retrieved = account_store.get_account(&address).await?;
    println!("Retrieved account balance: {}", retrieved.unwrap().balance);

    // Get balance directly
    let balance = account_store.get_balance(&address).await?;
    println!("Account balance: {}", balance);

    // Update nonce
    account_store.update_nonce(&address, Nonce::new(1)).await?;
    let nonce = account_store.get_nonce(&address).await?;
    println!("Updated nonce: {}", nonce);

    Ok(())
}

fn demo_merkle_trie() -> Result<(), Box<dyn std::error::Error>> {
    let mut trie = MerklePatriciaTrie::new();

    // Insert some key-value pairs
    println!("Inserting key-value pairs...");
    trie.insert(b"account1", b"balance:1000")?;
    trie.insert(b"account2", b"balance:2000")?;
    trie.insert(b"account3", b"balance:3000")?;

    // Commit and get state root
    let state_root = trie.commit()?;
    println!("State root: {}", state_root);

    // Retrieve a value
    let value = trie.get(b"account1")?;
    println!(
        "Value for 'account1': {}",
        String::from_utf8_lossy(value.as_ref().unwrap())
    );

    // Generate and verify a proof
    let proof = trie.generate_proof(b"account1")?;
    let is_valid =
        MerklePatriciaTrie::verify_proof(&proof, state_root, Some(b"balance:1000"))?;
    println!("Proof verification: {}", is_valid);

    // Delete a key
    println!("Deleting 'account2'...");
    trie.delete(b"account2")?;
    let new_root = trie.commit()?;
    println!("New state root: {}", new_root);
    println!("State root changed: {}", state_root != new_root);

    Ok(())
}
