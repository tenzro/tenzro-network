//! Basic storage operations example
//!
//! This example demonstrates basic usage of the tenzro-storage crate.

use std::sync::Arc;
use tenzro_storage::{
    account_store::AccountStoreImpl,
    block_store::BlockStoreImpl,
    kv::MemoryStore,
    traits::{AccountStore, BlockStore},
};
use tenzro_types::{Account, Address, Block, BlockHeader, BlockHeight, Hash, Nonce};

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

    // Example 3: State trie
    println!("\n=== State Trie ===");
    demo_state_trie(kv_store.clone())?;

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

fn demo_state_trie(kv_store: Arc<MemoryStore>) -> Result<(), Box<dyn std::error::Error>> {
    use tenzro_storage::{CF_ACCOUNTS, KvStore, StateTrie, verify_state_proof};
    let trie = StateTrie::new(kv_store as Arc<dyn KvStore>);

    // Commit the writes of height 1.
    let mut writes = tenzro_storage::state_trie::capture::Writes::new();
    for (key, value) in [("account1", "1000"), ("account2", "2000")] {
        writes.insert(
            (CF_ACCOUNTS.to_string(), key.as_bytes().to_vec()),
            Some(value.as_bytes().to_vec()),
        );
    }
    let root = trie.commit(1, &writes)?;
    println!("State root at height 1: {}", root);

    // Prove one entry and verify it against the root.
    let (value, proof) = trie.prove(1, CF_ACCOUNTS, b"account1")?;
    let ok = verify_state_proof(
        tenzro_types::hash_scheme::HashScheme::Sha256,
        &root.0,
        CF_ACCOUNTS,
        b"account1",
        value.as_deref(),
        &proof,
    )
    .is_ok();
    println!("Proof of account1 verifies: {}", ok);

    Ok(())
}
