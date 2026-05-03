# tenzro-storage

State storage layer for Tenzro Network. Provides persistent storage for Tenzro Ledger (the L1 settlement layer).

## Overview

The `tenzro-storage` crate provides a comprehensive storage infrastructure for the Tenzro Network blockchain, including efficient key-value storage, Merkle Patricia Trie state commitment, block indexing, account management, and state snapshots.

## Features

- **RocksDB Integration**: High-performance persistent storage with 24 column families
- **Merkle Patricia Trie**: Efficient state commitment and cryptographic proof generation
- **Block Storage**: Fast indexing and retrieval of blocks by hash and height
- **Account Storage**: Comprehensive account state management with balance and nonce tracking
- **State Snapshots**: Point-in-time state snapshots with automatic pruning and compression
- **In-Memory Storage**: Testing-friendly in-memory storage implementation
- **Durability Guarantees**: Explicit fsync via `write_batch_sync()` for finalized blocks
- **Async/Await Support**: Full async interface for all storage operations

## Architecture

### Column Families (24 total)

The storage layer uses RocksDB with the following column families:

- `blocks` - Block data indexed by hash and height
- `state` - Merkle Patricia Trie state data
- `accounts` - Account state and metadata
- `transactions` - Transaction storage and indexing
- `metadata` - System metadata and configuration
- `snapshots` - State snapshots at specific heights
- `identities` - TDIP identity registry
- `delegations` - Identity delegation records
- `credentials` - Verifiable credentials
- `channels` - Micropayment channels
- `agents` - AI agent registry and state
- `models` - Model catalog and metadata
- `providers` - Provider registrations
- `tasks` - Task marketplace data
- `agent_templates` - Agent template definitions
- `skills` - Skill registry
- `tools` - Tool definitions
- `tokens` - Token registry (ERC-20, SPL, CIP-56)
- `settlements` - Settlement receipts and history
- `model_services` - Served model endpoints
- `nfts` - NFT metadata and ownership
- `events` - Event store for event sourcing
- `webhooks` - Webhook subscriptions
- `compliance` - Compliance and audit logs

### Merkle Patricia Trie

The Merkle Patricia Trie implementation provides:

- **Efficient Storage**: Path compression using extension nodes
- **Cryptographic Commitment**: SHA-256 based state root computation
- **Proof Generation**: Generate and verify Merkle proofs for state inclusion
- **Node Types**: Branch (16-way), Extension (path compression), and Leaf nodes

## Usage

### Basic Storage Setup

```rust
use tenzro_storage::{
    config::StorageConfig,
    kv::RocksDbStore,
    block_store::BlockStoreImpl,
    account_store::AccountStoreImpl,
};
use std::sync::Arc;
use std::path::PathBuf;

// Create storage configuration
let config = StorageConfig::new(PathBuf::from("./data/tenzro-db"))
    .with_cache_size(512 * 1024 * 1024)  // 512 MB cache
    .with_compression(true);

// Open RocksDB store
let kv_store = Arc::new(RocksDbStore::open(&config)?);

// Create block and account stores
let block_store = BlockStoreImpl::new(kv_store.clone())?;
let account_store = AccountStoreImpl::new(kv_store.clone());
```

### Block Storage

```rust
use tenzro_storage::traits::BlockStore;
use tenzro_types::{Block, BlockHeight, Hash};

// Store a block
block_store.put_block(&block).await?;

// Retrieve by hash
let block = block_store.get_block(&block_hash).await?;

// Retrieve by height
let block = block_store.get_block_by_height(BlockHeight::new(100)).await?;

// Get latest block
let latest = block_store.latest_block().await?;

// Get block range
let blocks = block_store
    .blocks_by_height_range(
        BlockHeight::new(100),
        BlockHeight::new(200)
    )
    .await?;
```

### Account Storage

```rust
use tenzro_storage::traits::AccountStore;
use tenzro_types::{Account, Address, Nonce};

// Store an account
account_store.put_account(&account).await?;

// Retrieve an account
let account = account_store.get_account(&address).await?;

// Get balance
let balance = account_store.get_balance(&address).await?;

// Update nonce
account_store.update_nonce(&address, Nonce::new(5)).await?;

// Delete account
account_store.delete_account(&address).await?;
```

### Merkle Patricia Trie

```rust
use tenzro_storage::merkle::MerklePatriciaTrie;

let mut trie = MerklePatriciaTrie::new();

// Insert key-value pairs
trie.insert(b"key1", b"value1")?;
trie.insert(b"key2", b"value2")?;

// Commit changes and get state root
let state_root = trie.commit()?;

// Get values
let value = trie.get(b"key1")?;

// Generate Merkle proof
let proof = trie.generate_proof(b"key1")?;

// Verify proof (reconstructs root hash from proof and verifies match)
let is_valid = MerklePatriciaTrie::verify_proof(&proof, state_root, Some(b"value1"))?;

// Delete a key
trie.delete(b"key1")?;
trie.commit()?;
```

### State Snapshots

```rust
use tenzro_storage::snapshot::{SnapshotManager, CompressionType};
use tenzro_types::{BlockHeight, Hash};

// Create snapshot manager
let snapshot_manager = SnapshotManager::new(kv_store.clone(), 100);

// Create a snapshot
let snapshot = snapshot_manager
    .create_snapshot(
        BlockHeight::new(1000),
        state_root,
        block_hash,
        state_data,
    )
    .await?;

// Load a snapshot
let snapshot = snapshot_manager.load_snapshot(BlockHeight::new(1000)).await?;

// List all snapshots
let snapshots = snapshot_manager.list_snapshots().await?;

// Get latest snapshot
let latest = snapshot_manager.latest_snapshot().await?;

// Restore from snapshot
use tenzro_storage::snapshot::SnapshotRestorer;
let restored = SnapshotRestorer::restore_from_snapshot(&snapshot).await?;
```

### Durability and Persistence

```rust
use tenzro_storage::kv::WriteOp;

// Buffered write (may be lost on power failure)
kv_store.write_batch(vec![
    WriteOp::Put {
        cf: "accounts".to_string(),
        key: key1,
        value: value1,
    },
])?;

// Durable write with fsync (survives power failure)
kv_store.write_batch_sync(vec![
    WriteOp::Put {
        cf: "blocks".to_string(),
        key: block_hash.to_vec(),
        value: serialized_block,
    },
])?;
```

### In-Memory Storage (Testing)

```rust
use tenzro_storage::kv::MemoryStore;

// Create in-memory store for testing
let kv_store = Arc::new(MemoryStore::new());

// Use exactly like RocksDB store
let account_store = AccountStoreImpl::new(kv_store);
```

## Configuration

### StorageConfig Options

- `db_path`: Path to the database directory
- `cache_size`: LRU cache size in bytes (default: 512 MB, max: 1 GB)
- `compression`: Enable/disable compression (default: true)
- `max_open_files`: Maximum number of open files (default: 1000)
- `write_buffer_size`: Write buffer size in bytes (default: 64 MB)
- `max_write_buffer_number`: Maximum write buffer count (default: 3)
- `target_file_size_base`: Target SST file size (default: 64 MB)
- `enable_statistics`: Enable RocksDB statistics (default: false)
- `snapshot_retention`: Number of snapshots to retain (default: 100)
- `enable_wal`: Enable Write-Ahead Log (default: true)

## Storage Traits

### StateStore

Generic state storage interface:
- `get(key) -> value`
- `put(key, value)`
- `delete(key)`
- `state_root() -> Hash`
- `commit() -> Hash`
- `rollback()`

### BlockStore

Block storage interface:
- `get_block(hash) -> Block`
- `get_block_by_height(height) -> Block`
- `put_block(block)`
- `latest_block() -> Block`
- `blocks_by_height_range(start, end) -> Vec<Block>`

### AccountStore

Account storage interface:
- `get_account(address) -> Account`
- `put_account(account)`
- `delete_account(address)`
- `get_balance(address) -> u64`
- `update_nonce(address, nonce)`
- `get_nonce(address) -> Nonce`

## Dependencies

- `rocksdb` - Persistent key-value storage
- `sha2` - SHA-256 hashing for Merkle trie
- `serde`, `serde_json`, `bincode` - Serialization
- `tokio` - Async runtime
- `parking_lot` - High-performance locks
- `async-trait` - Async trait support
- `flate2` - LZ4 compression for snapshots

## Test Coverage

24 unit tests + 1 doc test covering:
- RocksDB store operations (get, put, delete, batch writes)
- Merkle Patricia Trie insertion, deletion, proof generation/verification
- Block storage indexing (by hash and height)
- Account storage operations
- Snapshot creation, compression, and restoration
- State root computation and commitment
- Genesis block persistence
- Durability guarantees (`write_batch_sync` with fsync)

## Constants

- `STORAGE_VERSION`: 1
- `MAX_CACHE_SIZE`: 1 GB (1,073,741,824 bytes)
- `DEFAULT_SNAPSHOT_RETENTION`: 100 snapshots

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE](../../LICENSE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT License (http://opensource.org/licenses/MIT)

at your option.
