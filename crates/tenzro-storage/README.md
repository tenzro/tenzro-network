# tenzro-storage

State storage layer for Tenzro Network. Provides persistent storage for Tenzro Ledger (the settlement layer).

## Overview

The `tenzro-storage` crate provides the storage infrastructure for the Tenzro Network blockchain, including efficient key-value storage, the unified binary state trie that commits block state, block indexing and account management.

## Features

- **RocksDB Integration**: High-performance persistent storage with 42 column families
- **`KvStore` trait**: `get`, `put`, `delete`, `get_keys_with_prefix`, `write_batch`, `write_batch_sync` — used by upper-layer registries for write-through persistence and startup hydration
- **Unified binary state trie** (`StateTrie`): the block state root over every committed column family, versioned by height, with inclusion and absence proofs and 4,096-bucket snapshot cuts
- **Block Storage**: Fast indexing and retrieval of blocks by hash and height
- **Account Storage**: Account state management with balance and nonce tracking
- **In-Memory Storage**: Testing-friendly in-memory storage implementation
- **Durability Guarantees**: Explicit fsync via `write_batch_sync()` for finalized blocks
- **Async/Await Support**: Full async interface for all storage operations

## Architecture

### Column Families (42 total)

The storage layer uses RocksDB with the following column families:

- `blocks` - Block data indexed by hash and height
- `state` - VM state, committed into the state trie
- `accounts` - Account state and metadata
- `transactions` - Transaction storage and indexing
- `metadata` - System metadata and configuration
- `state_trie` - State trie nodes, versioned by height
- `identities` - TDIP identity registry
- `delegations` - Identity delegation records
- `credentials` - Verifiable credentials
- `channels` - Micropayment channels
- `agents` - AI agent registry and state
- `models` - Model catalog and metadata
- `providers` - Provider registrations
- `agent_templates` - Agent template definitions
- `skills` - Skill registry
- `tools` - Tool definitions
- `knowledge` - Queryable data resources (vector indices, document corpora, data feeds)
- `workflow_templates` - Reusable saga specs tenants instantiate
- `tokens` - Token registry (ERC-20, SPL, CIP-56)
- `settlements` - Settlement receipts and history
- `model_services` - Served model endpoints
- `nfts` - NFT metadata and ownership
- `events` - Event store for event sourcing
- `webhooks` - Webhook subscriptions
- `compliance` - Compliance and audit logs
- `audit` - Audit log records
- `approvals` - Approval state for multi-step flows
- `validator_modules` - ERC-7579 validator module configs and state
- `da_committee` - Availability certificates and sliver assignments
- `challenges` - Filed disputes over an inference commitment
- `databases` - Database descriptors and partition placements
- `model_hashes` - Canonical per-model content hashes (BLAKE3 + SHA-256)

### Data Availability Primitives (`da` module)

High-volume receipts (inference, agent message, channel updates) carry a commitment + pointer instead of the full payload; sensitive low-volume receipts (kill-switch, governance, escrow, lifecycle) stay inline.

- `ReceiptEnvelope { kind, storage_mode, inline_summary, inline_payload, da_pointer, commitment, mandate_ref }` - Receipts either embed the payload (`Inline`) or record a pointer to an external DA layer (`OffloadedDA`). `commitment` is always `SHA-256(canonical_payload)` regardless of mode. The optional `mandate_ref` ties the receipt to a signed off-chain mandate (AP2 checkout, x402 challenge, MPP session, Stripe SPT, Visa TAP, Mastercard Agent Pay, Capital Intent, Workflow step) closing the audit loop from intent → settlement
- `MandateRef { protocol, mandate_hash, issuer_did, mandate_uri?, expires_at }` - Reference to a signed off-chain mandate authorizing the receipt; convenience constructor `MandateRef::x402(hash, did)`; attach via `ReceiptEnvelope::with_mandate(mandate_ref)`
- `ReceiptKind` - `SettlementEscrow | SettlementChannel | Inference | AgentMessage | KillSwitch | Lifecycle | Governance` with per-kind `default_mode()`
- `DaPointer { backend, namespace, locator, commitment_kzg, attestation_root }` - Reference to an external DA layer (IrohBlobs / EigenDA / Celestia / Avail)
- `DaBackendId`, `DaBackendStatus`
- `#[async_trait] DaBackend` trait - `submit` / `fetch` / `verify_availability`
- `InlineBackend` - Safe default; refuses offload until external backends are wired behind feature flags
- `compute_commitment(payload) -> Hash` - Canonical SHA-256 commitment

### State trie

- **Keys**: `SHA-256(namespace || key)`, split into a 31-byte stem and a 1-byte slot; each stem's 256 slots hash to one commitment and stems form a binary tree, with single-stem subtrees collapsed
- **Capture**: only writes made inside `capture::in_task` / `capture::in_thread` scopes are committed, so node-local writers cannot move the root
- **Versions**: `commit(height, writes)`, `root_at(height)`, `prove(height, namespace, key)`, `prune(keep_from)`
- **Snapshots**: `bucket_summaries` / `bucket_entries` / `verify_bucket` / `root_from_buckets` cut and check a version in 4,096 buckets

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

### State trie

```rust
use std::sync::Arc;
use tenzro_storage::{CF_ACCOUNTS, KvStore, MemoryStore, StateTrie, verify_state_proof};

let trie = StateTrie::new(Arc::new(MemoryStore::new()) as Arc<dyn KvStore>);
let mut writes = tenzro_storage::state_trie::capture::Writes::new();
writes.insert((CF_ACCOUNTS.to_string(), b"key1".to_vec()), Some(b"value1".to_vec()));
let root = trie.commit(1, &writes)?;

let (value, proof) = trie.prove(1, CF_ACCOUNTS, b"key1")?;
verify_state_proof(&root.0, CF_ACCOUNTS, b"key1", value.as_deref(), &proof)?;
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
- `sha2` - SHA-256 hashing for the state trie
- `serde`, `serde_json`, `bincode` - Serialization
- `tokio` - Async runtime
- `parking_lot` - High-performance locks
- `async-trait` - Async trait support

## Test Coverage

Unit tests and doc tests cover:
- RocksDB store operations (get, put, delete, batch writes)
- State trie commits, proofs (present, absent, forged), versions, pruning and bucket verification
- Block storage indexing (by hash and height)
- Account storage operations
- Genesis block persistence
- Durability guarantees (`write_batch_sync` with fsync)

## Constants

- `MAX_CACHE_SIZE`: 1 GB (1,073,741,824 bytes)

## License

Apache-2.0.
