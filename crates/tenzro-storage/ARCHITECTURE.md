# tenzro-storage Architecture

## Overview

The `tenzro-storage` crate provides a comprehensive storage layer for Tenzro Network, designed for high performance, reliability, and flexibility. It provides the persistent storage foundation for Tenzro Ledger (the L1 settlement layer).

## Module Structure

```
tenzro-storage/
├── src/
│   ├── lib.rs              # Main library exports
│   ├── error.rs            # Error types
│   ├── config.rs           # Storage configuration
│   ├── traits.rs           # Storage trait definitions
│   ├── kv.rs               # Key-value store abstraction
│   ├── merkle.rs           # Merkle Patricia Trie
│   ├── block_store.rs      # Block storage implementation
│   ├── account_store.rs    # Account storage implementation
│   └── snapshot.rs         # State snapshot management
├── examples/
│   └── basic_storage.rs    # Usage examples
└── Cargo.toml
```

## Core Components

### 1. Key-Value Store (kv.rs)

The foundation of the storage layer, providing abstract key-value storage with two implementations:

#### RocksDbStore
- **Purpose**: Persistent storage
- **Features**:
  - Column family support for data organization
  - Configurable caching, compression, and write buffering
  - Batch write operations
  - Prefix-based key scanning
  - Explicit fsync via `write_batch_sync()` for durability
- **Column Families (24 total)**:
  - `blocks` - Block data
  - `state` - Merkle trie state
  - `accounts` - Account information
  - `transactions` - Transaction data
  - `metadata` - System metadata
  - `snapshots` - State snapshots
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

#### MemoryStore
- **Purpose**: Testing and development
- **Features**:
  - Identical interface to RocksDbStore
  - No persistence
  - Fast and lightweight
  - Thread-safe using RwLock

### 2. Merkle Patricia Trie (merkle.rs)

A cryptographic data structure for state commitment and proof generation.

#### Node Types
1. **Leaf**: Terminal nodes storing values
   - Fields: `path`, `value`
   - Represents the end of a key-value pair

2. **Extension**: Path compression nodes
   - Fields: `path`, `child`
   - Compresses common path prefixes

3. **Branch**: 16-way branching nodes
   - Fields: `children[16]`, `value`
   - One child per hex nibble (0-F)
   - Optional value for keys ending at this node

#### Operations
- **Insert**: O(log n) average case
- **Get**: O(log n) average case
- **Delete**: O(log n) average case
- **Commit**: Computes state root hash
- **Proof Generation**: Creates inclusion/exclusion proofs
- **Proof Verification**: Validates proofs against state root by reconstructing root hash from sibling hashes

#### State Root Computation
```
hash(node) = SHA256("node_type" || node_data)
```

For each node type:
- Leaf: `SHA256("leaf" || path || value)`
- Extension: `SHA256("extension" || path || child_hash)`
- Branch: `SHA256("branch" || child_hashes || value)`

### 3. Block Store (block_store.rs)

Manages blockchain block storage with multi-index support.

#### Indexes
1. **By Hash**: Primary index for block lookup
   - Key: `block_hash:{hash}`
   - Value: Serialized block

2. **By Height**: Sequential index
   - Key: `block_height:{height}`
   - Value: Serialized block

3. **Height to Hash**: Mapping index
   - Key: `height_hash:{height}`
   - Value: Block hash

#### Features
- Atomic block insertion with index updates
- Latest block caching (in-memory)
- Range queries by height
- Batch operations for efficiency

### 4. Account Store (account_store.rs)

Manages account state with optimized indexes.

#### Indexes
1. **Full Account**: Complete account data
   - Key: `account:{address}`
   - Value: Serialized Account

2. **Balance Index**: Quick balance lookup
   - Key: `balance:{address}`
   - Value: Balance (u64)

3. **Nonce Index**: Quick nonce lookup
   - Key: `nonce:{address}`
   - Value: Nonce (u64)

#### Features
- Atomic account updates
- Indexed balance and nonce queries
- Account deletion with cleanup
- Provider and agent data support

### 5. State Store (account_store.rs)

Combines account storage with Merkle trie for state commitment.

#### Features
- Account CRUD operations
- State root computation
- Transaction-like semantics (commit/rollback)
- Merkle proof generation for accounts

### 6. Snapshot Manager (snapshot.rs)

Manages point-in-time state snapshots.

#### Snapshot Structure
```rust
Snapshot {
    height: BlockHeight,
    state_root: Hash,
    block_hash: Hash,
    timestamp: Timestamp,
    metadata: SnapshotMetadata,
    state_data: Vec<u8>,
}
```

#### Features
- Snapshot creation at specific heights
- Snapshot restoration
- Automatic pruning based on retention policy (default: 100)
- Compression support (None, LZ4, Zstd)
- Snapshot validation

## Storage Traits

### StateStore
Generic state storage interface:
```rust
trait StateStore {
    async fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>>;
    async fn put(&mut self, key: &[u8], value: &[u8]) -> Result<()>;
    async fn delete(&mut self, key: &[u8]) -> Result<()>;
    async fn state_root(&self) -> Result<Hash>;
    async fn commit(&mut self) -> Result<Hash>;
    async fn rollback(&mut self) -> Result<()>;
}
```

### BlockStore
Block storage interface:
```rust
trait BlockStore {
    async fn get_block(&self, hash: &Hash) -> Result<Option<Block>>;
    async fn get_block_by_height(&self, height: BlockHeight) -> Result<Option<Block>>;
    async fn put_block(&mut self, block: &Block) -> Result<()>;
    async fn latest_block(&self) -> Result<Option<Block>>;
    async fn blocks_by_height_range(&self, start: BlockHeight, end: BlockHeight) -> Result<Vec<Block>>;
}
```

### AccountStore
Account storage interface:
```rust
trait AccountStore {
    async fn get_account(&self, address: &Address) -> Result<Option<Account>>;
    async fn put_account(&mut self, account: &Account) -> Result<()>;
    async fn delete_account(&mut self, address: &Address) -> Result<()>;
    async fn get_balance(&self, address: &Address) -> Result<u64>;
    async fn update_nonce(&mut self, address: &Address, nonce: Nonce) -> Result<()>;
}
```

## Data Flow

### Block Storage Flow
```
Block → Serialize → {
    block_hash:{hash} → Block data
    block_height:{height} → Block data
    height_hash:{height} → Hash
    latest_height → Height
    latest_hash → Hash
}
```

### Account Storage Flow
```
Account → Serialize → {
    account:{address} → Account data
    balance:{address} → Balance
    nonce:{address} → Nonce
}
```

### State Commitment Flow
```
Account changes → Merkle Trie → {
    Insert/Update/Delete operations
    → Commit
    → State Root Hash
    → Merkle Proof (optional)
}
```

## Performance Characteristics

### Time Complexity
- Block by hash: O(1)
- Block by height: O(1)
- Account lookup: O(1)
- Merkle trie operations: O(log n)
- Snapshot creation: O(n) where n = state size
- Batch writes: O(k) where k = batch size

### Space Complexity
- Block storage: O(n) where n = number of blocks
- Account storage: O(m) where m = number of accounts
- Merkle trie: O(m) where m = number of accounts
- Snapshots: O(s × m) where s = snapshot count, m = state size

## Configuration Options

### RocksDB Tuning
```rust
StorageConfig {
    db_path: PathBuf,              // Database directory
    cache_size: usize,             // LRU cache size (512 MB default, 1 GB max)
    compression: bool,             // Enable LZ4 compression
    max_open_files: i32,           // Max open files (1000 default)
    write_buffer_size: usize,      // Write buffer (64 MB default)
    max_write_buffer_number: i32,  // Buffer count (3 default)
    target_file_size_base: u64,    // SST file size (64 MB default)
    enable_statistics: bool,       // Enable stats
    snapshot_retention: u64,       // Snapshot count (100 default)
    enable_wal: bool,              // Write-ahead log (true default)
}
```

## Durability Guarantees

### Finalized Blocks
- Use `write_batch_sync()` which calls `WriteOptions::set_sync(true)`
- Forces fsync to disk, survives power loss
- Used for genesis block and all finalized blocks

### Regular Writes
- Use `write_batch()` which relies on WAL
- May be lost on power failure if WAL not flushed
- Suitable for non-critical or recoverable data

## Error Handling

All storage operations return `Result<T, StorageError>` with comprehensive error types:

- `DatabaseError`: General database errors
- `RocksDbError`: RocksDB-specific errors
- `SerializationError`: Data encoding errors
- `KeyNotFound`: Missing key errors
- `BlockNotFound`: Missing block errors
- `AccountNotFound`: Missing account errors
- `InvalidStateRoot`: State root mismatch
- `InvalidMerkleProof`: Proof verification failure
- `SnapshotNotFound`: Missing snapshot
- `ConcurrentModification`: Race condition detection

## Thread Safety

All storage components are designed for concurrent access:

- `KvStore`: Send + Sync traits
- `BlockStore`: Send + Sync traits
- `AccountStore`: Send + Sync traits
- Internal locks use `parking_lot` for performance
- Atomic operations where applicable

## Testing Strategy

1. **Unit Tests**: Each module has comprehensive unit tests (24 total)
2. **Integration Tests**: Cross-module interaction tests
3. **Property Tests**: Merkle trie property verification
4. **Durability Tests**: Genesis block persistence, fsync verification

## Dependencies

- `rocksdb` - Persistent key-value storage (v0.22)
- `sha2` - Cryptographic hashing (v0.10)
- `serde`, `serde_json`, `bincode` - Serialization
- `tokio` - Async runtime
- `parking_lot` - High-performance locks
- `async-trait` - Async trait definitions
- `thiserror` - Error handling
- `flate2` - LZ4 compression

## Compatibility

- Rust Edition: 2021
- Storage Version: 1
- RocksDB: 0.22.x
- SHA2: 0.10.x
