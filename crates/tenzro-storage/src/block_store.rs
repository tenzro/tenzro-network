//! Block storage implementation for Tenzro Network
//!
//! This module provides storage and retrieval of blocks with indexing
//! by both hash and height. A block's body is stored once, by height; a
//! hash names it through a hash -> height index in [`CF_METADATA`]. The
//! index stays out of [`CF_BLOCKS`]: hashes are spread over the whole key
//! space, so among the bodies every flush would overlap every stored block
//! and compaction would rewrite them all.

use crate::error::{Result, StorageError};
use crate::kv::{CF_BLOCKS, CF_METADATA, KvStore, WriteOp};
use crate::traits::BlockStore;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::sync::Arc;
use tenzro_types::{Block, BlockHeight, Hash};

/// Block storage implementation using a key-value store.
///
/// `K` is `?Sized` so a caller holding an `Arc<dyn KvStore>` — the consensus
/// driver, which never sees the concrete store type — can build one without
/// duplicating the block key layout.
pub struct BlockStoreImpl<K: KvStore + ?Sized> {
    kv_store: Arc<K>,
    latest_height: Arc<RwLock<Option<BlockHeight>>>,
    latest_hash: Arc<RwLock<Option<Hash>>>,
}

impl<K: KvStore + ?Sized> BlockStoreImpl<K> {
    /// Creates a new block store
    pub fn new(kv_store: Arc<K>) -> Result<Self> {
        let store = Self {
            kv_store,
            latest_height: Arc::new(RwLock::new(None)),
            latest_hash: Arc::new(RwLock::new(None)),
        };

        // Load latest height and hash from metadata
        store.load_latest_info()?;

        Ok(store)
    }

    /// Loads the latest block info from storage
    fn load_latest_info(&self) -> Result<()> {
        if let Some(height_bytes) = self.kv_store.get(CF_METADATA, b"latest_height")? {
            let height: u64 = bincode::deserialize(&height_bytes)?;
            *self.latest_height.write() = Some(BlockHeight::new(height));
        }

        if let Some(hash_bytes) = self.kv_store.get(CF_METADATA, b"latest_hash")? {
            let hash = Hash::from_bytes(&hash_bytes)
                .ok_or_else(|| StorageError::InvalidValue("Invalid hash".to_string()))?;
            *self.latest_hash.write() = Some(hash);
        }

        Ok(())
    }

    /// Key of a block's hash in the hash -> height index, in [`CF_METADATA`];
    /// the value is the height, u64 big-endian
    fn block_hash_key(hash: &Hash) -> Vec<u8> {
        let mut key = b"block_hash:".to_vec();
        key.extend_from_slice(hash.as_bytes());
        key
    }

    /// Generates a key for storing a block by height
    fn block_height_key(height: BlockHeight) -> Vec<u8> {
        let mut key = b"block_height:".to_vec();
        key.extend_from_slice(&height.0.to_be_bytes());
        key
    }

    /// Generates a key for storing the hash at a specific height
    fn height_to_hash_key(height: BlockHeight) -> Vec<u8> {
        let mut key = b"height_hash:".to_vec();
        key.extend_from_slice(&height.0.to_be_bytes());
        key
    }

    /// Deletes the bodies of the blocks at heights `first..=last`. The
    /// height <-> hash indexes are kept: they are a few dozen bytes a height,
    /// and they let a pruned block still be named and fetched from elsewhere.
    /// Returns the number of blocks deleted.
    pub fn prune_range(&self, first: BlockHeight, last: BlockHeight) -> Result<u64> {
        let mut ops = Vec::new();
        let mut pruned = 0u64;
        for h in first.0..=last.0 {
            let height = BlockHeight::new(h);
            if self
                .kv_store
                .get(CF_BLOCKS, &Self::height_to_hash_key(height))?
                .is_none()
            {
                continue;
            }
            ops.push(WriteOp::Delete {
                cf: CF_BLOCKS.to_string(),
                key: Self::block_height_key(height),
            });
            pruned += 1;
        }
        if !ops.is_empty() {
            self.kv_store.write_batch(ops)?;
        }
        Ok(pruned)
    }

    /// [`Self::prune_range`], also deleting the height and hash indexes of
    /// the pruned blocks, so a pruned block leaves nothing behind locally.
    pub fn prune_range_with_indexes(&self, first: BlockHeight, last: BlockHeight) -> Result<u64> {
        let mut ops = Vec::new();
        let mut pruned = 0u64;
        for h in first.0..=last.0 {
            let height = BlockHeight::new(h);
            let Some(hash) = self
                .kv_store
                .get(CF_BLOCKS, &Self::height_to_hash_key(height))?
            else {
                continue;
            };
            ops.push(WriteOp::Delete {
                cf: CF_BLOCKS.to_string(),
                key: Self::block_height_key(height),
            });
            ops.push(WriteOp::Delete {
                cf: CF_BLOCKS.to_string(),
                key: Self::height_to_hash_key(height),
            });
            if let Ok(bytes) = <[u8; 32]>::try_from(hash.as_slice()) {
                ops.push(WriteOp::Delete {
                    cf: CF_METADATA.to_string(),
                    key: Self::block_hash_key(&Hash::new(bytes)),
                });
            }
            pruned += 1;
        }
        if !ops.is_empty() {
            self.kv_store.write_batch(ops)?;
        }
        Ok(pruned)
    }

    /// Serialize a block for on-disk storage as JSON.
    ///
    /// We cannot use `bincode` because `Block` transitively contains
    /// `TransactionType`, which is annotated with
    /// `#[serde(tag = "type", content = "data")]` (an internally-tagged enum).
    /// Bincode 1.x does not support internally-tagged or content-tagged enum
    /// representations — `bincode::serialize` produces output that
    /// `bincode::deserialize` refuses with "Bincode does not support
    /// Deserializer::deserialize_identifier", corrupting any block that
    /// contained at least one typed transaction. JSON round-trips tagged enums
    /// faithfully and matches the serialization already used for the per-tx
    /// records in `CF_TRANSACTIONS` (see `tenzro_node::event_loop`
    /// block-finalization indexing).
    fn encode_block(block: &Block) -> Result<Vec<u8>> {
        serde_json::to_vec(block)
            .map_err(|e| StorageError::SerializationError(format!("encode_block: {}", e)))
    }

    /// Decode a JSON-encoded block from storage.
    fn decode_block(data: &[u8]) -> Result<Block> {
        serde_json::from_slice::<Block>(data)
            .map_err(|e| StorageError::SerializationError(format!("decode_block: {}", e)))
    }
}

/// Reads the block stored at `height` straight from `kv`, without the async
/// store: for lookups that already hold a store handle and need one block.
pub fn read_block_by_height<K: KvStore + ?Sized>(
    kv: &K,
    height: BlockHeight,
) -> Result<Option<Block>> {
    let key = BlockStoreImpl::<crate::kv::MemoryStore>::block_height_key(height);
    kv.get(CF_BLOCKS, &key)?
        .map(|data| BlockStoreImpl::<K>::decode_block(&data))
        .transpose()
}

#[async_trait]
impl<K: KvStore + ?Sized + 'static> BlockStore for BlockStoreImpl<K> {
    async fn get_block(&self, hash: &Hash) -> Result<Option<Block>> {
        let Some(height_bytes) = self
            .kv_store
            .get(CF_METADATA, &Self::block_hash_key(hash))?
        else {
            return Ok(None);
        };
        let height = <[u8; 8]>::try_from(height_bytes.as_slice())
            .map(|b| BlockHeight::new(u64::from_be_bytes(b)))
            .map_err(|_| StorageError::InvalidValue("Invalid block height".to_string()))?;
        // The height may since hold another block: the hash names this one
        // only while the height still records it.
        if self.get_block_hash(height).await? != Some(*hash) {
            return Ok(None);
        }
        self.get_block_by_height(height).await
    }

    async fn get_block_by_height(&self, height: BlockHeight) -> Result<Option<Block>> {
        match self
            .kv_store
            .get(CF_BLOCKS, &Self::block_height_key(height))?
        {
            Some(data) => Ok(Some(Self::decode_block(&data)?)),
            None => Ok(None),
        }
    }

    async fn put_block(&mut self, block: &Block) -> Result<()> {
        let hash = block.hash();
        let height = block.height();

        // Serialize the block. See `encode_block` for the bincode/JSON rationale —
        // bincode cannot round-trip `TransactionType`'s tagged-enum representation.
        let block_data = Self::encode_block(block)?;

        // Prepare batch write
        let mut ops = Vec::new();

        // Index the hash to the height; the body is stored once, by height
        ops.push(WriteOp::Put {
            cf: CF_METADATA.to_string(),
            key: Self::block_hash_key(&hash),
            value: height.0.to_be_bytes().to_vec(),
        });

        // Store block by height
        ops.push(WriteOp::Put {
            cf: CF_BLOCKS.to_string(),
            key: Self::block_height_key(height),
            value: block_data,
        });

        // Store hash at height
        ops.push(WriteOp::Put {
            cf: CF_BLOCKS.to_string(),
            key: Self::height_to_hash_key(height),
            value: hash.as_bytes().to_vec(),
        });

        // Update latest height if this is newer
        let should_update = if let Some(latest) = *self.latest_height.read() {
            height > latest
        } else {
            true
        };

        if should_update {
            ops.push(WriteOp::Put {
                cf: CF_METADATA.to_string(),
                key: b"latest_height".to_vec(),
                value: bincode::serialize(&height.0)?,
            });

            ops.push(WriteOp::Put {
                cf: CF_METADATA.to_string(),
                key: b"latest_hash".to_vec(),
                value: hash.as_bytes().to_vec(),
            });
        }

        // Execute batch write with fsync for durability — blocks must survive power loss
        self.kv_store.write_batch_sync(ops)?;

        // Update in-memory cache
        if should_update {
            *self.latest_height.write() = Some(height);
            *self.latest_hash.write() = Some(hash);
        }

        Ok(())
    }

    async fn latest_block(&self) -> Result<Option<Block>> {
        let hash = *self.latest_hash.read();
        if let Some(hash) = hash {
            self.get_block(&hash).await
        } else {
            Ok(None)
        }
    }

    async fn latest_height(&self) -> Result<Option<BlockHeight>> {
        Ok(*self.latest_height.read())
    }

    async fn blocks_by_height_range(
        &self,
        start: BlockHeight,
        end: BlockHeight,
    ) -> Result<Vec<Block>> {
        if start > end {
            return Ok(Vec::new());
        }

        // One point read per height in the window, never a scan of the
        // column family: a request for a few blocks reads a few blocks
        // however long the chain is. Heights past the highest stored block
        // hold nothing, so the window ends there.
        let Some(latest) = *self.latest_height.read() else {
            return Ok(Vec::new());
        };
        let end_h = end.0.min(latest.0);
        let mut blocks = Vec::new();
        let mut h = start.0;
        while h <= end_h {
            if let Some(value) = self
                .kv_store
                .get(CF_BLOCKS, &Self::block_height_key(BlockHeight::new(h)))?
            {
                blocks.push(Self::decode_block(&value)?);
            }
            h += 1;
        }

        Ok(blocks)
    }

    async fn get_block_hash(&self, height: BlockHeight) -> Result<Option<Hash>> {
        let key = Self::height_to_hash_key(height);
        if let Some(hash_bytes) = self.kv_store.get(CF_BLOCKS, &key)? {
            let hash = Hash::from_bytes(&hash_bytes)
                .ok_or_else(|| StorageError::InvalidValue("Invalid hash".to_string()))?;
            Ok(Some(hash))
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv::MemoryStore;
    use tenzro_types::{Address, BlockHeader};

    fn create_test_block(height: u64) -> Block {
        let header = BlockHeader::new(
            BlockHeight::new(height),
            Hash::zero(),
            Hash::zero(),
            Hash::zero(),
            Address::zero(),
        );
        Block::new(header, vec![])
    }

    #[tokio::test]
    async fn test_block_store() {
        let kv_store = Arc::new(MemoryStore::new());
        let mut block_store = BlockStoreImpl::new(kv_store).unwrap();

        let block1 = create_test_block(1);
        let block2 = create_test_block(2);

        // Store blocks
        block_store.put_block(&block1).await.unwrap();
        block_store.put_block(&block2).await.unwrap();

        // Retrieve by hash
        let retrieved1 = block_store.get_block(&block1.hash()).await.unwrap();
        assert_eq!(retrieved1, Some(block1.clone()));

        // Retrieve by height
        let retrieved2 = block_store
            .get_block_by_height(BlockHeight::new(2))
            .await
            .unwrap();
        assert_eq!(retrieved2, Some(block2.clone()));

        // Check latest
        let latest = block_store.latest_block().await.unwrap();
        assert_eq!(latest, Some(block2));

        let latest_height = block_store.latest_height().await.unwrap();
        assert_eq!(latest_height, Some(BlockHeight::new(2)));
    }

    /// Regression: blocks containing typed transactions must round-trip.
    ///
    /// Pre-fix, `bincode::serialize` succeeded for blocks containing
    /// `TransactionType::Transfer` but `bincode::deserialize` then failed with
    /// "Bincode does not support Deserializer::deserialize_identifier" because
    /// `TransactionType` carries `#[serde(tag = "type", content = "data")]`.
    /// Result: any tx-bearing block written to RocksDB was unreadable, and
    /// `eth_getBlockByNumber` returned -32000 for them. Blocks are now
    /// serialized as JSON on both write and read — there is no bincode path.
    #[tokio::test]
    async fn test_block_with_typed_transactions_roundtrip() {
        use tenzro_crypto::HybridSigner;
        use tenzro_crypto::composite::testing::TestHybridSigner;
        use tenzro_types::primitives::{ChainId, Nonce, Timestamp};
        use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};

        let kv_store = Arc::new(MemoryStore::new());
        let mut block_store = BlockStoreImpl::new(kv_store).unwrap();

        let signer = TestHybridSigner::hybrid(3);
        let tx = Transaction {
            chain_id: ChainId::from(1337u64),
            from: Address::zero(),
            to: Address::zero(),
            nonce: Nonce::from(0u64),
            tx_type: TransactionType::Transfer {
                amount: 5_000_000_000_000_000_000u128,
            },
            gas_limit: 21_000,
            gas_price: 1_000_000_000,
            timestamp: Timestamp::new(1_700_000_000_000),
            valid_until: Timestamp::new(1_700_000_300_000),
            memo: None,
        };
        let signature = signer
            .sign(
                tenzro_crypto::SignatureContext::Transaction,
                tx.hash().as_bytes(),
            )
            .unwrap();
        let signed = SignedTransaction::new(tx, signer.public_key().p256.clone(), signature);

        let header = BlockHeader::new(
            BlockHeight::new(7),
            Hash::zero(),
            Hash::zero(),
            Hash::zero(),
            Address::zero(),
        );
        let block = Block::new(header, vec![signed]);

        block_store.put_block(&block).await.unwrap();
        let got = block_store
            .get_block_by_height(BlockHeight::new(7))
            .await
            .unwrap();
        assert_eq!(got.as_ref().map(|b| b.transactions.len()), Some(1));
        assert_eq!(got.unwrap().transactions[0].transaction.gas_limit, 21_000);
    }

    #[tokio::test]
    async fn test_block_range() {
        let kv_store = Arc::new(MemoryStore::new());
        let mut block_store = BlockStoreImpl::new(kv_store).unwrap();

        for i in 1..=5 {
            block_store.put_block(&create_test_block(i)).await.unwrap();
        }

        let blocks = block_store
            .blocks_by_height_range(BlockHeight::new(2), BlockHeight::new(4))
            .await
            .unwrap();

        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0].height(), BlockHeight::new(2));
        assert_eq!(blocks[1].height(), BlockHeight::new(3));
        assert_eq!(blocks[2].height(), BlockHeight::new(4));
    }

    /// Range scan over a larger window must return blocks in ascending height
    /// order, must skip missing heights silently, and must respect `end` as an
    /// inclusive upper bound.
    #[tokio::test]
    async fn test_block_range_with_gaps_and_bounds() {
        let kv_store = Arc::new(MemoryStore::new());
        let mut block_store = BlockStoreImpl::new(kv_store).unwrap();

        // Insert blocks at heights 0, 1, 2, 5, 6, 9, 10
        for h in [0u64, 1, 2, 5, 6, 9, 10] {
            block_store.put_block(&create_test_block(h)).await.unwrap();
        }

        // Pull [3, 9] inclusive — should return 5, 6, 9 in order.
        let blocks = block_store
            .blocks_by_height_range(BlockHeight::new(3), BlockHeight::new(9))
            .await
            .unwrap();
        let heights: Vec<u64> = blocks.iter().map(|b| b.height().0).collect();
        assert_eq!(heights, vec![5u64, 6, 9]);

        // Inclusive endpoint: [10, 10] returns just 10.
        let blocks = block_store
            .blocks_by_height_range(BlockHeight::new(10), BlockHeight::new(10))
            .await
            .unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].height(), BlockHeight::new(10));

        // start > end is empty (no error).
        let blocks = block_store
            .blocks_by_height_range(BlockHeight::new(7), BlockHeight::new(3))
            .await
            .unwrap();
        assert!(blocks.is_empty());

        // Range entirely above the highest stored block returns empty.
        let blocks = block_store
            .blocks_by_height_range(BlockHeight::new(100), BlockHeight::new(200))
            .await
            .unwrap();
        assert!(blocks.is_empty());
    }

    /// A store that counts the entries and bytes every read hands back.
    struct CountingStore {
        inner: MemoryStore,
        entries: std::sync::atomic::AtomicUsize,
        bytes: std::sync::atomic::AtomicUsize,
    }

    impl CountingStore {
        fn count(&self, n: usize, len: usize) {
            use std::sync::atomic::Ordering;
            self.entries.fetch_add(n, Ordering::Relaxed);
            self.bytes.fetch_add(len, Ordering::Relaxed);
        }
    }

    impl KvStore for CountingStore {
        fn get(&self, cf: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
            let v = self.inner.get(cf, key)?;
            if let Some(v) = &v {
                self.count(1, v.len());
            }
            Ok(v)
        }
        fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> Result<()> {
            self.inner.put(cf, key, value)
        }
        fn delete(&self, cf: &str, key: &[u8]) -> Result<()> {
            self.inner.delete(cf, key)
        }
        fn write_batch(&self, operations: Vec<WriteOp>) -> Result<()> {
            self.inner.write_batch(operations)
        }
        fn write_batch_sync(&self, operations: Vec<WriteOp>) -> Result<()> {
            self.inner.write_batch_sync(operations)
        }
        fn get_keys_with_prefix(&self, cf: &str, prefix: &[u8]) -> Result<Vec<Vec<u8>>> {
            let keys = self.inner.get_keys_with_prefix(cf, prefix)?;
            self.count(keys.len(), keys.iter().map(|k| k.len()).sum());
            Ok(keys)
        }
        fn scan_prefix(&self, cf: &str, prefix: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
            let pairs = self.inner.scan_prefix(cf, prefix)?;
            self.count(
                pairs.len(),
                pairs.iter().map(|(k, v)| k.len() + v.len()).sum(),
            );
            Ok(pairs)
        }
    }

    /// Asking for one block of a long chain reads that block, not the chain.
    #[tokio::test]
    async fn a_height_range_reads_only_the_blocks_it_returns() {
        use std::sync::atomic::Ordering;
        let kv_store = Arc::new(CountingStore {
            inner: MemoryStore::new(),
            entries: Default::default(),
            bytes: Default::default(),
        });
        let mut block_store = BlockStoreImpl::new(kv_store.clone()).unwrap();
        for h in 0..10_000u64 {
            block_store.put_block(&create_test_block(h)).await.unwrap();
        }
        kv_store.entries.store(0, Ordering::Relaxed);
        kv_store.bytes.store(0, Ordering::Relaxed);
        let one = block_store
            .blocks_by_height_range(BlockHeight::new(5_000), BlockHeight::new(5_000))
            .await
            .unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].height(), BlockHeight::new(5_000));
        let block_len = BlockStoreImpl::<MemoryStore>::encode_block(&one[0])
            .unwrap()
            .len();
        let entries = kv_store.entries.load(Ordering::Relaxed);
        let bytes = kv_store.bytes.load(Ordering::Relaxed);
        assert!(entries <= 4, "{entries} entries read for one block");
        assert!(bytes <= 4 * block_len, "{bytes} bytes read for one block");

        // A window reaching far past the tip reads only up to the tip.
        kv_store.entries.store(0, Ordering::Relaxed);
        let tail = block_store
            .blocks_by_height_range(BlockHeight::new(9_998), BlockHeight::new(u64::MAX))
            .await
            .unwrap();
        assert_eq!(tail.len(), 2);
        assert!(kv_store.entries.load(Ordering::Relaxed) <= 4);
    }

    /// A block's body is written to disk once. A second copy keyed by hash
    /// doubled the chain's growth on disk, and the hash keys, spread over the
    /// whole key space, made every flush overlap every stored block, so
    /// compaction rewrote the whole column family again and again.
    #[tokio::test]
    async fn a_block_body_is_stored_once() {
        let kv = Arc::new(MemoryStore::new());
        let mut store = BlockStoreImpl::new(kv.clone()).unwrap();
        let block = create_test_block(7);
        let body = BlockStoreImpl::<MemoryStore>::encode_block(&block).unwrap();
        store.put_block(&block).await.unwrap();

        let rows = kv.scan_prefix(CF_BLOCKS, b"").unwrap();
        let copies = rows.iter().filter(|(_, v)| *v == body).count();
        assert_eq!(copies, 1, "the block body must be stored exactly once");
        let bytes: usize = rows.iter().map(|(k, v)| k.len() + v.len()).sum();
        assert!(
            bytes < body.len() + 128,
            "{bytes} bytes in the block column family for a {}-byte block",
            body.len()
        );

        assert_eq!(
            store.get_block(&block.hash()).await.unwrap(),
            Some(block.clone())
        );
        assert_eq!(
            store
                .get_block_by_height(BlockHeight::new(7))
                .await
                .unwrap(),
            Some(block.clone())
        );
        assert_eq!(store.get_block(&Hash::zero()).await.unwrap(), None);

        // Pruning removes the body; the block is then gone by either name,
        // and its hash is still named by height.
        assert_eq!(
            store
                .prune_range(BlockHeight::new(7), BlockHeight::new(7))
                .unwrap(),
            1
        );
        let rows = kv.scan_prefix(CF_BLOCKS, b"").unwrap();
        assert!(rows.iter().all(|(_, v)| *v != body));
        assert_eq!(store.get_block(&block.hash()).await.unwrap(), None);
        assert_eq!(
            store
                .get_block_by_height(BlockHeight::new(7))
                .await
                .unwrap(),
            None
        );
        assert_eq!(
            store.get_block_hash(BlockHeight::new(7)).await.unwrap(),
            Some(block.hash())
        );
    }

    /// The same on the RocksDB store, at the small memory budget the node's
    /// own tests open it with: every block written can be read back by hash
    /// and by height.
    #[tokio::test]
    async fn blocks_round_trip_on_a_small_rocksdb_store() {
        let tmp = tempfile::tempdir().unwrap();
        let kv = Arc::new(
            crate::RocksDbStore::open(
                &crate::StorageConfig::new(tmp.path().join("db")).with_memory_bytes(8 << 20),
            )
            .unwrap(),
        );
        let mut store = BlockStoreImpl::new(kv.clone()).unwrap();
        let blocks: Vec<Block> = (1..=40).map(create_test_block).collect();
        for b in &blocks {
            store.put_block(b).await.unwrap();
        }
        for b in &blocks {
            assert_eq!(store.get_block(&b.hash()).await.unwrap().as_ref(), Some(b));
            assert_eq!(
                store
                    .get_block_by_height(b.height())
                    .await
                    .unwrap()
                    .as_ref(),
                Some(b)
            );
        }
    }
}
