//! Block storage implementation for Tenzro Network
//!
//! This module provides storage and retrieval of blocks with indexing
//! by both hash and height.

use crate::error::{Result, StorageError};
use crate::kv::{CF_BLOCKS, CF_METADATA, KvStore, WriteOp};
use crate::traits::BlockStore;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::sync::Arc;
use tenzro_types::{Block, BlockHeight, Hash};

/// Block storage implementation using a key-value store
pub struct BlockStoreImpl<K: KvStore> {
    kv_store: Arc<K>,
    latest_height: Arc<RwLock<Option<BlockHeight>>>,
    latest_hash: Arc<RwLock<Option<Hash>>>,
}

impl<K: KvStore> BlockStoreImpl<K> {
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

    /// Generates a key for storing a block by hash
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

#[async_trait]
impl<K: KvStore + 'static> BlockStore for BlockStoreImpl<K> {
    async fn get_block(&self, hash: &Hash) -> Result<Option<Block>> {
        let key = Self::block_hash_key(hash);
        if let Some(data) = self.kv_store.get(CF_BLOCKS, &key)? {
            let block = Self::decode_block(&data)?;
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }

    async fn get_block_by_height(&self, height: BlockHeight) -> Result<Option<Block>> {
        // First get the hash at this height
        let hash_key = Self::height_to_hash_key(height);
        if let Some(hash_bytes) = self.kv_store.get(CF_BLOCKS, &hash_key)? {
            let hash = Hash::from_bytes(&hash_bytes)
                .ok_or_else(|| StorageError::InvalidValue("Invalid hash".to_string()))?;
            self.get_block(&hash).await
        } else {
            Ok(None)
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

        // Store block by hash
        ops.push(WriteOp::Put {
            cf: CF_BLOCKS.to_string(),
            key: Self::block_hash_key(&hash),
            value: block_data.clone(),
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

        // Single prefix scan over `block_height:` keys. The full block payload
        // is stored under that key directly (see `put_block`), so no follow-up
        // hash→block lookup is needed. The big-endian u64 height suffix is
        // lexicographically equivalent to numeric order, but `KvStore::scan_prefix`
        // does not guarantee key ordering across implementations (RocksDB's
        // prefix_iterator yields sorted; MemoryStore's HashMap does not), so we
        // sort the filtered results explicitly.
        let prefix = b"block_height:";
        let pairs = self.kv_store.scan_prefix(CF_BLOCKS, prefix)?;

        let start_h = start.0;
        let end_h = end.0;
        let mut filtered: Vec<(u64, Vec<u8>)> = Vec::new();

        for (key, value) in pairs {
            let suffix = &key[prefix.len()..];
            if suffix.len() != 8 {
                continue;
            }
            let mut h_bytes = [0u8; 8];
            h_bytes.copy_from_slice(suffix);
            let h = u64::from_be_bytes(h_bytes);

            if h >= start_h && h <= end_h {
                filtered.push((h, value));
            }
        }

        filtered.sort_by_key(|(h, _)| *h);

        let mut blocks = Vec::with_capacity(filtered.len());
        for (_, value) in filtered {
            blocks.push(Self::decode_block(&value)?);
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
    use tenzro_types::block::ConsensusAlgorithm;
    use tenzro_types::{Address, BlockHeader, ConsensusProof};

    fn create_test_block(height: u64) -> Block {
        let header = BlockHeader::new(
            BlockHeight::new(height),
            Hash::zero(),
            Hash::zero(),
            Hash::zero(),
            Address::zero(),
            ConsensusProof::new(ConsensusAlgorithm::PoS, vec![]),
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
        use tenzro_crypto::pq::MlDsaSigningKey;
        use tenzro_types::primitives::{ChainId, Nonce, Signature, Timestamp};
        use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};

        let kv_store = Arc::new(MemoryStore::new());
        let mut block_store = BlockStoreImpl::new(kv_store).unwrap();

        let pq_key = MlDsaSigningKey::generate();
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
            memo: None,
            pq_public_key: pq_key.verifying_key_bytes().to_vec(),
        };
        let pq_sig = pq_key.sign(tx.hash().as_bytes()).to_vec();
        let signed =
            SignedTransaction::new(tx, Signature::new(vec![0u8; 64], vec![0u8; 32]), pq_sig);

        let header = BlockHeader::new(
            BlockHeight::new(7),
            Hash::zero(),
            Hash::zero(),
            Hash::zero(),
            Address::zero(),
            ConsensusProof::new(ConsensusAlgorithm::PoS, vec![]),
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
}
