//! The node layer of a simulated validator: what sits between the consensus
//! core and execution in a node, run on the simulated clock.
//!
//! - Every ordered segment becomes a block the way the node's event loop
//!   builds one, written to the validator's own block store and read back
//!   through the node's storage codec before it executes, so a block the
//!   node cannot read back stops that validator's execution exactly as it
//!   stops a node.
//! - A restarted validator reopens its block store and reads its tip back.
//! - The store keeps a window of blocks, pruned through the store's own
//!   range pruning, and its size is checked against a bound.
//!
//! Transactions are routed to the validator that batches them first through
//! [`tenzro_consensus::batch::assigned_validator`], the function the node
//! routes with.

use std::collections::BTreeMap;
use std::sync::Arc;

use tenzro_storage::block_store::BlockStoreImpl;
use tenzro_storage::kv::MemoryStore;
use tenzro_storage::traits::BlockStore;
use tenzro_types::block::{Block, BlockHeader, BlockMetadata};
use tenzro_types::primitives::{Address, BlockHeight, ChainId, Hash, Nonce, Timestamp};
use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};

use crate::ledger::{self, Envelope, SimTx};

/// The transaction a node holds for a simulated one: same sender and nonce,
/// fixed times so its hash follows from the run alone.
pub fn node_transaction(tx: &SimTx) -> Transaction {
    Transaction {
        chain_id: ChainId(ledger::CHAIN_ID),
        from: Address::new(ledger::account(tx.sender())),
        to: Address::zero(),
        nonce: Nonce(tx.nonce()),
        tx_type: TransactionType::Transfer { amount: 0 },
        gas_limit: 21_000,
        gas_price: 1,
        timestamp: Timestamp(0),
        valid_until: Timestamp(i64::MAX),
        memo: None,
    }
}

/// The index, in a committee of `n`, of the validator that batches `tx`
/// first.
pub fn batching_index(tx: &SimTx, n: u64) -> u64 {
    tenzro_consensus::batch::assigned_validator(&Address::new(ledger::account(tx.sender())), n)
}

/// A segment as the node's event loop receives it.
pub struct SegmentBlock<'a> {
    pub height: u64,
    pub epoch: u64,
    pub round: u64,
    pub anchor: [u8; 32],
    pub proposer: u32,
    pub timestamp_ms: u64,
    pub txs: &'a [Envelope],
}

/// One validator's block store. It survives a crash.
pub struct NodeBlocks {
    kv: Arc<MemoryStore>,
    store: BlockStoreImpl<MemoryStore>,
    kept: u64,
    prev: Hash,
    sizes: BTreeMap<u64, u64>,
    bytes: u64,
}

impl NodeBlocks {
    /// An empty store keeping the latest `kept` blocks.
    pub fn new(kept: u64) -> Self {
        let kv = Arc::new(MemoryStore::new());
        let store = BlockStoreImpl::new(kv.clone()).expect("memory block store");
        Self {
            kv,
            store,
            kept: kept.max(1),
            prev: Hash::zero(),
            sizes: BTreeMap::new(),
            bytes: 0,
        }
    }

    /// Bytes of the blocks held.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// Builds the segment's block, stores it and reads it back as execution
    /// does. An error is what the node would stop on.
    pub fn store_and_read(&mut self, seg: &SegmentBlock<'_>) -> Result<(), String> {
        let transactions: Vec<SignedTransaction> = seg
            .txs
            .iter()
            .map(|e| SignedTransaction::external(node_transaction(&e.tx)))
            .collect();
        let header = BlockHeader {
            height: BlockHeight::from(seg.height),
            epoch: seg.epoch,
            round: seg.round,
            anchor: Hash::new(seg.anchor),
            prev_hash: self.prev,
            tx_root: Block::compute_tx_root(&transactions),
            state_root: Hash::zero(),
            event_root: Hash::zero(),
            receipts_root: Hash::new(tenzro_types::eth_receipt::EMPTY_TRIE_ROOT),
            logs_bloom: tenzro_types::LogsBloom::default(),
            timestamp: Timestamp::new(seg.timestamp_ms as i64),
            proposer: Address::new(ledger::account(seg.proposer)),
            metadata: BlockMetadata {
                gas_used: 0,
                gas_limit: transactions.iter().map(|t| t.transaction.gas_limit).sum(),
                tx_count: transactions.len() as u64,
                protocol_version: 1,
                base_fee_per_gas: Some(0),
            },
        };
        let block = Block::new(header, transactions);
        let size = serde_json::to_vec(&block)
            .map(|v| v.len() as u64)
            .unwrap_or(0);
        let hash = block.hash();
        let height = seg.height;
        let read = poll(async {
            self.store
                .put_block(&block)
                .await
                .map_err(|e| format!("store block {height}: {e}"))?;
            self.store
                .get_block_by_height(BlockHeight::from(height))
                .await
                .map_err(|e| format!("read block {height}: {e}"))
        })?;
        match read {
            Some(b) if b.hash() == hash => {}
            Some(_) => return Err(format!("block {height} read back differs")),
            None => return Err(format!("block {height} missing after store")),
        }
        self.prev = hash;
        self.bytes += size;
        if let Some(old) = self.sizes.insert(height, size) {
            self.bytes -= old;
        }
        self.prune(height);
        Ok(())
    }

    /// Reopens the store, as a restarted node does, and reads its tip back.
    pub fn reopen(&mut self) -> Result<(), String> {
        self.store = BlockStoreImpl::new(self.kv.clone()).map_err(|e| format!("reopen: {e}"))?;
        match poll(self.store.latest_block()) {
            Ok(Some(b)) => {
                self.prev = b.hash();
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(e) => Err(format!("read tip after restart: {e}")),
        }
    }

    fn prune(&mut self, tip: u64) {
        let Some(last) = tip.checked_sub(self.kept) else {
            return;
        };
        let Some((&first, _)) = self.sizes.first_key_value() else {
            return;
        };
        if first > last {
            return;
        }
        if self
            .store
            .prune_range(BlockHeight::from(first), BlockHeight::from(last))
            .is_ok()
        {
            let keep = self.sizes.split_off(&(last + 1));
            self.bytes -= self.sizes.values().sum::<u64>();
            self.sizes = keep;
        }
    }
}

/// Drives a future that never waits on anything outside itself, as the
/// in-memory store's are, to completion on this thread.
fn poll<F: std::future::Future>(f: F) -> F::Output {
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let mut f = std::pin::pin!(f);
    loop {
        if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
            return v;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn segment(height: u64, txs: &[Envelope]) -> SegmentBlock<'_> {
        SegmentBlock {
            height,
            epoch: 0,
            round: height,
            anchor: [height as u8; 32],
            proposer: 0,
            timestamp_ms: height * 500,
            txs,
        }
    }

    fn transfers(n: usize) -> Vec<Envelope> {
        (0..n)
            .map(|k| Envelope {
                submitted_ms: 0,
                tx: SimTx::Transfer {
                    from: ledger::USER_BASE + k as u32,
                    to: ledger::USER_BASE,
                    amount: 1,
                    nonce: 0,
                },
            })
            .collect()
    }

    /// A block within the limit is stored and read back; one past it is
    /// stored but cannot be read back, which stops the node.
    #[test]
    fn a_block_past_the_decode_limit_stops_execution() {
        let mut b = NodeBlocks::new(16);
        let max = tenzro_types::block::MAX_TRANSACTIONS_PER_BLOCK;
        let ok = transfers(max);
        assert!(b.store_and_read(&segment(1, &ok)).is_ok());
        let over = transfers(max + 1);
        let e = b
            .store_and_read(&segment(2, &over))
            .expect_err("refused on read");
        assert!(e.contains("too many transactions"), "{e}");
    }

    /// The store keeps its window, and a reopened store reads its tip.
    #[test]
    fn the_store_keeps_its_window_and_reopens() {
        let mut b = NodeBlocks::new(4);
        let txs = transfers(3);
        for h in 1..=20 {
            b.store_and_read(&segment(h, &txs)).expect("stored");
        }
        assert_eq!(b.sizes.len(), 4);
        assert_eq!(b.bytes(), b.sizes.values().sum::<u64>());
        b.reopen().expect("reopened");
    }

    /// One sender's transactions all go to one validator, whatever their
    /// nonces.
    #[test]
    fn one_senders_transactions_route_to_one_validator() {
        let tx = |nonce| SimTx::Transfer {
            from: ledger::USER_BASE + 7,
            to: ledger::USER_BASE,
            amount: 1,
            nonce,
        };
        let v = batching_index(&tx(0), 7);
        assert!((1..32).all(|n| batching_index(&tx(n), 7) == v));
    }
}
