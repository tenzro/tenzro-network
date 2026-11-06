//! Every committed transaction under its sender and its recipient, newest
//! first, for `tenzro_getTransactionHistory`.
//!
//! Written with each block's commit, in the same batch as the block's
//! transactions. Keys under `CF_TRANSACTIONS`:
//! - `addr:<address hex>:n`: entries the address has had, u64 little endian;
//! - `addr:<address hex>:<seq, 16 hex>`: one [`AddressEntry`], JSON;
//! - `addr:from`: the first height indexed, u64 little endian.
//!
//! An address keeps its latest [`MAX_PER_ADDRESS`] entries; writing one past
//! that deletes its oldest.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tenzro_storage::{CF_TRANSACTIONS, KvStore, WriteOp};
use tenzro_types::primitives::Address;
use tenzro_types::transaction::SignedTransaction;

/// Entries one address keeps.
pub(crate) const MAX_PER_ADDRESS: u64 = 10_000;

const FROM_KEY: &[u8] = b"addr:from";

fn count_key(addr: &str) -> Vec<u8> {
    format!("addr:{addr}:n").into_bytes()
}

fn entry_key(addr: &str, seq: u64) -> Vec<u8> {
    format!("addr:{addr}:{seq:016x}").into_bytes()
}

fn key_of(a: &Address) -> String {
    hex::encode(a.as_bytes())
}

/// One transaction an address sent or received.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AddressEntry {
    /// The transaction hash, hex.
    pub tx_hash: String,
    pub height: u64,
    pub tx_index: u32,
    /// `sent`, `received`, or `self` for a transaction to its own sender.
    pub direction: String,
}

fn read_u64(store: &dyn KvStore, key: &[u8]) -> Result<Option<u64>, String> {
    match store.get(CF_TRANSACTIONS, key).map_err(|e| e.to_string())? {
        None => Ok(None),
        Some(b) => <[u8; 8]>::try_from(b.as_slice())
            .map(|a| Some(u64::from_le_bytes(a)))
            .map_err(|_| "a stored index counter is not 8 bytes".to_string()),
    }
}

/// The writes that index the transactions of the block at `height`, each
/// given with its index in the block.
pub(crate) fn block_ops(
    store: &dyn KvStore,
    height: u64,
    txs: &[(usize, SignedTransaction)],
) -> Result<Vec<WriteOp>, String> {
    block_ops_within(store, height, txs, MAX_PER_ADDRESS)
}

fn block_ops_within(
    store: &dyn KvStore,
    height: u64,
    txs: &[(usize, SignedTransaction)],
    kept: u64,
) -> Result<Vec<WriteOp>, String> {
    let put = |key: Vec<u8>, value: Vec<u8>| WriteOp::Put {
        cf: CF_TRANSACTIONS.to_string(),
        key,
        value,
    };
    let mut ops = Vec::new();
    if txs.is_empty() {
        return Ok(ops);
    }
    if read_u64(store, FROM_KEY)?.is_none() {
        ops.push(put(FROM_KEY.to_vec(), height.to_le_bytes().to_vec()));
    }
    let mut counts: HashMap<String, u64> = HashMap::new();
    for (tx_index, signed) in txs {
        let tx = &signed.transaction;
        let tx_hash = tx.hash().to_string();
        let from = key_of(&tx.from);
        let to = key_of(&tx.to);
        let mut parties = vec![(from.clone(), if from == to { "self" } else { "sent" })];
        if from != to && tx.to.as_bytes().iter().any(|b| *b != 0) {
            parties.push((to, "received"));
        }
        for (addr, direction) in parties {
            let n = match counts.get(&addr) {
                Some(n) => *n,
                None => read_u64(store, &count_key(&addr))?.unwrap_or(0),
            };
            let entry = AddressEntry {
                tx_hash: tx_hash.clone(),
                height,
                tx_index: *tx_index as u32,
                direction: direction.to_string(),
            };
            ops.push(put(
                entry_key(&addr, n),
                serde_json::to_vec(&entry).map_err(|e| e.to_string())?,
            ));
            if n >= kept {
                ops.push(WriteOp::Delete {
                    cf: CF_TRANSACTIONS.to_string(),
                    key: entry_key(&addr, n - kept),
                });
            }
            counts.insert(addr, n + 1);
        }
    }
    for (addr, n) in counts {
        ops.push(put(count_key(&addr), n.to_le_bytes().to_vec()));
    }
    Ok(ops)
}

/// A page of one address's entries, newest first.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Page {
    pub entries: Vec<AddressEntry>,
    /// Pass back as `cursor` to continue; `None` once nothing older is kept.
    pub cursor: Option<u64>,
    /// Entries the address has had.
    pub total: u64,
    /// The first height indexed, when any block has been.
    pub indexed_from: Option<u64>,
}

/// `address`'s entries older than `before` (all when `None`), newest
/// first, at most `limit`.
pub(crate) fn page(
    store: &dyn KvStore,
    address: &Address,
    before: Option<u64>,
    limit: usize,
) -> Result<Page, String> {
    page_within(store, address, before, limit, MAX_PER_ADDRESS)
}

fn page_within(
    store: &dyn KvStore,
    address: &Address,
    before: Option<u64>,
    limit: usize,
    kept: u64,
) -> Result<Page, String> {
    let addr = key_of(address);
    let total = read_u64(store, &count_key(&addr))?.unwrap_or(0);
    let oldest = total.saturating_sub(kept);
    let mut next = before.unwrap_or(total).min(total);
    let mut entries = Vec::new();
    while next > oldest && entries.len() < limit {
        next -= 1;
        if let Some(b) = store
            .get(CF_TRANSACTIONS, &entry_key(&addr, next))
            .map_err(|e| e.to_string())?
        {
            entries.push(serde_json::from_slice(&b).map_err(|e| e.to_string())?);
        }
    }
    Ok(Page {
        entries,
        cursor: (next > oldest).then_some(next),
        total,
        indexed_from: read_u64(store, FROM_KEY)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tenzro_storage::RocksDbStore;
    use tenzro_types::primitives::{ChainId, Nonce};
    use tenzro_types::transaction::{Transaction, TransactionType};

    fn tx(from: u8, to: u8, nonce: u64) -> SignedTransaction {
        let t = Transaction::new(
            ChainId::from(1),
            Address::new([from; 32]),
            Address::new([to; 32]),
            Nonce::from(nonce),
            TransactionType::Transfer { amount: 1 },
            21_000,
            1,
        );
        // A fixed stamp, so the same arguments always build the same
        // transaction and the same hash.
        let mut t = t;
        t.timestamp = tenzro_types::primitives::Timestamp::new(1_800_000_000_000);
        t.valid_until = tenzro_types::primitives::Timestamp::new(1_800_000_000_000 + 3_600_000);
        SignedTransaction::new(
            t,
            Vec::new(),
            tenzro_types::account_signature::CompositeSignature::classical(
                tenzro_types::account_signature::ClassicalProof::Raw {
                    signature: Vec::new(),
                },
            ),
        )
    }

    fn commit(store: &RocksDbStore, height: u64, txs: Vec<SignedTransaction>, kept: u64) {
        let txs: Vec<(usize, SignedTransaction)> = txs.into_iter().enumerate().collect();
        let ops = block_ops_within(store, height, &txs, kept).unwrap();
        store.write_batch(ops).unwrap();
    }

    fn hashes(p: &Page) -> Vec<(u64, u32, String)> {
        p.entries
            .iter()
            .map(|e| (e.height, e.tx_index, e.direction.clone()))
            .collect()
    }

    #[test]
    fn an_address_with_no_transactions_has_an_empty_page() {
        let dir = tempfile::tempdir().unwrap();
        let s = Arc::new(RocksDbStore::open_default(dir.path()).unwrap());
        let p = page(s.as_ref(), &Address::new([9; 32]), None, 10).unwrap();
        assert_eq!(p, Page::default());
    }

    #[test]
    fn transactions_are_indexed_under_sender_and_recipient_across_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let s = Arc::new(RocksDbStore::open_default(dir.path()).unwrap());
        commit(&s, 5, vec![tx(1, 2, 0), tx(3, 1, 0)], MAX_PER_ADDRESS);
        commit(&s, 6, vec![tx(1, 1, 1)], MAX_PER_ADDRESS);
        // Built once: a transaction carries the time it was made, so another
        // built from the same arguments a moment later hashes differently.
        let latest = tx(1, 3, 2);
        commit(&s, 7, vec![tx(2, 3, 0), latest.clone()], MAX_PER_ADDRESS);

        let one = page(s.as_ref(), &Address::new([1; 32]), None, 10).unwrap();
        assert_eq!(
            hashes(&one),
            vec![
                (7, 1, "sent".into()),
                (6, 0, "self".into()),
                (5, 1, "received".into()),
                (5, 0, "sent".into()),
            ]
        );
        assert_eq!(one.total, 4);
        assert_eq!(one.indexed_from, Some(5));
        assert_eq!(
            one.entries[0].tx_hash,
            latest.transaction.hash().to_string()
        );

        let three = page(s.as_ref(), &Address::new([3; 32]), None, 10).unwrap();
        assert_eq!(
            hashes(&three),
            vec![
                (7, 1, "received".into()),
                (7, 0, "received".into()),
                (5, 1, "sent".into()),
            ]
        );
    }

    #[test]
    fn a_cursor_pages_through_with_no_gap_and_old_entries_are_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let s = Arc::new(RocksDbStore::open_default(dir.path()).unwrap());
        for h in 0..6 {
            commit(&s, 10 + h, vec![tx(1, 2, h)], 4);
        }
        let a = Address::new([1; 32]);
        let first = page_within(s.as_ref(), &a, None, 3, 4).unwrap();
        assert_eq!(
            first.entries.iter().map(|e| e.height).collect::<Vec<_>>(),
            vec![15, 14, 13]
        );
        let rest = page_within(s.as_ref(), &a, first.cursor, 3, 4).unwrap();
        assert_eq!(
            rest.entries.iter().map(|e| e.height).collect::<Vec<_>>(),
            vec![12]
        );
        assert_eq!(rest.cursor, None);
        assert_eq!(rest.total, 6);
        assert!(
            s.get(CF_TRANSACTIONS, &entry_key(&key_of(&a), 1))
                .unwrap()
                .is_none()
        );
    }
}
