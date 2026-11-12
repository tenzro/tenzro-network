//! Where a stored transaction is read from.
//!
//! A finalized transaction's body is stored once, inside its block. The
//! `idx:<hash>` record in the transaction column family names the block
//! height and the position in it, and this module follows that to the body.
//! Records written before bodies were stored once hold their own copy under
//! the bare hash; it is read first, so an older store keeps working.

use tenzro_storage::{CF_TRANSACTIONS, KvStore};
use tenzro_types::primitives::BlockHeight;

/// The JSON of the transaction with hex hash `hash`, or `None` when this
/// node holds no such transaction (never finalized here, or pruned).
pub(crate) fn stored_transaction_json<S: KvStore + ?Sized>(
    store: &S,
    hash: &str,
) -> Option<Vec<u8>> {
    if let Ok(Some(own)) = store.get(CF_TRANSACTIONS, hash.as_bytes()) {
        return Some(own);
    }
    let idx = store
        .get(CF_TRANSACTIONS, format!("idx:{hash}").as_bytes())
        .ok()??;
    let at: serde_json::Value = serde_json::from_slice(&idx).ok()?;
    let height = at.get("block_height")?.as_u64()?;
    let position = at.get("tx_index")?.as_u64()? as usize;
    let block =
        tenzro_storage::block_store::read_block_by_height(store, BlockHeight(height)).ok()??;
    let tx = block.transactions.get(position)?;
    if tx.transaction.hash().to_string() != hash {
        return None;
    }
    serde_json::to_vec(tx).ok()
}
