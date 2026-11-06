//! Ethereum block parameters (EIP-1898) and the state they name.
//!
//! A block parameter is a tag (`latest`, `pending`, `safe`, `finalized`,
//! `earliest`), a hex height, or `{blockNumber}` / `{blockHash,
//! requireCanonical}`. Ordered blocks are final, so `latest`, `pending` and
//! `safe` name the executed tip; `finalized` names the highest height a
//! checkpoint certificate covers. State below the tip is read from the
//! height-versioned state trie, which keeps the last
//! `STATE_TRIE_RETAIN_HEIGHTS` heights; older state is refused with the
//! standard missing-trie error, never answered from the tip.

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;
use serde_json::Value;
use std::sync::Arc;
use tenzro_storage::state_trie::is_committed_cf;
use tenzro_storage::{
    BlockStoreImpl, KvStore, Result as StorageResult, StateTrie, StorageError, WriteOp,
};
use tenzro_types::primitives::{BlockHeight, Hash};

fn header_not_found() -> JsonRpcError {
    JsonRpcError {
        code: -32000,
        message: "header not found".to_string(),
        data: None,
    }
}

fn invalid(message: String) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message,
        data: None,
    }
}

fn block_store(
    node: &TenzroNode,
) -> Result<BlockStoreImpl<tenzro_storage::RocksDbStore>, JsonRpcError> {
    let storage = node.storage().ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "storage not initialized".to_string(),
        data: None,
    })?;
    BlockStoreImpl::new(storage.clone()).map_err(|e| JsonRpcError {
        code: -32000,
        message: format!("block store: {e}"),
        data: None,
    })
}

/// The height a named tag stands for, or `None` when `tag` is not one.
pub(crate) fn tag_height(node: &TenzroNode, tag: &str) -> Option<Result<u64, JsonRpcError>> {
    let tip = node.chain_tip_height();
    Some(match tag {
        "latest" | "pending" | "safe" => Ok(tip),
        "earliest" => Ok(0),
        "finalized" => match node.consensus() {
            Some(c) => Ok(c.certified_height().min(tip)),
            None => Err(JsonRpcError {
                code: -32000,
                message: "finalized block not found".to_string(),
                data: None,
            }),
        },
        _ => return None,
    })
}

fn quantity(s: &str) -> Result<u64, JsonRpcError> {
    let digits = s.strip_prefix("0x").ok_or_else(|| {
        invalid(format!(
            "block number must be a 0x-prefixed hex quantity, got {s}"
        ))
    })?;
    u64::from_str_radix(digits, 16).map_err(|_| invalid(format!("invalid block number {s}")))
}

async fn height_of_hash(node: &TenzroNode, s: &str) -> Result<u64, JsonRpcError> {
    let bytes: [u8; 32] = hex::decode(s.trim_start_matches("0x"))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| invalid(format!("blockHash must be 32 bytes, got {s}")))?;
    use tenzro_storage::BlockStore as _;
    let block = block_store(node)?
        .get_block(&Hash::new(bytes))
        .await
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("block store: {e}"),
            data: None,
        })?
        .ok_or_else(header_not_found)?;
    Ok(block.height().0)
}

/// The height an Ethereum block parameter names; an absent parameter is
/// `latest`. A height above the tip, or an unknown hash, is "header not
/// found".
pub(crate) async fn block_height(
    node: &TenzroNode,
    param: Option<&Value>,
) -> Result<u64, JsonRpcError> {
    let height = match param {
        None | Some(Value::Null) => node.chain_tip_height(),
        Some(Value::String(s)) => match tag_height(node, s) {
            Some(h) => h?,
            // A bare 32-byte hash is accepted as a block hash.
            None if s.len() == 66 => height_of_hash(node, s).await?,
            None => quantity(s)?,
        },
        Some(Value::Number(n)) => n
            .as_u64()
            .ok_or_else(|| invalid(format!("invalid block number {n}")))?,
        Some(Value::Object(o)) => match (o.get("blockNumber"), o.get("blockHash")) {
            (Some(Value::String(n)), None) => quantity(n)?,
            // Ordered blocks never reorganize, so every stored block is
            // canonical and `requireCanonical` always holds.
            (None, Some(Value::String(h))) => height_of_hash(node, h).await?,
            _ => {
                return Err(invalid(
                    "block parameter needs exactly one of blockNumber or blockHash".to_string(),
                ));
            }
        },
        Some(other) => return Err(invalid(format!("invalid block parameter {other}"))),
    };
    if height > node.chain_tip_height() {
        return Err(header_not_found());
    }
    Ok(height)
}

/// The block stored at `height`.
pub(crate) async fn block_at(
    node: &TenzroNode,
    height: u64,
) -> Result<tenzro_types::Block, JsonRpcError> {
    use tenzro_storage::BlockStore as _;
    block_store(node)?
        .get_block_by_height(BlockHeight::new(height))
        .await
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("block store: {e}"),
            data: None,
        })?
        .ok_or_else(header_not_found)
}

/// Chain state after the block at `height`: the committed state at the tip,
/// the state trie's version below it.
pub(crate) fn state_at(
    node: &TenzroNode,
    height: u64,
) -> Result<tenzro_vm::StateAdapter, JsonRpcError> {
    let storage = node.storage().ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "storage not initialized".to_string(),
        data: None,
    })?;
    let store = storage.clone() as Arc<dyn KvStore>;
    if height >= node.chain_tip_height() {
        return Ok(tenzro_vm::StateAdapter::with_storage(store));
    }
    let trie = StateTrie::new(store);
    match trie.root_at(height) {
        Ok(Some(_)) => Ok(tenzro_vm::StateAdapter::with_storage(Arc::new(
            StateAtHeight { trie, height },
        ))),
        Ok(None) => Err(JsonRpcError {
            code: -32000,
            message: format!(
                "missing trie node: the state of block {height} is not retained by this node"
            ),
            data: None,
        }),
        Err(e) => Err(JsonRpcError {
            code: -32000,
            message: format!("state trie: {e}"),
            data: None,
        }),
    }
}

/// A read-only key-value view of the committed state as of one height.
/// Only committed column families have history; anything else, and every
/// write or scan, is refused rather than answered from current state.
struct StateAtHeight {
    trie: StateTrie,
    height: u64,
}

fn refused(what: &str) -> StorageError {
    StorageError::DatabaseError(format!(
        "historical state is read-only and keyed: {what} is refused"
    ))
}

impl KvStore for StateAtHeight {
    fn get(&self, cf: &str, key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
        if !is_committed_cf(cf) {
            return Err(StorageError::DatabaseError(format!(
                "column family {cf} has no history"
            )));
        }
        self.trie.get(self.height, cf, key)
    }

    fn put(&self, _cf: &str, _key: &[u8], _value: &[u8]) -> StorageResult<()> {
        Err(refused("a write"))
    }

    fn delete(&self, _cf: &str, _key: &[u8]) -> StorageResult<()> {
        Err(refused("a delete"))
    }

    fn write_batch(&self, _operations: Vec<WriteOp>) -> StorageResult<()> {
        Err(refused("a write"))
    }

    fn write_batch_sync(&self, _operations: Vec<WriteOp>) -> StorageResult<()> {
        Err(refused("a write"))
    }

    fn get_keys_with_prefix(&self, _cf: &str, _prefix: &[u8]) -> StorageResult<Vec<Vec<u8>>> {
        Err(refused("a prefix scan"))
    }
}
