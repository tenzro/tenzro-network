//! JSON-RPC over the committed state: state roots and proofs a light client
//! verifies with [`tenzro_storage::verify_state_proof`], and this node's
//! snapshots of the committed state.
//!
//! - `tenzro_getStateRoot { height? }` — the committed root after executing
//!   `height` (default: the latest), and the index of the checkpoint whose
//!   certificate commits it, once one does.
//! - `tenzro_getStateProof { namespace, key, height? }` — the value of one
//!   committed entry (hex, or null when absent) and a proof of it under that
//!   height's root. `namespace` is a column family name (`accounts`,
//!   `state`, ...) or `epoch` / `validator_registry`; `key` is hex.
//! - `tenzro_listSnapshots`, `tenzro_getSnapshotManifest { height }`,
//!   `tenzro_produceSnapshot` — the snapshots this node serves over iroh.

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;
use serde_json::Value;
use std::sync::Arc;
use tenzro_storage::{KvStore, StateTrie};

fn err(code: i32, message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code,
        message: message.into(),
        data: None,
    }
}

fn trie(node: &Arc<TenzroNode>) -> Result<StateTrie, JsonRpcError> {
    let storage = node
        .storage()
        .ok_or_else(|| err(-32603, "storage not initialised"))?;
    Ok(StateTrie::new(storage.clone() as Arc<dyn KvStore>))
}

fn height_param(trie: &StateTrie, params: &Value) -> Result<u64, JsonRpcError> {
    match params.get("height") {
        Some(v) => v
            .as_u64()
            .ok_or_else(|| err(-32602, "'height' must be an unsigned integer")),
        None => trie
            .latest_version()
            .map_err(|e| err(-32603, format!("state trie: {e}")))?
            .ok_or_else(|| err(-32004, "no committed state yet")),
    }
}

/// `tenzro_getStateRoot`.
pub(crate) async fn get_state_root(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.unwrap_or(Value::Null);
    let trie = trie(node)?;
    let height = height_param(&trie, &params)?;
    let root = trie
        .root_at(height)
        .map_err(|e| err(-32603, format!("state trie: {e}")))?
        .ok_or_else(|| err(-32004, format!("no committed state at height {height}")))?;
    Ok(serde_json::json!({
        "height": height,
        "state_root": root.to_string(),
        "certified_by_checkpoint": certified_by(node, height),
    }))
}

/// Index of the checkpoint whose certified state root is the post-state of
/// `height`, when one has been decided. Blocks carry the root
/// [`tenzro_consensus::STATE_ROOT_LAG`] blocks later; a checkpoint decided
/// while no block was ordered carries the root of its last block, so the
/// state after a network's last transaction is certified without a later
/// block.
fn certified_by(node: &Arc<TenzroNode>, height: u64) -> Option<u64> {
    node.consensus()?
        .checkpoint_certifying_state(height)
        .map(|cp| cp.index)
}

/// `tenzro_getStateProof`.
pub(crate) async fn get_state_proof(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.unwrap_or(Value::Null);
    let namespace = params
        .get("namespace")
        .and_then(Value::as_str)
        .ok_or_else(|| err(-32602, "missing 'namespace'"))?;
    if !tenzro_storage::state_trie::is_committed_namespace(namespace) {
        return Err(err(
            -32602,
            format!("namespace '{namespace}' is not part of the committed state"),
        ));
    }
    let key_hex = params
        .get("key")
        .and_then(Value::as_str)
        .ok_or_else(|| err(-32602, "missing 'key' (hex)"))?;
    let key = hex::decode(key_hex.trim_start_matches("0x"))
        .map_err(|e| err(-32602, format!("'key' is not hex: {e}")))?;
    let trie = trie(node)?;
    let height = height_param(&trie, &params)?;
    let root = trie
        .root_at(height)
        .map_err(|e| err(-32603, format!("state trie: {e}")))?
        .ok_or_else(|| err(-32004, format!("no committed state at height {height}")))?;
    let (value, proof) = trie
        .prove(height, namespace, &key)
        .map_err(|e| err(-32603, format!("prove: {e}")))?;
    let scheme = trie
        .scheme_at(height)
        .map_err(|e| err(-32603, format!("state trie: {e}")))?;
    Ok(serde_json::json!({
        "height": height,
        "state_root": root.to_string(),
        "state_trie_hash": scheme,
        "certified_by_checkpoint": certified_by(node, height),
        "namespace": namespace,
        "key": hex::encode(&key),
        "value": value.map(hex::encode),
        "proof": proof,
    }))
}

/// `tenzro_listSnapshots`.
pub(crate) async fn list_snapshots(node: &Arc<TenzroNode>) -> Result<Value, JsonRpcError> {
    let store = node
        .snapshot_store()
        .ok_or_else(|| err(-32603, "snapshot store not initialised"))?;
    let snapshots = store
        .list()
        .await
        .map_err(|e| err(-32603, format!("list snapshots: {e}")))?;
    let endpoint = node
        .iroh_resolver
        .as_ref()
        .map(|r| r.endpoint_id().to_string());
    Ok(serde_json::json!({ "snapshots": snapshots, "endpoint_id": endpoint }))
}

/// `tenzro_getSnapshotManifest`.
pub(crate) async fn get_snapshot_manifest(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.unwrap_or(Value::Null);
    let height = params
        .get("height")
        .and_then(Value::as_u64)
        .ok_or_else(|| err(-32602, "missing or invalid 'height'"))?;
    let store = node
        .snapshot_store()
        .ok_or_else(|| err(-32603, "snapshot store not initialised"))?;
    let manifest = store
        .manifest(height)
        .await
        .map_err(|e| err(-32603, format!("manifest: {e}")))?
        .ok_or_else(|| err(-32004, format!("no snapshot at height {height}")))?;
    serde_json::to_value(manifest).map_err(|e| err(-32603, format!("serialize manifest: {e}")))
}

/// `tenzro_produceSnapshot`: a snapshot of the committed state at the start
/// of the current epoch, the most recent height a snapshot can be taken at.
pub(crate) async fn produce_snapshot(node: &Arc<TenzroNode>) -> Result<Value, JsonRpcError> {
    let store = node
        .snapshot_store()
        .ok_or_else(|| err(-32603, "snapshot store not initialised"))?;
    node.consensus()
        .ok_or_else(|| err(-32603, "no consensus engine on this node"))?;
    let tip = trie(node)?
        .latest_version()
        .map_err(|e| err(-32603, format!("state trie: {e}")))?
        .unwrap_or(0);
    let storage = node
        .storage()
        .ok_or_else(|| err(-32603, "storage not initialised"))?;
    let epoch_start = crate::snapshot::latest_epoch_open(
        storage,
        tip.saturating_sub(tenzro_consensus::STATE_ROOT_LAG),
    )
    .await
    .map_err(|e| err(-32603, format!("epoch start: {e}")))?
    .ok_or_else(|| {
        err(
            -32000,
            "no snapshot can be taken: no epoch has opened with its blocks committed",
        )
    })?;
    let manifest = store
        .produce(epoch_start)
        .await
        .map_err(|e| err(-32603, format!("produce snapshot: {e}")))?;
    Ok(serde_json::json!({
        "height": manifest.height,
        "state_root": manifest.state_root.to_string(),
        "buckets": manifest.buckets.len(),
    }))
}
