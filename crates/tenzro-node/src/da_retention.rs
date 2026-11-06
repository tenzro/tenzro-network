//! This node's part in the retention of data-availability objects.
//!
//! Every object this node certifies as a committee member is recorded in
//! consensus state with a `DaRetention` transaction, which starts its
//! retention (see `tenzro_vm::native::da_retention`). Block execution
//! expires it once the retention has passed; this node then drops the
//! sliver and certificate it holds for it.
//!
//! - `tenzro_getDaObject { commitment }`: the object as chain state records
//!   it, with its expiry.
//! - `tenzro_getDaRetention {}`: the retention of each class, the totals of
//!   live and expired objects, and where expiry stands.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{Value, json};
use tenzro_types::da_retention::{DaObjectClass, DaRetentionOp};
use tenzro_vm::native::da_retention::{read_da_object, read_da_stats, read_da_sweep, retention_ms};
use tracing::{debug, info, warn};

use crate::da_committee::CertifiedObject;
use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// How often held objects are checked against chain state for expiry.
const EXPIRY_CHECK: Duration = Duration::from_secs(600);

fn err(code: i32, message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code,
        message: message.into(),
        data: None,
    }
}

/// `tenzro_getDaObject`.
pub(crate) async fn handle_get_da_object(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = crate::rpc::unwrap_param_object(params);
    let commitment = params
        .get("commitment")
        .and_then(Value::as_str)
        .map(|c| c.trim_start_matches("0x").to_ascii_lowercase())
        .ok_or_else(|| err(-32602, "'commitment' is required"))?;
    let chain = crate::rpc::chain_state(node)?;
    let object = read_da_object(&chain, &commitment)
        .ok_or_else(|| err(-32004, format!("no object {commitment} is recorded")))?;
    Ok(json!({ "object": object, "live": object.is_live() }))
}

/// `tenzro_getDaRetention`.
pub(crate) async fn handle_get_da_retention(
    node: &Arc<TenzroNode>,
    _params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let chain = crate::rpc::chain_state(node)?;
    Ok(json!({
        "retention_ms": {
            "history": retention_ms(&chain, DaObjectClass::History),
            "audit": retention_ms(&chain, DaObjectClass::Audit),
        },
        "stats": read_da_stats(&chain),
        "sweep": read_da_sweep(&chain),
    }))
}

/// Record every object this node certifies, and drop held objects chain
/// state has expired.
pub fn spawn(node: Arc<TenzroNode>) {
    let Some(mut certified) = node.take_da_recorder() else {
        return;
    };
    let recorder = node.clone();
    tokio::spawn(async move {
        while let Some(object) = certified.recv().await {
            record(&recorder, &object).await;
        }
    });
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(EXPIRY_CHECK).await;
            drop_expired(&node);
        }
    });
}

async fn record(node: &Arc<TenzroNode>, object: &CertifiedObject) {
    let op = DaRetentionOp::Record {
        commitment: hex::encode(object.commitment.as_bytes()),
        class: object.class,
        size_bytes: object.size_bytes,
    };
    match crate::rpc::submit_as_validator(
        node,
        tenzro_types::TransactionType::DaRetention { op },
        tenzro_vm::native::da_retention::GAS_DA_RECORD,
    )
    .await
    {
        Ok(_) => {
            debug!(target: "da", commitment = %object.commitment, "recorded a certified object")
        }
        Err(e) => {
            warn!(target: "da", commitment = %object.commitment, error = %e.message, "could not record a certified object")
        }
    }
}

/// Drop the slivers and certificates of every held object chain state has
/// expired. Returns how many were dropped.
pub(crate) fn drop_expired(node: &TenzroNode) -> usize {
    let (Some(backend), Some(chain)) = (node.da_committee(), crate::rpc::chain_state_of(node))
    else {
        return 0;
    };
    let store = backend.custody_store();
    let mut dropped = 0;
    for commitment in store.known_commitments() {
        let expired = read_da_object(&chain, &hex::encode(commitment.as_bytes()))
            .is_some_and(|o| !o.is_live());
        if expired {
            match store.remove(&commitment) {
                Ok(()) => dropped += 1,
                Err(e) => {
                    warn!(target: "da", %commitment, error = %e, "could not drop an expired object")
                }
            }
        }
    }
    if dropped > 0 {
        info!(target: "da", dropped, "dropped expired data-availability objects");
    }
    dropped
}
