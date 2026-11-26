//! The app transport's JSON-RPC methods: where devices reach the listener and
//! which certificates to pin, and what it has carried.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

use super::AppTransport;

fn not_running() -> JsonRpcError {
    JsonRpcError {
        code: -32404,
        message: "this node runs no app transport".to_string(),
        data: None,
    }
}

fn refused(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32004,
        message: message.into(),
        data: None,
    }
}

fn listener(node: &TenzroNode) -> Result<&Arc<AppTransport>, JsonRpcError> {
    node.app_transport().ok_or_else(not_running)
}

/// `tenzro_getAppTransportInfo`: the URL devices reach the listener under and,
/// when the node mints its own certificates, their hashes signed by the key
/// the node's access tokens verify under.
pub(crate) async fn handle_info(node: &Arc<TenzroNode>) -> Result<Value, JsonRpcError> {
    let listener = listener(node)?;
    let engine = node
        .auth_engine()
        .ok_or_else(|| refused("this node issues no access tokens, so no device can sign in"))?;
    let publication = listener
        .publish(engine.signer().as_ref(), &engine.config().issuer)
        .transpose()
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("sign the pinned certificates: {e}"),
            data: None,
        })?;
    Ok(json!({
        "url": listener.url(),
        "publication": publication,
    }))
}

/// `tenzro_getAppTransportUsage`: what the app transport carried for the signed-in
/// caller, or for every identity when the caller administers the node.
pub(crate) async fn handle_usage(
    node: &Arc<TenzroNode>,
    caller: Option<&str>,
) -> Result<Value, JsonRpcError> {
    let listener = listener(node)?;
    let did = caller.ok_or_else(|| refused("sign in to read what was carried for you"))?;
    let meter = listener.meter();
    if node.access().is_admin(node, did) {
        let all: Vec<Value> = meter
            .all()
            .into_iter()
            .map(|(who, usage)| json!({ "did": who, "usage": usage }))
            .collect();
        return Ok(json!({ "all": all }));
    }
    Ok(json!({ "did": did, "usage": meter.usage(did) }))
}
