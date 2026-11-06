//! JSON-RPC surface of the model catalog.
//!
//! Reads only. Publishers publish entries with `tenzro_submitTrustRecord`,
//! signed on their own hardware; an operator names the publishers it serves
//! from in its configuration (`catalog_publishers`).

use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::{Value, json};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;
use crate::trust_hooks::invalid;

fn object_params(params: Option<Value>) -> Value {
    match params {
        Some(Value::Array(a)) => a.into_iter().next().unwrap_or(Value::Null),
        Some(v) => v,
        None => Value::Null,
    }
}

fn status(node: &TenzroNode) -> crate::catalog_sync::CatalogStatus {
    node.catalog_sync().map(|c| c.status()).unwrap_or_default()
}

/// The entry as published, with the billable units a call to it is charged on
/// under `billed_on`. Derived from the engine rather than carried in the
/// entry, so a publisher cannot declare a model cheaper than its engine bills.
fn with_billed_on(entry: &tenzro_model::catalog::CatalogEntry) -> Value {
    let mut value = serde_json::to_value(entry).unwrap_or(Value::Null);
    if let Some(obj) = value.as_object_mut() {
        obj.insert("billed_on".to_string(), json!(entry.model.billed_on()));
    }
    value
}

/// `tenzro_listCatalog`: optional `engine` (e.g. `gguf`, `onnx-vision`).
/// Returns every entry this node serves, and how the catalog was assembled:
/// the named publishers, its publishers, and each published model left out with
/// the reason.
pub(crate) async fn handle_list(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = object_params(params);
    let engine = p.get("engine").and_then(Value::as_str);
    let catalog = tenzro_model::catalog::store::current();
    let entries: Vec<Value> = catalog
        .entries()
        .iter()
        .filter(|e| engine.is_none_or(|want| e.model.engine() == want))
        .map(with_billed_on)
        .collect();
    Ok(json!({
        "status": status(node),
        "count": entries.len(),
        "entries": entries,
    }))
}

/// `tenzro_getCatalogEntry`: params `model`. The entry this node serves for
/// the model, with the publishers that published it and whether the
/// operator's token is needed to fetch it; for a published model the node
/// does not serve, the reason.
pub(crate) async fn handle_get(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = object_params(params);
    let model = p
        .get("model")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid("Missing model"))?;
    let status = status(node);
    let publishers: BTreeSet<String> = status.publishers.iter().cloned().collect();
    let published_by: Vec<String> = node
        .trust_ledger()
        .map(|l| l.catalog_records(&publishers))
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.model == model && r.entry.is_some())
        .map(|r| r.publisher)
        .collect();
    if let Some(entry) = tenzro_model::catalog::entry(model) {
        return Ok(json!({
            "model": model,
            "served": true,
            "publishers": published_by,
            "entry": with_billed_on(&entry),
        }));
    }
    let reason = status
        .refused
        .iter()
        .find(|r| r.model == model)
        .map(|r| r.reason.clone())
        .or(status.note)
        .unwrap_or_else(|| "no trusted publisher has published this model".into());
    Err(JsonRpcError {
        code: -32004,
        message: format!("{model} is not in this node's catalog: {reason}"),
        data: Some(json!({ "publishers": published_by })),
    })
}

/// The platform string of this build, as engine release artifacts name it.
pub(crate) fn platform() -> String {
    format!("{}-{}", std::env::consts::ARCH, std::env::consts::OS)
}

/// `tenzro_getEngineReleases`: the releases published by the publishers the
/// operator names in `release_publishers`, newest first, each marked
/// `newer` when it is newer than the running build. The node installs
/// nothing: its operator verifies and applies a release.
pub(crate) async fn handle_engine_releases(node: &Arc<TenzroNode>) -> Result<Value, JsonRpcError> {
    let running = env!("CARGO_PKG_VERSION");
    let named = node.config().release_publishers.clone();
    let ledger = node.trust_ledger();
    let publishers: BTreeSet<String> = match ledger {
        Some(l) => named
            .iter()
            .filter(|p| !p.is_empty())
            .filter(|p| !l.issuer_revoked(p) && !crate::trust_hooks::did_revoked(node)(p))
            .cloned()
            .collect(),
        None => BTreeSet::new(),
    };
    let note = named
        .is_empty()
        .then(|| "no release publisher is configured (release_publishers)".to_string());
    let releases: Vec<Value> = ledger
        .map(|l| l.engine_releases(&publishers))
        .unwrap_or_default()
        .into_iter()
        .map(|r| {
            json!({
                "version": r.version,
                "publisher": r.publisher,
                "newer": r.newer_than(running),
                "artifacts": r.artifacts,
                "record": r.document,
            })
        })
        .collect();
    let available = releases
        .iter()
        .find(|r| r["newer"] == true)
        .map(|r| r["version"].clone());
    Ok(json!({
        "running": running,
        "platform": platform(),
        "publishers": publishers,
        "available": available,
        "releases": releases,
        "note": note,
    }))
}

/// Engine-specific catalog rows as the per-modality listings return them:
/// each row with its entry's licence (`license`, `license_id`,
/// `license_tier`, `license_conditions`), whether it may be served for pay
/// (`paid_serving`) and whether it is `gated`.
pub(crate) fn with_licence<T: serde::Serialize>(rows: &[T]) -> Vec<Value> {
    rows.iter()
        .filter_map(|row| serde_json::to_value(row).ok())
        .map(|mut row| {
            let id = row
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if let (Some(entry), Some(obj)) =
                (tenzro_model::catalog::entry(&id), row.as_object_mut())
            {
                obj.insert("license".into(), json!(entry.licence.name));
                obj.insert("license_id".into(), json!(entry.licence.id));
                obj.insert("license_tier".into(), json!(entry.licence.effective_tier()));
                obj.insert(
                    "license_conditions".into(),
                    json!(entry.licence.all_conditions()),
                );
                obj.insert(
                    "paid_serving".into(),
                    json!(entry.licence.effective_tier().permits_paid_use()),
                );
                obj.insert("gated".into(), json!(entry.gated));
            }
            row
        })
        .collect()
}
