//! The node's visibility and the operator surface that changes it.
//!
//! One setting, [`tenzro_types::Visibility`], decides for every resource this
//! node offers whether it is announced and who may use it, unless the resource
//! carries its own override. See [`tenzro_types::visibility`] for the rules.
//! The choice is persisted so a restart comes back with the visibility the
//! operator last set.

use std::sync::Arc;

use serde_json::{Value, json};
use tenzro_storage::{CF_METADATA, KvStore};
use tenzro_types::Visibility;

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// Where the operator's runtime choice is persisted.
const VISIBILITY_KEY: &[u8] = b"node_visibility";

/// The visibility the operator last set at runtime, if any.
///
/// An unreadable row is ignored with a warning rather than failing startup, and
/// the configured visibility applies.
pub fn load(storage: &Arc<dyn KvStore>) -> Option<Visibility> {
    match storage.get(CF_METADATA, VISIBILITY_KEY) {
        Ok(Some(bytes)) => match serde_json::from_slice::<Visibility>(&bytes) {
            Ok(v) => Some(v),
            Err(e) => {
                tracing::warn!(error = %e, "Unreadable node visibility; using the configured value");
                None
            }
        },
        _ => None,
    }
}

/// Persist the operator's choice.
fn store(node: &Arc<TenzroNode>, visibility: Visibility) {
    let Some(storage) = node.storage() else {
        return;
    };
    match serde_json::to_vec(&visibility) {
        Ok(bytes) => {
            if let Err(e) = storage.put(CF_METADATA, VISIBILITY_KEY, &bytes) {
                tracing::warn!(error = %e, "Could not persist the node visibility");
            }
        }
        Err(e) => tracing::warn!(error = %e, "Could not serialize the node visibility"),
    }
}

/// The served models whose effective visibility is announced, sorted, and the
/// gated (key-required) subset of them. What every announcement and provider
/// listing publishes.
pub fn announced_models(
    served: &dashmap::DashMap<String, Option<Visibility>>,
    node: Visibility,
) -> (Vec<String>, Vec<String>) {
    let mut announced = Vec::new();
    let mut key_required = Vec::new();
    for e in served.iter() {
        let visibility = Visibility::resolve(*e.value(), node);
        if visibility.is_announced() {
            announced.push(e.key().clone());
        }
        if visibility.requires_key() {
            key_required.push(e.key().clone());
        }
    }
    announced.sort();
    key_required.sort();
    (announced, key_required)
}

/// The operator's per-use price for `Public` resources, in the settlement
/// asset's smallest unit. `0` serves them free.
pub fn operator_price(node: &TenzroNode) -> u128 {
    node.config().payments.default_amount
}

/// The visibility override stored in a served-model record, exactly as it was
/// set. A record without one follows the node's visibility; no default is
/// applied on restore.
pub fn persisted_visibility(record: &Value) -> Option<Visibility> {
    record
        .get("visibility")
        .and_then(|v| v.as_str())
        .and_then(Visibility::parse)
}

/// Read a resource's `visibility` parameter.
///
/// The one resolver every load and serve path uses, for every model type: a
/// `visibility` parameter is an explicit override; no parameter means no
/// override, so the resource follows the node's visibility.
pub(crate) fn visibility_override(params: &Value) -> Result<Option<Visibility>, JsonRpcError> {
    match params.get("visibility") {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_str()
            .and_then(Visibility::parse)
            .map(Some)
            .ok_or_else(|| JsonRpcError {
                code: -32602,
                message: format!("Unknown visibility {v}. Expected 'public', 'gated' or 'private'"),
                data: None,
            }),
    }
}

/// Render the node's visibility and the resources that override it.
fn render(node: &TenzroNode) -> Value {
    let visibility = node.visibility();
    let mut overrides: Vec<Value> = node
        .served_models
        .iter()
        .filter_map(|e| {
            e.value()
                .map(|v| json!({ "resource": "model", "id": e.key(), "visibility": v.as_str() }))
        })
        .collect();
    overrides.sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
    json!({
        "visibility": visibility.as_str(),
        "announced": visibility.is_announced(),
        "requires_key": visibility.requires_key(),
        "price_per_use": operator_price(node).to_string(),
        "overrides": overrides,
    })
}

/// `tenzro_nodeVisibility` — the node's visibility and any per-resource
/// overrides.
pub(crate) async fn handle_node_visibility(node: &Arc<TenzroNode>) -> Result<Value, JsonRpcError> {
    Ok(render(node))
}

/// `tenzro_setNodeVisibility` — set the node's visibility.
///
/// Params: `{visibility: "public" | "gated" | "private"}`. Admin-gated: this is
/// the operator's own machine policy. Every resource without an override takes
/// the new value on the next announcement heartbeat, which re-announces or
/// stops announcing it.
pub(crate) async fn handle_set_node_visibility(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let params = params.unwrap_or(Value::Null);
    let visibility = visibility_override(&params)?.ok_or_else(|| JsonRpcError {
        code: -32602,
        message: "Missing 'visibility'. Expected 'public', 'gated' or 'private'".to_string(),
        data: None,
    })?;
    *node.node_visibility.write() = visibility;
    store(node, visibility);
    tracing::info!(visibility = %visibility, "Node visibility updated");
    Ok(render(node))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_parameter_is_no_override() {
        assert_eq!(visibility_override(&json!({})).unwrap(), None);
        assert_eq!(
            visibility_override(&json!({ "visibility": null })).unwrap(),
            None
        );
    }

    #[test]
    fn an_explicit_parameter_is_an_override() {
        for v in [Visibility::Public, Visibility::Gated, Visibility::Private] {
            assert_eq!(
                visibility_override(&json!({ "visibility": v.as_str() })).unwrap(),
                Some(v)
            );
        }
    }

    /// Every multi-modal loader, named as its `load_*` RPC.
    const MULTIMODAL_LOADERS: [&str; 8] = [
        "tenzro_loadForecastModel",
        "tenzro_loadVisionModel",
        "tenzro_loadTextEmbeddingModel",
        "tenzro_loadSegmentationModel",
        "tenzro_loadTextSegmentationModel",
        "tenzro_loadDetectionModel",
        "tenzro_loadAudioModel",
        "tenzro_loadVideoModel",
    ];

    async fn node() -> (Arc<TenzroNode>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("temp dir");
        let config = crate::config::NodeConfig {
            data_dir: tmp.path().to_path_buf(),
            ..crate::config::NodeConfig::default()
        };
        let node = TenzroNode::new(config).await.expect("node");
        (Arc::new(node), tmp)
    }

    /// Every model type goes through the same resolver: no parameter is no
    /// override (the model follows the node), a parameter is an override.
    #[tokio::test]
    async fn every_model_type_follows_the_node_unless_it_overrides() {
        let (node, _tmp) = node().await;
        *node.node_visibility.write() = Visibility::Private;
        for (i, method) in MULTIMODAL_LOADERS.iter().enumerate() {
            let plain = format!("plain-{i}");
            crate::rpc::record_multimodal_visibility(&node, method, &json!({}), &plain)
                .expect("recorded");
            assert_eq!(
                node.served_models.get(&plain).map(|e| *e.value()),
                Some(None),
                "{method}"
            );
            assert_eq!(
                node.model_visibility(&plain),
                Some(Visibility::Private),
                "{method}"
            );

            let overridden = format!("public-{i}");
            crate::rpc::record_multimodal_visibility(
                &node,
                method,
                &json!({ "visibility": "public" }),
                &overridden,
            )
            .expect("recorded");
            assert_eq!(
                node.model_visibility(&overridden),
                Some(Visibility::Public),
                "{method}"
            );
        }

        // The language-model serve path records the same way.
        crate::rpc::record_served_model(&node, "llm", None);
        assert_eq!(node.model_visibility("llm"), Some(Visibility::Private));
        crate::rpc::record_served_model(&node, "llm", Some(Visibility::Gated));
        assert_eq!(node.model_visibility("llm"), Some(Visibility::Gated));

        // Changing the node's visibility moves every model without an override.
        *node.node_visibility.write() = Visibility::Public;
        assert_eq!(node.model_visibility("plain-0"), Some(Visibility::Public));
        assert_eq!(node.model_visibility("llm"), Some(Visibility::Gated));
    }

    /// Boot a started node on `dir` with the given node visibility.
    async fn started(dir: &std::path::Path, visibility: Visibility) -> Arc<TenzroNode> {
        let config = crate::config::NodeConfig {
            data_dir: dir.to_path_buf(),
            visibility,
            iroh: tenzro_iroh::TenzroIrohConfig::loopback(),
            ..crate::config::NodeConfig::default()
        };
        let mut node = TenzroNode::new(config).await.expect("node");
        node.start().await.expect("start");
        Arc::new(node)
    }

    /// A restart keeps every model's visibility exactly as it was set, for
    /// every model type, with no default applied on restore: a gated model
    /// comes back gated and announced, and a model loaded without a
    /// visibility comes back following the node.
    ///
    /// The first node's persisted served-model rows are copied into a fresh
    /// data directory and a second node boots from it, because a started
    /// node's background tasks keep its own database open for the life of the
    /// process.
    #[tokio::test]
    async fn a_restart_restores_every_model_visibility_exactly() {
        use tenzro_storage::{CF_MODELS, RocksDbStore, StorageConfig};

        let first_dir = tempfile::tempdir().expect("temp dir");
        let first = started(first_dir.path(), Visibility::Public).await;
        for (i, method) in MULTIMODAL_LOADERS.iter().enumerate() {
            crate::rpc::record_multimodal_visibility(
                &first,
                method,
                &json!({ "visibility": "gated" }),
                &format!("gated-{i}"),
            )
            .expect("recorded");
            crate::rpc::record_multimodal_visibility(
                &first,
                method,
                &json!({}),
                &format!("plain-{i}"),
            )
            .expect("recorded");
        }
        crate::rpc::record_served_model(&first, "llm-gated", Some(Visibility::Gated));
        crate::rpc::record_served_model(&first, "llm-plain", None);

        let store = first.storage().cloned().expect("storage");
        let rows: Vec<(Vec<u8>, Vec<u8>)> = store
            .get_keys_with_prefix(CF_MODELS, b"served:")
            .expect("rows")
            .into_iter()
            .filter_map(|k| store.get(CF_MODELS, &k).ok().flatten().map(|v| (k, v)))
            .collect();

        // What the boot restore reads back, for every model type, including the
        // language-model rows.
        for (key, bytes) in &rows {
            let record: Value = serde_json::from_slice(bytes).expect("json");
            let id = String::from_utf8_lossy(key)
                .trim_start_matches("served:")
                .to_string();
            let expected = id.contains("gated").then_some(Visibility::Gated);
            assert_eq!(persisted_visibility(&record), expected, "{id}: {record}");
        }

        let second_dir = tempfile::tempdir().expect("temp dir");
        {
            let copy = RocksDbStore::open(&StorageConfig::new(second_dir.path().join("db")))
                .expect("open copy");
            for (key, bytes) in &rows {
                copy.put(CF_MODELS, key, bytes).expect("copy row");
            }
        }
        // The restarted node is private, so a model without an override must
        // come back private: nothing hard-coded, nothing inherited from the
        // first node.
        let second = started(second_dir.path(), Visibility::Private).await;
        for i in 0..MULTIMODAL_LOADERS.len() {
            let gated = format!("gated-{i}");
            let plain = format!("plain-{i}");
            assert_eq!(
                second.model_visibility(&gated),
                Some(Visibility::Gated),
                "{gated}"
            );
            assert_eq!(
                second.model_visibility(&plain),
                Some(Visibility::Private),
                "{plain}"
            );
        }
        let (announced, key_required) =
            announced_models(&second.served_models, second.visibility());
        for i in 0..MULTIMODAL_LOADERS.len() {
            let gated = format!("gated-{i}");
            assert!(
                announced.contains(&gated),
                "{gated} not announced after restart"
            );
            assert!(
                key_required.contains(&gated),
                "{gated} not flagged key-required"
            );
            assert!(!announced.contains(&format!("plain-{i}")));
        }

        // Public and gated models of every type are announced; private ones
        // are not.
        *second.node_visibility.write() = Visibility::Public;
        let (announced, _) = announced_models(&second.served_models, second.visibility());
        for i in 0..MULTIMODAL_LOADERS.len() {
            assert!(announced.contains(&format!("plain-{i}")));
        }
    }

    /// Each loader records through that one path.
    #[test]
    fn every_loader_records_through_the_one_resolver() {
        let src = include_str!("rpc.rs");
        for method in MULTIMODAL_LOADERS {
            assert!(
                src.contains(&format!("record_multimodal_visibility(node, \"{method}\"")),
                "{method} does not record its visibility through record_multimodal_visibility"
            );
        }
    }

    #[test]
    fn an_unknown_value_is_refused_and_names_the_three_values() {
        for bad in [
            json!({ "visibility": "network" }),
            json!({ "visibility": 3 }),
        ] {
            let err = visibility_override(&bad).expect_err("refused");
            assert_eq!(err.code, -32602);
            assert!(
                err.message.contains("'public', 'gated' or 'private'"),
                "{}",
                err.message
            );
        }
    }
}
