//! Every model this node holds, of every type, in one listing.
//!
//! `tenzro_listModels { "loaded": true }` answers from here: the chat models
//! and every multi-modal runtime, each row with its type, the engine holding
//! it, its effective visibility, the access that visibility grants, and
//! whether it is resident and whether it is served.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use serde_json::{Value, json};
use tenzro_storage::{CF_MODELS, KvStore};
use tenzro_types::Visibility;
use tenzro_types::resource_access::ResourceAccess;

use crate::node::TenzroNode;

/// The model type each loader produces, keyed by the loader a served record
/// names. The same names the listing reports for resident models.
const LOADER_TYPES: &[(&str, &str)] = &[
    ("tenzro_loadVisionModel", "vision"),
    ("tenzro_loadTextEmbeddingModel", "embedding"),
    ("tenzro_loadForecastModel", "forecast"),
    ("tenzro_loadSegmentationModel", "segmentation"),
    ("tenzro_loadTextSegmentationModel", "text-segmentation"),
    ("tenzro_loadDetectionModel", "detection"),
    ("tenzro_loadAudioModel", "audio"),
    ("tenzro_loadVideoModel", "video"),
    ("tenzro_loadMediaModel", "media"),
];

/// The models resident in each runtime, labelled with their type.
fn resident(node: &TenzroNode) -> Vec<(&'static str, Vec<String>)> {
    vec![
        (
            "chat",
            node.model_runtime
                .as_ref()
                .map(|rt| rt.list_loaded())
                .unwrap_or_default(),
        ),
        ("vision", node.vision_runtime.loaded_models()),
        ("embedding", node.text_embedding_runtime.loaded_models()),
        ("forecast", node.timeseries_runtime.loaded_models()),
        ("segmentation", node.segmentation_runtime.loaded_models()),
        (
            "text-segmentation",
            node.text_segmentation_runtime.loaded_models(),
        ),
        ("detection", node.detection_runtime.loaded_models()),
        ("audio", node.audio_runtime.loaded_models()),
        ("video", node.video_runtime.loaded_models()),
        ("media", node.media_models.runtime().loaded()),
    ]
}

/// The type of a served model that is not resident: the loader its record
/// names, or a chat model when the record names none (chat models load on
/// first use).
fn served_type(node: &TenzroNode, model_id: &str) -> &'static str {
    let runtime = node
        .storage()
        .and_then(|s| {
            s.get(CF_MODELS, format!("served:{model_id}").as_bytes())
                .ok()
                .flatten()
        })
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|r| {
            r.get("runtime")
                .and_then(|v| v.as_str())
                .map(str::to_string)
        });
    match runtime {
        Some(method) => LOADER_TYPES
            .iter()
            .find(|(loader, _)| *loader == method)
            .map(|(_, ty)| *ty)
            .unwrap_or("chat"),
        None => "chat",
    }
}

/// One row per model, sorted by type then id.
pub(crate) fn list(node: &Arc<TenzroNode>) -> Value {
    let engines: HashMap<String, String> = node
        .model_host
        .engine_status()
        .into_iter()
        .map(|s| (s.model_id, s.engine))
        .collect();
    let node_visibility = node.visibility();
    let price = crate::visibility_rpc::operator_price(node);

    let mut rows: BTreeMap<(&'static str, String), bool> = BTreeMap::new();
    for (ty, ids) in resident(node) {
        for id in ids {
            rows.insert((ty, id), true);
        }
    }
    for entry in node.served_models.iter() {
        let id = entry.key();
        if !rows.keys().any(|(_, held)| held == id) {
            rows.insert((served_type(node, id), id.clone()), false);
        }
    }

    let models: Vec<Value> = rows
        .into_iter()
        .map(|((ty, id), loaded)| {
            let own = node.served_models.get(&id).map(|e| *e.value());
            let serving = own.is_some();
            let visibility = Visibility::resolve(own.flatten(), node_visibility);
            let price = if crate::catalog_sync::non_commercial(node, &id) {
                0
            } else {
                price
            };
            json!({
                "model_id": id,
                "type": ty,
                "engine": engines.get(&id),
                "visibility": visibility.as_str(),
                "visibility_source": if own.flatten().is_some() { "model" } else { "node" },
                "access": ResourceAccess::from_visibility(visibility, price),
                "loaded": loaded,
                "serving": serving,
            })
        })
        .collect();
    json!({ "models": models })
}
