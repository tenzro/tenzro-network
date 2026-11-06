//! Rerankers: `tenzro_loadRerankModel`, `tenzro_unloadRerankModel`,
//! `tenzro_listRerankCatalog` and `tenzro_rerank` (also `POST /tenzro/rerank`;
//! no OpenAI contract exists for reranking).
//!
//! A rerank call is billed per (query, document) pair scored, and answered with a signed receipt over the request and
//! the ranked scores at the verification level the caller asked for. Scoring draws
//! nothing, so any node holding the same weights recomputes the same scores.

use std::sync::Arc;

use serde_json::{Value, json};
use tenzro_types::model::BillableUnits;

use crate::node::TenzroNode;
use crate::rpc::{
    JsonRpcError, bill_local_units, catalog_load_params, fetch_catalog_bundle, forecast_err,
    missing_param, not_in_catalog, record_multimodal_visibility, units_to_json,
};
use crate::verifiable_inference::{attach_task_receipt, task_level};

fn invalid(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

/// `tenzro_loadRerankModel`: fetch and load a catalog reranker.
/// Params: `{ model_id, visibility? }`.
#[cfg(feature = "inference")]
pub(crate) async fn handle_load(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| missing_param("params"))?;
    let model_id = catalog_load_params(&p)?;
    let entry = tenzro_model::get_rerank_model_by_id(&model_id)
        .ok_or_else(|| not_in_catalog("rerank", &model_id))?;
    let mut files = vec![entry.hf_filename.clone()];
    files.extend(entry.mmproj.iter().map(|m| m.filename.clone()));
    let (bundle_dir, provenance) =
        fetch_catalog_bundle(node, &model_id, &entry.hf_repo, files, entry.size_bytes).await?;
    let gguf = bundle_dir.join(&entry.hf_filename);
    // A vision-language reranker serves with its projector and the
    // checkpoint's picture sizing; the catalog carries both or neither.
    let projector = match (&entry.mmproj, &entry.vision_input) {
        (Some(m), Some(input)) => Some((bundle_dir.join(&m.filename), input.clone())),
        (None, None) => None,
        _ => {
            return Err(JsonRpcError {
                code: -32603,
                message: format!(
                    "{model_id}: the catalog entry carries a projector without its picture sizing, or the reverse"
                ),
                data: None,
            });
        }
    };
    let rt = node.rerank_runtime.clone();
    let id = model_id.clone();
    tokio::task::spawn_blocking(move || {
        let projector = projector
            .as_ref()
            .map(|(path, input)| tenzro_model::projector::ProjectorFile { path, input });
        rt.load(&id, &gguf, projector)
    })
    .await
    .map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("rerank load task: {e}"),
        data: None,
    })?
    .map_err(forecast_err)?;
    record_multimodal_visibility(node, "tenzro_loadRerankModel", &p, &model_id)?;
    Ok(json!({
        "model_id": model_id,
        "bundle_dir": bundle_dir.display().to_string(),
        "loaded": true,
        "provenance": provenance.to_json(),
    }))
}

/// `tenzro_unloadRerankModel`. Params: `{ model_id }`.
#[cfg(feature = "inference")]
pub(crate) async fn handle_unload(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| missing_param("params"))?;
    let model_id = p
        .get("model_id")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_param("model_id"))?;
    let removed = node.rerank_runtime.unload(model_id);
    crate::rpc::forget_multimodal_model(node, model_id);
    Ok(json!({ "model_id": model_id, "removed": removed }))
}

/// `tenzro_listRerankCatalog`.
pub(crate) async fn handle_catalog() -> Result<Value, JsonRpcError> {
    Ok(json!({
        "models": crate::catalog_rpc::with_licence(&tenzro_model::get_rerank_catalog()),
    }))
}

/// `tenzro_rerank`: score documents against a query.
///
/// Params: `{ model_id, query, documents: [input], top_n?, return_documents?,
/// verification?, receipt_nonce?, payment?, channel_voucher? }`. The query
/// and every document take the embedding input shape: a string (text) or
/// `{ text?, image?: base64, video?: [base64 frame, ...] }`; pictures and
/// video are read by vision-language rerankers. Returns the documents
/// ordered by score, best first (`top_n` of them when given), with the units
/// billed, the cost, the settlement and the signed receipt.
pub(crate) async fn handle_rerank(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.ok_or_else(|| missing_param("params"))?;
    if let Some(model_id) = p.get("model_id").and_then(Value::as_str)
        && let Some(answer) =
            crate::task_route::forward(node, "tenzro_rerank", "rerank", &p, model_id).await?
    {
        return Ok(answer);
    }
    rerank_here(node, p).await
}

/// `tenzro_rerank` on this node's own reranker.
#[cfg(feature = "inference")]
async fn rerank_here(node: &Arc<TenzroNode>, p: Value) -> Result<Value, JsonRpcError> {
    let model_id = p
        .get("model_id")
        .and_then(Value::as_str)
        .ok_or_else(|| missing_param("model_id"))?;
    let query: tenzro_model::EmbedInput = serde_json::from_value(
        p.get("query")
            .cloned()
            .ok_or_else(|| missing_param("query"))?,
    )
    .map_err(|e| invalid(format!("'query': {e}")))?;
    let raw_documents = p
        .get("documents")
        .and_then(Value::as_array)
        .ok_or_else(|| missing_param("documents"))?;
    let documents: Vec<tenzro_model::EmbedInput> = raw_documents
        .iter()
        .enumerate()
        .map(|(i, d)| {
            serde_json::from_value(d.clone()).map_err(|e| invalid(format!("document {i}: {e}")))
        })
        .collect::<Result<_, _>>()?;
    let top_n = match p.get("top_n") {
        None | Some(Value::Null) => None,
        Some(v) => Some(
            v.as_u64()
                .filter(|n| *n > 0)
                .ok_or_else(|| invalid("top_n is a positive integer"))? as usize,
        ),
    };
    let return_documents = p
        .get("return_documents")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let level = task_level(node, &p, model_id)?;

    let bytes_in = query.byte_len()
        + documents
            .iter()
            .map(tenzro_model::EmbedInput::byte_len)
            .sum::<u64>();
    let started = std::time::Instant::now();
    let scored = node
        .rerank_runtime
        .rerank(model_id, query, documents)
        .await
        .map_err(forecast_err)?;
    let latency_ms = started.elapsed().as_millis() as u64;

    // A reranker bills per (query, document) pair scored; the tokens a pair
    // took are the provider's cost, not a second charge to the caller.
    let units =
        BillableUnits::default().with_rerank_pairs(u32::try_from(scored.len()).unwrap_or(u32::MAX));
    let bytes_out = (scored.len() * std::mem::size_of::<f32>()) as u64;
    let (cost_wei, settlement) = bill_local_units(
        node,
        &p,
        model_id,
        units.clone(),
        bytes_in,
        bytes_out,
        latency_ms,
    )
    .await?;

    let mut ranked = scored;
    ranked.sort_by(|a, b| b.score.total_cmp(&a.score).then(a.index.cmp(&b.index)));
    ranked.truncate(top_n.unwrap_or(ranked.len()));
    let results: Vec<Value> = ranked
        .iter()
        .map(|s| {
            let mut r = json!({ "index": s.index, "relevance_score": s.score });
            if return_documents {
                r["document"] = raw_documents[s.index].clone();
            }
            r
        })
        .collect();
    let mut out = json!({ "model_id": model_id, "results": results });
    attach_task_receipt(node, &p, model_id, "rerank", level, units.clone(), &mut out).await?;
    if let Some(obj) = out.as_object_mut() {
        obj.insert("units".to_string(), units_to_json(&units));
        obj.insert("cost_wei".to_string(), json!(cost_wei.to_string()));
        obj.insert("settlement".to_string(), settlement.to_json());
    }
    Ok(out)
}

/// The light build runs no reranker: a call no provider offers is refused.
#[cfg(not(feature = "inference"))]
async fn rerank_here(_node: &Arc<TenzroNode>, _p: Value) -> Result<Value, JsonRpcError> {
    Err(crate::rpc::not_offered("tenzro_rerank"))
}

/// `POST /tenzro/rerank`: the body is the `tenzro_rerank` params with the
/// model named `model`; the answer is the same.
pub(crate) async fn handle_http(
    axum::extract::State(node): axum::extract::State<Arc<TenzroNode>>,
    axum::Json(mut body): axum::Json<Value>,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    if let Some(obj) = body.as_object_mut()
        && let Some(model) = obj.remove("model")
    {
        obj.insert("model_id".to_string(), model);
    }
    match handle_rerank(&node, Some(body)).await {
        Ok(v) => axum::Json(v).into_response(),
        Err(e) => {
            let status = if e.code == -32602 {
                StatusCode::BAD_REQUEST
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            };
            crate::rpc::json_error_response(
                status,
                &e.message,
                "invalid_request_error",
                &e.code.to_string(),
            )
        }
    }
}
