//! Distributed MoE expert execution — the tensor-shipping layer on top of
//! the shard-view planner in `rpc_integrations.rs`.
//!
//! Three surfaces live here:
//!
//! 1. [`MoeIrohDispatcher`] — the `tenzro/moe` iroh ALPN server half.
//!    Expert holders answer `moe/execute` (batched expert-FFN forward)
//!    and `moe/status` (resident experts/gates) over length-prefixed
//!    JSON-RPC 2.0 frames. Registered at iroh bind time in `node.rs`;
//!    it needs only the [`MoeExpertRuntime`], not the full node.
//!
//! 2. Blob-load / local-execute RPC handlers (`tenzro_moeExpertLoad`,
//!    `tenzro_moeGateLoad`, `tenzro_moeExpertUnload`, `tenzro_moeGateUnload`,
//!    `tenzro_moeExpertStatus`, `tenzro_moeRoute`, `tenzro_moeExecute`) —
//!    the operator/provider surface for admitting per-expert safetensors
//!    blobs (inline base64 or `tenzro://` URI via iroh-blobs) and the
//!    HTTP fallback target router peers POST to when a holder has no
//!    reachable iroh endpoint.
//!
//! 3. [`handle_moe_forward`] — the router-peer client: gate-route a
//!    hidden-state batch locally, build the dispatch plan against the
//!    provider shard view, fan out per-holder batches concurrently
//!    (local runtime first, then iroh `tenzro/moe`, then HTTP JSON-RPC
//!    fallback), and gather the gate-weighted combination.
//!
//! Hidden-state tensors ride as base64 of little-endian `f32` bytes in
//! every JSON surface (see `tenzro_model::moe_exec::f32_base64`).

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use serde_json::{json, Value};
use tracing::{debug, warn};

use tenzro_iroh::{
    jsonrpc_call, EndpointId, IrohError, IrohResolver, IrohResult, JsonRpcDispatcher, ALPN_MOE,
};
use tenzro_model::{
    to_token_routing, ExpertBatch, ExpertExecuteRequest, ExpertExecuteResponse, ExpertQuantPlan,
    MoeCombiner, MoeExpertRuntime, MoeExtractor, MoeTensorNaming, QuantKind, RoutedToken,
};
use tenzro_types::tenzro_uri::TenzroUri;
use tenzro_types::{MoeExpertHolding, MoeExpertResidency};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// Wire method for batched expert-FFN execution on the `tenzro/moe` ALPN.
pub const MOE_METHOD_EXECUTE: &str = "moe/execute";
/// Wire method for the resident-expert snapshot on the `tenzro/moe` ALPN.
pub const MOE_METHOD_STATUS: &str = "moe/status";

// ---------------------------------------------------------------------------
// f32 <-> base64 helpers (JSON param surface)
// ---------------------------------------------------------------------------

fn decode_f32_base64(s: &str) -> Result<Vec<f32>, String> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|e| format!("invalid base64: {e}"))?;
    if bytes.len() % 4 != 0 {
        return Err("f32 payload length is not a multiple of 4 bytes".into());
    }
    Ok(bytes
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect())
}

fn encode_f32_base64(v: &[f32]) -> String {
    let mut bytes = Vec::with_capacity(v.len() * 4);
    for x in v {
        bytes.extend_from_slice(&x.to_le_bytes());
    }
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

// ---------------------------------------------------------------------------
// tenzro/moe ALPN server half
// ---------------------------------------------------------------------------

/// `JsonRpcDispatcher` for the `tenzro/moe` iroh ALPN.
///
/// Unlike the A2A/MCP dispatchers (which need the full node state and use
/// deferred trampolines), this dispatcher depends only on the
/// [`MoeExpertRuntime`], which exists before the iroh endpoint binds — so
/// the real dispatcher is registered directly at bind time.
pub struct MoeIrohDispatcher {
    runtime: Arc<MoeExpertRuntime>,
}

impl std::fmt::Debug for MoeIrohDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MoeIrohDispatcher").finish_non_exhaustive()
    }
}

impl MoeIrohDispatcher {
    /// Wrap the shared expert runtime for iroh-side dispatch.
    pub fn new(runtime: Arc<MoeExpertRuntime>) -> Self {
        Self { runtime }
    }

    fn handle(&self, method: &str, params: Option<Value>, id: Value) -> Value {
        match method {
            MOE_METHOD_EXECUTE => {
                let req: ExpertExecuteRequest =
                    match serde_json::from_value(params.unwrap_or(Value::Null)) {
                        Ok(r) => r,
                        Err(e) => {
                            return error_envelope(
                                id,
                                -32602,
                                format!("invalid moe/execute params: {e}"),
                            )
                        }
                    };
                match self.runtime.execute(&req) {
                    Ok(resp) => match serde_json::to_value(&resp) {
                        Ok(v) => json!({ "jsonrpc": "2.0", "result": v, "id": id }),
                        Err(e) => error_envelope(id, -32603, format!("encode response: {e}")),
                    },
                    Err(e) => error_envelope(id, -32004, format!("{e}")),
                }
            }
            MOE_METHOD_STATUS => match serde_json::to_value(self.runtime.status()) {
                Ok(v) => json!({ "jsonrpc": "2.0", "result": v, "id": id }),
                Err(e) => error_envelope(id, -32603, format!("encode status: {e}")),
            },
            other => error_envelope(id, -32601, format!("unknown method: {other}")),
        }
    }
}

fn error_envelope(id: Value, code: i64, message: String) -> Value {
    json!({
        "jsonrpc": "2.0",
        "error": { "code": code, "message": message },
        "id": id,
    })
}

#[async_trait]
impl JsonRpcDispatcher for MoeIrohDispatcher {
    async fn dispatch(&self, request: Bytes) -> IrohResult<Bytes> {
        // JSON parse error → JSON-RPC -32700 envelope (per spec). Don't
        // surface this as a transport error — that would close the stream.
        let req: Value = match serde_json::from_slice(&request) {
            Ok(v) => v,
            Err(e) => {
                let body =
                    serde_json::to_vec(&error_envelope(Value::Null, -32700, format!("{e}")))
                        .map_err(|e| IrohError::Backend(format!("encode parse-error: {e}")))?;
                return Ok(Bytes::from(body));
            }
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = req.get("params").cloned();

        // Expert-FFN matmuls are CPU-bound; keep them off the QUIC driver.
        let this = MoeIrohDispatcher {
            runtime: Arc::clone(&self.runtime),
        };
        let method_owned = method.to_string();
        let resp = tokio::task::spawn_blocking(move || this.handle(&method_owned, params, id))
            .await
            .map_err(|e| IrohError::Backend(format!("moe dispatch join: {e}")))?;

        let body = serde_json::to_vec(&resp)
            .map_err(|e| IrohError::Backend(format!("encode response: {e}")))?;
        Ok(Bytes::from(body))
    }
}

// ---------------------------------------------------------------------------
// Param helpers
// ---------------------------------------------------------------------------

fn missing(field: &str) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: format!("missing {field}"),
        data: None,
    }
}

fn req_str<'a>(p: &'a Value, field: &str) -> Result<&'a str, JsonRpcError> {
    p.get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| missing(field))
}

fn req_u32(p: &Value, field: &str) -> Result<u32, JsonRpcError> {
    p.get(field)
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .ok_or_else(|| missing(field))
}

/// Map a quant tag (`"q8_0"` / `"q4_k"` / `"q6_k"`) to a [`QuantKind`].
fn parse_quant_kind(tag: &str) -> Result<QuantKind, JsonRpcError> {
    match tag {
        "q8_0" => Ok(QuantKind::Q8_0),
        "q4_k" => Ok(QuantKind::Q4K),
        "q6_k" => Ok(QuantKind::Q6K),
        other => Err(JsonRpcError {
            code: -32602,
            message: format!("unknown quant kind '{other}': expected q8_0, q4_k, or q6_k"),
            data: None,
        }),
    }
}

/// Parse an optional `quant` param into a prepare-time quant plan. Accepts
/// either a preset string (`"q4_k_m"` / `"q8_0"` / `"q4_k"` / `"q6_k"`) that
/// applies a per-projection plan, or an object with explicit per-projection
/// tags: `{ "gate": "q4_k", "up": "q4_k", "down": "q6_k" }` (any projection
/// omitted stays dense f32). Returns `None` when the param is absent.
fn parse_quant_plan(p: &Value) -> Result<Option<ExpertQuantPlan>, JsonRpcError> {
    let Some(q) = p.get("quant") else {
        return Ok(None);
    };
    if q.is_null() {
        return Ok(None);
    }
    if let Some(tag) = q.as_str() {
        let plan = match tag {
            "q4_k_m" => ExpertQuantPlan::q4_k_m(),
            other => ExpertQuantPlan::uniform(parse_quant_kind(other)?),
        };
        return Ok(Some(plan));
    }
    if let Some(obj) = q.as_object() {
        let per = |key: &str| -> Result<Option<QuantKind>, JsonRpcError> {
            match obj.get(key).and_then(|v| v.as_str()) {
                Some(tag) => Ok(Some(parse_quant_kind(tag)?)),
                None => Ok(None),
            }
        };
        return Ok(Some(ExpertQuantPlan {
            gate: per("gate")?,
            up: per("up")?,
            down: per("down")?,
        }));
    }
    Err(JsonRpcError {
        code: -32602,
        message: "quant must be a preset string or a per-projection object".into(),
        data: None,
    })
}

/// Resolve an expert/gate weight blob from the params: either inline
/// `blob_base64` or a content-addressed `uri` (`tenzro://blob/<hash>` or
/// any hash-bearing variant) fetched over iroh-blobs.
async fn resolve_blob(node: &Arc<TenzroNode>, p: &Value) -> Result<Vec<u8>, JsonRpcError> {
    if let Some(b64) = p.get("blob_base64").and_then(|v| v.as_str()) {
        return base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .map_err(|e| JsonRpcError {
                code: -32602,
                message: format!("invalid blob_base64: {e}"),
                data: None,
            });
    }
    if let Some(uri_str) = p.get("uri").and_then(|v| v.as_str()) {
        let uri = TenzroUri::parse(uri_str).map_err(|e| JsonRpcError {
            code: -32602,
            message: format!("invalid uri: {e}"),
            data: None,
        })?;
        let resolver = node.iroh_resolver.as_ref().ok_or_else(|| JsonRpcError {
            code: -32000,
            message: "iroh resolver not bound — cannot fetch blob by uri".into(),
            data: None,
        })?;
        let bytes = resolver.fetch_bytes(&uri).await.map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("blob fetch: {e}"),
            data: None,
        })?;
        return Ok(bytes.to_vec());
    }
    Err(missing("blob_base64 or uri"))
}

fn routed_to_json(routed: &[RoutedToken]) -> Vec<Value> {
    routed
        .iter()
        .map(|t| {
            json!({
                "token_index": t.token_index,
                "slots": t.slots.iter().map(|s| json!({
                    "layer": s.expert.layer,
                    "expert": s.expert.expert,
                    "weight": s.weight,
                })).collect::<Vec<_>>(),
            })
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Expert-holder RPC handlers (load / unload / status / route / execute)
// ---------------------------------------------------------------------------

/// Rebuild this node's MoE declaration on the ProviderManager from the
/// live expert runtime, so the next provider heartbeat gossips the current
/// holdings and roles to the rest of the network.
fn sync_moe_declaration(node: &Arc<TenzroNode>) {
    let Some(pm) = node.provider_manager() else {
        debug!("MoE declaration sync skipped: no provider manager");
        return;
    };
    let Some(address) = node.self_provider_address() else {
        warn!("MoE declaration sync skipped: no self provider address");
        return;
    };
    let status = node.moe_runtime.status();
    let holdings: Vec<MoeExpertHolding> = status
        .experts
        .iter()
        .map(|e| MoeExpertHolding {
            model_id: e.model_id.clone(),
            layer: e.layer,
            expert: e.expert,
            residency: match e.tier {
                tenzro_model::ExpertTier::Memory => MoeExpertResidency::Warm,
                tenzro_model::ExpertTier::Disk => MoeExpertResidency::Cold,
            },
            committed_tps: 0,
        })
        .collect();
    let is_router = !status.gates.is_empty();
    let iroh_endpoint_id = node
        .iroh_resolver
        .as_ref()
        .map(|r| r.endpoint_id().to_string());
    let config = node.config();
    let endpoint_url = config
        .external_rpc_addr
        .clone()
        .unwrap_or_else(|| format!("http://{}", config.rpc_addr));
    pm.set_moe_declaration(
        address,
        Some(endpoint_url),
        holdings,
        is_router,
        iroh_endpoint_id,
        status.gpu,
    );
}

/// `tenzro_moeExpertLoad` — decode a per-expert safetensors blob
/// (gate/up/down projections) and admit it into the local expert runtime.
/// Blob source: inline `blob_base64` or content-addressed `uri`.
pub(crate) async fn handle_moe_expert_load(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.unwrap_or(json!({}));
    let model_id = req_str(&p, "model_id")?.to_string();
    let layer = req_u32(&p, "layer")?;
    let expert = req_u32(&p, "expert")?;
    let blob = resolve_blob(node, &p).await?;

    let runtime = Arc::clone(&node.moe_runtime);
    let row = tokio::task::spawn_blocking(move || runtime.load_expert(model_id, layer, expert, &blob))
        .await
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("load join: {e}"),
            data: None,
        })?
        .map_err(|e| JsonRpcError {
            code: -32004,
            message: format!("expert load: {e}"),
            data: None,
        })?;
    sync_moe_declaration(node);
    serde_json::to_value(&row).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize: {e}"),
        data: None,
    })
}

/// `tenzro_moeGateLoad` — decode a gating-network blob (`router.weight`)
/// and admit it for `(model_id, layer)`. Blob source as for expert load.
pub(crate) async fn handle_moe_gate_load(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.unwrap_or(json!({}));
    let model_id = req_str(&p, "model_id")?.to_string();
    let layer = req_u32(&p, "layer")?;
    let blob = resolve_blob(node, &p).await?;

    let runtime = Arc::clone(&node.moe_runtime);
    let row = tokio::task::spawn_blocking(move || runtime.load_gate(model_id, layer, &blob))
        .await
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("load join: {e}"),
            data: None,
        })?
        .map_err(|e| JsonRpcError {
            code: -32004,
            message: format!("gate load: {e}"),
            data: None,
        })?;
    sync_moe_declaration(node);
    serde_json::to_value(&row).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize: {e}"),
        data: None,
    })
}

/// `tenzro_moeExpertUnload` — drop one resident expert.
pub(crate) async fn handle_moe_expert_unload(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.unwrap_or(json!({}));
    let model_id = req_str(&p, "model_id")?;
    let layer = req_u32(&p, "layer")?;
    let expert = req_u32(&p, "expert")?;
    let removed = node.moe_runtime.unload_expert(model_id, layer, expert);
    if removed {
        sync_moe_declaration(node);
    }
    Ok(json!({
        "model_id": model_id,
        "layer": layer,
        "expert": expert,
        "removed": removed,
    }))
}

/// `tenzro_moeGateUnload` — drop one resident gating network.
pub(crate) async fn handle_moe_gate_unload(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.unwrap_or(json!({}));
    let model_id = req_str(&p, "model_id")?;
    let layer = req_u32(&p, "layer")?;
    let removed = node.moe_runtime.unload_gate(model_id, layer);
    if removed {
        sync_moe_declaration(node);
    }
    Ok(json!({
        "model_id": model_id,
        "layer": layer,
        "removed": removed,
    }))
}

/// `tenzro_moeExpertStatus` — snapshot of resident experts and gates.
pub(crate) async fn handle_moe_expert_status(
    node: &Arc<TenzroNode>,
) -> Result<Value, JsonRpcError> {
    serde_json::to_value(node.moe_runtime.status()).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize: {e}"),
        data: None,
    })
}

/// `tenzro_moeRoute` — run the locally-loaded gating network over a
/// hidden-state batch and return the per-token top-k expert selection
/// with renormalized weights.
pub(crate) async fn handle_moe_route(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.unwrap_or(json!({}));
    let model_id = req_str(&p, "model_id")?;
    let layer = req_u32(&p, "layer")?;
    let d_model = req_u32(&p, "d_model")? as usize;
    let hidden = decode_f32_base64(req_str(&p, "hidden_states")?).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("hidden_states: {e}"),
        data: None,
    })?;
    let top_k = resolve_top_k(&p, model_id)?;

    let routed = node
        .moe_runtime
        .route(model_id, layer, d_model, &hidden, top_k)
        .map_err(|e| JsonRpcError {
            code: -32004,
            message: format!("moe route: {e}"),
            data: None,
        })?;
    Ok(json!({
        "model_id": model_id,
        "layer": layer,
        "top_k": top_k,
        "tokens": routed.len(),
        "routed": routed_to_json(&routed),
    }))
}

/// `tenzro_moeExecute` — execute one batched expert-FFN request against
/// the local runtime. This is also the HTTP fallback target that router
/// peers POST to when a holder has no reachable iroh endpoint.
pub(crate) async fn handle_moe_execute(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let req: ExpertExecuteRequest =
        serde_json::from_value(params.unwrap_or(Value::Null)).map_err(|e| JsonRpcError {
            code: -32602,
            message: format!("invalid execute params: {e}"),
            data: None,
        })?;
    let runtime = Arc::clone(&node.moe_runtime);
    let resp = tokio::task::spawn_blocking(move || runtime.execute(&req))
        .await
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("execute join: {e}"),
            data: None,
        })?
        .map_err(|e| JsonRpcError {
            code: -32004,
            message: format!("moe execute: {e}"),
            data: None,
        })?;
    serde_json::to_value(&resp).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize: {e}"),
        data: None,
    })
}

// ---------------------------------------------------------------------------
// Registry-native expert extraction (tenzro_moePrepareExperts)
// ---------------------------------------------------------------------------

/// One published expert blob produced by a prepare job.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MoePreparedExpert {
    pub expert: u32,
    pub uri: String,
    pub bytes: u64,
    /// Coarsest quant tag of the published blob (`"q4_k"` / `"q6_k"` /
    /// `"q8_0"`), or `None` when the blob is dense f32.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quant: Option<String>,
}

/// The published gating-network blob produced by a prepare job.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MoePreparedGate {
    pub uri: String,
    pub bytes: u64,
}

/// Background expert-extraction job snapshot, keyed by job id in
/// `TenzroNode::moe_prepare_jobs` and read by `tenzro_moePrepareStatus`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MoePrepareJob {
    pub model_id: String,
    pub layer: u32,
    /// "running" | "completed" | "failed"
    pub state: String,
    pub error: Option<String>,
    pub total_experts: u32,
    pub completed_experts: u32,
    pub experts: Vec<MoePreparedExpert>,
    pub gate: Option<MoePreparedGate>,
}

/// `tenzro_moePrepareExperts` — extract per-expert (and optionally gate)
/// safetensors blobs for a catalog MoE model directly from its original
/// checkpoint via HTTP-Range tensor fetches, publish each blob into the
/// iroh blob store, and return a job id. Progress and the resulting
/// `tenzro://blob/` URIs are read back with `tenzro_moePrepareStatus`;
/// the URIs feed `tenzro_moeExpertLoad` / `tenzro_moeGateLoad` on any
/// node in the network.
pub(crate) async fn handle_moe_prepare_experts(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.unwrap_or(json!({}));
    let model_id = req_str(&p, "model_id")?.to_string();
    let layer = req_u32(&p, "layer")?;
    let include_gate = p.get("include_gate").and_then(|v| v.as_bool()).unwrap_or(true);
    let quant_plan = parse_quant_plan(&p)?;

    let entry = tenzro_model::catalog::get_model_by_id(&model_id).ok_or_else(|| JsonRpcError {
        code: -32602,
        message: format!("unknown catalog model_id: {model_id}"),
        data: None,
    })?;
    let shape = entry.moe.ok_or_else(|| JsonRpcError {
        code: -32602,
        message: format!("{model_id} is not a MoE catalog entry"),
        data: None,
    })?;
    let repo =
        tenzro_model::catalog::moe_safetensors_repo(&model_id).ok_or_else(|| JsonRpcError {
            code: -32004,
            message: format!("no safetensors checkpoint source mapped for {model_id}"),
            data: None,
        })?;
    let naming =
        MoeTensorNaming::for_architecture(entry.architecture).ok_or_else(|| JsonRpcError {
            code: -32004,
            message: format!(
                "no MoE tensor-naming scheme for architecture {:?}",
                entry.architecture
            ),
            data: None,
        })?;
    let resolver = node
        .iroh_resolver
        .as_ref()
        .cloned()
        .ok_or_else(|| JsonRpcError {
            code: -32000,
            message: "iroh resolver not bound — cannot publish expert blobs".into(),
            data: None,
        })?;

    let expert_ids: Vec<u32> = match p.get("experts").and_then(|v| v.as_array()) {
        Some(arr) => {
            let mut ids = Vec::with_capacity(arr.len());
            for v in arr {
                let id = v.as_u64().ok_or_else(|| JsonRpcError {
                    code: -32602,
                    message: "experts must be an array of integers".into(),
                    data: None,
                })? as u32;
                if id >= shape.num_experts {
                    return Err(JsonRpcError {
                        code: -32602,
                        message: format!(
                            "expert {id} out of range: {model_id} has {} experts",
                            shape.num_experts
                        ),
                        data: None,
                    });
                }
                ids.push(id);
            }
            ids
        }
        None => (0..shape.num_experts).collect(),
    };

    let total_experts = expert_ids.len();
    let job_id = uuid::Uuid::new_v4().to_string();
    node.moe_prepare_jobs.insert(
        job_id.clone(),
        MoePrepareJob {
            model_id: model_id.clone(),
            layer,
            state: "running".into(),
            error: None,
            total_experts: total_experts as u32,
            completed_experts: 0,
            experts: Vec::new(),
            gate: None,
        },
    );

    let quant_echo = p.get("quant").cloned().unwrap_or(Value::Null);

    let jobs = Arc::clone(&node.moe_prepare_jobs);
    let spawn_job_id = job_id.clone();
    tokio::spawn(async move {
        let outcome: Result<(), String> = async {
            let mut extractor = MoeExtractor::open(repo, naming)
                .await
                .map_err(|e| format!("open {repo}: {e}"))?;
            for expert in &expert_ids {
                let blob = match quant_plan {
                    Some(plan) => extractor
                        .quantized_expert_blob(layer, *expert, plan)
                        .await
                        .map_err(|e| format!("expert {expert}: {e}"))?,
                    None => extractor
                        .expert_blob(layer, *expert)
                        .await
                        .map_err(|e| format!("expert {expert}: {e}"))?,
                };
                let len = blob.len() as u64;
                let uri = resolver
                    .publish_bytes(Bytes::from(blob))
                    .await
                    .map_err(|e| format!("publish expert {expert}: {e}"))?;
                if let Some(mut job) = jobs.get_mut(&spawn_job_id) {
                    job.completed_experts += 1;
                    job.experts.push(MoePreparedExpert {
                        expert: *expert,
                        uri: uri.to_string(),
                        bytes: len,
                        quant: quant_plan.and_then(|p| p.coarsest_tag()).map(String::from),
                    });
                }
            }
            if include_gate {
                let blob = extractor
                    .gate_blob(layer)
                    .await
                    .map_err(|e| format!("gate: {e}"))?;
                let len = blob.len() as u64;
                let uri = resolver
                    .publish_bytes(Bytes::from(blob))
                    .await
                    .map_err(|e| format!("publish gate: {e}"))?;
                if let Some(mut job) = jobs.get_mut(&spawn_job_id) {
                    job.gate = Some(MoePreparedGate {
                        uri: uri.to_string(),
                        bytes: len,
                    });
                }
            }
            Ok(())
        }
        .await;
        if let Some(mut job) = jobs.get_mut(&spawn_job_id) {
            match outcome {
                Ok(()) => job.state = "completed".into(),
                Err(e) => {
                    warn!("MoE prepare job {spawn_job_id} failed: {e}");
                    job.state = "failed".into();
                    job.error = Some(e);
                }
            }
        }
    });

    Ok(json!({
        "job_id": job_id,
        "model_id": model_id,
        "layer": layer,
        "total_experts": total_experts,
        "include_gate": include_gate,
        "quant": quant_echo,
        "state": "running",
    }))
}

/// `tenzro_moePrepareStatus` — snapshot of one prepare job by id.
pub(crate) async fn handle_moe_prepare_status(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.unwrap_or(json!({}));
    let job_id = req_str(&p, "job_id")?;
    let job = node.moe_prepare_jobs.get(job_id).ok_or_else(|| JsonRpcError {
        code: -32602,
        message: format!("unknown prepare job: {job_id}"),
        data: None,
    })?;
    serde_json::to_value(&*job).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("serialize: {e}"),
        data: None,
    })
}

// ---------------------------------------------------------------------------
// Router-peer distributed forward
// ---------------------------------------------------------------------------

fn resolve_top_k(p: &Value, model_id: &str) -> Result<usize, JsonRpcError> {
    if let Some(k) = p.get("top_k").and_then(|v| v.as_u64()) {
        if k == 0 {
            return Err(JsonRpcError {
                code: -32602,
                message: "top_k must be >= 1".into(),
                data: None,
            });
        }
        return Ok(k as usize);
    }
    // Default from the catalog MoE shape (experts_per_token).
    tenzro_model::catalog::get_model_by_id(model_id)
        .and_then(|e| e.moe)
        .map(|s| s.experts_per_token as usize)
        .ok_or_else(|| JsonRpcError {
            code: -32602,
            message: format!(
                "top_k not given and no catalog MoE shape for model_id: {model_id}"
            ),
            data: None,
        })
}

/// How a per-holder batch was executed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transport {
    Local,
    Iroh,
    Http,
}

/// `tenzro_moeForward` — the distributed MoE layer forward. Gate-routes
/// the hidden-state batch with the locally-loaded gating network, plans
/// the per-holder dispatch against the provider shard view, ships each
/// batch to its expert holder (local runtime → iroh `tenzro/moe` →
/// HTTP JSON-RPC fallback), and returns the gate-weighted combination.
pub(crate) async fn handle_moe_forward(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.unwrap_or(json!({}));
    let model_id = req_str(&p, "model_id")?.to_string();
    let layer = req_u32(&p, "layer")?;
    let d_model = req_u32(&p, "d_model")? as usize;
    let hidden = decode_f32_base64(req_str(&p, "hidden_states")?).map_err(|e| JsonRpcError {
        code: -32602,
        message: format!("hidden_states: {e}"),
        data: None,
    })?;
    let top_k = resolve_top_k(&p, &model_id)?;
    let allow_cold = p
        .get("allow_cold")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    // 1. Gate route (local gating network required on router peers).
    let routed = node
        .moe_runtime
        .route(&model_id, layer, d_model, &hidden, top_k)
        .map_err(|e| JsonRpcError {
            code: -32004,
            message: format!("moe route: {e}"),
            data: None,
        })?;

    // 1b. Readahead: warm any disk-tier experts the gate just selected into
    //     the memory tier, overlapping the decode with dispatch planning and
    //     network setup below.
    let selected: Vec<tenzro_model::ExpertId> = routed
        .iter()
        .flat_map(|t| t.slots.iter().map(|s| s.expert))
        .collect();
    if !selected.is_empty() {
        let runtime = Arc::clone(&node.moe_runtime);
        let model = model_id.clone();
        let _ = tokio::task::spawn_blocking(move || runtime.readahead(&model, &selected)).await;
    }

    // 2. Dispatch plan against the provider shard view.
    let manager = node.provider_manager().ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "Provider manager not initialized".into(),
        data: None,
    })?;
    let providers = manager.list_providers();
    let view = tenzro_model::MoeShardView::build(&model_id, providers.iter());
    let routings = to_token_routing(&routed);
    let plan =
        tenzro_model::plan_dispatch(&view, &routings, allow_cold).map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("moe dispatch planner: {e}"),
            data: None,
        })?;

    // 3. Concurrent per-batch fan-out with pipelined combine. Each batch
    //    resolves independently (holder RTTs vary widely on a WAN); its
    //    response is folded into the combiner the moment it lands via
    //    `FuturesUnordered`, overlapping the gate-weighted gather with
    //    still-in-flight batches rather than blocking on the slowest one.
    let n_tokens = hidden.len() / d_model;
    let mut inflight = futures::stream::FuturesUnordered::new();
    for batch in &plan.batches {
        let req = batch_request(&model_id, d_model, &hidden, n_tokens, batch);
        inflight.push(async move {
            let req = req?;
            execute_batch(node, batch, req).await
        });
    }

    let mut combiner = MoeCombiner::new(d_model, &routed).map_err(|e| JsonRpcError {
        code: -32004,
        message: format!("moe combine setup: {e}"),
        data: None,
    })?;
    let (mut local_n, mut iroh_n, mut http_n) = (0usize, 0usize, 0usize);
    use futures::StreamExt;
    while let Some(r) = inflight.next().await {
        let (resp, transport) = r?;
        match transport {
            Transport::Local => local_n += 1,
            Transport::Iroh => iroh_n += 1,
            Transport::Http => http_n += 1,
        }
        combiner.accumulate(&resp).map_err(|e| JsonRpcError {
            code: -32004,
            message: format!("moe combine: {e}"),
            data: None,
        })?;
    }

    // 4. Finalize: verifies every gate-selected contribution arrived.
    let combined = combiner.finish().map_err(|e| JsonRpcError {
        code: -32004,
        message: format!("moe combine: {e}"),
        data: None,
    })?;

    Ok(json!({
        "model_id": model_id,
        "layer": layer,
        "d_model": d_model,
        "top_k": top_k,
        "tokens": routed.len(),
        "batches": plan.batches.len(),
        "transports": { "local": local_n, "iroh": iroh_n, "http": http_n },
        "routed": routed_to_json(&routed),
        "outputs": encode_f32_base64(&combined),
    }))
}

/// Build the per-holder execute request: the subset of hidden rows for
/// the batch's token indices, in batch order.
fn batch_request(
    model_id: &str,
    d_model: usize,
    hidden: &[f32],
    n_tokens: usize,
    batch: &ExpertBatch,
) -> Result<ExpertExecuteRequest, JsonRpcError> {
    let mut rows = Vec::with_capacity(batch.token_indices.len() * d_model);
    for &tok in &batch.token_indices {
        let i = tok as usize;
        if i >= n_tokens {
            return Err(JsonRpcError {
                code: -32603,
                message: format!("dispatch plan references token {i} of {n_tokens}"),
                data: None,
            });
        }
        rows.extend_from_slice(&hidden[i * d_model..(i + 1) * d_model]);
    }
    Ok(ExpertExecuteRequest::compressed(
        model_id.to_string(),
        batch.expert.layer,
        batch.expert.expert,
        batch.token_indices.clone(),
        d_model as u32,
        rows,
    ))
}

/// One holder endpoint a batch can be dispatched to: the primary carried
/// inline on the batch, or one of its standby backups.
struct HolderTarget<'a> {
    iroh_endpoint_id: Option<&'a str>,
    http_endpoint: Option<&'a str>,
}

/// Execute one planned batch: local runtime when the expert is resident
/// here, else remote dispatch to the primary holder, redispatching to
/// each standby backup in turn on failure. Per remote holder the order is
/// iroh `tenzro/moe` (QUIC), then HTTP JSON-RPC (`tenzro_moeExecute`).
/// The last holder's error propagates when every holder fails.
async fn execute_batch(
    node: &Arc<TenzroNode>,
    batch: &ExpertBatch,
    req: ExpertExecuteRequest,
) -> Result<(ExpertExecuteResponse, Transport), JsonRpcError> {
    // Local short-circuit: the router peer may itself hold the expert.
    if node
        .moe_runtime
        .has_expert(&req.model_id, req.layer, req.expert)
    {
        let runtime = Arc::clone(&node.moe_runtime);
        let resp = tokio::task::spawn_blocking(move || runtime.execute(&req))
            .await
            .map_err(|e| JsonRpcError {
                code: -32603,
                message: format!("execute join: {e}"),
                data: None,
            })?
            .map_err(|e| JsonRpcError {
                code: -32004,
                message: format!("moe execute (local): {e}"),
                data: None,
            })?;
        return Ok((resp, Transport::Local));
    }

    let params = serde_json::to_value(&req).map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("encode request: {e}"),
        data: None,
    })?;

    // Primary holder first, then each standby backup in the planner's
    // warm-first order. A holder that fails at the transport level or
    // returns a holder-side error is retired for this batch and the next
    // standby is tried.
    let primary = HolderTarget {
        iroh_endpoint_id: batch.iroh_endpoint_id.as_deref(),
        http_endpoint: batch.http_endpoint.as_deref(),
    };
    let backups = batch.backups.iter().map(|b| HolderTarget {
        iroh_endpoint_id: b.iroh_endpoint_id.as_deref(),
        http_endpoint: b.http_endpoint.as_deref(),
    });
    let targets = std::iter::once(primary).chain(backups);

    let mut last_err: Option<JsonRpcError> = None;
    let total = 1 + batch.backups.len();
    for (attempt, target) in targets.enumerate() {
        match dispatch_to_holder(node, batch, &params, &target).await {
            Ok(pair) => return Ok(pair),
            Err(e) => {
                if attempt + 1 < total {
                    debug!(
                        expert = %format!("l{}/e{}", batch.expert.layer, batch.expert.expert),
                        attempt,
                        "moe holder dispatch failed, redispatching to backup: {}",
                        e.message
                    );
                }
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| JsonRpcError {
        code: -32000,
        message: format!(
            "expert l{}/e{} has no reachable holder",
            batch.expert.layer, batch.expert.expert
        ),
        data: None,
    }))
}

/// Dispatch a batch to one holder: iroh `tenzro/moe` first, HTTP
/// JSON-RPC fallback. iroh transport failures fall through to HTTP within
/// the same holder; a holder-side JSON-RPC error propagates so the caller
/// can redispatch to a standby.
async fn dispatch_to_holder(
    node: &Arc<TenzroNode>,
    batch: &ExpertBatch,
    params: &Value,
    target: &HolderTarget<'_>,
) -> Result<(ExpertExecuteResponse, Transport), JsonRpcError> {
    // iroh first — same envelope as the ALPN server half expects.
    if let (Some(endpoint_id_str), Some(resolver)) =
        (target.iroh_endpoint_id, node.iroh_resolver.as_ref())
    {
        match endpoint_id_str.parse::<EndpointId>() {
            Ok(endpoint_id) => {
                let body = json!({
                    "jsonrpc": "2.0",
                    "method": MOE_METHOD_EXECUTE,
                    "params": params.clone(),
                    "id": 1,
                });
                let frame = Bytes::from(serde_json::to_vec(&body).map_err(|e| JsonRpcError {
                    code: -32603,
                    message: format!("encode frame: {e}"),
                    data: None,
                })?);
                match jsonrpc_call(resolver.endpoint(), endpoint_id, ALPN_MOE, frame).await {
                    Ok(resp_bytes) => {
                        return parse_holder_response(&resp_bytes, batch)
                            .map(|r| (r, Transport::Iroh));
                    }
                    Err(e) => {
                        // Transport-level failure only — try HTTP next.
                        debug!(
                            expert = %format!("l{}/e{}", batch.expert.layer, batch.expert.expert),
                            "moe iroh dispatch failed, falling back to http: {e}"
                        );
                    }
                }
            }
            Err(e) => {
                warn!(
                    endpoint_id = endpoint_id_str,
                    "provider advertised unparseable iroh endpoint id: {e}"
                );
            }
        }
    }

    // HTTP JSON-RPC fallback.
    let http_endpoint = target.http_endpoint.ok_or_else(|| JsonRpcError {
        code: -32000,
        message: format!(
            "expert l{}/e{} holder unreachable: no working iroh endpoint and no http endpoint",
            batch.expert.layer, batch.expert.expert
        ),
        data: None,
    })?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("http client: {e}"),
            data: None,
        })?;
    let resp = client
        .post(http_endpoint)
        .json(&json!({
            "jsonrpc": "2.0",
            "method": "tenzro_moeExecute",
            "params": params,
            "id": 1,
        }))
        .send()
        .await
        .map_err(|e| JsonRpcError {
            code: -32000,
            message: format!("moe http dispatch to {http_endpoint}: {e}"),
            data: None,
        })?;
    let body = resp.bytes().await.map_err(|e| JsonRpcError {
        code: -32000,
        message: format!("moe http response read: {e}"),
        data: None,
    })?;
    parse_holder_response(&body, batch).map(|r| (r, Transport::Http))
}

/// Decode a holder-side JSON-RPC response envelope into an
/// [`ExpertExecuteResponse`], propagating holder-side errors verbatim.
fn parse_holder_response(
    body: &[u8],
    batch: &ExpertBatch,
) -> Result<ExpertExecuteResponse, JsonRpcError> {
    let envelope: Value = serde_json::from_slice(body).map_err(|e| JsonRpcError {
        code: -32000,
        message: format!("holder response parse: {e}"),
        data: None,
    })?;
    if let Some(err) = envelope.get("error") {
        return Err(JsonRpcError {
            code: err
                .get("code")
                .and_then(|c| c.as_i64())
                .and_then(|c| i32::try_from(c).ok())
                .unwrap_or(-32000),
            message: format!(
                "expert l{}/e{} holder error: {}",
                batch.expert.layer,
                batch.expert.expert,
                err.get("message").and_then(|m| m.as_str()).unwrap_or("?")
            ),
            data: None,
        });
    }
    let result = envelope.get("result").cloned().ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "holder response has neither result nor error".into(),
        data: None,
    })?;
    serde_json::from_value(result).map_err(|e| JsonRpcError {
        code: -32000,
        message: format!("holder result decode: {e}"),
        data: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn f32_base64_roundtrip() {
        let v = vec![1.0f32, -2.5, 0.0, 3.75];
        let enc = encode_f32_base64(&v);
        assert_eq!(decode_f32_base64(&enc).unwrap(), v);
    }

    #[test]
    fn f32_base64_rejects_misaligned() {
        let enc = base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3]);
        assert!(decode_f32_base64(&enc).is_err());
    }

    #[tokio::test]
    async fn dispatcher_rejects_unknown_method() {
        let d = MoeIrohDispatcher::new(Arc::new(MoeExpertRuntime::new()));
        let req = json!({ "jsonrpc": "2.0", "method": "moe/nope", "id": 7 });
        let resp = d
            .dispatch(Bytes::from(serde_json::to_vec(&req).unwrap()))
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32601);
        assert_eq!(v["id"], 7);
    }

    #[tokio::test]
    async fn dispatcher_parse_error_is_envelope_not_transport_error() {
        let d = MoeIrohDispatcher::new(Arc::new(MoeExpertRuntime::new()));
        let resp = d.dispatch(Bytes::from_static(b"not json")).await.unwrap();
        let v: Value = serde_json::from_slice(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32700);
    }

    #[tokio::test]
    async fn dispatcher_execute_unloaded_expert_is_model_error() {
        let d = MoeIrohDispatcher::new(Arc::new(MoeExpertRuntime::new()));
        let req = json!({
            "jsonrpc": "2.0",
            "method": MOE_METHOD_EXECUTE,
            "params": {
                "model_id": "m",
                "layer": 0,
                "expert": 0,
                "token_indices": [0],
                "d_model": 2,
                "hidden_states": encode_f32_base64(&[1.0, 2.0]),
            },
            "id": 1,
        });
        let resp = d
            .dispatch(Bytes::from(serde_json::to_vec(&req).unwrap()))
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32004);
    }

    #[tokio::test]
    async fn dispatcher_status_reports_empty_runtime() {
        let d = MoeIrohDispatcher::new(Arc::new(MoeExpertRuntime::new()));
        let req = json!({ "jsonrpc": "2.0", "method": MOE_METHOD_STATUS, "id": 2 });
        let resp = d
            .dispatch(Bytes::from(serde_json::to_vec(&req).unwrap()))
            .await
            .unwrap();
        let v: Value = serde_json::from_slice(&resp).unwrap();
        assert_eq!(v["result"]["total_bytes"], 0);
        assert!(v["result"]["experts"].as_array().unwrap().is_empty());
    }
}
