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
//!    fallback), and gather the gate-weighted combination. Batches whose
//!    every holder fails are replanned mid-flight against the shard view
//!    minus the failed providers (bounded rounds); `allow_partial` lets
//!    the forward degrade to a gate-weight-renormalized partial combine
//!    when tokens remain unservable.
//!
//! Hidden-state tensors ride as base64 of little-endian `f32` bytes in
//! every JSON surface (see `tenzro_model::moe_exec::f32_base64`).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use serde_json::{Value, json};
use tracing::{debug, info, warn};

use tenzro_iroh::{
    ALPN_MOE, EndpointId, IrohError, IrohResolver, IrohResult, JsonRpcDispatcher, jsonrpc_call,
};
use tenzro_model::{
    DEFAULT_ACTIVATION_K, ExpertActivationCommitment, ExpertBatch, ExpertExecuteRequest,
    ExpertExecuteResponse, ExpertExecutionReceipt, ExpertId, ExpertQuantPlan, MoeCombiner,
    MoeExpertRuntime, MoeExtractor, MoeShardView, MoeTensorNaming, QuantKind, ReplicationPolicy,
    RoutedToken, TokenRouting, build_expert_receipt, quantize_expert_blob, to_token_routing,
    verify_expert_receipt,
};
use tenzro_storage::{CF_SETTLEMENTS, KvStore};
use tenzro_types::tenzro_uri::TenzroUri;
use tenzro_types::{Address, MoeExpertHolding, MoeExpertResidency};

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

/// Holder-side receipt identity: the node's announce signer plus the
/// provider wallet address remote routers know this holder by (the same
/// derivation the provider-announcement path uses). Absent on nodes with
/// no Ed25519 key on disk — their execute responses carry no receipt, and
/// remote routers reject receiptless responses, matching the rule that
/// unsigned provider announcements are dropped.
#[derive(Clone)]
pub struct MoeReceiptIdentity {
    pub signer: Arc<dyn tenzro_crypto::signatures::Signer + Send + Sync>,
    pub provider: Address,
}

/// Compute the activation commitment over the outputs and attach the
/// signed execution receipt to a holder response. The router recomputes
/// the commitment from the returned rows with the same
/// [`DEFAULT_ACTIVATION_K`], so both sides hash identical canonical bytes.
fn attach_execution_receipt(
    req: &ExpertExecuteRequest,
    resp: &mut ExpertExecuteResponse,
    identity: &MoeReceiptIdentity,
) -> Result<(), String> {
    let commitment = ExpertActivationCommitment::from_outputs(
        &req.token_indices,
        &resp.outputs,
        req.d_model as usize,
        DEFAULT_ACTIVATION_K,
    )
    .map_err(|e| format!("activation commitment: {e}"))?
    .commitment_hash();
    let receipt = build_expert_receipt(
        &req.model_id,
        req.layer,
        req.expert,
        &req.token_indices,
        req.carrier_hash(),
        commitment,
        identity.provider,
        identity.signer.as_ref(),
        identity.signer.public_key().clone(),
    )
    .map_err(|e| format!("receipt sign: {e}"))?;
    resp.receipt = Some(receipt);
    Ok(())
}

/// `JsonRpcDispatcher` for the `tenzro/moe` iroh ALPN.
///
/// Unlike the A2A/MCP dispatchers (which need the full node state and use
/// deferred trampolines), this dispatcher depends only on the
/// [`MoeExpertRuntime`] and the announce-signer identity, both of which
/// exist before the iroh endpoint binds — so the real dispatcher is
/// registered directly at bind time.
pub struct MoeIrohDispatcher {
    runtime: Arc<MoeExpertRuntime>,
    identity: Option<MoeReceiptIdentity>,
    /// Subscription api-key manager, used to admit `moe/execute` callers.
    /// `None` on nodes without an api-key manager — the api-key credential
    /// path is then unavailable and `moe/execute` falls through to refuse.
    api_key_manager: Option<Arc<crate::api_key::ApiKeyManager>>,
    /// Rental service-key admission gate. When disabled, the service-key
    /// credential path is unavailable and `moe/execute` refuses.
    admission_gate: Arc<crate::admission::NodeAdmissionGate>,
}

impl std::fmt::Debug for MoeIrohDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MoeIrohDispatcher").finish_non_exhaustive()
    }
}

impl MoeIrohDispatcher {
    /// Wrap the shared expert runtime for iroh-side dispatch. `identity`
    /// signs execution receipts; `None` serves without receipts (remote
    /// routers reject those responses). `api_key_manager` + `admission_gate`
    /// are the credential admission the `moe/execute` compute surface is
    /// gated through (fail-closed: no valid credential → refuse).
    pub fn new(
        runtime: Arc<MoeExpertRuntime>,
        identity: Option<MoeReceiptIdentity>,
        api_key_manager: Option<Arc<crate::api_key::ApiKeyManager>>,
        admission_gate: Arc<crate::admission::NodeAdmissionGate>,
    ) -> Self {
        Self {
            runtime,
            identity,
            api_key_manager,
            admission_gate,
        }
    }

    /// Credential admission for the `moe/execute` compute surface, mirroring
    /// the shape of `inference_admission::NodeInferenceAdmission::decide_creds`
    /// (steps 1 and 2) and `infer.rs`'s iroh gating: a valid inference-scoped
    /// subscription api-key, or a rental service-key admitted on the WebApi
    /// surface. There is no model-visibility fallback here — raw expert
    /// execution is never an open on-demand surface. Fail-closed: absent or
    /// invalid credential → `Err`, and the caller refuses without executing.
    fn authorize_execute(
        &self,
        api_key: Option<&str>,
        service_key: Option<&str>,
    ) -> Result<(), String> {
        // 1. Subscription api-key — must carry the Inference scope and be
        //    within its rate limit.
        if let Some(v) = api_key
            && let Some(mgr) = self.api_key_manager.as_ref()
            && let Some(rec) = mgr.lookup(v)
            && rec.has_scope(crate::api_key::ApiKeyScope::Inference)
        {
            if mgr.check_rate_limit(&rec).is_err() {
                return Err("api key rate limit exceeded".into());
            }
            return Ok(());
        }

        // 2. Rental service-key — admitted on the WebApi surface, only when
        //    the admission gate is enabled.
        if let Some(v) = service_key {
            let gate = &self.admission_gate;
            if gate.is_enabled()
                && matches!(
                    gate.admit(tenzro_auth::ServiceSurface::WebApi, "/moe/execute", Some(v)),
                    tenzro_auth::Admission::Allow
                )
            {
                return Ok(());
            }
        }

        // Fail-closed: no valid credential presented.
        Err(
            "moe/execute is gated; provide a valid inference api_key or service_key in the request frame"
                .into(),
        )
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
                            );
                        }
                    };
                match self.runtime.execute(&req) {
                    Ok(mut resp) => {
                        if let Some(identity) = &self.identity
                            && let Err(e) = attach_execution_receipt(&req, &mut resp, identity)
                        {
                            return error_envelope(id, -32603, format!("execution receipt: {e}"));
                        }
                        match serde_json::to_value(&resp) {
                            Ok(v) => json!({ "jsonrpc": "2.0", "result": v, "id": id }),
                            Err(e) => error_envelope(id, -32603, format!("encode response: {e}")),
                        }
                    }
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
                let body = serde_json::to_vec(&error_envelope(Value::Null, -32700, format!("{e}")))
                    .map_err(|e| IrohError::Backend(format!("encode parse-error: {e}")))?;
                return Ok(Bytes::from(body));
            }
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = req.get("params").cloned();

        // Gate the compute surface. `moe/execute` runs expert-FFN matmuls on
        // this node's hardware, so an unauthenticated peer could otherwise
        // burn its GPU/CPU for free. Credentials ride at the top level of the
        // JSON-RPC frame (same client contract as `tenzro/infer`): `api_key`
        // / `service_key`. `moe/status` stays an unauthenticated read surface.
        if method == MOE_METHOD_EXECUTE {
            let api_key = req.get("api_key").and_then(|v| v.as_str());
            let service_key = req.get("service_key").and_then(|v| v.as_str());
            if let Err(msg) = self.authorize_execute(api_key, service_key) {
                let body = serde_json::to_vec(&error_envelope(id, -32001, msg))
                    .map_err(|e| IrohError::Backend(format!("encode auth-error: {e}")))?;
                return Ok(Bytes::from(body));
            }
        }

        // Expert-FFN matmuls are CPU-bound; keep them off the QUIC driver.
        let this = MoeIrohDispatcher {
            runtime: Arc::clone(&self.runtime),
            identity: self.identity.clone(),
            api_key_manager: self.api_key_manager.clone(),
            admission_gate: Arc::clone(&self.admission_gate),
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
            // Host-level measured throughput stamped onto every holding —
            // the runtime meters aggregate tokens/s, not per-expert rates.
            committed_tps: status.measured_tps,
            blob_uri: e.source_uri.clone(),
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

/// Seconds between MoE replication repair passes.
pub(crate) const MOE_REPAIR_INTERVAL_SECS: u64 = 120;

/// Most experts one node admits in a single repair pass. Repair fetches
/// full expert weights, so an unbounded pass would let one membership
/// hiccup pull a whole model onto a single node.
const MOE_REPAIR_MAX_PER_PASS: usize = 2;

/// Raise replication on under-replicated experts this node was
/// rendezvous-selected to hold.
///
/// Pull-based by construction: the plan is computed locally and every row
/// naming another provider is discarded unread. Nothing here can make a
/// peer allocate memory — a command-based repair would hand any node a
/// way to exhaust any other node's VRAM.
///
/// Scope is the set of models this node already holds experts for. A node
/// serving no experts of a model is never conscripted into it, and the
/// scoping is also what puts this node in its own candidate pool: the
/// pool is `distinct_providers()`, which is exactly the providers already
/// declaring holdings for that model.
///
/// Returns the number of experts admitted.
pub(crate) async fn run_moe_repair_pass(node: &Arc<TenzroNode>) -> usize {
    let (Some(me), Some(pm)) = (node.self_provider_address(), node.provider_manager()) else {
        return 0;
    };
    let Some(resolver) = node.iroh_resolver.as_ref() else {
        return 0;
    };

    let status = node.moe_runtime.status();
    let models: BTreeSet<String> = status.experts.iter().map(|e| e.model_id.clone()).collect();
    if models.is_empty() {
        return 0;
    }

    let providers = pm.list_providers();
    let policy = ReplicationPolicy::default();
    let mut admitted = 0usize;

    for model_id in &models {
        if admitted >= MOE_REPAIR_MAX_PER_PASS {
            break;
        }
        let view = MoeShardView::build(model_id.clone(), providers.iter());
        let candidates = view.distinct_providers();
        for row in view.plan_repair(policy, &candidates) {
            if admitted >= MOE_REPAIR_MAX_PER_PASS {
                break;
            }
            if row.provider != me {
                continue;
            }
            let uri = match TenzroUri::parse(&row.blob_uri) {
                Ok(u) => u,
                Err(e) => {
                    warn!(
                        model_id = %model_id,
                        layer = row.expert.layer,
                        expert = row.expert.expert,
                        uri = %row.blob_uri,
                        "MoE repair skipped: unparseable holder uri: {e}"
                    );
                    continue;
                }
            };
            let blob = match resolver.fetch_bytes(&uri).await {
                Ok(b) => b,
                Err(e) => {
                    warn!(
                        model_id = %model_id,
                        layer = row.expert.layer,
                        expert = row.expert.expert,
                        "MoE repair fetch failed: {e}"
                    );
                    continue;
                }
            };
            let runtime = Arc::clone(&node.moe_runtime);
            let (mid, layer, expert, source) = (
                model_id.clone(),
                row.expert.layer,
                row.expert.expert,
                row.blob_uri.clone(),
            );
            let loaded = tokio::task::spawn_blocking(move || {
                runtime.load_expert(mid, layer, expert, &blob, Some(source))
            })
            .await;
            match loaded {
                Ok(Ok(_)) => {
                    admitted += 1;
                    info!(
                        model_id = %model_id,
                        layer = row.expert.layer,
                        expert = row.expert.expert,
                        "MoE repair admitted under-replicated expert"
                    );
                }
                Ok(Err(e)) => warn!(
                    model_id = %model_id,
                    layer = row.expert.layer,
                    expert = row.expert.expert,
                    "MoE repair load failed: {e}"
                ),
                Err(e) => warn!("MoE repair load join failed: {e}"),
            }
        }
    }

    if admitted > 0 {
        sync_moe_declaration(node);
    }
    admitted
}

/// Drive [`run_moe_repair_pass`] on a timer.
///
/// No leader gate and no role gate: every node runs the same plan against
/// its own membership view and acts only on its own rows, so concurrent
/// passes on different nodes converge instead of colliding. Nodes holding
/// no experts return immediately.
pub fn spawn_moe_repair_loop(node: Arc<TenzroNode>) {
    tokio::spawn(async move {
        let mut ticker =
            tokio::time::interval(std::time::Duration::from_secs(MOE_REPAIR_INTERVAL_SECS));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the immediate first tick — declarations have not propagated
        // at boot, so an early pass would read a view that under-reports
        // replication and repair experts that are in fact covered.
        ticker.tick().await;
        loop {
            ticker.tick().await;
            run_moe_repair_pass(&node).await;
        }
    });
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
    let source_uri = p.get("uri").and_then(|v| v.as_str()).map(str::to_string);

    let runtime = Arc::clone(&node.moe_runtime);
    let row = tokio::task::spawn_blocking(move || {
        runtime.load_expert(model_id, layer, expert, &blob, source_uri)
    })
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
    let identity = node
        .announce_signer()
        .cloned()
        .zip(node.self_provider_address())
        .map(|(signer, provider)| MoeReceiptIdentity { signer, provider });
    let resp =
        tokio::task::spawn_blocking(move || -> Result<ExpertExecuteResponse, JsonRpcError> {
            let mut resp = runtime.execute(&req).map_err(|e| JsonRpcError {
                code: -32004,
                message: format!("moe execute: {e}"),
                data: None,
            })?;
            if let Some(identity) = &identity {
                attach_execution_receipt(&req, &mut resp, identity).map_err(|e| JsonRpcError {
                    code: -32603,
                    message: format!("execution receipt: {e}"),
                    data: None,
                })?;
            }
            Ok(resp)
        })
        .await
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("execute join: {e}"),
            data: None,
        })??;
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
    let include_gate = p
        .get("include_gate")
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
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

    // Checkpoints with a fused shared-expert FFN expose it as one extra
    // preparable slot at index `num_experts` — the same index the gating
    // network appends it under at routing time.
    let shared_extra: u32 =
        if shape.shared_experts > 0 && matches!(naming, MoeTensorNaming::DeepSeekMoe) {
            1
        } else {
            0
        };
    let id_space = shape.num_experts + shared_extra;

    let expert_ids: Vec<u32> = match p.get("experts").and_then(|v| v.as_array()) {
        Some(arr) => {
            let mut ids = Vec::with_capacity(arr.len());
            for v in arr {
                let id = v.as_u64().ok_or_else(|| JsonRpcError {
                    code: -32602,
                    message: "experts must be an array of integers".into(),
                    data: None,
                })? as u32;
                if id >= id_space {
                    return Err(JsonRpcError {
                        code: -32602,
                        message: format!(
                            "expert {id} out of range: {model_id} has {} routed experts{}",
                            shape.num_experts,
                            if shared_extra > 0 {
                                format!(
                                    " plus the fused shared expert at index {}",
                                    shape.num_experts
                                )
                            } else {
                                String::new()
                            }
                        ),
                        data: None,
                    });
                }
                ids.push(id);
            }
            ids
        }
        None => (0..id_space).collect(),
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
    let num_routed = shape.num_experts;
    tokio::spawn(async move {
        let outcome: Result<(), String> = async {
            let mut extractor = MoeExtractor::open(repo, naming)
                .await
                .map_err(|e| format!("open {repo}: {e}"))?;
            for expert in &expert_ids {
                let blob = if *expert >= num_routed {
                    let dense = extractor
                        .shared_expert_blob(layer)
                        .await
                        .map_err(|e| format!("shared expert: {e}"))?;
                    match quant_plan {
                        Some(plan) => quantize_expert_blob(&dense, plan)
                            .map_err(|e| format!("shared expert: {e}"))?,
                        None => dense,
                    }
                } else {
                    match quant_plan {
                        Some(plan) => extractor
                            .quantized_expert_blob(layer, *expert, plan)
                            .await
                            .map_err(|e| format!("expert {expert}: {e}"))?,
                        None => extractor
                            .expert_blob(layer, *expert)
                            .await
                            .map_err(|e| format!("expert {expert}: {e}"))?,
                    }
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
    let job = node
        .moe_prepare_jobs
        .get(job_id)
        .ok_or_else(|| JsonRpcError {
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
            message: format!("top_k not given and no catalog MoE shape for model_id: {model_id}"),
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
///
/// Failover: a batch whose primary and every standby holder fail is
/// replanned — its (expert, token) pairs are re-dispatched against the
/// shard view minus every provider that already failed, up to
/// `MAX_REPLANS` rounds, while contributions already gathered stay in
/// the combiner. `allow_partial: true` degrades unservable tokens to a
/// renormalized partial combine (reported under `missing`) instead of
/// failing the forward; the default is fail-closed.
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
    // When true, tokens whose experts cannot be served by any reachable
    // holder are dropped from the combine and the surviving contributions
    // are gate-weight renormalized, instead of failing the whole forward.
    let allow_partial = p
        .get("allow_partial")
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

    // 3. Concurrent per-batch fan-out with pipelined combine and bounded
    //    failover. Each batch resolves independently (holder RTTs vary
    //    widely on a WAN); its response is folded into the combiner the
    //    moment it lands via `FuturesUnordered`, overlapping the
    //    gate-weighted gather with still-in-flight batches. When every
    //    holder of a batch fails, the round collects the failure and
    //    replans just the affected (expert, token) pairs against the shard
    //    view minus the providers that failed — the combiner persists
    //    across rounds, so contributions already gathered are kept. With
    //    `allow_partial`, tokens that remain unservable after the replan
    //    budget are dropped and the rest renormalized.
    const MAX_REPLANS: usize = 2;
    let n_tokens = hidden.len() / d_model;
    let mut combiner = MoeCombiner::new(d_model, &routed).map_err(|e| JsonRpcError {
        code: -32004,
        message: format!("moe combine setup: {e}"),
        data: None,
    })?;
    let (mut local_n, mut iroh_n, mut http_n) = (0usize, 0usize, 0usize);
    // Per-holder settlement basis for remote expert work: token count plus
    // the concatenated activation-commitment hashes from the signed
    // execution receipts. Local self-execution carries no receipt and is
    // never settled.
    let mut settled_basis: HashMap<Address, (u64, Vec<u8>)> = HashMap::new();
    let mut replans = 0usize;
    let mut excluded: HashSet<Address> = HashSet::new();
    let mut pending: Vec<ExpertBatch> = plan.batches;
    let mut batches_total = pending.len();
    // Set when failover gives up on some (expert, token) pairs — finalize
    // switches to the renormalizing partial combine.
    let mut gave_up = false;

    use futures::StreamExt;
    loop {
        let mut failures: Vec<BatchFailure> = Vec::new();
        {
            // The local short-circuit is disabled once this node's own
            // execution failed and it landed in the excluded set —
            // otherwise a replanned batch would short-circuit straight
            // back into the same failing local runtime.
            let use_local = node
                .self_provider_address()
                .is_none_or(|a| !excluded.contains(&a));
            let mut inflight = futures::stream::FuturesUnordered::new();
            for batch in &pending {
                let req = batch_request(&model_id, d_model, &hidden, n_tokens, batch);
                inflight.push(async move {
                    let req = req?;
                    execute_batch(node, batch, req, use_local).await
                });
            }
            while let Some(r) = inflight.next().await {
                match r? {
                    BatchOutcome::Success { resp, transport } => {
                        match transport {
                            Transport::Local => local_n += 1,
                            Transport::Iroh => iroh_n += 1,
                            Transport::Http => http_n += 1,
                        }
                        if let Some(receipt) = &resp.receipt {
                            let entry = settled_basis
                                .entry(receipt.provider)
                                .or_insert_with(|| (0u64, Vec::new()));
                            entry.0 += resp.token_indices.len() as u64;
                            entry.1.extend_from_slice(&receipt.commitment);
                        }
                        combiner.accumulate(&resp).map_err(|e| JsonRpcError {
                            code: -32004,
                            message: format!("moe combine: {e}"),
                            data: None,
                        })?;
                    }
                    BatchOutcome::HoldersExhausted(f) => failures.push(f),
                }
            }
        }
        if failures.is_empty() {
            break;
        }
        if replans >= MAX_REPLANS {
            if allow_partial {
                gave_up = true;
                break;
            }
            let f = failures.remove(0);
            return Err(f.error);
        }
        replans += 1;
        for f in &failures {
            excluded.extend(f.tried.iter().copied());
        }
        // Replan only the failed (expert, token) pairs against the view
        // minus every provider that already failed.
        let retry_view = tenzro_model::MoeShardView::build(
            &model_id,
            providers
                .iter()
                .filter(|pr| !excluded.contains(&pr.address)),
        );
        let mut by_token: BTreeMap<u32, Vec<ExpertId>> = BTreeMap::new();
        for f in &failures {
            for &tok in &f.tokens {
                by_token.entry(tok).or_default().push(f.expert);
            }
        }
        let retry_routings: Vec<TokenRouting> = by_token
            .into_iter()
            .map(|(token_index, experts)| TokenRouting {
                token_index,
                experts,
            })
            .collect();
        match tenzro_model::plan_dispatch(&retry_view, &retry_routings, allow_cold) {
            Ok(retry_plan) => {
                debug!(
                    replans,
                    retry_batches = retry_plan.batches.len(),
                    excluded = excluded.len(),
                    "moe failover: replanning failed batches"
                );
                batches_total += retry_plan.batches.len();
                pending = retry_plan.batches;
            }
            Err(e) => {
                // No remaining holder can serve the failed experts.
                if allow_partial {
                    gave_up = true;
                    break;
                }
                return Err(JsonRpcError {
                    code: -32000,
                    message: format!("moe failover replan: {e}"),
                    data: None,
                });
            }
        }
    }

    // 4. Finalize. The complete combine verifies every gate-selected
    //    contribution arrived; the partial combine renormalizes each
    //    affected token's surviving contributions and reports the slots
    //    that were dropped.
    let (combined, missing) = if gave_up {
        let partial = combiner.finish_partial().map_err(|e| JsonRpcError {
            code: -32004,
            message: format!("moe combine: {e}"),
            data: None,
        })?;
        (partial.outputs, partial.missing)
    } else {
        let full = combiner.finish().map_err(|e| JsonRpcError {
            code: -32004,
            message: format!("moe combine: {e}"),
            data: None,
        })?;
        (full, Vec::new())
    };

    let mut grouped_missing: BTreeMap<(u32, u32), Vec<u32>> = BTreeMap::new();
    for (expert, tok) in missing {
        grouped_missing
            .entry((expert.layer, expert.expert))
            .or_default()
            .push(tok);
    }
    let missing_json: Vec<Value> = grouped_missing
        .into_iter()
        .map(|((l, e), tokens)| json!({ "layer": l, "expert": e, "tokens": tokens }))
        .collect();

    // 5. Settle the remote expert work in the background: usage metering,
    //    settlement-engine audit record bound to the signed receipt
    //    commitments, and the settled-success reputation credit. The
    //    forward's response latency never waits on settlement.
    if !settled_basis.is_empty() {
        let settle_node = Arc::clone(node);
        let settle_model = model_id.clone();
        tokio::spawn(async move {
            settle_moe_forward(settle_node, settle_model, settled_basis).await;
        });
    }

    Ok(json!({
        "model_id": model_id,
        "layer": layer,
        "d_model": d_model,
        "top_k": top_k,
        "tokens": routed.len(),
        "batches": batches_total,
        "replans": replans,
        "missing": missing_json,
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
    /// Holder's wallet address — reputation and failover exclusion key.
    provider: Address,
    iroh_endpoint_id: Option<&'a str>,
    http_endpoint: Option<&'a str>,
}

/// Terminal outcome of one planned batch: a holder responded, or every
/// known holder (primary + standbys) failed. Exhaustion is a value, not
/// an error, so the forward loop can replan the affected tokens around
/// the failed providers instead of aborting the whole layer forward.
enum BatchOutcome {
    Success {
        resp: ExpertExecuteResponse,
        transport: Transport,
    },
    HoldersExhausted(BatchFailure),
}

/// A batch whose every known holder failed — the failover replan input.
struct BatchFailure {
    /// Expert the batch was destined for.
    expert: ExpertId,
    /// Token indices that still need this expert's contribution.
    tokens: Vec<u32>,
    /// Providers tried and failed; excluded from the replanned shard view.
    tried: Vec<Address>,
    /// Last holder's error — surfaced when failover cannot recover.
    error: JsonRpcError,
}

/// Execute one planned batch: local runtime when the expert is resident
/// here, else remote dispatch to the primary holder, redispatching to
/// each standby backup in turn on failure. Per remote holder the order is
/// iroh `tenzro/moe` (QUIC), then HTTP JSON-RPC (`tenzro_moeExecute`).
/// Holder failures record a reputation penalty (`record_call_failure`);
/// the winning holder's latency is metered via `record_success`. When
/// every holder fails the batch resolves to
/// [`BatchOutcome::HoldersExhausted`] carrying the tried provider set.
async fn execute_batch(
    node: &Arc<TenzroNode>,
    batch: &ExpertBatch,
    req: ExpertExecuteRequest,
    use_local: bool,
) -> Result<BatchOutcome, JsonRpcError> {
    // Local short-circuit: the router peer may itself hold the expert.
    // `use_local` is false on replan rounds after this node's own
    // execution failed, forcing the batch to its remote holders.
    if use_local
        && node
            .moe_runtime
            .has_expert(&req.model_id, req.layer, req.expert)
    {
        let runtime = Arc::clone(&node.moe_runtime);
        let local = tokio::task::spawn_blocking(move || runtime.execute(&req))
            .await
            .map_err(|e| JsonRpcError {
                code: -32603,
                message: format!("execute join: {e}"),
                data: None,
            })?;
        match local {
            Ok(resp) => {
                return Ok(BatchOutcome::Success {
                    resp,
                    transport: Transport::Local,
                });
            }
            Err(e) => {
                // Local execution failed — retire this node for the batch
                // so the replan routes the tokens to a remote holder.
                return Ok(BatchOutcome::HoldersExhausted(BatchFailure {
                    expert: batch.expert,
                    tokens: batch.token_indices.clone(),
                    tried: node.self_provider_address().into_iter().collect(),
                    error: JsonRpcError {
                        code: -32004,
                        message: format!("moe execute (local): {e}"),
                        data: None,
                    },
                }));
            }
        }
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
        provider: batch.provider,
        iroh_endpoint_id: batch.iroh_endpoint_id.as_deref(),
        http_endpoint: batch.http_endpoint.as_deref(),
    };
    let backups = batch.backups.iter().map(|b| HolderTarget {
        provider: b.provider,
        iroh_endpoint_id: b.iroh_endpoint_id.as_deref(),
        http_endpoint: b.http_endpoint.as_deref(),
    });
    let targets = std::iter::once(primary).chain(backups);

    let manager = node.provider_manager();
    let total = 1 + batch.backups.len();
    let mut tried: Vec<Address> = Vec::with_capacity(total);
    let mut last_err: Option<JsonRpcError> = None;
    for (attempt, target) in targets.enumerate() {
        let started = Instant::now();
        match dispatch_to_holder(node, batch, &params, &target)
            .await
            .and_then(|(resp, transport)| {
                let commitment = verify_remote_receipt(&req, &resp, &target.provider)?;
                Ok((resp, transport, commitment))
            }) {
            Ok((resp, transport, commitment)) => {
                if let Some(pm) = manager {
                    pm.record_success(&target.provider, started.elapsed().as_millis() as u64);
                }
                maybe_store_receipt(node, &req, &resp, commitment);
                return Ok(BatchOutcome::Success { resp, transport });
            }
            Err(e) => {
                if let Some(pm) = manager {
                    pm.record_call_failure(&target.provider);
                }
                tried.push(target.provider);
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
    Ok(BatchOutcome::HoldersExhausted(BatchFailure {
        expert: batch.expert,
        tokens: batch.token_indices.clone(),
        tried,
        error: last_err.unwrap_or_else(|| JsonRpcError {
            code: -32000,
            message: format!(
                "expert l{}/e{} has no reachable holder",
                batch.expert.layer, batch.expert.expert
            ),
            data: None,
        }),
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
    let client = crate::http_client::shared();
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

/// Verify the signed execution receipt on a remote holder response. The
/// receipt must be present, bound to the provider the batch was dispatched
/// to, commit to the exact carrier bytes the router sent and to the output
/// rows the holder returned (commitment recomputed router-side), and carry
/// a valid signature from the holder's announce key. Any failure retires
/// the holder for this batch — the standby / replan path takes over and
/// the holder eats a reputation penalty like any other call failure.
///
/// Returns the router-side recomputed activation commitment (full feature
/// rows, not just the hash) so the caller can sample it into the persisted
/// receipt store for later dispute re-execution.
fn verify_remote_receipt(
    req: &ExpertExecuteRequest,
    resp: &ExpertExecuteResponse,
    provider: &Address,
) -> Result<ExpertActivationCommitment, JsonRpcError> {
    let fail = |message: String| JsonRpcError {
        code: -32004,
        message,
        data: None,
    };
    let receipt = resp.receipt.as_ref().ok_or_else(|| {
        fail(format!(
            "expert l{}/e{} holder returned no execution receipt",
            req.layer, req.expert
        ))
    })?;
    if receipt.provider != *provider {
        return Err(fail(format!(
            "expert l{}/e{} receipt bound to a different provider",
            req.layer, req.expert
        )));
    }
    if resp.token_indices != req.token_indices {
        return Err(fail(format!(
            "expert l{}/e{} response token set differs from request",
            req.layer, req.expert
        )));
    }
    let commitment = ExpertActivationCommitment::from_outputs(
        &req.token_indices,
        &resp.outputs,
        req.d_model as usize,
        DEFAULT_ACTIVATION_K,
    )
    .map_err(|e| {
        fail(format!(
            "expert l{}/e{} receipt commitment recompute: {e}",
            req.layer, req.expert
        ))
    })?;
    verify_expert_receipt(
        receipt,
        &req.model_id,
        req.layer,
        req.expert,
        &req.token_indices,
        &req.carrier_hash(),
        &commitment.commitment_hash(),
    )
    .map_err(|e| {
        fail(format!(
            "expert l{}/e{} receipt invalid: {e}",
            req.layer, req.expert
        ))
    })?;
    Ok(commitment)
}

// ---------------------------------------------------------------------------
// Settlement + sampled receipt store (router side)
// ---------------------------------------------------------------------------

/// RocksDB key prefix for sampled MoE execution receipts (CF_SETTLEMENTS).
const MOE_RECEIPT_PREFIX: &str = "moe_receipt:";

/// Deterministic sampling mask over the receipt's commitment hash —
/// `hash[0] & MASK == 0` retains ~1/64 of verified batches. Holders cannot
/// predict which batches are retained because the commitment hash depends
/// on their own output values.
const MOE_RECEIPT_SAMPLE_MASK: u8 = 0x3F;

/// A sampled, dispute-capable execution receipt: the exact request carrier
/// the holder executed on, the router-side recomputed activation
/// commitment (full feature rows), and the holder's signed receipt. Any
/// peer holding the same expert can re-execute the request and compare
/// against the committed rows via `verify_activation_commitment`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct StoredMoeReceipt {
    pub request: ExpertExecuteRequest,
    pub commitment: ExpertActivationCommitment,
    pub receipt: ExpertExecutionReceipt,
    pub stored_at_ms: i64,
}

/// Sample a verified remote batch into the persisted receipt store. The
/// write is fire-and-forget on a blocking thread — dispatch latency never
/// waits on RocksDB.
fn maybe_store_receipt(
    node: &Arc<TenzroNode>,
    req: &ExpertExecuteRequest,
    resp: &ExpertExecuteResponse,
    commitment: ExpertActivationCommitment,
) {
    let Some(receipt) = resp.receipt.clone() else {
        return;
    };
    if receipt.commitment[0] & MOE_RECEIPT_SAMPLE_MASK != 0 {
        return;
    }
    let Some(storage) = node.storage().cloned() else {
        return;
    };
    let stored_at_ms = tenzro_types::Timestamp::now().as_millis();
    let key = format!(
        "{MOE_RECEIPT_PREFIX}{}:{stored_at_ms:013}:{}",
        req.model_id,
        hex::encode(&receipt.commitment[..8]),
    );
    let record = StoredMoeReceipt {
        request: req.clone(),
        commitment,
        receipt,
        stored_at_ms,
    };
    tokio::task::spawn_blocking(move || match serde_json::to_vec(&record) {
        Ok(bytes) => {
            if let Err(e) = storage.put(CF_SETTLEMENTS, key.as_bytes(), &bytes) {
                warn!("moe receipt store write failed ({key}): {e}");
            }
        }
        Err(e) => warn!("moe receipt store encode failed ({key}): {e}"),
    });
}

/// Settle one forward's remote expert work, per holder: meter usage,
/// record the settlement-engine audit entry bound to the signed receipt
/// commitments, and credit the holder's reputation via
/// `record_settled_success` — the only score-up path. Pricing is the
/// holder's own per-input-token price with its minimum-price floor; the
/// network's inference commission is deducted before the reputation
/// credit so the credited amount is what the holder actually earned.
async fn settle_moe_forward(
    node: Arc<TenzroNode>,
    model_id: String,
    settled_basis: HashMap<Address, (u64, Vec<u8>)>,
) {
    use tenzro_types::settlement::{ProofType, ServiceProof, ServiceType, SettlementRequest};

    let Some(manager) = node.provider_manager().cloned() else {
        return;
    };
    let Some(payer) = node.self_provider_address() else {
        return;
    };
    // The network's share of an expert's gross, read from the live economic
    // policy rather than a constant, so a governance change reaches this path
    // at the same moment it reaches every other one. An expert holder is the
    // operator here — they did the work — so what the network takes is whatever
    // the split does not give the operator.
    let policy = node.economic_policy();
    let mode = tenzro_types::economics::NodeEconomicMode::resolve(
        node.advertises(tenzro_types::node_visibility::Capability::Ai),
        node.runtime_roles.read().is_validator(),
    );
    let commission_bps = (tenzro_types::economics::BPS_DENOMINATOR
        - policy.share_bps(mode, tenzro_types::economics::PayeeRole::Operator))
        as u64;
    for (holder, (tokens, commitments)) in settled_basis {
        let pricing = manager
            .get_provider(&holder)
            .map(|p| p.pricing)
            .unwrap_or_default();
        let gross = tokens
            .saturating_mul(pricing.price_per_input_token)
            .max(pricing.minimum_price);
        let commission = gross.saturating_mul(commission_bps) / 10_000;
        let net = gross.saturating_sub(commission);
        let tokens_u32 = tokens.min(u32::MAX as u64) as u32;

        if let Some(tracker) = node.usage_tracker()
            && let Err(e) = tracker.record_usage(tenzro_model::UsageRecord::new(
                model_id.clone(),
                holder,
                // A remote expert is billed on the tokens routed to it, which
                // are prefill work on the holder's side: there is no completion
                // leg, no cache, and no media dimension in a forward pass.
                tenzro_types::model::BillableUnits::tokens(tokens_u32, 0),
                0,
                0,
                gross,
                0,
            ))
        {
            warn!("moe usage record failed for {holder}: {e}");
        }

        if let Some(engine) = node.settlement() {
            let proof = ServiceProof::new(ProofType::Cryptographic, commitments);
            let request = SettlementRequest::new(
                holder,
                payer,
                ServiceType::ModelInference {
                    model_id: model_id.clone(),
                    tokens: tokens_u32,
                },
                gross,
                proof,
            );
            if let Err(e) = engine.settle(request).await {
                warn!("moe settlement audit-record failed for {holder}: {e}");
            }
        }

        manager.record_settled_success(&holder, net as u128);
    }
}

/// `tenzro_moeListReceipts` — summaries of the sampled execution receipts
/// this router has persisted. Optional `model_id` filter; `limit` caps the
/// scan (default 100, newest keys are lexicographically later so the tail
/// is returned).
pub(crate) async fn handle_moe_list_receipts(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.unwrap_or(json!({}));
    let model_filter = p.get("model_id").and_then(|v| v.as_str()).map(String::from);
    let limit = p
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(100)
        .min(1000) as usize;
    let storage = node.storage().cloned().ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "storage not initialized".into(),
        data: None,
    })?;
    let prefix = match &model_filter {
        Some(m) => format!("{MOE_RECEIPT_PREFIX}{m}:"),
        None => MOE_RECEIPT_PREFIX.to_string(),
    };
    let receipts = tokio::task::spawn_blocking(move || -> Result<Vec<Value>, String> {
        let mut keys = storage
            .get_keys_with_prefix(CF_SETTLEMENTS, prefix.as_bytes())
            .map_err(|e| format!("receipt scan: {e}"))?;
        keys.sort();
        let tail = keys.len().saturating_sub(limit);
        let mut out = Vec::with_capacity(keys.len() - tail);
        for key in &keys[tail..] {
            let Some(bytes) = storage
                .get(CF_SETTLEMENTS, key)
                .map_err(|e| format!("receipt read: {e}"))?
            else {
                continue;
            };
            let record: StoredMoeReceipt = match serde_json::from_slice(&bytes) {
                Ok(r) => r,
                Err(_) => continue,
            };
            out.push(json!({
                "key": String::from_utf8_lossy(key),
                "model_id": record.request.model_id,
                "layer": record.request.layer,
                "expert": record.request.expert,
                "tokens": record.request.token_indices.len(),
                "provider": record.receipt.provider.to_string(),
                "commitment": hex::encode(record.receipt.commitment),
                "stored_at_ms": record.stored_at_ms,
            }));
        }
        Ok(out)
    })
    .await
    .map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("receipt scan join: {e}"),
        data: None,
    })?
    .map_err(|e| JsonRpcError {
        code: -32000,
        message: e,
        data: None,
    })?;
    Ok(json!({ "receipts": receipts, "count": receipts.len() }))
}

/// `tenzro_moeDisputeReceipt` — re-execute a sampled receipt's exact
/// request carrier against this node's own copy of the expert and compare
/// the output rows to the committed activation sketch. A failing
/// comparison is a fraud proof against the signed receipt: the holder is
/// hit with the stream-grade reputation penalty (quarantine-weight, same
/// as a corrupted stream). This node must hold the disputed expert.
pub(crate) async fn handle_moe_dispute_receipt(
    node: &Arc<TenzroNode>,
    params: Option<Value>,
) -> Result<Value, JsonRpcError> {
    let p = params.unwrap_or(json!({}));
    let key = req_str(&p, "key")?.to_string();
    let storage = node.storage().cloned().ok_or_else(|| JsonRpcError {
        code: -32000,
        message: "storage not initialized".into(),
        data: None,
    })?;
    let key_bytes = key.clone().into_bytes();
    let record = tokio::task::spawn_blocking(move || {
        storage
            .get(CF_SETTLEMENTS, &key_bytes)
            .map_err(|e| format!("receipt read: {e}"))
    })
    .await
    .map_err(|e| JsonRpcError {
        code: -32603,
        message: format!("receipt read join: {e}"),
        data: None,
    })?
    .map_err(|e| JsonRpcError {
        code: -32000,
        message: e,
        data: None,
    })?
    .ok_or_else(|| JsonRpcError {
        code: -32004,
        message: format!("no stored receipt at key {key}"),
        data: None,
    })?;
    let record: StoredMoeReceipt = serde_json::from_slice(&record).map_err(|e| JsonRpcError {
        code: -32000,
        message: format!("receipt decode: {e}"),
        data: None,
    })?;

    // The stored signature was verified at dispatch time; re-verify so a
    // tampered store row cannot manufacture a fraud proof.
    verify_expert_receipt(
        &record.receipt,
        &record.request.model_id,
        record.request.layer,
        record.request.expert,
        &record.request.token_indices,
        &record.request.carrier_hash(),
        &record.commitment.commitment_hash(),
    )
    .map_err(|e| JsonRpcError {
        code: -32004,
        message: format!("stored receipt no longer verifies: {e}"),
        data: None,
    })?;

    if !node.moe_runtime.has_expert(
        &record.request.model_id,
        record.request.layer,
        record.request.expert,
    ) {
        return Err(JsonRpcError {
            code: -32004,
            message: format!(
                "disputing node does not hold expert l{}/e{} of {}",
                record.request.layer, record.request.expert, record.request.model_id
            ),
            data: None,
        });
    }

    let runtime = Arc::clone(&node.moe_runtime);
    let reexec_req = record.request.clone();
    let reexec = tokio::task::spawn_blocking(move || runtime.execute(&reexec_req))
        .await
        .map_err(|e| JsonRpcError {
            code: -32603,
            message: format!("re-execute join: {e}"),
            data: None,
        })?
        .map_err(|e| JsonRpcError {
            code: -32004,
            message: format!("re-execute: {e}"),
            data: None,
        })?;

    let verification = tenzro_model::verify_activation_commitment(
        &record.commitment,
        &reexec.outputs,
        record.request.d_model as usize,
    )
    .map_err(|e| JsonRpcError {
        code: -32004,
        message: format!("activation verify: {e}"),
        data: None,
    })?;

    let disputed = !verification.pass;
    if disputed && let Some(pm) = node.provider_manager() {
        pm.record_stream_failure(&record.receipt.provider);
        warn!(
            provider = %record.receipt.provider,
            model = %record.request.model_id,
            expert = %format!("l{}/e{}", record.request.layer, record.request.expert),
            "moe receipt dispute UPHELD — holder output diverges from committed activations"
        );
    }

    Ok(json!({
        "key": key,
        "model_id": record.request.model_id,
        "layer": record.request.layer,
        "expert": record.request.expert,
        "tokens": record.request.token_indices.len(),
        "provider": record.receipt.provider.to_string(),
        "commitment": hex::encode(record.receipt.commitment),
        "disputed": disputed,
        "verification": {
            "rows_total": verification.rows_total,
            "rows_passed": verification.rows_passed,
            "failing_rows": verification.failing_rows,
            "pass": verification.pass,
        },
    }))
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
    let result = envelope
        .get("result")
        .cloned()
        .ok_or_else(|| JsonRpcError {
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
        let d = MoeIrohDispatcher::new(Arc::new(MoeExpertRuntime::new()), None);
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
        let d = MoeIrohDispatcher::new(Arc::new(MoeExpertRuntime::new()), None);
        let resp = d.dispatch(Bytes::from_static(b"not json")).await.unwrap();
        let v: Value = serde_json::from_slice(&resp).unwrap();
        assert_eq!(v["error"]["code"], -32700);
    }

    #[tokio::test]
    async fn dispatcher_execute_unloaded_expert_is_model_error() {
        let d = MoeIrohDispatcher::new(Arc::new(MoeExpertRuntime::new()), None);
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
        let d = MoeIrohDispatcher::new(Arc::new(MoeExpertRuntime::new()), None);
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
