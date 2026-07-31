//! Dispatch for the `builtin://` endpoint scheme.
//!
//! Skills and tools the node registers for itself carry a
//! `builtin://<name>` endpoint rather than an HTTP URL. Those names
//! resolve to node-owned machinery: the inference router for the
//! model-backed skills, the ledger read handlers for `blockchain-query`,
//! the `tenzro_training_*` surface for `tenzro-trainer`, the WASI 0.2
//! component sandbox for `code-executor`, and the node's own workspace
//! under `data_dir` for `file-manager`.
//!
//! Four tools address a node-native write rather than a read: the Canton
//! mandate submission, TDIP identity registration, blob publication, and
//! the ERC-7683 origin open. They exist as tools so a workflow step can
//! reach them through `tenzro_useTool` with a pinned id, which is what
//! the reference templates under `templates/workflows/` do.
//!
//! Two builtins broker an upstream the operator supplies rather than
//! the node: `web-search` / `web-search-mcp` need a SearXNG-compatible
//! JSON search endpoint, and `oneinch-aggregator` needs a 1inch API
//! key. Both are registered only when that upstream is configured, so a
//! node without it never advertises the entry.
//!
//! `tenzro_useSkill` and `tenzro_useTool` settle the invocation before
//! they reach dispatch, so a builtin arm never runs for a caller who
//! could not pay.

use std::path::{Component, Path, PathBuf};
use std::sync::Arc;

use serde_json::{json, Value};

use crate::node::TenzroNode;
use crate::rpc::JsonRpcError;

/// Endpoint scheme every node-owned skill and tool registers under.
pub(crate) const SCHEME: &str = "builtin://";

/// 1inch classic-swap base. Chain id is appended as a path segment.
const ONEINCH_SWAP_BASE: &str = "https://api.1inch.com/swap/v6.1";

/// Returns the builtin name an endpoint addresses, or `None` when the
/// endpoint belongs to another transport.
pub(crate) fn builtin_target(endpoint: &str) -> Option<&str> {
    endpoint.strip_prefix(SCHEME)
}

fn invalid_params(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32602,
        message: message.into(),
        data: None,
    }
}

fn unavailable(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32603,
        message: message.into(),
        data: None,
    }
}

fn upstream_error(message: impl Into<String>) -> JsonRpcError {
    JsonRpcError {
        code: -32000,
        message: message.into(),
        data: None,
    }
}

fn unknown_builtin(kind: &str, name: &str) -> JsonRpcError {
    JsonRpcError {
        code: -32601,
        message: format!("No dispatch for builtin {kind} '{name}'"),
        data: None,
    }
}

fn str_param<'a>(input: &'a Value, key: &str) -> std::result::Result<&'a str, JsonRpcError> {
    input
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid_params(format!("Missing '{key}'")))
}

/// Dispatch a `builtin://` skill invocation.
pub(crate) async fn dispatch_skill(
    node: &Arc<TenzroNode>,
    name: &str,
    input: &Value,
) -> std::result::Result<Value, JsonRpcError> {
    match name {
        "web-search" => web_search(node, input).await,
        "code-review" => {
            model_skill(
                node,
                "code",
                "You are a code reviewer. Report correctness bugs, security \
                 issues, and concrete improvements. Cite the line or symbol \
                 each finding applies to.",
                input,
            )
            .await
        }
        "data-analysis" => {
            model_skill(
                node,
                "reasoning",
                "You are a data analyst. Describe what the data shows, state \
                 the reasoning behind each conclusion, and name the \
                 assumptions a conclusion depends on.",
                input,
            )
            .await
        }
        "text-summarization" => {
            model_skill(
                node,
                "summarize",
                "Summarize the text. Preserve the claims, figures, and named \
                 entities that carry meaning; drop everything else.",
                input,
            )
            .await
        }
        "blockchain-query" => blockchain_query(node, input).await,
        "oneinch-aggregator" => oneinch(node, input).await,
        "tenzro-trainer" => trainer(node, input).await,
        other => Err(unknown_builtin("skill", other)),
    }
}

/// Dispatch a `builtin://` tool invocation. `tool_name` selects the
/// operation within the tool.
///
/// `api_key` is the key the caller presented to `tenzro_useTool`, if any.
/// Only the arms that reach an operator-brokered resource read it — the
/// Canton write needs a canton-scoped tenant key to resolve which party
/// acts.
pub(crate) async fn dispatch_tool(
    node: &Arc<TenzroNode>,
    name: &str,
    tool_name: &str,
    params: &Value,
    api_key: Option<&str>,
) -> std::result::Result<Value, JsonRpcError> {
    match name {
        "web-search-mcp" => match tool_name {
            "web_search" | "invoke" => web_search(node, params).await,
            "url_fetch" => url_fetch(params).await,
            other => Err(invalid_params(format!(
                "Unknown web-search-mcp tool '{other}' (expected web_search|url_fetch)"
            ))),
        },
        "code-executor" => execute_component(node, params).await,
        "file-manager" => file_manager(node, tool_name, params).await,
        "canton-submit-mandate" => {
            crate::rpc::handle_canton_submit_with_mandate(node, Some(params.clone()), api_key).await
        }
        "identity-register" => {
            crate::rpc::handle_register_identity(node, Some(params.clone())).await
        }
        "da-publish" => da_publish(node, params).await,
        "erc7683-origin" => erc7683_origin(node, params).await,
        other => Err(unknown_builtin("tool", other)),
    }
}

// ─────────────────────────────────────────────────────────────────────
// Model-backed skills
// ─────────────────────────────────────────────────────────────────────

/// Route the skill's text through intent-based inference. `use_case`
/// picks the routing class; `system` is the skill's own instruction,
/// prepended to the caller's text. No model id is pinned — the
/// MetaRouter selects one from the models this node can reach.
async fn model_skill(
    node: &Arc<TenzroNode>,
    use_case: &str,
    system: &str,
    input: &Value,
) -> std::result::Result<Value, JsonRpcError> {
    let text = input
        .get("text")
        .or_else(|| input.get("input"))
        .or_else(|| input.get("content"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid_params("Missing 'text'"))?;

    let mut params = json!({
        "use_case": use_case,
        "messages": [
            { "role": "system", "content": system },
            { "role": "user", "content": text },
        ],
    });

    // Forward the routing controls the caller may set on the skill
    // input so a skill invocation has the same reach as a direct
    // `tenzro_chatByIntent` call.
    for key in [
        "budget",
        "optimize",
        "quality_floor",
        "est_input_tokens",
        "est_output_tokens",
        "max_tokens",
        "temperature",
    ] {
        if let Some(v) = input.get(key) {
            params[key] = v.clone();
        }
    }

    crate::rpc::handle_chat_by_intent(node, Some(params)).await
}

// ─────────────────────────────────────────────────────────────────────
// Web search + URL fetch
// ─────────────────────────────────────────────────────────────────────

/// Query the operator's SearXNG-compatible endpoint and project the
/// result set down to the fields a skill consumer needs.
///
/// Wire format per the SearXNG search API: `GET {base}/search` with
/// `q` and `format=json`, optional `categories`, `language`, `pageno`,
/// `time_range`, `safesearch`.
async fn web_search(
    node: &Arc<TenzroNode>,
    input: &Value,
) -> std::result::Result<Value, JsonRpcError> {
    let base = node
        .config()
        .builtins
        .search_url
        .as_deref()
        .ok_or_else(|| unavailable("No search endpoint configured on this node"))?;
    let query = input
        .get("query")
        .or_else(|| input.get("q"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid_params("Missing 'query'"))?;

    let url = format!("{}/search", base.trim_end_matches('/'));
    let mut req = crate::http_client::shared()
        .get(&url)
        .query(&[("q", query), ("format", "json")]);
    for key in ["categories", "language", "time_range"] {
        if let Some(v) = input.get(key).and_then(|v| v.as_str()) {
            req = req.query(&[(key, v)]);
        }
    }
    if let Some(page) = input.get("page").and_then(|v| v.as_u64()) {
        req = req.query(&[("pageno", page.to_string())]);
    }
    if let Some(safe) = input.get("safesearch").and_then(|v| v.as_u64()) {
        req = req.query(&[("safesearch", safe.to_string())]);
    }
    if let Some(key) = node.config().builtins.search_api_key.as_deref() {
        req = req.bearer_auth(key);
    }

    let resp = req
        .send()
        .await
        .map_err(|e| upstream_error(format!("Search request failed: {e}")))?;
    if !resp.status().is_success() {
        return Err(upstream_error(format!(
            "Search endpoint returned HTTP {}",
            resp.status().as_u16()
        )));
    }
    let body: Value = resp
        .json()
        .await
        .map_err(|e| upstream_error(format!("Search response was not JSON: {e}")))?;

    let limit = input
        .get("limit")
        .and_then(|v| v.as_u64())
        .unwrap_or(10)
        .clamp(1, 50) as usize;
    let results: Vec<Value> = body
        .get("results")
        .and_then(|v| v.as_array())
        .map(|rows| {
            rows.iter()
                .take(limit)
                .map(|r| {
                    json!({
                        "title": r.get("title").cloned().unwrap_or(Value::Null),
                        "url": r.get("url").cloned().unwrap_or(Value::Null),
                        "content": r.get("content").cloned().unwrap_or(Value::Null),
                        "published_date": r.get("publishedDate").cloned().unwrap_or(Value::Null),
                        "engine": r.get("engine").cloned().unwrap_or(Value::Null),
                        "score": r.get("score").cloned().unwrap_or(Value::Null),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(json!({
        "query": query,
        "results": results,
        "number_of_results": body.get("number_of_results").cloned().unwrap_or(Value::Null),
        "answers": body.get("answers").cloned().unwrap_or_else(|| json!([])),
        "suggestions": body.get("suggestions").cloned().unwrap_or_else(|| json!([])),
    }))
}

/// Fetch a URL over HTTP GET and return its body as text.
async fn url_fetch(params: &Value) -> std::result::Result<Value, JsonRpcError> {
    let url = str_param(params, "url")?;
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(invalid_params("'url' must be an http or https URL"));
    }
    let max_bytes = params
        .get("max_bytes")
        .and_then(|v| v.as_u64())
        .unwrap_or(262_144)
        .clamp(1, 4_194_304) as usize;

    let resp = crate::http_client::shared()
        .get(url)
        .send()
        .await
        .map_err(|e| upstream_error(format!("Fetch failed: {e}")))?;
    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let body = resp
        .text()
        .await
        .map_err(|e| upstream_error(format!("Body read failed: {e}")))?;
    let truncated = body.len() > max_bytes;
    let body = if truncated {
        // Cut on a char boundary so the projection stays valid UTF-8.
        let mut end = max_bytes;
        while end > 0 && !body.is_char_boundary(end) {
            end -= 1;
        }
        body[..end].to_string()
    } else {
        body
    };

    Ok(json!({
        "url": url,
        "status": status,
        "content_type": content_type,
        "body": body,
        "truncated": truncated,
    }))
}

// ─────────────────────────────────────────────────────────────────────
// Ledger reads
// ─────────────────────────────────────────────────────────────────────

/// Read-only projection over the node's own ledger handlers. `operation`
/// picks which read runs; the remaining input is forwarded as that
/// handler's params.
async fn blockchain_query(
    node: &Arc<TenzroNode>,
    input: &Value,
) -> std::result::Result<Value, JsonRpcError> {
    let operation = str_param(input, "operation")?;
    let params = Some(input.clone());
    let result = match operation {
        "balance" => crate::rpc::handle_get_balance(node, params).await?,
        "nonce" => crate::rpc::handle_get_nonce(node, params).await?,
        "block" => crate::rpc::handle_get_block(node, params).await?,
        "transaction" => crate::rpc::handle_get_transaction(node, params).await?,
        "block_number" => crate::rpc::handle_block_number(node).await?,
        "status" => crate::rpc::handle_node_info(node).await?,
        other => {
            return Err(invalid_params(format!(
                "Unknown blockchain-query operation '{other}' (expected \
                 balance|nonce|block|transaction|block_number|status)"
            )))
        }
    };
    Ok(json!({ "operation": operation, "result": result }))
}

// ─────────────────────────────────────────────────────────────────────
// 1inch aggregation
// ─────────────────────────────────────────────────────────────────────

/// Proxy the 1inch classic-swap API with the operator's own key. The
/// caller never sees the key: the node brokers the request and returns
/// the upstream body.
async fn oneinch(
    node: &Arc<TenzroNode>,
    input: &Value,
) -> std::result::Result<Value, JsonRpcError> {
    let api_key = node
        .config()
        .builtins
        .oneinch_api_key
        .as_deref()
        .ok_or_else(|| unavailable("No 1inch API key configured on this node"))?;
    let operation = str_param(input, "operation")?;
    let chain_id = input
        .get("chain_id")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| invalid_params("Missing 'chain_id'"))?;

    let path = match operation {
        "quote" => "quote",
        "swap" => "swap",
        "tokens" => "tokens",
        "liquidity_sources" => "liquidity-sources",
        "approve_spender" => "approve/spender",
        "approve_transaction" => "approve/transaction",
        "approve_allowance" => "approve/allowance",
        other => {
            return Err(invalid_params(format!(
                "Unknown oneinch-aggregator operation '{other}' (expected \
                 quote|swap|tokens|liquidity_sources|approve_spender|\
                 approve_transaction|approve_allowance)"
            )))
        }
    };

    let url = format!("{ONEINCH_SWAP_BASE}/{chain_id}/{path}");
    let mut req = crate::http_client::shared().get(&url).bearer_auth(api_key);
    for key in [
        "src",
        "dst",
        "amount",
        "from",
        "slippage",
        "tokenAddress",
        "walletAddress",
    ] {
        if let Some(v) = input.get(key) {
            let as_str = match v {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            req = req.query(&[(key, as_str)]);
        }
    }
    for key in ["disableEstimate", "allowPartialFill"] {
        if let Some(v) = input.get(key).and_then(|v| v.as_bool()) {
            req = req.query(&[(key, v.to_string())]);
        }
    }

    let resp = req
        .send()
        .await
        .map_err(|e| upstream_error(format!("1inch request failed: {e}")))?;
    let status = resp.status();
    let body: Value = resp
        .json()
        .await
        .map_err(|e| upstream_error(format!("1inch response was not JSON: {e}")))?;
    if !status.is_success() {
        return Err(upstream_error(format!(
            "1inch returned HTTP {}: {}",
            status.as_u16(),
            body
        )));
    }
    Ok(json!({ "operation": operation, "chain_id": chain_id, "result": body }))
}

// ─────────────────────────────────────────────────────────────────────
// Training
// ─────────────────────────────────────────────────────────────────────

/// Drive a training run through the node's own `tenzro_training_*`
/// handlers. `operation` names the step; the rest of the input is that
/// handler's params.
async fn trainer(
    node: &Arc<TenzroNode>,
    input: &Value,
) -> std::result::Result<Value, JsonRpcError> {
    let operation = str_param(input, "operation")?;
    let params = Some(input.clone());
    let result = match operation {
        "post_task" => crate::rpc::handle_training_post_task(node, params).await?,
        "list_runs" => crate::rpc::handle_training_list_runs(node).await?,
        "get_run" => crate::rpc::handle_training_get_run(node, params).await?,
        "get_receipt" => crate::rpc::handle_training_get_receipt(node, params).await?,
        "enroll_trainer" => crate::rpc::handle_training_enroll_trainer(node, params).await?,
        "submit_gradient" => {
            crate::rpc::handle_training_submit_outer_gradient(node, params).await?
        }
        "finalize_round" => crate::rpc::handle_training_finalize_round(node, params).await?,
        "decide_round" => crate::rpc::handle_training_decide_round(node, params).await?,
        "challenge_commitment" => {
            crate::rpc::handle_training_challenge_commitment(node, params).await?
        }
        "install_sealed_manifest" => {
            crate::rpc::handle_training_install_sealed_manifest(node, params).await?
        }
        "get_sealed_manifest" => {
            crate::rpc::handle_training_get_sealed_manifest(node, params).await?
        }
        other => {
            return Err(invalid_params(format!(
                "Unknown tenzro-trainer operation '{other}' (expected \
                 post_task|list_runs|get_run|get_receipt|enroll_trainer|\
                 submit_gradient|finalize_round|decide_round|\
                 challenge_commitment|install_sealed_manifest|\
                 get_sealed_manifest)"
            )))
        }
    };
    Ok(json!({ "operation": operation, "result": result }))
}

// ─────────────────────────────────────────────────────────────────────
// WASI 0.2 component execution
// ─────────────────────────────────────────────────────────────────────

/// Execute a caller-supplied WASI 0.2 component in the sandbox.
///
/// The component is what runs — the languages the tool advertises
/// (Python, JavaScript, Rust) are the languages a component is compiled
/// *from*, not source text this handler interprets. Registration
/// re-hashes the bytes against `content_hash_hex`, so the id a caller
/// pins is the content address of what executed.
#[cfg(feature = "wasi-skills")]
async fn execute_component(
    node: &Arc<TenzroNode>,
    params: &Value,
) -> std::result::Result<Value, JsonRpcError> {
    use base64::Engine as _;
    use sha2::{Digest, Sha256};

    let sandbox = node.sandboxed_tools();

    let component_b64 = str_param(params, "component_b64")?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(component_b64)
        .map_err(|e| invalid_params(format!("'component_b64' is not valid base64: {e}")))?;
    let content_hash_hex = hex::encode(Sha256::digest(&bytes));

    // The name of an export inside the `tenzro:skill/skill@1.0.0` interface,
    // which is where the runtime resolves it. `invoke` is the contract every
    // component implements; a component exporting more than one entry point
    // names the one it wants.
    let function = params
        .get("function")
        .and_then(|v| v.as_str())
        .unwrap_or(crate::skill_sandbox::SKILL_EXPORT);
    let input = params.get("input").cloned().unwrap_or_else(|| json!({}));
    let caller_did = params
        .get("caller_did")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    // The registration is per-call, so two concurrent invocations of the same
    // bytes cannot unregister each other mid-flight. The content address stays
    // the identity the caller audits — it is what the receipt binds and what
    // the response reports.
    let registration_id = format!("{content_hash_hex}:{}", uuid::Uuid::new_v4());

    let manifest = tenzro_wasm::ComponentManifest {
        id: registration_id.clone(),
        version: "1.0.0".to_string(),
        content_hash_hex: content_hash_hex.clone(),
        runtime: tenzro_wasm::ComponentRuntime::McpTool,
        capabilities: Default::default(),
        deadline_ms: params.get("deadline_ms").and_then(|v| v.as_u64()),
        fuel_limit: params.get("fuel_limit").and_then(|v| v.as_u64()),
        description: None,
        creator_did: caller_did.clone(),
    };

    let input_bytes = bytes::Bytes::from(
        serde_json::to_vec(&input)
            .map_err(|e| invalid_params(format!("'input' is not serializable: {e}")))?,
    );
    sandbox
        .register(manifest, bytes::Bytes::from(bytes))
        .map_err(|e| invalid_params(format!("Component rejected: {e}")))?;
    let outcome = sandbox
        .invoke(&registration_id, function, input_bytes, caller_did)
        .await;
    // The component is single-use here: drop it so a long-lived node does
    // not accumulate one entry per call.
    sandbox.unregister(&registration_id);

    let (output, receipt) =
        outcome.map_err(|e| upstream_error(format!("Component execution failed: {e}")))?;
    let output_value = serde_json::from_slice::<Value>(output.as_ref())
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(output.as_ref()).into_owned()));

    Ok(json!({
        "component_id": content_hash_hex,
        "function": function,
        "output": output_value,
        "receipt": receipt,
    }))
}

/// Without the `wasi-skills` feature the node holds no component engine,
/// so the sandbox reports itself unavailable rather than pretending to
/// execute.
#[cfg(not(feature = "wasi-skills"))]
async fn execute_component(
    _node: &Arc<TenzroNode>,
    _params: &Value,
) -> std::result::Result<Value, JsonRpcError> {
    Err(unavailable(
        "This node was built without the component sandbox (wasi-skills)",
    ))
}

// ─────────────────────────────────────────────────────────────────────
// Workspace files
// ─────────────────────────────────────────────────────────────────────

/// Agent workspace root. Every `file-manager` path resolves under this
/// directory, so a workspace can never reach the node's keys, its
/// RocksDB column families, or the host filesystem.
fn workspace_root(node: &Arc<TenzroNode>) -> PathBuf {
    node.config().data_dir.join("agent_workspace")
}

/// Join `rel` under `root`, rejecting anything that could escape:
/// absolute paths, `..`, and Windows prefixes.
fn resolve_workspace_path(
    root: &Path,
    rel: &str,
) -> std::result::Result<PathBuf, JsonRpcError> {
    let rel_path = Path::new(rel);
    let mut out = root.to_path_buf();
    for component in rel_path.components() {
        match component {
            Component::Normal(part) => out.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(invalid_params(
                    "'path' must be relative and must not traverse outside the workspace",
                ))
            }
        }
    }
    if out == root {
        return Err(invalid_params("'path' must name a file or subdirectory"));
    }
    Ok(out)
}

/// Publish a payload to the data-availability layer.
///
/// `tenzro_irohPublishBlob` takes base64 bytes, but a workflow step
/// assembles its payload from earlier step outputs as JSON. This arm
/// accepts either form: `bytes_b64` passes through, `data` is
/// serialized and encoded here.
async fn da_publish(
    node: &Arc<TenzroNode>,
    params: &Value,
) -> std::result::Result<Value, JsonRpcError> {
    use base64::Engine as _;

    let bytes_b64 = match params.get("bytes_b64") {
        Some(v) => v
            .as_str()
            .ok_or_else(|| invalid_params("'bytes_b64' must be a base64 string"))?
            .to_string(),
        None => {
            let data = params
                .get("data")
                .ok_or_else(|| invalid_params("Missing 'data' (JSON payload) or 'bytes_b64'"))?;
            let encoded = serde_json::to_vec(data).map_err(|e| {
                invalid_params(format!("'data' could not be serialized: {e}"))
            })?;
            base64::engine::general_purpose::STANDARD.encode(encoded)
        }
    };

    crate::rpc::handle_iroh_publish_blob(node, Some(json!({ "bytes_b64": bytes_b64 }))).await
}

/// Parse a hex string into a fixed 32-byte chain-discriminated value.
/// A 20-byte EVM address is right-aligned, matching how 7683 encodes
/// addresses into its `bytes32` recipient fields.
fn hex_to_bytes32(value: &str, field: &str) -> std::result::Result<[u8; 32], JsonRpcError> {
    let raw = hex::decode(value.trim_start_matches("0x"))
        .map_err(|e| invalid_params(format!("'{field}' is not valid hex: {e}")))?;
    match raw.len() {
        32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&raw);
            Ok(out)
        }
        20 => {
            let mut out = [0u8; 32];
            out[12..].copy_from_slice(&raw);
            Ok(out)
        }
        n => Err(invalid_params(format!(
            "'{field}' must be 20 or 32 bytes, got {n}"
        ))),
    }
}

/// Parse a token amount into a big-endian uint256. A decimal string is
/// the precise form — it round-trips u128 through JSON — but a step
/// whose amount came from a model output may carry a JSON number, so
/// both are accepted.
fn decimal_to_uint256(
    value: &Value,
    field: &str,
) -> std::result::Result<[u8; 32], JsonRpcError> {
    let amount: u128 = match value {
        Value::String(s) => s
            .parse()
            .map_err(|e| invalid_params(format!("'{field}' is not a u128 decimal: {e}")))?,
        Value::Number(n) => n
            .as_u64()
            .ok_or_else(|| {
                invalid_params(format!(
                    "'{field}' must be a non-negative integer — pass a decimal string for values above u64"
                ))
            })?
            .into(),
        _ => {
            return Err(invalid_params(format!(
                "'{field}' must be a decimal string or an integer"
            )))
        }
    };
    Ok(tenzro_types::intent_7683::u128_to_uint256_be(amount))
}

/// Open an ERC-7683 order on the origin side.
///
/// `tenzro_open7683Order` takes `order_data` as hex-encoded bincode,
/// which a workflow step cannot produce. This arm also accepts the
/// payload as a JSON object and encodes it here, so a step can size an
/// order from an earlier step's output.
async fn erc7683_origin(
    node: &Arc<TenzroNode>,
    params: &Value,
) -> std::result::Result<Value, JsonRpcError> {
    use tenzro_types::intent_7683::{Output, ProofRoute, TenzroOrderData, TokenAmount};

    let order_data = params
        .get("order_data")
        .ok_or_else(|| invalid_params("Missing 'order_data'"))?;

    // Hex payloads (foreign origins, or a caller that already encoded)
    // pass through untouched.
    let mut forwarded = params.clone();
    if let Some(obj) = order_data.as_object() {
        let parse_route = |v: &Value| -> std::result::Result<ProofRoute, JsonRpcError> {
            match v.as_str() {
                Some("layerzero") => Ok(ProofRoute::LayerZero),
                Some("wormhole") => Ok(ProofRoute::Wormhole),
                Some("debridge") => Ok(ProofRoute::DeBridge),
                Some("hyperlane") => Ok(ProofRoute::Hyperlane),
                other => Err(invalid_params(format!(
                    "Unknown proof_route '{}' — expected one of layerzero, wormhole, debridge, hyperlane",
                    other.unwrap_or("<not a string>")
                ))),
            }
        };

        let mut inputs = Vec::new();
        for (i, entry) in obj
            .get("inputs")
            .and_then(|v| v.as_array())
            .ok_or_else(|| invalid_params("'order_data.inputs' must be an array"))?
            .iter()
            .enumerate()
        {
            inputs.push(TokenAmount {
                token: hex::decode(str_param(entry, "token")?.trim_start_matches("0x"))
                    .map_err(|e| {
                        invalid_params(format!(
                            "'order_data.inputs[{i}].token' is not valid hex: {e}"
                        ))
                    })?,
                amount: decimal_to_uint256(
                    entry
                        .get("amount")
                        .ok_or_else(|| {
                            invalid_params(format!("Missing 'order_data.inputs[{i}].amount'"))
                        })?,
                    &format!("order_data.inputs[{i}].amount"),
                )?,
            });
        }

        let mut outputs = Vec::new();
        for (i, entry) in obj
            .get("outputs")
            .and_then(|v| v.as_array())
            .ok_or_else(|| invalid_params("'order_data.outputs' must be an array"))?
            .iter()
            .enumerate()
        {
            outputs.push(Output {
                token: hex::decode(str_param(entry, "token")?.trim_start_matches("0x"))
                    .map_err(|e| {
                        invalid_params(format!(
                            "'order_data.outputs[{i}].token' is not valid hex: {e}"
                        ))
                    })?,
                amount: decimal_to_uint256(
                    entry.get("amount").ok_or_else(|| {
                        invalid_params(format!("Missing 'order_data.outputs[{i}].amount'"))
                    })?,
                    &format!("order_data.outputs[{i}].amount"),
                )?,
                recipient: hex_to_bytes32(
                    str_param(entry, "recipient")?,
                    &format!("order_data.outputs[{i}].recipient"),
                )?,
                chain_id: entry
                    .get("chain_id")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| {
                        invalid_params(format!("Missing 'order_data.outputs[{i}].chain_id'"))
                    })? as u32,
            });
        }

        let decoded = TenzroOrderData {
            inputs,
            outputs,
            dest_chain_id: obj
                .get("dest_chain_id")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| invalid_params("Missing 'order_data.dest_chain_id'"))?
                as u32,
            dest_recipient: hex_to_bytes32(
                str_param(order_data, "dest_recipient")?,
                "order_data.dest_recipient",
            )?,
            fill_deadline: obj
                .get("fill_deadline")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| invalid_params("Missing 'order_data.fill_deadline'"))?
                as u32,
            proof_route: parse_route(
                obj.get("proof_route")
                    .ok_or_else(|| invalid_params("Missing 'order_data.proof_route'"))?,
            )?,
            bridge_fee_hint: None,
        };

        let encoded = bincode::serialize(&decoded).map_err(|e| {
            upstream_error(format!("Failed to encode order_data: {e}"))
        })?;
        forwarded["order_data"] = Value::String(format!("0x{}", hex::encode(encoded)));
    }

    crate::rpc::handle_open_7683_order(node, Some(forwarded)).await
}

/// Read, write, and list files in the agent workspace.
async fn file_manager(
    node: &Arc<TenzroNode>,
    tool_name: &str,
    params: &Value,
) -> std::result::Result<Value, JsonRpcError> {
    let root = workspace_root(node);
    tokio::fs::create_dir_all(&root)
        .await
        .map_err(|e| unavailable(format!("Workspace unavailable: {e}")))?;

    match tool_name {
        "read" => {
            let path = resolve_workspace_path(&root, str_param(params, "path")?)?;
            let content = tokio::fs::read(&path)
                .await
                .map_err(|e| upstream_error(format!("Read failed: {e}")))?;
            let bytes = content.len();
            match String::from_utf8(content) {
                Ok(text) => Ok(json!({
                    "path": str_param(params, "path")?,
                    "bytes": bytes,
                    "encoding": "utf-8",
                    "content": text,
                })),
                Err(e) => {
                    use base64::Engine as _;
                    Ok(json!({
                        "path": str_param(params, "path")?,
                        "bytes": bytes,
                        "encoding": "base64",
                        "content": base64::engine::general_purpose::STANDARD
                            .encode(e.as_bytes()),
                    }))
                }
            }
        }
        "write" => {
            let rel = str_param(params, "path")?;
            let path = resolve_workspace_path(&root, rel)?;
            let content = str_param(params, "content")?;
            if let Some(parent) = path.parent() {
                tokio::fs::create_dir_all(parent)
                    .await
                    .map_err(|e| upstream_error(format!("Directory create failed: {e}")))?;
            }
            tokio::fs::write(&path, content.as_bytes())
                .await
                .map_err(|e| upstream_error(format!("Write failed: {e}")))?;
            Ok(json!({ "path": rel, "bytes": content.len() }))
        }
        "list" => {
            let rel = params.get("path").and_then(|v| v.as_str()).unwrap_or("");
            let dir = if rel.is_empty() {
                root.clone()
            } else {
                resolve_workspace_path(&root, rel)?
            };
            let mut entries = Vec::new();
            let mut read_dir = tokio::fs::read_dir(&dir)
                .await
                .map_err(|e| upstream_error(format!("List failed: {e}")))?;
            while let Some(entry) = read_dir
                .next_entry()
                .await
                .map_err(|e| upstream_error(format!("List failed: {e}")))?
            {
                let meta = entry
                    .metadata()
                    .await
                    .map_err(|e| upstream_error(format!("Stat failed: {e}")))?;
                entries.push(json!({
                    "name": entry.file_name().to_string_lossy(),
                    "kind": if meta.is_dir() { "directory" } else { "file" },
                    "bytes": if meta.is_dir() { Value::Null } else { json!(meta.len()) },
                }));
            }
            Ok(json!({ "path": rel, "entries": entries }))
        }
        "delete" => {
            let rel = str_param(params, "path")?;
            let path = resolve_workspace_path(&root, rel)?;
            tokio::fs::remove_file(&path)
                .await
                .map_err(|e| upstream_error(format!("Delete failed: {e}")))?;
            Ok(json!({ "path": rel, "deleted": true }))
        }
        other => Err(invalid_params(format!(
            "Unknown file-manager tool '{other}' (expected read|write|list|delete)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_target_strips_only_the_builtin_scheme() {
        assert_eq!(builtin_target("builtin://web-search"), Some("web-search"));
        assert_eq!(builtin_target("https://mcp.tenzro.xyz/mcp"), None);
        assert_eq!(builtin_target("builtin://"), Some(""));
    }

    #[test]
    fn workspace_paths_stay_under_the_root() {
        let root = Path::new("/data/agent_workspace");
        assert_eq!(
            resolve_workspace_path(root, "notes/a.txt").unwrap(),
            Path::new("/data/agent_workspace/notes/a.txt")
        );
        assert_eq!(
            resolve_workspace_path(root, "./notes/a.txt").unwrap(),
            Path::new("/data/agent_workspace/notes/a.txt")
        );
    }

    #[test]
    fn workspace_paths_reject_traversal_and_absolutes() {
        let root = Path::new("/data/agent_workspace");
        assert!(resolve_workspace_path(root, "../keys").is_err());
        assert!(resolve_workspace_path(root, "notes/../../keys").is_err());
        assert!(resolve_workspace_path(root, "/etc/passwd").is_err());
        assert!(resolve_workspace_path(root, "").is_err());
    }
}
