//! The Tauri command surface.
//!
//! Every module underneath exposes plain `pub async fn`s taking `&AppState`.
//! This file is the only place that knows about `tauri::State`, which keeps
//! those modules testable without a Tauri app and keeps the invoke names in
//! one list the frontend can be read against.
//!
//! Wei figures cross this boundary as decimal strings. JSON numbers are
//! IEEE-754 doubles on the other side, and a storage rate of 0.05 TNZO is
//! 5×10^16 wei — past the point where a double still counts exactly. The
//! strings are parsed back to `u128` here.

use serde_json::Value;
use tauri::ipc::Channel;
use tauri::State;

use crate::assistant::{AssistantEvent, AssistantRequest};
use crate::budget::BudgetReadout;
use crate::config::{Availability, ControlConfig, PricingBracket};
use crate::hardware::{CapabilityReadout, HardwareProfile};
use crate::node::NodeStatusView;
use crate::rpc::RpcCallArgs;
use crate::state::AppState;
use crate::transfer::SendReceipt;
use crate::wallet::WalletStatusView;

fn parse_wei(field: &str, raw: &str) -> Result<u128, String> {
    raw.trim()
        .parse::<u128>()
        .map_err(|_| format!("{} must be a whole number of wei, got {:?}", field, raw))
}

/* --------------------------------------------------------------------- */
/* hardware + budget                                                      */
/* --------------------------------------------------------------------- */

#[tauri::command]
pub fn scan_hardware() -> CapabilityReadout {
    HardwareProfile::detect().readout()
}

/// The model picker's live view: both ceilings, what the current selection
/// and storage pledge already spend, and every catalogue entry classified
/// against what is left.
#[tauri::command]
pub fn model_budget(selected: Vec<String>, storage_pledge_gb: u32) -> BudgetReadout {
    crate::budget::compute(&selected, storage_pledge_gb)
}

/* --------------------------------------------------------------------- */
/* configuration                                                          */
/* --------------------------------------------------------------------- */

#[tauri::command]
pub fn get_config() -> ControlConfig {
    crate::config::get()
}

/// One pricing bracket, resolved to the rates it implies so the picker
/// shows real numbers rather than percentages.
#[derive(Debug, serde::Serialize)]
pub struct PricingBracketView {
    pub id: &'static str,
    pub bps: String,
    pub input_price_per_token_wei: String,
    pub output_price_per_token_wei: String,
    pub input_display: String,
    pub output_display: String,
}

#[tauri::command]
pub fn pricing_brackets() -> Vec<PricingBracketView> {
    PricingBracket::ALL
        .iter()
        .map(|b| {
            let p = b.ai_pricing();
            PricingBracketView {
                id: b.id(),
                bps: b.bps().to_string(),
                input_price_per_token_wei: p.input_price_per_token_wei.to_string(),
                output_price_per_token_wei: p.output_price_per_token_wei.to_string(),
                input_display: crate::wallet::format_tnzo(p.input_price_per_token_wei),
                output_display: crate::wallet::format_tnzo(p.output_price_per_token_wei),
            }
        })
        .collect()
}

/// Persist the role selection, then tell a running node about it. The role
/// change is best-effort: during onboarding the node may still be starting,
/// and the persisted set is what the next start reads anyway.
#[tauri::command]
pub async fn set_roles(
    roles: Vec<String>,
    state: State<'_, AppState>,
) -> Result<ControlConfig, String> {
    let cfg = crate::config::update(|c| c.roles = roles.clone())?;
    if let Err(e) = crate::node::request_role_change(&roles, &state).await {
        tracing::warn!("role change not applied to the running node: {}", e);
    }
    Ok(cfg)
}

#[tauri::command]
pub fn set_models(models: Vec<String>) -> Result<ControlConfig, String> {
    crate::config::update(|c| c.models = models)
}

#[tauri::command]
pub fn set_availability(availability: Availability) -> Result<ControlConfig, String> {
    crate::config::update(|c| c.availability = availability)
}

#[tauri::command]
pub fn set_ai_pricing(
    input_price_per_token_wei: String,
    output_price_per_token_wei: String,
) -> Result<ControlConfig, String> {
    let input = parse_wei("input_price_per_token_wei", &input_price_per_token_wei)?;
    let output = parse_wei("output_price_per_token_wei", &output_price_per_token_wei)?;

    if input > crate::config::NETWORK_MAX_INPUT_WEI {
        return Err(format!(
            "input rate is above the network ceiling of {}",
            crate::wallet::format_tnzo(crate::config::NETWORK_MAX_INPUT_WEI)
        ));
    }
    if output > crate::config::NETWORK_MAX_OUTPUT_WEI {
        return Err(format!(
            "output rate is above the network ceiling of {}",
            crate::wallet::format_tnzo(crate::config::NETWORK_MAX_OUTPUT_WEI)
        ));
    }

    crate::config::update(|c| {
        c.ai_pricing.input_price_per_token_wei = input;
        c.ai_pricing.output_price_per_token_wei = output;
    })
    
}

#[tauri::command]
pub fn set_storage_pricing(
    capacity_gb: u64,
    min_rate_wei: String,
    max_rate_wei: String,
) -> Result<ControlConfig, String> {
    let min = parse_wei("min_rate_wei", &min_rate_wei)?;
    let max = parse_wei("max_rate_wei", &max_rate_wei)?;
    if min > max {
        return Err("the floor rate cannot be above the ceiling rate".to_string());
    }
    crate::config::update(|c| {
        c.storage_pricing.capacity_gb = capacity_gb;
        c.storage_pricing.min_rate_wei = min;
        c.storage_pricing.max_rate_wei = max;
    })
    
}

#[tauri::command]
pub fn set_compute_pricing(rate_per_hour_wei: String) -> Result<ControlConfig, String> {
    let rate = parse_wei("rate_per_hour_wei", &rate_per_hour_wei)?;
    crate::config::update(|c| c.compute_pricing.rate_per_hour_wei = rate)
}

/// Mark onboarding done. The app opens on the dashboard from here on.
#[tauri::command]
pub fn complete_onboarding() -> Result<ControlConfig, String> {
    crate::config::update(|c| c.onboarded = true)
}

/// Takes effect on the next restart — see [`crate::config::MemoryOverride`].
#[tauri::command]
pub fn set_memory_config(
    reserve_gb: Option<u32>,
    resident_ceiling_gb: Option<u32>,
    on_demand_ceiling_gb: Option<u32>,
) -> Result<ControlConfig, String> {
    crate::config::update(|c| {
        c.memory = crate::config::MemoryOverride {
            reserve_gb,
            resident_ceiling_gb,
            on_demand_ceiling_gb,
        };
    })
    
}

/* --------------------------------------------------------------------- */
/* node                                                                   */
/* --------------------------------------------------------------------- */

#[tauri::command]
pub async fn node_status(state: State<'_, AppState>) -> Result<Option<NodeStatusView>, String> {
    Ok(crate::node::node_status(&state).await)
}

#[tauri::command]
pub async fn restart_node(state: State<'_, AppState>) -> Result<(), String> {
    crate::node::restart_node(&state).await
}

/// Delete the local chain database and resync from the network. Keeps the
/// operator config.
#[tauri::command]
pub async fn reset_local_chain(state: State<'_, AppState>) -> Result<(), String> {
    crate::node::reset_local_chain(&state).await
}

#[tauri::command]
pub fn node_data_dir() -> Result<String, String> {
    crate::node::data_dir().map(|p| p.display().to_string())
}

/// Hand the data directory to the desktop file manager. Logs and the chain
/// database live there, and an operator asked to send a log
/// has no other way to reach it from inside the window.
#[tauri::command]
pub async fn reveal_data_dir(app: tauri::AppHandle) -> Result<(), String> {
    use tauri_plugin_opener::OpenerExt;

    let dir = crate::node::data_dir()?;
    app.opener()
        .open_path(dir.display().to_string(), None::<&str>)
        .map_err(|e| format!("could not open {}: {}", dir.display(), e))
}

/* --------------------------------------------------------------------- */
/* wallet                                                                 */
/* --------------------------------------------------------------------- */

#[tauri::command]
pub async fn wallet_status(state: State<'_, AppState>) -> Result<WalletStatusView, String> {
    crate::wallet::status(&state).await
}

fn stake_role(role: &str) -> Result<tenzro_types::network::NetworkRole, String> {
    role.parse()
}

fn wei(amount_wei: &str) -> Result<u128, String> {
    amount_wei.parse().map_err(|_| format!("{amount_wei:?} is not an amount in wei"))
}

/// Bond `amount_wei` for `role` from the node's operator account, signed by
/// this machine's hardware key.
#[tauri::command]
pub async fn stake_bond(
    role: String,
    amount_wei: String,
    state: State<'_, AppState>,
) -> Result<WalletStatusView, String> {
    let op = tenzro_types::token::StakeOp::Bond {
        role: stake_role(&role)?,
        amount: wei(&amount_wei)?,
        capacity: tenzro_types::token::StakeCapacity::None,
    };
    crate::native_tx::submit_stake(op, &state).await?;
    crate::wallet::status(&state).await
}

/// Move `amount_wei` of the bond for `role` into unbonding.
#[tauri::command]
pub async fn stake_unbond(
    role: String,
    amount_wei: String,
    state: State<'_, AppState>,
) -> Result<WalletStatusView, String> {
    let op = tenzro_types::token::StakeOp::Unbond { role: stake_role(&role)?, amount: wei(&amount_wei)? };
    crate::native_tx::submit_stake(op, &state).await?;
    crate::wallet::status(&state).await
}

/// Return the unbonded stake for `role` once its unbonding period has passed.
#[tauri::command]
pub async fn stake_withdraw(
    role: String,
    state: State<'_, AppState>,
) -> Result<WalletStatusView, String> {
    let op = tenzro_types::token::StakeOp::Withdraw { role: stake_role(&role)? };
    crate::native_tx::submit_stake(op, &state).await?;
    crate::wallet::status(&state).await
}

/// Set up the operator's wallet on this machine's hardware key.
#[tauri::command]
pub async fn wallet_use_hardware_key(
    display_name: String,
    state: State<'_, AppState>,
) -> Result<WalletStatusView, String> {
    crate::wallet::use_hardware_key(&state, display_name).await
}

/// Move TNZO out of the operator's wallet.
#[tauri::command]
pub async fn wallet_send(
    to: String,
    amount_wei: String,
    state: State<'_, AppState>,
) -> Result<SendReceipt, String> {
    let amount = parse_wei("amount_wei", &amount_wei)?;
    crate::transfer::send(&state, &to, amount).await
}

/* --------------------------------------------------------------------- */
/* models                                                                 */
/* --------------------------------------------------------------------- */

#[tauri::command]
pub async fn model_details(id: String, state: State<'_, AppState>) -> Result<Value, String> {
    crate::rpc::model_details(id, &state).await
}

/// Progress for every download the node knows about, finished ones
/// included — the UI decides what to show.
#[tauri::command]
pub async fn download_progress(state: State<'_, AppState>) -> Result<Value, String> {
    let guard = state.node.read().await;
    let Some(handle) = guard.as_ref() else {
        return Ok(Value::Array(Vec::new()));
    };
    let entries: Vec<_> = handle
        .node()
        .model_downloads
        .iter()
        .map(|kv| kv.value().clone())
        .collect();
    serde_json::to_value(entries).map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn serve_model(
    id: String,
    visibility: Option<String>,
    state: State<'_, AppState>,
) -> Result<Value, String> {
    crate::rpc::rpc_result(
        "tenzro_serveModel",
        serde_json::json!({
            "model_id": id,
            "visibility": visibility.unwrap_or_else(|| "network".to_string()),
        }),
        &state,
    )
    .await
}

#[tauri::command]
pub async fn stop_model(id: String, state: State<'_, AppState>) -> Result<Value, String> {
    crate::rpc::rpc_result(
        "tenzro_stopModel",
        serde_json::json!({ "model_id": id }),
        &state,
    )
    .await
}

/// Reclaim the disk a downloaded model holds. Returns bytes freed.
#[tauri::command]
pub async fn offload_model(id: String, state: State<'_, AppState>) -> Result<u64, String> {
    crate::rpc::offload_model(id, &state).await
}

/* --------------------------------------------------------------------- */
/* forecast                                                               */
/* --------------------------------------------------------------------- */

#[tauri::command]
pub async fn forecast_catalog(state: State<'_, AppState>) -> Result<Value, String> {
    crate::rpc::rpc_result("tenzro_listForecastCatalog", serde_json::json!({}), &state).await
}

/// The forecast models the node holds, from its one loaded-model listing.
#[tauri::command]
pub async fn forecast_list(state: State<'_, AppState>) -> Result<Value, String> {
    let all = crate::rpc::rpc_result(
        "tenzro_listModels",
        serde_json::json!({ "loaded": true }),
        &state,
    )
    .await?;
    let forecasters: Vec<Value> = all
        .get("models")
        .and_then(|m| m.as_array())
        .map(|models| {
            models
                .iter()
                .filter(|m| m.get("type").and_then(|t| t.as_str()) == Some("forecast"))
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    Ok(serde_json::json!({ "models": forecasters }))
}

/// Loads a catalog forecaster by id, matching `tenzro forecast load` on the
/// CLI: the node fetches and verifies the files the catalog entry names.
#[tauri::command]
pub async fn forecast_load(
    model_id: String,
    visibility: Option<String>,
    state: State<'_, AppState>,
) -> Result<Value, String> {
    let mut payload = serde_json::json!({ "model_id": model_id });
    if let Some(v) = visibility {
        payload["visibility"] = serde_json::json!(v);
    }
    crate::rpc::rpc_result("tenzro_loadForecastModel", payload, &state).await
}

#[tauri::command]
pub async fn forecast_unload(model_id: String, state: State<'_, AppState>) -> Result<Value, String> {
    crate::rpc::rpc_result(
        "tenzro_unloadForecastModel",
        serde_json::json!({ "model_id": model_id }),
        &state,
    )
    .await
}

#[tauri::command]
pub async fn forecast_run(
    model_id: String,
    history: Vec<f64>,
    horizon: u32,
    quantiles: Vec<f64>,
    state: State<'_, AppState>,
) -> Result<Value, String> {
    crate::rpc::rpc_result(
        "tenzro_forecast",
        serde_json::json!({
            "model_id": model_id,
            "history": history,
            "horizon": horizon,
            "quantiles": quantiles,
        }),
        &state,
    )
    .await
}

/* --------------------------------------------------------------------- */
/* media                                                                  */
/* --------------------------------------------------------------------- */

#[tauri::command]
pub async fn media_catalog(state: State<'_, AppState>) -> Result<Value, String> {
    crate::rpc::rpc_result("tenzro_mediaGen_listCatalog", serde_json::json!({}), &state).await
}

/// Renders one output on the node and reads the bytes back from its content
/// store, as a data URL the page can show.
#[allow(clippy::too_many_arguments)]
#[tauri::command]
pub async fn media_render(
    kind: String,
    model_id: String,
    prompt: String,
    negative_prompt: Option<String>,
    width: u32,
    height: u32,
    steps: u32,
    guidance_scale: f32,
    num_frames: Option<u32>,
    fps: Option<u32>,
    seed: u64,
    state: State<'_, AppState>,
) -> Result<Value, String> {
    let kind = tenzro_types::MediaGenKind::from_str_lossy(&kind)
        .ok_or_else(|| format!("unknown media kind '{kind}'"))?;
    let params = tenzro_types::media_gen::MediaGenParams {
        prompt,
        negative_prompt,
        width,
        height,
        num_frames,
        fps,
        steps,
        guidance_scale,
        voxel_resolution: None,
        audio_duration_secs: None,
        action_chunks: None,
        session_hold_secs: None,
        seed: Some(seed),
        inputs: Vec::new(),
        metadata: Default::default(),
    };
    params.validate_for(kind).map_err(|e| e.to_string())?;
    let rendered = crate::rpc::rpc_result(
        "tenzro_mediaGen_render",
        serde_json::json!({
            "model_id": model_id,
            "kind": kind,
            "params": params,
            "inputs_base64": [],
        }),
        &state,
    )
    .await?;
    let blake3 = rendered
        .get("output_blake3")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "the render answer named no output".to_string())?;
    let blob = crate::rpc::rpc_result(
        "tenzro_iroh_fetchBlob",
        serde_json::json!({ "tenzro_uri": format!("tenzro://blob/{blake3}") }),
        &state,
    )
    .await?;
    let data = blob
        .get("bytes_b64")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "the content store returned no bytes".to_string())?;
    let mime = rendered
        .get("mime")
        .and_then(|v| v.as_str())
        .unwrap_or("application/octet-stream");
    Ok(serde_json::json!({
        "data_url": format!("data:{mime};base64,{data}"),
        "mime": mime,
        "cost_wei": rendered.get("cost_wei").cloned().unwrap_or(Value::Null),
        "output_sha256": rendered.get("output_sha256").cloned().unwrap_or(Value::Null),
    }))
}

/* --------------------------------------------------------------------- */
/* assistant                                                              */
/* --------------------------------------------------------------------- */

#[tauri::command]
pub async fn assistant_chat(
    request: AssistantRequest,
    on_event: Channel<AssistantEvent>,
    state: State<'_, AppState>,
) -> Result<(), String> {
    crate::assistant::chat(request, on_event, &state).await
}

#[tauri::command]
pub async fn assistant_cancel(
    request_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    crate::assistant::cancel(request_id, &state).await
}

/* --------------------------------------------------------------------- */
/* escape hatch                                                           */
/* --------------------------------------------------------------------- */

/// The advanced settings console. Serves the read-only methods in
/// [`crate::rpc::CONSOLE_METHODS`] with no credential attached; every
/// mutation the app performs is a named command above.
#[tauri::command]
pub async fn rpc_call(args: RpcCallArgs, state: State<'_, AppState>) -> Result<Value, String> {
    crate::rpc::console_call(args, &state).await
}
