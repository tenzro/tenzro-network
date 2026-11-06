//! Embedded node lifecycle.
//!
//! The node is an always-on background service: it starts with the app,
//! dials the testnet bootstrap peers, and stays up. Onboarding decides
//! what the node DOES — which roles it serves, which models, on what
//! schedule — never whether it is running. A validator in particular has
//! no "off" state; the availability schedule governs paid serving
//! windows for the AI and storage roles only.
//!
//! Control talks to the node in-process. It deliberately does NOT start
//! the HTTP JSON-RPC server: a desktop app has no cross-process caller
//! and must never expose an RPC port.

use std::sync::Arc;

use serde::Serialize;
use serde_json::json;
use tracing::{info, warn};

use crate::state::AppState;

/// Where every subsystem anchors — RocksDB, keys, wallets, logs. Under
/// the Tenzro root, never the `.app` bundle's read-only cwd.
///
/// A named instance rather than a directory of its own, so the app's node
/// sits alongside any node started from the CLI instead of in a parallel
/// tree, and `$TENZRO_HOME` moves it with everything else.
pub fn data_dir() -> Result<std::path::PathBuf, String> {
    tenzro_types::paths::try_tenzro_home()
        .map(|_| tenzro_types::paths::instance_data_dir("control"))
        .map_err(|e| e.to_string())
}

/* --------------------------------------------------------------------- */
/* status                                                                 */
/* --------------------------------------------------------------------- */

/// Live status for the dashboard and status bar. A projection of
/// [`tenzro_node::NodeStatus`] plus one derived field.
#[derive(Debug, Clone, Serialize)]
pub struct NodeStatusView {
    pub state: String,
    /// Every role this node serves, comma-joined (e.g.
    /// `"validator,model_provider,storage"`). One node, one stake, many
    /// roles.
    pub roles: String,
    pub block_height: u64,
    pub peer_count: u64,
    pub uptime_secs: u64,
    pub tee_capable: bool,
    pub iroh_enabled: bool,
    /// Coarse connectivity for the status bar: `"connecting"` when the
    /// node has neither an admitted peer nor an imported block,
    /// `"syncing"` when it is importing blocks off the boot node without
    /// an admitted *validator* peer, `"connected"` once it holds one.
    ///
    /// The distinction matters for an edge node behind NAT: it
    /// legitimately never joins the validator set, so `peer_count` stays
    /// 0 forever, yet it block-syncs off the reachable boot node fine.
    /// Keying "connecting" on `peer_count == 0` alone would label that
    /// healthy node as stuck.
    pub connectivity: String,
}

impl From<&tenzro_node::NodeStatus> for NodeStatusView {
    fn from(s: &tenzro_node::NodeStatus) -> Self {
        Self {
            state: s.state.clone(),
            roles: s.roles.to_string(),
            block_height: s.block_height,
            peer_count: s.peer_count,
            uptime_secs: s.uptime_secs,
            tee_capable: s.tee_capable,
            iroh_enabled: s.iroh_enabled,
            connectivity: connectivity(s.peer_count, s.block_height).to_string(),
        }
    }
}

/// The status bar's connectivity for a node with `peer_count` admitted
/// peers at `block_height`.
fn connectivity(peer_count: u64, block_height: u64) -> &'static str {
    match (peer_count, block_height) {
        (0, 0) => "connecting",
        (0, _) | (_, 0) => "syncing",
        _ => "connected",
    }
}

/// Live status, or `None` during the boot race window before the node
/// handle lands in [`AppState`].
pub async fn node_status(state: &AppState) -> Option<NodeStatusView> {
    let guard = state.node.read().await;
    guard
        .as_ref()
        .map(|h| NodeStatusView::from(&h.current_status()))
}

/* --------------------------------------------------------------------- */
/* boot-time cleanup                                                      */
/* --------------------------------------------------------------------- */

/// Clear leftovers that would block a fresh start after an abnormal exit
/// (GPU teardown abort, SIGKILL, OOM, force-quit):
///
/// - the RocksDB `LOCK` file, which the next boot would otherwise wait on
///   forever;
/// - partial GGUF downloads.
pub fn clear_stale_state_on_boot() {
    if let Ok(dir) = data_dir() {
        let lock = dir.join("db").join("LOCK");
        if lock.exists() {
            // Safe to unlink only because a single-user desktop app is by
            // construction the sole writer. A multi-tenant deployment
            // would need a PID check here.
            info!(
                "clearing stale RocksDB LOCK from a previous abnormal exit: {}",
                lock.display()
            );
            let _ = std::fs::remove_file(&lock);
        }
    }
    clear_partial_downloads();
}

/// Unlink orphaned partial downloads from the models directory.
pub fn clear_partial_downloads() {
    if let Ok(dir) = crate::rpc::models_dir() {
        clear_partial_downloads_in(&dir);
    }
}

fn clear_partial_downloads_in(dir: &std::path::Path) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        if name.ends_with(".tmp")
            || name.ends_with(".partial")
            || name.ends_with(".download")
            || name.contains(".gguf.tmp")
        {
            info!("clearing orphaned partial download: {}", path.display());
            let _ = std::fs::remove_file(&path);
        }
    }
}

/* --------------------------------------------------------------------- */
/* start / restart / reset                                                */
/* --------------------------------------------------------------------- */

/// Spawn the embedded node in the background. Called once at startup, so
/// the user never has to ask. Idempotent — a second call is a no-op.
pub async fn auto_start_node(state: &AppState) -> Result<(), String> {
    clear_stale_state_on_boot();

    {
        let guard = state.node.read().await;
        if guard.is_some() {
            return Ok(());
        }
    }

    let mut config = tenzro_node::NodeConfig::default();

    // Roles come from the persisted onboarding result. Before onboarding
    // completes the node still joins and syncs — as a LightClient, which
    // advertises nothing and stakes nothing.
    config.roles = crate::config::role_set();

    // A validator role registers the validator: with a self-stake set, the
    // node registers itself on boot with its own hardware keys once its
    // account holds the stake and gas, and skips the registration, without
    // failing, while it does not. The stake is the genesis validator bond; a
    // raise by governance above it is refused at boot and logged.
    if config.roles.is_validator() {
        config.validator_self_stake = Some(tenzro_types::network::StakeLadder::genesis().validator);
    }

    let control = crate::config::get();
    apply_pricing(&mut config, &control);
    apply_memory(&mut config, &control.memory);

    // This machine operates the node it embeds: its hardware identity is
    // the operator, so the operator's account is the machine's wallet
    // account and Control signs in to the node's operator methods with the
    // same key.
    config.operator_did = Some(machine_did()?);

    config.data_dir = data_dir()?;
    std::fs::create_dir_all(&config.data_dir)
        .map_err(|e| format!("could not create data dir: {}", e))?;

    // Peers: the node joins through the boot identities in its iroh config
    // and learns the rest of the network from their signed endpoint records.
    info!(
        "starting embedded node: roles={}, data_dir={}, boot_identities={}",
        config.roles,
        config.data_dir.display(),
        config.iroh.boot.len()
    );

    // No keystore password is sealed for the embedded node: a sealed
    // envelope needs a second, software recovery recipient, and a software
    // key may not open anything this node holds. The operator's account is a
    // hardware passkey, so nothing here needs the password.
    let handle = tenzro_node::spawn_in_background(config)
        .await
        .map_err(|e| {
            warn!("embedded node failed to start: {}", e);
            format!("failed to start node: {}", e)
        })?;

    {
        let mut guard = state.node.write().await;
        *guard = Some(Arc::new(handle));
    }

    info!("embedded node running, dialing bootstrap peers");
    Ok(())
}

/// Copy the rates onboarding collected onto the node's own config.
///
/// Control runs the node in-process with no RPC server, so the rates have
/// to be in `NodeConfig` before the runtimes spawn — there is no later
/// call that could set them. A role the operator did not select is left
/// at the node's own default, since nothing reads it.
/// Copy the operator's memory-budget overrides, if any, onto the node's own
/// config. Same reasoning as [`apply_pricing`]: this has to happen before
/// the runtimes spawn, since there is no later call that could change a
/// running node's ceilings.
fn apply_memory(config: &mut tenzro_node::NodeConfig, mem: &crate::config::MemoryOverride) {
    if let Some(gb) = mem.reserve_gb {
        config.memory.reserve_gb = gb;
    }
    if mem.resident_ceiling_gb.is_some() {
        config.memory.resident_ceiling_gb = mem.resident_ceiling_gb;
    }
    if mem.on_demand_ceiling_gb.is_some() {
        config.memory.on_demand_ceiling_gb = mem.on_demand_ceiling_gb;
    }
}

/// `did:tenzro:machine:{id}` of this machine's hardware identity key.
fn machine_did() -> Result<String, String> {
    use tenzro_types::did_derivation::{machine_did, MACHINE_KEY_LABEL};
    let key = tenzro_device_key::signer::open_or_create(MACHINE_KEY_LABEL)
        .map_err(|e| format!("this machine has no hardware identity key: {e}"))?;
    let public_key = key
        .public_key_sec1()
        .map_err(|e| format!("machine identity key: {e}"))?;
    Ok(machine_did(&public_key))
}

fn apply_pricing(config: &mut tenzro_node::NodeConfig, cfg: &crate::config::ControlConfig) {
    use tenzro_node::pricing::PricingPolicy;

    config.provider_rates.inference.input_price_per_token_wei =
        cfg.ai_pricing.input_price_per_token_wei;
    config.provider_rates.inference.output_price_per_token_wei =
        cfg.ai_pricing.output_price_per_token_wei;

    // Onboarding quotes storage the way a depositor shops for it — TNZO per
    // gigabyte-month — while the runtime meters a byte per billing epoch.
    // One epoch is an hour and a month is 730 of them, so the divisor is
    // bytes-per-gigabyte times hours-per-month.
    const WEI_PER_GB_MONTH_TO_BYTE_EPOCH: u128 = 1_000_000_000 * 730;
    let to_byte_epoch = |gb_month: u128| gb_month / WEI_PER_GB_MONTH_TO_BYTE_EPOCH;

    // The rate is fixed and never follows demand: the quoted floor is the
    // price.
    config.provider_rates.storage = PricingPolicy::Fixed {
        rate: to_byte_epoch(cfg.storage_pricing.min_rate_wei),
    };

    config.provider_rates.compute = PricingPolicy::Fixed {
        rate: cfg.compute_pricing.rate_per_hour_wei,
    };
}

/// Force-restart. Surfaced as a retry affordance when the status bar has
/// been "connecting" too long — typically stale network state from a run
/// that died mid-dial, or briefly unreachable boot peers.
pub async fn restart_node(state: &AppState) -> Result<(), String> {
    info!("node restart requested");
    teardown(state).await;
    clear_stale_state_on_boot();
    auto_start_node(state).await
}

/// Wipe local chain state and restart.
///
/// Needed after a testnet rollback: the network's tip moved back to a
/// fresh genesis, so the client carries RocksDB state at a height the
/// network no longer recognises, which shows up as identify-handshake
/// failures and a peer count stuck at zero even though bootstrap DNS
/// resolves.
///
/// Wipes `db/` and `snapshots/`. Preserves every key, the wallet, and
/// agent memory — the peer id and validator identity survive. Destructive
/// enough that the UI must confirm before calling it.
pub async fn reset_local_chain(state: &AppState) -> Result<(), String> {
    warn!("local chain reset requested — wiping db/ and snapshots/");

    // RocksDB must release its handle before the directory can go.
    teardown(state).await;

    let dir = data_dir()?;
    for sub in ["db", "snapshots"] {
        let path = dir.join(sub);
        if path.exists() {
            info!("removing {}", path.display());
            std::fs::remove_dir_all(&path)
                .map_err(|e| format!("failed to remove {}: {}", path.display(), e))?;
        }
    }

    auto_start_node(state).await
}

/// Take the handle out of [`AppState`], unload its models, drain it.
/// Taking it out first means a concurrent status poll never observes a
/// half-shut-down node.
async fn teardown(state: &AppState) {
    let prev = {
        let mut guard = state.node.write().await;
        guard.take()
    };
    let Some(handle) = prev else {
        return;
    };
    unload_all_models(&handle).await;
    if let Err(e) = handle.shutdown_and_wait().await {
        warn!("node shutdown error: {}", e);
    }
}

/* --------------------------------------------------------------------- */
/* roles                                                                  */
/* --------------------------------------------------------------------- */

/// Change the live role set without restarting. The node swaps its
/// runtime role and re-gossips on the status topic.
///
/// The node applies its own admission gate on the far side — TEE hardware
/// for the confidential-compute role, a free-disk floor for storage, a
/// stake floor for validator. Control's hardware readout shapes what the
/// UI offers, but this call is where a bad choice is actually refused.
pub async fn request_role_change(roles: &[String], state: &AppState) -> Result<serde_json::Value, String> {
    crate::rpc::rpc_result_admin("tenzro_setRole", json!({ "roles": roles }), state).await
}

/* --------------------------------------------------------------------- */
/* model + download teardown                                              */
/* --------------------------------------------------------------------- */

/// Unload every loaded model, releasing GPU device buffers while the
/// runtime is still healthy.
///
/// Control serves models in-process, so a Metal (macOS) or CUDA (Linux)
/// context dropped implicitly during runtime teardown is how a clean quit
/// turns into a driver-level crash on exit. Unloading by hand, first,
/// avoids that.
pub async fn unload_all_models(handle: &tenzro_node::NodeHandle) {
    let Some(runtime) = handle.node().model_runtime_arc() else {
        return;
    };
    for model_id in runtime.list_loaded() {
        info!(model_id = %model_id, "unloading model");
        if let Err(e) = runtime.unload_model(&model_id).await {
            warn!("unload_model({}) failed: {}", model_id, e);
        }
    }
}

/// Cancel every in-flight download and unlink its partial file, so a quit
/// mid-download doesn't leave a half-written GGUF for the next launch to
/// inherit.
pub async fn cancel_all_downloads(state: &AppState) {
    let guard = state.node.read().await;
    let Some(handle) = guard.as_ref() else {
        return;
    };
    let node = handle.node();

    let in_flight: Vec<String> = node
        .model_downloads
        .iter()
        .filter(|kv| {
            matches!(
                kv.value().status.as_str(),
                "downloading" | "in_progress" | "not_started"
            )
        })
        .map(|kv| kv.key().clone())
        .collect();

    let dir = crate::rpc::models_dir().ok();

    for model_id in in_flight {
        if let Some(mut entry) = node.model_downloads.get_mut(&model_id) {
            entry.status = "cancelled".to_string();
            entry.error = Some("cancelled on app shutdown".to_string());
        }
        // Mirror what the cancel RPC does: drop the partial file. The
        // download path comes from the catalogue when the entry is known,
        // and falls back to the flat `<id>.gguf` layout when it isn't.
        if let Some(dir) = dir.as_ref() {
            let rel = tenzro_model::catalog::get_model_by_id(&model_id)
                .map(|e| crate::rpc::download_rel_path(&e))
                .unwrap_or_else(|| format!("{}.gguf", model_id));
            for path in [dir.join(&rel), dir.join(&model_id)] {
                if path.is_file() {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
        info!(model_id = %model_id, "cancelled in-flight download on shutdown");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ControlConfig, MemoryOverride};
    use tenzro_node::pricing::PricingPolicy;

    const GB_MONTH: u128 = 1_000_000_000 * 730;

    #[test]
    fn connectivity_reads_peers_and_blocks_together() {
        assert_eq!(connectivity(0, 0), "connecting");
        assert_eq!(connectivity(0, 12), "syncing");
        assert_eq!(connectivity(3, 0), "syncing");
        assert_eq!(connectivity(3, 12), "connected");
    }

    #[test]
    fn memory_overrides_replace_only_what_the_operator_set() {
        let mut config = tenzro_node::NodeConfig::default();
        let defaults = config.memory.clone();
        apply_memory(&mut config, &MemoryOverride::default());
        assert_eq!(config.memory.reserve_gb, defaults.reserve_gb);
        assert_eq!(config.memory.resident_ceiling_gb, defaults.resident_ceiling_gb);

        let set = MemoryOverride { reserve_gb: Some(6), resident_ceiling_gb: Some(40), on_demand_ceiling_gb: None };
        apply_memory(&mut config, &set);
        assert_eq!(config.memory.reserve_gb, 6);
        assert_eq!(config.memory.resident_ceiling_gb, Some(40));
        assert_eq!(config.memory.on_demand_ceiling_gb, defaults.on_demand_ceiling_gb);
    }

    #[test]
    fn prices_reach_the_node_in_its_own_units() {
        let mut cfg = ControlConfig::default();
        cfg.ai_pricing.input_price_per_token_wei = 11;
        cfg.ai_pricing.output_price_per_token_wei = 22;
        cfg.storage_pricing.capacity_gb = 0;
        cfg.storage_pricing.min_rate_wei = 5 * GB_MONTH;
        cfg.storage_pricing.max_rate_wei = 9 * GB_MONTH;
        cfg.compute_pricing.rate_per_hour_wei = 77;
        let mut config = tenzro_node::NodeConfig::default();
        apply_pricing(&mut config, &cfg);
        assert_eq!(config.provider_rates.inference.input_price_per_token_wei, 11);
        assert_eq!(config.provider_rates.inference.output_price_per_token_wei, 22);
        assert_eq!(config.provider_rates.storage, PricingPolicy::Fixed { rate: 5 });
        assert_eq!(config.provider_rates.compute, PricingPolicy::Fixed { rate: 77 });
    }

    #[test]
    fn pledged_storage_with_a_band_prices_dynamically() {
        let mut cfg = ControlConfig::default();
        cfg.storage_pricing.capacity_gb = 100;
        cfg.storage_pricing.min_rate_wei = 2 * GB_MONTH;
        cfg.storage_pricing.max_rate_wei = 10 * GB_MONTH;
        let mut config = tenzro_node::NodeConfig::default();
        apply_pricing(&mut config, &cfg);
        assert!(matches!(config.provider_rates.storage, PricingPolicy::Dynamic(_)));

        cfg.storage_pricing.max_rate_wei = cfg.storage_pricing.min_rate_wei;
        apply_pricing(&mut config, &cfg);
        assert_eq!(config.provider_rates.storage, PricingPolicy::Fixed { rate: 2 });
    }

    #[test]
    fn boot_cleanup_removes_partial_downloads_only() {
        let tmp = tempfile::tempdir().unwrap();
        for name in ["a.gguf", "b.gguf.tmp", "c.partial", "d.download", "e.tmp", "manifest.json"] {
            std::fs::write(tmp.path().join(name), b"x").unwrap();
        }
        clear_partial_downloads_in(tmp.path());
        let mut left: Vec<String> = std::fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, vec!["a.gguf".to_string(), "manifest.json".to_string()]);
    }
}
