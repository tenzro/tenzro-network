/// Commands the webview may invoke. Declaring them makes every app
/// command subject to the capability ACL: a command must be listed here
/// and granted as `allow-<command>` in `capabilities/default.json`, so a
/// command added to `generate_handler!` without both is unreachable from
/// the webview rather than open by default.
const WEBVIEW_COMMANDS: &[&str] = &[
    "scan_hardware",
    "model_budget",
    "get_config",
    "pricing_brackets",
    "set_roles",
    "set_models",
    "set_availability",
    "set_ai_pricing",
    "set_storage_pricing",
    "set_compute_pricing",
    "set_memory_config",
    "complete_onboarding",
    "node_status",
    "restart_node",
    "reset_local_chain",
    "node_data_dir",
    "reveal_data_dir",
    "wallet_status",
    "wallet_use_hardware_key",
    "wallet_send",
    "stake_bond",
    "stake_unbond",
    "stake_withdraw",
    "model_details",
    "download_progress",
    "serve_model",
    "stop_model",
    "offload_model",
    "forecast_catalog",
    "forecast_list",
    "forecast_load",
    "forecast_unload",
    "forecast_run",
    "media_catalog",
    "media_render",
    "assistant_chat",
    "assistant_cancel",
    "rpc_call",
    "device_create_passkey",
    "device_sign_with_passkey",
    "device_sign_hybrid_with_passkey",
    "device_start_cross_device_link",
    "device_complete_cross_device_link",
    "device_cancel_cross_device_link",
];

fn main() {
    tauri_build::try_build(
        tauri_build::Attributes::new()
            .app_manifest(tauri_build::AppManifest::new().commands(WEBVIEW_COMMANDS)),
    )
    .expect("failed to run the Tauri build script");
}
