//! Tenzro Control — application entry point.
//!
//! `run()` is called by `main.rs` and does three things in a fixed order
//! before Tauri exists at all:
//!
//! 1. arm the panic hook, so anything that fails after this point is
//!    diagnosable;
//! 2. install the aws-lc-rs crypto provider, because the embedded node's
//!    iroh transport negotiates a PQ-hybrid key exchange that the ring
//!    provider does not carry;
//! 3. start file logging, so the node's own `tracing` output lands
//!    somewhere an operator can read after the fact.
//!
//! Closing the window does not stop the node. Control runs a network
//! participant, not a document editor: the window is a view onto a
//! service that should keep validating and serving while it is hidden.
//! Quitting — from the tray, from Cmd-Q, or from a signal — is what
//! stops it, and always through [`state::graceful_shutdown`].

pub mod assistant;
pub mod budget;
pub mod cable;
pub mod commands;
pub mod config;
pub mod crash_safety;
pub mod device_commands;
pub mod hardware;
pub mod machine_identity;
pub mod native_tx;
pub mod node;
pub mod rpc;
pub mod state;
pub mod transfer;
pub mod wallet;

use std::sync::{Arc, OnceLock};

use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconEvent};
use tauri::{AppHandle, Manager, RunEvent, WindowEvent};

use crate::state::AppState;

/// Keeps the non-blocking log writer alive for the life of the process.
/// Dropping the guard closes the appender thread and silently discards
/// everything still queued.
static LOG_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();

pub fn run() {
    crash_safety::install_safety_net();

    install_crypto_provider();
    install_logging();

    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            // A second launch surfaces the window that already exists
            // rather than starting a second node against the same
            // RocksDB directory.
            focus_main_window(app);
        }))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        .plugin(tauri_plugin_window_state::Builder::new().build())
        .plugin(tauri_plugin_os::init())
        .manage(AppState::new())
        .manage(Arc::new(cable::CableSessionManager::new()))
        .setup(|app| {
            install_tray(app.handle())?;
            apply_platform_window_material(app.handle());
            start_node(app.handle().clone());
            install_signal_handler(app.handle().clone());
            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .invoke_handler(tauri::generate_handler![
            // hardware + budget
            commands::scan_hardware,
            commands::model_budget,
            // configuration
            commands::get_config,
            commands::pricing_brackets,
            commands::set_roles,
            commands::set_models,
            commands::set_availability,
            commands::set_ai_pricing,
            commands::set_storage_pricing,
            commands::set_compute_pricing,
            commands::set_memory_config,
            commands::complete_onboarding,
            // node
            commands::node_status,
            commands::restart_node,
            commands::reset_local_chain,
            commands::node_data_dir,
            commands::reveal_data_dir,
            // wallet
            commands::wallet_status,
            commands::wallet_use_hardware_key,
            commands::wallet_send,
            commands::stake_bond,
            commands::stake_unbond,
            commands::stake_withdraw,
            // models
            commands::model_details,
            commands::download_progress,
            commands::serve_model,
            commands::stop_model,
            commands::offload_model,
            // forecast
            commands::forecast_catalog,
            commands::forecast_list,
            commands::forecast_load,
            commands::forecast_unload,
            commands::forecast_run,
            // media
            commands::media_catalog,
            commands::media_render,
            // assistant
            commands::assistant_chat,
            commands::assistant_cancel,
            // escape hatch
            commands::rpc_call,
            // device keys + cross-device linking
            device_commands::device_create_passkey,
            device_commands::device_sign_with_passkey,
            device_commands::device_sign_hybrid_with_passkey,
            device_commands::device_start_cross_device_link,
            device_commands::device_complete_cross_device_link,
            device_commands::device_cancel_cross_device_link,
        ])
        .build(tauri::generate_context!())
        .expect("failed to build the Tenzro Control application")
        .run(|app, event| {
            if let RunEvent::Exit = event {
                // The main thread is not a tokio worker, so blocking here
                // is safe and is the only way to finish an async teardown
                // before the process goes away.
                let state = app.state::<AppState>();
                tauri::async_runtime::block_on(state::graceful_shutdown(state.inner()));
            }
        });
}

/* --------------------------------------------------------------------- */
/* startup pieces                                                         */
/* --------------------------------------------------------------------- */

fn install_crypto_provider() {
    // `install_default` fails only if a provider is already installed,
    // which is the outcome we wanted anyway.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Daily-rotated logs under the node's own data directory, plus stderr so
/// a terminal launch shows the same stream.
fn install_logging() {
    use tracing_subscriber::EnvFilter;
    use tracing_subscriber::fmt::writer::MakeWriterExt;

    let Ok(log_dir) = node::data_dir().map(|d| d.join("logs")) else {
        return;
    };
    if std::fs::create_dir_all(&log_dir).is_err() {
        return;
    }

    let appender = tracing_appender::rolling::daily(&log_dir, "control.log");
    let (writer, guard) = tracing_appender::non_blocking(appender);
    if LOG_GUARD.set(guard).is_err() {
        return;
    }

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,tenzro_control=debug"));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer.and(std::io::stderr))
        .with_ansi(false)
        .init();
}

/// The tray is how the app stays reachable once the window is hidden.
/// The icon itself is declared in `tauri.conf.json`; this attaches the
/// behaviour to it.
fn install_tray(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    let Some(tray) = app.tray_by_id("main") else {
        return Ok(());
    };

    let open = MenuItem::with_id(app, "open", "Open Tenzro Control", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit Tenzro Control", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &quit])?;

    tray.set_menu(Some(menu))?;
    tray.on_menu_event(|app, event| match event.id().as_ref() {
        "open" => focus_main_window(app),
        "quit" => app.exit(0),
        _ => {}
    });
    tray.on_tray_icon_event(|tray, event| {
        if let TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        } = event
        {
            focus_main_window(tray.app_handle());
        }
    });

    Ok(())
}

/// Start the embedded node without blocking the window from appearing.
/// Startup dials bootstrap peers and opens RocksDB, which takes long
/// enough to be visible if it ran on the setup path.
fn start_node(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let state = app.state::<AppState>();
        if let Err(e) = node::auto_start_node(state.inner()).await {
            tracing::error!("embedded node did not start: {}", e);
        }
    });
}

/// SIGTERM and SIGINT reach the process without going through Tauri's
/// window or menu paths, so they need their own route into the same
/// ordered teardown.
fn install_signal_handler(app: AppHandle) {
    #[cfg(unix)]
    tauri::async_runtime::spawn(async move {
        use tokio::signal::unix::{SignalKind, signal};

        let (Ok(mut term), Ok(mut interrupt)) = (
            signal(SignalKind::terminate()),
            signal(SignalKind::interrupt()),
        ) else {
            tracing::warn!("could not install signal handlers");
            return;
        };

        tokio::select! {
            _ = term.recv() => tracing::info!("SIGTERM received, shutting down"),
            _ = interrupt.recv() => tracing::info!("SIGINT received, shutting down"),
        }

        {
            let state = app.state::<AppState>();
            state::graceful_shutdown(state.inner()).await;
        }
        app.exit(0);
    });

    #[cfg(not(unix))]
    let _ = app;
}

fn focus_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

/// Windows 11's own window material. Mac gets its vibrancy for free from
/// `titleBarStyle: Overlay` in `tauri.conf.json`; Windows has no config-only
/// equivalent, so it is applied here instead. `dark: None` follows the
/// system theme rather than pinning one, matching every other themed surface
/// in the app.
///
/// Best-effort: Mica is Windows 11 only (`window-vibrancy` returns an `Err`
/// on Windows 10), and a window manager without composition enabled can
/// reject it too. Either way the window still renders — just with a flat
/// fill instead of the material — so failure here is silently swallowed
/// rather than surfaced as a startup error.
#[cfg(windows)]
fn apply_platform_window_material(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window_vibrancy::apply_mica(&window, None);
    }
}

#[cfg(not(windows))]
fn apply_platform_window_material(_app: &AppHandle) {}
