//! Typed persisted configuration for the Tenzro CLI.
//!
//! Matches the Tauri desktop app's PersistedConfig so both apps
//! share the same `~/.tenzro/config.json` file format.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Provider schedule configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProviderSchedule {
    pub enabled: bool,
    pub start_hour: u8,
    pub end_hour: u8,
    pub timezone: String,
    pub days_of_week: [bool; 7],
}

/// Provider pricing configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProviderPricing {
    pub input_price_per_token: f64,
    pub output_price_per_token: f64,
    pub network_max_input: f64,
    pub network_max_output: f64,
}

/// Persisted configuration saved to `~/.tenzro/config.json`.
///
/// This struct is the canonical config format shared between the CLI
/// and the Tauri desktop app. All fields are `Option` so that partial
/// configs (e.g. only `endpoint`) are valid.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PersistedConfig {
    pub endpoint: Option<String>,
    pub wallet_id: Option<String>,
    pub wallet_address: Option<String>,
    pub did: Option<String>,
    pub display_name: Option<String>,
    pub username: Option<String>,
    pub role: Option<String>,
    pub schedule: Option<ProviderSchedule>,
    pub pricing: Option<ProviderPricing>,
    #[serde(default)]
    pub served_models: Vec<String>,
    /// OAuth 2.1 access token (HS256 JWT, optionally DPoP-bound).
    /// Sent as `Authorization: Bearer <token>` on privileged calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
    /// Long-lived opaque refresh token. Exchange via `tenzro auth refresh`
    /// when the access token expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// Unix timestamp (seconds) at which the access token expires.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token_expires_at: Option<u64>,
    /// `true` iff the access token requires a DPoP proof on every call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_bound: Option<bool>,
}

/// Get the path to the config file: `~/.tenzro/config.json`
pub fn config_path() -> PathBuf {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    home.join(".tenzro").join("config.json")
}

/// Load persisted config from disk. Returns default if file doesn't exist.
pub fn load_config() -> PersistedConfig {
    let path = config_path();
    if let Ok(contents) = std::fs::read_to_string(&path) {
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        PersistedConfig::default()
    }
}

/// Save persisted config to disk.
pub fn save_config(config: &PersistedConfig) -> anyhow::Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(config)?;
    std::fs::write(&path, json)?;
    Ok(())
}
