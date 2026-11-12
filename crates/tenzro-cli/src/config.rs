//! Typed persisted configuration for the Tenzro CLI.
//!
//! Matches the Tauri desktop app's PersistedConfig so both apps
//! share the same `~/.tenzro/config.json` file format.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// The node's price cards as last read: the default card and per-model
/// cards, each as the node returns it.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProviderPricing {
    #[serde(default)]
    pub default: serde_json::Value,
    #[serde(default)]
    pub models: serde_json::Map<String, serde_json::Value>,
}

/// A stake a role needs that its account did not hold when setup or join
/// last ran. Kept so `tenzro status` and `tenzro sponsor status` keep naming
/// it until it is met.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PendingStake {
    /// What the stake is for, e.g. `validator`.
    pub role: String,
    /// The amount required, in wei.
    pub required_wei: String,
    /// The account that must hold it, `0x` and 64 hex.
    pub account: String,
}

/// The last application status this machine saw, so a run while the website
/// cannot be asked resumes from it instead of from the start. Never believed
/// past `funded`: the chain decides the rest. See `onboarding::state`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApplicationRecord {
    /// The wallet that applied, `0x` and 64 hex.
    pub account: String,
    /// The role slug applied for, e.g. `validator`.
    pub role: String,
    /// An `onboarding::state::ApplicationState` spelling.
    pub state: String,
    /// The opaque id on the form's receipt, when the website gave one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
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
    /// Label this machine was set up under, e.g. `alice`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub machine_name: Option<String>,
    /// Whether the operator chose to make this node publicly reachable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public: Option<bool>,
    /// `"autonomous"` (hardware-rooted, no human controller), `"self"`
    /// (a human operator holds the passkey) or `"agentic"` (an agent under a
    /// human delegation).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_mode: Option<String>,
    /// Who holds the identity and wallet key: `passkey`, `machine-key` or
    /// `delegated`. A name, never key material.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    /// The human who delegates to an agent in the `agentic` mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegator: Option<String>,
    /// Where an unfinished `tenzro setup` resumes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wizard: Option<crate::onboarding::wizard::WizardRecord>,
    /// Canonical `RoleSet` string, e.g. `"ai,storage,validator"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub roles: Option<String>,
    /// How this operator offers the resources they provide: any of
    /// `on-demand`, `subscription`, `rental`, comma-separated.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_models: Option<String>,
    pub pricing: Option<ProviderPricing>,
    #[serde(default)]
    pub served_models: Vec<String>,
    /// OAuth 2.1 access token (ES256 JWT, optionally DPoP-bound).
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
    /// The RPC endpoint that issued the access token. A node signs tokens
    /// with its own key, so the token is presented to that endpoint only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token_rpc: Option<String>,
    /// `true` iff the access token requires a DPoP proof on every call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dpop_bound: Option<bool>,
    /// The stake a role is waiting on, while its account does not hold it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_stake: Option<PendingStake>,
    /// Network phase override, `foundation` or `open-stake`; see
    /// `onboarding::phase`. Absent means the compiled default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub onboarding_phase: Option<String>,
    /// Join-form link override; see `onboarding::foundation_config`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub onboarding_join_link: Option<String>,
    /// The last application status seen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application: Option<ApplicationRecord>,
    /// Unix socket of the key holder this node signs through, when its keys
    /// are in another machine's TPM. A path, not a secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_holder_socket: Option<String>,
    /// The label that key holder's grant was issued under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_holder_label: Option<String>,
}

/// Get the path to the config file: `~/.tenzro/config.json`
pub fn config_path() -> PathBuf {
    tenzro_types::paths::cli_config_path()
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
    // Holds OAuth access and refresh tokens.
    let json = serde_json::to_string_pretty(config)?;
    crate::private_file::write_private(&path, json.as_bytes())?;
    Ok(())
}

/// Config path scoped to an explicit data directory (`<dir>/config.json`).
/// Used when `--data-dir` is given so a scoped/isolated run neither reads nor
/// mutates the global `~/.tenzro/config.json`.
pub fn config_path_in(data_dir: &std::path::Path) -> PathBuf {
    data_dir.join("config.json")
}

/// Load config from a data-dir-scoped path (default if absent).
pub fn load_config_in(data_dir: &std::path::Path) -> PersistedConfig {
    let path = config_path_in(data_dir);
    if let Ok(contents) = std::fs::read_to_string(&path) {
        serde_json::from_str(&contents).unwrap_or_default()
    } else {
        PersistedConfig::default()
    }
}

/// Save config to a data-dir-scoped path.
pub fn save_config_in(data_dir: &std::path::Path, config: &PersistedConfig) -> anyhow::Result<()> {
    let path = config_path_in(data_dir);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    crate::private_file::write_private(&path, serde_json::to_string_pretty(config)?.as_bytes())?;
    Ok(())
}
