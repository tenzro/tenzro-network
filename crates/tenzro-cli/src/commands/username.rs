//! Username management command for the Tenzro CLI.
//!
//! Ported from the Tauri desktop app's `set_username()` command.
//! Now supports on-chain registration via `tenzro_setUsername` RPC.

use clap::Parser;
use anyhow::Result;
use crate::config;
use crate::output;

/// Set your Tenzro username
#[derive(Debug, Parser)]
pub struct SetUsernameCmd {
    /// Username to set (lowercase alphanumeric + underscores, 3-20 chars)
    pub username: String,

    /// RPC endpoint for on-chain username registration
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

impl SetUsernameCmd {
    pub async fn execute(&self) -> Result<()> {
        // Strip @ prefix and normalize to lowercase
        let clean = self.username.trim_start_matches('@').to_lowercase();
        if clean.is_empty() {
            return Err(anyhow::anyhow!("Username cannot be empty"));
        }
        if clean.len() < 3 {
            return Err(anyhow::anyhow!("Username must be at least 3 characters"));
        }
        if clean.len() > 20 {
            return Err(anyhow::anyhow!("Username must be at most 20 characters"));
        }
        if !clean.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
            return Err(anyhow::anyhow!(
                "Username can only contain lowercase letters, digits, and underscores"
            ));
        }
        if clean.starts_with('_') || clean.ends_with('_') {
            return Err(anyhow::anyhow!(
                "Username must not start or end with an underscore"
            ));
        }

        let mut cfg = config::load_config();
        cfg.username = Some(clean.clone());
        cfg.display_name = Some(clean.clone());

        // Auto-generate DID if missing
        if cfg.did.is_none() {
            let uuid = uuid::Uuid::new_v4();
            let did = format!("did:tenzro:human:{}", uuid);
            cfg.did = Some(did.clone());
            output::print_info(&format!("Generated identity: {}", did));
        }

        // Auto-generate wallet if missing
        if cfg.wallet_id.is_none() {
            use sha2::{Sha256, Digest};
            let wallet_id = uuid::Uuid::new_v4().to_string();
            let mut hasher = Sha256::new();
            hasher.update(wallet_id.as_bytes());
            let hash = hasher.finalize();
            let wallet_address = format!("0x{}", hex::encode(&hash[..20]));
            cfg.wallet_id = Some(wallet_id);
            cfg.wallet_address = Some(wallet_address.clone());
            output::print_info(&format!("Generated wallet: {}", wallet_address));
        }

        // Save locally first
        config::save_config(&cfg)?;

        // Register on-chain via RPC
        let did = cfg.did.as_deref().unwrap_or("unknown");
        let spinner = output::create_spinner("Registering username on-chain...");

        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        match rpc.call::<serde_json::Value>("tenzro_setUsername", serde_json::json!([{
            "did": did,
            "username": clean,
        }])).await {
            Ok(result) => {
                spinner.finish_and_clear();
                output::print_success(&format!("Username @{} registered on-chain", clean));
                if let Some(status) = result.get("status").and_then(|v| v.as_str()) {
                    output::print_field("Status", status);
                }
            }
            Err(e) => {
                spinner.finish_and_clear();
                output::print_warning(&format!("On-chain registration failed: {}", e));
                output::print_info("Username saved locally. You can retry on-chain registration later.");
            }
        }

        output::print_field("Username", &format!("@{}", clean));
        output::print_field("DID", cfg.did.as_deref().unwrap_or("none"));
        output::print_field("Wallet", cfg.wallet_address.as_deref().unwrap_or("none"));
        output::print_field("Config", &config::config_path().display().to_string());

        Ok(())
    }
}
