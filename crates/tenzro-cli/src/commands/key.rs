//! Subject-gated API-key self-management for the Tenzro CLI.
//!
//! These commands wrap the developer-facing RPCs gated by the
//! `X-Tenzro-Api-Key` header — listing and revoking keys that belong
//! to the caller's own subject. Operator-side issuance lives under
//! `tenzro admin api-key` (admin-token-gated).
//!
//! Both commands resolve the caller's subject from the presented key
//! server-side; there is no way to act on a different subject's keys.
//! See `docs/api-keys.md` for the full key-class model.

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

/// Self-managed (subject-gated) API key commands.
///
/// Uses the developer's own `tnz_...` key via `X-Tenzro-Api-Key`.
/// For operator-side issuance see `tenzro admin api-key`.
#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// List every API key belonging to your subject (active + revoked).
    ListMine(KeyListMineCmd),
    /// Revoke an API key belonging to your subject.
    RevokeMine(KeyRevokeMineCmd),
}

impl KeyCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::ListMine(cmd) => cmd.execute().await,
            Self::RevokeMine(cmd) => cmd.execute().await,
        }
    }
}

/// List every API key that belongs to your subject.
#[derive(Debug, Parser)]
pub struct KeyListMineCmd {
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Your own Tenzro API key (`tnz_...`).
    /// Falls back to the `TENZRO_API_KEY` env var.
    #[arg(long, env = "TENZRO_API_KEY", hide_env_values = true)]
    api_key: Option<String>,
}

impl KeyListMineCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("My API Keys");

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(key) = &self.api_key {
            rpc = rpc.with_api_key(key);
        }

        let spinner = output::create_spinner("Loading keys...");
        let result: serde_json::Value = rpc
            .call("tenzro_listMyApiKeys", serde_json::json!({}))
            .await?;
        spinner.finish_and_clear();

        if let Some(subject) = result.get("subject").and_then(|v| v.as_str()) {
            output::print_field("Subject", subject);
        }

        let keys = result
            .get("keys")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        if keys.is_empty() {
            output::print_info("No API keys found for your subject.");
            return Ok(());
        }

        let headers = vec!["Key ID", "Label", "Scopes", "Class", "Active", "Created"];
        let mut rows = Vec::new();
        for key in keys {
            let scopes = key
                .get("scopes")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            rows.push(vec![
                key.get("key_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("?")
                    .to_string(),
                key.get("label")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                scopes,
                key.get("class")
                    .and_then(|v| v.as_str())
                    .unwrap_or("subject")
                    .to_string(),
                key.get("active")
                    .and_then(|v| v.as_bool())
                    .map(|b| if b { "yes" } else { "no" })
                    .unwrap_or("?")
                    .to_string(),
                key.get("created_at")
                    .and_then(|v| v.as_i64())
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "?".to_string()),
            ]);
        }
        output::print_table(&headers, &rows);

        Ok(())
    }
}

/// Revoke an API key belonging to your subject.
///
/// Only `subject`-class keys are eligible. `operator_internal` and
/// `operator_protected` keys must be handled by the operator.
#[derive(Debug, Parser)]
pub struct KeyRevokeMineCmd {
    /// Non-secret key id (8-byte hex prefix). Get this from `list-mine`.
    #[arg(long)]
    key_id: String,

    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Your own Tenzro API key (`tnz_...`).
    /// Falls back to the `TENZRO_API_KEY` env var.
    #[arg(long, env = "TENZRO_API_KEY", hide_env_values = true)]
    api_key: Option<String>,
}

impl KeyRevokeMineCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Revoke My API Key");

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(key) = &self.api_key {
            rpc = rpc.with_api_key(key);
        }

        let spinner = output::create_spinner("Revoking key...");
        let result: serde_json::Value = rpc
            .call(
                "tenzro_revokeMyApiKey",
                serde_json::json!({ "key_id": self.key_id }),
            )
            .await?;
        spinner.finish_and_clear();

        let revoked = result
            .get("revoked")
            .and_then(|v| v.as_bool())
            .ok_or_else(|| anyhow!("response missing `revoked` field"))?;

        output::print_field("Key ID", &self.key_id);
        output::print_field("Revoked", if revoked { "yes" } else { "no" });

        Ok(())
    }
}
