//! Operator/admin commands for the Tenzro CLI.
//!
//! These commands wrap the admin RPCs gated by the
//! `X-Tenzro-Admin-Token` header — minting API keys for developers,
//! listing the current keyring, and revoking keys by id.
//!
//! **Operator-only, per node.** Every Tenzro node operator holds
//! their own admin token for *their own node's* state. Tenzro Labs
//! holds the token for `rpc.tenzro.network`; a validator operator
//! holds the token for that validator's RPC; a self-hosted operator
//! holds the token for their local node. Calls without the matching
//! token are rejected `-32001`. There is no global "Tenzro Labs
//! token" and these commands grant no authority over network-wide
//! state (validator set, treasury, fee schedule, protocol params —
//! all of those flow through on-chain governance, not the admin
//! token). See `docs/api-keys.md` for the sovereignty model and the
//! per-key class semantics (`subject` / `operator_internal` /
//! `operator_protected`). Developers who need a key request one out
//! of band from whichever operator runs the node they want to use.

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

/// Operator admin commands (API key issuance, revocation, listing).
///
/// Operator-only — requires `X-Tenzro-Admin-Token` for whichever node
/// you target via `--rpc`. Every operator holds their own token;
/// developers request keys out of band (see `docs/api-keys.md`).
#[derive(Debug, Subcommand)]
pub enum AdminCommand {
    /// API key management (`X-Tenzro-Admin-Token` required).
    #[command(subcommand)]
    ApiKey(ApiKeySubcommand),
}

impl AdminCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::ApiKey(cmd) => cmd.execute().await,
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum ApiKeySubcommand {
    /// Mint a new API key for a developer.
    Create(ApiKeyCreateCmd),
    /// List every API key the node has issued (active + revoked).
    List(ApiKeyListCmd),
    /// Revoke an API key by its non-secret `key_id`.
    Revoke(ApiKeyRevokeCmd),
}

impl ApiKeySubcommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Create(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Revoke(cmd) => cmd.execute().await,
        }
    }
}

/// Mint a new API key.
#[derive(Debug, Parser)]
pub struct ApiKeyCreateCmd {
    /// Free-form label for the key (shown in `list`).
    #[arg(long)]
    label: String,

    /// Optional subject identifier — typically a Tenzro DID. Used for
    /// audit / revocation lookup; not enforced by the node.
    #[arg(long)]
    subject: Option<String>,

    /// Scopes to grant. Repeat for multiple. Defaults to `canton`.
    #[arg(long = "scope")]
    scopes: Vec<String>,

    /// Key class. One of `subject` (default — subject can self-revoke),
    /// `operator_internal` (operator-only, admin-revokable),
    /// `operator_protected` (operator-only, NOT revokable via RPC —
    /// rotate by updating the operator secret + restart).
    #[arg(long, default_value = "subject")]
    class: String,

    /// Required when `--class operator_protected`. Confirms the caller
    /// understands the resulting key cannot be revoked via RPC.
    #[arg(long)]
    confirm_operator_protected: bool,

    /// Optional Canton User Management Service user id this key acts
    /// as (e.g. `manexus@clients`). Binds the key to a Canton user so
    /// the node forwards canton-scoped calls with that user's primary
    /// party as `actAs`. Canton's AuthService enforces per-user
    /// CanActAs rights — keys without this binding fall back to the
    /// operator's primary party. See
    /// `docs/operators/CANTON_MULTITENANT.md`.
    #[arg(long)]
    canton_user_id: Option<String>,

    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Operator admin token (`X-Tenzro-Admin-Token`).
    /// Falls back to the `TENZRO_ADMIN_TOKEN` env var.
    #[arg(long, env = "TENZRO_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,
}

impl ApiKeyCreateCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Mint API Key");

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(token) = &self.admin_token {
            rpc = rpc.with_admin_token(token);
        }

        let scopes: Vec<String> = if self.scopes.is_empty() {
            vec!["canton".to_string()]
        } else {
            self.scopes.clone()
        };

        let mut params = serde_json::Map::new();
        params.insert(
            "label".to_string(),
            serde_json::Value::String(self.label.clone()),
        );
        if let Some(subject) = &self.subject {
            params.insert(
                "subject".to_string(),
                serde_json::Value::String(subject.clone()),
            );
        }
        params.insert(
            "scopes".to_string(),
            serde_json::Value::Array(
                scopes
                    .iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            ),
        );
        params.insert(
            "class".to_string(),
            serde_json::Value::String(self.class.clone()),
        );
        if self.confirm_operator_protected {
            params.insert(
                "confirm_operator_protected".to_string(),
                serde_json::Value::Bool(true),
            );
        }
        if let Some(canton_user_id) = &self.canton_user_id {
            params.insert(
                "canton_user_id".to_string(),
                serde_json::Value::String(canton_user_id.clone()),
            );
        }

        let spinner = output::create_spinner("Minting key...");
        let result: serde_json::Value = rpc
            .call("tenzro_createApiKey", serde_json::Value::Object(params))
            .await?;
        spinner.finish_and_clear();

        let key = result
            .get("key")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("response missing `key` field"))?;
        let key_id = result
            .get("key_id")
            .and_then(|v| v.as_str())
            .unwrap_or("?");
        let created_at = result
            .get("created_at")
            .and_then(|v| v.as_i64())
            .map(|t| t.to_string())
            .unwrap_or_else(|| "?".to_string());

        output::print_field("Key ID", key_id);
        output::print_field("Label", &self.label);
        if let Some(subject) = &self.subject {
            output::print_field("Subject", subject);
        }
        output::print_field("Scopes", &scopes.join(","));
        output::print_field("Class", &self.class);
        if let Some(cuid) = result.get("canton_user_id").and_then(|v| v.as_str()) {
            output::print_field("Canton User", cuid);
        }
        output::print_field("Created At", &created_at);
        output::print_info("");
        output::print_info("API key (shown ONCE — save it now):");
        output::print_info(key);

        Ok(())
    }
}

/// List every API key the node has issued.
#[derive(Debug, Parser)]
pub struct ApiKeyListCmd {
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Operator admin token.
    #[arg(long, env = "TENZRO_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,
}

impl ApiKeyListCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("API Keys");

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(token) = &self.admin_token {
            rpc = rpc.with_admin_token(token);
        }

        let spinner = output::create_spinner("Loading keys...");
        let result: serde_json::Value = rpc
            .call("tenzro_listApiKeys", serde_json::json!({}))
            .await?;
        spinner.finish_and_clear();

        let keys = result
            .get("keys")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        if keys.is_empty() {
            output::print_info("No API keys issued.");
            return Ok(());
        }

        let headers = vec!["Key ID", "Label", "Subject", "Scopes", "Class", "Active", "Created"];
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
                key.get("subject")
                    .and_then(|v| v.as_str())
                    .unwrap_or("-")
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

/// Revoke an API key by its non-secret `key_id`.
#[derive(Debug, Parser)]
pub struct ApiKeyRevokeCmd {
    /// Non-secret key id (8-byte hex prefix). Get this from `list`.
    #[arg(long)]
    key_id: String,

    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Operator admin token.
    #[arg(long, env = "TENZRO_ADMIN_TOKEN", hide_env_values = true)]
    admin_token: Option<String>,
}

impl ApiKeyRevokeCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Revoke API Key");

        let mut rpc = RpcClient::new(&self.rpc);
        if let Some(token) = &self.admin_token {
            rpc = rpc.with_admin_token(token);
        }

        let spinner = output::create_spinner("Revoking key...");
        let result: serde_json::Value = rpc
            .call(
                "tenzro_revokeApiKey",
                serde_json::json!({ "key_id": self.key_id }),
            )
            .await?;
        spinner.finish_and_clear();

        let revoked = result
            .get("revoked")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        output::print_field("Key ID", &self.key_id);
        output::print_field("Revoked", if revoked { "yes" } else { "no" });

        Ok(())
    }
}
