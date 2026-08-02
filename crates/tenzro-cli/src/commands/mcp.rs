//! Operator-only MCP plugin host CLI.
//!
//! Manages the sealed credential vault that the plugin host references
//! at MCP invocation time. The plaintext secret is never visible to
//! tenants; only the operator's admin token can write to the vault.

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::json;

use crate::{output, rpc};

#[derive(Debug, Subcommand)]
pub enum McpCommand {
    /// Store an upstream credential in the operator's sealed vault.
    /// The `sealed_secret_ref` is referenced by MCP tool registrations
    /// via `upstream_auth.sealed_secret_ref`.
    StoreSecret(StoreSecretCmd),
    /// Delete a credential from the vault. Idempotent.
    ForgetSecret(ForgetSecretCmd),
    /// Forcibly evict a persistent stdio MCP subprocess. The next
    /// invocation respawns it. Use after rotating credentials.
    EvictSubprocess(EvictSubprocessCmd),
}

impl McpCommand {
    pub async fn execute(self) -> Result<()> {
        match self {
            Self::StoreSecret(cmd) => cmd.execute().await,
            Self::ForgetSecret(cmd) => cmd.execute().await,
            Self::EvictSubprocess(cmd) => cmd.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct StoreSecretCmd {
    /// Opaque ref the operator picks. MCP registrations reference this.
    #[arg(long)]
    pub sealed_secret_ref: String,
    /// The plaintext upstream secret (Stripe key, OpenAI key, etc.).
    /// For safety in shell history, prefer reading from a file with
    /// `--plaintext-file`.
    #[arg(long, conflicts_with = "plaintext_file")]
    pub plaintext: Option<String>,
    /// Path to a file whose contents are the plaintext secret. Trimmed.
    #[arg(long, conflicts_with = "plaintext")]
    pub plaintext_file: Option<String>,
}

impl StoreSecretCmd {
    pub async fn execute(self) -> Result<()> {
        let plaintext = if let Some(p) = self.plaintext {
            p
        } else if let Some(f) = self.plaintext_file {
            std::fs::read_to_string(f)?.trim().to_string()
        } else {
            anyhow::bail!("Provide --plaintext or --plaintext-file");
        };
        let client = rpc::RpcClient::new("http://127.0.0.1:8545");
        let result: serde_json::Value = client
            .call(
                "tenzro_storeMcpSecret",
                json!({
                    "sealed_secret_ref": self.sealed_secret_ref,
                    "plaintext": plaintext,
                }),
            )
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ForgetSecretCmd {
    #[arg(long)]
    pub sealed_secret_ref: String,
}

impl ForgetSecretCmd {
    pub async fn execute(self) -> Result<()> {
        let client = rpc::RpcClient::new("http://127.0.0.1:8545");
        let result: serde_json::Value = client
            .call(
                "tenzro_forgetMcpSecret",
                json!({"sealed_secret_ref": self.sealed_secret_ref}),
            )
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct EvictSubprocessCmd {
    #[arg(long)]
    pub tool_id: String,
}

impl EvictSubprocessCmd {
    pub async fn execute(self) -> Result<()> {
        let client = rpc::RpcClient::new("http://127.0.0.1:8545");
        let result: serde_json::Value = client
            .call(
                "tenzro_evictMcpSubprocess",
                json!({"tool_id": self.tool_id}),
            )
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}
