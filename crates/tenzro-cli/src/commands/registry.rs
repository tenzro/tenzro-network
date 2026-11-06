//! The generic registry.
//!
//! Units of metered work, service types, price cards, apps and datasets are
//! all registry entries: an id, a kind, the hash of the harness module that
//! interprets it, opaque data and its owner. These commands only read.
//!
//! - `tenzro registry list` — the standing entries of one kind
//!   (`tenzro_listRegistry`)
//! - `tenzro registry get` — one entry, latest or a named version
//!   (`tenzro_getRegistryEntry`)

use crate::output;
use anyhow::Result;
use clap::{Parser, Subcommand};

/// The generic registry (read-only)
#[derive(Debug, Subcommand)]
pub enum RegistryCommand {
    /// List the standing entries of one kind, in id order (read-only)
    List(RegistryListCmd),
    /// Show one entry, the latest version or the one named (read-only)
    Get(RegistryGetCmd),
}

impl RegistryCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::List(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
        }
    }
}

/// List the standing entries of one kind.
#[derive(Debug, Parser)]
pub struct RegistryListCmd {
    /// Entry kind, e.g. unit, card, service, app, dataset
    #[arg(long)]
    kind: String,

    /// List ids after this one (the previous page's next)
    #[arg(long)]
    after: Option<String>,

    /// Most entries to return (default 100, at most 500)
    #[arg(long)]
    limit: Option<u64>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RegistryListCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_listRegistry",
                serde_json::json!({ "kind": self.kind, "after": self.after, "limit": self.limit }),
            )
            .await?;
        output::print_json(&result)
    }
}

/// Show one registry entry.
#[derive(Debug, Parser)]
pub struct RegistryGetCmd {
    /// Entry id
    #[arg(long)]
    id: String,

    /// A past version of the entry (default: the latest)
    #[arg(long)]
    version: Option<u64>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl RegistryGetCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getRegistryEntry",
                serde_json::json!({ "id": self.id, "version": self.version }),
            )
            .await?;
        if result.is_null() {
            output::print_warning("No such registry entry.");
            return Ok(());
        }
        output::print_json(&result)
    }
}
