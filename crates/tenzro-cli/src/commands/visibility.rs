//! `tenzro visibility` — the node's visibility.
//!
//! One setting for every resource the node offers, unless a resource carries
//! its own override:
//!
//! - `public`: announced; anyone may use a resource by paying the operator's
//!   per-use price (free at `0`).
//! - `gated`: announced as access-required; usable only by callers the
//!   access policy names.
//! - `private`: nothing announced; only this node's own callers are served.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};

use crate::output;
use crate::rpc::RpcClient;

/// Show or set this node's visibility
#[derive(Debug, Subcommand)]
pub enum VisibilityCommand {
    /// Show the node's visibility and the resources that override it
    Show(ShowCmd),
    /// Set the node's visibility
    Set(SetCmd),
}

impl VisibilityCommand {
    pub async fn execute(self) -> Result<()> {
        match self {
            Self::Show(c) => c.execute().await,
            Self::Set(c) => c.execute().await,
        }
    }
}

fn render(v: &serde_json::Value) {
    println!();
    output::print_field("Visibility", v["visibility"].as_str().unwrap_or("?"));
    output::print_field(
        "Announced",
        if v["announced"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        },
    );
    output::print_field(
        "Key required",
        if v["requires_key"].as_bool().unwrap_or(false) {
            "yes"
        } else {
            "no"
        },
    );
    output::print_field("Price per use", v["price_per_use"].as_str().unwrap_or("0"));
    let overrides = v["overrides"].as_array().cloned().unwrap_or_default();
    if !overrides.is_empty() {
        println!();
        output::print_header("Overrides");
        for o in overrides {
            let name = match o["id"].as_str() {
                Some(id) => format!("{} {}", o["resource"].as_str().unwrap_or("?"), id),
                None => o["resource"].as_str().unwrap_or("?").to_string(),
            };
            output::print_field(&name, o["visibility"].as_str().unwrap_or("?"));
        }
    }
}

#[derive(Debug, Parser)]
pub struct ShowCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ShowCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Node Visibility");
        let v: serde_json::Value = RpcClient::new(&self.rpc)
            .call("tenzro_nodeVisibility", serde_json::json!({}))
            .await
            .context("reading node visibility")?;
        render(&v);
        Ok(())
    }
}

/// A node visibility.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum VisibilityArg {
    /// Announced; anyone may use a resource by paying the per-use price
    Public,
    /// Announced as access-required; callers the access policy names only
    Gated,
    /// Not announced; this node's own callers only
    Private,
}

impl VisibilityArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Gated => "gated",
            Self::Private => "private",
        }
    }
}

#[derive(Debug, Parser)]
pub struct SetCmd {
    /// The node's visibility
    #[arg(value_enum)]
    visibility: VisibilityArg,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SetCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Node Visibility");
        let client = RpcClient::new(&self.rpc);
        let v: serde_json::Value = client
            .call(
                "tenzro_setNodeVisibility",
                serde_json::json!({ "visibility": self.visibility.as_str() }),
            )
            .await
            .context("setting node visibility")?;
        render(&v);
        Ok(())
    }
}
