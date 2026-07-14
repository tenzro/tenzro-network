//! Hosting-lease read commands for the Tenzro CLI
//!
//! Leases are the on-ledger placement records that bind a deployed app
//! (static site, function, or machine) to the nodes serving it, with the
//! per-hour price bid and expiry. Leases are cross-app, so they live in
//! their own command group rather than under `site`/`function`/`machine`.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;
use crate::rpc::RpcClient;

/// Hosting-lease inspection operations
#[derive(Debug, Subcommand)]
pub enum LeaseCommand {
    /// List all active hosting leases held by this node
    List(LeaseListCmd),
    /// Show the leases placed for a specific app
    Get(LeaseGetCmd),
}

impl LeaseCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::List(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
        }
    }
}

/// List all active hosting leases
#[derive(Debug, Parser)]
pub struct LeaseListCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl LeaseListCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Hosting Leases");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value =
            rpc.call("tenzro_listLeases", serde_json::json!({})).await?;

        print_lease_list(&result)?;
        Ok(())
    }
}

/// Show leases for one app
#[derive(Debug, Parser)]
pub struct LeaseGetCmd {
    /// App ID (site_id, function deployment id, or machine deployment id)
    #[arg(long)]
    app_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl LeaseGetCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("App Leases");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc
            .call("tenzro_getLeasesForApp", serde_json::json!({ "app_id": self.app_id }))
            .await?;

        output::print_field("App ID", &self.app_id);
        print_lease_list(&result)?;
        Ok(())
    }
}

/// Print the `placement` array a deploy response carries (leased serving nodes).
/// Shared by `site`/`function`/`machine` deploy commands.
pub fn print_placement(deployment: &serde_json::Value) {
    match deployment.get("placement").and_then(|v| v.as_array()) {
        Some(nodes) if !nodes.is_empty() => {
            output::print_field("Placed on", &format!("{} node(s)", nodes.len()));
            for n in nodes {
                if let Some(id) = n.as_str() {
                    output::print_field("  node", id);
                }
            }
        }
        _ => output::print_field("Placement", "local (no remote node leased)"),
    }
}

fn print_lease_list(result: &serde_json::Value) -> Result<()> {
    let leases = result.get("leases").and_then(|v| v.as_array());
    match leases {
        Some(leases) if !leases.is_empty() => {
            for l in leases {
                let node = l.get("node_id").and_then(|v| v.as_str()).unwrap_or("?");
                let class = l.get("runtime_class").and_then(|v| v.as_str()).unwrap_or("?");
                let price = l.get("price_per_hour").and_then(|v| v.as_str()).unwrap_or("0");
                let region = l.get("region").and_then(|v| v.as_str()).unwrap_or("-");
                let expires = l.get("expires_at").and_then(|v| v.as_u64()).unwrap_or(0);
                output::print_field(
                    node,
                    &format!("{class} · {price} TNZO/hr · region {region} · expires {expires}"),
                );
            }
            output::print_field(
                "Count",
                &result.get("count").and_then(|v| v.as_u64()).unwrap_or(0).to_string(),
            );
        }
        _ => output::print_info("No active leases."),
    }
    Ok(())
}
