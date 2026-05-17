//! SeedAgent treasury earmark + bootstrap-agent registry commands (Spec 10).
//!
//! Wraps the read-only `tenzro_*` JSON-RPC namespace for the SeedAgent
//! genesis-funded earmark, charters, provisioned records, and network
//! activity baseline:
//!
//! - `tenzro seed-agent earmark`            — singleton TreasuryEarmark
//! - `tenzro seed-agent charter <id>`       — single Charter by id
//! - `tenzro seed-agent charters`           — list every Charter
//! - `tenzro seed-agent list [--charter X]` — list SeedAgentRecords
//! - `tenzro seed-agent activity`           — network activity baseline
//!
//! Write-side (provisioning daemon, monthly decay, sunset wind-down) lands
//! alongside the governance-executor mutation paths in a later wave.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;

/// SeedAgent treasury earmark + charter + registry commands
#[derive(Debug, Subcommand)]
pub enum SeedAgentCommand {
    /// Show the singleton TreasuryEarmark
    Earmark(SeedAgentEarmarkCmd),
    /// Fetch a single Charter by id
    Charter(SeedAgentCharterCmd),
    /// List every registered Charter (active + sunset)
    Charters(SeedAgentChartersCmd),
    /// List provisioned SeedAgentRecords, optionally filtered by charter
    List(SeedAgentListCmd),
    /// Show network activity baseline (for counterparty filter)
    Activity(SeedAgentActivityCmd),
}

impl SeedAgentCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Earmark(cmd) => cmd.execute().await,
            Self::Charter(cmd) => cmd.execute().await,
            Self::Charters(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Activity(cmd) => cmd.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct SeedAgentEarmarkCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SeedAgentEarmarkCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("SeedAgent — TreasuryEarmark");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_getTreasuryEarmark", serde_json::json!({}))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SeedAgentCharterCmd {
    /// Charter id (hex)
    #[arg(long)]
    charter_id: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SeedAgentCharterCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("SeedAgent — Charter");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_getSeedAgentCharter",
                serde_json::json!({ "charter_id": self.charter_id }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SeedAgentChartersCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SeedAgentChartersCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("SeedAgent — Charters");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_listSeedAgentCharters", serde_json::json!({}))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SeedAgentListCmd {
    /// Optional charter id filter
    #[arg(long)]
    charter_id: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SeedAgentListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("SeedAgent — Provisioned Records");
        let rpc = RpcClient::new(&self.rpc);
        let params = match &self.charter_id {
            Some(cid) => serde_json::json!({ "charter_id": cid }),
            None => serde_json::json!({}),
        };
        let v: serde_json::Value = rpc.call("tenzro_listSeedAgents", params).await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct SeedAgentActivityCmd {
    /// Optional rolling window (in blocks)
    #[arg(long)]
    window_blocks: Option<u64>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl SeedAgentActivityCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("SeedAgent — Network Activity Baseline");
        let rpc = RpcClient::new(&self.rpc);
        let params = match self.window_blocks {
            Some(w) => serde_json::json!({ "window_blocks": w }),
            None => serde_json::json!({}),
        };
        let v: serde_json::Value = rpc.call("tenzro_getNetworkActivity", params).await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
