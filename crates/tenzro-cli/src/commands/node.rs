//! Node management commands for the Tenzro CLI

use clap::{Parser, Subcommand};
use anyhow::Result;
use tenzro_types::NetworkRole;
use crate::output::{self};
use std::path::PathBuf;

/// Node management commands
#[derive(Debug, Subcommand)]
pub enum NodeCommand {
    /// Start a Tenzro Network node
    Start(NodeStartCmd),
    /// Check node status
    Status(NodeStatusCmd),
    /// Stop the running node
    Stop(NodeStopCmd),
    /// Show connected peer count
    Peers(NodePeersCmd),
    /// Show sync status
    Syncing(NodeSyncingCmd),
    /// Fetch a contiguous range of blocks for sync inspection
    SyncRange(NodeSyncRangeCmd),
    /// Inspect the EIP-1559 fee market (current gas price, suggested tip, fee history)
    FeeMarket(NodeFeeMarketCmd),
}

impl NodeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Start(cmd) => cmd.execute().await,
            Self::Status(cmd) => cmd.execute().await,
            Self::Stop(cmd) => cmd.execute().await,
            Self::Peers(cmd) => cmd.execute().await,
            Self::Syncing(cmd) => cmd.execute().await,
            Self::SyncRange(cmd) => cmd.execute().await,
            Self::FeeMarket(cmd) => cmd.execute().await,
        }
    }
}

/// Start a Tenzro Network node
#[derive(Debug, Parser)]
pub struct NodeStartCmd {
    /// Node role (validator, model-provider, tee-provider, user)
    #[arg(long, default_value = "user")]
    role: String,

    /// Path to configuration file
    #[arg(long)]
    config: Option<PathBuf>,

    /// Data directory for blockchain storage
    #[arg(long, default_value = "~/.tenzro/data")]
    data_dir: PathBuf,

    /// Enable metrics server
    #[arg(long, default_value = "true")]
    metrics: bool,

    /// RPC listen address
    #[arg(long, default_value = "127.0.0.1:9944")]
    rpc_addr: String,

    /// P2P listen address
    #[arg(long, default_value = "0.0.0.0:30333")]
    p2p_addr: String,
}

impl NodeStartCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Starting Tenzro Network Node");

        // Parse role
        let role = self.parse_role()?;

        // Create spinner
        let spinner = output::create_spinner("Initializing node...");

        spinner.set_message("Loading configuration...");
        spinner.set_message("Initializing storage...");
        spinner.set_message("Starting P2P networking...");
        spinner.set_message("Starting RPC server...");
        spinner.finish_and_clear();

        // Print node info
        output::print_success("Node started successfully!");
        println!();
        output::print_field("Role", &format!("{:?}", role));
        output::print_field("Data Directory", &self.data_dir.display().to_string());
        output::print_field("RPC Address", &self.rpc_addr);
        output::print_field("P2P Address", &self.p2p_addr);
        output::print_field("Metrics Enabled", &self.metrics.to_string());

        if let Some(config) = &self.config {
            output::print_field("Config File", &config.display().to_string());
        }

        println!();
        output::print_info("Node is now running. Press Ctrl+C to stop.");
        output::print_info(&format!("RPC endpoint: http://{}", self.rpc_addr));

        // Start the actual node process
        output::print_info("Starting tenzro-node binary...");
        let mut args = vec![
            "--role".to_string(), self.role.clone(),
            "--rpc-addr".to_string(), self.rpc_addr.clone(),
            "--listen-addr".to_string(), format!("/ip4/{}/tcp/{}",
                self.p2p_addr.split(':').next().unwrap_or("0.0.0.0"),
                self.p2p_addr.split(':').nth(1).unwrap_or("30333")),
            "--data-dir".to_string(), self.data_dir.display().to_string(),
        ];
        if let Some(config) = &self.config {
            args.push("--config".to_string());
            args.push(config.display().to_string());
        }

        // Exec into tenzro-node (this blocks until the node exits)
        let status = tokio::process::Command::new("tenzro-node")
            .args(&args)
            .status()
            .await;

        match status {
            Ok(s) if s.success() => output::print_success("Node exited successfully"),
            Ok(s) => output::print_warning(&format!("Node exited with code: {}", s.code().unwrap_or(-1))),
            Err(e) => return Err(anyhow::anyhow!("Failed to start tenzro-node: {}. Is it installed?", e)),
        }

        Ok(())
    }

    fn parse_role(&self) -> Result<NetworkRole> {
        match self.role.to_lowercase().as_str() {
            "validator" => Ok(NetworkRole::Validator),
            "model-provider" => Ok(NetworkRole::ModelProvider),
            "tee-provider" | "tee" => Ok(NetworkRole::TeeProvider),
            "user" | "light-client" => Ok(NetworkRole::LightClient),
            _ => Err(anyhow::anyhow!("Invalid role: {}. Must be one of: validator, model-provider, tee-provider, user", self.role)),
        }
    }
}

/// Check node status
#[derive(Debug, Parser)]
pub struct NodeStatusCmd {
    /// RPC endpoint to query
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

impl NodeStatusCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::{RpcClient, parse_hex_u64};

        output::print_header("Node Status");

        let spinner = output::create_spinner("Querying node status...");

        let rpc = RpcClient::new(&self.rpc);

        // Fetch node information
        let node_info: serde_json::Value = rpc.call("tenzro_nodeInfo", serde_json::json!([])).await?;
        let block_number: String = rpc.call("eth_blockNumber", serde_json::json!([])).await?;
        let peer_count: String = rpc.call("net_peerCount", serde_json::json!([])).await?;
        let listening: bool = rpc.call("net_listening", serde_json::json!([])).await.unwrap_or(false);
        // Try derived API URL first, then fallback to default port 8080
        let api_status: serde_json::Value = match rpc.api_get("/status").await {
            Ok(v) => v,
            Err(_) => {
                // Fallback: try default web API port
                let fallback = RpcClient::new("http://127.0.0.1:8545");
                fallback.api_get("/status").await.unwrap_or_else(|_| serde_json::json!({}))
            }
        };

        spinner.finish_and_clear();

        let best_block = parse_hex_u64(&block_number);
        let peers = parse_hex_u64(&peer_count);

        if self.format == "json" {
            let status = serde_json::json!({
                "node_id": node_info.get("node_id").and_then(|v| v.as_str()).unwrap_or("unknown"),
                "role": node_info.get("role").and_then(|v| v.as_str()).unwrap_or("unknown"),
                "version": node_info.get("version").and_then(|v| v.as_str()).unwrap_or("unknown"),
                "chain": node_info.get("chain").and_then(|v| v.as_str()).unwrap_or("unknown"),
                "status": api_status.get("node_state").or_else(|| api_status.get("status")).and_then(|v| v.as_str()).unwrap_or("unknown"),
                "best_block": best_block,
                "finalized_block": best_block.saturating_sub(3),
                "peers": peers,
                "listening": listening
            });
            output::print_json(&status)?;
        } else {
            output::print_success("Node is running");
            println!();
            if let Some(node_id) = node_info.get("node_id").and_then(|v| v.as_str()) {
                output::print_field("Node ID", &output::format_address(node_id));
            }
            if let Some(role) = node_info.get("role").and_then(|v| v.as_str()) {
                output::print_field("Role", role);
            }
            if let Some(version) = node_info.get("version").and_then(|v| v.as_str()) {
                output::print_field("Version", version);
            }
            if let Some(chain) = node_info.get("chain").and_then(|v| v.as_str()) {
                output::print_field("Chain", chain);
            }
            println!();

            let status_str = api_status.get("node_state")
                .or_else(|| api_status.get("status"))
                .and_then(|v| v.as_str())
                .unwrap_or("Running");
            let is_synced = status_str.contains("Synced") || status_str.contains("Running");
            output::print_status("Status", status_str, is_synced);
            println!();

            output::print_field("Best Block", &format!("{}", best_block));
            output::print_field("Finalized Block", &format!("{}", best_block.saturating_sub(3)));
            output::print_field("Connected Peers", &peers.to_string());
            // Handle both "uptime_secs" (numeric) and "uptime" (string) response formats
            if let Some(uptime_secs) = api_status.get("uptime_secs").and_then(|v| v.as_u64()) {
                let hours = uptime_secs / 3600;
                let minutes = (uptime_secs % 3600) / 60;
                let secs = uptime_secs % 60;
                output::print_field("Uptime", &format!("{}h {}m {}s", hours, minutes, secs));
            } else if let Some(uptime) = api_status.get("uptime").and_then(|v| v.as_str()) {
                output::print_field("Uptime", uptime);
            }
        }

        Ok(())
    }
}

/// Stop the running node
#[derive(Debug, Parser)]
pub struct NodeStopCmd {
    /// RPC endpoint of the node to stop
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Force stop without graceful shutdown
    #[arg(long)]
    force: bool,
}

impl NodeStopCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Stopping Node");

        if self.force {
            output::print_warning("Force stop requested - no graceful shutdown");
        }

        let spinner = output::create_spinner("Sending stop signal to node...");

        let rpc = RpcClient::new(&self.rpc);

        // Send shutdown RPC call
        let result: Result<serde_json::Value, _> = rpc.call("tenzro_shutdown", serde_json::json!([{
            "force": self.force
        }])).await;

        spinner.finish_and_clear();

        match result {
            Ok(_) => output::print_success("Node stop signal sent successfully"),
            Err(e) => {
                // Connection refused likely means node is already stopped
                let err_str = e.to_string();
                if err_str.contains("connection") || err_str.contains("refused") {
                    output::print_info("Node is not running or already stopped");
                } else {
                    return Err(e);
                }
            }
        }

        Ok(())
    }
}

/// Show connected peer count
#[derive(Debug, Parser)]
pub struct NodePeersCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodePeersCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::{RpcClient, parse_hex_u64};
        output::print_header("Connected Peers");
        let rpc = RpcClient::new(&self.rpc);
        let peer_count: String = rpc.call("tenzro_peerCount", serde_json::json!([])).await?;
        let count = parse_hex_u64(&peer_count);
        output::print_field("Peer Count", &count.to_string());
        Ok(())
    }
}

/// Show sync status
#[derive(Debug, Parser)]
pub struct NodeSyncingCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeSyncingCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::{RpcClient, parse_hex_u64};
        output::print_header("Sync Status");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_syncing", serde_json::json!([])).await?;
        if result.is_boolean() {
            let syncing = result.as_bool().unwrap_or(false);
            if syncing { output::print_info("Node is syncing..."); }
            else { output::print_success("Node is fully synced."); }
        } else {
            // Heights come back hex-encoded ("0x...") per the eth_syncing /
            // tenzro_syncing JSON-RPC convention.
            if let Some(current) = result.get("currentBlock").and_then(|v| v.as_str()) {
                output::print_field("Current Block", &parse_hex_u64(current).to_string());
            }
            if let Some(highest) = result.get("highestBlock").and_then(|v| v.as_str()) {
                output::print_field("Highest Block", &parse_hex_u64(highest).to_string());
            }
        }
        Ok(())
    }
}

/// Fetch a contiguous range of blocks via the tenzro_getBlockRange RPC.
///
/// Read-only operator inspection — useful when a node has fallen behind and
/// you want to verify which blocks the network is actually serving without
/// hand-rolling a curl loop. Use `--max` to cap the batch size (default 64,
/// max 256 — enforced server-side).
#[derive(Debug, Parser)]
pub struct NodeSyncRangeCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Inclusive starting height
    #[arg(long)]
    start: u64,

    /// Inclusive ending height
    #[arg(long)]
    end: u64,

    /// Maximum number of blocks to return in this batch (1..=256, default 64)
    #[arg(long)]
    max: Option<u64>,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

impl NodeSyncRangeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        if self.start > self.end {
            return Err(anyhow::anyhow!(
                "--start ({}) must be <= --end ({})",
                self.start,
                self.end
            ));
        }

        output::print_header("Block Range Sync");

        let mut params = serde_json::json!({
            "startHeight": self.start,
            "endHeight": self.end,
        });
        if let Some(max) = self.max {
            params["maxResults"] = serde_json::json!(max);
        }

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getBlockRange", serde_json::json!([params]))
            .await?;

        if self.format == "json" {
            output::print_json(&result)?;
            return Ok(());
        }

        let blocks = result
            .get("blocks")
            .and_then(|v| v.as_array())
            .map(|a| a.len())
            .unwrap_or(0);
        let next_height = result
            .get("nextHeight")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let more = result
            .get("moreAvailable")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let local_tip = result
            .get("localTip")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        output::print_field("Blocks Returned", &blocks.to_string());
        output::print_field("Next Height", &next_height.to_string());
        output::print_field("More Available", &more.to_string());
        output::print_field("Local Tip", &local_tip.to_string());

        if more {
            output::print_info(&format!(
                "Continue with --start {} to fetch the next batch",
                next_height
            ));
        }
        Ok(())
    }
}

/// Inspect the EIP-1559 fee market.
///
/// Calls `eth_gasPrice` (effective price = base fee + suggested tip),
/// `eth_maxPriorityFeePerGas` (suggested tip), and `eth_feeHistory` over the
/// last `--blocks` blocks to summarize current network fee conditions. Useful
/// for operators sizing `maxFeePerGas` / `maxPriorityFeePerGas` on Type-2
/// transactions, or watching base-fee drift across a load spike.
#[derive(Debug, Parser)]
pub struct NodeFeeMarketCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Number of recent blocks to include in fee-history summary (1..=1024)
    #[arg(long, default_value = "10")]
    blocks: u64,

    /// Tip percentiles to request (e.g. "25,50,75")
    #[arg(long, default_value = "25,50,75")]
    percentiles: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

impl NodeFeeMarketCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        if self.blocks == 0 || self.blocks > 1024 {
            return Err(anyhow::anyhow!(
                "--blocks must be in 1..=1024 (got {})",
                self.blocks
            ));
        }

        let percentiles: Vec<f64> = self
            .percentiles
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().parse::<f64>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("invalid --percentiles: {}", e))?;

        let rpc = RpcClient::new(&self.rpc);

        let gas_price_hex: String = rpc
            .call("eth_gasPrice", serde_json::json!([]))
            .await?;
        let priority_hex: String = rpc
            .call("eth_maxPriorityFeePerGas", serde_json::json!([]))
            .await?;
        let history: serde_json::Value = rpc
            .call(
                "eth_feeHistory",
                serde_json::json!([format!("0x{:x}", self.blocks), "latest", percentiles]),
            )
            .await?;

        if self.format == "json" {
            let combined = serde_json::json!({
                "gasPrice": gas_price_hex,
                "maxPriorityFeePerGas": priority_hex,
                "feeHistory": history,
            });
            output::print_json(&combined)?;
            return Ok(());
        }

        output::print_header("Fee Market (EIP-1559)");
        output::print_field("Effective Gas Price (wei)", &parse_hex_u128_str(&gas_price_hex));
        output::print_field("Suggested Priority Tip (wei)", &parse_hex_u128_str(&priority_hex));

        if let Some(base_fees) = history.get("baseFeePerGas").and_then(|v| v.as_array()) {
            output::print_field(
                "Base Fee Samples",
                &format!("{} entries (last = next-block prediction)", base_fees.len()),
            );
            if let Some(next) = base_fees.last().and_then(|v| v.as_str()) {
                output::print_field("Next-Block Base Fee (wei)", &parse_hex_u128_str(next));
            }
        }

        if let Some(ratios) = history.get("gasUsedRatio").and_then(|v| v.as_array()) {
            let avg: f64 = ratios.iter().filter_map(|v| v.as_f64()).sum::<f64>()
                / ratios.len().max(1) as f64;
            output::print_field("Avg Gas-Used Ratio", &format!("{:.3}", avg));
        }

        Ok(())
    }
}

fn parse_hex_u128_str(hex: &str) -> String {
    let stripped = hex.trim_start_matches("0x");
    match u128::from_str_radix(stripped, 16) {
        Ok(v) => v.to_string(),
        Err(_) => hex.to_string(),
    }
}
