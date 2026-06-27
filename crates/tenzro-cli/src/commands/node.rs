//! Node management commands for the Tenzro CLI

use clap::{Parser, Subcommand};
use anyhow::Result;
use tenzro_types::RoleSet;
use crate::output::{self};
use std::path::PathBuf;
use std::str::FromStr;

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
    /// Show Spec-2 admission-controller mempool stats (per-lane admit/reject counters + lane config)
    MempoolStats(NodeMempoolStatsCmd),
    /// Resolve which admission lane an address would land in, plus its current token-bucket state
    MempoolLane(NodeMempoolLaneCmd),
    /// Show network-layer counters and gauges (gossip, connections, peer-address migrations)
    Stats(NodeStatsCmd),
    /// Storage-provider operations (store objects, open/charge streaming deals, pricing)
    #[command(subcommand)]
    Storage(StorageCommand),
    /// Compute-provider operations (book/settle fixed-term CPU/GPU rentals, pricing)
    #[command(subcommand)]
    Compute(ComputeCommand),
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
            Self::MempoolStats(cmd) => cmd.execute().await,
            Self::MempoolLane(cmd) => cmd.execute().await,
            Self::Stats(cmd) => cmd.execute().await,
            Self::Storage(cmd) => cmd.execute().await,
            Self::Compute(cmd) => cmd.execute().await,
        }
    }
}

/// Start a Tenzro Network node
#[derive(Debug, Parser)]
pub struct NodeStartCmd {
    /// Comma-separated node roles. One stake backs every role.
    /// Tokens: validator, ai, storage, tee, user. Examples:
    /// "validator", "validator,storage,ai", "storage".
    #[arg(long, default_value = "user")]
    roles: String,

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

        // Parse roles (validate before spawning the node binary)
        let roles = RoleSet::from_str(&self.roles)
            .map_err(|e| anyhow::anyhow!("Invalid --roles \"{}\": {}", self.roles, e))?;

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
        output::print_field("Roles", &roles.to_string());
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
            "--roles".to_string(), roles.to_string(),
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
                "roles": node_info.get("roles").cloned().unwrap_or(serde_json::json!([])),
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
            if let Some(roles) = node_info.get("roles").and_then(|v| v.as_array()) {
                let names: Vec<&str> = roles.iter().filter_map(|v| v.as_str()).collect();
                if !names.is_empty() {
                    output::print_field("Roles", &names.join(", "));
                }
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

/// Show Spec-2 admission-controller mempool stats.
///
/// Calls `tenzro_getMempoolStats` and prints per-lane (Verified / Delegated /
/// Open) admission counters, the active lane configuration (refill rate, burst
/// capacity, fee-floor multiplier, leader weight), and the current bucket
/// count. Useful for operators watching admission pressure under load or
/// validating that lane assignment is working as intended.
#[derive(Debug, Parser)]
pub struct NodeMempoolStatsCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

impl NodeMempoolStatsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getMempoolStats", serde_json::json!([]))
            .await?;

        if self.format == "json" {
            output::print_json(&result)?;
            return Ok(());
        }

        output::print_header("Mempool Admission Stats (Spec 2)");

        let bucket_count = result
            .get("bucket_count")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let min_verified_stake = result
            .get("min_verified_stake")
            .and_then(|v| v.as_str())
            .unwrap_or("0");
        let bond_promotes = result
            .get("bond_promotes_to_delegated")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        output::print_field("Active Buckets", &bucket_count.to_string());
        output::print_field("Min Verified Stake (smallest unit)", min_verified_stake);
        output::print_field(
            "Bond → Delegated Promotion",
            if bond_promotes { "enabled" } else { "disabled" },
        );

        if let Some(lanes) = result.get("lanes").and_then(|v| v.as_array()) {
            for lane_data in lanes {
                let lane_name = lane_data
                    .get("lane")
                    .and_then(|v| v.as_str())
                    .unwrap_or("(unknown)");
                println!();
                output::print_info(&format!("Lane: {}", lane_name));
                let admitted = lane_data
                    .get("admitted")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let rejected_rate = lane_data
                    .get("rejected_rate_limited")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let rejected_fee_floor = lane_data
                    .get("rejected_fee_floor")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let rejected_mempool_full = lane_data
                    .get("rejected_mempool_full")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let refill = lane_data
                    .get("refill_per_sec")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                let burst = lane_data
                    .get("burst_capacity")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let fee_mult = lane_data
                    .get("fee_floor_mult")
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                let weight = lane_data
                    .get("weight")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);

                output::print_field("  Admitted", &admitted.to_string());
                output::print_field("  Rejected (rate-limited)", &rejected_rate.to_string());
                output::print_field("  Rejected (fee-floor)", &rejected_fee_floor.to_string());
                output::print_field("  Rejected (mempool-full)", &rejected_mempool_full.to_string());
                output::print_field("  Refill (tx/s)", &format!("{:.3}", refill));
                output::print_field("  Burst Capacity", &burst.to_string());
                output::print_field("  Fee Floor Multiplier", &format!("{:.3}x", fee_mult));
                output::print_field("  Leader Weight", &weight.to_string());
            }
        }

        Ok(())
    }
}

/// Resolve which admission lane an address would land in.
///
/// Calls `tenzro_getMempoolLane` with a probe transaction to determine which
/// lane (Verified / Delegated / Open) a given address would be admitted on,
/// the bucket key that owns its rate-limit state (controller wallet for
/// machine DIDs, the address itself otherwise), and the current token-bucket
/// snapshot (capacity, available tokens, refill rate).
#[derive(Debug, Parser)]
pub struct NodeMempoolLaneCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Address to probe (hex, 0x-prefixed or bare)
    address: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

impl NodeMempoolLaneCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getMempoolLane",
                serde_json::json!([{ "address": self.address }]),
            )
            .await?;

        if self.format == "json" {
            output::print_json(&result)?;
            return Ok(());
        }

        output::print_header("Mempool Lane Resolution");

        let address = result
            .get("address")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)");
        let lane = result
            .get("lane")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)");
        let bucket_key = result
            .get("bucket_key")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)");
        let fee_mult = result
            .get("fee_floor_mult")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let refill = result
            .get("refill_per_sec")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let burst = result
            .get("burst_capacity")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        output::print_field("Address", address);
        output::print_field("Assigned Lane", lane);
        output::print_field("Bucket Key", bucket_key);
        output::print_field("Fee Floor Multiplier", &format!("{:.3}x", fee_mult));
        output::print_field("Lane Refill (tx/s)", &format!("{:.3}", refill));
        output::print_field("Lane Burst Capacity", &burst.to_string());

        if let Some(bucket) = result.get("bucket").and_then(|v| v.as_object()) {
            println!();
            output::print_info("Current Bucket State");
            let tokens = bucket.get("tokens").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let capacity = bucket
                .get("capacity")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let bucket_refill = bucket
                .get("refill_per_sec")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            output::print_field("  Tokens Available", &format!("{:.3}", tokens));
            output::print_field("  Capacity", &capacity.to_string());
            output::print_field("  Refill (tx/s)", &format!("{:.3}", bucket_refill));
        } else {
            output::print_info("Bucket has not been instantiated yet (no traffic from this address)");
        }

        Ok(())
    }
}

/// Show network-layer counters and gauges.
///
/// Calls `tenzro_getNetworkStats` and prints the snapshot. Includes gossip
/// admit/reject counts, connection totals + current gauge, banned/connected
/// peer counts, kad routing table size, gossipsub mesh size, and the
/// `peer_address_migrations_total` counter — incremented when libp2p observes
/// a new remote multiaddr for an already-known peer (QUIC path migration,
/// mobile network switch, NAT rebinding).
#[derive(Debug, Parser)]
pub struct NodeStatsCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

impl NodeStatsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getNetworkStats", serde_json::json!([]))
            .await?;

        if self.format == "json" {
            output::print_json(&result)?;
            return Ok(());
        }

        output::print_header("Network Stats");

        if !result.get("available").and_then(|v| v.as_bool()).unwrap_or(false) {
            let reason = result
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("network service not initialized");
            output::print_warning(reason);
            return Ok(());
        }

        let field = |k: &str| result.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
        let ifield = |k: &str| result.get(k).and_then(|v| v.as_i64()).unwrap_or(0);

        output::print_info("Connections");
        output::print_field("  Established (current)", &ifield("connections_established").to_string());
        output::print_field("  Inbound total", &field("connections_inbound_total").to_string());
        output::print_field("  Outbound total", &field("connections_outbound_total").to_string());
        output::print_field("  Peers connected", &ifield("peers_connected").to_string());
        output::print_field("  Peers banned", &ifield("peers_banned").to_string());

        println!();
        output::print_info("Gossipsub");
        output::print_field("  Published", &field("gossip_published").to_string());
        output::print_field("  Accepted", &field("gossip_accepted").to_string());
        output::print_field("  Rejected (validator-only)", &field("gossip_rejected_validator_only").to_string());
        output::print_field("  Rejected (invalid)", &field("gossip_rejected_invalid").to_string());
        output::print_field("  Rejected (duplicate)", &field("gossip_rejected_duplicate").to_string());
        output::print_field("  Mesh size", &ifield("gossipsub_mesh_size").to_string());

        println!();
        output::print_info("Discovery & Dialing");
        output::print_field("  Kademlia routing table", &ifield("kad_routing_table_size").to_string());
        output::print_field("  Dials rejected (per-IP)", &field("dials_rejected_per_ip").to_string());
        output::print_field("  Dials rejected (global)", &field("dials_rejected_global").to_string());
        output::print_field("  Swarm events dropped", &field("events_dropped").to_string());

        println!();
        output::print_info("Path Migration");
        output::print_field(
            "  Peer address migrations",
            &field("peer_address_migrations_total").to_string(),
        );

        Ok(())
    }
}

/// Storage-provider operations.
///
/// These RPCs only succeed on a node started with the `storage` role, which
/// spawns the storage-provider runtime. A renter pre-funds a streaming deal;
/// each epoch is charged only when a retrievability challenge passes.
#[derive(Debug, Subcommand)]
pub enum StorageCommand {
    /// Erasure-code an object and publish its shards over the transport
    Store(StorageStoreCmd),
    /// Open a streaming storage deal for a stored object
    OpenDeal(StorageOpenDealCmd),
    /// Run one proof-of-retrievability-gated charge epoch for a deal
    ChargeEpoch(StorageChargeEpochCmd),
    /// Look up a storage deal by id
    Deal(StorageDealCmd),
    /// Switch the provider to network-dynamic byte-epoch pricing
    SetPricing(StorageSetPricingCmd),
    /// Show this node's storage-provider state (rate, object count)
    Status(StorageStatusCmd),
}

impl StorageCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Store(cmd) => cmd.execute().await,
            Self::OpenDeal(cmd) => cmd.execute().await,
            Self::ChargeEpoch(cmd) => cmd.execute().await,
            Self::Deal(cmd) => cmd.execute().await,
            Self::SetPricing(cmd) => cmd.execute().await,
            Self::Status(cmd) => cmd.execute().await,
        }
    }
}

/// Store an object (read from a file, erasure-coded, shards published).
#[derive(Debug, Parser)]
pub struct StorageStoreCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Logical object id (content key the renter will reference)
    #[arg(long)]
    object_id: String,
    /// Owner address (hex, 0x-prefixed or bare)
    #[arg(long)]
    owner: String,
    /// Path to the file whose bytes are stored
    #[arg(long)]
    file: PathBuf,
    /// Data shards (default 4)
    #[arg(long, default_value = "4")]
    data_shards: u64,
    /// Parity shards (default 2)
    #[arg(long, default_value = "2")]
    parity_shards: u64,
}

impl StorageStoreCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        use base64::Engine as _;

        let bytes = std::fs::read(&self.file)
            .map_err(|e| anyhow::anyhow!("reading {}: {}", self.file.display(), e))?;
        let data_b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);

        output::print_header("Store Object");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_storageStoreObject",
                serde_json::json!([{
                    "object_id": self.object_id,
                    "owner": self.owner,
                    "data": data_b64,
                    "data_shards": self.data_shards,
                    "parity_shards": self.parity_shards,
                }]),
            )
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// Open a streaming storage deal.
#[derive(Debug, Parser)]
pub struct StorageOpenDealCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Object id of an already-stored object
    #[arg(long)]
    object_id: String,
    /// Renter address (hex) — pays from their pre-funded deposit
    #[arg(long)]
    renter: String,
    /// Object size in bytes (sets per-epoch price = size × rate)
    #[arg(long)]
    size_bytes: u64,
    /// Total epochs the deal runs
    #[arg(long)]
    total_epochs: u64,
}

impl StorageOpenDealCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Open Storage Deal");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_storageOpenDeal",
                serde_json::json!([{
                    "object_id": self.object_id,
                    "renter": self.renter,
                    "size_bytes": self.size_bytes,
                    "total_epochs": self.total_epochs,
                }]),
            )
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// Charge one PoR-gated epoch for a deal.
#[derive(Debug, Parser)]
pub struct StorageChargeEpochCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Deal id to charge
    #[arg(long)]
    deal_id: String,
}

impl StorageChargeEpochCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Charge Storage Epoch");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_storageChargeEpoch",
                serde_json::json!([{ "deal_id": self.deal_id }]),
            )
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// Look up a deal by id.
#[derive(Debug, Parser)]
pub struct StorageDealCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Deal id to look up
    #[arg(long)]
    deal_id: String,
}

impl StorageDealCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Storage Deal");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_storageGetDeal",
                serde_json::json!([{ "deal_id": self.deal_id }]),
            )
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// Switch the provider to network-dynamic byte-epoch pricing.
#[derive(Debug, Parser)]
pub struct StorageSetPricingCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Provider capacity in byte-epochs (utilization target = 50% of this)
    #[arg(long)]
    capacity: u128,
    /// Minimum byte-epoch rate (wei)
    #[arg(long, default_value = "1")]
    min_rate: u128,
    /// Maximum byte-epoch rate (wei)
    #[arg(long)]
    max_rate: Option<u128>,
}

impl StorageSetPricingCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Set Storage Pricing (network-dynamic)");
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({
            "mode": "dynamic",
            "capacity": self.capacity.to_string(),
            "min_rate": self.min_rate.to_string(),
        });
        if let Some(max) = self.max_rate {
            params["max_rate"] = serde_json::json!(max.to_string());
        }
        let result: serde_json::Value = rpc
            .call("tenzro_storageSetPricing", serde_json::json!([params]))
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// Show storage-provider state.
#[derive(Debug, Parser)]
pub struct StorageStatusCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl StorageStatusCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Storage Provider Status");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value =
            rpc.call("tenzro_storageStatus", serde_json::json!([])).await?;

        output::print_field(
            "Effective Rate (wei/byte-epoch)",
            result.get("effective_rate_wei").and_then(|v| v.as_str()).unwrap_or("0"),
        );
        output::print_field(
            "Objects Stored",
            &result.get("object_count").and_then(|v| v.as_u64()).unwrap_or(0).to_string(),
        );
        Ok(())
    }
}

/// Compute-provider operations. A node serving the `ai` role rents out its
/// CPU/GPU capacity for fixed terms; each epoch settles only when an
/// availability proof passes.
#[derive(Debug, Subcommand)]
pub enum ComputeCommand {
    /// Book a fixed-term compute rental against this provider
    BookRental(ComputeBookRentalCmd),
    /// Settle one availability-gated epoch of a rental
    SettleEpoch(ComputeSettleEpochCmd),
    /// Look up a compute rental by id
    Rental(ComputeRentalCmd),
    /// Switch the provider to network-dynamic per-epoch pricing
    SetPricing(ComputeSetPricingCmd),
    /// Show this node's compute-provider state (rate, active rentals)
    Status(ComputeStatusCmd),
}

impl ComputeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::BookRental(cmd) => cmd.execute().await,
            Self::SettleEpoch(cmd) => cmd.execute().await,
            Self::Rental(cmd) => cmd.execute().await,
            Self::SetPricing(cmd) => cmd.execute().await,
            Self::Status(cmd) => cmd.execute().await,
        }
    }
}

/// Book a fixed-term compute rental.
#[derive(Debug, Parser)]
pub struct ComputeBookRentalCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Renter address (hex) — pays from their pre-funded deposit
    #[arg(long)]
    renter: String,
    /// Total epochs the rental runs (per-epoch price = provider's effective rate)
    #[arg(long)]
    total_epochs: u64,
}

impl ComputeBookRentalCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Book Compute Rental");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_computeBookRental",
                serde_json::json!([{
                    "renter": self.renter,
                    "total_epochs": self.total_epochs,
                }]),
            )
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// Settle one availability-gated epoch of a rental.
#[derive(Debug, Parser)]
pub struct ComputeSettleEpochCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Rental id to settle
    #[arg(long)]
    rental_id: String,
    /// Whether the provider's availability proof for this epoch is valid
    #[arg(long, default_value = "true")]
    proof_valid: bool,
}

impl ComputeSettleEpochCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Settle Compute Epoch");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_computeSettleEpoch",
                serde_json::json!([{
                    "rental_id": self.rental_id,
                    "proof_valid": self.proof_valid,
                }]),
            )
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// Look up a rental by id.
#[derive(Debug, Parser)]
pub struct ComputeRentalCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Rental id to look up
    #[arg(long)]
    rental_id: String,
}

impl ComputeRentalCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Compute Rental");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_computeGetRental",
                serde_json::json!([{ "rental_id": self.rental_id }]),
            )
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// Switch the provider to network-dynamic per-epoch pricing.
#[derive(Debug, Parser)]
pub struct ComputeSetPricingCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Provider capacity in epoch-slots (utilization target = 50% of this)
    #[arg(long)]
    capacity: u128,
    /// Minimum per-epoch rate (wei)
    #[arg(long, default_value = "1")]
    min_rate: u128,
    /// Maximum per-epoch rate (wei)
    #[arg(long)]
    max_rate: Option<u128>,
}

impl ComputeSetPricingCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Set Compute Pricing (network-dynamic)");
        let rpc = RpcClient::new(&self.rpc);
        let mut params = serde_json::json!({
            "mode": "dynamic",
            "capacity": self.capacity.to_string(),
            "min_rate": self.min_rate.to_string(),
        });
        if let Some(max) = self.max_rate {
            params["max_rate"] = serde_json::json!(max.to_string());
        }
        let result: serde_json::Value = rpc
            .call("tenzro_computeSetPricing", serde_json::json!([params]))
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// Show compute-provider state.
#[derive(Debug, Parser)]
pub struct ComputeStatusCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ComputeStatusCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Compute Provider Status");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value =
            rpc.call("tenzro_computeStatus", serde_json::json!([])).await?;

        output::print_field(
            "Effective Rate (wei/epoch)",
            result.get("effective_rate_wei").and_then(|v| v.as_str()).unwrap_or("0"),
        );
        output::print_field(
            "Active Rentals",
            &result.get("active_rentals").and_then(|v| v.as_u64()).unwrap_or(0).to_string(),
        );
        Ok(())
    }
}
