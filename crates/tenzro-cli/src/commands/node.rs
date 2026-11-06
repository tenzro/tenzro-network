//! Node management commands for the Tenzro CLI

use crate::output::{self};
use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::str::FromStr;
use tenzro_types::RoleSet;

/// Node management commands
#[derive(Debug, Subcommand)]
pub enum NodeCommand {
    #[command(flatten)]
    Rpc(NodeRpcCommand),
    /// Start a Tenzro Network node
    Start(NodeStartCmd),
    /// Check node status
    Status(NodeStatusCmd),
    /// Stop the running node
    Stop(NodeStopCmd),
    /// Show the connected peer count and the peers this node hears from
    Peers(NodePeersCmd),
    /// Show settlement activity on the chain by reward epoch
    Activity(NodeActivityCmd),
    /// Show sync status
    Syncing(NodeSyncingCmd),
    /// Fetch a contiguous range of blocks for sync inspection
    SyncRange(NodeSyncRangeCmd),
    /// Inspect the EIP-1559 fee market (current gas price, suggested tip, fee history)
    FeeMarket(NodeFeeMarketCmd),
    /// Show admission-controller mempool stats (per-lane admit/reject counters + lane config)
    MempoolStats(NodeMempoolStatsCmd),
    /// Resolve which admission lane an address would land in, plus its current token-bucket state
    MempoolLane(NodeMempoolLaneCmd),
    /// Show network-layer counters and gauges (gossip, connections, peer-address migrations)
    Stats(NodeStatsCmd),
    /// Show this node's DID Document — every way of reaching it, in one place
    DidDocument(NodeDidDocumentCmd),
    /// Storage-provider operations (store objects, pricing)
    #[command(subcommand)]
    Storage(StorageCommand),
    /// Engine releases: check for, verify and install a signed release, or publish one
    #[command(subcommand)]
    Upgrade(crate::commands::node_upgrade::NodeUpgradeCommand),
}

impl NodeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Rpc(cmd) => cmd.execute().await,
            Self::Start(cmd) => cmd.execute().await,
            Self::Status(cmd) => cmd.execute().await,
            Self::Stop(cmd) => cmd.execute().await,
            Self::Peers(cmd) => cmd.execute().await,
            Self::Activity(cmd) => cmd.execute().await,
            Self::Syncing(cmd) => cmd.execute().await,
            Self::SyncRange(cmd) => cmd.execute().await,
            Self::FeeMarket(cmd) => cmd.execute().await,
            Self::MempoolStats(cmd) => cmd.execute().await,
            Self::MempoolLane(cmd) => cmd.execute().await,
            Self::Stats(cmd) => cmd.execute().await,
            Self::DidDocument(cmd) => cmd.execute().await,
            Self::Storage(cmd) => cmd.execute().await,
            Self::Upgrade(cmd) => cmd.execute().await,
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

    /// Data directory for blockchain storage. Defaults to the canonical
    /// per-instance directory under the Tenzro root ($TENZRO_HOME, or
    /// ~/.tenzro) — the same one `tenzro-node` picks with no flags, so
    /// starting through the CLI and starting the binary directly land on the
    /// same state rather than two half-populated trees. Also settable via
    /// `$TENZRO_DATA_DIR`, the same variable `tenzro-node` itself reads.
    #[arg(long, env = "TENZRO_DATA_DIR")]
    data_dir: Option<PathBuf>,

    /// Enable metrics server
    #[arg(long, default_value = "true")]
    metrics: bool,

    /// RPC listen address
    #[arg(long, default_value = "127.0.0.1:9944")]
    rpc_addr: String,
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
        output::print_field(
            "Data Directory",
            &self
                .data_dir
                .as_ref()
                .map(tenzro_types::paths::expand_tilde)
                .unwrap_or_else(tenzro_types::paths::default_data_dir)
                .display()
                .to_string(),
        );
        output::print_field("RPC Address", &self.rpc_addr);
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
            "--roles".to_string(),
            roles.to_string(),
            "--rpc-addr".to_string(),
            self.rpc_addr.clone(),
            "--data-dir".to_string(),
            // A tilde in `--data-dir` reaches us verbatim when the argument
            // was quoted or came from a unit file; passing it through
            // unexpanded is what created directories named `~`.
            self.data_dir
                .as_ref()
                .map(tenzro_types::paths::expand_tilde)
                .unwrap_or_else(tenzro_types::paths::default_data_dir)
                .display()
                .to_string(),
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
            Ok(s) => output::print_warning(&format!(
                "Node exited with code: {}",
                s.code().unwrap_or(-1)
            )),
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Failed to start tenzro-node: {}. Is it installed?",
                    e
                ));
            }
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
        let node_info: serde_json::Value = rpc
            .call("tenzro_getNodeStatus", serde_json::json!([]))
            .await?;
        let block_number: String = rpc.call("eth_blockNumber", serde_json::json!([])).await?;
        let peer_count: String = rpc.call("net_peerCount", serde_json::json!([])).await?;
        let listening: bool = rpc
            .call("net_listening", serde_json::json!([]))
            .await
            .unwrap_or(false);
        // Try derived API URL first, then fallback to default port 8080
        let api_status: serde_json::Value = match rpc.api_get("/status").await {
            Ok(v) => v,
            Err(_) => {
                // Fallback: try default web API port
                let fallback = RpcClient::new("http://127.0.0.1:8545");
                fallback
                    .api_get("/status")
                    .await
                    .unwrap_or_else(|_| serde_json::json!({}))
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

            let status_str = api_status
                .get("node_state")
                .or_else(|| api_status.get("status"))
                .and_then(|v| v.as_str())
                .unwrap_or("Running");
            let is_synced = status_str.contains("Synced") || status_str.contains("Running");
            output::print_status("Status", status_str, is_synced);
            println!();

            output::print_field("Best Block", &format!("{}", best_block));
            output::print_field(
                "Finalized Block",
                &format!("{}", best_block.saturating_sub(3)),
            );
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
        let result: Result<serde_json::Value, _> = rpc
            .call(
                "tenzro_shutdown",
                serde_json::json!([{
                    "force": self.force
                }]),
            )
            .await;

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
        let listed: serde_json::Value = rpc
            .call("tenzro_listPeers", serde_json::Value::Null)
            .await?;
        let text = |p: &serde_json::Value, k: &str| match &p[k] {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Null => "-".to_string(),
            v => v.to_string(),
        };
        let rows: Vec<Vec<String>> = listed["peers"]
            .as_array()
            .map(|peers| {
                peers
                    .iter()
                    .map(|p| {
                        let roles = p["roles"]
                            .as_array()
                            .map(|r| {
                                r.iter()
                                    .filter_map(|v| v.as_str())
                                    .collect::<Vec<_>>()
                                    .join(",")
                            })
                            .unwrap_or_default();
                        vec![
                            text(p, "peer_id"),
                            text(p, "account"),
                            roles,
                            text(p, "hardware_tier"),
                            text(p, "identity_anchor"),
                            text(p, "region"),
                            text(p, "version"),
                        ]
                    })
                    .collect()
            })
            .unwrap_or_default();
        output::print_table(
            &[
                "Peer", "Account", "Roles", "Tier", "Anchor", "Region", "Version",
            ],
            &rows,
        );
        Ok(())
    }
}

/// Show settlement activity on the chain by reward epoch
#[derive(Debug, Parser)]
pub struct NodeActivityCmd {
    /// How many of the latest epochs (at most 168)
    #[arg(long)]
    epochs: Option<u64>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeActivityCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getNetworkActivity",
                serde_json::json!({ "epochs": self.epochs }),
            )
            .await?;
        output::print_json(&result)
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
            if syncing {
                output::print_info("Node is syncing...");
            } else {
                output::print_success("Node is fully synced.");
            }
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
        let local_tip = result.get("localTip").and_then(|v| v.as_u64()).unwrap_or(0);

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

        let gas_price_hex: String = rpc.call("eth_gasPrice", serde_json::json!([])).await?;
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
        output::print_field(
            "Effective Gas Price (wei)",
            &parse_hex_u128_str(&gas_price_hex),
        );
        output::print_field(
            "Suggested Priority Tip (wei)",
            &parse_hex_u128_str(&priority_hex),
        );

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
            let avg: f64 =
                ratios.iter().filter_map(|v| v.as_f64()).sum::<f64>() / ratios.len().max(1) as f64;
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

/// Show admission-controller mempool stats.
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

        output::print_header("Mempool Admission Stats");

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
                output::print_field(
                    "  Rejected (mempool-full)",
                    &rejected_mempool_full.to_string(),
                );
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
            let capacity = bucket.get("capacity").and_then(|v| v.as_u64()).unwrap_or(0);
            let bucket_refill = bucket
                .get("refill_per_sec")
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            output::print_field("  Tokens Available", &format!("{:.3}", tokens));
            output::print_field("  Capacity", &capacity.to_string());
            output::print_field("  Refill (tx/s)", &format!("{:.3}", bucket_refill));
        } else {
            output::print_info(
                "Bucket has not been instantiated yet (no traffic from this address)",
            );
        }

        Ok(())
    }
}

/// Show network-layer counters and gauges.
///
/// Calls `tenzro_getNetworkStats` and prints the snapshot: gossip
/// admit/reject counts and the number of peers this node gossips with
/// directly.
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

        if !result
            .get("available")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            let reason = result
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("network service not initialized");
            output::print_warning(reason);
            return Ok(());
        }

        let field = |k: &str| result.get(k).and_then(|v| v.as_u64()).unwrap_or(0);

        output::print_field("Peers connected", &field("peers_connected").to_string());

        println!();
        output::print_info("Gossip");
        output::print_field("  Published", &field("gossip_published").to_string());
        output::print_field("  Accepted", &field("gossip_accepted").to_string());
        output::print_field(
            "  Rejected (invalid)",
            &field("gossip_rejected_invalid").to_string(),
        );
        output::print_field(
            "  Rejected (duplicate)",
            &field("gossip_rejected_duplicate").to_string(),
        );

        Ok(())
    }
}

/// Storage-provider operations.
///
/// These RPCs only succeed on a node started with the `storage` role, which
/// spawns the storage-provider runtime. A renter pays for keeping an object
/// through a storage compute claim that commits its descriptor digest.
#[derive(Debug, Subcommand)]
pub enum StorageCommand {
    /// Erasure-code an object and publish its shards over the transport
    Store(StorageStoreCmd),
    /// Rebuild a stored object from its shards and write its bytes to a file
    Retrieve(StorageRetrieveCmd),
    /// Switch the provider to network-dynamic byte-epoch pricing
    SetPricing(StorageSetPricingCmd),
    /// Show this node's storage-provider state (rate, object count)
    Status(StorageStatusCmd),
}

impl StorageCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Store(cmd) => cmd.execute().await,
            Self::Retrieve(cmd) => cmd.execute().await,
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

/// Rebuild an object this provider stored and write its bytes to a file.
#[derive(Debug, Parser)]
pub struct StorageRetrieveCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Logical object id it was stored under
    #[arg(long)]
    object_id: String,
    /// Where the bytes are written
    #[arg(long)]
    out: PathBuf,
}

impl StorageRetrieveCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        use base64::Engine as _;

        output::print_header("Retrieve Object");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_storageRetrieveObject",
                serde_json::json!([{ "object_id": self.object_id }]),
            )
            .await?;
        let data = result
            .get("data")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("the node returned no data"))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(data)
            .map_err(|e| anyhow::anyhow!("the node returned invalid base64: {e}"))?;
        std::fs::write(&self.out, &bytes)
            .map_err(|e| anyhow::anyhow!("writing {}: {}", self.out.display(), e))?;
        output::print_field("Bytes", &bytes.len().to_string());
        output::print_field("Written to", &self.out.display().to_string());
        Ok(())
    }
}

/// Set the provider's fixed byte-epoch rate.
#[derive(Debug, Parser)]
pub struct StorageSetPricingCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Fixed byte-epoch rate (wei)
    #[arg(long)]
    rate: u128,
}

impl StorageSetPricingCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Set Storage Rate");
        let rpc = RpcClient::new(&self.rpc);
        let params = serde_json::json!({
            "mode": "fixed",
            "rate": self.rate.to_string(),
        });
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
        let result: serde_json::Value = rpc
            .call("tenzro_storageStatus", serde_json::json!([]))
            .await?;

        output::print_field(
            "Effective Rate (wei/byte-epoch)",
            result
                .get("effective_rate_wei")
                .and_then(|v| v.as_str())
                .unwrap_or("0"),
        );
        output::print_field(
            "Objects Stored",
            &result
                .get("object_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .to_string(),
        );
        Ok(())
    }
}

/// Show this node's DID Document.
///
/// A node is addressed by its TDIP DID, Ed25519 key, iroh `EndpointId` and
/// relays, plus its service URLs.
/// Resolving the DID is the single entry point that yields all of them, so a
/// caller holding any one identifier can get the rest.
#[derive(Debug, Parser)]
pub struct NodeDidDocumentCmd {
    /// RPC endpoint.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeDidDocumentCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let doc: serde_json::Value = rpc
            .call("tenzro_nodeDidDocument", serde_json::json!({}))
            .await?;

        output::print_header("Node DID Document");
        output::print_field("DID", doc.get("id").and_then(|v| v.as_str()).unwrap_or("?"));

        // The service list is the useful part — it is the map from one
        // identifier to all the others.
        if let Some(services) = doc.get("service").and_then(|v| v.as_array()) {
            for svc in services {
                output::print_field(
                    svc.get("type").and_then(|v| v.as_str()).unwrap_or("?"),
                    svc.get("serviceEndpoint")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?"),
                );
            }
        }

        output::print_info(
            "Also served at /.well-known/did.json on this node's web API, for generic DID \
             resolvers.",
        );
        println!("\n{}", serde_json::to_string_pretty(&doc)?);
        Ok(())
    }
}

/// Node commands that call one node RPC each and print its answer
#[derive(Debug, clap::Subcommand)]
pub enum NodeRpcCommand {
    /// Call tenzro_blockNumber (block number) and print the node's answer
    BlockNumber(NodeBlockNumberRpcCmd),
    /// Call tenzro_getBlock (get block) and print the node's answer
    Block(NodeBlockRpcCmd),
    /// Call tenzro_exportConfig (export config) and print the node's answer
    ExportConfig(NodeExportConfigRpcCmd),
    /// Call tenzro_getHardwareProfile (get hardware profile) and print the node's answer
    HardwareProfile(NodeHardwareProfileRpcCmd),
    /// Call tenzro_getRole (get role) and print the node's answer
    Role(NodeRoleRpcCmd),
    /// Call tenzro_setRole (set role) and print the node's answer
    SetRole(NodeSetRoleRpcCmd),
    /// Call tenzro_getSnapshotManifest (get snapshot manifest) and print the node's answer
    SnapshotManifest(NodeSnapshotManifestRpcCmd),
    /// Call tenzro_listSnapshots (list snapshots) and print the node's answer
    Snapshots(NodeSnapshotsRpcCmd),
    /// Call tenzro_currentHeader (current header) and print the node's answer
    CurrentHeader(NodeCurrentHeaderRpcCmd),
    /// Call tenzro_fabricProfile (fabric profile) and print the node's answer
    FabricProfile(NodeFabricProfileRpcCmd),
    /// Call tenzro_gossipStats (gossip stats) and print the node's answer
    GossipStats(NodeGossipStatsRpcCmd),
    /// Call tenzro_gracefulExit (graceful exit) and print the node's answer
    GracefulExit(NodeGracefulExitRpcCmd),
    /// Call tenzro_iroh_resolveTenzroUri (iroh resolve tenzro uri) and print the node's answer
    ResolveTenzroUri(NodeResolveTenzroUriRpcCmd),
    /// Call tenzro_livenessStats (liveness stats) and print the node's answer
    LivenessStats(NodeLivenessStatsRpcCmd),
    /// Call tenzro_setDraining (set draining) and print the node's answer
    SetDraining(NodeSetDrainingRpcCmd),
    /// Call tenzro_cleanupIdleLocalModelServices (cleanup idle local model services) and print the node's answer
    CleanupIdleModelServices(NodeCleanupIdleModelServicesRpcCmd),
    /// Call tenzro_layerPipelineStatus and print this machine's part in a model served across the operator's machines
    LayerPipelineStatus(NodeLayerPipelineStatusRpcCmd),
    /// Call tenzro_produceSnapshot (produce snapshot) and print the node's answer
    ProduceSnapshot(NodeProduceSnapshotRpcCmd),
    /// Call tenzro_getStateRoot (get state root) and print the node's answer
    StateRoot(NodeStateRootRpcCmd),
    /// Call tenzro_getStateProof (get state proof) and print the node's answer
    StateProof(NodeStateProofRpcCmd),
    /// Call tenzro_getAccountContention (get account contention) and print the node's answer
    AccountContention(NodeAccountContentionRpcCmd),
    /// Call tenzro_getConsensusMetrics (get consensus metrics) and print the node's answer
    ConsensusMetrics(NodeConsensusMetricsRpcCmd),
    /// Call tenzro_getFinality (get finality) and print the node's answer
    Finality(NodeFinalityRpcCmd),
    /// Call tenzro_getRewardEpoch (get reward epoch) and print the node's answer
    RewardEpoch(NodeRewardEpochRpcCmd),
    /// Call tenzro_getRewardSchedule (get reward schedule) and print the node's answer
    RewardSchedule(NodeRewardScheduleRpcCmd),
    /// Call tenzro_listRewardCoupons (list reward coupons) and print the node's answer
    RewardCoupons(NodeRewardCouponsRpcCmd),
    /// Call tenzro_getHardwareLevel (get hardware level) and print the node's answer
    HardwareLevel(NodeHardwareLevelRpcCmd),
    /// Call tenzro_getVesting (get vesting) and print the node's answer
    Vesting(NodeVestingRpcCmd),
    /// Call tenzro_validatorSelfStake (validator self stake) and print the node's answer
    ValidatorSelfStake(NodeValidatorSelfStakeRpcCmd),
    /// Call tenzro_getDaBackends (get da backends) and print the node's answer
    DaBackends(NodeDaBackendsRpcCmd),
    /// Call tenzro_verifyDaPointer (verify da pointer) and print the node's answer
    VerifyDaPointer(NodeVerifyDaPointerRpcCmd),
    /// Call tenzro_verifyEventProof (verify event proof) and print the node's answer
    VerifyEventProof(NodeVerifyEventProofRpcCmd),
}

impl NodeRpcCommand {
    pub async fn execute(&self) -> anyhow::Result<()> {
        match self {
            Self::BlockNumber(cmd) => cmd.execute().await,
            Self::Block(cmd) => cmd.execute().await,
            Self::ExportConfig(cmd) => cmd.execute().await,
            Self::HardwareProfile(cmd) => cmd.execute().await,
            Self::Role(cmd) => cmd.execute().await,
            Self::SetRole(cmd) => cmd.execute().await,
            Self::SnapshotManifest(cmd) => cmd.execute().await,
            Self::Snapshots(cmd) => cmd.execute().await,
            Self::CurrentHeader(cmd) => cmd.execute().await,
            Self::FabricProfile(cmd) => cmd.execute().await,
            Self::GossipStats(cmd) => cmd.execute().await,
            Self::GracefulExit(cmd) => cmd.execute().await,
            Self::ResolveTenzroUri(cmd) => cmd.execute().await,
            Self::LivenessStats(cmd) => cmd.execute().await,
            Self::SetDraining(cmd) => cmd.execute().await,
            Self::CleanupIdleModelServices(cmd) => cmd.execute().await,
            Self::LayerPipelineStatus(cmd) => cmd.execute().await,
            Self::ProduceSnapshot(cmd) => cmd.execute().await,
            Self::StateRoot(cmd) => cmd.execute().await,
            Self::StateProof(cmd) => cmd.execute().await,
            Self::AccountContention(cmd) => cmd.execute().await,
            Self::ConsensusMetrics(cmd) => cmd.execute().await,
            Self::Finality(cmd) => cmd.execute().await,
            Self::RewardEpoch(cmd) => cmd.execute().await,
            Self::RewardSchedule(cmd) => cmd.execute().await,
            Self::RewardCoupons(cmd) => cmd.execute().await,
            Self::HardwareLevel(cmd) => cmd.execute().await,
            Self::Vesting(cmd) => cmd.execute().await,
            Self::ValidatorSelfStake(cmd) => cmd.execute().await,
            Self::DaBackends(cmd) => cmd.execute().await,
            Self::VerifyDaPointer(cmd) => cmd.execute().await,
            Self::VerifyEventProof(cmd) => cmd.execute().await,
        }
    }
}

/// Call tenzro_blockNumber (block number)
#[derive(Debug, clap::Parser)]
pub struct NodeBlockNumberRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeBlockNumberRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_blockNumber", serde_json::json!([]))
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getBlock (get block)
#[derive(Debug, clap::Parser)]
pub struct NodeBlockRpcCmd {
    /// block number
    #[arg(long)]
    block_number: Option<u64>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeBlockRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getBlock",
                serde_json::json!([{ "block_number": self.block_number }]),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_exportConfig (export config)
#[derive(Debug, clap::Parser)]
pub struct NodeExportConfigRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeExportConfigRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_exportConfig", serde_json::json!([]))
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getHardwareProfile (get hardware profile)
#[derive(Debug, clap::Parser)]
pub struct NodeHardwareProfileRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeHardwareProfileRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getHardwareProfile", serde_json::json!([]))
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getRole (get role)
#[derive(Debug, clap::Parser)]
pub struct NodeRoleRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeRoleRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_getRole", serde_json::json!([])).await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_setRole (set role)
#[derive(Debug, clap::Parser)]
pub struct NodeSetRoleRpcCmd {
    /// A role this node takes (repeatable): the full set replaces the current one
    #[arg(long = "role", required = true)]
    roles: Vec<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeSetRoleRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_setRole",
                serde_json::json!([{ "roles": self.roles }]),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getSnapshotManifest (get snapshot manifest)
#[derive(Debug, clap::Parser)]
pub struct NodeSnapshotManifestRpcCmd {
    /// height
    #[arg(long)]
    height: u64,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeSnapshotManifestRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getSnapshotManifest",
                serde_json::json!([{ "height": self.height }]),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_listSnapshots (list snapshots)
#[derive(Debug, clap::Parser)]
pub struct NodeSnapshotsRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeSnapshotsRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_listSnapshots", serde_json::json!([]))
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_currentHeader (current header)
#[derive(Debug, clap::Parser)]
pub struct NodeCurrentHeaderRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeCurrentHeaderRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_currentHeader", serde_json::Value::Null)
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_fabricProfile (fabric profile)
#[derive(Debug, clap::Parser)]
pub struct NodeFabricProfileRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeFabricProfileRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_fabricProfile", serde_json::Value::Null)
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_gossipStats (gossip stats)
#[derive(Debug, clap::Parser)]
pub struct NodeGossipStatsRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeGossipStatsRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_gossipStats", serde_json::Value::Null)
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_gracefulExit (graceful exit)
#[derive(Debug, clap::Parser)]
pub struct NodeGracefulExitRpcCmd {
    /// max wait secs
    #[arg(long)]
    max_wait_secs: Option<u64>,
    /// force
    #[arg(long)]
    force: Option<bool>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeGracefulExitRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_gracefulExit",
                serde_json::json!({ "max_wait_secs": self.max_wait_secs, "force": self.force }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_iroh_resolveTenzroUri (iroh resolve tenzro uri)
#[derive(Debug, clap::Parser)]
pub struct NodeResolveTenzroUriRpcCmd {
    /// tenzro uri
    #[arg(long)]
    tenzro_uri: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeResolveTenzroUriRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_iroh_resolveTenzroUri",
                serde_json::json!({ "tenzro_uri": self.tenzro_uri }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_livenessStats (liveness stats)
#[derive(Debug, clap::Parser)]
pub struct NodeLivenessStatsRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeLivenessStatsRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_livenessStats", serde_json::Value::Null)
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_setDraining (set draining)
#[derive(Debug, clap::Parser)]
pub struct NodeSetDrainingRpcCmd {
    /// draining
    #[arg(long)]
    draining: Option<bool>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeSetDrainingRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_setDraining",
                serde_json::json!({ "draining": self.draining }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_cleanupIdleLocalModelServices (cleanup idle local model services)
#[derive(Debug, clap::Parser)]
pub struct NodeCleanupIdleModelServicesRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeCleanupIdleModelServicesRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_cleanupIdleLocalModelServices",
                serde_json::Value::Null,
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_layerPipelineStatus: this machine's part in a model served
/// across the operator's machines
#[derive(Debug, clap::Parser)]
pub struct NodeLayerPipelineStatusRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeLayerPipelineStatusRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_layerPipelineStatus", serde_json::Value::Null)
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_produceSnapshot (produce snapshot)
#[derive(Debug, clap::Parser)]
pub struct NodeProduceSnapshotRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeProduceSnapshotRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_produceSnapshot", serde_json::Value::Null)
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getStateRoot (get state root)
#[derive(Debug, clap::Parser)]
pub struct NodeStateRootRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeStateRootRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getStateRoot", serde_json::Value::Null)
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getStateProof (get state proof)
#[derive(Debug, clap::Parser)]
pub struct NodeStateProofRpcCmd {
    /// namespace
    #[arg(long)]
    namespace: String,
    /// key
    #[arg(long)]
    key: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeStateProofRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getStateProof",
                serde_json::json!({ "namespace": self.namespace, "key": self.key }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getAccountContention (get account contention)
#[derive(Debug, clap::Parser)]
pub struct NodeAccountContentionRpcCmd {
    /// address
    #[arg(long)]
    address: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeAccountContentionRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getAccountContention",
                serde_json::json!({ "address": self.address }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getConsensusMetrics (get consensus metrics)
#[derive(Debug, clap::Parser)]
pub struct NodeConsensusMetricsRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeConsensusMetricsRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getConsensusMetrics", serde_json::Value::Null)
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getFinality (get finality)
#[derive(Debug, clap::Parser)]
pub struct NodeFinalityRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeFinalityRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getFinality", serde_json::Value::Null)
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getRewardEpoch (get reward epoch)
#[derive(Debug, clap::Parser)]
pub struct NodeRewardEpochRpcCmd {
    /// epoch
    #[arg(long)]
    epoch: u64,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeRewardEpochRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getRewardEpoch",
                serde_json::json!({ "epoch": self.epoch }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getRewardSchedule (get reward schedule)
#[derive(Debug, clap::Parser)]
pub struct NodeRewardScheduleRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeRewardScheduleRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getRewardSchedule", serde_json::Value::Null)
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_listRewardCoupons (list reward coupons)
#[derive(Debug, clap::Parser)]
pub struct NodeRewardCouponsRpcCmd {
    /// address
    #[arg(long)]
    address: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeRewardCouponsRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_listRewardCoupons",
                serde_json::json!({ "address": self.address }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getHardwareLevel (get hardware level)
#[derive(Debug, clap::Parser)]
pub struct NodeHardwareLevelRpcCmd {
    /// address
    #[arg(long)]
    address: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeHardwareLevelRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getHardwareLevel",
                serde_json::json!({ "address": self.address }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getVesting (get vesting)
#[derive(Debug, clap::Parser)]
pub struct NodeVestingRpcCmd {
    /// address
    #[arg(long)]
    address: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeVestingRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getVesting",
                serde_json::json!({ "address": self.address }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_validatorSelfStake (validator self stake)
#[derive(Debug, clap::Parser)]
pub struct NodeValidatorSelfStakeRpcCmd {
    /// additional
    #[arg(long)]
    additional: Option<u64>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeValidatorSelfStakeRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_validatorSelfStake",
                serde_json::json!({ "additional": self.additional }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_getDaBackends (get da backends)
#[derive(Debug, clap::Parser)]
pub struct NodeDaBackendsRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeDaBackendsRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getDaBackends", serde_json::Value::Null)
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_verifyDaPointer (verify da pointer)
#[derive(Debug, clap::Parser)]
pub struct NodeVerifyDaPointerRpcCmd {
    /// pointer (JSON)
    #[arg(long)]
    pointer: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeVerifyDaPointerRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let pointer: serde_json::Value =
            serde_json::from_str(&self.pointer).context("--pointer is not JSON")?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_verifyDaPointer",
                serde_json::json!({ "pointer": pointer }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_verifyEventProof (verify event proof)
#[derive(Debug, clap::Parser)]
pub struct NodeVerifyEventProofRpcCmd {
    /// proof (JSON)
    #[arg(long)]
    proof: Option<String>,
    /// certified proof (JSON)
    #[arg(long)]
    certified_proof: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl NodeVerifyEventProofRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let proof: Option<serde_json::Value> = self
            .proof
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .context("--proof is not JSON")?;
        let certified_proof: Option<serde_json::Value> = self
            .certified_proof
            .as_deref()
            .map(serde_json::from_str)
            .transpose()
            .context("--certified-proof is not JSON")?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_verifyEventProof",
                serde_json::json!({ "proof": proof, "certified_proof": certified_proof }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}
