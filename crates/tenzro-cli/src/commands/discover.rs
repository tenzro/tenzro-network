//! Local-network discovery commands: mDNS local peers, this node's
//! reachability tier, and its hardware serving profile.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::{output, rpc};

#[derive(Debug, Subcommand)]
pub enum DiscoverCommand {
    /// List peers discovered on this node's local network segment
    LocalPeers(LocalPeersCmd),
    /// Show this node's sustained connectivity tier
    Reachability(ReachabilityCmd),
    /// Show this node's hardware serving profile
    Profile(ProfileCmd),
}

impl DiscoverCommand {
    pub async fn execute(self) -> Result<()> {
        match self {
            Self::LocalPeers(cmd) => cmd.execute().await,
            Self::Reachability(cmd) => cmd.execute().await,
            Self::Profile(cmd) => cmd.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct LocalPeersCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl LocalPeersCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Local Network Peers");
        let spinner = output::create_spinner("Querying local peer set...");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: Result<serde_json::Value> =
            rpc.call("tenzro_localPeers", serde_json::json!([])).await;
        spinner.finish_and_clear();

        match result {
            Ok(value) => {
                println!();
                let available = value.get("available").and_then(|v| v.as_bool()).unwrap_or(true);
                if !available {
                    output::print_info("Networking is not running; no local peer set available.");
                    return Ok(());
                }
                let count = value.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
                output::print_field("Local Peers", &count.to_string());
                if let Some(peers) = value.get("local_peers").and_then(|v| v.as_array()) {
                    for peer in peers {
                        if let Some(id) = peer.as_str() {
                            output::print_field("Peer", id);
                        }
                    }
                    if peers.is_empty() {
                        output::print_info("No peers discovered on the local segment yet.");
                    }
                }
            }
            Err(e) => output::print_error(&format!("Failed to query local peers: {}", e)),
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ReachabilityCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ReachabilityCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Node Reachability");
        let spinner = output::create_spinner("Querying reachability tier...");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: Result<serde_json::Value> =
            rpc.call("tenzro_nodeReachability", serde_json::json!([])).await;
        spinner.finish_and_clear();

        match result {
            Ok(value) => {
                println!();
                let available = value.get("available").and_then(|v| v.as_bool()).unwrap_or(true);
                if !available {
                    output::print_info("Networking is not running; reachability tier is unknown.");
                    return Ok(());
                }
                let tier = value.get("tier").and_then(|v| v.as_str()).unwrap_or("unknown");
                output::print_field("Tier", tier);
            }
            Err(e) => output::print_error(&format!("Failed to query reachability: {}", e)),
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ProfileCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProfileCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Node Serving Profile");
        let spinner = output::create_spinner("Detecting hardware profile...");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: Result<serde_json::Value> =
            rpc.call("tenzro_nodeProfile", serde_json::json!([])).await;
        spinner.finish_and_clear();

        match result {
            Ok(value) => {
                println!();
                if let Some(v) = value.get("llama_commit").and_then(|v| v.as_str()) {
                    output::print_field("llama.cpp Commit", v);
                }
                if let Some(v) = value.get("cpu_arch").and_then(|v| v.as_str()) {
                    output::print_field("CPU Architecture", v);
                }
                if let Some(v) = value.get("os").and_then(|v| v.as_str()) {
                    output::print_field("OS", v);
                }
                if let Some(v) = value.get("serving_vram_gb").and_then(|v| v.as_f64()) {
                    output::print_field("Serving Capacity", &format!("{:.2} GB", v));
                }
                if let Some(v) = value.get("serving_backend") {
                    output::print_field("Serving Backend", v.to_string().trim_matches('"'));
                }
                if let Some(v) = value.get("serving_cap_key").and_then(|v| v.as_str()) {
                    output::print_field("Capability Key", v);
                }
                if let Some(devices) = value.get("devices").and_then(|v| v.as_array()) {
                    println!();
                    output::print_field("Devices", &devices.len().to_string());
                    for dev in devices {
                        let desc = dev.get("description").and_then(|v| v.as_str()).unwrap_or("?");
                        let backend = dev.get("backend").map(|v| v.to_string()).unwrap_or_default();
                        let backend = backend.trim_matches('"');
                        output::print_field("Device", &format!("{} [{}]", desc, backend));
                    }
                }
            }
            Err(e) => output::print_error(&format!("Failed to query node profile: {}", e)),
        }
        Ok(())
    }
}
