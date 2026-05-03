//! Join command for one-click participation in Tenzro Network.
//!
//! Calls the node's `tenzro_joinAsMicroNode` RPC to provision a TDIP identity,
//! MPC wallet, and full network capabilities as a zero-install MicroNode.
//! Falls back to `tenzro_participate` for nodes that don't yet support MicroNode.

use clap::Parser;
use anyhow::Result;
use crate::config;
use crate::output;
use crate::rpc::RpcClient;

/// Join the Tenzro Network as a MicroNode participant.
///
/// Zero-install — no P2P binary required.
/// Auto-provisions a TDIP DID, MPC wallet, and full network capabilities.
#[derive(Debug, Parser)]
pub struct JoinCmd {
    /// RPC endpoint
    #[arg(long, default_value = "https://rpc.tenzro.network")]
    pub rpc: String,

    /// Display name
    #[arg(long, default_value = "Tenzro User")]
    pub name: String,

    /// Origin hint (e.g. "cli", "sdk", "app", "mcp", "a2a")
    #[arg(long, default_value = "cli")]
    pub origin: String,

    /// Participant type: human, agent, or bot
    #[arg(long, default_value = "human")]
    pub r#type: String,
}

impl JoinCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Join Tenzro Network");

        println!();
        output::print_field("Endpoint", &self.rpc);
        output::print_field("Display Name", &self.name);
        output::print_field("Type", &self.r#type);
        output::print_field("Origin", &self.origin);
        println!();

        // Step 1: Verify endpoint is reachable
        let spinner = output::create_spinner("Connecting to network...");

        let rpc = RpcClient::new(&self.rpc);
        let chain_id_hex: String = rpc.call("eth_chainId", serde_json::json!([]))
            .await
            .map_err(|e| anyhow::anyhow!("Cannot connect to {}: {}", self.rpc, e))?;
        let chain_id = crate::rpc::parse_hex_u64(&chain_id_hex);

        spinner.finish_and_clear();
        output::print_success(&format!("Connected to network (Chain ID: {})", chain_id));

        let clean_name = self.name.trim_start_matches('@').to_string();

        // Step 2: Try tenzro_joinAsMicroNode first, fall back to tenzro_participate
        let spinner = output::create_spinner("Provisioning MicroNode identity and wallet...");

        let (result, is_micro_node) = match rpc.call::<serde_json::Value>("tenzro_joinAsMicroNode", serde_json::json!([{
            "display_name": clean_name,
            "origin": self.origin,
            "participant_type": self.r#type,
        }])).await {
            Ok(r) => {
                spinner.finish_and_clear();
                output::print_success("MicroNode provisioned on Tenzro Network");
                (r, true)
            }
            Err(_) => {
                // Fall back to legacy tenzro_participate
                let r: serde_json::Value = rpc.call("tenzro_participate", serde_json::json!([{
                    "display_name": clean_name
                }]))
                .await
                .map_err(|e| anyhow::anyhow!("Failed to join network: {}", e))?;
                spinner.finish_and_clear();
                output::print_success("Identity and wallet provisioned on Tenzro Ledger");
                (r, false)
            }
        };

        // Extract identity from RPC response
        let identity = result.get("identity").cloned().unwrap_or_default();
        let did = identity.get("did").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        let display_name = identity.get("display_name").and_then(|v| v.as_str()).unwrap_or(&clean_name).to_string();
        let identity_type = identity.get("identity_type").and_then(|v| v.as_str()).unwrap_or(&self.r#type).to_string();

        // Extract wallet from RPC response
        let wallet = result.get("wallet").cloned().unwrap_or_default();
        let wallet_id = wallet.get("wallet_id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();
        let wallet_address = wallet.get("address").and_then(|v| v.as_str()).unwrap_or("unknown").to_string();

        // Display identity
        println!();
        output::print_header("Identity");
        println!();
        output::print_field("DID", &did);
        output::print_field("Display Name", &display_name);
        output::print_field("Type", &identity_type);
        output::print_field("Role", result.get("role").and_then(|v| v.as_str()).unwrap_or("MicroNode"));
        output::print_field("Status", identity.get("status").and_then(|v| v.as_str()).unwrap_or("active"));

        // Display wallet
        println!();
        output::print_header("Wallet (MPC)");
        println!();
        output::print_field("Wallet ID", &wallet_id);
        output::print_field("Address", &wallet_address);
        if let Some(pk) = wallet.get("public_key").and_then(|v| v.as_str()) {
            if !pk.is_empty() {
                let truncated = if pk.len() > 20 { format!("{}...", &pk[..20]) } else { pk.to_string() };
                output::print_field("Public Key", &truncated);
            }
        }

        // Display MicroNode capabilities (only when joinAsMicroNode is supported)
        if is_micro_node {
            if let Some(caps) = result.get("capabilities") {
                println!();
                output::print_header("Network Capabilities");
                println!();
                let cap_names = [
                    ("inference",          "AI Model Inference"),
                    ("payments",           "TNZO Payments"),
                    ("agent_collaboration","Agent Collaboration (A2A)"),
                    ("mcp_tools",          "MCP Tools (24 tools)"),
                    ("task_execution",     "Task Marketplace"),
                    ("chain_query",        "Chain State Queries"),
                    ("smart_contracts",    "Smart Contracts (EVM/SVM/DAML)"),
                    ("tee_services",       "TEE Confidential Compute"),
                    ("bridge",             "Cross-Chain Bridge"),
                    ("governance",         "Governance & Voting"),
                ];
                for (key, label) in &cap_names {
                    let enabled = caps.get(key).and_then(|v| v.as_bool()).unwrap_or(false);
                    let status = if enabled { "enabled" } else { "disabled" };
                    output::print_field(label, status);
                }
            }

            if let Some(network) = result.get("network") {
                println!();
                output::print_header("Network Endpoints");
                println!();
                if let Some(rpc_url) = network.get("rpc").and_then(|v| v.as_str()) {
                    output::print_field("JSON-RPC", rpc_url);
                }
                if let Some(mcp_url) = network.get("mcp").and_then(|v| v.as_str()) {
                    output::print_field("MCP Server", mcp_url);
                }
                if let Some(a2a_url) = network.get("a2a").and_then(|v| v.as_str()) {
                    output::print_field("A2A Protocol", a2a_url);
                }
            }

            if let Some(msg) = result.get("message").and_then(|v| v.as_str()) {
                println!();
                output::print_info(msg);
            }
        } else {
            // Legacy: show hardware profile from tenzro_participate response
            let hardware = result.get("hardware").cloned().unwrap_or_default();
            if !hardware.is_null() {
                println!();
                output::print_header("Hardware Profile");
                println!();
                if let Some(cpu) = hardware.get("cpu_model").and_then(|v| v.as_str()) {
                    let cores = hardware.get("cpu_cores").and_then(|v| v.as_u64()).unwrap_or(0);
                    let threads = hardware.get("cpu_threads").and_then(|v| v.as_u64()).unwrap_or(0);
                    output::print_field("CPU", &format!("{} ({} cores, {} threads)", cpu, cores, threads));
                }
                if let Some(ram) = hardware.get("total_ram_gb").and_then(|v| v.as_f64()) {
                    output::print_field("RAM", &format!("{:.1} GB", ram));
                }
                if let Some(gpus) = hardware.get("gpus").and_then(|v| v.as_array()) {
                    if gpus.is_empty() {
                        output::print_field("GPUs", "None detected");
                    } else {
                        for (i, gpu) in gpus.iter().enumerate() {
                            let name = gpu.get("name").and_then(|v| v.as_str()).unwrap_or("Unknown");
                            let mem = gpu.get("memory_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
                            output::print_field(&format!("GPU {}", i + 1), &format!("{} ({:.1} GB)", name, mem));
                        }
                    }
                }
            }
        }

        // `tenzro_participate` provisions the identity + wallet + hardware
        // profile. To acquire an authenticated bearer, call one of
        // `tenzro_onboardHuman` / `tenzro_onboardDelegatedAgent` /
        // `tenzro_onboardAutonomousAgent` — each returns an OAuth 2.1 +
        // DPoP-bound JWT. Export the result as `TENZRO_BEARER_JWT` +
        // `TENZRO_DPOP_PROOF` for subsequent privileged calls.
        println!();
        output::print_info(
            "Run `tenzro auth onboard-human` to mint a DPoP-bound JWT for this identity, then export TENZRO_BEARER_JWT + TENZRO_DPOP_PROOF for privileged calls.",
        );

        let spinner = output::create_spinner("Saving configuration...");

        let mut cfg = config::load_config();
        cfg.endpoint = Some(self.rpc.clone());
        cfg.wallet_id = Some(wallet_id);
        cfg.wallet_address = Some(wallet_address);
        cfg.did = Some(did);
        cfg.display_name = Some(display_name.clone());
        if !display_name.is_empty() {
            cfg.username = Some(display_name);
        }
        cfg.role = Some(if is_micro_node { "micro-node".to_string() } else { self.r#type.clone() });

        config::save_config(&cfg)?;

        spinner.finish_and_clear();

        output::print_success(&format!("Configuration saved to: {}", config::config_path().display()));

        println!();
        output::print_success("You are now part of the Tenzro Network!");
        output::print_info(&format!("Chain ID: {}", chain_id));

        Ok(())
    }
}
