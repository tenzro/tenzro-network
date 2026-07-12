//! Join command for one-click participation in Tenzro Network.
//!
//! Calls the node's `tenzro_joinAsMicroNode` RPC to provision a TDIP identity,
//! MPC wallet, and full network capabilities as a zero-install MicroNode.
//! Falls back to `tenzro_participate` for nodes that don't yet support MicroNode.
//!
//! With `--provider`, continues past identity provisioning into the full
//! provider path against the local node: hardware detection, testnet funding,
//! compute bond, provider registration, default pricing, automatic model
//! selection + download + serving, and TEE detection where hardware exists.

use clap::Parser;
use anyhow::Result;
use crate::config;
use crate::output;
use crate::rpc::RpcClient;

/// Join the Tenzro Network as a MicroNode participant.
///
/// Zero-install — no P2P binary required.
/// Auto-provisions a TDIP DID, MPC wallet, and full network capabilities.
/// Pass `--provider` on a machine running `tenzro-node` to also become
/// an inference provider in the same command.
#[derive(Debug, Parser)]
pub struct JoinCmd {
    /// RPC endpoint. Defaults to https://rpc.tenzro.xyz, or to the
    /// local node (http://127.0.0.1:8545) when --provider is set.
    #[arg(long)]
    pub rpc: Option<String>,

    /// Display name
    #[arg(long, default_value = "Tenzro User")]
    pub name: String,

    /// Origin hint (e.g. "cli", "sdk", "app", "mcp", "a2a")
    #[arg(long, default_value = "cli")]
    pub origin: String,

    /// Participant type: human, agent, or bot
    #[arg(long, default_value = "human")]
    pub r#type: String,

    /// Also become an inference provider: detect hardware, post the
    /// compute bond, register, set default pricing, and pull + serve the
    /// largest catalog model that fits this machine. Requires a running
    /// local tenzro-node (or --rpc pointing at your node).
    #[arg(long)]
    pub provider: bool,
}

impl JoinCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc_url = self.rpc.clone().unwrap_or_else(|| {
            if self.provider {
                "http://127.0.0.1:8545".to_string()
            } else {
                "https://rpc.tenzro.xyz".to_string()
            }
        });

        output::print_header("Join Tenzro Network");

        println!();
        output::print_field("Endpoint", &rpc_url);
        output::print_field("Display Name", &self.name);
        output::print_field("Type", &self.r#type);
        output::print_field("Origin", &self.origin);
        if self.provider {
            output::print_field("Mode", "provider");
        }
        println!();

        // Step 1: Verify endpoint is reachable
        let spinner = output::create_spinner("Connecting to network...");

        let rpc = RpcClient::new(&rpc_url);
        let chain_id_hex: String = rpc.call("eth_chainId", serde_json::json!([]))
            .await
            .map_err(|e| {
                if self.provider && self.rpc.is_none() {
                    anyhow::anyhow!(
                        "Cannot connect to your local node at {}: {}\n\
                         Provider mode registers on your own node. Start it first:\n\
                         \n    tenzro-node --role model-provider\n\
                         \nor point at a node you operate with --rpc <url>.",
                        rpc_url, e
                    )
                } else {
                    anyhow::anyhow!("Cannot connect to {}: {}", rpc_url, e)
                }
            })?;
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
        if let Some(pk) = wallet.get("public_key").and_then(|v| v.as_str())
            && !pk.is_empty() {
                let truncated = if pk.len() > 20 { format!("{}...", &pk[..20]) } else { pk.to_string() };
                output::print_field("Public Key", &truncated);
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

        // Provider path: hardware detection → funding → compute bond →
        // registration → default pricing → model pull + serve → TEE check.
        let provider_result = if self.provider {
            Some(run_provider_flow(&rpc, &did, &wallet_address, &clean_name).await?)
        } else {
            None
        };

        let spinner = output::create_spinner("Saving configuration...");

        let mut cfg = config::load_config();
        cfg.endpoint = Some(rpc_url.clone());
        cfg.wallet_id = Some(wallet_id);
        cfg.wallet_address = Some(wallet_address);
        cfg.did = Some(did);
        cfg.display_name = Some(display_name.clone());
        if !display_name.is_empty() {
            cfg.username = Some(display_name);
        }
        cfg.role = Some(if self.provider {
            "provider".to_string()
        } else if is_micro_node {
            "micro-node".to_string()
        } else {
            self.r#type.clone()
        });
        if let Some((pricing, served_model)) = provider_result {
            cfg.pricing = Some(pricing);
            if let Some(model_id) = served_model
                && !cfg.served_models.contains(&model_id) {
                    cfg.served_models.push(model_id);
                }
        }

        config::save_config(&cfg)?;

        spinner.finish_and_clear();

        output::print_success(&format!("Configuration saved to: {}", config::config_path().display()));

        println!();
        if self.provider {
            output::print_success("You are now a Tenzro Network provider!");
            output::print_info("Your node advertises its capacity on the provider gossip topic; inference demand routes to you automatically and settles in TNZO.");
        } else {
            output::print_success("You are now part of the Tenzro Network!");
        }
        output::print_info(&format!("Chain ID: {}", chain_id));

        Ok(())
    }
}

/// Minimum compute bond: 100 TNZO in wei (matches the node's
/// `DEFAULT_COMPUTE_BOND_MIN`).
const COMPUTE_BOND_MIN_WEI: u128 = 100 * 1_000_000_000_000_000_000u128;

/// Automatic provider provisioning against the node at `rpc`.
///
/// Returns the pricing that was set on the node plus the model id that
/// ended up being served (None when no catalog model fits the hardware).
async fn run_provider_flow(
    rpc: &RpcClient,
    did: &str,
    wallet_address: &str,
    name: &str,
) -> Result<(config::ProviderPricing, Option<String>)> {
    println!();
    output::print_header("Provider Setup");
    println!();

    // 1. Hardware detection (local, no RPC).
    let spinner = output::create_spinner("Detecting hardware...");
    let hw = crate::commands::hardware::detect_hardware_profile().await;
    spinner.finish_and_clear();

    output::print_field("CPU", &format!("{} ({} cores, {} threads)", hw.cpu_model, hw.cpu_cores, hw.cpu_threads));
    output::print_field("RAM", &format!("{:.1} GB{}", hw.total_ram_gb, if hw.unified_memory { " (unified)" } else { "" }));
    if hw.gpus.is_empty() {
        output::print_field("GPU", "None detected (CPU inference)");
    } else {
        for (i, gpu) in hw.gpus.iter().enumerate() {
            output::print_field(&format!("GPU {}", i + 1), &format!("{} ({:.1} GB)", gpu.name, gpu.memory_gb));
        }
    }
    output::print_field("TEE", if hw.tee_available {
        hw.tee_type.as_deref().unwrap_or("available")
    } else {
        "not available"
    });

    // Memory budget for model selection: discrete GPU VRAM when present,
    // otherwise a conservative share of system RAM (covers unified-memory
    // machines and CPU-only inference).
    let gpu_vram = hw.gpus.iter().map(|g| g.memory_gb).fold(0.0_f64, f64::max);
    let budget_gb = if gpu_vram > 0.0 && !hw.unified_memory {
        gpu_vram
    } else {
        hw.total_ram_gb * 0.7
    };
    let max_concurrent: u32 = if gpu_vram > 0.0 { 4 } else { 2 };
    output::print_field("Model memory budget", &format!("{:.1} GB", budget_gb));
    println!();

    // 2. Funding: the compute bond needs at least 100 TNZO. On testnet the
    // faucet grants a starter allotment, so a fresh wallet self-funds.
    let spinner = output::create_spinner("Checking wallet balance...");
    let mut balance_wei = get_balance_wei(rpc, wallet_address).await;
    if balance_wei < COMPUTE_BOND_MIN_WEI {
        spinner.set_message("Requesting testnet TNZO from faucet...");
        match rpc.call::<serde_json::Value>("tenzro_faucet", serde_json::json!({
            "address": wallet_address,
        })).await {
            Ok(_) => {
                balance_wei = get_balance_wei(rpc, wallet_address).await;
            }
            Err(e) => {
                spinner.finish_and_clear();
                output::print_warning(&format!("Faucet request failed: {}", e));
            }
        }
    }
    spinner.finish_and_clear();
    output::print_field("Balance", &crate::rpc::format_tnzo(balance_wei));
    if balance_wei < COMPUTE_BOND_MIN_WEI {
        anyhow::bail!(
            "Wallet {} holds less than the 100 TNZO compute bond minimum. \
             Fund it and re-run `tenzro join --provider`.",
            wallet_address
        );
    }

    // 3. Compute bond (skip when one is already posted for this DID).
    let existing_bond: serde_json::Value = rpc
        .call("tenzro_getComputeBond", serde_json::json!([{ "provider_did": did }]))
        .await
        .unwrap_or(serde_json::Value::Null);
    if existing_bond.is_null() {
        let spinner = output::create_spinner("Posting compute bond (100 TNZO)...");
        rpc.call::<serde_json::Value>("tenzro_postComputeBond", serde_json::json!([{
            "provider_did": did,
            "provider_address": wallet_address,
            "amount": COMPUTE_BOND_MIN_WEI.to_string(),
        }])).await
            .map_err(|e| anyhow::anyhow!("Compute bond failed: {}", e))?;
        spinner.finish_and_clear();
        output::print_success("Compute bond posted (100 TNZO)");
    } else {
        output::print_success("Compute bond already posted for this DID");
    }

    // 4. Provider registration. The node advertises registered capacity on
    // the provider gossip topic automatically — no separate publish step.
    let spinner = output::create_spinner("Registering as model provider...");
    let reg: serde_json::Value = rpc.call("tenzro_registerProvider", serde_json::json!([{
        "provider_type": "model-provider",
        "name": name,
        "provider_did": did,
        "max_concurrent": max_concurrent,
    }])).await
        .map_err(|e| anyhow::anyhow!("Provider registration failed: {}", e))?;
    spinner.finish_and_clear();
    output::print_success("Registered as model provider");
    if let Some(pid) = reg.get("provider_id").and_then(|v| v.as_str()) {
        output::print_field("Provider ID", pid);
    }

    // 5. Default pricing (the node's own defaults, made explicit and saved
    // locally so `tenzro provider pricing show` matches).
    let pricing = config::ProviderPricing {
        input_price_per_token_wei: "100000000000000".to_string(),
        output_price_per_token_wei: "200000000000000".to_string(),
        network_max_input_wei: "1000000000000000".to_string(),
        network_max_output_wei: "2000000000000000".to_string(),
    };
    let spinner = output::create_spinner("Setting default pricing...");
    rpc.call::<serde_json::Value>("tenzro_setProviderPricing", serde_json::json!([pricing]))
        .await
        .map_err(|e| anyhow::anyhow!("Setting pricing failed: {}", e))?;
    spinner.finish_and_clear();
    output::print_success("Pricing set: 0.0001 TNZO/input token, 0.0002 TNZO/output token");

    // 6. Model selection: largest catalog model that fits the memory
    // budget, preferring one that is already downloaded.
    let models: Vec<serde_json::Value> = rpc
        .call("tenzro_listModels", serde_json::json!({}))
        .await
        .map_err(|e| anyhow::anyhow!("Listing models failed: {}", e))?;

    let mut best: Option<(&serde_json::Value, bool, u64)> = None;
    for m in &models {
        let min_ram = m.get("min_ram_gb").and_then(|v| v.as_u64()).unwrap_or(u64::MAX);
        if (min_ram as f64) > budget_gb {
            continue;
        }
        let downloaded = m.get("downloaded").and_then(|v| v.as_bool()).unwrap_or(false);
        let size = m.get("size_bytes").and_then(|v| v.as_u64()).unwrap_or(0);
        let better = match &best {
            None => true,
            Some((_, best_dl, best_size)) => (downloaded, size) > (*best_dl, *best_size),
        };
        if better {
            best = Some((m, downloaded, size));
        }
    }

    let Some((model, downloaded, size)) = best else {
        output::print_warning(&format!(
            "No catalog model fits within {:.1} GB — provider is registered but not serving. \
             Serve one manually with `tenzro model serve <model-id> --rpc {}`.",
            budget_gb, rpc.url()
        ));
        return Ok((pricing, None));
    };
    let model_id = model.get("id").and_then(|v| v.as_str()).unwrap_or_default().to_string();
    let model_name = model.get("name").and_then(|v| v.as_str()).unwrap_or(&model_id);
    output::print_field("Selected model", &format!("{} ({:.1} GB)", model_name, size as f64 / 1e9));

    // 7. Download on the node (async on the node side; poll listModels
    // for per-model download_status until it completes).
    if !downloaded {
        rpc.call::<serde_json::Value>("tenzro_downloadModel", serde_json::json!({
            "model_id": model_id,
        })).await
            .map_err(|e| anyhow::anyhow!("Download request failed: {}", e))?;

        let spinner = output::create_spinner(&format!("Downloading {} on node...", model_id));
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let models: Vec<serde_json::Value> = match rpc
                .call("tenzro_listModels", serde_json::json!({}))
                .await
            {
                Ok(m) => m,
                Err(_) => continue,
            };
            let Some(entry) = models.iter().find(|m| {
                m.get("id").and_then(|v| v.as_str()) == Some(model_id.as_str())
            }) else {
                continue;
            };
            let status = entry.get("download_status").and_then(|v| v.as_str()).unwrap_or("unknown");
            match status {
                "completed" => break,
                "failed" => {
                    spinner.finish_and_clear();
                    anyhow::bail!("Model download failed on node — check the node logs and re-run `tenzro join --provider`.");
                }
                _ => {
                    let pct = entry.get("download_progress").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    spinner.set_message(format!("Downloading {} on node... {:.0}%", model_id, pct));
                }
            }
        }
        spinner.finish_and_clear();
        output::print_success(&format!("Model {} downloaded", model_id));
    }

    // 8. Serve on the network.
    let spinner = output::create_spinner(&format!("Serving {} to the network...", model_id));
    let serve: serde_json::Value = rpc.call("tenzro_serveModel", serde_json::json!({
        "model_id": model_id,
        "user_forced": false,
        "force_single": false,
        "visibility": "network",
    })).await
        .map_err(|e| anyhow::anyhow!("Serve request failed: {}", e))?;
    spinner.finish_and_clear();
    output::print_success(&format!("Model {} is serving on the network", model_id));
    if let Some(ep) = serve.get("api_endpoint").and_then(|v| v.as_str()) {
        output::print_field("API Endpoint", ep);
    }

    // 9. TEE detection on the node — attestation enrollment is node-side;
    // report what the node sees so the operator knows the confidential
    // tier is (or is not) in play.
    if hw.tee_available {
        match rpc.call::<serde_json::Value>("tenzro_detectTee", serde_json::json!([])).await {
            Ok(tee) => {
                let available = tee.get("available").and_then(|v| v.as_bool()).unwrap_or(false);
                if available {
                    let vendor = tee.get("vendor").and_then(|v| v.as_str()).unwrap_or("unknown");
                    output::print_success(&format!("TEE detected on node: {} — attestation is announced with your capacity", vendor));
                } else {
                    output::print_info("TEE hardware detected locally but not visible to the node — confidential-tier serving stays off until the node runs on the TEE host.");
                }
            }
            Err(e) => output::print_warning(&format!("TEE detection on node failed: {}", e)),
        }
    }

    Ok((pricing, Some(model_id)))
}

async fn get_balance_wei(rpc: &RpcClient, address: &str) -> u128 {
    match rpc.call::<serde_json::Value>("eth_getBalance", serde_json::json!([address, "latest"])).await {
        Ok(v) => {
            let hex = v.as_str().unwrap_or("0x0");
            u128::from_str_radix(hex.trim_start_matches("0x"), 16).unwrap_or(0)
        }
        Err(_) => 0,
    }
}
