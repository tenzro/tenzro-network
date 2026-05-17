//! Provider management commands for the Tenzro CLI

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output::{self};

/// Provider management commands
#[derive(Debug, Subcommand)]
pub enum ProviderCommand {
    /// Register as a provider
    Register(ProviderRegisterCmd),
    /// Show provider status
    Status(ProviderStatusCmd),
    /// List models being served
    Models(ProviderModelsCmd),
    /// List all providers discovered on the network
    List(ProviderListCmd),
    /// Provider pricing management
    #[command(subcommand)]
    Pricing(PricingCommand),
    /// Compute bond (admission collateral) management
    #[command(subcommand)]
    Bond(BondCommand),
}

impl ProviderCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Register(cmd) => cmd.execute().await,
            Self::Status(cmd) => cmd.execute().await,
            Self::Models(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Pricing(cmd) => cmd.execute().await,
            Self::Bond(cmd) => cmd.execute().await,
        }
    }
}

/// Compute bond (admission collateral) subcommands.
///
/// Providers must post a compute bond before they can register via
/// `tenzro provider register`. The bond is held in a deterministic vault
/// derived from the provider DID and is returnable after a 7-day cooldown.
#[derive(Debug, Subcommand)]
pub enum BondCommand {
    /// Post a new compute bond
    Post(BondPostCmd),
    /// Top up an existing bond
    Increase(BondIncreaseCmd),
    /// Get a single provider's bond state
    Get(BondGetCmd),
    /// List all compute bonds on the node
    List(BondListCmd),
    /// Initiate withdrawal (or finalize once cooldown elapses)
    Withdraw(BondWithdrawCmd),
}

impl BondCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Post(cmd) => cmd.execute().await,
            Self::Increase(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Withdraw(cmd) => cmd.execute().await,
        }
    }
}

fn print_compute_bond_state(state: &serde_json::Value) {
    if let Some(v) = state.get("provider_did").and_then(|v| v.as_str()) {
        output::print_field("Provider DID", v);
    }
    if let Some(v) = state.get("provider_address").and_then(|v| v.as_str()) {
        output::print_field("Provider Address", &output::format_address(v));
    }
    if let Some(v) = state.get("amount").and_then(|v| v.as_str()) {
        output::print_field("Amount (wei)", v);
    }
    if let Some(v) = state.get("status").and_then(|v| v.as_str()) {
        let active = v == "Active";
        output::print_status("Status", v, active);
    }
    if let Some(v) = state.get("cooldown_until").and_then(|v| v.as_u64()) {
        output::print_field("Cooldown Until (ms)", &v.to_string());
    }
    if let Some(v) = state.get("last_modified_block").and_then(|v| v.as_u64()) {
        output::print_field("Last Modified Block", &v.to_string());
    }
    if let Some(v) = state.get("effective_amount").and_then(|v| v.as_str()) {
        output::print_field("Effective for Registration", v);
    }
    if let Some(v) = state.get("is_eligible").and_then(|v| v.as_bool()) {
        output::print_field("Registration-Eligible", &v.to_string());
    }
}

#[derive(Debug, Parser)]
pub struct BondPostCmd {
    /// Provider DID (e.g. did:tenzro:machine:...)
    #[arg(long)]
    did: String,

    /// Provider wallet address (32-byte hex; with or without 0x)
    #[arg(long)]
    address: String,

    /// Bond amount in TNZO (decimal, e.g. "100" for 100 TNZO)
    #[arg(long)]
    amount: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BondPostCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Post Compute Bond");
        let amount_wei = crate::units::tnzo_to_wei_string(&self.amount)?;
        output::print_field("Provider DID", &self.did);
        output::print_field("Provider Address", &output::format_address(&self.address));
        output::print_field("Amount", &format!("{} TNZO ({} wei)", self.amount, amount_wei));
        println!();

        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Posting compute bond...");
        let state: serde_json::Value = rpc
            .call(
                "tenzro_postComputeBond",
                serde_json::json!([{
                    "provider_did": self.did,
                    "provider_address": self.address,
                    "amount": amount_wei,
                }]),
            )
            .await?;
        spinner.finish_and_clear();
        output::print_success("Compute bond posted");
        println!();
        print_compute_bond_state(&state);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct BondIncreaseCmd {
    /// Provider DID
    #[arg(long)]
    did: String,

    /// Additional amount in TNZO
    #[arg(long)]
    amount: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BondIncreaseCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Increase Compute Bond");
        let amount_wei = crate::units::tnzo_to_wei_string(&self.amount)?;
        output::print_field("Provider DID", &self.did);
        output::print_field("Top-up", &format!("{} TNZO ({} wei)", self.amount, amount_wei));
        println!();

        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Increasing compute bond...");
        let state: serde_json::Value = rpc
            .call(
                "tenzro_increaseComputeBond",
                serde_json::json!([{
                    "provider_did": self.did,
                    "amount": amount_wei,
                }]),
            )
            .await?;
        spinner.finish_and_clear();
        output::print_success("Compute bond increased");
        println!();
        print_compute_bond_state(&state);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct BondGetCmd {
    /// Provider DID
    #[arg(long)]
    did: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BondGetCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Compute Bond");
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Fetching compute bond...");
        let state: serde_json::Value = rpc
            .call(
                "tenzro_getComputeBond",
                serde_json::json!([{ "provider_did": self.did }]),
            )
            .await?;
        spinner.finish_and_clear();
        if state.is_null() {
            output::print_warning(&format!("No compute bond found for {}", self.did));
            return Ok(());
        }
        print_compute_bond_state(&state);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct BondListCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BondListCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Compute Bonds");
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Listing compute bonds...");
        let result: serde_json::Value = rpc
            .call("tenzro_listComputeBonds", serde_json::json!([]))
            .await?;
        spinner.finish_and_clear();
        let bonds = result
            .get("bonds")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if bonds.is_empty() {
            output::print_info("No compute bonds posted yet");
            return Ok(());
        }
        let headers = vec!["Provider DID", "Address", "Amount (wei)", "Status", "Eligible"];
        let mut rows = Vec::new();
        for b in &bonds {
            rows.push(vec![
                b.get("provider_did").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                output::format_address(b.get("provider_address").and_then(|v| v.as_str()).unwrap_or("")),
                b.get("amount").and_then(|v| v.as_str()).unwrap_or("0").to_string(),
                b.get("status").and_then(|v| v.as_str()).unwrap_or("?").to_string(),
                b.get("is_eligible").and_then(|v| v.as_bool()).unwrap_or(false).to_string(),
            ]);
        }
        output::print_table(&headers, &rows);
        println!();
        output::print_field("Total", &bonds.len().to_string());
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct BondWithdrawCmd {
    /// Provider DID
    #[arg(long)]
    did: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BondWithdrawCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Withdraw Compute Bond");
        output::print_info("Active → Cooldown initiates a 7-day unbonding window. Re-run after the cooldown elapses to finalize and reclaim funds.");
        println!();

        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Submitting withdrawal...");
        let state: serde_json::Value = rpc
            .call(
                "tenzro_withdrawComputeBond",
                serde_json::json!([{ "provider_did": self.did }]),
            )
            .await?;
        spinner.finish_and_clear();
        let status = state.get("status").and_then(|v| v.as_str()).unwrap_or("?");
        match status {
            "Cooldown" => output::print_success("Withdrawal initiated — bond is in 7-day cooldown"),
            "Returned" => output::print_success("Bond returned to provider"),
            other => output::print_warning(&format!("Unexpected post-withdraw status: {}", other)),
        }
        println!();
        print_compute_bond_state(&state);
        Ok(())
    }
}

/// Provider pricing management
#[derive(Debug, Subcommand)]
pub enum PricingCommand {
    /// Set provider pricing
    Set(PricingSetCmd),
    /// Show current pricing
    Show(PricingShowCmd),
}

impl PricingCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Set(cmd) => cmd.execute().await,
            Self::Show(cmd) => cmd.execute().await,
        }
    }
}

/// Register as a provider
#[derive(Debug, Parser)]
pub struct ProviderRegisterCmd {
    /// Provider type (inference, tee)
    #[arg(long)]
    r#type: String,

    /// Provider name
    #[arg(long)]
    name: Option<String>,

    /// Provider DID — must match a posted compute bond. Required for
    /// model-provider, tee-provider, and storage-provider types; ignored
    /// for validator type (validators are gated by self-stake instead).
    #[arg(long)]
    did: Option<String>,

    /// Stake amount (TNZO) — optional for model/inference providers, required for validators
    #[arg(long, default_value = "0")]
    stake: String,

    /// Maximum concurrent requests
    #[arg(long, default_value = "10")]
    max_concurrent: u32,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProviderRegisterCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Register as Provider");

        // Parse provider type
        let provider_type = match self.r#type.to_lowercase().as_str() {
            "inference" | "model" => "Inference Provider",
            "tee" | "trusted-execution" => "TEE Provider",
            _ => {
                return Err(anyhow::anyhow!(
                    "Invalid provider type: {}. Must be one of: inference, tee",
                    self.r#type
                ));
            }
        };

        // Show registration details
        println!();
        output::print_field("Provider Type", provider_type);

        if let Some(name) = &self.name {
            output::print_field("Provider Name", name);
        }

        let stake_val: f64 = self.stake.parse().unwrap_or(0.0);
        if stake_val > 0.0 {
            output::print_field("Stake Amount", &format!("{} TNZO", self.stake));
        }
        output::print_field("Max Concurrent", &format!("{} requests", self.max_concurrent));
        println!();

        // Confirm with user
        use dialoguer::Confirm;
        let confirmed = Confirm::new()
            .with_prompt("Register as provider?")
            .default(false)
            .interact()?;

        if !confirmed {
            output::print_warning("Registration cancelled");
            return Ok(());
        }

        let spinner = output::create_spinner("Registering provider...");

        let rpc = crate::rpc::RpcClient::new(&self.rpc);

        // The RPC takes the stake amount in **wei** (10^-18 TNZO).
        let stake_wei = if stake_val > 0.0 {
            crate::units::tnzo_to_wei_string(&self.stake)?
        } else {
            "0".to_string()
        };
        let result: serde_json::Value = rpc.call("tenzro_registerProvider", serde_json::json!([{
            "provider_type": self.r#type,
            "name": self.name.as_deref(),
            "provider_did": self.did.as_deref(),
            "stake": stake_wei,
            "max_concurrent": self.max_concurrent,
        }])).await?;

        spinner.finish_and_clear();

        output::print_success("Provider registered successfully!");
        println!();
        if let Some(v) = result.get("provider_id").and_then(|v| v.as_str()) {
            output::print_field("Provider ID", v);
        }
        if let Some(v) = result.get("transaction_hash").and_then(|v| v.as_str()) {
            output::print_field("Registration TX", v);
        }
        let status = result.get("status").and_then(|v| v.as_str()).unwrap_or("Pending verification");
        let is_active = status.to_lowercase().contains("active");
        output::print_status("Status", status, is_active);
        println!();
        output::print_info("Your provider will be active once the registration is verified.");

        Ok(())
    }
}

/// Show provider status
#[derive(Debug, Parser)]
pub struct ProviderStatusCmd {
    /// Provider address (optional, uses default wallet if not specified)
    #[arg(long)]
    address: Option<String>,

    /// Show detailed statistics
    #[arg(long)]
    detailed: bool,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProviderStatusCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Provider Status");

        let spinner = output::create_spinner("Fetching provider information...");

        let rpc = RpcClient::new(&self.rpc);

        // Fetch node info which includes provider status
        let node_info: serde_json::Value = rpc.call("tenzro_nodeInfo", serde_json::json!([])).await?;

        spinner.finish_and_clear();

        if let Some(addr) = &self.address {
            output::print_field("Address", &output::format_address(addr));
        }

        println!();

        if let Some(provider_id) = node_info.get("provider_id").and_then(|v| v.as_str()) {
            output::print_field("Provider ID", provider_id);
        }
        if let Some(role) = node_info.get("role").and_then(|v| v.as_str()) {
            output::print_field("Type", role);
        }
        if let Some(status) = node_info.get("status").and_then(|v| v.as_str()) {
            let is_active = status.contains("Active") || status.contains("Running");
            output::print_status("Status", status, is_active);
        } else {
            output::print_status("Status", "Active - accepting requests", true);
        }

        println!();

        if self.detailed {
            // Fetch detailed provider stats from node
            let stats: serde_json::Value = rpc.call("tenzro_providerStats", serde_json::json!([{
                "address": self.address.as_deref()
            }])).await.unwrap_or(serde_json::json!({}));

            println!();
            output::print_header("Performance Statistics");
            println!();
            if let Some(v) = stats.get("total_requests").and_then(|v| v.as_u64()) {
                output::print_field("Total Requests", &format!("{}", v));
            }
            if let Some(v) = stats.get("successful").and_then(|v| v.as_u64()) {
                let total = stats.get("total_requests").and_then(|v| v.as_u64()).unwrap_or(1);
                let pct = if total > 0 { (v as f64 / total as f64) * 100.0 } else { 0.0 };
                output::print_field("Successful", &format!("{} ({:.1}%)", v, pct));
            }
            if let Some(v) = stats.get("avg_latency").and_then(|v| v.as_str()) {
                output::print_field("Avg Latency", v);
            }
            if let Some(v) = stats.get("total_earnings").and_then(|v| v.as_str()) {
                output::print_field("Total Earnings", v);
            }
            if let Some(v) = stats.get("total_rewards").and_then(|v| v.as_str()) {
                output::print_field("Total Rewards", v);
            }

            println!();
            output::print_header("Capacity");
            println!();
            if let Some(v) = stats.get("max_concurrent").and_then(|v| v.as_u64()) {
                output::print_field("Max Concurrent", &format!("{} requests", v));
            }
            if let Some(v) = stats.get("current_active").and_then(|v| v.as_u64()) {
                output::print_field("Current Active", &format!("{} requests", v));
            }
            if let Some(v) = stats.get("utilization").and_then(|v| v.as_str()) {
                output::print_field("Utilization", v);
            }

            if let Some(activity) = stats.get("recent_activity").and_then(|v| v.as_array())
                && !activity.is_empty() {
                    println!();
                    output::print_header("Recent Activity");
                    let headers = vec!["Time", "Request ID", "Model", "Status", "Earned"];
                    let mut rows = Vec::new();
                    for item in activity {
                        rows.push(vec![
                            item.get("time").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            item.get("request_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            item.get("model").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            item.get("status").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            item.get("earned").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        ]);
                    }
                    output::print_table(&headers, &rows);
                }
        }

        Ok(())
    }
}

/// List models being served
#[derive(Debug, Parser)]
pub struct ProviderModelsCmd {
    /// Provider address (optional, uses default wallet if not specified)
    #[arg(long)]
    address: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProviderModelsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Served Models");

        let spinner = output::create_spinner("Fetching served models...");

        let rpc = RpcClient::new(&self.rpc);

        let models: Vec<serde_json::Value> = rpc.call("tenzro_listModels", serde_json::json!([{
            "provider": self.address.as_deref()
        }])).await?;

        spinner.finish_and_clear();

        if let Some(addr) = &self.address {
            output::print_field("Provider", &output::format_address(addr));
            println!();
        }

        if models.is_empty() {
            output::print_info("No models currently being served");
            return Ok(());
        }

        let headers = vec!["Model ID", "Name", "Status", "Requests", "Avg Price", "Earnings"];
        let mut rows = Vec::new();
        let mut active_count = 0u64;

        for model in &models {
            let status = model.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
            if status.to_lowercase().contains("active") {
                active_count += 1;
            }
            rows.push(vec![
                model.get("model_id").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                model.get("name").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                status.to_string(),
                model.get("requests").and_then(|v| v.as_u64()).unwrap_or(0).to_string(),
                model.get("avg_price").and_then(|v| v.as_str()).unwrap_or("N/A").to_string(),
                model.get("earnings").and_then(|v| v.as_str()).unwrap_or("0 TNZO").to_string(),
            ]);
        }
        output::print_table(&headers, &rows);

        println!();
        output::print_field("Total Models", &models.len().to_string());
        output::print_field("Active Models", &active_count.to_string());

        Ok(())
    }
}

/// Set provider pricing (wei per token; 1 TNZO = 10^18 wei)
#[derive(Debug, Parser)]
pub struct PricingSetCmd {
    /// Wei per input token (decimal string)
    #[arg(long = "input-price-wei")]
    pub input_price_wei: String,

    /// Wei per output token (decimal string)
    #[arg(long = "output-price-wei")]
    pub output_price_wei: String,

    /// Network ceiling for input price in wei (decimal string)
    #[arg(long = "network-max-input-wei", default_value = "1000000000000000")]
    pub network_max_input_wei: String,

    /// Network ceiling for output price in wei (decimal string)
    #[arg(long = "network-max-output-wei", default_value = "2000000000000000")]
    pub network_max_output_wei: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

impl PricingSetCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        use serde::Serialize;

        #[derive(Serialize)]
        struct ProviderPricing {
            input_price_per_token_wei: String,
            output_price_per_token_wei: String,
            network_max_input_wei: String,
            network_max_output_wei: String,
        }

        // Parse-validate: each field must be a non-negative u128 decimal string.
        let input_wei: u128 = self
            .input_price_wei
            .parse()
            .map_err(|_| anyhow::anyhow!("--input-price-wei must be a non-negative integer"))?;
        let output_wei: u128 = self
            .output_price_wei
            .parse()
            .map_err(|_| anyhow::anyhow!("--output-price-wei must be a non-negative integer"))?;
        let max_in_wei: u128 = self
            .network_max_input_wei
            .parse()
            .map_err(|_| anyhow::anyhow!("--network-max-input-wei must be a non-negative integer"))?;
        let max_out_wei: u128 = self.network_max_output_wei.parse().map_err(|_| {
            anyhow::anyhow!("--network-max-output-wei must be a non-negative integer")
        })?;

        output::print_header("Set Provider Pricing");
        println!();
        output::print_field("Input Price", &format!("{} wei/token", input_wei));
        output::print_field("Output Price", &format!("{} wei/token", output_wei));
        println!();

        let spinner = output::create_spinner("Updating pricing...");

        let pricing = ProviderPricing {
            input_price_per_token_wei: input_wei.to_string(),
            output_price_per_token_wei: output_wei.to_string(),
            network_max_input_wei: max_in_wei.to_string(),
            network_max_output_wei: max_out_wei.to_string(),
        };

        let rpc = RpcClient::new(&self.rpc);
        let _: serde_json::Value = rpc
            .call("tenzro_setProviderPricing", serde_json::json!([pricing]))
            .await?;

        spinner.finish_and_clear();
        output::print_success("Provider pricing updated successfully!");

        Ok(())
    }
}

/// Show current pricing
#[derive(Debug, Parser)]
pub struct PricingShowCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

impl PricingShowCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        use serde::Deserialize;

        #[derive(Deserialize)]
        struct ProviderPricing {
            input_price_per_token_wei: String,
            output_price_per_token_wei: String,
            network_max_input_wei: String,
            network_max_output_wei: String,
        }

        output::print_header("Provider Pricing");

        let spinner = output::create_spinner("Fetching pricing...");

        let rpc = RpcClient::new(&self.rpc);
        let pricing: ProviderPricing = rpc.call("tenzro_getProviderPricing", serde_json::json!([]))
            .await?;

        spinner.finish_and_clear();

        println!();
        output::print_field(
            "Input Price",
            &format!("{} wei/token", pricing.input_price_per_token_wei),
        );
        output::print_field(
            "Output Price",
            &format!("{} wei/token", pricing.output_price_per_token_wei),
        );
        println!();
        output::print_field(
            "Network Max Input",
            &format!("{} wei/token", pricing.network_max_input_wei),
        );
        output::print_field(
            "Network Max Output",
            &format!("{} wei/token", pricing.network_max_output_wei),
        );

        Ok(())
    }
}

/// List all providers discovered on the Tenzro Network
#[derive(Debug, Parser)]
pub struct ProviderListCmd {
    /// Filter by provider type (llm, tee, general)
    #[arg(long, name = "type")]
    provider_type: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProviderListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Network Providers");

        let spinner = output::create_spinner("Discovering network providers...");

        let rpc = RpcClient::new(&self.rpc);

        let params = if let Some(ref pt) = self.provider_type {
            serde_json::json!({ "provider_type": pt })
        } else {
            serde_json::json!({})
        };

        let providers: Vec<serde_json::Value> = rpc
            .call("tenzro_listProviders", params)
            .await?;

        spinner.finish_and_clear();

        if let Some(ref pt) = self.provider_type {
            output::print_field("Filter", &format!("type = {}", pt));
            println!();
        }

        if providers.is_empty() {
            output::print_info("No providers discovered on the network yet.");
            output::print_info("Providers broadcast announcements every 60s via gossipsub.");
            return Ok(());
        }

        let headers = vec!["Peer ID", "Address", "Type", "Models", "Capabilities", "Status", "Endpoint"];
        let mut rows = Vec::new();

        for p in &providers {
            let peer_id = p.get("peer_id").and_then(|v| v.as_str()).unwrap_or("unknown");
            let peer_id_short = if peer_id.len() > 16 {
                format!("{}...{}", &peer_id[..8], &peer_id[peer_id.len()-6..])
            } else {
                peer_id.to_string()
            };

            let address = p.get("provider_address").and_then(|v| v.as_str()).unwrap_or("");
            let addr_short = output::format_address(address);

            let provider_type = p.get("provider_type").and_then(|v| v.as_str()).unwrap_or("general");

            let models = p.get("served_models")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter()
                    .filter_map(|m| m.as_str())
                    .collect::<Vec<_>>()
                    .join(", "))
                .unwrap_or_default();

            let capabilities = p.get("capabilities")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter()
                    .filter_map(|m| m.as_str())
                    .collect::<Vec<_>>()
                    .join(", "))
                .unwrap_or_default();

            let status = p.get("status").and_then(|v| v.as_str()).unwrap_or("unknown");
            let is_local = p.get("is_local").and_then(|v| v.as_bool()).unwrap_or(false);
            let status_display = if is_local {
                format!("{} (local)", status)
            } else {
                status.to_string()
            };

            let endpoint = p.get("rpc_endpoint").and_then(|v| v.as_str()).unwrap_or("");

            rows.push(vec![
                peer_id_short,
                addr_short,
                provider_type.to_string(),
                models,
                capabilities,
                status_display,
                endpoint.to_string(),
            ]);
        }

        output::print_table(&headers, &rows);

        println!();
        output::print_field("Total Providers", &providers.len().to_string());
        let local_count = providers.iter()
            .filter(|p| p.get("is_local").and_then(|v| v.as_bool()).unwrap_or(false))
            .count();
        if local_count > 0 {
            output::print_field("Local Node", "included");
        }

        Ok(())
    }
}
