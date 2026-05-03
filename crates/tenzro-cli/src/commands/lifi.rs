//! LI.FI cross-chain aggregator commands for the Tenzro CLI
//!
//! Direct REST integration with the LI.FI API (li.quest/v1) for
//! multi-bridge cross-chain routing, token discovery, gas prices,
//! and transfer status tracking.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

const LIFI_API_BASE: &str = "https://li.quest/v1";

/// LI.FI cross-chain aggregator commands
#[derive(Debug, Subcommand)]
pub enum LifiCommand {
    /// List supported chains
    Chains(LifiChainsCmd),
    /// List available tokens (optionally filter by chain)
    Tokens(LifiTokensCmd),
    /// List available bridge/DEX tools
    Tools(LifiToolsCmd),
    /// Get a cross-chain swap quote
    Quote(LifiQuoteCmd),
    /// Find advanced cross-chain routes
    Routes(LifiRoutesCmd),
    /// Check transfer status by transaction hash
    Status(LifiStatusCmd),
    /// Get gas prices for chains
    Gas(LifiGasCmd),
    /// Get available connections between two chains
    Connections(LifiConnectionsCmd),
}

impl LifiCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Chains(cmd) => cmd.execute().await,
            Self::Tokens(cmd) => cmd.execute().await,
            Self::Tools(cmd) => cmd.execute().await,
            Self::Quote(cmd) => cmd.execute().await,
            Self::Routes(cmd) => cmd.execute().await,
            Self::Status(cmd) => cmd.execute().await,
            Self::Gas(cmd) => cmd.execute().await,
            Self::Connections(cmd) => cmd.execute().await,
        }
    }
}

/// Helper to build a reqwest client with common headers
fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .user_agent("tenzro-cli/0.1.0")
        .build()?)
}

// ---------------------------------------------------------------------------
// Chains
// ---------------------------------------------------------------------------

/// List all blockchain networks supported by LI.FI
#[derive(Debug, Parser)]
pub struct LifiChainsCmd;

impl LifiChainsCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("LI.FI Supported Chains");
        let spinner = output::create_spinner("Fetching chains...");

        let client = http_client()?;
        let resp: serde_json::Value = client
            .get(format!("{LIFI_API_BASE}/chains"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        spinner.finish_and_clear();

        if let Some(chains) = resp.get("chains").and_then(|v| v.as_array()) {
            output::print_field("Total Chains", &chains.len().to_string());
            println!();
            for chain in chains {
                let id = chain.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                let name = chain.get("name").and_then(|v| v.as_str()).unwrap_or("unknown");
                let key = chain.get("key").and_then(|v| v.as_str()).unwrap_or("");
                let native = chain.get("nativeToken")
                    .and_then(|t| t.get("symbol"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("");
                println!("  {:>8}  {:<24} {:<16} native: {}", id, name, key, native);
            }
        } else {
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------

/// List available tokens on LI.FI (optionally filter by chain IDs)
#[derive(Debug, Parser)]
pub struct LifiTokensCmd {
    /// Comma-separated chain IDs to filter (e.g. "1,137,42161")
    #[arg(long)]
    chains: Option<String>,
}

impl LifiTokensCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("LI.FI Tokens");
        let spinner = output::create_spinner("Fetching tokens...");

        let client = http_client()?;
        let mut url = format!("{LIFI_API_BASE}/tokens");
        if let Some(ref chains) = self.chains {
            url = format!("{url}?chains={chains}");
        }

        let resp: serde_json::Value = client
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        spinner.finish_and_clear();

        if let Some(tokens_map) = resp.get("tokens").and_then(|v| v.as_object()) {
            for (chain_id, tokens) in tokens_map {
                let count = tokens.as_array().map(|a| a.len()).unwrap_or(0);
                println!("  Chain {}: {} tokens", chain_id, count);
                if let Some(arr) = tokens.as_array() {
                    for token in arr.iter().take(10) {
                        let symbol = token.get("symbol").and_then(|v| v.as_str()).unwrap_or("?");
                        let name = token.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        let addr = token.get("address").and_then(|v| v.as_str()).unwrap_or("");
                        let decimals = token.get("decimals").and_then(|v| v.as_u64()).unwrap_or(0);
                        println!("    {:<10} {:<30} dec={} {}", symbol, name, decimals, addr);
                    }
                    if arr.len() > 10 {
                        println!("    ... and {} more", arr.len() - 10);
                    }
                }
            }
        } else {
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tools
// ---------------------------------------------------------------------------

/// List available bridge and DEX tools on LI.FI
#[derive(Debug, Parser)]
pub struct LifiToolsCmd;

impl LifiToolsCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("LI.FI Bridge & DEX Tools");
        let spinner = output::create_spinner("Fetching tools...");

        let client = http_client()?;
        let resp: serde_json::Value = client
            .get(format!("{LIFI_API_BASE}/tools"))
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        spinner.finish_and_clear();

        // The response has "bridges" and "exchanges" arrays
        if let Some(bridges) = resp.get("bridges").and_then(|v| v.as_array()) {
            println!("  Bridges ({}):", bridges.len());
            for b in bridges {
                let name = b.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let key = b.get("key").and_then(|v| v.as_str()).unwrap_or("");
                let chains_count = b.get("supportedChains")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                println!("    {:<24} key={:<20} chains={}", name, key, chains_count);
            }
        }
        if let Some(exchanges) = resp.get("exchanges").and_then(|v| v.as_array()) {
            println!("  Exchanges ({}):", exchanges.len());
            for e in exchanges {
                let name = e.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                let key = e.get("key").and_then(|v| v.as_str()).unwrap_or("");
                let chains_count = e.get("supportedChains")
                    .and_then(|v| v.as_array())
                    .map(|a| a.len())
                    .unwrap_or(0);
                println!("    {:<24} key={:<20} chains={}", name, key, chains_count);
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Quote
// ---------------------------------------------------------------------------

/// Get a cross-chain swap quote from LI.FI
#[derive(Debug, Parser)]
pub struct LifiQuoteCmd {
    /// Source chain ID (e.g. 1 for Ethereum, 137 for Polygon)
    #[arg(long)]
    from_chain: u64,
    /// Destination chain ID
    #[arg(long)]
    to_chain: u64,
    /// Source token address (use 0x0000000000000000000000000000000000000000 for native)
    #[arg(long)]
    from_token: String,
    /// Destination token address
    #[arg(long)]
    to_token: String,
    /// Amount in smallest unit (wei)
    #[arg(long)]
    amount: String,
    /// Sender/from address
    #[arg(long)]
    from_address: String,
}

impl LifiQuoteCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("LI.FI Quote");
        let spinner = output::create_spinner("Fetching quote...");

        let client = http_client()?;
        let url = format!(
            "{LIFI_API_BASE}/quote?fromChain={}&toChain={}&fromToken={}&toToken={}&fromAmount={}&fromAddress={}",
            self.from_chain, self.to_chain, self.from_token, self.to_token, self.amount, self.from_address,
        );

        let resp: serde_json::Value = client
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        spinner.finish_and_clear();

        // Display key quote fields
        if let Some(action) = resp.get("action") {
            output::print_field("From Chain", &action.get("fromChainId").and_then(|v| v.as_u64()).unwrap_or(0).to_string());
            output::print_field("To Chain", &action.get("toChainId").and_then(|v| v.as_u64()).unwrap_or(0).to_string());
            output::print_field("From Amount", action.get("fromAmount").and_then(|v| v.as_str()).unwrap_or("N/A"));
        }
        if let Some(estimate) = resp.get("estimate") {
            output::print_field("To Amount", estimate.get("toAmount").and_then(|v| v.as_str()).unwrap_or("N/A"));
            output::print_field("Approval Address", estimate.get("approvalAddress").and_then(|v| v.as_str()).unwrap_or("N/A"));
            if let Some(fee_costs) = estimate.get("feeCosts").and_then(|v| v.as_array()) {
                for fc in fee_costs {
                    let name = fc.get("name").and_then(|v| v.as_str()).unwrap_or("fee");
                    let amount = fc.get("amount").and_then(|v| v.as_str()).unwrap_or("0");
                    output::print_field(&format!("Fee ({})", name), amount);
                }
            }
            if let Some(exec_dur) = estimate.get("executionDuration").and_then(|v| v.as_u64()) {
                output::print_field("Est. Duration", &format!("{}s", exec_dur));
            }
        }
        if let Some(tool) = resp.get("tool").and_then(|v| v.as_str()) {
            output::print_field("Tool", tool);
        }
        if let Some(tx) = resp.get("transactionRequest") {
            println!();
            output::print_field("TX To", tx.get("to").and_then(|v| v.as_str()).unwrap_or("N/A"));
            output::print_field("TX Value", tx.get("value").and_then(|v| v.as_str()).unwrap_or("0"));
            let data_preview = tx.get("data").and_then(|v| v.as_str()).unwrap_or("");
            if data_preview.len() > 66 {
                output::print_field("TX Data", &format!("{}...({} bytes)", &data_preview[..66], (data_preview.len() - 2) / 2));
            } else {
                output::print_field("TX Data", data_preview);
            }
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// Find advanced cross-chain routes via LI.FI
#[derive(Debug, Parser)]
pub struct LifiRoutesCmd {
    /// Source chain ID
    #[arg(long)]
    from_chain: u64,
    /// Destination chain ID
    #[arg(long)]
    to_chain: u64,
    /// Source token address
    #[arg(long)]
    from_token: String,
    /// Destination token address
    #[arg(long)]
    to_token: String,
    /// Amount in smallest unit (wei)
    #[arg(long)]
    amount: String,
    /// Sender/from address
    #[arg(long)]
    from_address: String,
}

impl LifiRoutesCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("LI.FI Advanced Routes");
        let spinner = output::create_spinner("Finding routes...");

        let client = http_client()?;
        let body = serde_json::json!({
            "fromChainId": self.from_chain,
            "toChainId": self.to_chain,
            "fromTokenAddress": self.from_token,
            "toTokenAddress": self.to_token,
            "fromAmount": self.amount,
            "fromAddress": self.from_address,
        });

        let resp: serde_json::Value = client
            .post(format!("{LIFI_API_BASE}/advanced/routes"))
            .json(&body)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        spinner.finish_and_clear();

        if let Some(routes) = resp.get("routes").and_then(|v| v.as_array()) {
            output::print_field("Routes Found", &routes.len().to_string());
            println!();
            for (i, route) in routes.iter().enumerate() {
                println!("  Route {}:", i + 1);
                if let Some(to_amount) = route.get("toAmount").and_then(|v| v.as_str()) {
                    println!("    To Amount:     {}", to_amount);
                }
                if let Some(gas_usd) = route.get("gasCostUSD").and_then(|v| v.as_str()) {
                    println!("    Gas Cost USD:  ${}", gas_usd);
                }
                if let Some(steps) = route.get("steps").and_then(|v| v.as_array()) {
                    println!("    Steps:         {}", steps.len());
                    for (j, step) in steps.iter().enumerate() {
                        let tool = step.get("tool").and_then(|v| v.as_str()).unwrap_or("?");
                        let stype = step.get("type").and_then(|v| v.as_str()).unwrap_or("?");
                        println!("      Step {}: {} ({})", j + 1, tool, stype);
                    }
                }
                if let Some(tags) = route.get("tags").and_then(|v| v.as_array()) {
                    let tag_strs: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
                    if !tag_strs.is_empty() {
                        println!("    Tags:          {}", tag_strs.join(", "));
                    }
                }
                println!();
            }
        } else {
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Status
// ---------------------------------------------------------------------------

/// Check the status of a LI.FI cross-chain transfer
#[derive(Debug, Parser)]
pub struct LifiStatusCmd {
    /// Transaction hash to check
    #[arg(long)]
    tx_hash: String,
    /// Bridge tool name (optional, e.g. "stargate", "hop", "cbridge")
    #[arg(long)]
    bridge: Option<String>,
    /// Source chain ID (optional)
    #[arg(long)]
    from_chain: Option<u64>,
}

impl LifiStatusCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("LI.FI Transfer Status");
        let spinner = output::create_spinner("Checking status...");

        let client = http_client()?;
        let mut url = format!("{LIFI_API_BASE}/status?txHash={}", self.tx_hash);
        if let Some(ref bridge) = self.bridge {
            url = format!("{url}&bridge={bridge}");
        }
        if let Some(from_chain) = self.from_chain {
            url = format!("{url}&fromChain={from_chain}");
        }

        let resp: serde_json::Value = client
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        spinner.finish_and_clear();

        output::print_field("Status", resp.get("status").and_then(|v| v.as_str()).unwrap_or("UNKNOWN"));
        output::print_field("Substatus", resp.get("substatus").and_then(|v| v.as_str()).unwrap_or("N/A"));
        if let Some(sending) = resp.get("sending") {
            output::print_field("Sending TX", sending.get("txHash").and_then(|v| v.as_str()).unwrap_or("N/A"));
            output::print_field("Sending Chain", &sending.get("chainId").and_then(|v| v.as_u64()).unwrap_or(0).to_string());
        }
        if let Some(receiving) = resp.get("receiving") {
            output::print_field("Receiving TX", receiving.get("txHash").and_then(|v| v.as_str()).unwrap_or("N/A"));
            output::print_field("Receiving Chain", &receiving.get("chainId").and_then(|v| v.as_u64()).unwrap_or(0).to_string());
        }
        if let Some(tool) = resp.get("tool").and_then(|v| v.as_str()) {
            output::print_field("Bridge Tool", tool);
        }
        if let Some(sub) = resp.get("substatusMessage").and_then(|v| v.as_str()) {
            output::print_field("Message", sub);
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Gas
// ---------------------------------------------------------------------------

/// Get gas prices for supported chains via LI.FI
#[derive(Debug, Parser)]
pub struct LifiGasCmd {
    /// Comma-separated chain IDs (e.g. "1,137,42161"), omit for all
    #[arg(long)]
    chains: Option<String>,
}

impl LifiGasCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("LI.FI Gas Prices");
        let spinner = output::create_spinner("Fetching gas prices...");

        let client = http_client()?;
        let mut url = format!("{LIFI_API_BASE}/gas/prices");
        if let Some(ref chains) = self.chains {
            url = format!("{url}?chains={chains}");
        }

        let resp: serde_json::Value = client
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        spinner.finish_and_clear();

        // Response is typically an object keyed by chain ID
        if let Some(obj) = resp.as_object() {
            for (chain_id, gas_data) in obj {
                println!("  Chain {}:", chain_id);
                if let Some(standard) = gas_data.get("standard") {
                    println!("    Standard:  {}", format_gas(standard));
                }
                if let Some(fast) = gas_data.get("fast") {
                    println!("    Fast:      {}", format_gas(fast));
                }
                if let Some(slow) = gas_data.get("slow") {
                    println!("    Slow:      {}", format_gas(slow));
                }
                if let Some(instant) = gas_data.get("instant") {
                    println!("    Instant:   {}", format_gas(instant));
                }
                // Some responses have gasPrice directly
                if let Some(gp) = gas_data.get("gasPrice").and_then(|v| v.as_str()) {
                    println!("    Gas Price: {} wei", gp);
                }
            }
        } else {
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        Ok(())
    }
}

fn format_gas(v: &serde_json::Value) -> String {
    if let Some(s) = v.as_str() {
        format!("{} wei", s)
    } else if let Some(n) = v.as_u64() {
        format!("{} wei", n)
    } else if let Some(obj) = v.as_object() {
        let max_fee = obj.get("maxFeePerGas").and_then(|v| v.as_str()).unwrap_or("?");
        let priority = obj.get("maxPriorityFeePerGas").and_then(|v| v.as_str()).unwrap_or("?");
        format!("maxFee={} priority={}", max_fee, priority)
    } else {
        v.to_string()
    }
}

// ---------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------

/// Get available token connections between two chains on LI.FI
#[derive(Debug, Parser)]
pub struct LifiConnectionsCmd {
    /// Source chain ID
    #[arg(long)]
    from_chain: u64,
    /// Destination chain ID
    #[arg(long)]
    to_chain: u64,
}

impl LifiConnectionsCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("LI.FI Connections");
        let spinner = output::create_spinner("Fetching connections...");

        let client = http_client()?;
        let url = format!(
            "{LIFI_API_BASE}/connections?fromChain={}&toChain={}",
            self.from_chain, self.to_chain,
        );

        let resp: serde_json::Value = client
            .get(&url)
            .send()
            .await?
            .error_for_status()?
            .json()
            .await?;

        spinner.finish_and_clear();

        if let Some(connections) = resp.get("connections").and_then(|v| v.as_array()) {
            output::print_field("Connections", &connections.len().to_string());
            println!();
            for conn in connections {
                let from_token = conn.get("fromToken")
                    .and_then(|t| t.get("symbol"))
                    .and_then(|s| s.as_str())
                    .unwrap_or("?");
                let to_tokens = conn.get("toTokens")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|t| t.get("symbol").and_then(|s| s.as_str()))
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                println!("  {} -> [{}]", from_token, to_tokens);
            }
        } else {
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        Ok(())
    }
}
