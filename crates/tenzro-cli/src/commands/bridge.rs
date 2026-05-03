//! Cross-chain bridge commands for the Tenzro CLI
//!
//! Quote, execute, and track cross-chain token bridges via LayerZero,
//! Chainlink CCIP, deBridge, and Canton adapters.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// Cross-chain bridge commands
#[derive(Debug, Subcommand)]
pub enum BridgeCommand {
    /// Get a cross-chain bridge quote
    Quote(BridgeQuoteCmd),
    /// Execute a cross-chain token bridge
    Execute(BridgeExecuteCmd),
    /// Check bridge transfer status
    Status(BridgeStatusCmd),
    /// List available bridge routes between two chains
    Routes(BridgeRoutesCmd),
    /// List registered bridge adapters
    Adapters(BridgeAdaptersCmd),
    /// Create a deBridge order with a post-fulfillment hook
    Hook(BridgeHookCmd),
    /// Authorize a cross-chain bridge transfer
    AuthorizeCrosschain(BridgeAuthorizeCrosschainCmd),
}

impl BridgeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Quote(cmd) => cmd.execute().await,
            Self::Execute(cmd) => cmd.execute().await,
            Self::Status(cmd) => cmd.execute().await,
            Self::Routes(cmd) => cmd.execute().await,
            Self::Adapters(cmd) => cmd.execute().await,
            Self::Hook(cmd) => cmd.execute().await,
            Self::AuthorizeCrosschain(cmd) => cmd.execute().await,
        }
    }
}

/// Get a cross-chain bridge quote
#[derive(Debug, Parser)]
pub struct BridgeQuoteCmd {
    /// Source chain (e.g. "ethereum", "arbitrum", "solana")
    #[arg(long)]
    from_chain: String,
    /// Destination chain (e.g. "arbitrum", "base", "polygon")
    #[arg(long)]
    to_chain: String,
    /// Token symbol (e.g. "USDC", "ETH", "TNZO")
    #[arg(long)]
    token: String,
    /// Amount to bridge
    #[arg(long)]
    amount: String,
    /// Bridge protocol to use (optional: "layerzero", "ccip", "debridge", "lifi", "wormhole")
    #[arg(long)]
    protocol: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BridgeQuoteCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Bridge Quote");
        let spinner = output::create_spinner("Fetching quote...");
        let rpc = RpcClient::new(&self.rpc);

        let mut params = serde_json::json!({
            "from_chain": self.from_chain,
            "to_chain": self.to_chain,
            "token": self.token,
            "amount": self.amount,
        });
        if let Some(ref protocol) = self.protocol {
            params["protocol"] = serde_json::json!(protocol);
        }

        let result: serde_json::Value = rpc.call("tenzro_bridgeQuote", params).await?;

        spinner.finish_and_clear();

        output::print_field("From Chain", result.get("from_chain").and_then(|v| v.as_str()).unwrap_or(&self.from_chain));
        output::print_field("To Chain", result.get("to_chain").and_then(|v| v.as_str()).unwrap_or(&self.to_chain));
        output::print_field("Token", result.get("token").and_then(|v| v.as_str()).unwrap_or(&self.token));
        output::print_field("Amount In", result.get("amount_in").and_then(|v| v.as_str()).unwrap_or(&self.amount));
        output::print_field("Estimated Output", result.get("estimated_output").and_then(|v| v.as_str()).unwrap_or("N/A"));
        output::print_field("Fee", result.get("fee").and_then(|v| v.as_str()).unwrap_or("N/A"));
        output::print_field("Estimated Time", result.get("estimated_time").and_then(|v| v.as_str()).unwrap_or("N/A"));
        output::print_field("Protocol", result.get("protocol").and_then(|v| v.as_str()).unwrap_or("auto"));
        if let Some(route) = result.get("route").and_then(|v| v.as_str()) {
            output::print_field("Route", route);
        }
        if let Some(expires) = result.get("expires_at").and_then(|v| v.as_str()) {
            output::print_field("Expires At", expires);
        }

        Ok(())
    }
}

/// Execute a cross-chain token bridge
#[derive(Debug, Parser)]
pub struct BridgeExecuteCmd {
    /// Source chain (e.g. "ethereum")
    #[arg(long)]
    from_chain: String,
    /// Destination chain (e.g. "arbitrum")
    #[arg(long)]
    to_chain: String,
    /// Token symbol (e.g. "USDC", "ETH", "TNZO")
    #[arg(long)]
    token: String,
    /// Amount to bridge
    #[arg(long)]
    amount: String,
    /// Sender address (hex)
    #[arg(long)]
    sender: String,
    /// Recipient address (hex)
    #[arg(long)]
    recipient: String,
    /// Bridge protocol to use (optional: "layerzero", "ccip", "debridge", "lifi", "wormhole")
    #[arg(long)]
    protocol: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BridgeExecuteCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Execute Bridge Transfer");
        let spinner = output::create_spinner("Submitting bridge transfer...");
        let rpc = RpcClient::new(&self.rpc);

        let mut params = serde_json::json!({
            "from_chain": self.from_chain,
            "to_chain": self.to_chain,
            "token": self.token,
            "amount": self.amount,
            "sender": self.sender,
            "recipient": self.recipient,
        });
        if let Some(ref protocol) = self.protocol {
            params["protocol"] = serde_json::json!(protocol);
        }

        let result: serde_json::Value = rpc.call("tenzro_bridgeTokens", params).await?;

        spinner.finish_and_clear();

        output::print_success("Bridge transfer submitted!");
        output::print_field("Transfer ID", result.get("transfer_id").and_then(|v| v.as_str()).unwrap_or("unknown"));
        output::print_field("Tx Hash", result.get("tx_hash").and_then(|v| v.as_str()).unwrap_or("pending"));
        output::print_field("Protocol", result.get("protocol").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Fee", result.get("fee").and_then(|v| v.as_str()).unwrap_or("N/A"));
        output::print_field("Estimated Arrival", result.get("estimated_arrival").and_then(|v| v.as_str()).unwrap_or("N/A"));
        output::print_field("Status", result.get("status").and_then(|v| v.as_str()).unwrap_or("Pending"));

        Ok(())
    }
}

/// Check bridge transfer status
#[derive(Debug, Parser)]
pub struct BridgeStatusCmd {
    /// Transfer ID to look up
    transfer_id: String,
    /// Bridge protocol (optional, for faster lookup)
    #[arg(long)]
    protocol: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BridgeStatusCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Bridge Transfer Status");
        let spinner = output::create_spinner("Querying status...");
        let rpc = RpcClient::new(&self.rpc);

        let mut params = serde_json::json!({
            "transfer_id": self.transfer_id,
        });
        if let Some(ref protocol) = self.protocol {
            params["protocol"] = serde_json::json!(protocol);
        }

        let result: serde_json::Value = rpc.call("tenzro_bridgeStatus", params).await?;

        spinner.finish_and_clear();

        output::print_field("Transfer ID", result.get("transfer_id").and_then(|v| v.as_str()).unwrap_or(&self.transfer_id));
        output::print_field("Status", result.get("status").and_then(|v| v.as_str()).unwrap_or("Unknown"));
        output::print_field("Protocol", result.get("protocol").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Source Chain", result.get("source_chain").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Dest Chain", result.get("dest_chain").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Token", result.get("token").and_then(|v| v.as_str()).unwrap_or(""));
        output::print_field("Amount", result.get("amount").and_then(|v| v.as_str()).unwrap_or(""));
        if let Some(src_tx) = result.get("source_tx_hash").and_then(|v| v.as_str()) {
            output::print_field("Source Tx", src_tx);
        }
        if let Some(dst_tx) = result.get("dest_tx_hash").and_then(|v| v.as_str()) {
            output::print_field("Dest Tx", dst_tx);
        }
        if let Some(created) = result.get("created_at").and_then(|v| v.as_str()) {
            output::print_field("Created At", created);
        }
        if let Some(completed) = result.get("completed_at").and_then(|v| v.as_str()) {
            output::print_field("Completed At", completed);
        }

        Ok(())
    }
}

/// List available bridge routes between two chains
#[derive(Debug, Parser)]
pub struct BridgeRoutesCmd {
    /// Source chain (e.g. "ethereum")
    #[arg(long)]
    from_chain: String,
    /// Destination chain (e.g. "arbitrum")
    #[arg(long)]
    to_chain: String,
    /// Filter by token symbol (optional)
    #[arg(long)]
    token: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BridgeRoutesCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Bridge Routes");
        let spinner = output::create_spinner("Loading routes...");
        let rpc = RpcClient::new(&self.rpc);

        let mut params = serde_json::json!({
            "from_chain": self.from_chain,
            "to_chain": self.to_chain,
        });
        if let Some(ref token) = self.token {
            params["token"] = serde_json::json!(token);
        }

        let result: serde_json::Value = rpc.call("tenzro_bridgeRoutes", params).await?;

        spinner.finish_and_clear();

        if let Some(routes) = result.get("routes").and_then(|v| v.as_array()) {
            if routes.is_empty() {
                output::print_info("No routes available between the specified chains.");
            } else {
                let headers = vec!["Protocol", "Est. Fee", "Est. Time", "Supported Tokens"];
                let mut rows = Vec::new();
                for r in routes {
                    rows.push(vec![
                        r.get("protocol").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        r.get("estimated_fee").and_then(|v| v.as_str()).unwrap_or("N/A").to_string(),
                        r.get("estimated_time").and_then(|v| v.as_str()).unwrap_or("N/A").to_string(),
                        r.get("supported_tokens")
                            .and_then(|v| v.as_array())
                            .map(|arr| arr.iter()
                                .filter_map(|t| t.as_str())
                                .collect::<Vec<_>>()
                                .join(", "))
                            .unwrap_or_else(|| r.get("supported_tokens")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string()),
                    ]);
                }
                output::print_table(&headers, &rows);
            }
        } else {
            output::print_info("No routes found.");
        }

        Ok(())
    }
}

/// List registered bridge adapters
#[derive(Debug, Parser)]
pub struct BridgeAdaptersCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BridgeAdaptersCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Bridge Adapters");
        let spinner = output::create_spinner("Loading adapters...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_listBridgeAdapters", serde_json::json!({})).await?;

        spinner.finish_and_clear();

        if let Some(adapters) = result.get("adapters").and_then(|v| v.as_array()) {
            if adapters.is_empty() {
                output::print_info("No bridge adapters registered.");
            } else {
                let headers = vec!["Name", "Protocol", "Chains", "Status"];
                let mut rows = Vec::new();
                for a in adapters {
                    rows.push(vec![
                        a.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        a.get("protocol").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                        a.get("supported_chains_count")
                            .and_then(|v| v.as_u64())
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| a.get("supported_chains")
                                .and_then(|v| v.as_array())
                                .map(|arr| arr.len().to_string())
                                .unwrap_or_default()),
                        a.get("status").and_then(|v| v.as_str()).unwrap_or("unknown").to_string(),
                    ]);
                }
                output::print_table(&headers, &rows);
            }
        } else {
            output::print_info("No adapters found.");
        }

        Ok(())
    }
}

/// Create a deBridge order with a post-fulfillment hook
#[derive(Debug, Parser)]
pub struct BridgeHookCmd {
    /// Source chain (e.g. "ethereum")
    #[arg(long)]
    from_chain: String,
    /// Destination chain (e.g. "arbitrum")
    #[arg(long)]
    to_chain: String,
    /// Token symbol (e.g. "USDC")
    #[arg(long)]
    token: String,
    /// Amount to bridge
    #[arg(long)]
    amount: String,
    /// Sender address (hex)
    #[arg(long)]
    sender: String,
    /// Hook target contract address (hex)
    #[arg(long)]
    hook_target: String,
    /// Hook calldata (hex-encoded)
    #[arg(long)]
    hook_calldata: String,
    /// Revert the order if the hook call fails
    #[arg(long)]
    hook_revert_on_fail: bool,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BridgeHookCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Bridge with Hook (deBridge)");
        let spinner = output::create_spinner("Creating hooked bridge order...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_bridgeWithHook", serde_json::json!({
            "from_chain": self.from_chain,
            "to_chain": self.to_chain,
            "token": self.token,
            "amount": self.amount,
            "sender": self.sender,
            "hook_target": self.hook_target,
            "hook_calldata": self.hook_calldata,
            "hook_revert_on_fail": self.hook_revert_on_fail,
        })).await?;

        spinner.finish_and_clear();

        output::print_success("Hooked bridge order created!");
        output::print_field("Order ID", result.get("order_id").and_then(|v| v.as_str()).unwrap_or("unknown"));
        output::print_field("Hook Target", result.get("hook_target").and_then(|v| v.as_str()).unwrap_or(&self.hook_target));
        output::print_field("Revert on Fail", &result.get("hook_revert_on_fail").and_then(|v| v.as_bool()).unwrap_or(self.hook_revert_on_fail).to_string());
        output::print_field("Status", result.get("status").and_then(|v| v.as_str()).unwrap_or("Pending"));
        if let Some(tx_hash) = result.get("tx_hash").and_then(|v| v.as_str()) {
            output::print_field("Tx Hash", tx_hash);
        }
        if let Some(fee) = result.get("fee").and_then(|v| v.as_str()) {
            output::print_field("Fee", fee);
        }

        Ok(())
    }
}

/// Authorize a cross-chain bridge transfer
#[derive(Debug, Parser)]
pub struct BridgeAuthorizeCrosschainCmd {
    /// Transfer ID to authorize
    #[arg(long)]
    transfer_id: String,
    /// Authorizer address (hex)
    #[arg(long)]
    authorizer: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BridgeAuthorizeCrosschainCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Authorize Cross-Chain Bridge");
        let spinner = output::create_spinner("Authorizing...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_authorizeCrosschainBridge", serde_json::json!({
            "transfer_id": self.transfer_id,
            "authorizer": self.authorizer,
        })).await?;
        spinner.finish_and_clear();
        output::print_success("Bridge transfer authorized!");
        output::print_field("Transfer ID", &self.transfer_id);
        output::print_field("Status", result.get("status").and_then(|v| v.as_str()).unwrap_or("authorized"));
        Ok(())
    }
}
