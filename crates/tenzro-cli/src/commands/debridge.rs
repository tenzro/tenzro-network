//! deBridge cross-chain commands for the Tenzro CLI
//!
//! Proxy tools for the official deBridge MCP server at agents.debridge.com/mcp.
//! Search tokens, list supported chains, create cross-chain transactions,
//! and execute same-chain swaps via deBridge DLN.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// deBridge cross-chain operations
#[derive(Debug, Subcommand)]
pub enum DebridgeCommand {
    /// Search for tokens on deBridge
    SearchTokens(DebridgeSearchTokensCmd),
    /// List supported chains
    Chains(DebridgeChainsCmd),
    /// Get operational instructions
    Instructions(DebridgeInstructionsCmd),
    /// Create cross-chain transaction
    CreateTx(DebridgeCreateTxCmd),
    /// Same-chain token swap
    Swap(DebridgeSwapCmd),
}

impl DebridgeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::SearchTokens(cmd) => cmd.execute().await,
            Self::Chains(cmd) => cmd.execute().await,
            Self::Instructions(cmd) => cmd.execute().await,
            Self::CreateTx(cmd) => cmd.execute().await,
            Self::Swap(cmd) => cmd.execute().await,
        }
    }
}

/// Search for tokens available on deBridge DLN
#[derive(Debug, Parser)]
pub struct DebridgeSearchTokensCmd {
    /// Token name, symbol, or address to search for
    query: String,
    /// Optional chain ID to filter results (e.g. 1 for Ethereum, 56 for BSC)
    #[arg(long)]
    chain_id: Option<u64>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DebridgeSearchTokensCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("deBridge Token Search");
        let spinner = output::create_spinner("Searching tokens...");
        let rpc = RpcClient::new(&self.rpc);

        let mut params = serde_json::json!({
            "query": self.query,
        });
        if let Some(cid) = self.chain_id {
            params["chain_id"] = serde_json::json!(cid);
        }

        let result: serde_json::Value = rpc.call("tenzro_debridgeSearchTokens", params).await?;
        spinner.finish_and_clear();

        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }
}

/// List all blockchain networks supported by deBridge DLN
#[derive(Debug, Parser)]
pub struct DebridgeChainsCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DebridgeChainsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("deBridge Supported Chains");
        let spinner = output::create_spinner("Fetching chains...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_debridgeGetChains", serde_json::json!({})).await?;
        spinner.finish_and_clear();

        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }
}

/// Get deBridge operational instructions and guidance
#[derive(Debug, Parser)]
pub struct DebridgeInstructionsCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DebridgeInstructionsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("deBridge Instructions");
        let spinner = output::create_spinner("Fetching instructions...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_debridgeGetInstructions", serde_json::json!({})).await?;
        spinner.finish_and_clear();

        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }
}

/// Create a cross-chain transaction via deBridge DLN
#[derive(Debug, Parser)]
pub struct DebridgeCreateTxCmd {
    /// Source chain ID (e.g. 1 for Ethereum)
    #[arg(long)]
    src_chain: u64,
    /// Destination chain ID
    #[arg(long)]
    dst_chain: u64,
    /// Source token address
    #[arg(long)]
    src_token: String,
    /// Destination token address
    #[arg(long)]
    dst_token: String,
    /// Amount in smallest unit (wei/lamports)
    #[arg(long)]
    amount: String,
    /// Recipient address on destination chain
    #[arg(long)]
    recipient: String,
    /// Sender address on source chain (optional)
    #[arg(long)]
    sender: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DebridgeCreateTxCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("deBridge Create Transaction");
        let spinner = output::create_spinner("Creating cross-chain transaction...");
        let rpc = RpcClient::new(&self.rpc);

        let mut params = serde_json::json!({
            "src_chain_id": self.src_chain,
            "dst_chain_id": self.dst_chain,
            "src_token": self.src_token,
            "dst_token": self.dst_token,
            "amount": self.amount,
            "recipient": self.recipient,
        });
        if let Some(ref sender) = self.sender {
            params["sender"] = serde_json::json!(sender);
        }

        let result: serde_json::Value = rpc.call("tenzro_debridgeCreateTx", params).await?;
        spinner.finish_and_clear();

        output::print_success("Transaction created!");
        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }
}

/// Execute a same-chain token swap via deBridge
#[derive(Debug, Parser)]
pub struct DebridgeSwapCmd {
    /// Chain ID for the swap
    #[arg(long)]
    chain_id: u64,
    /// Input token address
    #[arg(long)]
    token_in: String,
    /// Output token address
    #[arg(long)]
    token_out: String,
    /// Amount of input token in smallest unit
    #[arg(long)]
    amount: String,
    /// Sender address (optional)
    #[arg(long)]
    sender: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DebridgeSwapCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("deBridge Same-Chain Swap");
        let spinner = output::create_spinner("Creating swap transaction...");
        let rpc = RpcClient::new(&self.rpc);

        let mut params = serde_json::json!({
            "chain_id": self.chain_id,
            "token_in": self.token_in,
            "token_out": self.token_out,
            "amount": self.amount,
        });
        if let Some(ref sender) = self.sender {
            params["sender"] = serde_json::json!(sender);
        }

        let result: serde_json::Value = rpc.call("tenzro_debridgeSameChainSwap", params).await?;
        spinner.finish_and_clear();

        output::print_success("Swap transaction created!");
        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }
}
