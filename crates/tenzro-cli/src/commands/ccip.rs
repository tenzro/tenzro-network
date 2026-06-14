//! Chainlink CCIP cross-chain commands — the regulated-rail CLI surface.
//!
//! Wraps the `tenzro_ccip*` JSON-RPC namespace. CCIP is the
//! institutional rail: OCR commit-store committee + RMN ARM blessing,
//! the route Tenzro picks when a leg must be regulated and attested
//! rather than generic permissionless.

use anyhow::Result;
use clap::{Parser, Subcommand};
use serde_json::{json, Value};

use crate::output;
use crate::rpc::RpcClient;

/// Chainlink CCIP regulated-rail operations
#[derive(Debug, Subcommand)]
pub enum CcipCommand {
    /// Quote a CCIP fee via Router.getFee() eth_call
    GetFee(CcipGetFeeCmd),
    /// Prepare a Router.ccipSend() envelope (calldata + msg.value)
    Send(CcipSendCmd),
    /// Track a CCIP message via OffRamp.getExecutionState()
    Track(CcipTrackCmd),
    /// List CCIP-supported chains (Chainlink docs API)
    SupportedChains(CcipSupportedChainsCmd),
    /// List CCIP-supported tokens
    SupportedTokens(CcipSupportedTokensCmd),
    /// List CCIP lanes (source-destination chain pairs)
    Lanes(CcipLanesCmd),
    /// Inspect a CCIP CCT v1.6+ token-pool contract
    TokenPool(CcipTokenPoolCmd),
    /// Read pool rate-limiter state for a (pool, remote-chain) pair
    RateLimits(CcipRateLimitsCmd),
    /// Bridge tokens through the CCIP regulated rail
    Bridge(CcipBridgeCmd),
}

impl CcipCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::GetFee(cmd) => cmd.execute().await,
            Self::Send(cmd) => cmd.execute().await,
            Self::Track(cmd) => cmd.execute().await,
            Self::SupportedChains(cmd) => cmd.execute().await,
            Self::SupportedTokens(cmd) => cmd.execute().await,
            Self::Lanes(cmd) => cmd.execute().await,
            Self::TokenPool(cmd) => cmd.execute().await,
            Self::RateLimits(cmd) => cmd.execute().await,
            Self::Bridge(cmd) => cmd.execute().await,
        }
    }
}

fn default_rpc() -> &'static str {
    "http://127.0.0.1:8545"
}

#[derive(Debug, Parser)]
pub struct CcipGetFeeCmd {
    /// Source chain (ethereum, arbitrum, base)
    #[arg(long)]
    source_chain: String,
    /// Destination chain name or selector
    #[arg(long)]
    dest_chain: String,
    /// Receiver address on the destination chain (hex)
    #[arg(long)]
    receiver: String,
    /// Hex-encoded data payload (default empty)
    #[arg(long, default_value = "")]
    data_hex: String,
    /// Fee token address (default: native = 0x000…000)
    #[arg(long)]
    fee_token: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value_t = default_rpc().to_string())]
    rpc: String,
}

impl CcipGetFeeCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("CCIP Fee Quote");
        let rpc = RpcClient::new(&self.rpc);
        let result: Value = rpc
            .call(
                "tenzro_ccipGetFee",
                json!({
                    "source_chain": self.source_chain,
                    "dest_chain": self.dest_chain,
                    "receiver": self.receiver,
                    "data_hex": self.data_hex,
                    "token_amounts": [],
                    "fee_token": self.fee_token,
                }),
            )
            .await?;
        output::print_field("Source", result["source_chain"].as_str().unwrap_or(""));
        output::print_field("Router", result["router_address"].as_str().unwrap_or(""));
        output::print_field(
            "Dest selector",
            result["dest_chain_selector"].as_str().unwrap_or(""),
        );
        output::print_field("Fee (wei)", result["fee_wei"].as_str().unwrap_or(""));
        output::print_field("Fee (native)", result["fee_native"].as_str().unwrap_or(""));
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CcipSendCmd {
    #[arg(long)]
    source_chain: String,
    #[arg(long)]
    dest_chain: String,
    #[arg(long)]
    receiver: String,
    #[arg(long, default_value = "")]
    data_hex: String,
    #[arg(long)]
    fee_token: Option<String>,
    /// Destination-chain execution gas limit (default: 200000)
    #[arg(long)]
    gas_limit: Option<u64>,
    #[arg(long, default_value_t = default_rpc().to_string())]
    rpc: String,
}

impl CcipSendCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("CCIP Send Envelope");
        let rpc = RpcClient::new(&self.rpc);
        let result: Value = rpc
            .call(
                "tenzro_ccipSend",
                json!({
                    "source_chain": self.source_chain,
                    "dest_chain": self.dest_chain,
                    "receiver": self.receiver,
                    "data_hex": self.data_hex,
                    "token_amounts": [],
                    "fee_token": self.fee_token,
                    "gas_limit": self.gas_limit,
                }),
            )
            .await?;
        output::print_field("Status", result["status"].as_str().unwrap_or(""));
        output::print_field("Router", result["router_address"].as_str().unwrap_or(""));
        output::print_field(
            "Dest selector",
            result["dest_chain_selector"].as_str().unwrap_or(""),
        );
        output::print_field(
            "msg.value (wei)",
            result["msg_value_wei"].as_str().unwrap_or(""),
        );
        if let Some(g) = result["gas_limit_destination"].as_u64() {
            output::print_field("Dest gas limit", &g.to_string());
        }
        output::print_field("Calldata", result["calldata"].as_str().unwrap_or(""));
        if let Some(note) = result["note"].as_str() {
            output::print_field("Note", note);
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CcipTrackCmd {
    /// 32-byte CCIP message id (hex)
    #[arg(long)]
    message_id: String,
    /// Destination chain
    #[arg(long)]
    dest_chain: String,
    /// OffRamp contract address on the destination chain
    #[arg(long)]
    offramp_address: String,
    #[arg(long, default_value_t = default_rpc().to_string())]
    rpc: String,
}

impl CcipTrackCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("CCIP Execution State");
        let rpc = RpcClient::new(&self.rpc);
        let result: Value = rpc
            .call(
                "tenzro_ccipTrack",
                json!({
                    "message_id": self.message_id,
                    "dest_chain": self.dest_chain,
                    "offramp_address": self.offramp_address,
                }),
            )
            .await?;
        output::print_field("Message id", result["message_id"].as_str().unwrap_or(""));
        output::print_field("Dest", result["dest_chain"].as_str().unwrap_or(""));
        if let Some(s) = result["execution_state"].as_u64() {
            output::print_field("State", &s.to_string());
        }
        output::print_field("Name", result["state_name"].as_str().unwrap_or(""));
        output::print_field("Description", result["description"].as_str().unwrap_or(""));
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CcipSupportedChainsCmd {
    /// Environment (mainnet or testnet)
    #[arg(long, default_value = "mainnet")]
    environment: String,
    #[arg(long, default_value_t = default_rpc().to_string())]
    rpc: String,
}

impl CcipSupportedChainsCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("CCIP Supported Chains");
        let rpc = RpcClient::new(&self.rpc);
        let result: Value = rpc
            .call(
                "tenzro_ccipSupportedChains",
                json!({ "environment": self.environment }),
            )
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CcipSupportedTokensCmd {
    #[arg(long, default_value = "mainnet")]
    environment: String,
    #[arg(long, default_value_t = default_rpc().to_string())]
    rpc: String,
}

impl CcipSupportedTokensCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("CCIP Supported Tokens");
        let rpc = RpcClient::new(&self.rpc);
        let result: Value = rpc
            .call(
                "tenzro_ccipSupportedTokens",
                json!({ "environment": self.environment }),
            )
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CcipLanesCmd {
    #[arg(long, default_value = "mainnet")]
    environment: String,
    #[arg(long)]
    source_chain_selector: Option<String>,
    #[arg(long)]
    dest_chain_selector: Option<String>,
    #[arg(long, default_value_t = default_rpc().to_string())]
    rpc: String,
}

impl CcipLanesCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("CCIP Lanes");
        let rpc = RpcClient::new(&self.rpc);
        let result: Value = rpc
            .call(
                "tenzro_ccipLanes",
                json!({
                    "environment": self.environment,
                    "source_chain_selector": self.source_chain_selector,
                    "dest_chain_selector": self.dest_chain_selector,
                }),
            )
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CcipTokenPoolCmd {
    #[arg(long)]
    chain: String,
    /// Token-pool contract address
    #[arg(long)]
    pool_address: String,
    #[arg(long, default_value_t = default_rpc().to_string())]
    rpc: String,
}

impl CcipTokenPoolCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("CCIP Token Pool");
        let rpc = RpcClient::new(&self.rpc);
        let result: Value = rpc
            .call(
                "tenzro_ccipTokenPool",
                json!({
                    "chain": self.chain,
                    "pool_address": self.pool_address,
                }),
            )
            .await?;
        output::print_field("Chain", result["chain"].as_str().unwrap_or(""));
        output::print_field("Pool", result["pool_address"].as_str().unwrap_or(""));
        output::print_field("Token", result["token_address"].as_str().unwrap_or(""));
        if let Some(note) = result["note"].as_str() {
            output::print_field("Note", note);
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CcipRateLimitsCmd {
    #[arg(long)]
    chain: String,
    #[arg(long)]
    pool_address: String,
    /// Remote chain name or selector
    #[arg(long)]
    remote_chain: String,
    #[arg(long, default_value_t = default_rpc().to_string())]
    rpc: String,
}

impl CcipRateLimitsCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("CCIP Rate Limits");
        let rpc = RpcClient::new(&self.rpc);
        let result: Value = rpc
            .call(
                "tenzro_ccipRateLimits",
                json!({
                    "chain": self.chain,
                    "pool_address": self.pool_address,
                    "remote_chain": self.remote_chain,
                }),
            )
            .await?;
        output::print_json(&result)?;
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CcipBridgeCmd {
    #[arg(long)]
    source_chain: String,
    #[arg(long)]
    dest_chain: String,
    #[arg(long, default_value = "TNZO")]
    asset: String,
    /// Amount in smallest units (u128)
    #[arg(long)]
    amount: String,
    #[arg(long)]
    sender: String,
    #[arg(long)]
    recipient: String,
    #[arg(long, default_value_t = default_rpc().to_string())]
    rpc: String,
}

impl CcipBridgeCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("CCIP Bridge Transfer (Regulated Rail)");
        let spinner = output::create_spinner("Submitting CCIP transfer...");
        let rpc = RpcClient::new(&self.rpc);
        let result: Value = rpc
            .call(
                "tenzro_ccipBridge",
                json!({
                    "source_chain": self.source_chain,
                    "dest_chain": self.dest_chain,
                    "asset": self.asset,
                    "amount": self.amount,
                    "sender": self.sender,
                    "recipient": self.recipient,
                }),
            )
            .await?;
        spinner.finish_and_clear();

        if let Some(status) = result.get("status").and_then(|v| v.as_str()) {
            output::print_error(&format!(
                "Transfer {}: {}",
                status,
                result.get("error").and_then(|v| v.as_str()).unwrap_or("")
            ));
            if let Some(adapters) = result.get("registered_adapters").and_then(|v| v.as_array()) {
                let joined: Vec<&str> = adapters.iter().filter_map(|v| v.as_str()).collect();
                output::print_field("Registered Adapters", &joined.join(", "));
            }
            return Ok(());
        }

        output::print_success("Transfer submitted via Chainlink CCIP");
        output::print_field("Transfer ID", result["transfer_id"].as_str().unwrap_or(""));
        output::print_field("Source", result["source_chain"].as_str().unwrap_or(""));
        output::print_field("Dest", result["dest_chain"].as_str().unwrap_or(""));
        output::print_field("Tx Hash", result["tx_hash"].as_str().unwrap_or(""));
        output::print_field("Fee Paid", result["fee_paid"].as_str().unwrap_or(""));
        if let Some(eta) = result["estimated_arrival_ms"].as_u64() {
            output::print_field("ETA (ms)", &eta.to_string());
        }
        output::print_field("Adapter", result["adapter"].as_str().unwrap_or(""));
        Ok(())
    }
}
