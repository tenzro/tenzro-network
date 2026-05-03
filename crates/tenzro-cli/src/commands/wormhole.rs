//! Wormhole cross-chain commands.
//!
//! Wraps `tenzro_wormhole*` RPCs: chain id lookup, VAA id parsing,
//! and token bridging through the BridgeRouter's Wormhole adapter.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// Wormhole cross-chain operations
#[derive(Debug, Subcommand)]
pub enum WormholeCommand {
    /// Look up the Wormhole numeric chain id for a chain name
    ChainId(WormholeChainIdCmd),
    /// Parse a VAA id ({chain}/{emitter}/{sequence}) into components
    ParseVaa(WormholeParseVaaCmd),
    /// Bridge tokens through the Wormhole adapter
    Bridge(WormholeBridgeCmd),
}

impl WormholeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::ChainId(cmd) => cmd.execute().await,
            Self::ParseVaa(cmd) => cmd.execute().await,
            Self::Bridge(cmd) => cmd.execute().await,
        }
    }
}

/// Look up Wormhole chain id
#[derive(Debug, Parser)]
pub struct WormholeChainIdCmd {
    /// Chain name (e.g. ethereum, solana, base, arbitrum, optimism)
    #[arg(long)]
    chain: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WormholeChainIdCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Wormhole Chain ID Lookup");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_wormholeChainId",
                serde_json::json!({ "chain": self.chain }),
            )
            .await?;
        output::print_field(
            "Chain",
            result.get("chain").and_then(|v| v.as_str()).unwrap_or(""),
        );
        if let Some(id) = result.get("wormhole_chain_id").and_then(|v| v.as_u64()) {
            output::print_field("Wormhole Chain ID", &id.to_string());
        }
        Ok(())
    }
}

/// Parse a canonical VAA id
#[derive(Debug, Parser)]
pub struct WormholeParseVaaCmd {
    /// VAA id in the form {chain}/{emitter}/{sequence}
    #[arg(long)]
    vaa_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WormholeParseVaaCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Parse Wormhole VAA ID");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_wormholeParseVaaId",
                serde_json::json!({ "vaa_id": self.vaa_id }),
            )
            .await?;
        if let Some(c) = result.get("emitter_chain").and_then(|v| v.as_u64()) {
            output::print_field("Emitter Chain", &c.to_string());
        }
        output::print_field(
            "Emitter Address",
            result.get("emitter_address").and_then(|v| v.as_str()).unwrap_or(""),
        );
        if let Some(s) = result.get("sequence").and_then(|v| v.as_u64()) {
            output::print_field("Sequence", &s.to_string());
        }
        Ok(())
    }
}

/// Bridge tokens via Wormhole
#[derive(Debug, Parser)]
pub struct WormholeBridgeCmd {
    /// Source chain name
    #[arg(long)]
    source_chain: String,
    /// Destination chain name
    #[arg(long)]
    dest_chain: String,
    /// Asset symbol (default: TNZO)
    #[arg(long, default_value = "TNZO")]
    asset: String,
    /// Amount in smallest units (u128)
    #[arg(long)]
    amount: String,
    /// Sender address
    #[arg(long)]
    sender: String,
    /// Recipient address on destination chain
    #[arg(long)]
    recipient: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl WormholeBridgeCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("Wormhole Bridge Transfer");
        let spinner = output::create_spinner("Submitting transfer...");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_wormholeBridge",
                serde_json::json!({
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

        output::print_success("Transfer submitted");
        output::print_field(
            "Transfer ID",
            result.get("transfer_id").and_then(|v| v.as_str()).unwrap_or(""),
        );
        output::print_field(
            "Source Chain",
            result.get("source_chain").and_then(|v| v.as_str()).unwrap_or(""),
        );
        output::print_field(
            "Dest Chain",
            result.get("dest_chain").and_then(|v| v.as_str()).unwrap_or(""),
        );
        output::print_field(
            "Tx Hash",
            result.get("tx_hash").and_then(|v| v.as_str()).unwrap_or(""),
        );
        output::print_field(
            "Fee Paid",
            result.get("fee_paid").and_then(|v| v.as_str()).unwrap_or(""),
        );
        if let Some(eta) = result.get("estimated_arrival_ms").and_then(|v| v.as_u64()) {
            output::print_field("ETA (ms)", &eta.to_string());
        }
        Ok(())
    }
}
