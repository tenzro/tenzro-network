//! Bridge fee in TNZO commands.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum BridgeFeeCommand {
    /// Quote a destination-native bridge fee in TNZO
    Quote(QuoteCmd),
}

impl BridgeFeeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Quote(c) => c.execute().await,
        }
    }
}

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

#[derive(Debug, Parser)]
pub struct QuoteCmd {
    /// Route transport: ccip, ibc, deposit or contract
    #[arg(long)]
    adapter: String,
    /// Destination chain CAIP-2 identifier (e.g. eip155:1, solana:mainnet-beta)
    #[arg(long)]
    dest_chain: String,
    /// Destination-native fee in the destination chain smallest unit (u128 decimal)
    #[arg(long)]
    native_fee: String,
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl QuoteCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Bridge Fee in TNZO — Quote");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_quoteBridgeFeeInTnzo",
                serde_json::json!({
                    "adapter": self.adapter,
                    "dest_chain": self.dest_chain,
                    "native_fee_smallest_unit": self.native_fee,
                }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
