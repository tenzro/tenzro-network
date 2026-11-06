//! `tenzro fee-market`: the base fee of every resource market the next block
//! charges (`tenzro_getFeeMarket`): compute gas, state growth, bandwidth and
//! proof verification, each in atto-USD and in TNZO base units per unit,
//! with its per-block target.

use anyhow::Result;
use clap::Parser;

use crate::output;
use crate::rpc::RpcClient;

/// Show the base fee of every resource market
#[derive(Debug, Parser)]
pub struct FeeMarketCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl FeeMarketCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let markets: serde_json::Value = rpc
            .call("tenzro_getFeeMarket", serde_json::json!({}))
            .await?;
        output::print_header("Resource Fee Markets");
        output::print_json(&markets)
    }
}
