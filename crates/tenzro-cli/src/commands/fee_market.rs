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

/// Estimate the gas a transaction would use, run against the latest state
#[derive(Debug, Parser)]
pub struct EstimateGasCmd {
    /// The unsigned transaction as a JSON object (`from`, `to`, `value`, and
    /// the other transaction fields), or `@file` to read it from a file
    #[arg(long)]
    tx: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl EstimateGasCmd {
    pub async fn execute(&self) -> Result<()> {
        let text = match self.tx.strip_prefix('@') {
            Some(path) => std::fs::read_to_string(path)?,
            None => self.tx.clone(),
        };
        let tx: serde_json::Value = serde_json::from_str(&text)?;
        let gas: String = RpcClient::new(&self.rpc)
            .call("tenzro_estimateGas", tx)
            .await?;
        output::print_header("Gas Estimate");
        output::print_field("Gas", &gas);
        Ok(())
    }
}
