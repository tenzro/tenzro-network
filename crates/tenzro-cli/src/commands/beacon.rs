//! The chain's randomness beacon (`tenzro_getBeacon`).
//!
//! - `tenzro beacon`                  — the head: next round and current mix
//! - `tenzro beacon --round <n>`      — the value taken at round `n`
//! - `tenzro beacon --at-ms <ms>`     — the first value taken at or after `ms`

use anyhow::Result;
use clap::Parser;

use crate::output;
use crate::rpc::RpcClient;

/// Show the chain's randomness beacon
#[derive(Debug, Parser)]
pub struct BeaconCmd {
    /// The value taken at this round
    #[arg(long, conflicts_with = "at_ms")]
    round: Option<u64>,
    /// The first value taken at or after this block time, ms
    #[arg(long)]
    at_ms: Option<i64>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl BeaconCmd {
    pub async fn execute(&self) -> Result<()> {
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getBeacon",
                serde_json::json!({ "round": self.round, "at_ms": self.at_ms }),
            )
            .await?;
        output::print_header("Randomness Beacon");
        output::print_json(&result)
    }
}
