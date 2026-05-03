//! TNZO CCT (Chainlink Cross-Chain Token) commands.
//!
//! Lists and inspects TNZO CCT pools in the canonical mainnet registry
//! (Ethereum LockRelease; Base/Arbitrum/Optimism/Solana BurnMint).

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// TNZO CCT pool inspection
#[derive(Debug, Subcommand)]
pub enum CctCommand {
    /// List all registered TNZO CCT pools
    ListPools(CctListPoolsCmd),
    /// Get a single TNZO CCT pool by chain name
    GetPool(CctGetPoolCmd),
}

impl CctCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::ListPools(cmd) => cmd.execute().await,
            Self::GetPool(cmd) => cmd.execute().await,
        }
    }
}

/// List all TNZO CCT pools
#[derive(Debug, Parser)]
pub struct CctListPoolsCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CctListPoolsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("TNZO CCT Pools");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_cctListPools", serde_json::json!({}))
            .await?;

        if let Some(count) = result.get("count").and_then(|v| v.as_u64()) {
            output::print_field("Pool Count", &count.to_string());
        }
        if let Some(pools) = result.get("pools").and_then(|v| v.as_array()) {
            for pool in pools {
                println!();
                print_pool(pool);
            }
        }
        Ok(())
    }
}

/// Get a single TNZO CCT pool
#[derive(Debug, Parser)]
pub struct CctGetPoolCmd {
    /// Chain name (e.g. ethereum, base, arbitrum, optimism, solana)
    #[arg(long)]
    chain: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CctGetPoolCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        output::print_header("TNZO CCT Pool");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_cctGetPool",
                serde_json::json!({ "chain": self.chain }),
            )
            .await?;
        print_pool(&result);
        Ok(())
    }
}

fn print_pool(pool: &serde_json::Value) {
    output::print_field(
        "Chain ID",
        pool.get("chain_id").and_then(|v| v.as_str()).unwrap_or(""),
    );
    output::print_field(
        "Chain Selector",
        pool.get("chain_selector").and_then(|v| v.as_str()).unwrap_or(""),
    );
    output::print_field(
        "Pool Address",
        pool.get("pool_address").and_then(|v| v.as_str()).unwrap_or(""),
    );
    output::print_field(
        "Token Address",
        pool.get("token_address").and_then(|v| v.as_str()).unwrap_or(""),
    );
    output::print_field(
        "Pool Type",
        pool.get("pool_type").and_then(|v| v.as_str()).unwrap_or(""),
    );
    output::print_field(
        "Contract Name",
        pool.get("contract_name").and_then(|v| v.as_str()).unwrap_or(""),
    );
    output::print_field(
        "Outbound Capacity",
        pool.get("outbound_capacity").and_then(|v| v.as_str()).unwrap_or(""),
    );
    output::print_field(
        "Inbound Capacity",
        pool.get("inbound_capacity").and_then(|v| v.as_str()).unwrap_or(""),
    );
    output::print_field(
        "Refill Rate",
        pool.get("refill_rate").and_then(|v| v.as_str()).unwrap_or(""),
    );
}
