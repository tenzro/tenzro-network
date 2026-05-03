//! Reputation inspection commands.
//!
//! Reputation is a per-provider score maintained by `ProviderManager`.
//! Successful inferences raise the score by +1 (saturating to 1000),
//! failures drop it by 5 (saturating to 0). The asymmetric update is
//! deliberate — flaky providers fall out of the top of routing decisions
//! quickly, while well-behaved ones recover slowly enough that operators
//! can correlate the score with actual reliability.
//!
//! Reads route through `tenzro_getProviderReputation`. The score is
//! durable: `record_success` / `record_failure` write through to RocksDB
//! via `persist_provider`, so a node restart does not reset reputation.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

/// Reputation operations.
#[derive(Debug, Subcommand)]
pub enum ReputationCommand {
    /// Print the current reputation score for a provider address.
    Get(ReputationGetCmd),
}

impl ReputationCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Get(cmd) => cmd.execute().await,
        }
    }
}

/// `tenzro reputation get <provider>` — read the score for a provider
/// address. Returns the integer score (0-1000) and the address echoed
/// back from the node.
#[derive(Debug, Parser)]
pub struct ReputationGetCmd {
    /// Provider address (hex, 0x-prefix optional).
    provider: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ReputationGetCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Provider Reputation");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getProviderReputation",
                serde_json::json!({ "provider": self.provider }),
            )
            .await
            .context("calling tenzro_getProviderReputation")?;

        output::print_field(
            "Provider",
            result.get("provider").and_then(|v| v.as_str()).unwrap_or(""),
        );
        let score = result
            .get("reputation")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        output::print_field("Score", &format!("{} / 1000", score));
        Ok(())
    }
}
