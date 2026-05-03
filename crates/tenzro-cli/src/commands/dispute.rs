//! Channel-dispute inspection commands.
//!
//! Micropayment-channel disputes are first-class records in the
//! settlement engine — `MicropaymentChannelManager` exposes the full
//! open / respond / resolve lifecycle, and disputes are durable in
//! RocksDB (`CF_CHANNELS`, `dispute:<id>` prefix). These subcommands
//! are read-only inspection tools for operators and challengers; the
//! actual open/respond/resolve calls happen through the on-chain
//! settlement transaction path, not here.
//!
//! Backed by `tenzro_getDispute` and `tenzro_listDisputesByChannel`.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

/// Dispute inspection operations.
#[derive(Debug, Subcommand)]
pub enum DisputeCommand {
    /// Show the current state of a single dispute by id.
    Status(DisputeStatusCmd),
    /// List every dispute (open or historical) attached to a channel.
    ListByChannel(DisputeListByChannelCmd),
}

impl DisputeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Status(cmd) => cmd.execute().await,
            Self::ListByChannel(cmd) => cmd.execute().await,
        }
    }
}

/// `tenzro dispute status <dispute_id>` — fetch a single dispute record.
/// The response includes challenger, evidence blobs, current status,
/// open/timeout/resolved timestamps, and the resolution string (if any).
#[derive(Debug, Parser)]
pub struct DisputeStatusCmd {
    /// Dispute id (returned when the dispute was opened).
    dispute_id: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DisputeStatusCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Channel Dispute");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getDispute",
                serde_json::json!({ "dispute_id": self.dispute_id }),
            )
            .await
            .context("calling tenzro_getDispute")?;
        output::print_json(&result)?;
        Ok(())
    }
}

/// `tenzro dispute list-by-channel --channel-id <id>` — every dispute
/// that has ever been opened against the given channel. Returns an
/// empty list (not an error) for channels with no disputes.
#[derive(Debug, Parser)]
pub struct DisputeListByChannelCmd {
    /// Channel id to list disputes for.
    #[arg(long)]
    channel_id: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DisputeListByChannelCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Channel Disputes");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_listDisputesByChannel",
                serde_json::json!({ "channel_id": self.channel_id }),
            )
            .await
            .context("calling tenzro_listDisputesByChannel")?;
        output::print_field(
            "Channel",
            result.get("channel_id").and_then(|v| v.as_str()).unwrap_or(""),
        );
        output::print_field(
            "Count",
            &result
                .get("count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .to_string(),
        );
        if let Some(items) = result.get("disputes").and_then(|v| v.as_array()) {
            for item in items {
                output::print_json(item)?;
            }
        }
        Ok(())
    }
}
