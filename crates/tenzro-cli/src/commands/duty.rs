//! Network duties: work the chain pays the first prover for.
//!
//! - `tenzro duty list` — every open duty (`tenzro_listDuties`)
//! - `tenzro duty get` — one duty by id (`tenzro_getDuty`)
//!
//! A duty is paid by the transaction that proves its work (a verified
//! reconciliation, a proven grant install); nothing is sent from here.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

/// Network duties
#[derive(Debug, Subcommand)]
pub enum DutyCommand {
    /// List every open duty (read-only)
    List(DutyListCmd),
    /// Show one duty by id (read-only)
    Get(DutyGetCmd),
}

impl DutyCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::List(cmd) => cmd.execute().await,
            Self::Get(cmd) => cmd.execute().await,
        }
    }
}

/// List every open duty
#[derive(Debug, Parser)]
pub struct DutyListCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DutyListCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Open Duties");
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call("tenzro_listDuties", serde_json::json!({}))
            .await?;
        let duties = result
            .get("duties")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        for d in &duties {
            println!();
            print_duty(d);
        }
        if duties.is_empty() {
            output::print_info("No open duties.");
        }
        Ok(())
    }
}

/// Show one duty
#[derive(Debug, Parser)]
pub struct DutyGetCmd {
    /// Duty id (32-byte hex)
    duty_id: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl DutyGetCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Duty");
        let result: serde_json::Value = RpcClient::new(&self.rpc)
            .call(
                "tenzro_getDuty",
                serde_json::json!({ "duty_id": self.duty_id }),
            )
            .await?;
        if result.is_null() {
            output::print_info("No such duty.");
        } else {
            print_duty(&result);
        }
        Ok(())
    }
}

fn print_duty(d: &serde_json::Value) {
    let field = |k: &str| {
        d.get(k)
            .map(|v| v.to_string().trim_matches('"').to_string())
            .unwrap_or_default()
    };
    output::print_field("Id", &field("id"));
    output::print_field("Work", &field("kind"));
    output::print_field("Reward (wei)", &field("reward"));
    output::print_field("State", &field("state"));
    if let Some(to) = d.get("paid_to").and_then(|v| v.as_str()) {
        output::print_field("Paid to", to);
    }
}
