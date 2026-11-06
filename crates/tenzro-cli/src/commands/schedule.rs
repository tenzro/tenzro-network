//! Model stacks command

use crate::output;
use crate::rpc::RpcClient;
use anyhow::Result;
use clap::{Parser, Subcommand};

/// Provider schedule management
#[derive(Debug, Subcommand)]
pub enum ScheduleCommand {
    /// Show model stacks: what is serving now, what runs next, and when
    Stacks(StacksShowCmd),
}

impl ScheduleCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Stacks(cmd) => cmd.execute().await,
        }
    }
}

/// Show model stacks and their switch times.
///
/// A "stack" is a scheduling window's named set of models. The switch times are
/// the point: an app that knows when its stack ends can drain in-flight work
/// rather than discovering the change through failures.
#[derive(Debug, Parser)]
pub struct StacksShowCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    pub rpc: String,
}

impl StacksShowCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Model Stacks");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_getModelStacks", serde_json::json!([]))
            .await?;

        let models_of = |v: &serde_json::Value| -> String {
            v.get("models")
                .and_then(|m| m.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|m| {
                            let id = m.get("id")?.as_str()?;
                            let state = m.get("state").and_then(|s| s.as_str()).unwrap_or("?");
                            Some(format!("{id} ({state})"))
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default()
        };

        println!();
        match result.get("active") {
            Some(a) if !a.is_null() => {
                output::print_field(
                    "Active stack",
                    a.get("stack").and_then(|s| s.as_str()).unwrap_or("?"),
                );
                if let Some(u) = a.get("until").and_then(|u| u.as_str()) {
                    output::print_field("Until", u);
                }
                output::print_field("Models", &models_of(a));
            }
            // Distinguished from "no stacks configured" below, because the two
            // call for different fixes.
            _ => output::print_field("Active stack", "none — no window is active now"),
        }

        println!();
        match result.get("next") {
            Some(n) if !n.is_null() => {
                output::print_field(
                    "Next stack",
                    n.get("stack").and_then(|s| s.as_str()).unwrap_or("?"),
                );
                if let Some(t) = n.get("starts_at").and_then(|t| t.as_str()) {
                    output::print_field("Starts at", t);
                }
                output::print_field("Models", &models_of(n));
            }
            _ => output::print_field("Next stack", "none scheduled"),
        }

        let configured = result
            .get("stacks")
            .and_then(|s| s.as_array())
            .cloned()
            .unwrap_or_default();
        println!();
        if configured.is_empty() {
            output::print_field("Configured", "no stacks — every model stays as-is");
        } else {
            for w in &configured {
                let name = w.get("stack").and_then(|s| s.as_str()).unwrap_or("?");
                let tz = w.get("timezone").and_then(|s| s.as_str()).unwrap_or("UTC");
                let start = w.get("start_hour").and_then(|h| h.as_u64()).unwrap_or(0);
                let end = w.get("end_hour").and_then(|h| h.as_u64()).unwrap_or(0);
                let models = w
                    .get("models")
                    .and_then(|m| m.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|m| m.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                output::print_field(name, &format!("{start:02}:00-{end:02}:00 {tz} — {models}"));
            }
        }

        if let Some(t) = result.get("node_time").and_then(|t| t.as_str()) {
            println!();
            output::print_field("Node time", t);
        }

        Ok(())
    }
}
