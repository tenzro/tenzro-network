//! Tenzro Train commands for the Tenzro CLI.
//!
//! Decentralized verifiable foundation-model training over Decoupled DiLoCo.
//! Phase 1: timeseries-first, Open trust tier, Mean aggregation.
//!
//! Subcommands wrap `tenzro_training_*` JSON-RPC methods exposed by the node.
//! See `TRAIN.md` for the full architecture.

use crate::output;
use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};

/// Tenzro Train operations
#[derive(Debug, Subcommand)]
pub enum TrainCommand {
    /// Post a new training task spec (sponsor flow)
    PostTask(TrainPostTaskCmd),
    /// List all active training runs the node is syncing
    ListRuns(TrainListRunsCmd),
    /// Look up a single run by task_id
    GetRun(TrainGetRunCmd),
    /// Look up a sealed receipt by task_id
    GetReceipt(TrainGetReceiptCmd),
    /// Enroll a trainer DID into a run
    EnrollTrainer(TrainEnrollCmd),
    /// Submit an outer gradient (trainer flow)
    SubmitGradient(TrainSubmitGradientCmd),
    /// Finalize the current round (syncer flow)
    FinalizeRound(TrainFinalizeRoundCmd),
}

impl TrainCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::PostTask(c) => c.execute().await,
            Self::ListRuns(c) => c.execute().await,
            Self::GetRun(c) => c.execute().await,
            Self::GetReceipt(c) => c.execute().await,
            Self::EnrollTrainer(c) => c.execute().await,
            Self::SubmitGradient(c) => c.execute().await,
            Self::FinalizeRound(c) => c.execute().await,
        }
    }
}

// ---------------------------------------------------------------------------
// Post task
// ---------------------------------------------------------------------------

/// Post a new training task. The full task spec is loaded from a JSON file.
///
/// Phase 1 example task spec is published at
/// `crates/tenzro-training/examples/timesfm-task.json` (see TRAIN.md §A.1).
#[derive(Debug, Parser)]
pub struct TrainPostTaskCmd {
    /// Path to a JSON file containing a `TrainingTaskSpec`
    #[arg(long)]
    spec: String,

    /// Optional syncer DID (defaults to a deterministic value derived from task_id)
    #[arg(long)]
    syncer_did: Option<String>,

    /// Optional syncer address (32-byte hex; defaults to all-zero)
    #[arg(long)]
    syncer_address: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TrainPostTaskCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let spec_text = std::fs::read_to_string(&self.spec)
            .map_err(|e| anyhow!("read spec file '{}': {}", self.spec, e))?;
        let spec: serde_json::Value = serde_json::from_str(&spec_text)
            .map_err(|e| anyhow!("parse spec JSON: {}", e))?;

        output::print_header("Post Training Task");
        let spinner = output::create_spinner("Submitting...");
        let rpc = RpcClient::new(&self.rpc);

        let mut params = serde_json::json!({ "task_spec": spec });
        if let Some(did) = &self.syncer_did {
            params["syncer_did"] = serde_json::Value::String(did.clone());
        }
        if let Some(addr) = &self.syncer_address {
            params["syncer_address"] = serde_json::Value::String(addr.clone());
        }

        let result: serde_json::Value = rpc.call("tenzro_training_postTask", params).await?;
        spinner.finish_and_clear();

        output::print_success("Task posted!");
        output::print_field(
            "Task ID",
            result.get("task_id").and_then(|v| v.as_str()).unwrap_or(""),
        );
        output::print_field(
            "Status",
            result.get("status").and_then(|v| v.as_str()).unwrap_or(""),
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// List runs
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
pub struct TrainListRunsCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

impl TrainListRunsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_training_listRuns", serde_json::json!({})).await?;

        if self.format == "json" {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }

        output::print_header("Training Runs");
        let runs = result
            .get("runs")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if runs.is_empty() {
            output::print_info("No active training runs.");
            return Ok(());
        }
        for run in runs {
            let task_id = run.get("task_id").and_then(|v| v.as_str()).unwrap_or("?");
            let status = run.get("status").and_then(|v| v.as_str()).unwrap_or("?");
            let round = run.get("current_round").and_then(|v| v.as_u64()).unwrap_or(0);
            let trainers = run
                .get("trainers")
                .and_then(|v| v.as_array())
                .map(|a| a.len())
                .unwrap_or(0);
            output::print_field(
                task_id,
                &format!("status={}, round={}, trainers={}", status, round, trainers),
            );
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Get run
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
pub struct TrainGetRunCmd {
    /// Task ID to look up
    #[arg(long)]
    task_id: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TrainGetRunCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_training_getRun",
                serde_json::json!({ "task_id": self.task_id }),
            )
            .await?;

        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Get receipt
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
pub struct TrainGetReceiptCmd {
    /// Task ID to look up
    #[arg(long)]
    task_id: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TrainGetReceiptCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_training_getReceipt",
                serde_json::json!({ "task_id": self.task_id }),
            )
            .await?;

        if result.is_null() {
            output::print_info("No sealed receipt for this task yet.");
            return Ok(());
        }
        println!("{}", serde_json::to_string_pretty(&result)?);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Enroll trainer
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
pub struct TrainEnrollCmd {
    /// Task ID to enroll into
    #[arg(long)]
    task_id: String,
    /// Trainer DID (`did:tenzro:machine:...`)
    #[arg(long)]
    trainer_did: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TrainEnrollCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_training_enrollTrainer",
                serde_json::json!({
                    "task_id": self.task_id,
                    "trainer_did": self.trainer_did,
                }),
            )
            .await?;

        output::print_success("Trainer enrolled!");
        output::print_field(
            "Trainer count",
            &result
                .get("trainer_count")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .to_string(),
        );
        output::print_field(
            "Status",
            result.get("status").and_then(|v| v.as_str()).unwrap_or(""),
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Submit outer gradient
// ---------------------------------------------------------------------------

/// Submit a single outer gradient to the syncer. The full gradient is loaded
/// from a JSON file (typically produced by the Python reference trainer).
#[derive(Debug, Parser)]
pub struct TrainSubmitGradientCmd {
    /// Path to a JSON file containing an `OuterGradient`
    #[arg(long)]
    gradient: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TrainSubmitGradientCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let text = std::fs::read_to_string(&self.gradient)
            .map_err(|e| anyhow!("read gradient file '{}': {}", self.gradient, e))?;
        let gradient: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| anyhow!("parse gradient JSON: {}", e))?;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_training_submitOuterGradient",
                serde_json::json!({ "gradient": gradient }),
            )
            .await?;

        output::print_success("Gradient submitted!");
        output::print_field(
            "Task ID",
            result.get("task_id").and_then(|v| v.as_str()).unwrap_or(""),
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Finalize round
// ---------------------------------------------------------------------------

/// Finalize the current outer round and advance the syncer state.
///
/// `--post-step-hashes` is a JSON object mapping fragment index → hex hash,
/// e.g. `'{"0":"0xabcd...","1":"0x1234..."}'`. The Python reference trainer
/// emits this map after running aggregation + the outer optimizer step.
#[derive(Debug, Parser)]
pub struct TrainFinalizeRoundCmd {
    /// Task ID
    #[arg(long)]
    task_id: String,
    /// Round number to finalize
    #[arg(long)]
    round: u32,
    /// JSON map: fragment index → hex hash
    #[arg(long)]
    post_step_hashes: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl TrainFinalizeRoundCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let post_step: serde_json::Value =
            serde_json::from_str(&self.post_step_hashes)
                .map_err(|e| anyhow!("parse post_step_hashes JSON: {}", e))?;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_training_finalizeRound",
                serde_json::json!({
                    "task_id": self.task_id,
                    "round": self.round,
                    "post_step_hashes": post_step,
                }),
            )
            .await?;

        output::print_success("Round finalized!");
        if let Some(state_root) = result.get("state_root") {
            output::print_field("State root", &serde_json::to_string(state_root)?);
        }
        Ok(())
    }
}
