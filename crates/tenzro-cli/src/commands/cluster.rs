//! Local-network cluster planning commands. Computes a deterministic layer
//! placement for a model across a set of candidate members.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::{output, rpc};

#[derive(Debug, Subcommand)]
pub enum ClusterCommand {
    /// Compute a deterministic cluster placement plan for a model
    Plan(PlanCmd),
}

impl ClusterCommand {
    pub async fn execute(self) -> Result<()> {
        match self {
            Self::Plan(cmd) => cmd.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct PlanCmd {
    /// Total transformer layers in the model
    #[arg(long)]
    layers: u32,
    /// Hidden dimension (sets boundary-activation size per token)
    #[arg(long)]
    hidden_dim: u32,
    /// Total loaded weights footprint, in GB
    #[arg(long)]
    total_vram_gb: f32,
    /// Path to a JSON file holding the candidate members array
    #[arg(long)]
    members: String,
    /// Treat the cluster as user-forced even when the model fits on one member
    #[arg(long)]
    force: bool,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PlanCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Cluster Plan");

        let raw = std::fs::read_to_string(&self.members)
            .with_context(|| format!("reading members file '{}'", self.members))?;
        let members: serde_json::Value = serde_json::from_str(&raw)
            .with_context(|| format!("parsing members file '{}' as JSON", self.members))?;

        let params = serde_json::json!({
            "model": {
                "layers": self.layers,
                "hidden_dim": self.hidden_dim,
                "total_vram_gb": self.total_vram_gb,
            },
            "members": members,
            "user_forced": self.force,
        });

        let spinner = output::create_spinner("Computing placement...");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: Result<serde_json::Value> =
            rpc.call("tenzro_clusterPlan", serde_json::json!([params])).await;
        spinner.finish_and_clear();

        match result {
            Ok(value) => {
                println!();
                if let Some(fit) = value.get("fit").and_then(|v| v.as_str()) {
                    output::print_field("Fit Decision", fit);
                }
                let forms = value.get("forms_cluster").and_then(|v| v.as_bool()).unwrap_or(false);
                output::print_field("Forms Cluster", &forms.to_string());
                if let Some(bytes) = value
                    .get("activation_bytes_per_token")
                    .and_then(|v| v.as_u64())
                {
                    output::print_field("Activation Bytes / Token", &bytes.to_string());
                }
                if let Some(stages) = value.get("stages").and_then(|v| v.as_array()) {
                    println!();
                    output::print_field("Stages", &stages.len().to_string());
                    for (i, stage) in stages.iter().enumerate() {
                        let address = stage.get("address").and_then(|v| v.as_str()).unwrap_or("?");
                        let start = stage.get("start_layer").and_then(|v| v.as_u64()).unwrap_or(0);
                        let end = stage.get("end_layer").and_then(|v| v.as_u64()).unwrap_or(0);
                        output::print_field(
                            &format!("Stage {}", i),
                            &format!("{} layers [{}, {})", address, start, end),
                        );
                    }
                    if stages.is_empty() {
                        output::print_info("Model runs locally; no cluster stages assigned.");
                    }
                }
            }
            Err(e) => output::print_error(&format!("Failed to compute cluster plan: {}", e)),
        }
        Ok(())
    }
}
