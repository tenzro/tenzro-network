//! Local-network cluster planning commands. Computes a deterministic layer
//! placement for a model across a set of candidate members.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::{output, rpc};

#[derive(Debug, Subcommand)]
pub enum ClusterCommand {
    /// Compute a deterministic cluster placement plan from explicit model
    /// dimensions and a candidate-members file
    Plan(PlanCmd),
    /// Preview how a downloaded model would be placed using the node's live
    /// view — derives the model shape from the GGUF header and discovers LAN
    /// members from gossip. Takes just a model ID.
    Preview(PreviewCmd),
    /// List the local node and every LAN/gossip member it can pool into a
    /// cluster — model-independent discovery of who's on your network.
    Members(MembersCmd),
}

impl ClusterCommand {
    pub async fn execute(self) -> Result<()> {
        match self {
            Self::Plan(cmd) => cmd.execute().await,
            Self::Preview(cmd) => cmd.execute().await,
            Self::Members(cmd) => cmd.execute().await,
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

#[derive(Debug, Parser)]
pub struct PreviewCmd {
    /// Model ID to preview placement for (must be downloaded on the node)
    model_id: String,
    /// Treat the cluster as user-forced even when the model fits one member
    #[arg(long)]
    force: bool,
    /// Never form a cluster; preview as single-host
    #[arg(long, conflicts_with = "force")]
    force_single: bool,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl PreviewCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header(&format!("Cluster Preview: {}", self.model_id));

        let params = serde_json::json!({
            "model_id": self.model_id,
            "user_forced": self.force,
            "force_single": self.force_single,
        });

        let spinner = output::create_spinner("Reading model shape and discovering members...");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: Result<serde_json::Value> =
            rpc.call("tenzro_clusterPreview", params).await;
        spinner.finish_and_clear();

        let value = match result {
            Ok(v) => v,
            Err(e) => {
                output::print_error(&format!("Failed to preview cluster placement: {}", e));
                return Ok(());
            }
        };

        println!();
        if let Some(shape) = value.get("model_shape") {
            let layers = shape.get("layers").and_then(|v| v.as_u64()).unwrap_or(0);
            let vram = shape.get("total_vram_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
            output::print_field("Model Shape", &format!("{} layers, {:.1} GB weights", layers, vram));
        }
        if let Some(fit) = value.get("fit").and_then(|v| v.as_str()) {
            output::print_field("Fit Decision", fit);
        }
        let forms = value.get("forms_cluster").and_then(|v| v.as_bool()).unwrap_or(false);
        output::print_field("Forms Cluster", &forms.to_string());

        if let Some(members) = value.get("members").and_then(|v| v.as_array()) {
            println!();
            output::print_field("Discovered Members", &members.len().to_string());
            for m in members {
                let address = m.get("address").and_then(|v| v.as_str()).unwrap_or("?");
                let vram = m.get("vram_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let backend = m.get("backend").and_then(|v| v.as_str()).unwrap_or("?");
                let reach = m.get("reachability").and_then(|v| v.as_str()).unwrap_or("?");
                let head = if m.get("is_head").and_then(|v| v.as_bool()).unwrap_or(false) {
                    " [head]"
                } else {
                    ""
                };
                output::print_field(
                    &format!("  {}", address),
                    &format!("{:.1} GB {} {}{}", vram, backend, reach, head),
                );
            }
        }

        if let Some(rejected) = value.get("rejected").and_then(|v| v.as_array())
            && !rejected.is_empty()
        {
            println!();
            output::print_field("Not Eligible", &rejected.len().to_string());
            for r in rejected {
                let address = r.get("address").and_then(|v| v.as_str()).unwrap_or("?");
                let reason = r
                    .get("reason")
                    .and_then(|v| v.get("kind"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("?");
                output::print_field(&format!("  {}", address), reason);
            }
        }

        if let Some(stages) = value.get("stages").and_then(|v| v.as_array()) {
            println!();
            if stages.is_empty() {
                output::print_info("Model runs locally; no cluster stages assigned.");
            } else {
                output::print_field("Proposed Split", &format!("{} stages", stages.len()));
                for (i, stage) in stages.iter().enumerate() {
                    let address = stage.get("address").and_then(|v| v.as_str()).unwrap_or("?");
                    let start = stage.get("start_layer").and_then(|v| v.as_u64()).unwrap_or(0);
                    let end = stage.get("end_layer").and_then(|v| v.as_u64()).unwrap_or(0);
                    output::print_field(
                        &format!("Stage {}", i),
                        &format!("{} layers [{}, {})", address, start, end),
                    );
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct MembersCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl MembersCmd {
    pub async fn execute(self) -> Result<()> {
        output::print_header("Cluster Members");

        let spinner = output::create_spinner("Discovering members on the local network...");
        let rpc = rpc::RpcClient::new(&self.rpc);
        let result: Result<serde_json::Value> =
            rpc.call("tenzro_clusterMembers", serde_json::json!({})).await;
        spinner.finish_and_clear();

        let value = match result {
            Ok(v) => v,
            Err(e) => {
                output::print_error(&format!("Failed to discover cluster members: {}", e));
                return Ok(());
            }
        };

        println!();
        if let Some(n) = value.get("member_count").and_then(|v| v.as_u64()) {
            output::print_field("Total", &n.to_string());
        }
        if let Some(n) = value.get("local_count").and_then(|v| v.as_u64()) {
            output::print_field("On LAN", &n.to_string());
        }
        if let Some(g) = value.get("total_vram_gb").and_then(|v| v.as_f64()) {
            output::print_field("Pooled Memory", &format!("{:.1} GB", g));
        }

        if let Some(members) = value.get("members").and_then(|v| v.as_array()) {
            println!();
            for m in members {
                let address = m.get("address").and_then(|v| v.as_str()).unwrap_or("?");
                let vram = m.get("vram_gb").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let backend = m.get("backend").and_then(|v| v.as_str()).unwrap_or("?");
                let reach = m.get("reachability").and_then(|v| v.as_str()).unwrap_or("?");
                let head = if m.get("is_head").and_then(|v| v.as_bool()).unwrap_or(false) {
                    " [head]"
                } else {
                    ""
                };
                output::print_field(
                    &format!("  {}", address),
                    &format!("{:.1} GB {} {}{}", vram, backend, reach, head),
                );
            }
        }

        Ok(())
    }
}
