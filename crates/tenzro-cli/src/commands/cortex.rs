//! Cortex recurrent-depth reasoning commands for the Tenzro CLI.
//!
//! Cortex is Tenzro's network-level reasoning primitive: depth (loops),
//! cost, and attestation are all caller-controlled, priced on-chain, and
//! cryptographically verified via signed receipts. Every inference can be
//! settled in TNZO at the ledger layer.
//!
//! Tagline: "Cortex reasons. Praecise governs. Tenzro settles."
//! (Praecise is an open AI governance framework by Ipnops; Tenzro
//! integrates with it but does not own it.)

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;

/// Cortex (recurrent-depth reasoning) operations
#[derive(Debug, Subcommand)]
pub enum CortexCommand {
    /// Register a new Cortex worker backed by an HTTP sidecar
    Register(CortexRegisterCmd),
    /// List all registered Cortex workers on the local node
    List(CortexListCmd),
    /// Run a Cortex reasoning inference against a registered worker
    Reason(CortexReasonCmd),
}

impl CortexCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Register(cmd) => cmd.execute().await,
            Self::List(cmd) => cmd.execute().await,
            Self::Reason(cmd) => cmd.execute().await,
        }
    }
}

/// Register a Cortex worker with an HTTP sidecar backend.
#[derive(Debug, Parser)]
pub struct CortexRegisterCmd {
    /// Model identifier (e.g. `openmythos-7b`)
    #[arg(long)]
    model_id: String,
    /// HTTP sidecar base URL serving the recurrent-depth backend
    #[arg(long, default_value = "http://127.0.0.1:8799")]
    sidecar_url: String,
    /// Optional bearer token for authenticating to the sidecar
    #[arg(long)]
    bearer_token: Option<String>,
    /// Architecture label: `rdt-moe`, `rdt-gqa`, etc.
    #[arg(long, default_value = "rdt-moe")]
    arch: String,
    /// Maximum recurrent-depth loops the worker will execute
    #[arg(long, default_value = "32")]
    max_loops: u32,
    /// Total MoE experts
    #[arg(long, default_value = "64")]
    moe_experts: u32,
    /// Experts activated per token (top-k)
    #[arg(long, default_value = "2")]
    experts_per_token: u32,
    /// Attention type: `mla`, `gqa`, `mha`
    #[arg(long, default_value = "mla")]
    attn_type: String,
    /// Explicit worker DID. Default: `did:tenzro:machine:cortex-<model_id>`
    #[arg(long)]
    worker_did: Option<String>,
    /// Sidecar request timeout in seconds
    #[arg(long, default_value = "120")]
    timeout_secs: u64,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl CortexRegisterCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Register Cortex Worker");
        let spinner = output::create_spinner("Registering worker...");
        let rpc = RpcClient::new(&self.rpc);

        let mut params = serde_json::json!({
            "model_id": self.model_id,
            "sidecar_url": self.sidecar_url,
            "arch": self.arch,
            "max_loops": self.max_loops,
            "moe_experts": self.moe_experts,
            "experts_per_token": self.experts_per_token,
            "attn_type": self.attn_type,
            "timeout_secs": self.timeout_secs,
        });
        if let Some(tok) = &self.bearer_token {
            params["bearer_token"] = serde_json::Value::String(tok.clone());
        }
        if let Some(did) = &self.worker_did {
            params["worker_did"] = serde_json::Value::String(did.clone());
        }

        let result: serde_json::Value = rpc.call("tenzro_registerCortexWorker", params).await?;
        spinner.finish_and_clear();

        output::print_success("Cortex worker registered");
        output::print_field(
            "Model ID",
            result.get("model_id").and_then(|v| v.as_str()).unwrap_or(""),
        );
        output::print_field(
            "Worker DID",
            result
                .get("worker_did")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        );
        output::print_field(
            "Sidecar",
            result
                .get("sidecar_url")
                .and_then(|v| v.as_str())
                .unwrap_or(""),
        );
        Ok(())
    }
}

/// List registered Cortex workers.
#[derive(Debug, Parser)]
pub struct CortexListCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Emit raw JSON instead of formatted fields
    #[arg(long)]
    json: bool,
}

impl CortexListCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value =
            rpc.call("tenzro_listCortexWorkers", serde_json::json!({})).await?;

        if self.json {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }

        output::print_header("Registered Cortex Workers");
        let workers = result
            .get("workers")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if workers.is_empty() {
            output::print_info("No Cortex workers registered on this node.");
            return Ok(());
        }
        for w in workers {
            let model_id = w.get("model_id").and_then(|v| v.as_str()).unwrap_or("?");
            let worker_did = w.get("worker_did").and_then(|v| v.as_str()).unwrap_or("?");
            output::print_field("Model", model_id);
            output::print_field("DID", worker_did);
            if let Some(family) = w.get("family") {
                output::print_field("Family", &family.to_string());
            }
            if let Some(pricing) = w.get("pricing") {
                output::print_field("Pricing", &pricing.to_string());
            }
            println!();
        }
        Ok(())
    }
}

/// Run a Cortex reasoning request against a registered worker.
#[derive(Debug, Parser)]
pub struct CortexReasonCmd {
    /// Model identifier of a registered Cortex worker
    #[arg(long)]
    model_id: String,
    /// Input text/prompt
    #[arg(long)]
    input: String,
    /// Reasoning tier: `fast`, `standard`, `deep`, `institutional`
    #[arg(long, default_value = "standard")]
    tier: String,
    /// Minimum recurrent-depth loops
    #[arg(long, default_value = "8")]
    min_loops: u32,
    /// Maximum recurrent-depth loops
    #[arg(long, default_value = "16")]
    max_loops: u32,
    /// Max cost budget in smallest TNZO unit
    #[arg(long, default_value = "1000000")]
    max_cost_tnzo: u64,
    /// Attestation requirement: `none`, `tee`, `zk`, `tee+zk`
    #[arg(long, default_value = "none")]
    attestation: String,
    /// Requester address (hex, 32 bytes). Default: zero — skips settlement.
    #[arg(long)]
    requester: Option<String>,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
    /// Emit raw JSON instead of formatted fields
    #[arg(long)]
    json: bool,
}

impl CortexReasonCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Cortex Reasoning");
        let spinner = output::create_spinner(&format!(
            "Reasoning with {} loops (tier={})...",
            self.max_loops, self.tier
        ));
        let rpc = RpcClient::new(&self.rpc);

        let mut params = serde_json::json!({
            "model_id": self.model_id,
            "input": self.input,
            "tier": self.tier,
            "min_loops": self.min_loops,
            "max_loops": self.max_loops,
            "max_cost_tnzo": self.max_cost_tnzo,
            "attestation": self.attestation,
        });
        if let Some(r) = &self.requester {
            params["requester"] = serde_json::Value::String(r.clone());
        }

        let result: serde_json::Value = rpc.call("tenzro_cortexReason", params).await?;
        spinner.finish_and_clear();

        if self.json {
            println!("{}", serde_json::to_string_pretty(&result)?);
            return Ok(());
        }

        output::print_success("Inference complete");
        // The RPC returns the response at the top level plus a `settled` flag.
        if let Some(output_text) = result.get("output_text").and_then(|v| v.as_str()) {
            output::print_field("Output", output_text);
        } else if let Some(hex_out) = result.get("output").and_then(|v| v.as_str()) {
            output::print_field("Output (hex)", hex_out);
        }
        if let Some(price) = result.get("price_tnzo").and_then(|v| v.as_u64()) {
            output::print_field("Price (TNZO)", &price.to_string());
        }
        if let Some(meta) = result.get("metadata") {
            if let Some(loops) = meta.get("loops_used").and_then(|v| v.as_u64()) {
                output::print_field("Loops used", &loops.to_string());
            }
            if let Some(ti) = meta.get("input_tokens").and_then(|v| v.as_u64()) {
                output::print_field("Tokens in", &ti.to_string());
            }
            if let Some(to) = meta.get("output_tokens").and_then(|v| v.as_u64()) {
                output::print_field("Tokens out", &to.to_string());
            }
        }
        if let Some(settled) = result.get("settled").and_then(|v| v.as_bool()) {
            output::print_field("Settled on-chain", if settled { "yes" } else { "no" });
        }
        if let Some(receipt) = result.get("receipt") {
            if let Some(sig) = receipt.get("signature") {
                output::print_field("Receipt sig", &sig.to_string());
            }
        }
        Ok(())
    }
}
