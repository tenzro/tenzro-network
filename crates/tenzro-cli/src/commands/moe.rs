//! Decentralized MoE serving commands.

use anyhow::Result;
use base64::Engine;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

#[derive(Debug, Subcommand)]
pub enum MoeCommand {
    /// Show the live expert-shard map for a model (holders, replication,
    /// hot experts, under-replicated experts).
    ShardMap(ShardMapCmd),
    /// Build a dispatch plan from a JSON file of top-k routing decisions.
    /// Useful for inspecting how a request would fan out across holders
    /// before submitting it.
    PlanDispatch(PlanDispatchCmd),
    /// Show the current governance-tuned replication policy.
    ReplicationPolicy(RpcOnly),
    /// Show the catalog-side MoE topology for a model.
    CatalogShape(CatalogShapeCmd),
    /// Load a per-expert safetensors weight blob into the node's expert
    /// runtime, from a local file or a tenzro://blob URI.
    LoadExpert(LoadExpertCmd),
    /// Load a gating-network safetensors blob (router.weight) for a layer.
    LoadGate(LoadGateCmd),
    /// Unload one resident expert.
    UnloadExpert(UnloadExpertCmd),
    /// Unload one resident gating network.
    UnloadGate(UnloadGateCmd),
    /// Show the node's resident experts and gates.
    Status(StatusCmd),
    /// Run a distributed MoE forward for one layer: route locally, fan
    /// expert sub-batches out to holders, gather the combined outputs.
    Forward(ForwardCmd),
}

impl MoeCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::ShardMap(c) => c.execute().await,
            Self::PlanDispatch(c) => c.execute().await,
            Self::ReplicationPolicy(c) => c.execute().await,
            Self::CatalogShape(c) => c.execute().await,
            Self::LoadExpert(c) => c.execute().await,
            Self::LoadGate(c) => c.execute().await,
            Self::UnloadExpert(c) => c.execute().await,
            Self::UnloadGate(c) => c.execute().await,
            Self::Status(c) => c.execute().await,
            Self::Forward(c) => c.execute().await,
        }
    }
}

fn blob_params(file: &Option<String>, uri: &Option<String>) -> Result<serde_json::Value> {
    match (file, uri) {
        (Some(path), None) => {
            let bytes = std::fs::read(path)?;
            Ok(serde_json::json!({
                "blob_base64": base64::engine::general_purpose::STANDARD.encode(&bytes),
            }))
        }
        (None, Some(u)) => Ok(serde_json::json!({ "uri": u })),
        _ => anyhow::bail!("pass exactly one of --file or --uri"),
    }
}

fn default_rpc() -> String {
    "http://127.0.0.1:8545".to_string()
}

#[derive(Debug, Parser)]
pub struct RpcOnly {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl RpcOnly {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("MoE Replication Policy");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_moeReplicationPolicy", serde_json::json!({}))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ShardMapCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    /// Tenzro model id (e.g. `qwen3.5-397b-a17b`).
    #[arg(long)]
    model_id: String,
}

impl ShardMapCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header(&format!("MoE Shard Map — {}", self.model_id));
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_moeShardMap",
                serde_json::json!({ "model_id": self.model_id }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct PlanDispatchCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    /// Tenzro model id.
    #[arg(long)]
    model_id: String,
    /// Path to a JSON file containing an array of routing decisions —
    /// `[{token_index: u32, experts: [{layer: u32, expert: u32}, ...]}]`.
    #[arg(long)]
    routings_json: String,
    /// Allow cold-residency holders when no warm holder is available.
    #[arg(long, default_value_t = false)]
    allow_cold: bool,
}

impl PlanDispatchCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header(&format!("MoE Dispatch Plan — {}", self.model_id));
        let raw = std::fs::read_to_string(&self.routings_json)?;
        let routings: serde_json::Value = serde_json::from_str(&raw)?;
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_moePlanDispatch",
                serde_json::json!({
                    "model_id": self.model_id,
                    "allow_cold": self.allow_cold,
                    "routings": routings,
                }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct CatalogShapeCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    #[arg(long)]
    model_id: String,
}

impl CatalogShapeCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header(&format!("MoE Catalog Shape — {}", self.model_id));
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_moeCatalogShape",
                serde_json::json!({ "model_id": self.model_id }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct LoadExpertCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    #[arg(long)]
    model_id: String,
    #[arg(long)]
    layer: u32,
    #[arg(long)]
    expert: u32,
    /// Local safetensors file with gate_proj/up_proj/down_proj weights.
    #[arg(long)]
    file: Option<String>,
    /// Content-addressed tenzro://blob/<hash> URI (fetched over iroh-blobs).
    #[arg(long)]
    uri: Option<String>,
}

impl LoadExpertCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header(&format!(
            "MoE Load Expert — {} l{}/e{}",
            self.model_id, self.layer, self.expert
        ));
        let mut params = blob_params(&self.file, &self.uri)?;
        params["model_id"] = serde_json::json!(self.model_id);
        params["layer"] = serde_json::json!(self.layer);
        params["expert"] = serde_json::json!(self.expert);
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc.call("tenzro_moeExpertLoad", params).await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct LoadGateCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    #[arg(long)]
    model_id: String,
    #[arg(long)]
    layer: u32,
    /// Local safetensors file with the router.weight tensor.
    #[arg(long)]
    file: Option<String>,
    /// Content-addressed tenzro://blob/<hash> URI (fetched over iroh-blobs).
    #[arg(long)]
    uri: Option<String>,
}

impl LoadGateCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header(&format!(
            "MoE Load Gate — {} l{}",
            self.model_id, self.layer
        ));
        let mut params = blob_params(&self.file, &self.uri)?;
        params["model_id"] = serde_json::json!(self.model_id);
        params["layer"] = serde_json::json!(self.layer);
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc.call("tenzro_moeGateLoad", params).await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct UnloadExpertCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    #[arg(long)]
    model_id: String,
    #[arg(long)]
    layer: u32,
    #[arg(long)]
    expert: u32,
}

impl UnloadExpertCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header(&format!(
            "MoE Unload Expert — {} l{}/e{}",
            self.model_id, self.layer, self.expert
        ));
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_moeExpertUnload",
                serde_json::json!({
                    "model_id": self.model_id,
                    "layer": self.layer,
                    "expert": self.expert,
                }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct UnloadGateCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    #[arg(long)]
    model_id: String,
    #[arg(long)]
    layer: u32,
}

impl UnloadGateCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header(&format!(
            "MoE Unload Gate — {} l{}",
            self.model_id, self.layer
        ));
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call(
                "tenzro_moeGateUnload",
                serde_json::json!({
                    "model_id": self.model_id,
                    "layer": self.layer,
                }),
            )
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct StatusCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
}

impl StatusCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("MoE Expert Runtime Status");
        let rpc = RpcClient::new(&self.rpc);
        let v: serde_json::Value = rpc
            .call("tenzro_moeExpertStatus", serde_json::json!({}))
            .await?;
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct ForwardCmd {
    #[arg(long, default_value_t = default_rpc())]
    rpc: String,
    #[arg(long)]
    model_id: String,
    #[arg(long)]
    layer: u32,
    /// Hidden dimension per token.
    #[arg(long)]
    d_model: u32,
    /// Local file of raw little-endian f32 hidden states (n_tokens x d_model).
    #[arg(long)]
    hidden_file: String,
    /// Experts per token; defaults to the catalog experts_per_token.
    #[arg(long)]
    top_k: Option<u32>,
    /// Allow dispatch to experts that are not warm-resident.
    #[arg(long, default_value_t = false)]
    allow_cold: bool,
    /// Write the combined f32 outputs to this file instead of printing base64.
    #[arg(long)]
    out_file: Option<String>,
}

impl ForwardCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header(&format!(
            "MoE Forward — {} l{}",
            self.model_id, self.layer
        ));
        let bytes = std::fs::read(&self.hidden_file)?;
        if bytes.len() % 4 != 0 {
            anyhow::bail!("hidden-state file length must be a multiple of 4 (f32 LE)");
        }
        let rpc = RpcClient::new(&self.rpc);
        let mut v: serde_json::Value = rpc
            .call(
                "tenzro_moeForward",
                serde_json::json!({
                    "model_id": self.model_id,
                    "layer": self.layer,
                    "d_model": self.d_model,
                    "hidden_states": base64::engine::general_purpose::STANDARD.encode(&bytes),
                    "top_k": self.top_k,
                    "allow_cold": self.allow_cold,
                }),
            )
            .await?;
        if let Some(out) = &self.out_file {
            if let Some(b64) = v.get("outputs").and_then(|o| o.as_str()) {
                let decoded = base64::engine::general_purpose::STANDARD.decode(b64)?;
                std::fs::write(out, &decoded)?;
                v["outputs"] = serde_json::json!(format!("written to {out} ({} bytes)", decoded.len()));
            }
        }
        println!("{}", serde_json::to_string_pretty(&v)?);
        Ok(())
    }
}
