//! Generative media commands for the Tenzro CLI.
//!
//! A node renders images, video, audio, 3D assets (GLB) and action chunks
//! with the media models it loads.
//! Subcommands wrap `tenzro_mediaGen_listCatalog` and `tenzro_mediaGen_render`.

use crate::output;
use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};

const DEFAULT_RPC: &str = "http://127.0.0.1:8545";

/// Generative media operations
#[derive(Debug, Subcommand)]
pub enum MediaGenCommand {
    /// List the curated generative-media model catalog
    Catalog(MediaGenCatalogCmd),
    /// Render one output now, on this node or a provider serving the model
    Render(MediaGenRenderCmd),
}

impl MediaGenCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Catalog(c) => c.execute().await,
            Self::Render(c) => c.execute().await,
        }
    }
}

/// Read a JSON file into a `Value`, reporting the path on failure.
fn read_json(path: &str, what: &str) -> Result<serde_json::Value> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("read {} file '{}': {}", what, path, e))?;
    serde_json::from_str(&text).map_err(|e| anyhow!("parse {} JSON: {}", what, e))
}

// ---------------------------------------------------------------------------
// Catalog
// ---------------------------------------------------------------------------

#[derive(Debug, Parser)]
pub struct MediaGenCatalogCmd {
    /// Only entries serving this kind (text2image, image2image, text2video, image2video, text2audio, image23d, text23d, action_policy, world_model)
    #[arg(long)]
    kind: Option<String>,

    /// RPC endpoint
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,
}

impl MediaGenCatalogCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_mediaGen_listCatalog", serde_json::json!({}))
            .await?;

        let models: Vec<serde_json::Value> = result
            .get("models")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter(|m| match &self.kind {
                Some(k) => m
                    .get("kinds")
                    .and_then(|v| v.as_array())
                    .map(|a| a.iter().any(|x| x.as_str() == Some(k.as_str())))
                    .unwrap_or(false),
                None => true,
            })
            .collect();

        if self.format == "json" {
            println!("{}", serde_json::to_string_pretty(&models)?);
            return Ok(());
        }

        output::print_header("Media Gen Catalog");
        if models.is_empty() {
            output::print_info("No matching models.");
            return Ok(());
        }
        for m in &models {
            let id = m.get("id").and_then(|v| v.as_str()).unwrap_or("?");
            let kinds = m
                .get("kinds")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str())
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default();
            // An expert pair means the denoising schedule splits across two
            // machines, which is the only reason a claim needs a role.
            let split = if m.get("expert_pair").map(|v| !v.is_null()).unwrap_or(false) {
                " [split]"
            } else {
                ""
            };
            output::print_field(id, &format!("{}{}", kinds, split));
        }
        output::print_info(&format!("{} model(s)", models.len()));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

/// Render one output synchronously (`tenzro_mediaGen_render`). The answer
/// carries what its signed receipt commits to (the output's SHA-256 and
/// perceptual fingerprint) and `output_blake3`, under which the output is
/// fetched; `--out` fetches and writes it.
#[derive(Debug, Parser)]
pub struct MediaGenRenderCmd {
    /// Catalog model id
    #[arg(long)]
    model: String,

    /// Media kind (text2image, image2image, text2video, image2video, text2audio, image23d, action_policy, world_model)
    #[arg(long)]
    kind: String,

    /// Path to a JSON file containing `MediaGenParams`, with a `seed`
    #[arg(long)]
    params: String,

    /// A file holding one of the inputs `params.inputs` names by SHA-256, in their order; repeatable
    #[arg(long = "input")]
    inputs: Vec<String>,

    /// Verification the answer must carry: none, receipt, optimistic or tee
    #[arg(long)]
    verification: Option<String>,

    /// Write the rendered output to this path
    #[arg(long)]
    out: Option<String>,

    /// A signed channel voucher (`tenzro escrow voucher --out`) the render's
    /// metered cost is charged against
    #[arg(long)]
    channel_voucher: Option<String>,

    /// Print the whole answer as JSON (receipt, units, settlement)
    #[arg(long)]
    json: bool,

    /// RPC endpoint
    #[arg(long, default_value = DEFAULT_RPC)]
    rpc: String,
}

impl MediaGenRenderCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;
        use base64::Engine as _;

        let mut inputs = Vec::new();
        for path in &self.inputs {
            let bytes = std::fs::read(path).map_err(|e| anyhow!("read input '{path}': {e}"))?;
            inputs.push(base64::engine::general_purpose::STANDARD.encode(bytes));
        }
        let mut req = serde_json::json!({
            "model_id": self.model,
            "kind": self.kind,
            "params": read_json(&self.params, "params")?,
            "inputs_base64": inputs,
        });
        if let Some(v) = &self.verification {
            req["verification"] = v.as_str().into();
        }
        if let Some(path) = &self.channel_voucher {
            req["channel_voucher"] = read_json(path, "channel voucher")?;
        }
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_mediaGen_render", req).await?;

        if self.json {
            output::print_json(&result)?;
        } else {
            output::print_header("Media Render");
            for key in [
                "mime",
                "output_sha256",
                "output_blake3",
                "cost_wei",
                "provider",
            ] {
                if let Some(v) = result.get(key).and_then(|v| v.as_str()) {
                    output::print_field(key, v);
                }
            }
            if let Some(n) = result.get("output_bytes").and_then(|v| v.as_u64()) {
                output::print_field("output_bytes", &n.to_string());
            }
        }
        if let (Some(out), Some(hash)) = (
            &self.out,
            result.get("output_blake3").and_then(|v| v.as_str()),
        ) {
            let blob: serde_json::Value = rpc
                .call(
                    "tenzro_iroh_fetchBlob",
                    serde_json::json!({ "tenzro_uri": format!("tenzro://blob/{hash}") }),
                )
                .await?;
            let bytes = blob
                .get("bytes_b64")
                .and_then(|v| v.as_str())
                .map(|d| base64::engine::general_purpose::STANDARD.decode(d))
                .ok_or_else(|| anyhow!("the blob answer carried no bytes"))?
                .map_err(|e| anyhow!("decode output: {e}"))?;
            std::fs::write(out, &bytes).map_err(|e| anyhow!("write '{out}': {e}"))?;
            if self.json {
                eprintln!("written {} bytes to {out}", bytes.len());
            } else {
                output::print_field("written", &format!("{} bytes to {out}", bytes.len()));
            }
        }
        Ok(())
    }
}
