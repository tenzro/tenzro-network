//! Iroh consumer surface commands for the Tenzro CLI.
//!
//! Wraps the `tenzro_iroh_*` JSON-RPC namespace exposed by `tenzro-node`,
//! which in turn fronts the shared `IrohBackedResolver`. The same QUIC +
//! Pkarr + iroh-blobs substrate backs:
//!
//! - the storage DA backend (`IrohBlobsDaBackend`),
//! - training outer-gradient distribution (`IrohGradientStore`),
//! - confidential sealed-shard distribution (`IrohSealedShardStore`),
//! - model-weight peer fetch (`IrohBlobFetcher`),
//! - the agent-memory archive DA path,
//! - and A2A JSON-RPC over the `tenzro/a2a` ALPN.
//!
//! Subcommands:
//!
//! - `tenzro iroh info`        — endpoint id, Pkarr relay, bound ALPNs
//! - `tenzro iroh endpoint-id` — z-base-32 + hex form of the iroh EndpointId
//! - `tenzro iroh alpns`       — list ALPNs registered on the shared router
//! - `tenzro iroh publish`     — push a local file into iroh-blobs, print the tenzro:// URI
//! - `tenzro iroh fetch`       — pull a `tenzro://blob|model|gradient|shard|receipt/...` URI

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand};

use crate::output;

/// Iroh content-addressed transport commands
#[derive(Debug, Subcommand)]
pub enum IrohCommand {
    /// Show endpoint id, Pkarr relay, and bound ALPNs
    Info(IrohInfoCmd),
    /// Print just the iroh EndpointId (z-base-32 + hex)
    EndpointId(IrohEndpointIdCmd),
    /// List ALPNs registered on the shared iroh router
    Alpns(IrohAlpnsCmd),
    /// Publish a local file as a tenzro:// blob
    Publish(IrohPublishCmd),
    /// Fetch a tenzro:// URI to a local file (or stdout)
    Fetch(IrohFetchCmd),
}

impl IrohCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Info(cmd) => cmd.execute().await,
            Self::EndpointId(cmd) => cmd.execute().await,
            Self::Alpns(cmd) => cmd.execute().await,
            Self::Publish(cmd) => cmd.execute().await,
            Self::Fetch(cmd) => cmd.execute().await,
        }
    }
}

#[derive(Debug, Parser)]
pub struct IrohInfoCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IrohInfoCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Iroh Endpoint Info");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_iroh_getInfo", serde_json::json!({}))
            .await?;

        for (key, val) in result.as_object().unwrap_or(&serde_json::Map::new()) {
            output::print_field(key, val.to_string().trim_matches('"'));
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct IrohEndpointIdCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IrohEndpointIdCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_iroh_getEndpointId", serde_json::json!({}))
            .await?;

        let id = result
            .get("endpoint_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let hex = result
            .get("endpoint_id_hex")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        println!("{}", id);
        if !hex.is_empty() {
            output::print_field("hex", hex);
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct IrohAlpnsCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IrohAlpnsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Iroh Bound ALPNs");

        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_iroh_listAlpns", serde_json::json!({}))
            .await?;

        let alpns = result
            .get("alpns")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        if alpns.is_empty() {
            output::print_warning("No ALPNs bound (iroh disabled?).");
            return Ok(());
        }
        for entry in &alpns {
            let alpn = entry.get("alpn").and_then(|v| v.as_str()).unwrap_or("?");
            let desc = entry
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            output::print_field(alpn, desc);
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct IrohPublishCmd {
    /// Path to the local file whose bytes should be published
    #[arg(long)]
    file: PathBuf,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IrohPublishCmd {
    pub async fn execute(&self) -> Result<()> {
        use base64::Engine as _;
        use crate::rpc::RpcClient;

        output::print_header("Publish to Iroh Blob Store");

        let bytes =
            std::fs::read(&self.file).with_context(|| format!("read {:?}", self.file))?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&bytes);

        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Publishing...");
        let result: serde_json::Value = rpc
            .call(
                "tenzro_iroh_publishBlob",
                serde_json::json!({ "bytes_b64": b64 }),
            )
            .await?;
        spinner.finish_and_clear();

        output::print_success("Published");
        for (key, val) in result.as_object().unwrap_or(&serde_json::Map::new()) {
            output::print_field(key, val.to_string().trim_matches('"'));
        }
        Ok(())
    }
}

#[derive(Debug, Parser)]
pub struct IrohFetchCmd {
    /// tenzro:// URI to fetch (blob / model / gradient / shard / receipt)
    #[arg(long)]
    uri: String,

    /// Output path; if omitted, writes raw bytes to stdout
    #[arg(long)]
    out: Option<PathBuf>,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl IrohFetchCmd {
    pub async fn execute(&self) -> Result<()> {
        use base64::Engine as _;
        use std::io::Write as _;
        use crate::rpc::RpcClient;

        let rpc = RpcClient::new(&self.rpc);
        let spinner = output::create_spinner("Fetching...");
        let result: serde_json::Value = rpc
            .call(
                "tenzro_iroh_fetchBlob",
                serde_json::json!({ "tenzro_uri": self.uri }),
            )
            .await?;
        spinner.finish_and_clear();

        let b64 = result
            .get("bytes_b64")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("response missing bytes_b64"))?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .context("decode bytes_b64")?;

        match &self.out {
            Some(path) => {
                std::fs::write(path, &bytes).with_context(|| format!("write {path:?}"))?;
                output::print_success("Fetched");
                output::print_field("path", &path.display().to_string());
                output::print_field("size_bytes", &bytes.len().to_string());
            }
            None => {
                std::io::stdout()
                    .write_all(&bytes)
                    .context("write bytes to stdout")?;
            }
        }
        Ok(())
    }
}
