//! C2PA-style provenance inspection.
//!
//! Under EU AI Act Article 50(2), synthetic content must carry a
//! machine-readable origin marker. Tenzro records a `ProvenanceManifest`
//! per piece of generated content, keyed by `content_hash`. Validators
//! sign and persist these manifests; this command lets operators and
//! verifiers fetch the cached manifest for a given content hash.
//!
//! Backed by `tenzro_getProvenance`.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

/// Provenance operations.
#[derive(Debug, Subcommand)]
pub enum ProvenanceCommand {
    /// Fetch the provenance manifest for a given content hash.
    Get(ProvenanceGetCmd),
}

impl ProvenanceCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Get(cmd) => cmd.execute().await,
        }
    }
}

/// `tenzro provenance get <content_hash>` — return the cached manifest.
/// JSON-RPC error `-32004` if no manifest is recorded for that hash.
#[derive(Debug, Parser)]
pub struct ProvenanceGetCmd {
    /// Content hash (32 bytes hex, 0x-prefix optional).
    content_hash: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProvenanceGetCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Provenance Manifest");
        let rpc = RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_getProvenance",
                serde_json::json!({ "content_hash": self.content_hash }),
            )
            .await
            .context("calling tenzro_getProvenance")?;
        output::print_json(&result)?;
        Ok(())
    }
}
