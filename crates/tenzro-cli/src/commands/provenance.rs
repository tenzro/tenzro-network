//! C2PA-style provenance inspection.
//!
//! Under EU AI Act Article 50(2), synthetic content must carry a
//! machine-readable origin marker. Tenzro records a `ProvenanceManifest`
//! per piece of generated content, keyed by `content_hash`. Validators
//! sign and persist these manifests; this command lets operators and
//! verifiers fetch the cached manifest for a given content hash.
//!
//! Backed by `tenzro_getProvenance`.

use anyhow::Result;
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

    /// Output format (text, json)
    #[arg(long, default_value = "text")]
    format: String,

    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ProvenanceGetCmd {
    pub async fn execute(&self) -> Result<()> {
        output::print_header("Provenance Manifest");
        let rpc = RpcClient::new(&self.rpc);
        let result: Result<serde_json::Value> = rpc
            .call(
                "tenzro_getProvenance",
                serde_json::json!({ "content_hash": self.content_hash }),
            )
            .await;

        let manifest = match result {
            Ok(m) => m,
            // -32004 is the "no manifest recorded" miss — a normal outcome,
            // not an error the operator needs a backtrace for.
            Err(e) if e.to_string().contains("[-32004]") => {
                output::print_info(&format!(
                    "No provenance manifest recorded for {}",
                    self.content_hash
                ));
                return Ok(());
            }
            Err(e) => return Err(e),
        };

        if self.format == "json" {
            output::print_json(&manifest)?;
            return Ok(());
        }

        // Structured render of the fields a verifier cares about. `assertion`
        // is the EU AI Act Art. 50 content marker ("ai-generated" for ordinary
        // inference outputs, "deepfake" for imitations of a real person/place/
        // event under Art. 50(4)).
        if let Some(assertion) = manifest.get("assertion").and_then(|v| v.as_str()) {
            output::print_field("Assertion", assertion);
        }
        if let Some(model_id) = manifest.get("model_id").and_then(|v| v.as_str()) {
            output::print_field("Model", model_id);
        }
        if let Some(provider) = manifest.get("provider") {
            output::print_field("Provider", &bytes_to_hex(provider));
        }
        if let Some(signed_at) = manifest.get("signed_at").and_then(|v| v.as_i64()) {
            output::print_field("Signed at", &signed_at.to_string());
        }
        if let Some(algorithm) = manifest.get("algorithm").and_then(|v| v.as_str()) {
            output::print_field("Signature algorithm", algorithm);
        }
        let content_hash = manifest
            .get("content_hash")
            .map(bytes_to_hex)
            .unwrap_or_else(|| self.content_hash.clone());
        output::print_field("Content hash", &content_hash);

        Ok(())
    }
}

/// Render a serde JSON value that is a byte array (`[u8; N]` serializes as a
/// number array) as a lowercase hex string. Non-array values fall back to a
/// compact JSON string so nothing is silently dropped.
fn bytes_to_hex(value: &serde_json::Value) -> String {
    match value.as_array() {
        Some(arr) => arr
            .iter()
            .filter_map(|v| v.as_u64())
            .map(|b| format!("{:02x}", b as u8))
            .collect(),
        None => value.to_string(),
    }
}
