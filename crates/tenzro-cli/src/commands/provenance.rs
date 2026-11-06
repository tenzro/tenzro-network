//! C2PA-style provenance inspection.
//!
//! Under EU AI Act Article 50(2), synthetic content must carry a
//! machine-readable origin marker. Tenzro records a `ContentProvenanceManifest`
//! per piece of generated content, keyed by `content_hash`. Validators
//! sign and persist these manifests; this command lets operators and
//! verifiers fetch the cached manifest for a given content hash.
//!
//! Backed by `tenzro_getContentProvenance`.

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::output;
use crate::rpc::RpcClient;

/// Provenance operations.
#[derive(Debug, Subcommand)]
pub enum ProvenanceCommand {
    /// Fetch the provenance manifest for a given content hash.
    Get(ProvenanceGetCmd),
    /// Verify offline where a trained model came from: its trainer's signed
    /// receipt, every round on chain, each milestone released, from the
    /// chain's genesis anchor alone
    Model(ProvenanceModelCmd),
}

impl ProvenanceCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Get(cmd) => cmd.execute().await,
            Self::Model(cmd) => cmd.execute(),
        }
    }
}

/// `tenzro provenance model`: verify a trained model's provenance pack
/// (`tenzro_trainedModelProvenance`) against the chain's genesis anchor.
#[derive(Debug, Parser)]
pub struct ProvenanceModelCmd {
    /// The provenance pack
    #[arg(long)]
    file: std::path::PathBuf,
    /// Chain id, from the genesis file
    #[arg(long)]
    chain_id: u64,
    /// Genesis block hash, hex
    #[arg(long)]
    genesis_hash: String,
    /// Root of the genesis committee, hex
    #[arg(long)]
    genesis_committee_root: String,
    /// Image id of the handover program, hex, when the pack's checkpoint is
    /// certified from a handover chain proof
    #[arg(long)]
    handover_program: Option<String>,
    /// The weights file, to check it is the one the receipt names
    #[arg(long)]
    weights: Option<std::path::PathBuf>,
}

impl ProvenanceModelCmd {
    pub fn execute(&self) -> Result<()> {
        use super::evidence::hex32;
        let pack: tenzro_types::training_provenance::TrainingProvenancePack =
            serde_json::from_slice(&std::fs::read(&self.file)?)?;
        let anchor = tenzro_consensus::light_client::GenesisAnchor {
            chain_id: self.chain_id,
            genesis_hash: hex32(&self.genesis_hash, "--genesis-hash")?,
            committee_root: hex32(&self.genesis_committee_root, "--genesis-committee-root")?,
        };
        let program = self
            .handover_program
            .as_deref()
            .map(|h| hex32(h, "--handover-program"))
            .transpose()?;
        let report = tenzro_consensus::training_provenance::verify_provenance(
            &pack,
            &anchor,
            program,
            tenzro_zk::handover_chain::verify_receipt,
        )
        .map_err(|e| anyhow::anyhow!(e))?;
        if let Some(path) = &self.weights
            && !tenzro_consensus::training_provenance::weights_match(
                &report.receipt,
                &std::fs::read(path)?,
            )
        {
            anyhow::bail!("the weights file is not the one the receipt names");
        }
        output::print_header("Trained model provenance verified");
        output::print_field("Model", &report.receipt.model_id);
        output::print_field("Trainer", &report.receipt.trainer_did);
        output::print_field("Base weights", &report.receipt.base_sha256);
        output::print_field("Output weights", &report.receipt.output_sha256);
        output::print_field(
            "Weights file",
            if self.weights.is_some() {
                "matches"
            } else {
                "not checked"
            },
        );
        output::print_field("Certified checkpoint", &report.checkpoint.to_string());
        for r in &report.rounds {
            output::print_field(
                &format!("Round {}", r.round),
                &format!(
                    "dataset {} attested {} escrow {} released",
                    r.shard_commitment, r.attested, r.escrow_id
                ),
            );
        }
        Ok(())
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
                "tenzro_getContentProvenance",
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
