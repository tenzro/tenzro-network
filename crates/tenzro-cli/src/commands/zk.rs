//! Zero-knowledge proof commands for the Tenzro CLI
//!
//! Create proofs, verify proofs, and list circuits.

use clap::{Parser, Subcommand};
use anyhow::Result;
use crate::output;

/// ZK proof operations
#[derive(Debug, Subcommand)]
pub enum ZkCommand {
    /// Create a Plonky3 STARK proof
    Prove(ZkProveCmd),
    /// Verify a Plonky3 STARK proof
    Verify(ZkVerifyCmd),
    /// List available ZK circuits
    Circuits(ZkCircuitsCmd),
    /// File a fraud proof against an attested commitment
    FileFraudProof(ZkFileFraudProofCmd),
    /// Read the fraud-window record for a commitment
    Attestation(ZkAttestationCmd),
}

impl ZkCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Prove(cmd) => cmd.execute().await,
            Self::Verify(cmd) => cmd.execute().await,
            Self::Circuits(cmd) => cmd.execute().await,
            Self::FileFraudProof(cmd) => cmd.execute().await,
            Self::Attestation(cmd) => cmd.execute().await,
        }
    }
}

/// Create a Plonky3 STARK proof.
///
/// Pass per-circuit witness fields in `--witness` as a JSON object. See
/// `tenzro zk circuits` for the expected fields per circuit:
///   inference: {model_checksum, input_checksum, computed_output}
///   settlement: {service_proof, amount}
///   identity: {private_key, capabilities, capability_blinding}
#[derive(Debug, Parser)]
pub struct ZkProveCmd {
    /// Circuit identifier — one of `inference`, `settlement`, `identity`.
    #[arg(long)]
    circuit_id: String,
    /// JSON object of witness field-element values (decimal u64 each).
    #[arg(long)]
    witness: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ZkProveCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Create ZK Proof");
        let spinner = output::create_spinner("Generating proof...");
        let rpc = RpcClient::new(&self.rpc);

        let mut params: serde_json::Value = serde_json::from_str(&self.witness)?;
        if let Some(obj) = params.as_object_mut() {
            obj.insert("circuit_id".to_string(), serde_json::Value::String(self.circuit_id.clone()));
        } else {
            anyhow::bail!("--witness must be a JSON object");
        }

        let result: serde_json::Value = rpc.call("tenzro_createZkProof", params).await?;

        spinner.finish_and_clear();

        output::print_success("Proof generated!");
        output::print_field("Circuit", &self.circuit_id);
        output::print_field("Proof", &output::format_hash(result.get("proof").and_then(|v| v.as_str()).unwrap_or("")));
        if let Some(size) = result.get("proof_size_bytes").and_then(|v| v.as_u64()) {
            output::print_field("Size (bytes)", &size.to_string());
        }

        Ok(())
    }
}

/// Verify a Plonky3 STARK proof
#[derive(Debug, Parser)]
pub struct ZkVerifyCmd {
    /// Proof data (hex)
    #[arg(long)]
    proof: String,
    /// Circuit identifier — one of `inference`, `settlement`, `identity`.
    #[arg(long)]
    circuit_id: String,
    /// Public inputs (JSON array of hex strings — 4-byte LE KoalaBear chunks).
    #[arg(long)]
    inputs: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ZkVerifyCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Verify ZK Proof");
        let spinner = output::create_spinner("Verifying...");
        let rpc = RpcClient::new(&self.rpc);

        let public_inputs: serde_json::Value = serde_json::from_str(&self.inputs)?;

        let result: serde_json::Value = rpc.call("tenzro_verifyZkProof", serde_json::json!({
            "proof": self.proof,
            "circuit_id": self.circuit_id,
            "public_inputs": public_inputs,
        })).await?;

        spinner.finish_and_clear();

        let valid = result.get("valid").and_then(|v| v.as_bool()).unwrap_or(false);
        if valid {
            output::print_success("Proof is valid!");
            if let Some(commitment) = result.get("commitment_hex").and_then(|v| v.as_str()) {
                output::print_field("Commitment", commitment);
            }
            let newly = result.get("newly_attested").and_then(|v| v.as_bool()).unwrap_or(false);
            output::print_field(
                "Attested",
                if newly {
                    "yes (2f+1 quorum reached)"
                } else {
                    "not yet (quorum still collecting across the validator set)"
                },
            );
        } else {
            output::print_error("Proof verification failed.");
            if let Some(err) = result.get("error").and_then(|v| v.as_str()) {
                output::print_field("Error", err);
            }
        }

        Ok(())
    }
}

/// File a fraud proof against an attested ZK commitment.
///
/// The node fetches the proof from the commitment's DA locator, re-runs the
/// Plonky3 verifier deterministically, and adjudicates. If the proof fails
/// re-verification the commitment is retracted and every co-signer on the
/// certificate is slashed; if it re-verifies the commitment stands.
#[derive(Debug, Parser)]
pub struct ZkFileFraudProofCmd {
    /// Hex-encoded 32-byte commitment hash (with or without 0x prefix).
    #[arg(long)]
    commitment: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ZkFileFraudProofCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("File ZK Fraud Proof");
        let spinner = output::create_spinner("Re-verifying proof...");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_fileZkFraudProof", serde_json::json!({
            "commitment": self.commitment,
        })).await?;

        spinner.finish_and_clear();

        let upheld = result.get("upheld").and_then(|v| v.as_bool()).unwrap_or(false);
        if upheld {
            output::print_success("Fraud proof upheld — commitment retracted, co-signers slashed.");
        } else {
            output::print_info("Fraud proof unfounded — commitment re-verified and stands.");
        }
        if let Some(note) = result.get("note").and_then(|v| v.as_str()) {
            output::print_field("Note", note);
        }

        Ok(())
    }
}

/// Read the fraud-window record for a ZK commitment.
#[derive(Debug, Parser)]
pub struct ZkAttestationCmd {
    /// Hex-encoded 32-byte commitment hash (with or without 0x prefix).
    #[arg(long)]
    commitment: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ZkAttestationCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("ZK Attestation");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_getZkAttestation", serde_json::json!({
            "commitment": self.commitment,
        })).await?;

        let attested_present = result.get("circuit_id").is_some();
        if !attested_present {
            output::print_info("No open fraud window for this commitment.");
            let on_chain = result.get("on_chain_attested").and_then(|v| v.as_bool()).unwrap_or(false);
            output::print_field("On-chain attested", if on_chain { "yes" } else { "no" });
            return Ok(());
        }

        if let Some(circuit) = result.get("circuit_id").and_then(|v| v.as_str()) {
            output::print_field("Circuit", circuit);
        }
        if let Some(power) = result.get("voting_power").and_then(|v| v.as_str()) {
            output::print_field("Voting power", power);
        }
        if let Some(h) = result.get("attested_at_height").and_then(|v| v.as_u64()) {
            output::print_field("Attested at height", &h.to_string());
        }
        if let Some(h) = result.get("fraud_window_closes_at").and_then(|v| v.as_u64()) {
            output::print_field("Fraud window closes at", &h.to_string());
        }
        let open = result.get("fraud_window_open").and_then(|v| v.as_bool()).unwrap_or(false);
        output::print_field("Fraud window", if open { "open" } else { "closed" });
        if let Some(loc) = result.get("proof_locator").and_then(|v| v.as_str()) {
            output::print_field("Proof locator", loc);
        }
        let on_chain = result.get("on_chain_attested").and_then(|v| v.as_bool()).unwrap_or(false);
        output::print_field("On-chain attested", if on_chain { "yes" } else { "no" });

        Ok(())
    }
}

/// List ZK circuits
#[derive(Debug, Parser)]
pub struct ZkCircuitsCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ZkCircuitsCmd {
    pub async fn execute(&self) -> Result<()> {
        use crate::rpc::RpcClient;

        output::print_header("Available ZK Circuits");
        let rpc = RpcClient::new(&self.rpc);

        let result: serde_json::Value = rpc.call("tenzro_listZkCircuits", serde_json::json!([])).await?;

        if let Some(circuits) = result.as_array() {
            if circuits.is_empty() {
                output::print_info("No circuits available.");
            } else {
                for c in circuits {
                    let name = c.get("name").and_then(|v| v.as_str()).unwrap_or("?");
                    let desc = c.get("description").and_then(|v| v.as_str()).unwrap_or("");
                    output::print_field(name, desc);
                }
            }
        } else {
            output::print_json(&result)?;
        }

        Ok(())
    }
}
