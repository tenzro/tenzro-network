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
}

impl ZkCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Prove(cmd) => cmd.execute().await,
            Self::Verify(cmd) => cmd.execute().await,
            Self::Circuits(cmd) => cmd.execute().await,
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
        } else {
            output::print_error("Proof verification failed.");
            if let Some(err) = result.get("error").and_then(|v| v.as_str()) {
                output::print_field("Error", err);
            }
        }

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
