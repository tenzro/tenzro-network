//! Zero-knowledge proof commands for the Tenzro CLI
//!
//! Create proofs, verify proofs, and list circuits.

use crate::output;
use anyhow::{Context as _, Result};
use clap::{Parser, Subcommand};

/// ZK proof operations
#[derive(Debug, Subcommand)]
pub enum ZkCommand {
    #[command(flatten)]
    Rpc(ZkRpcCommand),
    /// Create a Plonky3 STARK proof
    Prove(ZkProveCmd),
    /// Verify a Plonky3 STARK proof
    Verify(ZkVerifyCmd),
    /// List available ZK circuits
    Circuits(ZkCircuitsCmd),
    /// Whether a commitment is attested on chain
    Attestation(ZkAttestationCmd),
}

impl ZkCommand {
    pub async fn execute(&self) -> Result<()> {
        match self {
            Self::Rpc(cmd) => cmd.execute().await,
            Self::Prove(cmd) => cmd.execute().await,
            Self::Verify(cmd) => cmd.execute().await,
            Self::Circuits(cmd) => cmd.execute().await,
            Self::Attestation(cmd) => cmd.execute().await,
        }
    }
}

/// Prove a statement on this machine, in every proof system.
///
/// The 32-byte witness is read as hex from standard input and never leaves
/// this process: it is not an argument (shell history), not a file, and not
/// sent to any node. The output is the proof bundle `tenzro zk verify` takes.
#[derive(Debug, Parser)]
pub struct ZkProveCmd {
    /// Circuit identifier — `identity` or `settlement`.
    #[arg(long)]
    circuit_id: String,
    /// 32-byte hex binding: the verifier's challenge or the request hash.
    #[arg(long)]
    binding: String,
}

fn parse_word(label: &str, hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim().trim_start_matches("0x"))
        .map_err(|e| anyhow::anyhow!("{label}: {e}"))?;
    bytes
        .try_into()
        .map_err(|b: Vec<u8>| anyhow::anyhow!("{label} must be 32 bytes, got {}", b.len()))
}

impl ZkProveCmd {
    pub async fn execute(&self) -> Result<()> {
        let circuit = tenzro_zk::Circuit::parse(&self.circuit_id)
            .ok_or_else(|| anyhow::anyhow!("unknown circuit {}", self.circuit_id))?;
        let binding = parse_word("--binding", &self.binding)?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        let witness = parse_word("witness (stdin)", &line)?;
        line.clear();

        output::print_header("Create ZK Proof");
        let spinner = output::create_spinner("Proving in every proof system...");
        let proofs = tokio::task::spawn_blocking(move || {
            tenzro_zk::ProofSystem::ALL
                .into_iter()
                .map(|system| tenzro_zk::prove(system, circuit, &witness, &binding))
                .collect::<tenzro_zk::Result<Vec<_>>>()
        })
        .await??;
        spinner.finish_and_clear();

        output::print_success("Proofs generated");
        output::print_json(&serde_json::json!({
            "circuit_id": circuit.id(),
            "public_inputs": proofs[0].public_inputs.iter().map(|p| format!("0x{}", hex::encode(p))).collect::<Vec<_>>(),
            "proofs": proofs.iter().map(|p| serde_json::json!({
                "system": p.system.as_str(),
                "proof": format!("0x{}", hex::encode(&p.proof_bytes)),
            })).collect::<Vec<_>>(),
        }))?;
        Ok(())
    }
}

/// Verify a proof bundle against a node.
#[derive(Debug, Parser)]
pub struct ZkVerifyCmd {
    /// Path to the JSON bundle printed by `tenzro zk prove`
    /// (`{circuit_id, public_inputs, proofs}`).
    #[arg(long)]
    bundle: std::path::PathBuf,
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

        let bundle: serde_json::Value = serde_json::from_slice(&std::fs::read(&self.bundle)?)?;
        let result: serde_json::Value = rpc.call("tenzro_verifyZkProof", bundle).await?;

        spinner.finish_and_clear();

        let valid = result
            .get("valid")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if valid {
            output::print_success("Proof is valid!");
            if let Some(statement) = result.get("statement_commitment").and_then(|v| v.as_str()) {
                output::print_field("Statement", statement);
            }
            let diverse = result
                .get("meets_diverse_threshold")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            output::print_field(
                "Submitted for attestation",
                if diverse {
                    "yes (verified in every proof system)"
                } else {
                    "no (needs a verifying proof in every proof system)"
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

/// Whether a ZK commitment is attested on chain.
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

        let result: serde_json::Value = rpc
            .call(
                "tenzro_getZkAttestation",
                serde_json::json!({
                    "commitment": self.commitment,
                }),
            )
            .await?;

        let on_chain = result
            .get("attested")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
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

        let result: serde_json::Value = rpc
            .call("tenzro_listZkCircuits", serde_json::json!([]))
            .await?;

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

/// Zk commands that call one node RPC each and print its answer
#[derive(Debug, clap::Subcommand)]
pub enum ZkRpcCommand {
    /// Call tenzro_createZkProof (create zk proof) and print the node's answer
    CreateProof(ZkCreateProofRpcCmd),
    /// Call tenzro_listCircuits (list circuits) and print the node's answer
    ListCircuits(ZkListCircuitsRpcCmd),
    /// Call tenzro_verifyTeeZkProof (verify tee zk proof) and print the node's answer
    VerifyTeeProof(ZkVerifyTeeProofRpcCmd),
    /// Call tenzro_createTeeZkProof (create tee zk proof) and print the node's answer
    CreateTeeZkProof(ZkCreateTeeZkProofRpcCmd),
    /// Bind a Groth16-wrapped finality proof made on this machine to an
    /// attestation of the node's TEE (tenzro_attestFinalityProof). The wrap
    /// rests on a classical assumption (BN254) and is not quantum-safe
    AttestFinalityProof(ZkAttestFinalityProofCmd),
    /// Verify a TEE-bound finality proof and print its measurement registers
    /// (tenzro_verifyTeeFinalityProof)
    VerifyTeeFinalityProof(ZkVerifyTeeFinalityProofCmd),
}

impl ZkRpcCommand {
    pub async fn execute(&self) -> anyhow::Result<()> {
        match self {
            Self::CreateProof(cmd) => cmd.execute().await,
            Self::ListCircuits(cmd) => cmd.execute().await,
            Self::VerifyTeeProof(cmd) => cmd.execute().await,
            Self::CreateTeeZkProof(cmd) => cmd.execute().await,
            Self::AttestFinalityProof(cmd) => cmd.execute().await,
            Self::VerifyTeeFinalityProof(cmd) => cmd.execute().await,
        }
    }
}

/// Prove a settlement statement on the node (tenzro_createZkProof)
#[derive(Debug, clap::Parser)]
pub struct ZkCreateProofRpcCmd {
    /// The 32-byte service result, hex
    #[arg(long)]
    witness: String,
    /// The 32-byte request binding, hex
    #[arg(long)]
    binding: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ZkCreateProofRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_createZkProof",
                serde_json::json!({ "circuit_id": "settlement", "witness": self.witness, "binding": self.binding }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_listCircuits (list circuits)
#[derive(Debug, clap::Parser)]
pub struct ZkListCircuitsRpcCmd {
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ZkListCircuitsRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call("tenzro_listCircuits", serde_json::json!([]))
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_verifyTeeZkProof (verify tee zk proof)
#[derive(Debug, clap::Parser)]
pub struct ZkVerifyTeeProofRpcCmd {
    /// tee zk proof (JSON)
    #[arg(long)]
    tee_zk_proof: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ZkVerifyTeeProofRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let tee_zk_proof: serde_json::Value =
            serde_json::from_str(&self.tee_zk_proof).context("--tee-zk-proof is not JSON")?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_verifyTeeZkProof",
                serde_json::json!({ "tee_zk_proof": tee_zk_proof }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}

/// Call tenzro_createTeeZkProof (create tee zk proof)
#[derive(Debug, clap::Parser)]
pub struct ZkCreateTeeZkProofRpcCmd {
    /// circuit id
    #[arg(long)]
    circuit_id: String,
    /// vendor
    #[arg(long)]
    vendor: String,
    /// witness
    #[arg(long)]
    witness: String,
    /// binding
    #[arg(long)]
    binding: String,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ZkCreateTeeZkProofRpcCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc.call("tenzro_createTeeZkProof", serde_json::json!({ "circuit_id": self.circuit_id, "vendor": self.vendor, "witness": self.witness, "binding": self.binding })).await?;
        crate::output::print_json(&result)
    }
}

/// Bind a Groth16-wrapped finality proof (a classical assumption over BN254,
/// not quantum-safe) to an attestation of the node's TEE
#[derive(Debug, clap::Parser)]
pub struct ZkAttestFinalityProofCmd {
    /// The proof JSON `tenzro-finality-prover wrap` wrote
    #[arg(long)]
    proof: std::path::PathBuf,
    /// Where to write the bound proof (JSON)
    #[arg(long)]
    out: std::path::PathBuf,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ZkAttestFinalityProofCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let raw = std::fs::read(&self.proof)
            .with_context(|| format!("reading {}", self.proof.display()))?;
        let proof: serde_json::Value =
            serde_json::from_slice(&raw).context("the proof is not JSON")?;
        let field = |k: &str| -> anyhow::Result<String> {
            proof
                .get(k)
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .with_context(|| format!("the proof has no {k}"))
        };
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_attestFinalityProof",
                serde_json::json!({
                    "image_id": field("image_id")?,
                    "journal": field("journal")?,
                    "seal": field("seal")?,
                }),
            )
            .await?;
        let bundle = result
            .get("tee_finality_proof")
            .context("the node returned no bundle")?;
        std::fs::write(&self.out, serde_json::to_vec_pretty(bundle)?)?;
        crate::output::print_json(&serde_json::json!({
            "vendor": result.get("vendor"),
            "binding_digest": result.get("binding_digest"),
            "measurements": result.get("measurements"),
            "written": self.out.display().to_string(),
        }))
    }
}

/// Verify a TEE-bound finality proof
#[derive(Debug, clap::Parser)]
pub struct ZkVerifyTeeFinalityProofCmd {
    /// The bound proof `attest-finality-proof` wrote
    #[arg(long)]
    bundle: std::path::PathBuf,
    /// RPC endpoint
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc: String,
}

impl ZkVerifyTeeFinalityProofCmd {
    pub async fn execute(&self) -> anyhow::Result<()> {
        let raw = std::fs::read(&self.bundle)
            .with_context(|| format!("reading {}", self.bundle.display()))?;
        let bundle: serde_json::Value =
            serde_json::from_slice(&raw).context("the bundle is not JSON")?;
        let rpc = crate::rpc::RpcClient::new(&self.rpc);
        let result: serde_json::Value = rpc
            .call(
                "tenzro_verifyTeeFinalityProof",
                serde_json::json!({ "tee_finality_proof": bundle }),
            )
            .await?;
        crate::output::print_json(&result)
    }
}
