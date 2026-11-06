//! Zero-knowledge proofs: the node proves a settlement statement in every
//! proof system it runs, verifies proofs of a statement (and attests them when
//! they span enough systems), and binds proofs to an attestation of its TEE.

use crate::error::SdkResult;
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Client for zero-knowledge proof operations.
///
/// # Example
///
/// ```no_run
/// # #[tokio::main]
/// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
/// let zk = client.zk();
/// for c in zk.list_circuits().await? {
///     println!("{}: {} ({} proof systems)", c.circuit_type, c.statement, c.proof_systems.len());
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct ZkClient {
    rpc: Arc<RpcClient>,
}

impl ZkClient {
    /// Creates a new ZK client
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Proves a settlement statement in every proof system the node runs
    /// (`tenzro_createZkProof`).
    ///
    /// `witness_hex` is the 32-byte service result and `binding_hex` the
    /// 32-byte request binding. Identity statements are never proven by a
    /// node: their witness is the holder's secret and is proven where it lives.
    pub async fn prove_settlement(
        &self,
        witness_hex: &str,
        binding_hex: &str,
    ) -> SdkResult<ZkProof> {
        self.rpc
            .call(
                "tenzro_createZkProof",
                serde_json::json!({
                    "circuit_id": "settlement",
                    "witness": witness_hex,
                    "binding": binding_hex,
                }),
            )
            .await
    }

    /// Verifies proofs of one statement (`tenzro_verifyZkProof`).
    ///
    /// `circuit_id` is `identity` or `settlement`, `public_inputs` the digest
    /// and binding as hex, and `proofs` one proof per proof system. When the
    /// proofs span enough systems, the node submits each as an
    /// `AttestZkProof` transaction.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let zk = client.zk();
    /// let proof = zk.prove_settlement(&"21".repeat(32), &"43".repeat(32)).await?;
    /// let verdict = zk
    ///     .verify_proof(&proof.circuit_id, proof.public_inputs.clone(), proof.proofs.clone())
    ///     .await?;
    /// println!("valid: {}, attested: {}", verdict.valid, verdict.meets_diverse_threshold);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn verify_proof(
        &self,
        circuit_id: &str,
        public_inputs: Vec<String>,
        proofs: Vec<ZkProofLeg>,
    ) -> SdkResult<ZkVerifyResult> {
        let proofs: Vec<serde_json::Value> = proofs
            .into_iter()
            .map(|p| serde_json::json!({ "system": p.system, "proof": p.proof }))
            .collect();
        self.rpc
            .call(
                "tenzro_verifyZkProof",
                serde_json::json!({
                    "circuit_id": circuit_id,
                    "public_inputs": public_inputs,
                    "proofs": proofs,
                }),
            )
            .await
    }

    /// The circuits the node proves and verifies, with their proof systems
    /// (`tenzro_listCircuits`).
    pub async fn list_circuits(&self) -> SdkResult<Vec<CircuitInfo>> {
        let list: CircuitList = self
            .rpc
            .call("tenzro_listCircuits", serde_json::json!({}))
            .await?;
        Ok(list.circuits)
    }

    /// The circuit catalogue as a bare list (`tenzro_listZkCircuits`).
    pub async fn list_zk_circuits(&self) -> SdkResult<Vec<CircuitInfo>> {
        self.rpc
            .call("tenzro_listZkCircuits", serde_json::json!({}))
            .await
    }

    /// Verifies a bundle from [`ZkClient::create_tee_zk_proof`]
    /// (`tenzro_verifyTeeZkProof`).
    pub async fn verify_tee_zk_proof(
        &self,
        tee_zk_proof: serde_json::Value,
    ) -> SdkResult<TeeZkVerifyResult> {
        self.rpc
            .call(
                "tenzro_verifyTeeZkProof",
                serde_json::json!({ "tee_zk_proof": tee_zk_proof }),
            )
            .await
    }

    /// Binds a wrapped finality proof made on the node's machine to an
    /// attestation of its TEE (`tenzro_attestFinalityProof`). `image_id`,
    /// `journal` and `seal` are hex, as `tenzro-finality-prover wrap` writes
    /// them; the result carries `tee_finality_proof` and the measurement
    /// registers.
    pub async fn attest_finality_proof(
        &self,
        image_id: &str,
        journal: &str,
        seal: &str,
    ) -> SdkResult<AttestedFinalityProof> {
        self.rpc
            .call(
                "tenzro_attestFinalityProof",
                serde_json::json!({ "image_id": image_id, "journal": journal, "seal": seal }),
            )
            .await
    }

    /// Verifies a bundle from [`ZkClient::attest_finality_proof`] and returns
    /// the verified measurement registers (`tenzro_verifyTeeFinalityProof`).
    pub async fn verify_tee_finality_proof(
        &self,
        tee_finality_proof: serde_json::Value,
    ) -> SdkResult<serde_json::Value> {
        self.rpc
            .call(
                "tenzro_verifyTeeFinalityProof",
                serde_json::json!({ "tee_finality_proof": tee_finality_proof }),
            )
            .await
    }

    /// Proves a statement and binds the proof to an attestation of the node's
    /// TEE (`tenzro_createTeeZkProof`). `vendor` is `intel-tdx`,
    /// `amd-sev-snp`, `aws-nitro` or `intel-sgx` and must be the node's TEE;
    /// `witness` and `binding` are 32-byte hex.
    pub async fn create_tee_zk_proof(
        &self,
        circuit_id: &str,
        vendor: &str,
        witness: &str,
        binding: &str,
    ) -> SdkResult<TeeZkProofResult> {
        self.rpc
            .call(
                "tenzro_createTeeZkProof",
                serde_json::json!({
                    "circuit_id": circuit_id,
                    "vendor": vendor,
                    "witness": witness,
                    "binding": binding,
                }),
            )
            .await
    }
}

/// One proof system's proof of a statement.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ZkProofLeg {
    /// Proof system, as the node names it.
    pub system: String,
    /// The proof bytes, 0x-prefixed hex.
    pub proof: String,
    /// Size of the proof in bytes, on proofs the node made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof_size_bytes: Option<u64>,
}

/// A statement proven in every proof system the node runs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkProof {
    /// The circuit (`settlement`).
    pub circuit_id: String,
    /// Public inputs, 0x-prefixed hex: the digest and the binding.
    pub public_inputs: Vec<String>,
    /// Commitment to the circuit and its public inputs.
    pub statement_commitment: String,
    /// One proof per proof system.
    pub proofs: Vec<ZkProofLeg>,
}

/// The verdict on a statement's proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkVerifyResult {
    /// Whether every given proof verifies.
    pub valid: bool,
    /// The circuit.
    pub circuit_id: String,
    /// Commitment to the circuit and its public inputs.
    pub statement_commitment: String,
    /// Number of proofs given.
    pub legs: u64,
    /// Proof systems whose proofs verified.
    #[serde(default)]
    pub verified_systems: Vec<String>,
    /// Proof systems a statement needs before it is attested.
    pub diverse_threshold: u64,
    /// Whether the proofs span enough systems for the statement to be attested.
    pub meets_diverse_threshold: bool,
    /// The `AttestZkProof` transactions submitted, one per proof.
    #[serde(default)]
    pub attestations: Vec<serde_json::Value>,
    /// Why verification failed, when it did.
    #[serde(default)]
    pub error: Option<String>,
}

/// A circuit the node proves and verifies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitInfo {
    /// Circuit id: `identity` or `settlement`.
    #[serde(rename = "type")]
    pub circuit_type: String,
    /// The AIR the circuit is built on.
    pub name: String,
    /// What a proof shows.
    pub statement: String,
    /// The public inputs, described.
    #[serde(default)]
    pub public_inputs: Vec<String>,
    /// Whether a node may prove it.
    pub node_provable: bool,
    /// Each proof system with its parameters and security level.
    #[serde(default)]
    pub proof_systems: Vec<serde_json::Value>,
    /// Proof systems a statement needs before it is attested.
    pub diverse_threshold: u64,
}

#[derive(Deserialize)]
struct CircuitList {
    circuits: Vec<CircuitInfo>,
}

/// A ZK proof bound to a TEE attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeZkProofResult {
    /// The bundle to pass to [`ZkClient::verify_tee_zk_proof`].
    pub tee_zk_proof: serde_json::Value,
    /// The digest the attestation commits to.
    pub binding_digest: String,
    /// The circuit.
    pub circuit_id: String,
    /// The TEE vendor.
    pub vendor: String,
}

/// The verdict on a TEE-bound ZK proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeZkVerifyResult {
    /// Whether both the proof and the attestation verify.
    pub admitted: bool,
    /// The circuit.
    pub circuit_id: String,
    /// The proof system.
    pub system: String,
    /// Whether the proof verifies and the attestation binds it.
    pub proof_and_binding_valid: bool,
    /// Why not, when it does not.
    #[serde(default)]
    pub proof_and_binding_error: Option<String>,
    /// Whether the attestation report verifies.
    pub attestation_valid: bool,
    /// Why not, when it does not.
    #[serde(default)]
    pub attestation_error: Option<String>,
    /// The TEE vendor.
    pub vendor: String,
    /// The digest the attestation commits to.
    pub binding_digest: String,
}

/// A finality proof bound to the node's TEE.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestedFinalityProof {
    /// The TEE vendor.
    pub vendor: String,
    /// The digest the attestation commits to.
    pub binding_digest: String,
    /// The measurement registers.
    pub measurements: serde_json::Value,
    /// The bundle to pass to [`ZkClient::verify_tee_finality_proof`].
    pub tee_finality_proof: serde_json::Value,
}
