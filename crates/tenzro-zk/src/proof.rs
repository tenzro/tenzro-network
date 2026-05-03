//! Zero-knowledge proof types for Tenzro Network

use crate::error::Result;
use serde::{Deserialize, Serialize};
use tenzro_types::tee::AttestationReport;
use tenzro_types::primitives::Timestamp;

/// Type of zero-knowledge proof system.
///
/// Tenzro uses Plonky3 STARKs over the KoalaBear field — no trusted setup,
/// post-quantum sound. The single-variant enum is kept as a forward-compat
/// tag in case a second proof system is ever added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProofType {
    /// Plonky3 STARK over KoalaBear.
    Plonky3,
}

impl ProofType {
    /// Get the proof type name as a string
    pub fn as_str(&self) -> &str {
        match self {
            ProofType::Plonky3 => "plonky3",
        }
    }
}

impl std::fmt::Display for ProofType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A zero-knowledge proof
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// The proof bytes (bincode-encoded `p3_uni_stark::Proof`)
    pub proof_bytes: Vec<u8>,
    /// Public inputs to the circuit (each entry is a 4-byte LE KoalaBear chunk)
    pub public_inputs: Vec<Vec<u8>>,
    /// Circuit identifier — one of `"inference" | "settlement" | "identity"`
    pub circuit_id: String,
    /// Timestamp when proof was generated
    pub created_at: Timestamp,
    /// Optional metadata
    #[serde(default)]
    pub metadata: ProofMetadata,
}

impl Proof {
    /// Create a new proof
    pub fn new(
        proof_bytes: Vec<u8>,
        public_inputs: Vec<Vec<u8>>,
        circuit_id: String,
    ) -> Self {
        Self {
            proof_bytes,
            public_inputs,
            circuit_id,
            created_at: Timestamp::now(),
            metadata: ProofMetadata::default(),
        }
    }

    /// Add metadata to the proof
    pub fn with_metadata(mut self, metadata: ProofMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Serialize the proof to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| e.into())
    }

    /// Deserialize a proof from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| e.into())
    }

    /// Serialize the proof to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| e.into())
    }

    /// Deserialize a proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| e.into())
    }

    /// Get the proof size in bytes
    pub fn size(&self) -> usize {
        self.proof_bytes.len()
    }

    /// Get the number of public inputs
    pub fn num_public_inputs(&self) -> usize {
        self.public_inputs.len()
    }
}

/// Metadata associated with a proof
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofMetadata {
    /// Prover identifier (optional)
    pub prover_id: Option<String>,
    /// Proving time in milliseconds
    pub proving_time_ms: Option<u64>,
    /// Additional custom metadata
    #[serde(default)]
    pub custom: std::collections::HashMap<String, String>,
}

impl ProofMetadata {
    /// Create new metadata
    pub fn new() -> Self {
        Self::default()
    }

    /// Add custom metadata field
    pub fn with_custom(mut self, key: String, value: String) -> Self {
        self.custom.insert(key, value);
        self
    }
}

/// A ZK proof combined with TEE attestation
///
/// This represents the hybrid ZK-in-TEE execution model where
/// a zero-knowledge proof is generated inside a Trusted Execution
/// Environment, and the TEE attestation is bundled with the proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeZkProof {
    /// The zero-knowledge proof
    pub zk_proof: Proof,
    /// TEE attestation report proving the proof was generated in a TEE
    pub tee_attestation: AttestationReport,
    /// Timestamp when the TEE-ZK proof was created
    pub created_at: Timestamp,
    /// Ed25519 signature over the commitment hash (proof_bytes ++ quote ++ measurement)
    pub signature: Vec<u8>,
    /// Ed25519 public key of the signer (the TEE enclave signing key).
    /// Serialised as `[key_type_byte(0=Ed25519) || 32 raw key bytes]` (33 bytes total).
    /// Empty when the proof has not been signed.
    #[serde(default)]
    pub signing_public_key: Vec<u8>,
}

impl TeeZkProof {
    /// Create a new TEE-ZK proof
    pub fn new(zk_proof: Proof, tee_attestation: AttestationReport) -> Self {
        Self {
            zk_proof,
            tee_attestation,
            created_at: Timestamp::now(),
            signature: Vec::new(),
            signing_public_key: Vec::new(),
        }
    }

    /// Add a signature to the TEE-ZK proof
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = signature;
        self
    }

    /// Attach the signer's public key (33-byte encoding: 1-byte key_type tag + 32 raw bytes).
    pub fn with_signing_public_key(mut self, key_bytes: Vec<u8>) -> Self {
        self.signing_public_key = key_bytes;
        self
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| e.into())
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| e.into())
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| e.into())
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| e.into())
    }

    /// Get the commitment hash of the proof + attestation
    pub fn commitment_hash(&self) -> Vec<u8> {
        use tenzro_crypto::hash::sha256;

        let mut data = Vec::new();
        data.extend_from_slice(&self.zk_proof.proof_bytes);
        data.extend_from_slice(&self.tee_attestation.quote);
        data.extend_from_slice(&self.tee_attestation.measurement);

        sha256(&data).as_bytes().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::tee::TeeVendor;

    #[test]
    fn test_proof_type_serialization() {
        assert_eq!(ProofType::Plonky3.as_str(), "plonky3");
    }

    #[test]
    fn test_proof_creation() {
        let proof = Proof::new(
            vec![1, 2, 3, 4],
            vec![vec![5, 6], vec![7, 8]],
            "inference".to_string(),
        );

        assert_eq!(proof.proof_bytes, vec![1, 2, 3, 4]);
        assert_eq!(proof.public_inputs.len(), 2);
        assert_eq!(proof.circuit_id, "inference");
    }

    #[test]
    fn test_proof_serialization() {
        let proof = Proof::new(
            vec![1, 2, 3, 4],
            vec![vec![5, 6]],
            "settlement".to_string(),
        );

        let json = proof.to_json().unwrap();
        let deserialized = Proof::from_json(&json).unwrap();
        assert_eq!(proof, deserialized);
    }

    #[test]
    fn test_tee_zk_proof() {
        let proof = Proof::new(
            vec![1, 2, 3, 4],
            vec![vec![5, 6]],
            "identity".to_string(),
        );

        let attestation = AttestationReport::new(
            TeeVendor::IntelSGX,
            vec![10, 11, 12],
            vec![13, 14, 15],
            vec![16, 17, 18],
        );

        let tee_zk_proof = TeeZkProof::new(proof.clone(), attestation.clone());

        assert_eq!(tee_zk_proof.zk_proof, proof);
        assert_eq!(tee_zk_proof.tee_attestation, attestation);

        // Test serialization
        let json = tee_zk_proof.to_json().unwrap();
        let deserialized = TeeZkProof::from_json(&json).unwrap();
        assert_eq!(tee_zk_proof, deserialized);
    }

    #[test]
    fn test_commitment_hash() {
        let proof = Proof::new(
            vec![1, 2, 3],
            vec![],
            "inference".to_string(),
        );

        let attestation = AttestationReport::new(
            TeeVendor::IntelSGX,
            vec![],
            vec![4, 5, 6],
            vec![7, 8, 9],
        );

        let tee_zk_proof = TeeZkProof::new(proof, attestation);
        let hash = tee_zk_proof.commitment_hash();

        assert_eq!(hash.len(), 32); // SHA-256 hash
    }
}
