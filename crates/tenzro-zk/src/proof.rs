//! Wire types for Tenzro zero-knowledge proofs.

use crate::error::Result;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_types::primitives::Timestamp;
use tenzro_types::tee::AttestationReport;

/// The proof system a proof was produced in.
///
/// Every statement Tenzro accepts can be proven in every system. The two
/// Plonky3 systems share the statement and the uni-STARK protocol code and
/// differ in base field, extension field, Merkle and Fiat-Shamir hash and FRI
/// rate. The Halo2 system shares only the statement: it is a separate
/// implementation with its own arithmetization, field, commitment scheme and
/// transcript. A relying party that requires proofs from every system is
/// protected against a soundness failure confined to one field, one hash, one
/// parameter set or one implementation (see [`crate::diverse`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProofSystem {
    /// KoalaBear base field, degree-8 extension, SHA-256 Merkle tree and
    /// transcript, FRI at rate 1/16.
    KoalaBearSha256Fri,
    /// Goldilocks base field, degree-5 extension, BLAKE3 Merkle tree and
    /// transcript, FRI at rate 1/32.
    GoldilocksBlake3Fri,
    /// Halo2: PLONKish circuit over the Pallas scalar field, inner-product
    /// argument commitments over the Pasta cycle, BLAKE2b transcript.
    Halo2IpaPasta,
}

impl ProofSystem {
    /// Every system a verifier knows.
    pub const ALL: [ProofSystem; 3] = [
        ProofSystem::KoalaBearSha256Fri,
        ProofSystem::GoldilocksBlake3Fri,
        ProofSystem::Halo2IpaPasta,
    ];

    /// Stable wire name (matches the serde encoding).
    pub fn as_str(&self) -> &'static str {
        match self {
            ProofSystem::KoalaBearSha256Fri => "koala-bear-sha256-fri",
            ProofSystem::GoldilocksBlake3Fri => "goldilocks-blake3-fri",
            ProofSystem::Halo2IpaPasta => "halo2-ipa-pasta",
        }
    }

    /// Parse the wire name.
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.as_str() == name)
    }

    /// One-byte tag used inside hashed encodings.
    pub fn tag(&self) -> u8 {
        match self {
            ProofSystem::KoalaBearSha256Fri => 1,
            ProofSystem::GoldilocksBlake3Fri => 2,
            ProofSystem::Halo2IpaPasta => 3,
        }
    }

    /// The implementation that verifies this system's proofs. Systems of
    /// one implementation share its protocol code.
    pub fn implementation(&self) -> Implementation {
        match self {
            ProofSystem::KoalaBearSha256Fri | ProofSystem::GoldilocksBlake3Fri => {
                Implementation::Plonky3
            }
            ProofSystem::Halo2IpaPasta => Implementation::Halo2,
        }
    }
}

/// An independently written prover and verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Implementation {
    /// The Plonky3 uni-STARK stack.
    Plonky3,
    /// The Halo2 PLONKish stack.
    Halo2,
}

impl std::fmt::Display for ProofSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A zero-knowledge proof of one statement in one proof system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// The system the proof bytes belong to.
    pub system: ProofSystem,
    /// The proof bytes: a bincode-encoded `p3_uni_stark::Proof` for the
    /// Plonky3 systems, a Halo2 transcript for [`ProofSystem::Halo2IpaPasta`].
    pub proof_bytes: Vec<u8>,
    /// Statement public inputs: `[digest (32 bytes), binding (32 bytes)]`.
    /// These are the same bytes in every proof system.
    pub public_inputs: Vec<Vec<u8>>,
    /// Circuit identifier — `"identity"` or `"settlement"`.
    pub circuit_id: String,
    /// Timestamp when the proof was generated
    pub created_at: Timestamp,
}

impl Proof {
    /// A proof in the KoalaBear/SHA-256 system, the one every relying party
    /// accepts on its own.
    pub fn new(proof_bytes: Vec<u8>, public_inputs: Vec<Vec<u8>>, circuit_id: String) -> Self {
        Self::new_in(
            ProofSystem::KoalaBearSha256Fri,
            proof_bytes,
            public_inputs,
            circuit_id,
        )
    }

    /// A proof in an explicitly named system.
    pub fn new_in(
        system: ProofSystem,
        proof_bytes: Vec<u8>,
        public_inputs: Vec<Vec<u8>>,
        circuit_id: String,
    ) -> Self {
        Self {
            system,
            proof_bytes,
            public_inputs,
            circuit_id,
            created_at: Timestamp::now(),
        }
    }

    /// Serialize the proof to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| e.into())
    }

    /// Deserialize a proof from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| e.into())
    }
}

/// A proof produced inside a TEE, bundled with the attestation that binds it.
///
/// The attestation's signed report data (REPORT_DATA on SGX/TDX/SEV-SNP, the
/// `user_data` field of a Nitro document) must carry
/// [`TeeZkProof::binding_digest`], which commits to the circuit, the proof
/// system, every public input and the proof bytes. The vendor's attestation
/// signature is therefore a signature over this exact proof: it cannot be
/// moved onto another proof, another statement or another circuit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeZkProof {
    /// The zero-knowledge proof
    pub zk_proof: Proof,
    /// TEE attestation report whose report data is the binding digest
    pub tee_attestation: AttestationReport,
    /// Timestamp when the bundle was created
    pub created_at: Timestamp,
}

impl TeeZkProof {
    /// Domain tag for [`Self::binding_digest`].
    pub const BINDING_DOMAIN: &'static [u8] = b"tenzro/zk/tee-bound-proof";

    /// The 32-byte value a TEE must place in its report data to vouch for
    /// `proof`.
    ///
    /// `SHA-256(domain || len(circuit_id) || circuit_id || system_tag ||
    /// count(public_inputs) || Σ(len(pi) || pi) || SHA-256(proof_bytes))`,
    /// all lengths as 4-byte little-endian integers.
    pub fn binding_digest(proof: &Proof) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(Self::BINDING_DOMAIN);
        h.update((proof.circuit_id.len() as u32).to_le_bytes());
        h.update(proof.circuit_id.as_bytes());
        h.update([proof.system.tag()]);
        h.update((proof.public_inputs.len() as u32).to_le_bytes());
        for pi in &proof.public_inputs {
            h.update((pi.len() as u32).to_le_bytes());
            h.update(pi);
        }
        h.update(Sha256::digest(&proof.proof_bytes));
        h.finalize().into()
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| e.into())
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Proof {
        Proof::new(
            vec![1, 2, 3, 4],
            vec![vec![5u8; 32], vec![6u8; 32]],
            "settlement".to_string(),
        )
    }

    #[test]
    fn proof_system_wire_names_roundtrip() {
        for s in ProofSystem::ALL {
            assert_eq!(ProofSystem::parse(s.as_str()), Some(s));
            let json = serde_json::to_string(&s).unwrap();
            assert_eq!(json, format!("\"{}\"", s.as_str()));
        }
        assert_eq!(ProofSystem::parse("plonky3"), None);
    }

    #[test]
    fn proof_json_roundtrip() {
        let p = sample();
        let back = Proof::from_json(&p.to_json().unwrap()).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn binding_digest_covers_every_field() {
        let base = sample();
        let d = TeeZkProof::binding_digest(&base);

        let mut other = base.clone();
        other.proof_bytes[0] ^= 1;
        assert_ne!(d, TeeZkProof::binding_digest(&other));

        let mut other = base.clone();
        other.public_inputs[1][0] ^= 1;
        assert_ne!(d, TeeZkProof::binding_digest(&other));

        let mut other = base.clone();
        other.circuit_id = "identity".to_string();
        assert_ne!(d, TeeZkProof::binding_digest(&other));

        let mut other = base.clone();
        other.system = ProofSystem::GoldilocksBlake3Fri;
        assert_ne!(d, TeeZkProof::binding_digest(&other));

        // The timestamp is not part of what the attestation vouches for.
        let mut other = base.clone();
        other.created_at = Timestamp(1);
        assert_eq!(d, TeeZkProof::binding_digest(&other));
    }
}
