//! Finality proofs.
//!
//! The finality guest program runs one light-client step over a checkpoint's
//! certificate inside the RISC Zero zkVM and commits the step's journal. A
//! proof that it did comes in two forms ([`ProofForm`]):
//!
//! - the STARK ([`verify_stark`]), the canonical form: the program's
//!   succinct receipt, a FRI proof whose soundness rests on hash functions
//!   alone, so it holds against a quantum computer. Light clients and Tenzro
//!   verify this form.
//! - the Groth16 wrap ([`verify_groth16`]), an optional compact form for
//!   chains that need one: the same receipt reproven as a 256-byte Groth16
//!   seal over BN254 that an EVM contract verifies for about a quarter of a
//!   million gas. Its soundness rests on discrete logarithms in BN254, which
//!   a quantum computer breaks, so it is not quantum-safe.
//!
//! Either form proves that the program with `image_id` halted normally
//! having committed exactly `journal`. The image id is the hash of the guest
//! program; which one is accepted is on-chain configuration.

use bincode::Options as _;
use risc0_zkvm::sha::{Digest, Digestible};
use risc0_zkvm::{
    Groth16Receipt, Groth16ReceiptVerifierParameters, InnerReceipt, MaybePruned, Receipt,
    ReceiptClaim, SuccinctReceipt,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tenzro_types::tee::AttestationReport;

/// The form a finality proof takes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofForm {
    /// The program's succinct STARK receipt: hash-based, quantum-safe, and
    /// the canonical form.
    #[default]
    #[serde(rename = "stark")]
    Stark,
    /// The receipt wrapped into a Groth16 proof over BN254: compact, for
    /// chains that need one, and not quantum-safe.
    #[serde(rename = "groth16-bn254")]
    Groth16Bn254,
}

impl ProofForm {
    /// Whether the form's soundness holds against a quantum computer.
    pub fn quantum_safe(self) -> bool {
        matches!(self, Self::Stark)
    }

    /// The form's name, as proofs and evidence label it.
    pub fn name(self) -> &'static str {
        match self {
            Self::Stark => "stark",
            Self::Groth16Bn254 => "groth16-bn254",
        }
    }
}

/// Bytes of a Groth16 seal: the proof points `a`, `b` and `c`.
pub const SEAL_LEN: usize = 256;

/// Most bytes a STARK finality proof may take. A succinct receipt of the
/// finality program is a fixed-size recursion proof well below this.
pub const MAX_STARK_LEN: usize = 512 * 1024;

/// The encoding of a STARK finality proof: the succinct receipt, as
/// [`encode_stark`] writes it.
fn stark_codec() -> impl bincode::Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_STARK_LEN as u64)
}

/// The bytes of a STARK finality proof: the succinct receipt of the program.
pub fn encode_stark(receipt: &SuccinctReceipt<ReceiptClaim>) -> Result<Vec<u8>, String> {
    stark_codec().serialize(receipt).map_err(|e| e.to_string())
}

/// The succinct receipt [`encode_stark`] wrote.
pub fn decode_stark(stark: &[u8]) -> Result<SuccinctReceipt<ReceiptClaim>, String> {
    if stark.len() > MAX_STARK_LEN {
        return Err(format!(
            "a STARK finality proof is at most {MAX_STARK_LEN} bytes, got {}",
            stark.len()
        ));
    }
    stark_codec()
        .deserialize(stark)
        .map_err(|e| format!("the STARK does not decode: {e}"))
}

/// Checks that `stark`, the program's succinct STARK receipt, proves the
/// program `image_id` committed `journal`. This is the quantum-safe check:
/// the receipt is verified against the recursion program's control root and
/// nothing in it rests on a pairing or a discrete logarithm.
pub fn verify_stark(image_id: &[u8; 32], journal: &[u8], stark: &[u8]) -> Result<(), String> {
    let receipt = decode_stark(stark)?;
    Receipt::new(InnerReceipt::Succinct(receipt), journal.to_vec())
        .verify(Digest::from(*image_id))
        .map_err(|e| e.to_string())
}

/// Checks a finality proof of either form.
pub fn verify(
    form: ProofForm,
    image_id: &[u8; 32],
    journal: &[u8],
    proof: &[u8],
) -> Result<(), String> {
    match form {
        ProofForm::Stark => verify_stark(image_id, journal, proof),
        ProofForm::Groth16Bn254 => verify_groth16(image_id, journal, proof),
    }
}

/// Checks that `seal`, the Groth16 wrap over BN254, proves the program
/// `image_id` committed `journal`. The wrap rests on a classical assumption
/// (discrete logarithms in BN254) and is not quantum-safe: see [`ProofForm`].
/// Take the STARK ([`verify_stark`]) unless an EVM contract must verify it.
pub fn verify_groth16(image_id: &[u8; 32], journal: &[u8], seal: &[u8]) -> Result<(), String> {
    if seal.len() != SEAL_LEN {
        return Err(format!("a seal is {SEAL_LEN} bytes, got {}", seal.len()));
    }
    let image = Digest::from(*image_id);
    let claim = ReceiptClaim::ok(image, journal.to_vec());
    let params = Groth16ReceiptVerifierParameters::default().digest();
    let inner = InnerReceipt::Groth16(Groth16Receipt::new(
        seal.to_vec(),
        MaybePruned::Value(claim),
        params,
    ));
    Receipt::new(inner, journal.to_vec())
        .verify(image)
        .map_err(|e| e.to_string())
}

/// RISC Zero's Groth16 prover container (`v2025-04-03.1`), by the digest of
/// its linux/amd64 image manifest: the wrap stage runs only on x86-64 hosts,
/// and a measured image carries exactly this manifest and its layers. The wrap
/// runs exactly this image, and a proof made in a confidential VM names it as
/// its prover.
pub const GROTH16_PROVER_IMAGE: &str = "risczero/risc0-groth16-prover@sha256:7f173963196570b7a71816ed70565a4579264c5d2e3e0ecb028102538ad0e331";

/// The digest in [`GROTH16_PROVER_IMAGE`].
pub fn groth16_prover_digest() -> [u8; 32] {
    let (_, digest) = GROTH16_PROVER_IMAGE
        .split_once("@sha256:")
        .expect("a digest reference");
    let mut out = [0u8; 32];
    hex::decode_to_slice(digest, &mut out).expect("a 32-byte hex digest");
    out
}

/// A Groth16-wrapped finality proof made inside a TEE, with the attestation
/// that binds it. The seal is the classical form ([`ProofForm::Groth16Bn254`]),
/// and so is the vendor's signature over the attestation.
///
/// The attestation's signed report data carries [`Self::binding_digest`]
/// (packed for its vendor), which commits to the program, the journal, the
/// seal and the prover. The vendor's signature over the report is therefore a
/// signature over this exact proof made by this prover, and the report's
/// measurement registers name the software that made it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeeFinalityProof {
    /// The finality program's image id.
    #[serde(with = "hex::serde")]
    pub image_id: [u8; 32],
    /// The journal the program committed.
    #[serde(with = "hex::serde")]
    pub journal: Vec<u8>,
    /// The 256-byte Groth16 seal.
    #[serde(with = "hex::serde")]
    pub seal: Vec<u8>,
    /// The prover the proof was wrapped with ([`groth16_prover_digest`]).
    #[serde(with = "hex::serde")]
    pub prover_digest: [u8; 32],
    /// The attestation whose report data is the binding digest.
    pub tee_attestation: AttestationReport,
}

impl TeeFinalityProof {
    /// Domain tag for [`Self::binding_digest`].
    pub const BINDING_DOMAIN: &'static [u8] = b"tenzro/zk/tee-bound-finality-proof";

    /// The 32-byte value a TEE places in its report data to vouch for a
    /// proof: `SHA-256(domain || image_id || SHA-256(journal) || SHA-256(seal)
    /// || prover_digest)`.
    pub fn binding_digest(
        image_id: &[u8; 32],
        journal: &[u8],
        seal: &[u8],
        prover_digest: &[u8; 32],
    ) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(Self::BINDING_DOMAIN);
        h.update(image_id);
        h.update(Sha256::digest(journal));
        h.update(Sha256::digest(seal));
        h.update(prover_digest);
        h.finalize().into()
    }

    /// This bundle's binding digest.
    pub fn digest(&self) -> [u8; 32] {
        Self::binding_digest(
            &self.image_id,
            &self.journal,
            &self.seal,
            &self.prover_digest,
        )
    }
}

/// Verify the proof and its binding: the seal proves the program committed
/// the journal, the prover is [`GROTH16_PROVER_IMAGE`], and the attestation's
/// signed report data carries the binding digest. The vendor signature over
/// the attestation is checked by the strict TEE verifier at the call site.
pub fn verify_tee_finality_proof(bundle: &TeeFinalityProof) -> crate::Result<()> {
    if bundle.prover_digest != groth16_prover_digest() {
        return Err(crate::ZkError::ProofRejected(format!(
            "the proof names prover {}, not the published {GROTH16_PROVER_IMAGE}",
            hex::encode(bundle.prover_digest)
        )));
    }
    verify_groth16(&bundle.image_id, &bundle.journal, &bundle.seal)
        .map_err(crate::ZkError::ProofRejected)?;
    crate::tee_integration::report_carries_digest(&bundle.digest(), &bundle.tee_attestation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seal_of_the_wrong_length_or_content_is_refused() {
        assert!(verify_groth16(&[1; 32], b"journal", &[0; 10]).is_err());
        assert!(verify_groth16(&[1; 32], b"journal", &[0; SEAL_LEN]).is_err());
    }

    #[test]
    fn the_default_form_is_the_stark() {
        assert_eq!(ProofForm::default(), ProofForm::Stark);
        assert!(ProofForm::default().quantum_safe());
    }

    #[test]
    fn only_the_stark_form_is_quantum_safe() {
        assert!(ProofForm::Stark.quantum_safe());
        assert!(!ProofForm::Groth16Bn254.quantum_safe());
        assert_eq!(ProofForm::default(), ProofForm::Stark);
        assert_eq!(ProofForm::Stark.name(), "stark");
        assert_eq!(ProofForm::Groth16Bn254.name(), "groth16-bn254");
    }

    #[test]
    fn a_stark_that_is_not_one_is_refused() {
        assert!(verify_stark(&[1; 32], b"journal", b"not a stark").is_err());
        assert!(verify_stark(&[1; 32], b"journal", &[0; SEAL_LEN]).is_err());
        let err = verify_stark(&[1; 32], b"journal", &vec![0; MAX_STARK_LEN + 1]).unwrap_err();
        assert!(err.contains("at most"), "{err}");
    }

    #[test]
    fn the_prover_digest_is_the_container_digest() {
        assert_eq!(
            hex::encode(groth16_prover_digest()),
            "7f173963196570b7a71816ed70565a4579264c5d2e3e0ecb028102538ad0e331"
        );
    }

    #[test]
    fn the_binding_covers_every_field() {
        let base = TeeFinalityProof::binding_digest(&[1; 32], b"journal", &[2; SEAL_LEN], &[3; 32]);
        assert_ne!(
            base,
            TeeFinalityProof::binding_digest(&[9; 32], b"journal", &[2; SEAL_LEN], &[3; 32])
        );
        assert_ne!(
            base,
            TeeFinalityProof::binding_digest(&[1; 32], b"journak", &[2; SEAL_LEN], &[3; 32])
        );
        assert_ne!(
            base,
            TeeFinalityProof::binding_digest(&[1; 32], b"journal", &[4; SEAL_LEN], &[3; 32])
        );
        assert_ne!(
            base,
            TeeFinalityProof::binding_digest(&[1; 32], b"journal", &[2; SEAL_LEN], &[5; 32])
        );
    }

    #[test]
    fn a_bundle_naming_another_prover_is_refused() {
        let bundle = TeeFinalityProof {
            image_id: [1; 32],
            journal: b"journal".to_vec(),
            seal: vec![0; SEAL_LEN],
            prover_digest: [7; 32],
            tee_attestation: AttestationReport::default(),
        };
        let err = verify_tee_finality_proof(&bundle).unwrap_err().to_string();
        assert!(err.contains("published"), "{err}");
    }
}
