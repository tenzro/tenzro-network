//! ZK-in-TEE hybrid execution helpers.
//!
//! Combines a Plonky3 STARK proof with a TEE attestation report into a
//! single [`TeeZkProof`]. The hybrid model lets a verifier check both:
//!
//! 1. The witness satisfies the AIR (cryptographic — Plonky3).
//! 2. The proof was produced inside an attested TEE running expected code
//!    (hardware — Intel TDX / AMD SEV-SNP / AWS Nitro / NVIDIA GPU CC).
//!
//! [`generate_tee_zk_proof`] runs the prover, then bundles its byte-encoded
//! output with an attestation report. [`verify_tee_zk_proof`] re-checks
//! the Plonky3 proof and (optionally) the embedded enclave-key signature.
//!
//! Pure cryptographic helpers ([`sign_tee_zk_proof`],
//! [`verify_tee_zk_signature`], [`extract_tee_public_key`],
//! [`get_expected_measurement`]) operate on the byte-oriented
//! [`TeeZkProof`] / [`AttestationReport`] types and are independent of the
//! underlying proof system.

use p3_air::{Air, DebugConstraintBuilder};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{ProverConstraintFolder, SymbolicAirBuilder, VerifierConstraintFolder};

use crate::error::{Result, ZkError};
use crate::plonky3::config::{TenzroStarkConfig, Val};
use crate::plonky3::envelope::{decode_proof, encode_proof, encode_public_inputs};
use crate::plonky3::{Plonky3Prover, Plonky3Verifier};
use crate::proof::{Proof, TeeZkProof};
use tenzro_crypto::hash::sha256;
use tenzro_crypto::keys::{KeyType, PublicKey};
use tenzro_crypto::signatures::{Signature, Signer};
use tenzro_types::tee::{AttestationReport, TeeVendor};
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Plonky3 ZK-in-TEE proof generation and verification
// ---------------------------------------------------------------------------

/// Generate a Plonky3 STARK proof and bundle it with a TEE attestation.
///
/// Produces a [`TeeZkProof`] whose `zk_proof` carries:
/// - `proof_bytes`: bincode-encoded Plonky3 proof
/// - `public_inputs`: each public input as a 4-byte little-endian KoalaBear
/// - `circuit_id`: caller-supplied identifier (e.g. `"inference"`)
///
/// The caller is responsible for producing the trace and public-input vector
/// from their AIR's witness — see `circuits::airs::*::generate_*_trace`.
pub fn generate_tee_zk_proof<A>(
    air: &A,
    trace: RowMajorMatrix<Val>,
    public_inputs: Vec<Val>,
    circuit_id: &str,
    vendor: TeeVendor,
) -> Result<TeeZkProof>
where
    A: Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<ProverConstraintFolder<'a, TenzroStarkConfig>>
        + for<'a> Air<DebugConstraintBuilder<'a, Val>>,
{
    let prover = Plonky3Prover::<A>::new();
    let p3_proof = prover.prove_air(air, trace, &public_inputs);

    let proof_bytes = encode_proof(&p3_proof)?;
    let pi_blobs = encode_public_inputs(&public_inputs);

    let zk_proof = Proof::new(
        proof_bytes,
        pi_blobs,
        circuit_id.to_string(),
    );

    // Build a placeholder attestation: in production this comes from the
    // running TEE (TDX TDREPORT / SEV-SNP report / Nitro NSM document).
    // The measurement field is filled with the expected code measurement
    // for this circuit so verifiers can compare against a known-good value.
    let measurement = get_expected_measurement(circuit_id, vendor);
    let attestation = AttestationReport::new(
        vendor,
        Vec::new(),       // quote — populated by hardware adapter
        measurement,
        Vec::new(),       // additional_data
    );

    debug!(
        "TeeZkProof generated: circuit={} vendor={:?} proof_size={}B pi_count={}",
        circuit_id,
        vendor,
        zk_proof.proof_bytes.len(),
        zk_proof.public_inputs.len(),
    );

    Ok(TeeZkProof::new(zk_proof, attestation))
}

/// Verify a [`TeeZkProof`] by re-running the Plonky3 verifier against the
/// embedded proof bytes and public inputs.
///
/// This checks the cryptographic ZK proof. Hardware attestation
/// verification (quote chain + measurement allowlisting) is the caller's
/// responsibility — typically routed through `tenzro-tee::AttestationVerifier`.
/// If the proof carries an enclave-key signature
/// ([`TeeZkProof::signing_public_key`] populated), [`verify_tee_zk_signature`]
/// can additionally bind the proof to a specific enclave.
pub fn verify_tee_zk_proof<A>(air: &A, proof: &TeeZkProof) -> Result<bool>
where
    A: Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, TenzroStarkConfig>>,
{
    let p3_proof = decode_proof(&proof.zk_proof.proof_bytes)?;
    let public_inputs = crate::plonky3::envelope::decode_public_inputs(
        &proof.zk_proof.public_inputs,
    )?;

    let verifier = Plonky3Verifier::<A>::new();
    match verifier.verify_air(air, &p3_proof, &public_inputs) {
        Ok(()) => {
            debug!(
                "TeeZkProof verified: circuit={} pi_count={}",
                proof.zk_proof.circuit_id,
                public_inputs.len()
            );
            Ok(true)
        }
        Err(e) => {
            warn!(
                "TeeZkProof Plonky3 verification failed: circuit={} err={:?}",
                proof.zk_proof.circuit_id, e
            );
            Ok(false)
        }
    }
}

// ---------------------------------------------------------------------------
// Signing public key wire encoding
// ---------------------------------------------------------------------------
// We embed the signer's public key inside TeeZkProof as a compact byte slice:
//   [0x00]              → Ed25519  (32 raw key bytes follow)
//   [0x01]              → Secp256k1 (33 compressed bytes follow)
// This allows the verifier to reconstruct a PublicKey without any extra
// out-of-band state.
const TAG_ED25519: u8 = 0x00;

/// Encode a `PublicKey` into the wire format used by TeeZkProof.
fn encode_signing_pubkey(pk: &PublicKey) -> Vec<u8> {
    let tag = match pk.key_type() {
        KeyType::Ed25519 => TAG_ED25519,
        KeyType::Secp256k1 => 0x01,
    };
    let mut out = Vec::with_capacity(1 + pk.as_bytes().len());
    out.push(tag);
    out.extend_from_slice(pk.as_bytes());
    out
}

/// Decode a `PublicKey` from the wire format produced by `encode_signing_pubkey`.
fn decode_signing_pubkey(raw: &[u8]) -> Result<PublicKey> {
    if raw.len() < 2 {
        return Err(ZkError::TeeIntegrationError(
            "signing_public_key too short to decode".to_string(),
        ));
    }
    let (tag, key_bytes) = (raw[0], &raw[1..]);
    let key_type = match tag {
        TAG_ED25519 => KeyType::Ed25519,
        0x01 => KeyType::Secp256k1,
        other => {
            return Err(ZkError::TeeIntegrationError(format!(
                "unknown signing key type tag: 0x{:02x}",
                other
            )))
        }
    };
    Ok(PublicKey::new(key_type, key_bytes.to_vec()))
}

// ---------------------------------------------------------------------------
// Real signing
// ---------------------------------------------------------------------------

/// Sign a `TeeZkProof` using the given `Signer` and return the raw signature
/// bytes plus encoded public key.
///
/// The message signed is the SHA-256 commitment hash of the proof, which
/// already covers `proof_bytes ++ attestation_quote ++ attestation_measurement`.
fn sign_tee_zk_proof_with_signer(
    proof: &TeeZkProof,
    signer: &dyn Signer,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let commitment = proof.commitment_hash();

    let signature = signer
        .sign(&commitment)
        .map_err(ZkError::CryptoError)?;

    let pubkey_bytes = encode_signing_pubkey(signer.public_key());

    debug!(
        "TeeZkProof signed with {:?} key {} (commitment = {})",
        signer.public_key().key_type(),
        hex::encode(signer.public_key().as_bytes()),
        hex::encode(&commitment),
    );

    Ok((signature.to_bytes(), pubkey_bytes))
}

// ---------------------------------------------------------------------------
// Real verification
// ---------------------------------------------------------------------------

/// Verify a `TeeZkProof` signature using the public key embedded in the proof.
fn verify_tee_zk_signature_with_key(proof: &TeeZkProof) -> Result<bool> {
    if proof.signature.is_empty() {
        warn!("TeeZkProof has no signature");
        return Ok(false);
    }
    if proof.signing_public_key.is_empty() {
        warn!("TeeZkProof has no embedded signing public key");
        return Ok(false);
    }

    let public_key = decode_signing_pubkey(&proof.signing_public_key)?;

    // Reconstruct the Signature wrapper that tenzro_crypto expects.
    let sig = Signature::new(public_key.key_type(), proof.signature.clone());

    let commitment = proof.commitment_hash();

    match tenzro_crypto::signatures::verify(&public_key, &commitment, &sig) {
        Ok(()) => {
            debug!(
                "TeeZkProof signature verified (key = {})",
                hex::encode(public_key.as_bytes())
            );
            Ok(true)
        }
        Err(e) => {
            warn!("TeeZkProof signature verification failed: {}", e);
            Ok(false)
        }
    }
}

/// Sign a `TeeZkProof` using the provided signer and attach both the raw
/// signature bytes and the encoded public key to the proof.
pub fn sign_tee_zk_proof(proof: TeeZkProof, signer: &dyn Signer) -> Result<TeeZkProof> {
    let (signature, pubkey_bytes) = sign_tee_zk_proof_with_signer(&proof, signer)?;
    Ok(proof
        .with_signature(signature)
        .with_signing_public_key(pubkey_bytes))
}

/// Verify only the signature on a `TeeZkProof` using the embedded
/// public key, without re-running the full ZK or TEE attestation checks.
pub fn verify_tee_zk_signature(proof: &TeeZkProof) -> Result<bool> {
    verify_tee_zk_signature_with_key(proof)
}

/// Extract the TEE public key from an attestation report.
///
/// In a real implementation this would parse the attestation format and
/// extract the embedded public key (Intel SGX REPORT_DATA, AWS Nitro
/// attestation document, AMD SEV certificate chain). The current
/// implementation derives a deterministic placeholder from the measurement.
pub fn extract_tee_public_key(report: &AttestationReport) -> Result<Vec<u8>> {
    debug!("Extracting TEE public key from {:?} attestation", report.vendor);
    let pubkey = sha256(&report.measurement).as_bytes().to_vec();
    Ok(pubkey)
}

/// Get the expected code measurement for a circuit.
pub fn get_expected_measurement(circuit_id: &str, vendor: TeeVendor) -> Vec<u8> {
    let measurement_data = format!("CODE_MEASUREMENT_{}_{}", circuit_id, vendor.as_str());
    sha256(measurement_data.as_bytes()).as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::Proof;
    use tenzro_crypto::signatures::Ed25519SignerImpl;

    /// Helper: build a minimal unsigned TeeZkProof.
    fn make_unsigned_proof() -> TeeZkProof {
        let proof = Proof::new(
            vec![0xde, 0xad, 0xbe, 0xef],
            vec![],
            "test_circuit".to_string(),
        );
        let attestation = AttestationReport::new(
            TeeVendor::IntelSGX,
            vec![1, 2, 3],
            vec![4, 5, 6],
            vec![7, 8, 9],
        )
        .with_signature(vec![10, 11, 12]);
        TeeZkProof::new(proof, attestation)
    }

    #[test]
    fn test_extract_tee_public_key() {
        let report = AttestationReport::new(
            TeeVendor::AWSNitro,
            vec![],
            vec![1, 2, 3],
            vec![4, 5, 6],
        );

        let pubkey = extract_tee_public_key(&report).unwrap();
        assert_eq!(pubkey.len(), 32); // SHA-256 hash
    }

    #[test]
    fn test_get_expected_measurement() {
        let measurement1 = get_expected_measurement("inference_verification", TeeVendor::IntelSGX);
        let measurement2 = get_expected_measurement("inference_verification", TeeVendor::AMDSEV);

        assert_eq!(measurement1.len(), 32);
        assert_eq!(measurement2.len(), 32);
        assert_ne!(measurement1, measurement2);
    }

    #[test]
    fn test_sign_tee_zk_proof_produces_valid_ed25519_signature() {
        let signer = Ed25519SignerImpl::generate().unwrap();
        let unsigned = make_unsigned_proof();
        let signed = sign_tee_zk_proof(unsigned, &signer).unwrap();

        assert_eq!(signed.signature.len(), 64);
        assert_eq!(signed.signing_public_key.len(), 33);
        assert_eq!(signed.signing_public_key[0], TAG_ED25519);
    }

    #[test]
    fn test_verify_tee_zk_signature_accepts_valid_proof() {
        let signer = Ed25519SignerImpl::generate().unwrap();
        let unsigned = make_unsigned_proof();
        let signed = sign_tee_zk_proof(unsigned, &signer).unwrap();

        assert!(verify_tee_zk_signature(&signed).unwrap());
    }

    #[test]
    fn test_verify_tee_zk_signature_rejects_tampered_proof_bytes() {
        let signer = Ed25519SignerImpl::generate().unwrap();
        let unsigned = make_unsigned_proof();
        let mut signed = sign_tee_zk_proof(unsigned, &signer).unwrap();

        signed.zk_proof.proof_bytes[0] ^= 0xff;

        assert!(!verify_tee_zk_signature(&signed).unwrap());
    }

    #[test]
    fn test_verify_tee_zk_signature_rejects_wrong_key() {
        let signer = Ed25519SignerImpl::generate().unwrap();
        let wrong_signer = Ed25519SignerImpl::generate().unwrap();
        let unsigned = make_unsigned_proof();
        let signed = sign_tee_zk_proof(unsigned, &signer).unwrap();

        let wrong_pubkey_bytes = encode_signing_pubkey(wrong_signer.public_key());
        let mut tampered = signed.clone();
        tampered.signing_public_key = wrong_pubkey_bytes;

        assert!(!verify_tee_zk_signature(&tampered).unwrap());
    }

    #[test]
    fn test_verify_tee_zk_signature_rejects_unsigned_proof() {
        let unsigned = make_unsigned_proof();
        assert!(!verify_tee_zk_signature(&unsigned).unwrap());
    }

    #[test]
    fn test_verify_tee_zk_signature_rejects_missing_pubkey() {
        let signer = Ed25519SignerImpl::generate().unwrap();
        let unsigned = make_unsigned_proof();
        let mut signed = sign_tee_zk_proof(unsigned, &signer).unwrap();

        signed.signing_public_key.clear();

        assert!(!verify_tee_zk_signature(&signed).unwrap());
    }

    #[test]
    fn test_encode_decode_signing_pubkey_roundtrip() {
        let signer = Ed25519SignerImpl::generate().unwrap();
        let encoded = encode_signing_pubkey(signer.public_key());
        let decoded = decode_signing_pubkey(&encoded).unwrap();

        assert_eq!(decoded.key_type(), signer.public_key().key_type());
        assert_eq!(decoded.as_bytes(), signer.public_key().as_bytes());
    }

    // ----------------------------------------------------------------------
    // ZK-in-TEE end-to-end tests using the inference AIR.
    // ----------------------------------------------------------------------

    use crate::circuits::airs::inference::{
        InferenceAir, generate_inference_trace, inference_public_inputs,
    };
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    fn build_valid_inference_proof() -> TeeZkProof {
        let model = KoalaBear::from_u64(3);
        let input = KoalaBear::from_u64(5);
        let output = KoalaBear::from_u64(15);

        let trace = generate_inference_trace(model, input, output, 1 << 3);
        let pis = inference_public_inputs(model, input, output);

        generate_tee_zk_proof(
            &InferenceAir,
            trace,
            pis,
            "inference",
            TeeVendor::IntelSGX,
        )
        .expect("generate")
    }

    #[test]
    fn test_generate_tee_zk_proof_carries_plonky3_payload() {
        let bundle = build_valid_inference_proof();
        assert_eq!(bundle.zk_proof.circuit_id, "inference");
        assert!(!bundle.zk_proof.proof_bytes.is_empty());
        // Inference AIR has 24 public inputs (3 digests × 8).
        assert_eq!(bundle.zk_proof.public_inputs.len(), 24);
        assert!(bundle.zk_proof.public_inputs.iter().all(|b| b.len() == 4));
        assert_eq!(bundle.tee_attestation.vendor, TeeVendor::IntelSGX);
    }

    #[test]
    fn test_verify_tee_zk_proof_accepts_valid_proof() {
        let bundle = build_valid_inference_proof();
        let ok = verify_tee_zk_proof(&InferenceAir, &bundle).expect("verify");
        assert!(ok, "valid Plonky3 ZK-in-TEE proof must verify");
    }

    #[test]
    fn test_verify_tee_zk_proof_rejects_tampered_public_inputs() {
        let mut bundle = build_valid_inference_proof();
        // Flip a byte in the first public-input chunk.
        bundle.zk_proof.public_inputs[0][0] ^= 0xff;

        let ok = verify_tee_zk_proof(&InferenceAir, &bundle).expect("verify");
        assert!(!ok, "tampered public inputs must be rejected");
    }
}
