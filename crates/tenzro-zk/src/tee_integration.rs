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
use tenzro_crypto::composite::{CompositePublicKey, HybridSigner, StandardHybridVerifier};
use tenzro_crypto::composite::CompositeSignature;
use tenzro_crypto::composite::HybridVerifier as _;
use tenzro_crypto::hash::sha256;
use tenzro_crypto::keys::{KeyType, PublicKey};
use tenzro_crypto::signatures::{Signature, Signer};
use tenzro_types::tee::{AttestationReport, AttestationResult, TeeVendor};
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
// We embed the signer's public key inside TeeZkProof as a compact byte slice.
//
// Three wire formats exist, distinguished by the leading tag byte:
//
//   Classical:
//     [0x00]              → Ed25519  (32 raw key bytes follow)
//     [0x01]              → Secp256k1 (33 compressed bytes follow)
//
//   Post-quantum hybrid (composite Ed25519/Secp256k1 + ML-DSA-65):
//     [0x02 | classical_tag(1) | classical_len(u16 LE) | classical_bytes |
//      ml_dsa_65_vk_bytes(1952)]
//
// The ML-DSA-65 verifying key has a fixed length (1952 bytes) so no length
// prefix is needed for the PQ leg — everything after the classical bytes is
// the PQ verifying key. Per `project_pq_migration` this is a flag-day
// extension: the existing classical tags remain interpretable for proofs
// produced before the rebind, but new TEE enclaves sign hybrid going forward.
const TAG_ED25519: u8 = 0x00;
const TAG_SECP256K1: u8 = 0x01;
const TAG_HYBRID_ED25519_ML_DSA_65: u8 = 0x02;

/// Encode a `PublicKey` into the classical wire format used by TeeZkProof.
fn encode_signing_pubkey(pk: &PublicKey) -> Vec<u8> {
    let tag = match pk.key_type() {
        KeyType::Ed25519 => TAG_ED25519,
        KeyType::Secp256k1 => TAG_SECP256K1,
    };
    let mut out = Vec::with_capacity(1 + pk.as_bytes().len());
    out.push(tag);
    out.extend_from_slice(pk.as_bytes());
    out
}

/// Encode a [`CompositePublicKey`] into the hybrid wire format used by TeeZkProof.
fn encode_hybrid_signing_pubkey(pk: &CompositePublicKey) -> Result<Vec<u8>> {
    let classical_tag = match pk.classical.key_type() {
        KeyType::Ed25519 => TAG_ED25519,
        KeyType::Secp256k1 => TAG_SECP256K1,
    };
    let classical_bytes = pk.classical.as_bytes();
    if classical_bytes.len() > u16::MAX as usize {
        return Err(ZkError::TeeIntegrationError(
            "classical public key too large for hybrid wire format".to_string(),
        ));
    }
    let classical_len = classical_bytes.len() as u16;

    let mut out = Vec::with_capacity(1 + 1 + 2 + classical_bytes.len() + pk.pq.len());
    out.push(TAG_HYBRID_ED25519_ML_DSA_65);
    out.push(classical_tag);
    out.extend_from_slice(&classical_len.to_le_bytes());
    out.extend_from_slice(classical_bytes);
    out.extend_from_slice(&pk.pq);
    Ok(out)
}

/// Decoded signing-pubkey from the wire format. Either a classical key
/// (Ed25519/Secp256k1) or a composite Ed25519/Secp256k1 + ML-DSA-65 key.
enum DecodedSigningPubkey {
    Classical(PublicKey),
    Hybrid(CompositePublicKey),
}

/// Decode a signing pubkey from any of the supported wire formats.
fn decode_signing_pubkey_any(raw: &[u8]) -> Result<DecodedSigningPubkey> {
    if raw.is_empty() {
        return Err(ZkError::TeeIntegrationError(
            "signing_public_key too short to decode".to_string(),
        ));
    }
    match raw[0] {
        TAG_ED25519 | TAG_SECP256K1 => decode_signing_pubkey(raw).map(DecodedSigningPubkey::Classical),
        TAG_HYBRID_ED25519_ML_DSA_65 => decode_hybrid_signing_pubkey(raw).map(DecodedSigningPubkey::Hybrid),
        other => Err(ZkError::TeeIntegrationError(format!(
            "unknown signing key type tag: 0x{:02x}",
            other
        ))),
    }
}

/// Decode a classical `PublicKey` from the wire format produced by `encode_signing_pubkey`.
fn decode_signing_pubkey(raw: &[u8]) -> Result<PublicKey> {
    if raw.len() < 2 {
        return Err(ZkError::TeeIntegrationError(
            "signing_public_key too short to decode".to_string(),
        ));
    }
    let (tag, key_bytes) = (raw[0], &raw[1..]);
    let key_type = match tag {
        TAG_ED25519 => KeyType::Ed25519,
        TAG_SECP256K1 => KeyType::Secp256k1,
        other => {
            return Err(ZkError::TeeIntegrationError(format!(
                "unknown signing key type tag: 0x{:02x}",
                other
            )))
        }
    };
    Ok(PublicKey::new(key_type, key_bytes.to_vec()))
}

/// Decode a [`CompositePublicKey`] from the hybrid wire format produced by
/// [`encode_hybrid_signing_pubkey`].
fn decode_hybrid_signing_pubkey(raw: &[u8]) -> Result<CompositePublicKey> {
    // Layout: [tag(1) | classical_tag(1) | classical_len(2) | classical | pq(1952)]
    if raw.len() < 4 {
        return Err(ZkError::TeeIntegrationError(
            "hybrid signing_public_key truncated".to_string(),
        ));
    }
    if raw[0] != TAG_HYBRID_ED25519_ML_DSA_65 {
        return Err(ZkError::TeeIntegrationError(format!(
            "expected hybrid pubkey tag, got 0x{:02x}",
            raw[0]
        )));
    }
    let classical_tag = raw[1];
    let classical_key_type = match classical_tag {
        TAG_ED25519 => KeyType::Ed25519,
        TAG_SECP256K1 => KeyType::Secp256k1,
        other => {
            return Err(ZkError::TeeIntegrationError(format!(
                "unknown classical tag inside hybrid pubkey: 0x{:02x}",
                other
            )));
        }
    };
    let classical_len = u16::from_le_bytes([raw[2], raw[3]]) as usize;
    let classical_start = 4usize;
    let classical_end = classical_start
        .checked_add(classical_len)
        .ok_or_else(|| ZkError::TeeIntegrationError("classical_len overflow".to_string()))?;
    if raw.len() < classical_end {
        return Err(ZkError::TeeIntegrationError(format!(
            "hybrid signing_public_key truncated: need {} bytes for classical, have {}",
            classical_end,
            raw.len()
        )));
    }
    let classical_bytes = &raw[classical_start..classical_end];
    let pq_bytes = &raw[classical_end..];
    if pq_bytes.len() != tenzro_crypto::ML_DSA_65_VK_LEN {
        return Err(ZkError::TeeIntegrationError(format!(
            "hybrid signing_public_key wrong PQ leg length: expected {}, got {}",
            tenzro_crypto::ML_DSA_65_VK_LEN,
            pq_bytes.len()
        )));
    }
    Ok(CompositePublicKey::new(
        PublicKey::new(classical_key_type, classical_bytes.to_vec()),
        pq_bytes.to_vec(),
    ))
}

// ---------------------------------------------------------------------------
// Hybrid signature wire encoding
// ---------------------------------------------------------------------------
// Hybrid signatures are stored in the `signature` field of TeeZkProof with
// the same tag-dispatch pattern as the signing pubkey:
//
//   Classical: raw 64-byte signature (no tag — distinguished by the pubkey
//              tag being 0x00 or 0x01).
//   Hybrid:    [0x02 | classical_sig_len(u16 LE) | classical_sig |
//              ml_dsa_65_sig(3309)]
//
// The ML-DSA-65 signature has a fixed length (3309 bytes) so no length
// prefix is needed for the PQ leg.

/// Encode a [`CompositeSignature`] into the hybrid wire format used by TeeZkProof.
fn encode_hybrid_signature(sig: &CompositeSignature) -> Result<Vec<u8>> {
    if sig.classical.len() > u16::MAX as usize {
        return Err(ZkError::TeeIntegrationError(
            "classical signature too large for hybrid wire format".to_string(),
        ));
    }
    let classical_len = sig.classical.len() as u16;
    let mut out = Vec::with_capacity(1 + 2 + sig.classical.len() + sig.pq.len());
    out.push(TAG_HYBRID_ED25519_ML_DSA_65);
    out.extend_from_slice(&classical_len.to_le_bytes());
    out.extend_from_slice(&sig.classical);
    out.extend_from_slice(&sig.pq);
    Ok(out)
}

/// Decode a [`CompositeSignature`] from the hybrid wire format.
fn decode_hybrid_signature(raw: &[u8]) -> Result<CompositeSignature> {
    if raw.len() < 3 {
        return Err(ZkError::TeeIntegrationError(
            "hybrid signature truncated".to_string(),
        ));
    }
    if raw[0] != TAG_HYBRID_ED25519_ML_DSA_65 {
        return Err(ZkError::TeeIntegrationError(format!(
            "expected hybrid signature tag, got 0x{:02x}",
            raw[0]
        )));
    }
    let classical_len = u16::from_le_bytes([raw[1], raw[2]]) as usize;
    let classical_start = 3usize;
    let classical_end = classical_start
        .checked_add(classical_len)
        .ok_or_else(|| ZkError::TeeIntegrationError("classical_len overflow".to_string()))?;
    if raw.len() < classical_end {
        return Err(ZkError::TeeIntegrationError(format!(
            "hybrid signature truncated: need {} bytes for classical leg, have {}",
            classical_end,
            raw.len()
        )));
    }
    let classical_bytes = raw[classical_start..classical_end].to_vec();
    let pq_bytes = raw[classical_end..].to_vec();
    if pq_bytes.len() != tenzro_crypto::pq::ML_DSA_65_SIG_LEN {
        return Err(ZkError::TeeIntegrationError(format!(
            "hybrid signature wrong PQ leg length: expected {}, got {}",
            tenzro_crypto::pq::ML_DSA_65_SIG_LEN,
            pq_bytes.len()
        )));
    }
    Ok(CompositeSignature::new(classical_bytes, pq_bytes))
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
///
/// Dispatches on the leading byte of `signing_public_key`:
///   - `0x00` / `0x01` → classical Ed25519 / Secp256k1 verification
///   - `0x02`          → composite Ed25519/Secp256k1 + ML-DSA-65 hybrid verification
///     (both legs MUST validate)
fn verify_tee_zk_signature_with_key(proof: &TeeZkProof) -> Result<bool> {
    if proof.signature.is_empty() {
        warn!("TeeZkProof has no signature");
        return Ok(false);
    }
    if proof.signing_public_key.is_empty() {
        warn!("TeeZkProof has no embedded signing public key");
        return Ok(false);
    }

    let commitment = proof.commitment_hash();

    match decode_signing_pubkey_any(&proof.signing_public_key)? {
        DecodedSigningPubkey::Classical(public_key) => {
            // Reconstruct the Signature wrapper that tenzro_crypto expects.
            let sig = Signature::new(public_key.key_type(), proof.signature.clone());

            match tenzro_crypto::signatures::verify(&public_key, &commitment, &sig) {
                Ok(()) => {
                    debug!(
                        "TeeZkProof classical signature verified (key = {})",
                        hex::encode(public_key.as_bytes())
                    );
                    Ok(true)
                }
                Err(e) => {
                    warn!("TeeZkProof classical signature verification failed: {}", e);
                    Ok(false)
                }
            }
        }
        DecodedSigningPubkey::Hybrid(composite_pk) => {
            let composite_sig = match decode_hybrid_signature(&proof.signature) {
                Ok(s) => s,
                Err(e) => {
                    warn!("TeeZkProof hybrid signature decode failed: {}", e);
                    return Ok(false);
                }
            };

            let verifier = StandardHybridVerifier::new(composite_pk.clone());
            match verifier.verify(&commitment, &composite_sig) {
                Ok(()) => {
                    debug!(
                        "TeeZkProof hybrid signature verified (classical key = {}, pq_vk_len = {})",
                        hex::encode(composite_pk.classical.as_bytes()),
                        composite_pk.pq.len()
                    );
                    Ok(true)
                }
                Err(e) => {
                    warn!("TeeZkProof hybrid signature verification failed: {}", e);
                    Ok(false)
                }
            }
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

/// Sign a `TeeZkProof` using a composite (classical + ML-DSA-65) hybrid signer
/// and attach the encoded hybrid signature + composite public key to the proof.
///
/// This is the post-quantum rebind path per `project_pq_migration`: the
/// commitment hash (`SHA-256(proof_bytes || quote || measurement)`) is signed
/// with both an Ed25519/Secp256k1 key and an ML-DSA-65 key. The verifier
/// requires both legs to validate — an adversary must break the classical
/// curve AND the lattice scheme to forge a TEE-attested ZK proof.
pub fn sign_tee_zk_proof_hybrid(
    proof: TeeZkProof,
    signer: &dyn HybridSigner,
) -> Result<TeeZkProof> {
    let commitment = proof.commitment_hash();
    let composite_sig = signer.sign(&commitment).map_err(ZkError::CryptoError)?;
    let sig_bytes = encode_hybrid_signature(&composite_sig)?;
    let pubkey_bytes = encode_hybrid_signing_pubkey(signer.public_key())?;

    debug!(
        "TeeZkProof signed hybrid (classical key = {}, pq_vk_len = {}, commitment = {})",
        hex::encode(signer.public_key().classical.as_bytes()),
        signer.public_key().pq.len(),
        hex::encode(&commitment),
    );

    Ok(proof
        .with_signature(sig_bytes)
        .with_signing_public_key(pubkey_bytes))
}

/// Verify only the signature on a `TeeZkProof` using the embedded
/// public key, without re-running the full ZK or TEE attestation checks.
///
/// Automatically dispatches between classical and hybrid verification based
/// on the embedded `signing_public_key` tag byte.
pub fn verify_tee_zk_signature(proof: &TeeZkProof) -> Result<bool> {
    verify_tee_zk_signature_with_key(proof)
}

// ---------------------------------------------------------------------------
// TEE attestation composition with hosted appraisal services
// ---------------------------------------------------------------------------

/// Bind an externally-verified [`AttestationResult`] to a `TeeZkProof`.
///
/// `tenzro-zk` is intentionally decoupled from HTTP-bearing TEE adapters such
/// as Intel Tiber Trust Authority (`tenzro-tee::IntelTiberClient`). The
/// orchestration node:
///
/// 1. Extracts the TDX quote from the proof's `tee_attestation.quote` field.
/// 2. Calls `IntelTiberClient::verify_quote(quote, ...)` → `(AttestationResult, TiberClaims)`.
/// 3. Passes the `AttestationResult` here to bind it to the same proof.
///
/// This helper performs the cross-binding checks: the result's vendor MUST
/// match the proof's attestation vendor, and at least one of the result's
/// measurements MUST equal the measurement embedded in the proof. Returns
/// `true` only when the appraisal result is valid AND it is correctly bound
/// to this proof.
pub fn bind_external_attestation_result(
    proof: &TeeZkProof,
    result: &AttestationResult,
) -> Result<bool> {
    if !result.valid {
        warn!(
            "External attestation result is not valid (vendor={:?})",
            result.vendor
        );
        return Ok(false);
    }

    if result.vendor != proof.tee_attestation.vendor {
        warn!(
            "Attestation result vendor mismatch: proof says {:?}, result says {:?}",
            proof.tee_attestation.vendor, result.vendor
        );
        return Ok(false);
    }

    // The result's `measurements` is a Vec<Measurement> where each entry
    // carries a register name + raw bytes. The proof embeds a single
    // canonical measurement; at least one measurement in the result must
    // match it for the binding to hold.
    let proof_measurement = &proof.tee_attestation.measurement;
    if proof_measurement.is_empty() {
        warn!("TeeZkProof has empty measurement — cannot bind to external attestation");
        return Ok(false);
    }

    let matched = result
        .measurements
        .iter()
        .any(|m| m.value.as_slice() == proof_measurement.as_slice());

    if !matched {
        warn!(
            "External attestation result measurements do not bind to proof's measurement"
        );
        return Ok(false);
    }

    debug!(
        "External attestation bound to TeeZkProof: vendor={:?} tcb_version={}",
        result.vendor, result.tcb_version
    );
    Ok(true)
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
    use tenzro_crypto::composite::InMemoryHybridSigner;
    use tenzro_crypto::keys::{KeyPair, KeyType};
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_crypto::signatures::Ed25519SignerImpl;
    use tenzro_types::tee::Measurement;

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

    // ----------------------------------------------------------------------
    // PQ hybrid signature tests
    // ----------------------------------------------------------------------

    fn make_hybrid_signer() -> InMemoryHybridSigner {
        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let classical = Ed25519SignerImpl::new(kp).unwrap();
        InMemoryHybridSigner::new(Box::new(classical), MlDsaSigningKey::generate())
    }

    #[test]
    fn test_sign_tee_zk_proof_hybrid_produces_composite_signature() {
        let signer = make_hybrid_signer();
        let unsigned = make_unsigned_proof();
        let signed = sign_tee_zk_proof_hybrid(unsigned, &signer).unwrap();

        // Signing pubkey: tag(1) + classical_tag(1) + classical_len(2) +
        // classical(32 Ed25519) + pq_vk(1952)
        assert_eq!(signed.signing_public_key[0], TAG_HYBRID_ED25519_ML_DSA_65);
        assert_eq!(signed.signing_public_key[1], TAG_ED25519);
        assert_eq!(
            u16::from_le_bytes([signed.signing_public_key[2], signed.signing_public_key[3]]),
            32
        );
        assert_eq!(
            signed.signing_public_key.len(),
            1 + 1 + 2 + 32 + tenzro_crypto::ML_DSA_65_VK_LEN
        );

        // Signature: tag(1) + classical_len(2) + classical(64 Ed25519) + pq(3309)
        assert_eq!(signed.signature[0], TAG_HYBRID_ED25519_ML_DSA_65);
        assert_eq!(
            u16::from_le_bytes([signed.signature[1], signed.signature[2]]),
            64
        );
        assert_eq!(
            signed.signature.len(),
            1 + 2 + 64 + tenzro_crypto::pq::ML_DSA_65_SIG_LEN
        );
    }

    #[test]
    fn test_verify_tee_zk_signature_accepts_valid_hybrid_proof() {
        let signer = make_hybrid_signer();
        let unsigned = make_unsigned_proof();
        let signed = sign_tee_zk_proof_hybrid(unsigned, &signer).unwrap();

        assert!(verify_tee_zk_signature(&signed).unwrap());
    }

    #[test]
    fn test_verify_tee_zk_signature_hybrid_rejects_tampered_proof_bytes() {
        let signer = make_hybrid_signer();
        let unsigned = make_unsigned_proof();
        let mut signed = sign_tee_zk_proof_hybrid(unsigned, &signer).unwrap();

        signed.zk_proof.proof_bytes[0] ^= 0xff;

        assert!(!verify_tee_zk_signature(&signed).unwrap());
    }

    #[test]
    fn test_verify_tee_zk_signature_hybrid_rejects_tampered_classical_leg() {
        let signer = make_hybrid_signer();
        let unsigned = make_unsigned_proof();
        let mut signed = sign_tee_zk_proof_hybrid(unsigned, &signer).unwrap();

        // Flip one byte deep in the classical signature leg.
        // Layout: tag(1) + classical_len(2) + classical(64) → byte 10 is mid-classical.
        signed.signature[10] ^= 0x01;

        assert!(!verify_tee_zk_signature(&signed).unwrap());
    }

    #[test]
    fn test_verify_tee_zk_signature_hybrid_rejects_tampered_pq_leg() {
        let signer = make_hybrid_signer();
        let unsigned = make_unsigned_proof();
        let mut signed = sign_tee_zk_proof_hybrid(unsigned, &signer).unwrap();

        // Flip a byte well into the PQ leg.
        // Layout: tag(1) + classical_len(2) + classical(64) + pq(3309) → byte 100 of pq.
        let pq_start = 1 + 2 + 64;
        signed.signature[pq_start + 100] ^= 0x01;

        assert!(!verify_tee_zk_signature(&signed).unwrap());
    }

    #[test]
    fn test_verify_tee_zk_signature_hybrid_rejects_wrong_composite_key() {
        let signer = make_hybrid_signer();
        let wrong_signer = make_hybrid_signer();
        let unsigned = make_unsigned_proof();
        let signed = sign_tee_zk_proof_hybrid(unsigned, &signer).unwrap();

        // Replace the embedded composite pubkey with a different one.
        let mut tampered = signed.clone();
        tampered.signing_public_key = encode_hybrid_signing_pubkey(wrong_signer.public_key()).unwrap();

        assert!(!verify_tee_zk_signature(&tampered).unwrap());
    }

    #[test]
    fn test_hybrid_pubkey_roundtrip() {
        let signer = make_hybrid_signer();
        let encoded = encode_hybrid_signing_pubkey(signer.public_key()).unwrap();
        let decoded = match decode_signing_pubkey_any(&encoded).unwrap() {
            DecodedSigningPubkey::Hybrid(pk) => pk,
            DecodedSigningPubkey::Classical(_) => panic!("expected hybrid"),
        };
        assert_eq!(decoded.classical.key_type(), KeyType::Ed25519);
        assert_eq!(decoded.classical.as_bytes(), signer.public_key().classical.as_bytes());
        assert_eq!(decoded.pq, signer.public_key().pq);
    }

    #[test]
    fn test_hybrid_signature_roundtrip() {
        let signer = make_hybrid_signer();
        let composite_sig = signer.sign(b"msg").unwrap();
        let encoded = encode_hybrid_signature(&composite_sig).unwrap();
        let decoded = decode_hybrid_signature(&encoded).unwrap();
        assert_eq!(decoded.classical, composite_sig.classical);
        assert_eq!(decoded.pq, composite_sig.pq);
    }

    #[test]
    fn test_decode_signing_pubkey_any_rejects_unknown_tag() {
        let raw = vec![0xfeu8; 16];
        assert!(decode_signing_pubkey_any(&raw).is_err());
    }

    #[test]
    fn test_decode_hybrid_pubkey_rejects_wrong_pq_length() {
        // Build a valid header but truncated PQ leg.
        let mut raw = vec![TAG_HYBRID_ED25519_ML_DSA_65, TAG_ED25519];
        raw.extend_from_slice(&32u16.to_le_bytes());
        raw.extend_from_slice(&[0xaa; 32]); // classical
        raw.extend_from_slice(&[0xbb; 100]); // truncated PQ (real length is 1952)
        assert!(decode_hybrid_signing_pubkey(&raw).is_err());
    }

    #[test]
    fn test_decode_hybrid_signature_rejects_wrong_pq_length() {
        let mut raw = vec![TAG_HYBRID_ED25519_ML_DSA_65];
        raw.extend_from_slice(&64u16.to_le_bytes());
        raw.extend_from_slice(&[0xaa; 64]); // classical
        raw.extend_from_slice(&[0xbb; 100]); // truncated PQ (real length is 3309)
        assert!(decode_hybrid_signature(&raw).is_err());
    }

    // ----------------------------------------------------------------------
    // External attestation binding (Tiber composition)
    // ----------------------------------------------------------------------

    fn make_attestation_result_matching(
        vendor: TeeVendor,
        measurement: Vec<u8>,
        valid: bool,
    ) -> AttestationResult {
        let mut result = AttestationResult::default();
        result.vendor = vendor;
        result.valid = valid;
        result.tcb_version = "OK".to_string();
        result.measurements.push(Measurement {
            index: 0,
            algorithm: "SHA384".to_string(),
            value: measurement,
            ..Default::default()
        });
        result
    }

    #[test]
    fn test_bind_external_attestation_accepts_matching_valid_result() {
        let unsigned = make_unsigned_proof();
        let measurement = unsigned.tee_attestation.measurement.clone();
        let result = make_attestation_result_matching(TeeVendor::IntelSGX, measurement, true);

        assert!(bind_external_attestation_result(&unsigned, &result).unwrap());
    }

    #[test]
    fn test_bind_external_attestation_rejects_invalid_result() {
        let unsigned = make_unsigned_proof();
        let measurement = unsigned.tee_attestation.measurement.clone();
        let result = make_attestation_result_matching(TeeVendor::IntelSGX, measurement, false);

        assert!(!bind_external_attestation_result(&unsigned, &result).unwrap());
    }

    #[test]
    fn test_bind_external_attestation_rejects_vendor_mismatch() {
        let unsigned = make_unsigned_proof();
        let measurement = unsigned.tee_attestation.measurement.clone();
        // proof's vendor is IntelSGX, but result claims AMDSEV
        let result = make_attestation_result_matching(TeeVendor::AMDSEV, measurement, true);

        assert!(!bind_external_attestation_result(&unsigned, &result).unwrap());
    }

    #[test]
    fn test_bind_external_attestation_rejects_measurement_mismatch() {
        let unsigned = make_unsigned_proof();
        let result = make_attestation_result_matching(
            TeeVendor::IntelSGX,
            vec![0xff; 48], // different from proof's [4,5,6]
            true,
        );

        assert!(!bind_external_attestation_result(&unsigned, &result).unwrap());
    }
}
