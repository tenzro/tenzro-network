//! Top-level proof-envelope verification.
//!
//! [`verify_proof_envelope`] takes a wire-format [`crate::proof::Proof`] (the
//! `Vec<u8>` proof bytes + `Vec<Vec<u8>>` public inputs envelope used across
//! storage, RPC, MCP, settlement, and the EVM commitment-attestation path) and
//! dispatches to the right [`p3_air::Air`] based on the embedded `circuit_id`.
//!
//! This is the single entry point the web/MCP `verify_zk_proof` handlers and
//! the settlement-engine ZK dispatch should call. The bytes-in / bool-out
//! shape keeps the rest of the network agnostic to AIR specifics.
//!
//! Recognised `circuit_id` values:
//! - `"inference"` — [`InferenceAir`]
//! - `"settlement"` — [`SettlementAir`]
//! - `"identity"` — [`IdentityAir`]
//!
//! Unknown circuit IDs return [`VerifyEnvelopeError::UnknownCircuit`]. All
//! envelope-decode errors and verifier errors are surfaced verbatim so callers
//! can include them in audit logs.

use crate::circuits::airs::{IdentityAir, InferenceAir, SettlementAir};
use crate::error::ZkError;
use crate::plonky3::envelope::{decode_proof, decode_public_inputs};
use crate::plonky3::verifier::Plonky3Verifier;
use crate::proof::Proof;

/// Errors raised by [`verify_proof_envelope`].
#[derive(Debug, thiserror::Error)]
pub enum VerifyEnvelopeError {
    /// `circuit_id` did not match any registered AIR.
    #[error("unknown circuit_id: {0}")]
    UnknownCircuit(String),

    /// Wire-encoded proof or public inputs were malformed.
    #[error("envelope decode failed: {0}")]
    EnvelopeDecode(ZkError),

    /// The Plonky3 verifier rejected the proof.
    #[error("verifier rejected proof: {0:?}")]
    VerifierRejected(String),
}

/// Verify a wire-format [`Proof`] envelope.
///
/// Returns `Ok(())` iff:
/// 1. `proof.circuit_id` names a known AIR, and
/// 2. The Plonky3 verifier accepts the decoded proof + public inputs.
///
/// The function is pure / side-effect-free and safe to call from any thread.
/// Callers that want to additionally write a commitment into the on-chain
/// `ZkCommitmentRegistry` must do so themselves after this returns `Ok`.
pub fn verify_proof_envelope(proof: &Proof) -> Result<(), VerifyEnvelopeError> {
    let p3_proof = decode_proof(&proof.proof_bytes).map_err(VerifyEnvelopeError::EnvelopeDecode)?;
    let public_values =
        decode_public_inputs(&proof.public_inputs).map_err(VerifyEnvelopeError::EnvelopeDecode)?;

    match proof.circuit_id.as_str() {
        "inference" => {
            let verifier = Plonky3Verifier::<InferenceAir>::new();
            verifier
                .verify_air(&InferenceAir, &p3_proof, &public_values)
                .map_err(|e| VerifyEnvelopeError::VerifierRejected(format!("{:?}", e)))
        }
        "settlement" => {
            let verifier = Plonky3Verifier::<SettlementAir>::new();
            verifier
                .verify_air(&SettlementAir, &p3_proof, &public_values)
                .map_err(|e| VerifyEnvelopeError::VerifierRejected(format!("{:?}", e)))
        }
        "identity" => {
            let verifier = Plonky3Verifier::<IdentityAir>::new();
            verifier
                .verify_air(&IdentityAir, &p3_proof, &public_values)
                .map_err(|e| VerifyEnvelopeError::VerifierRejected(format!("{:?}", e)))
        }
        other => Err(VerifyEnvelopeError::UnknownCircuit(other.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuits::airs::inference::{
        generate_inference_trace, inference_public_inputs,
    };
    use crate::plonky3::envelope::{encode_proof, encode_public_inputs};
    use crate::plonky3::prover::Plonky3Prover;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    fn build_inference_proof() -> Proof {
        let model = KoalaBear::from_u64(3);
        let input = KoalaBear::from_u64(5);
        let output = KoalaBear::from_u64(15);

        let trace = generate_inference_trace(model, input, output, 1 << 3);
        let pis = inference_public_inputs(model, input, output);

        let prover = Plonky3Prover::<InferenceAir>::new();
        let p3_proof = prover.prove_air(&InferenceAir, trace, &pis);

        Proof::new(
            encode_proof(&p3_proof).unwrap(),
            encode_public_inputs(&pis),
            "inference".to_string(),
        )
    }

    #[test]
    fn accepts_valid_inference_proof() {
        let proof = build_inference_proof();
        verify_proof_envelope(&proof).expect("valid inference proof must verify");
    }

    #[test]
    fn rejects_unknown_circuit() {
        let mut proof = build_inference_proof();
        proof.circuit_id = "made_up_circuit".to_string();
        assert!(matches!(
            verify_proof_envelope(&proof),
            Err(VerifyEnvelopeError::UnknownCircuit(_))
        ));
    }

    #[test]
    fn rejects_tampered_public_inputs() {
        let mut proof = build_inference_proof();
        // Replace the first public input with garbage of the right length.
        proof.public_inputs[0] = vec![0xff, 0xff, 0xff, 0x7f];
        assert!(verify_proof_envelope(&proof).is_err());
    }

    #[test]
    fn rejects_malformed_proof_bytes() {
        let mut proof = build_inference_proof();
        proof.proof_bytes = vec![0xde, 0xad, 0xbe, 0xef];
        assert!(matches!(
            verify_proof_envelope(&proof),
            Err(VerifyEnvelopeError::EnvelopeDecode(_))
        ));
    }
}
