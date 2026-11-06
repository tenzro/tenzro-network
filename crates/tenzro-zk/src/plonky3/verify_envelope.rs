//! Verification of a wire-format [`Proof`] envelope.
//!
//! [`verify_proof_envelope`] is the single verification entry point used by
//! the RPC, MCP and web handlers, the settlement engine, the quorum
//! co-signers and the fraud-proof path. It resolves the circuit, decodes the
//! `[digest, binding]` public inputs, and runs the envelope's system's
//! verifier: for the Plonky3 systems it decodes the proof and checks the
//! trace height is the one the circuit is defined over; Halo2 proofs go to
//! [`crate::halo2::verify`].

use p3_field::PrimeField64;
use p3_uni_stark::{StarkGenericConfig, Val};
use serde::de::DeserializeOwned;

use crate::circuits::Circuit;
use crate::circuits::preimage::{PreimageAir, TRACE_HEIGHT, WORD_BYTES, public_values};
use crate::plonky3::config;
use crate::proof::{Proof, ProofSystem};

/// `degree_bits` of every honest proof: the trace height, doubled by the
/// hiding PCS's randomization.
pub const EXPECTED_DEGREE_BITS: usize = TRACE_HEIGHT.trailing_zeros() as usize + 1;

/// Errors raised by [`verify_proof_envelope`].
#[derive(Debug, thiserror::Error)]
pub enum VerifyEnvelopeError {
    /// `circuit_id` did not name a known circuit.
    #[error("unknown circuit_id: {0}")]
    UnknownCircuit(String),

    /// The public inputs are not two 32-byte words, or the proof bytes do not
    /// decode for the envelope's system.
    #[error("envelope decode failed: {0}")]
    EnvelopeDecode(String),

    /// The STARK verifier rejected the proof.
    #[error("verifier rejected proof: {0}")]
    VerifierRejected(String),
}

/// Decode `[digest, binding]` from envelope public inputs.
pub fn decode_statement(
    public_inputs: &[Vec<u8>],
) -> Result<([u8; WORD_BYTES], [u8; WORD_BYTES]), VerifyEnvelopeError> {
    let [digest, binding] = public_inputs else {
        return Err(VerifyEnvelopeError::EnvelopeDecode(format!(
            "expected 2 public inputs (digest, binding), got {}",
            public_inputs.len()
        )));
    };
    let word = |v: &Vec<u8>, name: &str| -> Result<[u8; WORD_BYTES], VerifyEnvelopeError> {
        v.as_slice().try_into().map_err(|_| {
            VerifyEnvelopeError::EnvelopeDecode(format!(
                "{name} must be {WORD_BYTES} bytes, got {}",
                v.len()
            ))
        })
    };
    Ok((word(digest, "digest")?, word(binding, "binding")?))
}

/// Verify a wire-format [`Proof`] envelope. Pure and thread-safe.
pub fn verify_proof_envelope(proof: &Proof) -> Result<(), VerifyEnvelopeError> {
    let circuit = Circuit::parse(&proof.circuit_id)
        .ok_or_else(|| VerifyEnvelopeError::UnknownCircuit(proof.circuit_id.clone()))?;
    let (digest, binding) = decode_statement(&proof.public_inputs)?;
    match proof.system {
        ProofSystem::KoalaBearSha256Fri => verify_with(
            config::koala_bear::config(),
            circuit,
            &proof.proof_bytes,
            &digest,
            &binding,
        ),
        ProofSystem::GoldilocksBlake3Fri => verify_with(
            config::goldilocks::config(),
            circuit,
            &proof.proof_bytes,
            &digest,
            &binding,
        ),
        ProofSystem::Halo2IpaPasta => {
            crate::halo2::verify(circuit, &proof.proof_bytes, &digest, &binding)
                .map_err(|e| VerifyEnvelopeError::VerifierRejected(e.to_string()))
        }
    }
}

fn verify_with<SC>(
    config: SC,
    circuit: Circuit,
    proof_bytes: &[u8],
    digest: &[u8; WORD_BYTES],
    binding: &[u8; WORD_BYTES],
) -> Result<(), VerifyEnvelopeError>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField64,
    p3_uni_stark::Proof<SC>: DeserializeOwned,
{
    let proof: p3_uni_stark::Proof<SC> = bincode::deserialize(proof_bytes)
        .map_err(|e| VerifyEnvelopeError::EnvelopeDecode(e.to_string()))?;
    if proof.degree_bits != EXPECTED_DEGREE_BITS {
        return Err(VerifyEnvelopeError::VerifierRejected(format!(
            "trace degree_bits {} is not the circuit's {}",
            proof.degree_bits, EXPECTED_DEGREE_BITS
        )));
    }
    let air = PreimageAir::new(circuit);
    let pis = public_values::<Val<SC>>(digest, binding);
    p3_uni_stark::verify(&config, &air, &proof, &pis)
        .map_err(|e| VerifyEnvelopeError::VerifierRejected(format!("{e:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plonky3::prove;

    const WITNESS: [u8; 32] = [0x5a; 32];
    const BINDING: [u8; 32] = [0x11; 32];

    fn proof_in(system: ProofSystem, circuit: Circuit) -> Proof {
        prove(system, circuit, &WITNESS, &BINDING).expect("honest witness proves")
    }

    #[test]
    fn honest_proofs_verify_in_every_system() {
        for system in ProofSystem::ALL {
            for circuit in Circuit::ALL {
                let started = std::time::Instant::now();
                let p = proof_in(system, circuit);
                let proved = started.elapsed();
                let started = std::time::Instant::now();
                verify_proof_envelope(&p)
                    .unwrap_or_else(|e| panic!("{system} {} must verify: {e}", circuit.id()));
                eprintln!(
                    "{system} {}: {} proof bytes, prove {proved:?}, verify {:?}",
                    circuit.id(),
                    p.proof_bytes.len(),
                    started.elapsed()
                );
                assert_eq!(p.public_inputs[0], circuit.digest(&WITNESS).to_vec());
            }
        }
    }

    #[test]
    fn honest_proofs_have_the_expected_degree_bits() {
        let p = proof_in(ProofSystem::KoalaBearSha256Fri, Circuit::Identity);
        let decoded: p3_uni_stark::Proof<config::koala_bear::Config> =
            bincode::deserialize(&p.proof_bytes).unwrap();
        assert_eq!(decoded.degree_bits, EXPECTED_DEGREE_BITS);
    }

    /// Someone who knows the published digest but not the witness takes a
    /// valid proof for a witness of their own and presents it against the
    /// victim's digest.
    #[test]
    fn proof_for_another_witness_is_rejected_against_the_victims_digest() {
        let victim_digest = Circuit::Identity.digest(&[0x77; 32]);
        for system in ProofSystem::ALL {
            let mut p = proof_in(system, Circuit::Identity);
            p.public_inputs[0] = victim_digest.to_vec();
            assert!(
                matches!(
                    verify_proof_envelope(&p),
                    Err(VerifyEnvelopeError::VerifierRejected(_))
                ),
                "{system}"
            );
        }
    }

    /// A proof made for one binding is replayed into another context.
    #[test]
    fn proof_replayed_under_a_different_binding_is_rejected() {
        for system in ProofSystem::ALL {
            let mut p = proof_in(system, Circuit::Settlement);
            p.public_inputs[1] = vec![0x22; 32];
            assert!(verify_proof_envelope(&p).is_err(), "{system}");
        }
    }

    /// An identity proof is relabelled as a settlement proof with the same
    /// digest and binding.
    #[test]
    fn identity_proof_does_not_verify_as_settlement() {
        for system in [ProofSystem::KoalaBearSha256Fri, ProofSystem::Halo2IpaPasta] {
            let mut p = proof_in(system, Circuit::Identity);
            p.circuit_id = Circuit::Settlement.id().to_string();
            assert!(verify_proof_envelope(&p).is_err(), "{system}");
        }
    }

    /// Proof bytes from one system presented under another system's tag.
    #[test]
    fn proof_under_the_wrong_system_tag_is_rejected() {
        let mut p = proof_in(ProofSystem::KoalaBearSha256Fri, Circuit::Settlement);
        p.system = ProofSystem::GoldilocksBlake3Fri;
        assert!(verify_proof_envelope(&p).is_err());
        p.system = ProofSystem::Halo2IpaPasta;
        assert!(verify_proof_envelope(&p).is_err());
        let mut h = proof_in(ProofSystem::Halo2IpaPasta, Circuit::Settlement);
        h.system = ProofSystem::KoalaBearSha256Fri;
        assert!(verify_proof_envelope(&h).is_err());
    }

    #[test]
    fn unknown_circuit_and_malformed_statements_are_rejected() {
        let mut p = proof_in(ProofSystem::KoalaBearSha256Fri, Circuit::Settlement);
        p.circuit_id = "inference".to_string();
        assert!(matches!(
            verify_proof_envelope(&p),
            Err(VerifyEnvelopeError::UnknownCircuit(_))
        ));

        let mut p = proof_in(ProofSystem::KoalaBearSha256Fri, Circuit::Settlement);
        p.public_inputs.pop();
        assert!(matches!(
            verify_proof_envelope(&p),
            Err(VerifyEnvelopeError::EnvelopeDecode(_))
        ));

        let mut p = proof_in(ProofSystem::KoalaBearSha256Fri, Circuit::Settlement);
        p.proof_bytes = vec![0xde, 0xad, 0xbe, 0xef];
        assert!(matches!(
            verify_proof_envelope(&p),
            Err(VerifyEnvelopeError::EnvelopeDecode(_))
        ));
    }

    /// The prover itself cannot produce a proof whose trace hashes a
    /// different witness than the digest it claims. Built directly against
    /// the AIR so the claimed digest can be forged.
    #[test]
    fn trace_of_one_witness_cannot_prove_another_digest() {
        let config = config::koala_bear::config();
        let air = PreimageAir::new(Circuit::Identity);
        let trace = air.generate_trace::<p3_koala_bear::KoalaBear>(&[0x01; 32]);
        let forged = public_values::<p3_koala_bear::KoalaBear>(
            &Circuit::Identity.digest(&[0x02; 32]),
            &BINDING,
        );
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            p3_uni_stark::prove(&config, &air, trace, &forged)
        }));
        if let Ok(proof) = outcome {
            assert!(p3_uni_stark::verify(&config, &air, &proof, &forged).is_err());
        }
    }

    /// A trace whose absorbed block carries the identity domain cannot prove
    /// the settlement statement for that block's digest.
    #[test]
    fn trace_under_one_domain_cannot_prove_the_other_circuit() {
        let config = config::koala_bear::config();
        let identity_trace = PreimageAir::new(Circuit::Identity)
            .generate_trace::<p3_koala_bear::KoalaBear>(&WITNESS);
        let settlement_air = PreimageAir::new(Circuit::Settlement);
        // The digest the identity block actually hashes to.
        let pis = public_values::<p3_koala_bear::KoalaBear>(
            &Circuit::Identity.digest(&WITNESS),
            &BINDING,
        );
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            p3_uni_stark::prove(&config, &settlement_air, identity_trace, &pis)
        }));
        if let Ok(proof) = outcome {
            assert!(p3_uni_stark::verify(&config, &settlement_air, &proof, &pis).is_err());
        }
    }
}
