//! Proving and verifying Tenzro statements in either pinned STARK system.
//!
//! - [`config`] — the two pinned configurations (field, hash, FRI).
//! - [`soundness`] — the proven-security calculation for those parameters.
//! - [`verify_envelope`] — verification of a wire-format [`crate::Proof`].
//!
//! [`prove`] is the single proving entry point for every system, including
//! the Halo2 one ([`crate::halo2`]): it takes the circuit, the system, the
//! 32-byte witness and the 32-byte binding, and returns a proof envelope whose
//! public inputs are `[digest, binding]`.

pub mod config;
pub mod soundness;
pub mod verify_envelope;

use p3_field::PrimeField64;
use p3_uni_stark::{StarkGenericConfig, Val};
use serde::Serialize;

use crate::circuits::Circuit;
use crate::circuits::preimage::{PreimageAir, WORD_BYTES, public_values};
use crate::error::{Result, ZkError};
use crate::proof::{Proof, ProofSystem};

pub use verify_envelope::{VerifyEnvelopeError, verify_proof_envelope};

/// Prove knowledge of `witness` for `circuit` in `system`, bound to
/// `binding`.
///
/// The public digest is computed from the witness, so the statement proven
/// is always the true one; the proof is useful to a verifier only if that
/// verifier already holds the digest it expects.
pub fn prove(
    system: ProofSystem,
    circuit: Circuit,
    witness: &[u8; WORD_BYTES],
    binding: &[u8; WORD_BYTES],
) -> Result<Proof> {
    let proof_bytes = match system {
        ProofSystem::KoalaBearSha256Fri => {
            prove_with(config::koala_bear::config(), circuit, witness, binding)?
        }
        ProofSystem::GoldilocksBlake3Fri => {
            prove_with(config::goldilocks::config(), circuit, witness, binding)?
        }
        ProofSystem::Halo2IpaPasta => crate::halo2::prove(circuit, witness, binding)
            .map_err(|e| ZkError::ProofGenerationFailed(e.to_string()))?,
    };
    Ok(Proof::new_in(
        system,
        proof_bytes,
        vec![circuit.digest(witness).to_vec(), binding.to_vec()],
        circuit.id().to_string(),
    ))
}

fn prove_with<SC>(
    config: SC,
    circuit: Circuit,
    witness: &[u8; WORD_BYTES],
    binding: &[u8; WORD_BYTES],
) -> Result<Vec<u8>>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField64,
    p3_uni_stark::Proof<SC>: Serialize,
{
    let air = PreimageAir::new(circuit);
    let trace = air.generate_trace::<Val<SC>>(witness);
    let pis = public_values::<Val<SC>>(&circuit.digest(witness), binding);
    let proof = p3_uni_stark::prove(&config, &air, trace, &pis);
    bincode::serialize(&proof).map_err(|e| ZkError::SerializationError(e.to_string()))
}
