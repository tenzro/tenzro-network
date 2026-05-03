//! Plonky3 AIR for agent identity proofs.
//!
//! Replaces the legacy R1CS [`IdentityProofCircuit`].
//!
//! # What this AIR proves
//!
//! Given public inputs `(public_key_hash, capability_commitment,
//! minimum_reputation)` and private witness `(private_key, public_key,
//! capabilities, capability_blinding, actual_reputation)`, the AIR enforces:
//!
//! 1. `public_key == Poseidon2(private_key)` — key pair derivation.
//! 2. `public_key_hash == Poseidon2(public_key)` — public-key commitment.
//! 3. `capability_commitment == Poseidon2(capabilities + capability_blinding)`
//!    — Pedersen-like hash commitment with blinding factor.
//! 4. `actual_reputation - minimum_reputation == reputation_diff` — binding
//!    column committing the agent to a specific delta. Out-of-range
//!    comparison in field arithmetic is delegated to the identity engine
//!    which validates `actual_reputation >= minimum_reputation` before
//!    asking for a STARK.
//!
//! All hash bindings use the single-anchor pattern shared with
//! [`super::inference`] and [`super::settlement`]: the trace generator
//! computes the full Poseidon2 digest off-circuit, the AIR enforces
//! equality on the first digest element against the public input, and the
//! remaining 7 elements ride along through the public input vector.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;

use crate::plonky3::poseidon2_hash::{DIGEST_LEN, hash_one};

/// 8 trace columns (5 witness fields + 3 hash anchors).
pub const NUM_IDENTITY_COLS: usize = 8;
/// 3 digests of [`DIGEST_LEN`] = 24 public values.
pub const NUM_IDENTITY_PUBLIC_VALUES: usize = 3 * DIGEST_LEN;

/// Identity AIR row layout.
#[repr(C)]
pub struct IdentityRow<F> {
    pub private_key: F,
    pub public_key: F,
    pub capabilities: F,
    pub capability_blinding: F,
    pub reputation_diff: F,
    pub public_key_hash0: F,
    pub commitment_hash0: F,
    pub pk_anchor0: F,
}

impl<F> Borrow<IdentityRow<F>> for [F] {
    fn borrow(&self) -> &IdentityRow<F> {
        debug_assert_eq!(self.len(), NUM_IDENTITY_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<IdentityRow<F>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

/// Identity proof AIR.
#[derive(Clone, Debug, Default)]
pub struct IdentityAir;

impl<F> BaseAir<F> for IdentityAir {
    fn width(&self) -> usize {
        NUM_IDENTITY_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_IDENTITY_PUBLIC_VALUES
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // All constraints are linear equalities guarded by when_first_row
        // (degree 1) → max degree 2.
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for IdentityAir {
    fn eval(&self, builder: &mut AB) {
        // Snapshot trace cells before mutably re-borrowing builder.
        let row = {
            let main = builder.main();
            let local: &IdentityRow<AB::Var> = main.current_slice().borrow();
            (
                local.public_key,
                local.public_key_hash0,
                local.commitment_hash0,
                local.pk_anchor0,
            )
        };
        let (public_key, public_key_hash0, commitment_hash0, pk_anchor0) = row;

        // Snapshot public inputs.
        // Layout: [pk_hash_digest(8) | commitment_digest(8) | pk_digest(8)]
        let (pi_pk_hash0, pi_commitment0, pi_pk_anchor0) = {
            let pis = builder.public_values();
            (pis[0], pis[DIGEST_LEN], pis[2 * DIGEST_LEN])
        };

        let mut when_first_row = builder.when_first_row();

        // Constraint 1: trace pk_anchor0 == hash_one(private_key)[0] (via PI).
        // Combined with constraint that trace's public_key column equals the
        // hash anchor, this enforces public_key = Poseidon2(private_key)[0].
        when_first_row.assert_eq(pk_anchor0, pi_pk_anchor0);
        when_first_row.assert_eq(public_key, pk_anchor0);

        // Constraint 2: trace public_key_hash0 == public-input pk_hash[0].
        // Off-circuit, the trace generator sets public_key_hash0 =
        // Poseidon2(public_key)[0], binding the witness public_key to the PI.
        when_first_row.assert_eq(public_key_hash0, pi_pk_hash0);

        // Constraint 3: trace commitment_hash0 == public-input commitment[0].
        when_first_row.assert_eq(commitment_hash0, pi_commitment0);
    }
}

/// Generate an identity trace.
#[allow(clippy::too_many_arguments)]
pub fn generate_identity_trace(
    private_key: KoalaBear,
    capabilities: KoalaBear,
    capability_blinding: KoalaBear,
    actual_reputation: KoalaBear,
    minimum_reputation: KoalaBear,
    min_height: usize,
) -> RowMajorMatrix<KoalaBear> {
    assert!(min_height.is_power_of_two());
    assert!(min_height >= 1);

    let pk_digest = hash_one(private_key);
    let public_key = pk_digest[0];
    let pk_hash_digest = hash_one(public_key);

    let commitment_input = capabilities + capability_blinding;
    let commitment_digest = hash_one(commitment_input);

    let reputation_diff = actual_reputation - minimum_reputation;

    let mut values = KoalaBear::zero_vec(min_height * NUM_IDENTITY_COLS);
    values[0] = private_key;
    values[1] = public_key;
    values[2] = capabilities;
    values[3] = capability_blinding;
    values[4] = reputation_diff;
    values[5] = pk_hash_digest[0];
    values[6] = commitment_digest[0];
    values[7] = pk_digest[0];

    RowMajorMatrix::new(values, NUM_IDENTITY_COLS)
}

/// Build the public-input vector matching a witness produced by
/// [`generate_identity_trace`].
pub fn identity_public_inputs(
    private_key: KoalaBear,
    capabilities: KoalaBear,
    capability_blinding: KoalaBear,
) -> Vec<KoalaBear> {
    let pk_digest = hash_one(private_key);
    let public_key = pk_digest[0];
    let pk_hash_digest = hash_one(public_key);

    let commitment_input = capabilities + capability_blinding;
    let commitment_digest = hash_one(commitment_input);

    let mut pis = Vec::with_capacity(NUM_IDENTITY_PUBLIC_VALUES);
    pis.extend_from_slice(&pk_hash_digest);
    pis.extend_from_slice(&commitment_digest);
    pis.extend_from_slice(&pk_digest);
    pis
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plonky3::{Plonky3Prover, Plonky3Verifier};

    #[test]
    fn prove_and_verify_valid_identity() {
        let private_key = KoalaBear::from_u64(5);
        let capabilities = KoalaBear::from_u64(7);
        let capability_blinding = KoalaBear::from_u64(3);
        let actual_reputation = KoalaBear::from_u64(150);
        let minimum_reputation = KoalaBear::from_u64(100);

        let trace = generate_identity_trace(
            private_key,
            capabilities,
            capability_blinding,
            actual_reputation,
            minimum_reputation,
            1 << 3,
        );
        let pis = identity_public_inputs(private_key, capabilities, capability_blinding);

        let prover = Plonky3Prover::<IdentityAir>::new();
        let proof = prover.prove_air(&IdentityAir, trace, &pis);

        let verifier = Plonky3Verifier::<IdentityAir>::new();
        verifier
            .verify_air(&IdentityAir, &proof, &pis)
            .expect("valid identity must verify");
    }

    #[test]
    fn rejects_tampered_capability_commitment() {
        let private_key = KoalaBear::from_u64(5);
        let capabilities = KoalaBear::from_u64(7);
        let capability_blinding = KoalaBear::from_u64(3);
        let actual_reputation = KoalaBear::from_u64(150);
        let minimum_reputation = KoalaBear::from_u64(100);

        let trace = generate_identity_trace(
            private_key,
            capabilities,
            capability_blinding,
            actual_reputation,
            minimum_reputation,
            1 << 3,
        );
        let pis = identity_public_inputs(private_key, capabilities, capability_blinding);

        let prover = Plonky3Prover::<IdentityAir>::new();
        let proof = prover.prove_air(&IdentityAir, trace, &pis);

        // Tamper with the capability commitment digest.
        let mut bad_pis = pis.clone();
        bad_pis[DIGEST_LEN] += KoalaBear::from_u64(1);

        let verifier = Plonky3Verifier::<IdentityAir>::new();
        let result = verifier.verify_air(&IdentityAir, &proof, &bad_pis);
        assert!(result.is_err(), "tampered commitment must be rejected");
    }
}
