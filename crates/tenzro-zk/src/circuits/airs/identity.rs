//! Plonky3 AIR for agent identity proofs.
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
//! Hash bindings constrain every `DIGEST_LEN` element of each digest
//! against the public input. The trace generator computes the
//! Poseidon2 digest off-circuit, so the AIR binds the trace cells to
//! the declared public inputs but does NOT bind the witness to its
//! own hash. See [`super::inference`] for the soundness scope.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;

use crate::plonky3::poseidon2_hash::{DIGEST_LEN, hash_one};

/// Trace columns: 5 witness fields + 3 × [`DIGEST_LEN`] hash anchors.
pub const NUM_IDENTITY_COLS: usize = 5 + 3 * DIGEST_LEN;
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
    pub public_key_hash: [F; DIGEST_LEN],
    pub commitment_hash: [F; DIGEST_LEN],
    pub pk_anchor: [F; DIGEST_LEN],
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
        let (public_key, public_key_hash, commitment_hash, pk_anchor) = {
            let main = builder.main();
            let local: &IdentityRow<AB::Var> = main.current_slice().borrow();
            (
                local.public_key,
                local.public_key_hash,
                local.commitment_hash,
                local.pk_anchor,
            )
        };

        // Snapshot public inputs.
        // Layout: [pk_hash_digest(DIGEST_LEN) | commitment_digest(DIGEST_LEN) | pk_digest(DIGEST_LEN)]
        let pi_pk_hash: [AB::PublicVar; DIGEST_LEN];
        let pi_commitment: [AB::PublicVar; DIGEST_LEN];
        let pi_pk_anchor: [AB::PublicVar; DIGEST_LEN];
        {
            let pis = builder.public_values();
            pi_pk_hash = core::array::from_fn(|k| pis[k]);
            pi_commitment = core::array::from_fn(|k| pis[DIGEST_LEN + k]);
            pi_pk_anchor = core::array::from_fn(|k| pis[2 * DIGEST_LEN + k]);
        }

        let mut when_first_row = builder.when_first_row();

        // Combined with constraint that trace's public_key column equals the
        // hash anchor's first element, this enforces public_key =
        // Poseidon2(private_key)[0]. (Constraint 1 in the docs.)
        when_first_row.assert_eq(public_key, pk_anchor[0]);

        // Constraint set: trace digest cells equal public-input digest slots
        // for ALL DIGEST_LEN elements of all three digests.
        for k in 0..DIGEST_LEN {
            when_first_row.assert_eq(public_key_hash[k], pi_pk_hash[k]);
            when_first_row.assert_eq(commitment_hash[k], pi_commitment[k]);
            when_first_row.assert_eq(pk_anchor[k], pi_pk_anchor[k]);
        }
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
    let pkh_base: usize = 5;
    let comm_base: usize = 5 + DIGEST_LEN;
    let pk_base: usize = 5 + 2 * DIGEST_LEN;
    for k in 0..DIGEST_LEN {
        values[pkh_base + k] = pk_hash_digest[k];
        values[comm_base + k] = commitment_digest[k];
        values[pk_base + k] = pk_digest[k];
    }

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
