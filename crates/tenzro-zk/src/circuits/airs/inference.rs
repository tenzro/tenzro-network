//! Plonky3 AIR for inference verification.
//!
//! STARK AIR over the [`KoalaBear`] field.
//!
//! # What this AIR proves
//!
//! Public inputs: `(model_hash[..8], input_hash[..8], output_hash[..8])`.
//! Private witness: `(model_checksum, input_checksum, computed_output)`.
//!
//! Constraints:
//! 1. `model_checksum * input_checksum == computed_output`.
//! 2. The trace's hash columns equal the public-input digest slots for
//!    every `DIGEST_LEN` element. This binds the declared
//!    `(model_hash, input_hash, output_hash)` to the trace's own copy
//!    bit-for-bit.
//!
//! # Soundness scope
//!
//! The trace generator computes `hash_one(witness)` off-circuit and
//! writes the result into the hash columns. The AIR checks that the
//! trace's hash columns equal the public-input slots, but it does NOT
//! evaluate Poseidon2 in-circuit, so a prover can supply arbitrary
//! `(witness, declared_hash)` pairs as long as `m*i==o` AND the trace's
//! hash columns match the public-input slots.
//!
//! A relying party that treats the public-input digests as canonical
//! artefact hashes (e.g. `sha256(model_bytes)`) must additionally
//! verify out of band that the witness's off-circuit hash matches the
//! declared artefact. The `tenzro_verifyZkProof` RPC reports
//! `soundness_class: "advisory"` for this AIR so relying parties cannot
//! silently use it as a value-binding gate.
//!
//! # Trace layout (`NUM_INFERENCE_COLS = 3 + 3 × DIGEST_LEN`)
//!
//! | col index             | meaning                          |
//! |-----------------------|----------------------------------|
//! | 0                     | model_checksum                   |
//! | 1                     | input_checksum                   |
//! | 2                     | computed_output                  |
//! | 3..3+DIGEST_LEN       | Poseidon2 digest of model        |
//! | …+DIGEST_LEN          | Poseidon2 digest of input        |
//! | …+DIGEST_LEN          | Poseidon2 digest of output       |
//!
//! Trace height is padded to the smallest power of two ≥ 1 that
//! satisfies Plonky3's FRI constraints. The first row carries the live
//! witness; later rows are zero-padded (the AIR uses only
//! `when_first_row`).
//!
//! # Public input layout (3 × `DIGEST_LEN` = 24 field elements)
//!
//! `[0..DIGEST_LEN]` model_hash, `[DIGEST_LEN..2*DIGEST_LEN]` input_hash,
//! `[2*DIGEST_LEN..3*DIGEST_LEN]` output_hash. Each digest matches the
//! `DIGEST_LEN`-element output of [`hash_one`].

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;

use crate::plonky3::poseidon2_hash::{DIGEST_LEN, hash_one};

/// Number of trace columns: 3 witnesses + 3 × [`DIGEST_LEN`] hash
/// anchors. The trace carries the full 8-element Poseidon2 output for
/// each of the three digests, and the AIR constrains every trace cell
/// against its public-input slot.
pub const NUM_INFERENCE_COLS: usize = 3 + 3 * DIGEST_LEN;
/// Number of public values (3 digests of length [`DIGEST_LEN`]).
pub const NUM_INFERENCE_PUBLIC_VALUES: usize = 3 * DIGEST_LEN;

const COL_MODEL_CHECKSUM: usize = 0;
const COL_INPUT_CHECKSUM: usize = 1;
const COL_COMPUTED_OUTPUT: usize = 2;
const COL_MODEL_HASH_BASE: usize = 3;
const COL_INPUT_HASH_BASE: usize = 3 + DIGEST_LEN;
const COL_OUTPUT_HASH_BASE: usize = 3 + 2 * DIGEST_LEN;

/// Layout of one inference trace row.
///
/// The row holds the three private witnesses followed by three
/// `DIGEST_LEN`-element Poseidon2 digests. `#[repr(C)]` + the
/// `[KoalaBear; DIGEST_LEN]` shape keeps the contiguous-bytes alignment
/// that `align_to::<InferenceRow<F>>()` relies on for safe column access
/// from a `&[F]`.
#[repr(C)]
pub struct InferenceRow<F> {
    pub model_checksum: F,
    pub input_checksum: F,
    pub computed_output: F,
    pub model_hash: [F; DIGEST_LEN],
    pub input_hash: [F; DIGEST_LEN],
    pub output_hash: [F; DIGEST_LEN],
}

impl<F> Borrow<InferenceRow<F>> for [F] {
    fn borrow(&self) -> &InferenceRow<F> {
        debug_assert_eq!(self.len(), NUM_INFERENCE_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<InferenceRow<F>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

/// Inference verification AIR.
#[derive(Clone, Debug, Default)]
pub struct InferenceAir;

impl<F> BaseAir<F> for InferenceAir {
    fn width(&self) -> usize {
        NUM_INFERENCE_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_INFERENCE_PUBLIC_VALUES
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // The multiplication constraint is degree 2 (a*b = c). All other
        // constraints are linear equality. Guarded by when_first_row (degree 1)
        // gives total degree 3.
        Some(3)
    }
}

impl<AB: AirBuilder> Air<AB> for InferenceAir {
    fn eval(&self, builder: &mut AB) {
        // Snapshot the row + public inputs BEFORE acquiring the
        // `when_first_row()` filter, which mutably re-borrows `builder`.
        // The trace row carries 3 witnesses followed by 3 × DIGEST_LEN
        // hash elements; we copy each of the 8 elements per digest
        // because the AIR constraints below enforce equality across
        // every slot.
        let (model_checksum, input_checksum, computed_output, model_hash, input_hash, output_hash) = {
            let main = builder.main();
            let local: &InferenceRow<AB::Var> = main.current_slice().borrow();
            (
                local.model_checksum,
                local.input_checksum,
                local.computed_output,
                local.model_hash,
                local.input_hash,
                local.output_hash,
            )
        };

        let pi_model_hash: [AB::PublicVar; DIGEST_LEN];
        let pi_input_hash: [AB::PublicVar; DIGEST_LEN];
        let pi_output_hash: [AB::PublicVar; DIGEST_LEN];
        {
            let pis = builder.public_values();
            pi_model_hash = core::array::from_fn(|k| pis[k]);
            pi_input_hash = core::array::from_fn(|k| pis[DIGEST_LEN + k]);
            pi_output_hash = core::array::from_fn(|k| pis[2 * DIGEST_LEN + k]);
        }

        let mut when_first_row = builder.when_first_row();

        // Constraint: model_checksum * input_checksum == computed_output.
        when_first_row.assert_eq(
            model_checksum.into() * input_checksum.into(),
            computed_output,
        );

        // Constraint: full DIGEST_LEN binding — trace[hash[k]] equals
        // public-input[hash[k]] for every k.
        for k in 0..DIGEST_LEN {
            when_first_row.assert_eq(model_hash[k], pi_model_hash[k]);
            when_first_row.assert_eq(input_hash[k], pi_input_hash[k]);
            when_first_row.assert_eq(output_hash[k], pi_output_hash[k]);
        }
    }
}

/// Generate a 1-row trace (padded to `min_height`) for the inference AIR.
///
/// `min_height` must be a power of two and ≥ 1. The recommended value for
/// testnet is `1 << 3 = 8` (matches the FibonacciAir example, satisfies
/// `log_min_height > log_final_poly_len + log_blowup` for our config).
pub fn generate_inference_trace(
    model_checksum: KoalaBear,
    input_checksum: KoalaBear,
    computed_output: KoalaBear,
    min_height: usize,
) -> RowMajorMatrix<KoalaBear> {
    assert!(min_height.is_power_of_two());
    assert!(min_height >= 1);

    let model_digest = hash_one(model_checksum);
    let input_digest = hash_one(input_checksum);
    let output_digest = hash_one(computed_output);

    let mut values = KoalaBear::zero_vec(min_height * NUM_INFERENCE_COLS);

    // Row 0 — live witness.
    values[COL_MODEL_CHECKSUM] = model_checksum;
    values[COL_INPUT_CHECKSUM] = input_checksum;
    values[COL_COMPUTED_OUTPUT] = computed_output;
    // Populate the full DIGEST_LEN of each digest; the AIR constrains
    // every cell against its public-input slot.
    for k in 0..DIGEST_LEN {
        values[COL_MODEL_HASH_BASE + k] = model_digest[k];
        values[COL_INPUT_HASH_BASE + k] = input_digest[k];
        values[COL_OUTPUT_HASH_BASE + k] = output_digest[k];
    }

    // Rows 1.. are zero-padding. Constraints are guarded by when_first_row
    // so they remain trivially satisfied on the padding rows.

    RowMajorMatrix::new(values, NUM_INFERENCE_COLS)
}

/// Build the public-input vector matching a witness produced by
/// [`generate_inference_trace`]. Returns `3 × DIGEST_LEN` field elements.
pub fn inference_public_inputs(
    model_checksum: KoalaBear,
    input_checksum: KoalaBear,
    computed_output: KoalaBear,
) -> Vec<KoalaBear> {
    let model_digest = hash_one(model_checksum);
    let input_digest = hash_one(input_checksum);
    let output_digest = hash_one(computed_output);

    let mut pis = Vec::with_capacity(NUM_INFERENCE_PUBLIC_VALUES);
    pis.extend_from_slice(&model_digest);
    pis.extend_from_slice(&input_digest);
    pis.extend_from_slice(&output_digest);
    pis
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plonky3::{Plonky3Prover, Plonky3Verifier};

    #[test]
    fn prove_and_verify_valid_inference() {
        // Witness: 3 * 5 = 15.
        let model = KoalaBear::from_u64(3);
        let input = KoalaBear::from_u64(5);
        let output = KoalaBear::from_u64(15);

        let trace = generate_inference_trace(model, input, output, 1 << 3);
        let pis = inference_public_inputs(model, input, output);

        let prover = Plonky3Prover::<InferenceAir>::new();
        let proof = prover.prove_air(&InferenceAir, trace, &pis);

        let verifier = Plonky3Verifier::<InferenceAir>::new();
        verifier
            .verify_air(&InferenceAir, &proof, &pis)
            .expect("valid proof must verify");
    }

    #[test]
    fn rejects_bad_multiplication() {
        // Wrong output: 3 * 5 ≠ 16.
        let model = KoalaBear::from_u64(3);
        let input = KoalaBear::from_u64(5);
        let output = KoalaBear::from_u64(16);

        // Generating the trace happily fills the witness columns — but the AIR
        // multiplication constraint will fire during proving (debug_assertions)
        // or verification (release).
        let trace = generate_inference_trace(model, input, output, 1 << 3);
        let pis = inference_public_inputs(model, input, output);

        let prover = Plonky3Prover::<InferenceAir>::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prover.prove_air(&InferenceAir, trace, &pis)
        }));

        // In debug builds Plonky3 panics on unsatisfied constraints during
        // proving. In release builds we'd build the proof and have the
        // verifier reject it; debug is fine for this test.
        assert!(result.is_err(), "bad witness must not produce a valid proof");
    }

    #[test]
    fn rejects_tampered_public_inputs() {
        let model = KoalaBear::from_u64(3);
        let input = KoalaBear::from_u64(5);
        let output = KoalaBear::from_u64(15);

        let trace = generate_inference_trace(model, input, output, 1 << 3);
        let pis = inference_public_inputs(model, input, output);

        let prover = Plonky3Prover::<InferenceAir>::new();
        let proof = prover.prove_air(&InferenceAir, trace, &pis);

        // Tamper with the model_hash digest.
        let mut bad_pis = pis.clone();
        bad_pis[0] += KoalaBear::from_u64(1);

        let verifier = Plonky3Verifier::<InferenceAir>::new();
        let result = verifier.verify_air(&InferenceAir, &proof, &bad_pis);
        assert!(result.is_err(), "tampered public inputs must be rejected");
    }
}
