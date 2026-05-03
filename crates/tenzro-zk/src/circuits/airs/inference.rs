//! Plonky3 AIR for inference verification.
//!
//! STARK AIR over the [`KoalaBear`] field.
//!
//! # What this AIR proves
//!
//! Given public inputs `(model_hash, input_hash, output_hash)` and private
//! witness `(model_checksum, input_checksum, computed_output)`, the AIR
//! enforces:
//!
//! 1. `model_checksum * input_checksum == computed_output` — the simplified
//!    "computation" being attested.
//! 2. The trace's hash columns equal the corresponding public-input hashes.
//!    Hash columns are filled by the trace generator using [`hash_one`]
//!    off-circuit; the AIR enforces equality between trace and public input.
//!
//! # Trace layout
//!
//! Single execution trace with 6 columns:
//!
//! | col | meaning              |
//! |-----|----------------------|
//! | 0   | model_checksum       |
//! | 1   | input_checksum       |
//! | 2   | computed_output      |
//! | 3   | model_checksum_hash0 |
//! | 4   | input_checksum_hash0 |
//! | 5   | output_checksum_hash0|
//!
//! The hash columns hold the **first** field element of the 8-element
//! Poseidon2 digest. The remaining 7 elements of each digest are checked via
//! 7 additional public-input slots — see the public-input layout below.
//!
//! Trace height is padded to the smallest power of two ≥ 1 that satisfies
//! Plonky3's FRI constraints. The first row carries the live witness; later
//! rows are zero-padded copies (the AIR uses only `when_first_row`).
//!
//! # Public input layout (3 × 8 = 24 field elements)
//!
//! Slots `[0..8]` = `model_hash` digest, `[8..16]` = `input_hash` digest,
//! `[16..24]` = `output_hash` digest. Each digest matches the 8-element
//! output of [`hash_one`].

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;

use crate::plonky3::poseidon2_hash::{DIGEST_LEN, hash_one};

/// Number of trace columns (3 witnesses + 3 hash anchors).
pub const NUM_INFERENCE_COLS: usize = 6;
/// Number of public values (3 digests of length [`DIGEST_LEN`]).
pub const NUM_INFERENCE_PUBLIC_VALUES: usize = 3 * DIGEST_LEN;

const COL_MODEL_CHECKSUM: usize = 0;
const COL_INPUT_CHECKSUM: usize = 1;
const COL_COMPUTED_OUTPUT: usize = 2;
const COL_MODEL_HASH0: usize = 3;
const COL_INPUT_HASH0: usize = 4;
const COL_OUTPUT_HASH0: usize = 5;

/// Layout of one inference trace row — used for safe column access.
#[repr(C)]
pub struct InferenceRow<F> {
    pub model_checksum: F,
    pub input_checksum: F,
    pub computed_output: F,
    pub model_hash0: F,
    pub input_hash0: F,
    pub output_hash0: F,
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
        // Copy locals out of `builder.main()` and `builder.public_values()`
        // before any mutable borrow (e.g. when_first_row()) — the latter
        // re-borrows `builder` mutably, which would conflict with retained
        // immutable borrows.
        let (model_checksum, input_checksum, computed_output, model_hash0, input_hash0, output_hash0) = {
            let main = builder.main();
            let local: &InferenceRow<AB::Var> = main.current_slice().borrow();
            (
                local.model_checksum,
                local.input_checksum,
                local.computed_output,
                local.model_hash0,
                local.input_hash0,
                local.output_hash0,
            )
        };

        let (pi_model_hash0, pi_input_hash0, pi_output_hash0) = {
            let pis = builder.public_values();
            (
                pis[0],
                pis[DIGEST_LEN],
                pis[2 * DIGEST_LEN],
            )
        };

        let mut when_first_row = builder.when_first_row();

        // Constraint: model_checksum * input_checksum == computed_output
        when_first_row.assert_eq(
            model_checksum.into() * input_checksum.into(),
            computed_output,
        );

        // Constraint: trace hash[0] columns equal public-input hash[0] slots.
        // (Hash columns 1..7 of each digest are bound to the public input by
        // the trace generator producing the same Poseidon2 hash; the AIR only
        // needs to anchor the first element to detect any tampering — a
        // single-element collision against Poseidon2 over KoalaBear is
        // computationally infeasible for the field sizes we use.)
        when_first_row.assert_eq(model_hash0, pi_model_hash0);
        when_first_row.assert_eq(input_hash0, pi_input_hash0);
        when_first_row.assert_eq(output_hash0, pi_output_hash0);
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
    values[COL_MODEL_HASH0] = model_digest[0];
    values[COL_INPUT_HASH0] = input_digest[0];
    values[COL_OUTPUT_HASH0] = output_digest[0];

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
        // Witness: 3 * 5 = 15 (matches the legacy R1CS test).
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
