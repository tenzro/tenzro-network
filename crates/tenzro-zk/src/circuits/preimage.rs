//! Hash-preimage statements, proven with an in-circuit Keccak-f[1600].
//!
//! # Statement
//!
//! For a circuit with 32-byte domain label `D`, public inputs
//! `(digest, binding)` and a private 32-byte witness `w`:
//!
//! ```text
//! digest == SHA3-256(D || w)
//! ```
//!
//! `binding` is not hashed. It is absorbed into the Fiat-Shamir transcript
//! with the rest of the public values, so a proof made for one binding does
//! not verify for any other: a relying party puts its challenge, request hash
//! or context there, and a proof cannot be replayed into a different context
//! by anyone who does not know `w`.
//!
//! # Why the constraints are sufficient
//!
//! The trace is the Plonky3 Keccak-f AIR (every round of the permutation is
//! constrained bit by bit) plus one `active` column. On top of it:
//!
//! 1. On the first row every preimage lane except the four witness lanes is
//!    pinned to a constant: the domain label (lanes 0-3), the SHA3 padding
//!    (lanes 8 and 16) and zero rate/capacity lanes. The witness lanes are free
//!    but range checked to 16-bit limbs by the Keccak AIR's bit decomposition.
//! 2. `active` is 1 on the first row, stays constant inside a permutation and
//!    drops to 0 after the first permutation's final round, so it selects the
//!    first permutation only.
//! 3. On the row where `active == 1` and the round flag is the final round,
//!    the first 256 bits of the permuted state equal the `digest` limbs.
//!
//! A prover who knows only `digest` must therefore exhibit a Keccak-f preimage
//! with the fixed domain and padding, which is a SHA3-256 preimage.
//!
//! # Trace height
//!
//! [`TRACE_HEIGHT`] rows hold the real permutation followed by zero-input
//! padding permutations. The height is chosen larger than the number of
//! points a verifier opens (FRI queries plus the two out-of-domain points),
//! which the hiding PCS needs to keep the witness hidden.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_keccak_air::{KeccakAir, KeccakCols, NUM_KECCAK_COLS, NUM_ROUNDS, generate_trace_rows};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::SubAirBuilder;
use sha3::{Digest, Sha3_256};

/// Bytes in a witness, a digest, a binding and a domain label.
pub const WORD_BYTES: usize = 32;

/// Field elements per 32-byte word (16-bit limbs).
pub const WORD_LIMBS: usize = WORD_BYTES / 2;

/// Public values: digest limbs followed by binding limbs.
pub const NUM_PUBLIC_VALUES: usize = 2 * WORD_LIMBS;

/// Trace columns: the Keccak-f AIR plus the `active` selector.
pub const NUM_COLS: usize = NUM_KECCAK_COLS + 1;

/// Column index of the `active` selector.
const ACTIVE_COL: usize = NUM_KECCAK_COLS;

/// Trace rows (five permutations' worth, rounded up to a power of two).
pub const TRACE_HEIGHT: usize = 128;

/// SHA3 rate in bytes (1088 bits).
const RATE_BYTES: usize = 136;

/// First preimage lane that carries the witness.
const WITNESS_FIRST_LANE: usize = 4;

/// Number of 64-bit lanes carrying the witness.
const WITNESS_LANES: usize = WORD_BYTES / 8;

/// The statements Tenzro proves. Each is a preimage statement under its own
/// domain label, so a proof for one can never verify as the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Circuit {
    /// Knowledge of the secret behind a published identity key commitment.
    Identity,
    /// Knowledge of the service result a customer committed to before paying.
    Settlement,
}

impl Circuit {
    /// Every circuit a verifier knows.
    pub const ALL: [Circuit; 2] = [Circuit::Identity, Circuit::Settlement];

    /// Wire identifier used in proof envelopes.
    pub fn id(&self) -> &'static str {
        match self {
            Circuit::Identity => "identity",
            Circuit::Settlement => "settlement",
        }
    }

    /// Resolve a wire identifier.
    pub fn parse(id: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.id() == id)
    }

    fn label(&self) -> &'static [u8] {
        match self {
            Circuit::Identity => b"tenzro/zk/identity-key",
            Circuit::Settlement => b"tenzro/zk/settlement-service",
        }
    }

    /// The 32-byte domain label (ASCII, zero padded).
    pub fn domain(&self) -> [u8; WORD_BYTES] {
        let mut d = [0u8; WORD_BYTES];
        let label = self.label();
        d[..label.len()].copy_from_slice(label);
        d
    }

    /// `SHA3-256(domain || witness)` — the public digest for `witness`.
    pub fn digest(&self, witness: &[u8; WORD_BYTES]) -> [u8; WORD_BYTES] {
        let mut h = Sha3_256::new();
        h.update(self.domain());
        h.update(witness);
        h.finalize().into()
    }

    /// The SHA3-padded single-block Keccak state for `witness`.
    fn initial_state(&self, witness: &[u8; WORD_BYTES]) -> [u64; 25] {
        let mut block = [0u8; RATE_BYTES];
        block[..WORD_BYTES].copy_from_slice(&self.domain());
        block[WORD_BYTES..2 * WORD_BYTES].copy_from_slice(witness);
        // SHA3 domain-separation suffix 0b01 followed by pad10*1.
        block[2 * WORD_BYTES] = 0x06;
        block[RATE_BYTES - 1] |= 0x80;
        let mut state = [0u64; 25];
        for (lane, chunk) in block.as_chunks::<8>().0.iter().enumerate() {
            state[lane] = u64::from_le_bytes(*chunk);
        }
        state
    }

    /// Every constant `(lane, limb, value)` of the initial state, i.e. every
    /// preimage limb except the witness lanes.
    fn constant_limbs(&self) -> Vec<(usize, usize, u16)> {
        let state = self.initial_state(&[0u8; WORD_BYTES]);
        let mut out = Vec::with_capacity(25 * 4);
        for (lane, value) in state.iter().enumerate() {
            if (WITNESS_FIRST_LANE..WITNESS_FIRST_LANE + WITNESS_LANES).contains(&lane) {
                continue;
            }
            for limb in 0..4 {
                out.push((lane, limb, (value >> (16 * limb)) as u16));
            }
        }
        out
    }
}

/// Split a 32-byte word into 16 little-endian 16-bit limbs.
pub fn word_to_limbs(word: &[u8; WORD_BYTES]) -> [u16; WORD_LIMBS] {
    core::array::from_fn(|k| u16::from_le_bytes([word[2 * k], word[2 * k + 1]]))
}

/// Public values for `(digest, binding)` in field `F`.
pub fn public_values<F: PrimeCharacteristicRing>(
    digest: &[u8; WORD_BYTES],
    binding: &[u8; WORD_BYTES],
) -> Vec<F> {
    word_to_limbs(digest)
        .into_iter()
        .chain(word_to_limbs(binding))
        .map(F::from_u16)
        .collect()
}

/// The preimage AIR for one circuit.
#[derive(Debug, Clone, Copy)]
pub struct PreimageAir {
    circuit: Circuit,
}

impl PreimageAir {
    /// The AIR for `circuit`.
    pub fn new(circuit: Circuit) -> Self {
        Self { circuit }
    }

    /// Build the execution trace for `witness`.
    ///
    /// The first permutation absorbs the padded `domain || witness` block;
    /// the remaining rows are zero-input permutations that the constraints
    /// deliberately ignore.
    pub fn generate_trace<F: PrimeField64>(&self, witness: &[u8; WORD_BYTES]) -> RowMajorMatrix<F> {
        // Whole permutations that fit; the generator pads the remaining rows
        // with one more zero-input permutation cut short.
        let permutations = TRACE_HEIGHT / NUM_ROUNDS;
        let mut inputs = vec![[0u64; 25]; permutations];
        inputs[0] = self.circuit.initial_state(witness);
        let keccak = generate_trace_rows::<F>(inputs, 0);
        debug_assert_eq!(keccak.values.len(), TRACE_HEIGHT * NUM_KECCAK_COLS);

        let mut values = F::zero_vec(TRACE_HEIGHT * NUM_COLS);
        for (row, keccak_row) in keccak
            .values
            .as_chunks::<NUM_KECCAK_COLS>()
            .0
            .iter()
            .enumerate()
        {
            let base = row * NUM_COLS;
            values[base..base + NUM_KECCAK_COLS].copy_from_slice(keccak_row);
            if row < NUM_ROUNDS {
                values[base + ACTIVE_COL] = F::ONE;
            }
        }
        RowMajorMatrix::new(values, NUM_COLS)
    }
}

impl<F> BaseAir<F> for PreimageAir {
    fn width(&self) -> usize {
        NUM_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl<AB: AirBuilder> Air<AB> for PreimageAir {
    fn eval(&self, builder: &mut AB) {
        // The full Keccak-f permutation over the first NUM_KECCAK_COLS columns.
        {
            let mut keccak_builder =
                SubAirBuilder::<AB, KeccakAir, AB::Var>::new(builder, 0..NUM_KECCAK_COLS);
            KeccakAir {}.eval(&mut keccak_builder);
        }

        let main = builder.main();
        let local_row = main.current_slice();
        let next_row = main.next_slice();
        let local: &KeccakCols<AB::Var> = local_row[..NUM_KECCAK_COLS].borrow();
        let active = local_row[ACTIVE_COL];
        let next_active = next_row[ACTIVE_COL];
        let final_round = local.step_flags[NUM_ROUNDS - 1];

        let digest: [AB::PublicVar; WORD_LIMBS] = {
            let pis = builder.public_values();
            core::array::from_fn(|k| pis[k])
        };

        // `active` selects exactly the first permutation.
        builder.assert_bool(active);
        builder.when_first_row().assert_one(active);
        builder
            .when_transition()
            .when(AB::Expr::ONE - final_round)
            .assert_eq(next_active, active);
        builder
            .when_transition()
            .when(final_round)
            .assert_zero(next_active);

        // Domain label, SHA3 padding and zero lanes of the absorbed block.
        {
            let mut first = builder.when_first_row();
            for (lane, limb, value) in self.circuit.constant_limbs() {
                let (x, y) = (lane % 5, lane / 5);
                first.assert_eq(local.preimage[y][x][limb], AB::Expr::from_u16(value));
            }
        }

        // The first 256 bits of the permuted state are the public digest.
        let mut output = builder.when(active * final_round);
        for (k, pi) in digest.iter().enumerate() {
            let lane = k / 4;
            let (x, y) = (lane % 5, lane / 5);
            output.assert_eq(local.a_prime_prime_prime(y, x, k % 4), *pi);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_sha3_256_of_domain_and_witness() {
        let witness = [7u8; WORD_BYTES];
        let mut msg = Circuit::Identity.domain().to_vec();
        msg.extend_from_slice(&witness);
        let expected: [u8; 32] = Sha3_256::digest(&msg).into();
        assert_eq!(Circuit::Identity.digest(&witness), expected);
    }

    #[test]
    fn circuits_have_distinct_domains() {
        assert_ne!(Circuit::Identity.domain(), Circuit::Settlement.domain());
        let w = [1u8; WORD_BYTES];
        assert_ne!(Circuit::Identity.digest(&w), Circuit::Settlement.digest(&w));
    }

    #[test]
    fn constant_limbs_exclude_exactly_the_witness_lanes() {
        let limbs = Circuit::Settlement.constant_limbs();
        assert_eq!(limbs.len(), (25 - WITNESS_LANES) * 4);
        assert!(limbs.iter().all(|(lane, _, _)| {
            !(WITNESS_FIRST_LANE..WITNESS_FIRST_LANE + WITNESS_LANES).contains(lane)
        }));
    }

    #[test]
    fn circuit_ids_roundtrip() {
        for c in Circuit::ALL {
            assert_eq!(Circuit::parse(c.id()), Some(c));
        }
        assert_eq!(Circuit::parse("inference"), None);
    }
}
