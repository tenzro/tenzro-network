//! Plonky3 AIR for post-quantum quorum-certificate aggregation.
//!
//! # What this AIR proves
//!
//! A quorum certificate collects one ML-DSA-65 signature per signer over the
//! same vote message. Individual votes are already PQ-hybrid (Ed25519 +
//! ML-DSA-65 + BLS), but the *aggregated* certificate has only a BLS leg —
//! ML-DSA does not aggregate, so the classical BLS aggregate is the only thing
//! a certificate carries. This AIR is the structure that lets a certificate
//! also carry a succinct PQ leg: a single STARK standing in for N ML-DSA
//! verifications over the vote message.
//!
//! Given public inputs `(bitmap[0..N], count, message_digest[0..DIGEST_LEN])`
//! and a private witness `verified[0..N]`, the AIR enforces, on row 0:
//!
//! 1. `bitmap[i]` is boolean for every `i`.
//! 2. `verified[i]` is boolean for every `i`.
//! 3. **Coupling:** `bitmap[i] == bitmap[i] * verified[i]` — a signer counted
//!    in the certificate must carry a passing ML-DSA verification. A set bit
//!    forces `verified[i] = 1`; a clear bit places no constraint on the
//!    (unused) verification cell.
//! 4. `count == Σ bitmap[i]` — the declared signer count equals the popcount
//!    of the bitmap, so a relying party cannot inflate the count past the
//!    signers actually present.
//! 5. The trace's message-digest columns equal the public-input digest slots
//!    for every element, binding the certificate to one vote message.
//!
//! # Soundness scope
//!
//! The trace generator computes each `verified[i]` off-circuit by calling the
//! native `tenzro_crypto::ml_dsa_verify` and writing the boolean result into
//! the witness. The AIR binds the *structure* — booleanity, the
//! bitmap↔verification coupling, the popcount, and the message digest — but it
//! does **not** evaluate the ML-DSA-65 verification equation in-circuit
//! (`w1` recomputation, NTT, hint decoding). A prover who lies and writes
//! `verified[i] = 1` for a signature that does not actually verify produces a
//! structurally-valid STARK.
//!
//! Consequently this AIR is `soundness_class: "advisory"` — identical posture
//! to [`super::inference`] and [`super::identity`], which bind off-circuit
//! Poseidon2 digests rather than evaluating the hash in-circuit. A verifier
//! that wants the PQ leg to be *value-binding* (not advisory) must either
//! re-run the N native verifications out of band, or adopt a future AIR that
//! folds the ML-DSA verification equation into constraints. That in-circuit
//! variant is expensive (lattice arithmetic over a degree-256 ring mod
//! 8380417) and is the subject of the G11 benchmark go/no-go — see the
//! `pq_qc_aggregation` benches. The interim honest posture: per-vote PQ
//! binding exists on the individual votes; the certificate's PQ leg attests to
//! aggregation structure, and the ML-DSA equation itself is checked natively.
//!
//! # Trace layout (`cols_for(num_signers) = 2*N + 1 + DIGEST_LEN`)
//!
//! | col range                     | meaning                              |
//! |-------------------------------|--------------------------------------|
//! | `0 .. N`                      | `bitmap[i]` — signer present (0/1)   |
//! | `N .. 2N`                     | `verified[i]` — ML-DSA passed (0/1)  |
//! | `2N`                          | `count` — declared signer count      |
//! | `2N+1 .. 2N+1+DIGEST_LEN`     | vote-message Poseidon2 digest        |
//!
//! Only row 0 is live; later rows are zero padding (all constraints are
//! `when_first_row`), so the trace height is padded to the smallest power of
//! two that satisfies the FRI config (testnet default `1 << 3`).
//!
//! # Public-input layout (`public_values_for(num_signers) = N + 1 + DIGEST_LEN`)
//!
//! `[bitmap[0..N] | count | message_digest[0..DIGEST_LEN]]`. The bitmap is
//! exposed per-bit so a relying party sees exactly which validator seats the
//! certificate claims, and can weight by stake without trusting an opaque
//! popcount.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;

use crate::plonky3::poseidon2_hash::{DIGEST_LEN, hash_many};

/// Trace column count for a certificate over `num_signers` seats.
pub const fn cols_for(num_signers: usize) -> usize {
    2 * num_signers + 1 + DIGEST_LEN
}

/// Public-value count for a certificate over `num_signers` seats.
pub const fn public_values_for(num_signers: usize) -> usize {
    num_signers + 1 + DIGEST_LEN
}

/// Post-quantum QC aggregation AIR, parameterised by the validator-set size.
///
/// `num_signers` is the number of seats the certificate ranges over. It is a
/// runtime value (not a const generic) because the validator set is
/// permissionless and unbounded — the same AIR type serves N = 4 and
/// N = 10_000 by carrying N in the struct and computing [`BaseAir::width`]
/// from it.
#[derive(Clone, Debug)]
pub struct PqQcAggregationAir {
    num_signers: usize,
}

impl PqQcAggregationAir {
    /// Construct an AIR for a certificate over `num_signers` seats.
    pub fn new(num_signers: usize) -> Self {
        assert!(num_signers >= 1, "a certificate needs at least one seat");
        Self { num_signers }
    }

    /// Number of signer seats this AIR ranges over.
    pub fn num_signers(&self) -> usize {
        self.num_signers
    }
}

impl<F> BaseAir<F> for PqQcAggregationAir {
    fn width(&self) -> usize {
        cols_for(self.num_signers)
    }

    fn num_public_values(&self) -> usize {
        public_values_for(self.num_signers)
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // Booleanity (`b*(b-1)`) and coupling (`bit == bit*verified`) are
        // degree 2; guarded by `when_first_row` (degree 1) → total degree 3.
        Some(3)
    }
}

impl<AB: AirBuilder> Air<AB> for PqQcAggregationAir {
    fn eval(&self, builder: &mut AB) {
        let n = self.num_signers;
        let bit_base = 0usize;
        let verified_base = n;
        let count_col = 2 * n;
        let digest_base = 2 * n + 1;

        // Snapshot the live row cells before acquiring the `when_first_row`
        // filter, which mutably re-borrows the builder.
        let (bits, verifieds, count, digest): (Vec<AB::Var>, Vec<AB::Var>, AB::Var, Vec<AB::Var>) = {
            let main = builder.main();
            let row = main.current_slice();
            let bits: Vec<AB::Var> = (0..n).map(|i| row[bit_base + i]).collect();
            let verifieds: Vec<AB::Var> = (0..n).map(|i| row[verified_base + i]).collect();
            let count = row[count_col];
            let digest: Vec<AB::Var> = (0..DIGEST_LEN).map(|k| row[digest_base + k]).collect();
            (bits, verifieds, count, digest)
        };

        // Snapshot public inputs: [bitmap(N) | count(1) | digest(DIGEST_LEN)].
        let (pi_bits, pi_count, pi_digest): (
            Vec<AB::PublicVar>,
            AB::PublicVar,
            Vec<AB::PublicVar>,
        ) = {
            let pis = builder.public_values();
            let pi_bits: Vec<AB::PublicVar> = (0..n).map(|i| pis[i]).collect();
            let pi_count = pis[n];
            let pi_digest: Vec<AB::PublicVar> = (0..DIGEST_LEN).map(|k| pis[n + 1 + k]).collect();
            (pi_bits, pi_count, pi_digest)
        };

        let mut when_first_row = builder.when_first_row();

        // Running sum of the bitmap, accumulated as an expression so the final
        // popcount constraint is a single linear equality.
        let mut popcount: AB::Expr = AB::Expr::ZERO;
        for i in 0..n {
            let bit = bits[i];
            let verified = verifieds[i];

            // Constraint 1: bit ∈ {0, 1}.
            when_first_row.assert_zero(bit.into() * (bit.into() - AB::Expr::ONE));
            // Constraint 2: verified ∈ {0, 1}.
            when_first_row.assert_zero(verified.into() * (verified.into() - AB::Expr::ONE));
            // Constraint 3: a set bit forces verified = 1.
            // bit == bit * verified  ⇔  bit * (1 - verified) == 0.
            when_first_row.assert_eq(bit, bit.into() * verified.into());
            // Constraint 5a: the trace bitmap equals the public bitmap.
            when_first_row.assert_eq(bit, pi_bits[i]);

            popcount += bit.into();
        }

        // Constraint 4: count == Σ bit[i], and the trace count equals the
        // public count.
        when_first_row.assert_eq(count, popcount);
        when_first_row.assert_eq(count, pi_count);

        // Constraint 5b: the message digest binds the certificate to one vote.
        for k in 0..DIGEST_LEN {
            when_first_row.assert_eq(digest[k], pi_digest[k]);
        }
    }
}

/// Hash a raw vote message to the `DIGEST_LEN`-element Poseidon2 digest used as
/// the certificate's public message binding.
///
/// The message bytes are folded into field elements little-endian, 3 bytes per
/// element (KoalaBear is a 31-bit field, so 3 bytes always fit), with the byte
/// length prepended so distinct-length messages cannot collide under the
/// padding-free sponge.
pub fn message_digest(message: &[u8]) -> [KoalaBear; DIGEST_LEN] {
    let mut felts = Vec::with_capacity(2 + message.len() / 3);
    felts.push(KoalaBear::from_u64(message.len() as u64));
    for chunk in message.chunks(3) {
        let mut v = 0u32;
        for (j, b) in chunk.iter().enumerate() {
            v |= (*b as u32) << (8 * j);
        }
        felts.push(KoalaBear::from_u32(v));
    }
    hash_many(&felts)
}

/// Generate a QC-aggregation trace.
///
/// `bitmap[i]` marks whether seat `i` contributed a signature; `verified[i]`
/// is the off-circuit ML-DSA-65 verification result for that seat (caller
/// supplies it by running [`tenzro_crypto::ml_dsa_verify`] per seat). The two
/// must agree wherever `bitmap[i] == 1` — the AIR rejects a set bit whose
/// verification did not pass.
///
/// `message` is the raw vote message every signer signed. `min_height` must be
/// a power of two ≥ 1.
pub fn generate_pq_qc_trace(
    bitmap: &[bool],
    verified: &[bool],
    message: &[u8],
    min_height: usize,
) -> RowMajorMatrix<KoalaBear> {
    assert!(min_height.is_power_of_two());
    assert!(min_height >= 1);
    let n = bitmap.len();
    assert_eq!(verified.len(), n, "bitmap and verified must be same length");

    let cols = cols_for(n);
    let mut values = KoalaBear::zero_vec(min_height * cols);

    let mut count = 0u64;
    for i in 0..n {
        let bit = bitmap[i];
        values[i] = if bit { KoalaBear::ONE } else { KoalaBear::ZERO };
        values[n + i] = if verified[i] {
            KoalaBear::ONE
        } else {
            KoalaBear::ZERO
        };
        if bit {
            count += 1;
        }
    }
    values[2 * n] = KoalaBear::from_u64(count);

    let digest = message_digest(message);
    let digest_base = 2 * n + 1;
    values[digest_base..(DIGEST_LEN + digest_base)].copy_from_slice(&digest[..DIGEST_LEN]);

    RowMajorMatrix::new(values, cols)
}

/// Build the public-input vector matching a trace from [`generate_pq_qc_trace`].
///
/// Layout: `[bitmap(N) | count | message_digest(DIGEST_LEN)]`.
pub fn pq_qc_public_inputs(bitmap: &[bool], message: &[u8]) -> Vec<KoalaBear> {
    let n = bitmap.len();
    let mut pis = Vec::with_capacity(public_values_for(n));
    let mut count = 0u64;
    for &bit in bitmap {
        pis.push(if bit { KoalaBear::ONE } else { KoalaBear::ZERO });
        if bit {
            count += 1;
        }
    }
    pis.push(KoalaBear::from_u64(count));
    pis.extend_from_slice(&message_digest(message));
    pis
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plonky3::{Plonky3Prover, Plonky3Verifier};

    fn bits(spec: &[u8]) -> Vec<bool> {
        spec.iter().map(|b| *b != 0).collect()
    }

    #[test]
    fn prove_and_verify_valid_quorum() {
        // 4 seats, 3 signed and verified, seat 2 absent.
        let bitmap = bits(&[1, 1, 0, 1]);
        let verified = bits(&[1, 1, 0, 1]);
        let message = b"tenzro/qc/view=42/block=0xdead";

        let air = PqQcAggregationAir::new(bitmap.len());
        let trace = generate_pq_qc_trace(&bitmap, &verified, message, 1 << 3);
        let pis = pq_qc_public_inputs(&bitmap, message);

        let prover = Plonky3Prover::<PqQcAggregationAir>::new();
        let proof = prover.prove_air(&air, trace, &pis);

        let verifier = Plonky3Verifier::<PqQcAggregationAir>::new();
        verifier
            .verify_air(&air, &proof, &pis)
            .expect("valid quorum certificate must verify");
    }

    #[test]
    fn rejects_set_bit_without_verification() {
        // Seat 2's bit is set but its ML-DSA verification did not pass — the
        // coupling constraint must fire during proving.
        let bitmap = bits(&[1, 1, 1, 0]);
        let verified = bits(&[1, 1, 0, 0]);
        let message = b"tenzro/qc/view=7";

        let air = PqQcAggregationAir::new(bitmap.len());
        let trace = generate_pq_qc_trace(&bitmap, &verified, message, 1 << 3);
        let pis = pq_qc_public_inputs(&bitmap, message);

        let prover = Plonky3Prover::<PqQcAggregationAir>::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prover.prove_air(&air, trace, &pis)
        }));
        assert!(
            result.is_err(),
            "a set bit without a passing verification must not prove"
        );
    }

    #[test]
    fn rejects_inflated_count() {
        // Honest trace, but a relying party is handed public inputs claiming a
        // higher count than the bitmap supports.
        let bitmap = bits(&[1, 0, 1, 0]);
        let verified = bits(&[1, 0, 1, 0]);
        let message = b"tenzro/qc/view=9";

        let air = PqQcAggregationAir::new(bitmap.len());
        let trace = generate_pq_qc_trace(&bitmap, &verified, message, 1 << 3);
        let pis = pq_qc_public_inputs(&bitmap, message);

        let prover = Plonky3Prover::<PqQcAggregationAir>::new();
        let proof = prover.prove_air(&air, trace, &pis);

        // Tamper: bump the declared count public input (index N).
        let mut bad_pis = pis.clone();
        bad_pis[bitmap.len()] += KoalaBear::from_u64(1);

        let verifier = Plonky3Verifier::<PqQcAggregationAir>::new();
        let result = verifier.verify_air(&air, &proof, &bad_pis);
        assert!(result.is_err(), "inflated count must be rejected");
    }

    #[test]
    fn rejects_tampered_message_digest() {
        let bitmap = bits(&[1, 1, 1, 1]);
        let verified = bits(&[1, 1, 1, 1]);
        let message = b"tenzro/qc/view=1";

        let air = PqQcAggregationAir::new(bitmap.len());
        let trace = generate_pq_qc_trace(&bitmap, &verified, message, 1 << 3);
        let pis = pq_qc_public_inputs(&bitmap, message);

        let prover = Plonky3Prover::<PqQcAggregationAir>::new();
        let proof = prover.prove_air(&air, trace, &pis);

        // Tamper the first digest slot (index N + 1).
        let mut bad_pis = pis.clone();
        bad_pis[bitmap.len() + 1] += KoalaBear::from_u64(1);

        let verifier = Plonky3Verifier::<PqQcAggregationAir>::new();
        let result = verifier.verify_air(&air, &proof, &bad_pis);
        assert!(result.is_err(), "tampered message digest must be rejected");
    }

    #[test]
    fn scales_to_wider_validator_sets() {
        // 64-seat certificate, alternating signers — exercises the runtime
        // width path for a realistic mid-size committee.
        let bitmap: Vec<bool> = (0..64).map(|i| i % 2 == 0).collect();
        let verified = bitmap.clone();
        let message = b"tenzro/qc/wide";

        let air = PqQcAggregationAir::new(bitmap.len());
        let trace = generate_pq_qc_trace(&bitmap, &verified, message, 1 << 3);
        let pis = pq_qc_public_inputs(&bitmap, message);

        let prover = Plonky3Prover::<PqQcAggregationAir>::new();
        let proof = prover.prove_air(&air, trace, &pis);

        let verifier = Plonky3Verifier::<PqQcAggregationAir>::new();
        verifier
            .verify_air(&air, &proof, &pis)
            .expect("64-seat certificate must verify");
    }
}
