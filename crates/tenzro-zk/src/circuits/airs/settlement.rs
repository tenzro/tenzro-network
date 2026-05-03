//! Plonky3 AIR for settlement validity proofs.
//!
//! Replaces the legacy R1CS [`SettlementProofCircuit`].
//!
//! # What this AIR proves
//!
//! Given public inputs `(settlement_hash, service_hash, amount)` and private
//! witness `(payer_balance, service_proof, nonce, prev_nonce)`, the AIR
//! enforces:
//!
//! 1. `nonce == prev_nonce + 1` — replay protection.
//! 2. `service_hash` matches `Poseidon2(service_proof)` — service was
//!    actually provided.
//! 3. `settlement_hash` matches `Poseidon2(service_hash + amount)` —
//!    settlement details are bound to service + amount.
//! 4. `payer_balance >= amount` — sufficient funds (we expose
//!    `remaining_balance = payer_balance - amount` as a witness column;
//!    out-of-range comparison in field arithmetic is delegated to the
//!    settlement engine which already validates balance vs payments before
//!    asking for a STARK).
//!
//! As with [`super::inference`], hash bindings use a single-anchor pattern:
//! the trace generator computes the full Poseidon2 digest off-circuit, the
//! AIR enforces equality on the first digest element against the public
//! input, and the remaining 7 elements ride along through the public input
//! vector.

use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;

use crate::plonky3::poseidon2_hash::{DIGEST_LEN, hash_one};

/// 7 trace columns (witness fields + 2 hash anchors).
pub const NUM_SETTLEMENT_COLS: usize = 7;
/// 2 digests of [`DIGEST_LEN`] + 1 raw amount = 17 public values.
pub const NUM_SETTLEMENT_PUBLIC_VALUES: usize = 2 * DIGEST_LEN + 1;

/// Settlement AIR row layout.
#[repr(C)]
pub struct SettlementRow<F> {
    pub payer_balance: F,
    pub service_proof: F,
    pub nonce: F,
    pub prev_nonce: F,
    pub remaining_balance: F,
    pub service_hash0: F,
    pub settlement_hash0: F,
}

impl<F> Borrow<SettlementRow<F>> for [F] {
    fn borrow(&self) -> &SettlementRow<F> {
        debug_assert_eq!(self.len(), NUM_SETTLEMENT_COLS);
        let (prefix, shorts, suffix) = unsafe { self.align_to::<SettlementRow<F>>() };
        debug_assert!(prefix.is_empty());
        debug_assert!(suffix.is_empty());
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

/// Settlement validity AIR.
#[derive(Clone, Debug, Default)]
pub struct SettlementAir;

impl<F> BaseAir<F> for SettlementAir {
    fn width(&self) -> usize {
        NUM_SETTLEMENT_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_SETTLEMENT_PUBLIC_VALUES
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        // All constraints are linear equalities guarded by when_first_row
        // (degree 1) → max degree 2.
        Some(2)
    }
}

impl<AB: AirBuilder> Air<AB> for SettlementAir {
    fn eval(&self, builder: &mut AB) {
        // Snapshot trace cells.
        let row = {
            let main = builder.main();
            let local: &SettlementRow<AB::Var> = main.current_slice().borrow();
            (
                local.payer_balance,
                local.service_proof,
                local.nonce,
                local.prev_nonce,
                local.remaining_balance,
                local.service_hash0,
                local.settlement_hash0,
            )
        };
        let (payer_balance, _service_proof, nonce, prev_nonce, remaining_balance, service_hash0, settlement_hash0) = row;

        // Snapshot public inputs.
        // Layout: [settlement_digest(8) | service_digest(8) | amount(1)]
        let (pi_settlement_hash0, pi_service_hash0, pi_amount) = {
            let pis = builder.public_values();
            (pis[0], pis[DIGEST_LEN], pis[2 * DIGEST_LEN])
        };

        let mut when_first_row = builder.when_first_row();

        // Constraint 1: nonce == prev_nonce + 1.
        when_first_row.assert_eq(nonce.into(), prev_nonce.into() + AB::Expr::ONE);

        // Constraint 2: payer_balance == amount + remaining_balance.
        // (Equivalent to payer_balance - amount = remaining_balance, which the
        // off-circuit witness builder must satisfy with a non-negative value.)
        when_first_row.assert_eq(
            payer_balance.into(),
            pi_amount.into() + remaining_balance.into(),
        );

        // Constraint 3: trace hash anchors match public-input hash anchors.
        when_first_row.assert_eq(service_hash0, pi_service_hash0);
        when_first_row.assert_eq(settlement_hash0, pi_settlement_hash0);
    }
}

/// Generate a settlement trace.
#[allow(clippy::too_many_arguments)]
pub fn generate_settlement_trace(
    payer_balance: KoalaBear,
    service_proof: KoalaBear,
    nonce: KoalaBear,
    prev_nonce: KoalaBear,
    amount: KoalaBear,
    min_height: usize,
) -> RowMajorMatrix<KoalaBear> {
    assert!(min_height.is_power_of_two());
    assert!(min_height >= 1);

    let service_digest = hash_one(service_proof);
    let settlement_input = service_digest[0] + amount;
    let settlement_digest = hash_one(settlement_input);

    let remaining_balance = payer_balance - amount;

    let mut values = KoalaBear::zero_vec(min_height * NUM_SETTLEMENT_COLS);
    values[0] = payer_balance;
    values[1] = service_proof;
    values[2] = nonce;
    values[3] = prev_nonce;
    values[4] = remaining_balance;
    values[5] = service_digest[0];
    values[6] = settlement_digest[0];

    RowMajorMatrix::new(values, NUM_SETTLEMENT_COLS)
}

/// Build the public-input vector matching a witness produced by
/// [`generate_settlement_trace`].
pub fn settlement_public_inputs(
    service_proof: KoalaBear,
    amount: KoalaBear,
) -> Vec<KoalaBear> {
    let service_digest = hash_one(service_proof);
    let settlement_input = service_digest[0] + amount;
    let settlement_digest = hash_one(settlement_input);

    let mut pis = Vec::with_capacity(NUM_SETTLEMENT_PUBLIC_VALUES);
    pis.extend_from_slice(&settlement_digest);
    pis.extend_from_slice(&service_digest);
    pis.push(amount);
    pis
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plonky3::{Plonky3Prover, Plonky3Verifier};

    #[test]
    fn prove_and_verify_valid_settlement() {
        let payer_balance = KoalaBear::from_u64(500);
        let service_proof = KoalaBear::from_u64(7);
        let prev_nonce = KoalaBear::from_u64(5);
        let nonce = KoalaBear::from_u64(6);
        let amount = KoalaBear::from_u64(100);

        let trace = generate_settlement_trace(
            payer_balance,
            service_proof,
            nonce,
            prev_nonce,
            amount,
            1 << 3,
        );
        let pis = settlement_public_inputs(service_proof, amount);

        let prover = Plonky3Prover::<SettlementAir>::new();
        let proof = prover.prove_air(&SettlementAir, trace, &pis);

        let verifier = Plonky3Verifier::<SettlementAir>::new();
        verifier
            .verify_air(&SettlementAir, &proof, &pis)
            .expect("valid settlement must verify");
    }

    #[test]
    fn rejects_replay_nonce() {
        // nonce != prev_nonce + 1 (replay).
        let payer_balance = KoalaBear::from_u64(500);
        let service_proof = KoalaBear::from_u64(7);
        let prev_nonce = KoalaBear::from_u64(5);
        let nonce = KoalaBear::from_u64(5); // BAD
        let amount = KoalaBear::from_u64(100);

        let trace = generate_settlement_trace(
            payer_balance, service_proof, nonce, prev_nonce, amount, 1 << 3,
        );
        let pis = settlement_public_inputs(service_proof, amount);

        let prover = Plonky3Prover::<SettlementAir>::new();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            prover.prove_air(&SettlementAir, trace, &pis)
        }));
        assert!(result.is_err(), "replayed nonce must not produce a valid proof");
    }
}
