//! Plonky3 AIR for settlement validity proofs.
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

/// Trace columns: 5 witness/scratch fields + 2 × [`DIGEST_LEN`] hash
/// anchors. The trace carries the full `DIGEST_LEN`-element Poseidon2
/// output for both digests, and the AIR constrains every trace cell
/// against its public-input slot.
pub const NUM_SETTLEMENT_COLS: usize = 5 + 2 * DIGEST_LEN;
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
    pub service_hash: [F; DIGEST_LEN],
    pub settlement_hash: [F; DIGEST_LEN],
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
        // Snapshot trace cells before acquiring the when_first_row mut borrow.
        let (payer_balance, _service_proof, nonce, prev_nonce, remaining_balance, service_hash, settlement_hash) = {
            let main = builder.main();
            let local: &SettlementRow<AB::Var> = main.current_slice().borrow();
            (
                local.payer_balance,
                local.service_proof,
                local.nonce,
                local.prev_nonce,
                local.remaining_balance,
                local.service_hash,
                local.settlement_hash,
            )
        };

        // Snapshot public inputs.
        // Layout: [settlement_digest(DIGEST_LEN) | service_digest(DIGEST_LEN) | amount(1)]
        let pi_settlement_hash: [AB::PublicVar; DIGEST_LEN];
        let pi_service_hash: [AB::PublicVar; DIGEST_LEN];
        let pi_amount;
        {
            let pis = builder.public_values();
            pi_settlement_hash = core::array::from_fn(|k| pis[k]);
            pi_service_hash = core::array::from_fn(|k| pis[DIGEST_LEN + k]);
            pi_amount = pis[2 * DIGEST_LEN];
        }

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

        // Constraint 3: trace hash columns equal public-input
        // hash slots for ALL DIGEST_LEN elements, not just slot 0.
        for k in 0..DIGEST_LEN {
            when_first_row.assert_eq(service_hash[k], pi_service_hash[k]);
            when_first_row.assert_eq(settlement_hash[k], pi_settlement_hash[k]);
        }
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
    // Trace cells 5..5+DIGEST_LEN = service digest, then settlement digest.
    let service_base: usize = 5;
    let settlement_base: usize = 5 + DIGEST_LEN;
    for k in 0..DIGEST_LEN {
        values[service_base + k] = service_digest[k];
        values[settlement_base + k] = settlement_digest[k];
    }

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
