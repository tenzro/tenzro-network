//! Slashing: the stake taken equals what the insurance pool is credited.
//!
//! `bps_share` is proved in three parts: the share of the whole lots of
//! 10 000 (a product), the share of the rest (a product and a quotient below
//! one lot), and their sum, which uses only the two parts' contracts. The
//! harnesses that use `bps_share` replace it by `bps_share_by_lemma`.

use crate::native::staking::{bps_share, share_of_lots, share_of_rest, slash_split};

/// The share of whole lots is within the lots, all of them at 10 000 basis
/// points and none at zero.
#[kani::proof_for_contract(share_of_lots)]
#[kani::solver(cvc5)]
fn a_share_of_whole_lots_is_within_the_lots() {
    let (lots, bps): (u128, u128) = kani::any();
    share_of_lots(lots, bps);
}

/// The share of the rest below one lot is within the rest.
#[kani::proof_for_contract(share_of_rest)]
fn a_share_of_the_rest_is_within_the_rest() {
    let (rest, bps): (u128, u128) = kani::any();
    share_of_rest(rest, bps);
}

/// A basis-point share never exceeds the amount and never overflows.
#[kani::proof]
#[kani::solver(cvc5)]
#[kani::stub_verified(share_of_lots)]
#[kani::stub_verified(share_of_rest)]
fn a_basis_point_share_is_within_the_amount() {
    let (amount, bps): (u128, u128) = kani::any();
    let share = bps_share(amount, bps);
    assert!(share <= amount);
    if bps >= 10_000 {
        assert!(share == amount);
    }
    if bps == 0 {
        assert!(share == 0);
    }
}

/// `bps_share` as `a_basis_point_share_is_within_the_amount` proves it: a
/// pure function, one result per argument pair, chosen freely among the
/// results that harness allows.
pub(super) fn bps_share_by_lemma(amount: u128, bps: u128) -> u128 {
    static mut SEEN: Option<(u128, u128, u128)> = None;
    // SAFETY: a proof harness runs on one thread.
    if let Some((a, b, share)) = unsafe { SEEN } {
        if a == amount && b == bps {
            return share;
        }
    }
    let share: u128 = kani::any();
    kani::assume(share <= amount && (bps < 10_000 || share == amount) && (bps != 0 || share == 0));
    unsafe { SEEN = Some((amount, bps, share)) };
    share
}

/// `slash` debits the vault by the total it takes from the bond and the
/// unbonding amount, and `slash_to_insurance` credits the pool with that
/// same total: the credit equals the debit, and no stake is created or lost.
#[kani::proof]
#[kani::stub(bps_share, bps_share_by_lemma)]
fn a_slash_credits_exactly_what_it_debits() {
    let (bond, unbonding, bps): (u128, u128, u16) = kani::any();
    let (vault, pool): (u128, u128) = kani::any();
    // The vault holds every bond and unbonding amount.
    kani::assume(bond.checked_add(unbonding).is_some_and(|s| s <= vault));
    kani::assume(vault.checked_add(pool).is_some());
    let Some((from_bond, from_unbonding, total)) = slash_split(bond, unbonding, bps) else {
        panic!("a slash of stake the vault holds cannot overflow");
    };
    assert!(from_bond <= bond && from_unbonding <= unbonding);
    assert!(total == from_bond + from_unbonding);
    let vault_after = vault
        .checked_sub(total)
        .expect("the vault covers the slash");
    let pool_after = pool.checked_add(total).expect("the pool cannot overflow");
    assert!(vault_after + pool_after == vault + pool);
    assert!((bond - from_bond) + (unbonding - from_unbonding) + total == bond + unbonding);
}
