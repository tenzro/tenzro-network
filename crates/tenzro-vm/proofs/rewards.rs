//! Rewards one settlement earns: the provider reward weight and the activity
//! reward weight together stay below the protocol fee the settlement paid
//! outside the trade, for every credit, fee and pair of governed shares, so
//! a buyer, provider and app acting together never earn back what it cost.

use tenzro_token::rewards::{MAX_SETTLEMENT_REWARD_BPS, provider_work_weight};

/// The provider weight and the activity weight of one settlement, at the
/// shares in force as `settlement_reward_bps` reads them.
fn weights(credited: u128, fee: u128, provider_set: u64, activity_set: u64) -> (u128, u128) {
    let activity = activity_set.min(MAX_SETTLEMENT_REWARD_BPS);
    let provider = provider_set.min(MAX_SETTLEMENT_REWARD_BPS - activity);
    let p = provider_work_weight(credited, fee, provider);
    // The activity weight, as the fee step records it.
    let a = fee.saturating_mul(u128::from(activity)) / 10_000;
    (p, a)
}

// Bit-precise: cvc5 with integer arithmetic does not finish on the two
// symbolic shares.
#[kani::proof]
fn a_settlement_never_earns_its_fee_back() {
    let (credited, fee): (u128, u128) = kani::any();
    let (provider_set, activity_set): (u64, u64) = kani::any();
    kani::assume(fee > 0);
    let (p, a) = weights(credited, fee, provider_set, activity_set);
    assert!(p < fee);
    assert!(a < fee - p);
}
