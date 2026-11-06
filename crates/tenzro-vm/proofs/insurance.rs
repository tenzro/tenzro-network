//! Insurance: a claim never takes more than its caps, and a payout moves
//! value without creating it.

use super::slashing::bps_share_by_lemma;
use crate::native::insurance::claim_cap_of;
use crate::native::staking::bps_share;

/// The cap is within both the pool share and the absolute limit, so the
/// payout `loss.min(cap)` can always be taken from the pool.
#[kani::proof]
#[kani::stub(bps_share, bps_share_by_lemma)]
fn a_claim_is_within_its_caps() {
    let (pool, bps, abs, loss, claimant): (u128, u128, u128, u128, u128) = kani::any();
    let cap = claim_cap_of(pool, bps, abs);
    assert!(cap <= pool && cap <= abs);
    assert!(cap <= bps_share(pool, bps));
    let paid = loss.min(cap);
    kani::assume(claimant.checked_add(pool).is_some());
    let pool_after = pool - paid;
    let claimant_after = claimant + paid;
    assert!(pool_after + claimant_after == pool + claimant);
}
