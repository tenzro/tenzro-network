//! Bridge limits: lane buckets, mint caps, the network outflow cap, the
//! one-step cap raise, the exit delay rule, and the supply record a route
//! keeps, with the TNZO an exit moves through escrow and the route vault.
//!
//! The framework reads and writes these through chain state; the arithmetic
//! is the functions proved here, which it calls as they are.

use tenzro_bridge::route::lane::LaneBucket;
use tenzro_bridge::route::state::{SupplyRecord, mint_admitted, within_epoch_cap};
use tenzro_types::bridge_route::{
    LaneRateLimit, MintRateLimit, exit_waits, lower_within, raise_within,
};

fn any_limit() -> LaneRateLimit {
    LaneRateLimit {
        capacity: kani::any(),
        rate: kani::any(),
    }
}

/// A bucket never holds more than its capacity, whatever was stored, however
/// long ago, and under whatever limit governance set since (a lowered
/// capacity cuts a fuller bucket at once).
#[kani::proof]
fn a_lane_bucket_never_holds_more_than_its_capacity() {
    let limit = any_limit();
    let stored: Option<(u128, u64)> = kani::any();
    let now: u64 = kani::any();
    let b = LaneBucket::refill(stored, now, limit);
    assert!(b.tokens <= limit.capacity);
    assert!(b.capacity == limit.capacity && b.rate == limit.rate);
    assert!(b.last_updated >= now);
}

/// Over any span a bucket gains at most its rate for each second of it: what
/// leaves over a window is bounded by the bucket at its start plus the
/// refill, never more.
#[kani::proof]
#[kani::solver(cvc5)]
fn a_lane_bucket_refills_at_most_its_rate_per_second() {
    let limit = any_limit();
    let tokens: u128 = kani::any();
    let last: u64 = kani::any();
    let now: u64 = kani::any();
    let b = LaneBucket::refill(Some((tokens, last)), now, limit);
    let elapsed = u128::from(now.saturating_sub(last));
    assert!(b.tokens <= tokens.saturating_add(limit.rate.saturating_mul(elapsed)));
    if now <= last {
        assert!(b.tokens <= tokens);
    }
}

/// A transfer takes exactly its amount and never more than the bucket
/// holds or than its capacity; one that does not fit is refused.
#[kani::proof]
fn a_lane_take_never_exceeds_the_bucket() {
    let bucket = LaneBucket::refill(kani::any(), kani::any(), any_limit());
    let amount: u128 = kani::any();
    match bucket.take(amount) {
        Some(after) => {
            assert!(amount <= bucket.tokens && amount <= bucket.capacity);
            assert!(after.tokens == bucket.tokens - amount);
            assert!(after.capacity == bucket.capacity);
        }
        None => assert!(amount > bucket.tokens || amount > bucket.capacity),
    }
}

/// A mint is admitted only within the per-mint cap, and the epoch total it
/// leaves never passes the per-epoch limit; every mint within both is
/// admitted.
#[kani::proof]
fn a_mint_never_passes_the_per_mint_cap_or_the_epoch_limit() {
    let limit = MintRateLimit {
        per_mint: kani::any(),
        per_epoch: kani::any(),
    };
    let minted: u128 = kani::any();
    let amount: u128 = kani::any();
    match mint_admitted(minted, amount, limit) {
        Some(after) => {
            assert!(amount <= limit.per_mint);
            assert!(after <= limit.per_epoch);
            assert!(after == minted + amount);
        }
        None => assert!(
            amount > limit.per_mint
                || minted
                    .checked_add(amount)
                    .is_none_or(|a| a > limit.per_epoch)
        ),
    }
}

/// The network outflow total never passes its cap in an epoch.
#[kani::proof]
fn the_network_outflow_never_passes_its_cap() {
    let used: u128 = kani::any();
    let amount: u128 = kani::any();
    let cap: u128 = kani::any();
    match within_epoch_cap(used, amount, cap) {
        Some(after) => assert!(after <= cap && after == used + amount),
        None => assert!(used.checked_add(amount).is_none_or(|a| a > cap)),
    }
}

/// One step raises a cap to at most `max_raise_bps` of its value; any
/// lowering passes. Values up to 2^64, factors up to the governed maximum.
///
/// This and the next proof compare `wide_mul` against a plain 128-bit
/// product. Bit-blasted for the default SAT solver, that is a comparison of
/// two multipliers, which took from 7 s to past the 15-minute budget
/// depending on host load; cvc5 over integers proves each in under a second.
#[kani::proof]
#[kani::solver(cvc5)]
fn one_step_never_raises_a_cap_past_the_factor() {
    let current = u128::from(kani::any::<u64>());
    let proposed = u128::from(kani::any::<u64>());
    let bps: u64 = kani::any_where(|b| (10_000..=100_000).contains(b));
    let allowed = proposed <= current || proposed * 10_000 <= current * u128::from(bps);
    assert!(raise_within(current, proposed, bps) == allowed);
}

/// One step lowers a floor (such as the exit delay) to no less than its
/// value scaled down by `max_raise_bps`; any raise passes. Values up to
/// 2^64.
#[kani::proof]
#[kani::solver(cvc5)]
fn one_step_never_lowers_a_floor_past_the_factor() {
    let current = u128::from(kani::any::<u64>());
    let proposed = u128::from(kani::any::<u64>());
    let bps: u64 = kani::any_where(|b| (10_000..=100_000).contains(b));
    let allowed = proposed >= current || current * 10_000 <= proposed * u128::from(bps);
    assert!(lower_within(current, proposed, bps) == allowed);
}

/// An exit waits exactly when it is larger than the threshold share of its
/// bucket's capacity. Amounts and capacities up to 2^64.
#[kani::proof]
fn an_exit_waits_exactly_above_the_threshold_share() {
    let amount = u128::from(kani::any::<u64>());
    let capacity = u128::from(kani::any::<u64>());
    let bps: u64 = kani::any_where(|b| *b <= 10_000);
    assert!(exit_waits(amount, capacity, bps) == (amount * 10_000 > capacity * u128::from(bps)));
}

/// The TNZO an exit moves, a route's vault and its supply record, as the
/// exit queue and the route compose them: queue (sender to escrow), cancel
/// (escrow to sender), release (escrow to sender, then sender to the vault
/// with the lock recorded), and an inbound release (vault to a receiver,
/// recorded). Accounts: sender, escrow, vault, receiver.
#[derive(Clone, Copy)]
struct Exits {
    bal: [u128; 4],
    supply: SupplyRecord,
}

const SENDER: usize = 0;
const ESCROW: usize = 1;
const VAULT: usize = 2;
const RECEIVER: usize = 3;

impl Exits {
    fn total(&self) -> Option<u128> {
        self.bal.iter().try_fold(0u128, |s, b| s.checked_add(*b))
    }

    /// The vault holds exactly the TNZO locked for the route, and no more
    /// is outstanding on the external chain than is locked.
    fn holds(&self) -> bool {
        self.total().is_some()
            && self.bal[VAULT] == self.supply.locked
            && self.supply.bridged <= self.supply.locked
    }

    fn mv(&mut self, from: usize, to: usize, amount: u128) -> Option<()> {
        self.bal[from] = self.bal[from].checked_sub(amount)?;
        self.bal[to] = self.bal[to].checked_add(amount)?;
        Some(())
    }

    fn release(&mut self, amount: u128) -> Option<()> {
        self.mv(ESCROW, SENDER, amount)?;
        self.supply = self.supply.after_lock(amount)?;
        self.mv(SENDER, VAULT, amount)
    }

    fn inbound(&mut self, amount: u128) -> Option<()> {
        self.supply = self.supply.after_release(amount)?;
        self.mv(VAULT, RECEIVER, amount)
    }
}

/// Every exit and inbound step conserves TNZO and keeps the vault equal to
/// what is locked; a refused step leaves the state as it was (the
/// transaction reverts).
#[kani::proof]
fn every_exit_step_conserves_tnzo_and_the_vault_backs_the_lock() {
    let before = Exits {
        bal: kani::any(),
        supply: SupplyRecord {
            locked: kani::any(),
            bridged: kani::any(),
        },
    };
    kani::assume(before.holds());
    let mut after = before;
    let amount: u128 = kani::any();
    let op: u8 = kani::any();
    let applied = match op % 4 {
        0 => after.mv(SENDER, ESCROW, amount),
        1 => after.mv(ESCROW, SENDER, amount),
        2 => after.release(amount),
        _ => after.inbound(amount),
    };
    let end = if applied.is_some() { after } else { before };
    assert!(end.holds());
    assert!(end.total() == before.total());
}

/// A lock moves the locked and the outstanding totals by the same amount,
/// and so does a release; neither ever leaves more outstanding than locked.
#[kani::proof]
fn a_lock_or_release_moves_both_totals_together() {
    let before = SupplyRecord {
        locked: kani::any(),
        bridged: kani::any(),
    };
    kani::assume(before.bridged <= before.locked);
    let amount: u128 = kani::any();
    if let Some(r) = before.after_lock(amount) {
        assert!(r.locked - before.locked == amount && r.bridged - before.bridged == amount);
        assert!(r.bridged <= r.locked);
    }
    if let Some(r) = before.after_release(amount) {
        assert!(before.locked - r.locked == amount && before.bridged - r.bridged == amount);
        assert!(r.bridged <= r.locked);
    } else {
        assert!(amount > before.bridged);
    }
}

/// The security ratio never overflows, is unbounded when nothing can leave,
/// and is exact wherever slashable stake times 10,000 fits in 128 bits.
#[kani::proof]
#[kani::solver(cvc5)]
fn the_security_ratio_never_overflows_and_is_exact_in_range() {
    use crate::native::security::ratio_bps_of;
    let (slashable, extractable): (u128, u128) = kani::any();
    let r = ratio_bps_of(slashable, extractable);
    if extractable == 0 {
        assert!(r == u64::MAX);
    } else if let Some(n) = slashable.checked_mul(10_000) {
        assert!(u128::from(r) == (n / extractable).min(u128::from(u64::MAX)));
    }
}
