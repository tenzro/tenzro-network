//! Governance: vote replacement, decisions, the timelock and the veto.

use crate::governance::{
    GovernanceRules, GrantVesting, Proposal, ProposalAction, ProposalStatus, ProposalTrack, Tally,
    Tighten, decide, extension_for_share, guard_step_base, guard_step_loosens, locked_share_bps,
    scaled_extension, share_at_least, veto_extension_ms,
};
use tenzro_types::primitives::Address;

fn any_status() -> ProposalStatus {
    match kani::any::<u8>() % 7 {
        0 => ProposalStatus::Voting,
        1 => ProposalStatus::Passed,
        2 => ProposalStatus::Queued,
        3 => ProposalStatus::Vetoed,
        4 => ProposalStatus::Rejected,
        5 => ProposalStatus::Executed,
        _ => ProposalStatus::Contested,
    }
}

fn any_track() -> ProposalTrack {
    match kani::any::<u8>() % 4 {
        0 => ProposalTrack::Standard,
        1 => ProposalTrack::Expedited,
        2 => ProposalTrack::Ratify,
        _ => ProposalTrack::SecurityFix,
    }
}

/// A proposal in any status on any track, at any point of its timelock.
/// The veto extension is never negative: it is only ever set from
/// `veto_extension_ms`, which is not.
fn any_proposal() -> Proposal {
    let mut p = Proposal::open(
        String::new(),
        Address::default(),
        ProposalAction::TreasuryGrant {
            recipient: Address::default(),
            amount: 0,
            memo: String::new(),
            category: String::new(),
            link: String::new(),
            tranches: Vec::new(),
            milestones: vec!["milestone".into()],
            vesting: GrantVesting::Liquid,
            asset: None,
            release: Default::default(),
        },
        kani::any(),
        GovernanceRules::GENESIS,
    );
    p.status = any_status();
    p.track = any_track();
    p.voting_ends_ms = kani::any();
    p.queued_ms = kani::any();
    p.eta_ms = kani::any();
    p.veto_extension_ms = kani::any();
    kani::assume(p.veto_extension_ms >= 0);
    p.concern_doubled = kani::any();
    p
}

fn any_tally() -> Tally {
    Tally {
        yes: kani::any(),
        no: kani::any(),
        total_eligible: kani::any(),
    }
}

/// Replacing a counted vote removes exactly the old weight from its side
/// and adds the new weight to the new side.
#[kani::proof]
fn a_replaced_vote_is_counted_once() {
    let mut t = any_tally();
    let before = t;
    let (weight, in_favour): (u128, bool) = kani::any();
    let previous: Option<(u128, bool)> = kani::any();
    if let Some((w, yes)) = previous {
        // The earlier vote is in the tally.
        kani::assume(if yes { before.yes >= w } else { before.no >= w });
    }
    kani::assume(
        before.yes.checked_add(weight).is_some() && before.no.checked_add(weight).is_some(),
    );
    t.apply_vote(weight, in_favour, previous);
    let (old_yes, old_no) = match previous {
        Some((w, true)) => (w, 0),
        Some((w, false)) => (0, w),
        None => (0, 0),
    };
    let (new_yes, new_no) = if in_favour { (weight, 0) } else { (0, weight) };
    assert!(t.yes == before.yes - old_yes + new_yes);
    assert!(t.no == before.no - old_no + new_no);
    assert!(t.total_eligible == before.total_eligible);
}

/// Casting the same vote again changes nothing.
#[kani::proof]
fn a_repeated_vote_changes_nothing() {
    let mut t = any_tally();
    let (weight, in_favour): (u128, bool) = kani::any();
    kani::assume(if in_favour {
        t.yes >= weight
    } else {
        t.no >= weight
    });
    let before = t;
    t.apply_vote(weight, in_favour, Some((weight, in_favour)));
    assert!(t == before);
}

/// `Tally::quorum_met` as an arbitrary fixed predicate: any answer, but the
/// same answer every time it is asked about the same tally and quorum.
fn quorum_met_as_any_predicate(t: &Tally, rules: &GovernanceRules) -> bool {
    static mut SEEN: Option<(Tally, u64, bool)> = None;
    let met: bool = kani::any();
    // SAFETY: a proof harness runs on one thread.
    if let Some((seen_t, seen_q, seen_met)) = unsafe { SEEN } {
        if seen_t == *t && seen_q == rules.quorum_bps {
            kani::assume(met == seen_met);
        }
    }
    unsafe { SEEN = Some((*t, rules.quorum_bps, met)) };
    met
}

/// `Tally::threshold_met_on` as an arbitrary fixed predicate: any answer, but
/// the same answer every time it is asked about the same tally, track and bar.
fn threshold_met_as_any_predicate(
    t: &Tally,
    track: ProposalTrack,
    rules: &GovernanceRules,
) -> bool {
    static mut SEEN: Option<(Tally, ProposalTrack, u64, bool)> = None;
    let bar = track.threshold_bps(rules);
    let met: bool = kani::any();
    // SAFETY: a proof harness runs on one thread.
    if let Some((seen_t, seen_track, seen_bar, seen_met)) = unsafe { SEEN } {
        if seen_t == *t && seen_track == track && seen_bar == bar {
            kani::assume(met == seen_met);
        }
    }
    unsafe { SEEN = Some((*t, track, bar, met)) };
    met
}

/// A decision is only ever Passed or Rejected, Passed only with quorum and
/// the track's threshold, never before the window closes, and never for an
/// executed proposal.
///
/// The quorum and threshold tests are replaced by arbitrary fixed predicates,
/// so this holds whatever they compute: `decide` passes a proposal only when
/// both say yes. Their arithmetic is 128-bit multiplication on symbolic
/// stake, which the bit-level solver cannot prove equal to itself in bounded
/// time when the same test is asked twice. The two tests themselves are
/// proved against the exact share, and monotone, in the harnesses below.
#[kani::proof]
#[kani::stub(Tally::quorum_met, quorum_met_as_any_predicate)]
#[kani::stub(Tally::threshold_met_on, threshold_met_as_any_predicate)]
fn a_decision_is_terminal_and_earned() {
    let p = any_proposal();
    let t = any_tally();
    let now: i64 = kani::any();
    match decide(&p, &t, now) {
        Ok(ProposalStatus::Passed) => {
            assert!(t.quorum_met(&p.rules) && t.threshold_met_on(p.track, &p.rules));
            assert!(now >= p.voting_ends_ms && p.status != ProposalStatus::Executed);
        }
        Ok(ProposalStatus::Rejected) => {
            assert!(now >= p.voting_ends_ms && p.status != ProposalStatus::Executed);
        }
        Ok(_) => panic!("decide returned a non-terminal status"),
        Err(_) => assert!(now < p.voting_ends_ms || p.status == ProposalStatus::Executed),
    }
}

/// The least share of `lots` whole lots of 10_000 at `bps`: `lots * bps`,
/// or `None` past `u128::MAX`.
fn lots_share(lots: u128, bps: u64) -> Option<u128> {
    lots.checked_mul(u128::from(bps))
}

/// `lots_share` with its overflow found by division: past `u128::MAX`
/// exactly when `lots` is above `u128::MAX / bps`.
fn lots_share_by_division(lots: u128, bps: u64) -> Option<u128> {
    let bps = u128::from(bps);
    if bps != 0 && lots > u128::MAX / bps {
        return None;
    }
    Some(lots * bps)
}

/// The least share of a rest below one lot: `rest * bps / 10_000` rounded
/// up. `rest * bps` is below 10_000 * 2^64.
fn rest_share(rest: u128, bps: u64) -> u128 {
    (rest * u128::from(bps)).div_ceil(10_000)
}

/// The least part that is at least `bps` basis points of `whole`:
/// `whole * bps / 10_000` rounded up, or `None` past `u128::MAX`. With
/// `whole = q * 10_000 + r` it is the share of `q` lots plus that of the
/// rest `r`, and nothing on the way passes `u128::MAX`.
fn least_share(whole: u128, bps: u64) -> Option<u128> {
    lots_share(whole / 10_000, bps)?.checked_add(rest_share(whole % 10_000, bps))
}

/// `part * 10_000 >= whole * bps` by long division: `part` reaches the
/// least share of `whole`.
fn share_by_long_division(part: u128, whole: u128, bps: u64) -> bool {
    least_share(whole, bps).is_some_and(|least| part >= least)
}

/// For every input the share test agrees with long division, a second exact
/// method that never forms a product past `u128::MAX`: no stake and no bar
/// can make the share test saturate or wrap into a different answer.
#[kani::proof]
#[kani::solver(cvc5)]
fn the_share_test_is_exact_for_every_input() {
    let (part, whole): (u128, u128) = kani::any();
    let bps: u64 = kani::any();
    assert!(share_at_least(part, whole, bps) == share_by_long_division(part, whole, bps));
}

/// Where `whole * bps` fits in a u128, the least share is that product
/// divided by 10_000, rounded up.
#[kani::proof]
#[kani::solver(cvc5)]
fn the_least_share_is_the_rounded_up_product_where_it_fits() {
    let whole: u128 = kani::any();
    let bps: u64 = kani::any();
    let Some(product) = whole.checked_mul(u128::from(bps)) else {
        return;
    };
    // The product splits into whole lots and the rest, and so does its
    // rounded-up share: each step is proved, then taken as given.
    let (lots, rest, b) = (whole / 10_000, whole % 10_000, u128::from(bps));
    assert!(product == lots * b * 10_000 + rest * b);
    kani::assume(product == lots * b * 10_000 + rest * b);
    assert!(product.div_ceil(10_000) == lots * b + (rest * b).div_ceil(10_000));
    kani::assume(product.div_ceil(10_000) == lots * b + (rest * b).div_ceil(10_000));
    assert!(least_share(whole, bps) == Some(product.div_ceil(10_000)));
}

/// `least_share` where `the_least_share_is_the_rounded_up_product_where_it_fits`
/// states it, and any answer elsewhere.
fn least_share_where_it_fits(whole: u128, bps: u64) -> Option<u128> {
    match whole.checked_mul(u128::from(bps)) {
        Some(product) => Some(product.div_ceil(10_000)),
        None => kani::any(),
    }
}

/// The share test agrees with the plain products wherever both fit in a
/// u128. The share test is taken as long division
/// (`the_share_test_is_exact_for_every_input`).
#[kani::proof]
#[kani::stub(share_at_least, share_by_long_division)]
#[kani::stub(least_share, least_share_where_it_fits)]
#[kani::solver(cvc5)]
fn the_share_test_is_the_plain_comparison_where_it_fits() {
    let (part, whole): (u128, u128) = kani::any();
    let bps: u64 = kani::any();
    let (Some(cast), Some(bar)) = (part.checked_mul(10_000), whole.checked_mul(u128::from(bps)))
    else {
        return;
    };
    assert!(share_at_least(part, whole, bps) == (cast >= bar));
}

/// One more lot adds exactly `bps` to the share of whole lots.
#[kani::proof]
#[kani::solver(cvc5)]
fn one_more_lot_adds_the_bar() {
    let lots: u128 = kani::any();
    let bps: u64 = kani::any();
    kani::assume(lots < u128::MAX);
    if let Some(share) = lots_share(lots, bps) {
        assert!(lots_share(lots + 1, bps) == share.checked_add(u128::from(bps)));
    }
}

/// A share of whole lots past `u128::MAX` stays past it with one more lot.
/// `lots_share` is taken by division
/// (`the_lots_share_by_division_is_the_same`).
#[kani::proof]
#[kani::stub(lots_share, lots_share_by_division)]
#[kani::solver(cvc5)]
fn one_more_lot_stays_past_the_maximum() {
    let lots: u128 = kani::any();
    let bps: u64 = kani::any();
    kani::assume(lots < u128::MAX);
    if lots_share(lots, bps).is_none() {
        assert!(lots_share(lots + 1, bps).is_none());
    }
}

/// Finding the overflow by division gives the same share of whole lots.
#[kani::proof]
#[kani::solver(cvc5)]
fn the_lots_share_by_division_is_the_same() {
    let lots: u128 = kani::any();
    let bps: u64 = kani::any();
    assert!(lots_share_by_division(lots, bps) == lots_share(lots, bps));
}

/// Within a lot, one more unit of rest never lowers its share, and with a
/// bar of at most 10_000 basis points raises it by at most one.
#[kani::proof]
#[kani::solver(cvc5)]
fn the_rest_share_moves_by_at_most_one_per_unit() {
    let rest: u128 = kani::any();
    let bps: u64 = kani::any();
    kani::assume(rest < 9_999);
    let (now, next) = (rest_share(rest, bps), rest_share(rest + 1, bps));
    assert!(now <= next);
    assert!(bps > 10_000 || next <= now + 1);
}

/// An empty rest has no share, and a full one at most the bar and, with a
/// bar of at most 10_000 basis points, at least the bar less one.
#[kani::proof]
#[kani::solver(cvc5)]
fn the_rest_share_of_an_empty_and_a_full_rest() {
    let bps: u64 = kani::any();
    assert!(rest_share(0, bps) == 0);
    let full = rest_share(9_999, bps);
    assert!(full <= u128::from(bps) && (bps > 10_000 || u128::from(bps) - full <= 1));
}

/// `lots_share` as `one_more_lot_adds_the_bar` and
/// `one_more_lot_stays_past_the_maximum` state it, between this call
/// and the one before.
fn lots_share_by_lemmas(lots: u128, bps: u64) -> Option<u128> {
    static mut SEEN: Option<(u128, u64, Option<u128>)> = None;
    let share: Option<u128> = kani::any();
    // SAFETY: a proof harness runs on one thread.
    if let Some((l, b, seen)) = unsafe { SEEN } {
        if b == bps && l == lots {
            kani::assume(share == seen);
        }
        if b == bps && l < u128::MAX && l + 1 == lots {
            kani::assume(share == seen.and_then(|s| s.checked_add(u128::from(bps))));
        }
    }
    unsafe { SEEN = Some((lots, bps, share)) };
    share
}

/// `rest_share` as `the_rest_share_moves_by_at_most_one_per_unit` and
/// `the_rest_share_of_an_empty_and_a_full_rest` state it,
/// between this call and the one before.
fn rest_share_by_lemmas(rest: u128, bps: u64) -> u128 {
    static mut SEEN: Option<(u128, u64, u128)> = None;
    assert!(rest < 10_000);
    let share: u128 = kani::any();
    let b = u128::from(bps);
    if rest == 0 {
        kani::assume(share == 0);
    }
    if rest == 9_999 {
        kani::assume(share <= b && (bps > 10_000 || b - share <= 1));
    }
    // SAFETY: a proof harness runs on one thread.
    if let Some((r, seen_bps, seen)) = unsafe { SEEN } {
        if seen_bps == bps && r == rest {
            kani::assume(share == seen);
        }
        if seen_bps == bps && r + 1 == rest {
            kani::assume(seen <= share && (bps > 10_000 || share - seen <= 1));
        }
    }
    unsafe { SEEN = Some((rest, bps, share)) };
    share
}

/// One more unit of whole: the least share never falls (a least share past
/// `u128::MAX` stays past it), and with a bar of at most 10_000 basis points
/// it rises by at most one.
fn check_one_more_unit(whole: u128, bps: u64) {
    let now = least_share(whole, bps);
    let next = least_share(whole + 1, bps);
    match (now, next) {
        (Some(l), Some(n)) => assert!(l <= n && (bps > 10_000 || n - l <= 1)),
        (Some(l), None) => assert!(bps > 10_000 || l == u128::MAX),
        (None, Some(_)) => panic!("a larger whole has a least share that a smaller one lacks"),
        (None, None) => {}
    }
}

/// `check_one_more_unit` for a whole whose next unit stays within its lot.
#[kani::proof]
#[kani::stub(lots_share, lots_share_by_lemmas)]
#[kani::stub(rest_share, rest_share_by_lemmas)]
#[kani::solver(cvc5)]
fn one_more_unit_within_a_lot_moves_the_least_share_by_at_most_one() {
    let whole: u128 = kani::any();
    let bps: u64 = kani::any();
    kani::assume(whole % 10_000 != 9_999 && whole < u128::MAX);
    check_one_more_unit(whole, bps);
}

/// `check_one_more_unit` for a whole whose next unit completes a lot.
#[kani::proof]
#[kani::stub(lots_share, lots_share_by_lemmas)]
#[kani::stub(rest_share, rest_share_by_lemmas)]
#[kani::solver(cvc5)]
fn one_more_unit_across_a_lot_moves_the_least_share_by_at_most_one() {
    let whole: u128 = kani::any();
    let bps: u64 = kani::any();
    kani::assume(whole % 10_000 == 9_999 && whole < u128::MAX);
    check_one_more_unit(whole, bps);
}

/// `least_share` as its lemmas state it, for the harnesses that compose
/// them: any answer, the same for the same inputs, and between two calls
/// with the same bar it never falls as the whole grows, and with a bar of
/// at most 10_000 basis points it rises by no more than the whole does.
/// `None` stands for a least share past `u128::MAX`. The two
/// `one_more_unit_*` harnesses prove both for a whole one unit larger;
/// induction on the difference between the two wholes gives them for any
/// two.
fn least_share_by_lemmas(whole: u128, bps: u64) -> Option<u128> {
    static mut SEEN: Option<(u128, u64, Option<u128>)> = None;
    let least: Option<u128> = kani::any();
    // SAFETY: a proof harness runs on one thread.
    if let Some((w, b, seen)) = unsafe { SEEN } {
        if b == bps {
            if w == whole {
                kani::assume(least == seen);
            }
            if whole <= w {
                if let Some(s) = seen {
                    kani::assume(least.is_some_and(|l| l <= s));
                }
            }
            if w <= whole {
                if let Some(l) = least {
                    kani::assume(seen.is_some_and(|s| s <= l));
                }
                if bps <= 10_000 {
                    if let Some(bound) = seen.and_then(|s| s.checked_add(whole - w)) {
                        kani::assume(least.is_some_and(|l| l <= bound));
                    }
                }
            }
        }
    }
    unsafe { SEEN = Some((whole, bps, least)) };
    least
}

/// For any stake and any bar: a larger part or a smaller whole never loses a
/// met share, from the least share never falling as the whole grows.
#[kani::proof]
#[kani::stub(share_at_least, share_by_long_division)]
#[kani::stub(least_share, least_share_by_lemmas)]
fn the_share_test_is_monotone() {
    let (p1, p2, w1, w2): (u128, u128, u128, u128) = kani::any();
    let bps: u64 = kani::any();
    kani::assume(p1 <= p2 && w2 <= w1);
    assert!(!share_at_least(p1, w1, bps) || share_at_least(p2, w2, bps));
}

/// For any stake and any bar up to 10_000 basis points: adding the same
/// stake to a part and to the whole that contains it never loses a met
/// share, from the least share rising no faster than the whole.
#[kani::proof]
#[kani::stub(share_at_least, share_by_long_division)]
#[kani::stub(least_share, least_share_by_lemmas)]
fn adding_to_part_and_whole_keeps_a_met_share() {
    let (part, whole, added): (u128, u128, u128) = kani::any();
    let bps: u64 = kani::any();
    kani::assume(bps <= 10_000 && part <= whole);
    let (Some(p2), Some(w2)) = (part.checked_add(added), whole.checked_add(added)) else {
        return;
    };
    assert!(!share_at_least(part, whole, bps) || share_at_least(p2, w2, bps));
}

/// `share_at_least` as its three lemmas state it, for the harnesses that
/// compose them: any answer, but the same answer for the same inputs, and
/// between two calls with the same bar the monotonicity
/// (`the_share_test_is_monotone`) and the shared addition
/// (`adding_to_part_and_whole_keeps_a_met_share`) hold. Exactness is
/// `the_share_test_is_exact_for_every_input`.
fn share_at_least_by_lemmas(part: u128, whole: u128, bps: u64) -> bool {
    static mut SEEN: Option<(u128, u128, u64, bool)> = None;
    let met: bool = kani::any();
    // SAFETY: a proof harness runs on one thread.
    if let Some((p, w, b, seen)) = unsafe { SEEN } {
        if b == bps {
            if p == part && w == whole {
                kani::assume(met == seen);
            }
            if p <= part && whole <= w {
                kani::assume(!seen || met);
            }
            if part <= p && w <= whole {
                kani::assume(!met || seen);
            }
            if bps <= 10_000 && part >= p && whole >= w && part - p == whole - w && p <= w {
                kani::assume(!seen || met);
            }
            if bps <= 10_000 && p >= part && w >= whole && p - part == w - whole && part <= whole {
                kani::assume(!met || seen);
            }
        }
    }
    unsafe { SEEN = Some((part, whole, bps, met)) };
    met
}

/// A tally whose turnout, yes plus no, fits in a u128.
fn any_tally_with_a_turnout() -> Tally {
    let t = any_tally();
    kani::assume(t.yes.checked_add(t.no).is_some());
    t
}

/// The genesis rules with every quorum and threshold bar set to any share
/// from 0 to 10_000 basis points.
fn rules_with_any_bars() -> GovernanceRules {
    let mut r = GovernanceRules::GENESIS;
    r.quorum_bps = kani::any();
    r.threshold_bps = kani::any();
    r.expedited_threshold_bps = kani::any();
    r.ratify_threshold_bps = kani::any();
    kani::assume(r.quorum_bps <= 10_000 && r.threshold_bps <= 10_000);
    kani::assume(r.expedited_threshold_bps <= 10_000 && r.ratify_threshold_bps <= 10_000);
    r
}

/// The quorum test is the share test of the turnout within the eligible
/// stake at the quorum bar, never met by an empty electorate. With
/// `the_share_test_is_exact_for_every_input` that makes it exactly
/// `(yes + no) / eligible >= quorum_bps / 10_000`.
#[kani::proof]
#[kani::stub(share_at_least, share_at_least_by_lemmas)]
fn the_quorum_test_is_the_share_of_the_turnout() {
    let t = any_tally_with_a_turnout();
    let mut rules = GovernanceRules::GENESIS;
    rules.quorum_bps = kani::any();
    let met = t.quorum_met(&rules);
    let turnout = t.yes + t.no;
    assert!(
        met == (t.total_eligible > 0
            && share_at_least(turnout, t.total_eligible, rules.quorum_bps))
    );
}

/// For any stake and any quorum bar: more stake voting, either way, never
/// loses a met quorum, and a larger electorate never meets a quorum that a
/// smaller one missed.
/// The share test is taken as long division and the least share as its
/// lemmas state it.
#[kani::proof]
#[kani::stub(share_at_least, share_by_long_division)]
#[kani::stub(least_share, least_share_by_lemmas)]
fn the_quorum_test_is_monotone() {
    let a = any_tally();
    let mut rules = GovernanceRules::GENESIS;
    rules.quorum_bps = kani::any();
    let more_votes = Tally {
        yes: kani::any(),
        no: kani::any(),
        ..a
    };
    kani::assume(more_votes.yes >= a.yes && more_votes.no >= a.no);
    assert!(!a.quorum_met(&rules) || more_votes.quorum_met(&rules));
    let larger = Tally {
        total_eligible: kani::any(),
        ..a
    };
    kani::assume(larger.total_eligible >= a.total_eligible && a.total_eligible > 0);
    assert!(!larger.quorum_met(&rules) || a.quorum_met(&rules));
}

/// The threshold test is the share test of yes within the turnout, at the
/// track's bar, which is never below the standard one; no turnout never meets
/// it. With `the_share_test_is_exact_for_every_input` that makes it exactly
/// `yes / (yes + no) >= bar / 10_000`.
#[kani::proof]
#[kani::stub(share_at_least, share_at_least_by_lemmas)]
fn the_threshold_test_is_the_share_of_yes() {
    let t = any_tally_with_a_turnout();
    let rules = rules_with_any_bars();
    let track = any_track();
    let bar = track.threshold_bps(&rules);
    assert!(bar >= rules.threshold_bps && bar <= 10_000);
    let met = t.threshold_met_on(track, &rules);
    let turnout = t.yes + t.no;
    assert!(t.participation() == turnout);
    assert!(met == (turnout > 0 && share_at_least(t.yes, turnout, bar)));
}

/// For any stake whose turnout fits in a u128 and any bar up to 10_000 basis
/// points: more yes stake, with the no stake unchanged, never loses a met
/// threshold.
#[kani::proof]
#[kani::stub(share_at_least, share_at_least_by_lemmas)]
fn the_threshold_test_is_monotone_in_yes() {
    let a = any_tally();
    let rules = rules_with_any_bars();
    let track = any_track();
    let more_yes = Tally {
        yes: kani::any(),
        ..a
    };
    kani::assume(more_yes.yes >= a.yes && more_yes.yes.checked_add(a.no).is_some());
    assert!(!a.threshold_met_on(track, &rules) || more_yes.threshold_met_on(track, &rules));
}

/// Only a passed proposal queues, and its execution time is never before
/// the moment it was queued.
#[kani::proof]
fn queueing_sets_a_timelock_after_now() {
    let mut p = any_proposal();
    let was = p.status;
    let now: i64 = kani::any();
    let queued = p.queue(now);
    assert!(queued == (was == ProposalStatus::Passed));
    if queued {
        assert!(p.status == ProposalStatus::Queued);
        assert!(matches!(p.eta_ms, Some(eta) if eta >= now));
        assert!(!p.is_executable_at(now) || p.eta_ms == Some(now));
    } else {
        assert!(p.status == was);
    }
}

/// Once executable, a proposal stays executable as time passes; nothing
/// but a queued proposal with an execution time is ever executable.
#[kani::proof]
fn executability_is_monotone_in_time() {
    let p = any_proposal();
    let (t1, t2): (i64, i64) = kani::any();
    kani::assume(t1 <= t2);
    if p.is_executable_at(t1) {
        assert!(p.is_executable_at(t2));
    }
    if p.is_executable_at(t2) {
        assert!(p.status == ProposalStatus::Queued && p.eta_ms.is_some_and(|eta| eta <= t2));
    }
}

/// A veto stops only a queued proposal, and a vetoed proposal is terminal:
/// it never executes, queues, is vetoed again or is contested.
#[kani::proof]
fn a_veto_is_terminal() {
    let mut p = any_proposal();
    let was = p.status;
    let vetoed = p.veto();
    assert!(vetoed == (was == ProposalStatus::Queued));
    if p.status == ProposalStatus::Vetoed {
        let now: i64 = kani::any();
        assert!(!p.is_executable_at(now));
        assert!(!p.clone().queue(now));
        assert!(!p.clone().veto());
        assert!(!p.clone().contest(now));
    }
}

/// The holders' veto escrow only ever moves the execution time later.
#[kani::proof]
fn the_veto_extension_never_shortens_the_timelock() {
    let mut p = any_proposal();
    kani::assume(p.status == ProposalStatus::Queued);
    kani::assume(p.eta_ms == p.stretched_eta());
    let before = p.eta_ms;
    let ext_before = p.veto_extension_ms;
    let ext: i64 = kani::any();
    kani::assume(ext >= 0);
    p.extend_by_veto(ext);
    assert!(p.veto_extension_ms >= ext_before);
    match (before, p.eta_ms) {
        (Some(b), Some(a)) => assert!(a >= b),
        (None, None) => {}
        _ => panic!("the extension changed whether the proposal has an execution time"),
    }
}

/// The scaled extension never exceeds the maximum.
#[kani::proof]
#[kani::solver(cvc5)]
fn a_scaled_extension_is_within_the_maximum() {
    let (max_ext, share, block_bps): (u64, u128, u64) = kani::any();
    kani::assume(block_bps > 0 && share <= u128::from(block_bps));
    assert!(scaled_extension(max_ext, share, block_bps) <= u128::from(max_ext));
}

/// A larger share of the blocking share scales to a longer extension.
#[kani::proof]
#[kani::solver(cvc5)]
fn a_larger_share_scales_to_a_longer_extension() {
    let (max_ext, block_bps): (u64, u64) = kani::any();
    let (s1, s2): (u128, u128) = kani::any();
    kani::assume(block_bps > 0 && s1 <= s2 && s2 <= u128::from(block_bps));
    assert!(scaled_extension(max_ext, s1, block_bps) <= scaled_extension(max_ext, s2, block_bps));
}

/// `scaled_extension` as its two lemmas state it: within the maximum
/// (`a_scaled_extension_is_within_the_maximum`) and monotone in the share for
/// the same maximum and blocking share
/// (`a_larger_share_scales_to_a_longer_extension`), with its precondition
/// checked at every call.
fn scaled_extension_by_lemmas(max_ext: u64, share: u128, block_bps: u64) -> u128 {
    static mut SEEN: Option<(u64, u128, u64, u128)> = None;
    assert!(block_bps > 0 && share <= u128::from(block_bps));
    let ext: u128 = kani::any();
    kani::assume(ext <= u128::from(max_ext));
    // SAFETY: a proof harness runs on one thread.
    if let Some((m, s, b, seen)) = unsafe { SEEN } {
        if m == max_ext && b == block_bps {
            kani::assume(s > share || seen <= ext);
            kani::assume(share > s || ext <= seen);
        }
    }
    unsafe { SEEN = Some((max_ext, share, block_bps, ext)) };
    ext
}

/// The extension is between zero and the maximum, and grows with the
/// locked share.
#[kani::proof]
#[kani::stub(scaled_extension, scaled_extension_by_lemmas)]
fn the_veto_extension_is_bounded_and_monotone() {
    let (s1, s2): (u128, u128) = kani::any();
    let (signal_bps, block_bps, max_ext): (u64, u64, u64) = kani::any();
    kani::assume(signal_bps <= 10_000 && block_bps <= 10_000);
    kani::assume(max_ext <= i64::MAX as u64);
    kani::assume(s1 <= s2);
    let e1 = extension_for_share(s1, signal_bps, block_bps, max_ext);
    let e2 = extension_for_share(s2, signal_bps, block_bps, max_ext);
    assert!(e1 >= 0 && e1 as u64 <= max_ext);
    assert!(e1 <= e2);
}

/// The locked share grows with the locked amount, and an empty supply or
/// blocking share gives no extension.
#[kani::proof]
#[kani::solver(cvc5)]
fn the_locked_share_grows_with_the_lock() {
    let (l1, l2, supply): (u64, u64, u64) = kani::any();
    kani::assume(l1 <= l2 && supply > 0);
    let share = |l: u64| locked_share_bps(u128::from(l), u128::from(supply));
    assert!(share(l1) <= share(l2));
    let (locked, signal, max_ext): (u128, u64, u64) = kani::any();
    assert!(veto_extension_ms(locked, 0, signal, 10_000, max_ext) == 0);
    assert!(veto_extension_ms(locked, u128::from(supply), signal, 0, max_ext) == 0);
}

/// A guard change loosens it exactly when it moves against the direction
/// that tightens it; a key with no direction, or a status lever, never
/// loosens.
#[kani::proof]
fn a_guard_loosens_only_against_its_tightening_direction() {
    let (current, value): (u64, u64) = kani::any();
    for t in [Tighten::Up, Tighten::Down] {
        assert_eq!(
            guard_step_loosens(t, current, value),
            value != current && !t.tightens(current, value)
        );
    }
    assert!(!guard_step_loosens(Tighten::Neither, current, value));
    assert!(!guard_step_loosens(Tighten::Retire, current, value));
}

/// The base a guard's next step is measured from is never looser than the
/// value in force nor than the value already scheduled, so queued proposals
/// cannot stack steps inside one grace.
#[kani::proof]
fn a_guard_steps_from_the_tighter_of_in_force_and_scheduled() {
    let (in_force, scheduled): (u64, u64) = kani::any();
    for (key, t) in [
        (crate::native::rewards::MINT_BASE_PARAM, Tighten::Down),
        (crate::governance::QUORUM_PARAM, Tighten::Up),
    ] {
        let base = guard_step_base(key, in_force, scheduled);
        assert!(base == in_force || base == scheduled);
        assert!(!guard_step_loosens(t, in_force, base));
        assert!(!guard_step_loosens(t, scheduled, base));
    }
}

/// A grant of any size passes only with yes votes of at least the approval
/// share of all eligible stake, whatever the quorum and threshold say.
#[kani::proof]
#[kani::solver(cvc5)]
#[kani::stub(Tally::quorum_met, quorum_met_as_any_predicate)]
#[kani::stub(Tally::threshold_met_on, threshold_met_as_any_predicate)]
fn a_payment_needs_the_approval_share_of_eligible_stake() {
    let mut p = any_proposal();
    let amount: u128 = kani::any();
    p.action = ProposalAction::TreasuryGrant {
        recipient: Address::default(),
        amount,
        memo: String::new(),
        category: String::new(),
        link: String::new(),
        tranches: Vec::new(),
        milestones: vec!["milestone".into()],
        vesting: GrantVesting::Liquid,
        asset: None,
        release: Default::default(),
    };
    let t = any_tally();
    if amount > 0 && p.outcome(&t) == ProposalStatus::Passed {
        assert!(
            t.yes.saturating_mul(10_000)
                >= t.total_eligible
                    .saturating_mul(u128::from(p.rules.large_spend_approval_bps))
        );
    }
}

/// The issuance multiplier stays within its governed bounds for every input:
/// whatever the ratio, goal, speed and epoch count, one step never leaves
/// `[min, max]`.
#[kani::proof]
fn the_mint_multiplier_stays_within_its_bounds() {
    let (mult, measured, goal, adj, epochs, min, max): (u64, u64, u64, u64, u64, u64, u64) =
        kani::any();
    kani::assume(min <= max && max <= u64::MAX / 100);
    let next = tenzro_token::next_mint_mult(mult, measured, goal, adj, epochs, min, max);
    assert!(u128::from(next) >= u128::from(min) * 100);
    assert!(u128::from(next) <= u128::from(max) * 100);
}
