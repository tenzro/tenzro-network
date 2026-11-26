//! Whether paying a higher priority fee buys a requester a bigger share of
//! a capped per-epoch resource, against three real caps: the payout swap
//! cap (`payout_swap::fill_epoch`), the settlement asset inflow cap
//! (`settlement_asset::admit_inflow`) and the treasury outflow period cap
//! (`funding::record_outflow`, which the availability reward and other
//! treasury-funded payouts draw on).
//!
//! `tenzro_consensus::mempool`'s block-proposer selection is real,
//! confirmed priority-fee ordering: `priority()` keys a pooled transaction
//! by its `gas_price`, and `select_with` walks the pool highest price
//! first (see that crate's own `test_mempool_priority_ordering`). A
//! requester who bids a higher gas price lands earlier in a block, and so
//! earlier in whichever epoch its request falls in, than one who bids
//! less.
//!
//! The payout swap cap never reads that order: `fill_epoch` computes every
//! due request's fill from the whole epoch's book at once, so where in the
//! book a request landed changes nothing. Tested below: fill is
//! proportional to the request's own size and identical whichever of two
//! competing requests joined the book first.
//!
//! The inflow cap and the outflow period cap are, by contrast, first-come:
//! each is a running counter against a fixed ceiling, checked and
//! incremented as a request is processed, with no accounting for size or
//! order beyond who got there first. Tested below: whichever of two
//! requests is processed first takes the headroom it asked for in full and
//! the other is refused outright, regardless of which one asked for more --
//! not scaled down to a fair share of either. Since block order is real
//! priority-fee order, a requester able to pay more can reliably buy this
//! outcome for these two caps. This is a real, confirmed gap against this
//! item's pass condition for those two caps, not something invented here:
//! the mechanism is exactly as the rest of this file's and
//! `settlement_asset.rs`'s own comments already describe it ("the inflow
//! cap is first-come and the payment settles at once").

use crate::native::economy;
use crate::native::funding;
use crate::native::payout_swap;
use crate::native::settlement_asset::{self, Permitted, install_for_test, permitted};
use crate::native::{derive_treasury_address, set_governed_param_for_test};
use crate::state_adapter::StateAdapter;
use crate::traits::VmState;
use tenzro_types::settlement_asset::SettlementAsset;

fn token_held_by(state: &mut StateAdapter, holder: &[u8], symbol: &str, supply: u128) -> [u8; 32] {
    let spec = crate::token_ledger::TokenRecord {
        name: symbol.into(),
        symbol: symbol.into(),
        decimals: 6,
        total_supply: supply,
        creator: Vec::new(),
        max_supply: None,
        powers: tenzro_types::token_policy::PowerManifest::NONE,
        policy: tenzro_types::token_policy::TokenPolicy::default(),
        council: None,
        reserve_backing: None,
        pending: None,
    };
    crate::token_ledger::create(state, holder, &spec, &mut Vec::new()).unwrap()
}

/// Registers `symbol` as a settlement asset priced at `rate` nano-USD per
/// whole token, genesis limits otherwise, with `supply` minted to `holder`.
fn settlement_token(
    state: &mut StateAdapter,
    holder: &[u8],
    symbol: &str,
    supply: u128,
    rate: u128,
) -> [u8; 32] {
    let id = token_held_by(state, holder, symbol, supply);
    let asset = SettlementAsset::new(&format!("0x{}", hex::encode(id)), symbol, "USD", 6);
    install_for_test(state, &asset);
    economy::write_symbol_rate_for_tests(state, symbol, 0, rate);
    id
}

/// A payee's queued swap request, once `payout_swap::pay_out` finds a
/// payout asset it can settle in now.
fn queue_swap_request(
    state: &mut StateAdapter,
    arrival: &[u8; 32],
    payee: &[u8; 32],
    credit: u128,
) {
    let p = permitted(state, arrival).unwrap();
    let (_, immediate) =
        payout_swap::pay_out(state, arrival, &p, payee, credit, 0, &mut Vec::new()).unwrap();
    assert_eq!(
        immediate, 0,
        "the request should join the book, not settle at once"
    );
}

/// One genesis, priced and funded the same way every time, so a scenario
/// can be run twice with only the order of two calls swapped.
fn swap_cap_genesis() -> (StateAdapter, [u8; 32], [u8; 32]) {
    let mut state = StateAdapter::new();
    // TNZO priced so the treasury's existing bond gives it ample exposure
    // headroom for the tiny amounts this scenario moves.
    economy::write_rate_for_tests(&mut state, 0, 1_000_000_000, 1_000_000_000);
    let treasury = derive_treasury_address();
    state.set_balance(treasury.as_bytes(), 1_000 * 10u128.pow(18));
    // The payout asset both payees prefer, held by the treasury in a
    // supply well past anything this scenario pays out.
    let payout = settlement_token(
        &mut state,
        treasury.as_bytes(),
        "USDY",
        10_000_000,
        1_000_000_000,
    );
    // The epoch cap: $1 of value a epoch, far under the $3 the two
    // payees below ask for between them, so it binds.
    set_governed_param_for_test(&mut state, payout_swap::EPOCH_CAP_PARAM, 1);
    (state, treasury.0, payout)
}

fn prefer(state: &mut StateAdapter, payee: &[u8; 32], payout: &[u8; 32]) {
    payout_swap::set_payout_assets(
        state,
        payee,
        &[format!("0x{}", hex::encode(payout))],
        &mut Vec::new(),
    )
    .unwrap();
}

/// B7, the payout swap cap: fill share matches request share within
/// rounding, and is the same whichever of two competing requests joined
/// the epoch's book first -- paying to land earlier buys nothing.
#[test]
fn payout_swap_cap_fills_pro_rata_and_unaffected_by_which_request_joined_the_book_first() {
    let payee_a = [0xA1u8; 32];
    let payee_b = [0xB2u8; 32];
    // B asks for twice what A asks for.
    let credit_a = 1_000_000u128;
    let credit_b = 2_000_000u128;

    let run = |a_first: bool| {
        let (mut state, _treasury, payout) = swap_cap_genesis();
        let arrival_a = settlement_token(&mut state, &payee_a, "USDA", credit_a, 1_000_000_000);
        let arrival_b = settlement_token(&mut state, &payee_b, "USDB", credit_b, 1_000_000_000);
        prefer(&mut state, &payee_a, &payout);
        prefer(&mut state, &payee_b, &payout);
        if a_first {
            queue_swap_request(&mut state, &arrival_a, &payee_a, credit_a);
            queue_swap_request(&mut state, &arrival_b, &payee_b, credit_b);
        } else {
            queue_swap_request(&mut state, &arrival_b, &payee_b, credit_b);
            queue_swap_request(&mut state, &arrival_a, &payee_a, credit_a);
        }
        let epoch = economy::read_current_epoch(&state);
        let mut logs = Vec::new();
        payout_swap::fill_epoch(&mut state, epoch, 8, &mut Vec::new(), &mut logs).unwrap();
        let out_a = crate::token_ledger::balance(&state, &payout, &payee_a);
        let out_b = crate::token_ledger::balance(&state, &payout, &payee_b);
        (out_a, out_b)
    };

    let (a_when_a_first, b_when_a_first) = run(true);
    let (a_when_b_first, b_when_b_first) = run(false);

    // Neither payee's fill changed with which of the two joined the book
    // first: a request's place in the epoch does not change what it gets.
    assert_eq!(a_when_a_first, a_when_b_first);
    assert_eq!(b_when_a_first, b_when_b_first);

    // Both are filled (the cap bound, not either asset's own limits), and
    // B's fill is B's share of what was asked (2 of 3) within rounding of
    // A's (1 of 3): about double, not the whole cap and not nothing.
    assert!(a_when_a_first > 0, "A should receive a pro-rata fill");
    assert!(b_when_a_first > 0, "B should receive a pro-rata fill");
    let ratio = b_when_a_first as f64 / a_when_a_first as f64;
    assert!(
        (1.99..=2.01).contains(&ratio),
        "B asked for 2x A's credit; B's fill should be ~2x A's fill within rounding, got {ratio}"
    );
}

fn inflow_cap_genesis(cap_whole_units: u64) -> (StateAdapter, [u8; 32], Permitted) {
    let mut state = StateAdapter::new();
    let held = token_held_by(&mut state, &[9u8; 32], "USDC", 10_000_000);
    let hex_id = format!("0x{}", hex::encode(held));
    let mut entry = SettlementAsset::new(&hex_id, "USDC", "USD", 6);
    entry.epoch_inflow_cap_units = cap_whole_units;
    install_for_test(&mut state, &entry);
    economy::write_symbol_rate_for_tests(&mut state, "USDC", 0, 1_000_000_000);
    let p = permitted(&state, &held).unwrap();
    (state, held, p)
}

/// The settlement asset inflow cap is first-come, not pro-rata: whichever
/// of two requests is processed first (which a higher priority fee buys in
/// the real chain, via the mempool's gas-price ordering) takes the cap's
/// headroom in full; the other is refused outright, whatever its own size.
/// This fails both of B7's pass conditions for this cap -- a real, confirmed
/// gap, recorded here rather than silently patched.
#[test]
fn inflow_cap_grants_the_cap_to_whichever_request_is_processed_first_not_by_size() {
    let small = 200_000u128;
    let large = 900_000u128;

    let (mut state, held, p) = inflow_cap_genesis(1);
    settlement_asset::admit_inflow(&mut state, &held, &p, &[0xA1u8; 20], small, &mut Vec::new())
        .unwrap();
    let refused = settlement_asset::admit_inflow(
        &mut state,
        &held,
        &p,
        &[0xA1u8; 20],
        large,
        &mut Vec::new(),
    );
    assert!(
        refused.is_err(),
        "the much larger request should be refused, not scaled down"
    );
    assert_eq!(settlement_asset::read_epoch_inflow(&state, &held), small);

    // Same two requests, order reversed: the outcome flips completely.
    // Nothing about either request's size decided this, only which one was
    // processed first.
    let (mut state, held, p) = inflow_cap_genesis(1);
    settlement_asset::admit_inflow(&mut state, &held, &p, &[0xA1u8; 20], large, &mut Vec::new())
        .unwrap();
    let refused = settlement_asset::admit_inflow(
        &mut state,
        &held,
        &p,
        &[0xA1u8; 20],
        small,
        &mut Vec::new(),
    );
    assert!(
        refused.is_err(),
        "the small request should now be the one refused"
    );
    assert_eq!(settlement_asset::read_epoch_inflow(&state, &held), large);
}

/// The treasury outflow period cap -- the ceiling a reward payout (the
/// availability reward, among others) is forfeited against once it is
/// spent -- is the same first-come shape as the inflow cap above: whichever
/// outflow is counted first takes the period's headroom in full and the
/// other is refused, whatever either one's own size. Same real, confirmed
/// gap as the inflow cap, for the same reason: processing order, which a
/// higher priority fee buys in the real chain, decides it.
#[test]
fn treasury_outflow_period_cap_grants_the_cap_to_whichever_outflow_is_processed_first_not_by_size()
{
    let setup = || {
        let mut state = StateAdapter::new();
        let treasury = derive_treasury_address();
        state.set_balance(treasury.as_bytes(), 1_000_000);
        // 10% of the opening balance a period.
        set_governed_param_for_test(
            &mut state,
            crate::governance::MAX_PERIOD_OUTFLOW_PARAM,
            1_000,
        );
        state
    };
    let small = 20_000u128;
    let large = 90_000u128;

    let mut state = setup();
    funding::record_outflow(&mut state, small, 0, &mut Vec::new()).unwrap();
    assert!(
        funding::record_outflow(&mut state, large, 0, &mut Vec::new()).is_err(),
        "the much larger outflow should be refused, not scaled down"
    );

    let mut state = setup();
    funding::record_outflow(&mut state, large, 0, &mut Vec::new()).unwrap();
    assert!(
        funding::record_outflow(&mut state, small, 0, &mut Vec::new()).is_err(),
        "the small outflow should now be the one refused"
    );
}
