//! Payments in a stable token on the ledger, the treasury leg taken in it,
//! and the governed treasury sell-back; with all of them off, a run is the
//! run it was before they existed.

use tenzro_econsim::economy::{Economy, Market, RunConfig, RunOutcome};

/// The launch package the listing-gate and float runs use.
const PACKAGE: &str = "preset=realistic,treasury_genesis_tnzo=50000000,\
treasury_stake_tnzo=5000000,pol_usd=0,staking_ratio=0.4,agent_tasks_per_day=100000,\
compute_hour_usd=1.8,agent_task_usd=0.45,running_cost_ask_usd_month=100000,\
validator_exit_yield=-1000000,pool_depth_usd=2000000";

/// An 8% inference leg and 5% compute and storage legs.
const LEG: [(&str, u64); 4] = [
    ("fees.activity_reward_fee_bps", 5_000),
    ("fees.treasury_leg_inference_bps", 800),
    ("fees.treasury_leg_compute_bps", 500),
    ("fees.treasury_leg_storage_bps", 500),
];

fn run(market: Market, days: u32, extra: &str, leg: bool) -> RunOutcome {
    run_with(market, days, extra, leg, &[])
}

fn run_with(
    market: Market,
    days: u32,
    extra: &str,
    leg: bool,
    params: &[(&str, u64)],
) -> RunOutcome {
    let mut c = RunConfig::scenario(market, 21, days);
    let list = if extra.is_empty() {
        PACKAGE.to_string()
    } else {
        format!("{PACKAGE},{extra}")
    };
    c.assumptions.apply_list(&list).expect("valid list");
    if leg {
        for (k, v) in LEG {
            c.network_params.insert(k.into(), v);
        }
    }
    for (k, v) in params {
        c.network_params.insert((*k).into(), *v);
    }
    let out = Economy::new(c).run();
    assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);
    out
}

#[test]
fn with_every_option_off_a_run_repeats_its_earlier_figures() {
    // Growth, seed 21, 120 days, the package with the 8%/5% leg paid in
    // TNZO: the figures a run with the stable token, the stable leg and the
    // sell-back off gives now. They moved from the first figures (price
    // 0.1000044, outside float 302855826.6, refused 261) at the integration
    // of the payment-settlement rules (payout swaps filled pro-rata by
    // epoch, the settlement-asset breaker, the grant floor against the
    // running-cost reserve): a bisect of the first-parent merges leaves five
    // candidates, and the only one that changes the VM is that merge; the
    // merge before them gives the first figures to the bit. They moved again
    // at the integration of the gated payouts: the reserve pays a running
    // cost only to an approved operator, against verified-available hours,
    // at a governed per-hour value. The simulated desk that asked for the
    // running costs is no approved operator and has no verified hours, so
    // the chain refuses each ask and the reserve pays nothing (the stable
    // sponsorship is the paid path); the reserve keeps what it collects.
    // d66759d54 (before the gates) gives the earlier figures to the bit.
    let out = run(Market::Growth, 120, "", true);
    let d = out.days.last().expect("a day");
    let same = |name: &str, got: f64, want: f64| {
        assert_eq!(
            got.to_bits(),
            want.to_bits(),
            "{name}: {got} now, {want} before"
        );
    };
    same("price", d.price_usd, 0.08680065338093561);
    same("outside float", d.outside_float_tnzo, 300644996.2177158);
    same("treasury", d.snap.treasury, 46883263.97590146);
    same("supply", d.snap.supply, 999958739.2906293);
    same("reserve", d.snap.reserve, 3295080.204079371);
    same("revenue", d.revenue_usd_year, 1636295.9513085969);
    same("running costs paid", d.running_costs_paid_usd_total, 0.0);
    same(
        "unrelated demand",
        d.unrelated_demand_usd_day,
        57080.34934714157,
    );
    same(
        "refused share",
        out.launch.as_ref().expect("launch").users.refused_share,
        0.05934856640667912,
    );
    assert_eq!(d.refused, 242);
    assert_eq!(out.applied, 226051);
    assert_eq!(d.treasury_stable_usd, 0.0);
    assert_eq!(d.sellback_sold_tnzo_total, 0.0);
}

#[test]
fn the_closed_phase_pays_providers_and_the_leg_in_the_stable_token() {
    let with_leg = run(Market::Growth, 40, "closed_phase=1", true);
    let no_leg = run(Market::Growth, 40, "closed_phase=1", false);
    let (l, o) = (
        with_leg.days.last().expect("a day"),
        no_leg.days.last().expect("a day"),
    );
    // The leg reaches the treasury in the token, near 8% of the agent
    // spend and 5% of the compute, less the fee.
    // The settlement fee of a token payment is collected in the token, so
    // the treasury holds some without the leg too; the leg adds to it.
    assert!(o.treasury_stable_usd > 0.0);
    assert!(l.treasury_stable_usd > o.treasury_stable_usd);
    let spend: f64 = with_leg
        .days
        .iter()
        .map(|d| d.unrelated_demand_usd_day)
        .sum();
    let share = l.stable_legs_usd_total / spend;
    assert!(share > 0.05 && share < 0.08, "leg share {share}");
    // What the treasury holds is what providers sent it, less the last
    // day's legs still in flight.
    assert!(l.treasury_stable_usd - o.treasury_stable_usd <= l.stable_legs_usd_total);
    // Payments do not move TNZO: the outside float with the leg is within
    // a tenth of a percent of the one without it.
    let gap = (l.outside_float_tnzo / o.outside_float_tnzo - 1.0).abs();
    assert!(
        gap < 0.001,
        "float {} vs {}",
        l.outside_float_tnzo,
        o.outside_float_tnzo
    );
    // Providers are paid: the settled demand reaches them.
    assert!(l.unrelated_demand_usd_day > 40_000.0);
    assert!(l.providers_profitable > 0.5);
}

#[test]
fn a_stable_leg_keeps_the_leg_out_of_the_treasurys_tnzo() {
    // Nothing leaves the treasury's TNZO but the leg: no monthly grants, no
    // running costs and none of the fee revenue moved on into the
    // running-cost reserve, which would otherwise differ between the runs.
    let still = [("treasury.reserve_fill_share_bps", 0)];
    let off = "grants_tnzo_month=0,running_cost_ask_usd_month=0";
    let tnzo_leg = run_with(
        Market::Growth,
        60,
        &format!("stable_asset=1,{off}"),
        true,
        &still,
    );
    let stable_leg = run_with(
        Market::Growth,
        60,
        &format!("stable_leg=1,{off}"),
        true,
        &still,
    );
    let (t, s) = (
        tnzo_leg.days.last().expect("a day"),
        stable_leg.days.last().expect("a day"),
    );
    // The VM collects the settlement fee and the leg of a token payment in
    // the token itself (an in-kind fee), whichever way the simulator
    // charges the provider: the leg stays out of the treasury's TNZO, and
    // the treasury holds the token in both runs.
    assert!(t.treasury_stable_usd > 0.0);
    assert!(s.treasury_stable_usd > 0.0);
    assert!(
        (s.snap.treasury - t.snap.treasury).abs() < 1.0,
        "treasury TNZO {} with the stable leg, {} with the TNZO leg",
        s.snap.treasury,
        t.snap.treasury
    );
}

#[test]
fn the_sell_back_sells_the_treasurys_tnzo_above_its_target() {
    // The chain holds treasury grants, the sell-back's included, while the
    // running-cost reserve is under half its target, and fees in the stable
    // token do not fill that reserve: the launch seeds it from the treasury.
    // No monthly grants in either run, so the treasury differs by the
    // sell-back alone.
    let base = run(
        Market::Growth,
        150,
        "reserve_seed_tnzo=10000000,grants_tnzo_month=0",
        true,
    );
    let sold = run(
        Market::Growth,
        150,
        "reserve_seed_tnzo=10000000,grants_tnzo_month=0,treasury_sellback=1,sellback_target_tnzo=40000000",
        true,
    );
    let (b, s) = (
        base.days.last().expect("a day"),
        sold.days.last().expect("a day"),
    );
    assert!(s.sellback_sold_tnzo_total > 0.0);
    // At most the desk's daily cap a day.
    let mut last = 0.0;
    for d in &sold.days {
        assert!(d.sellback_sold_tnzo_total - last <= 1_000_000.0 + 1e-6);
        last = d.sellback_sold_tnzo_total;
    }
    assert!(s.snap.treasury < b.snap.treasury);
    assert!(s.outside_float_tnzo > b.outside_float_tnzo);
}
