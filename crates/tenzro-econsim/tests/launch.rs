//! Launch assumptions: the valuation bound, the realistic preset, staking,
//! stable settlement, and the strategies measured against a baseline run.

use tenzro_econsim::attack::{Adversary, pair};
use tenzro_econsim::economy::{Assumptions, Economy, Market, RunConfig};

#[test]
fn the_default_assumptions_set_no_bound_and_no_new_behaviour() {
    let a = Assumptions::default();
    assert_eq!(a.max_price_to_revenue, 0.0);
    assert_eq!(a.max_fdv_usd, 0.0);
    assert_eq!(a.fdv_stress_year1, 0.0);
    assert_eq!(a.staking_ratio, 0.0);
    assert_eq!(a.demand_growth_per_year, 0.0);
    assert!(!a.stable_settlement);
    let out = Economy::new(RunConfig::scenario(Market::Flat, 1, 2)).run();
    let last = out.days.last().expect("a day");
    assert!(last.price_ceiling_usd.is_infinite());
}

#[test]
fn a_preset_applies_first_and_the_other_keys_after_it() {
    let mut a = Assumptions::default();
    a.apply_list("agent_tasks_per_day=5,preset=realistic")
        .expect("valid list");
    let r = Assumptions::preset("realistic").expect("preset");
    assert_eq!(a.agent_tasks_per_day, 5.0);
    assert_eq!(a.max_price_to_revenue, r.max_price_to_revenue);
    assert_eq!(a.staking_ratio, 0.40);
    assert_eq!(a.running_cost_ask_usd_month, 200_000.0);
    assert!(a.apply_list("preset=nothing").is_err());
    assert!(a.apply_list("staking_ratio=abc").is_err());
}

#[test]
fn the_price_never_rises_above_the_valuation_bound() {
    // Agent demand on a thin pool lifts the price without a bound; the value
    // cap holds it at half the launch value while outside holders still
    // have TNZO to sell (a scarce float is the next test).
    let mut c = RunConfig::scenario(Market::Growth, 3, 6);
    c.assumptions.agent_tasks_per_day = 200_000.0;
    c.assumptions.max_fdv_usd = 50_000_000.0;
    let out = Economy::new(c).run();
    assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);
    for d in &out.days {
        assert!(d.price_ceiling_usd.is_finite());
        assert!(
            d.price_usd <= d.price_ceiling_usd * 1.000_001,
            "day {}: price {} over ceiling {}",
            d.snap.day,
            d.price_usd,
            d.price_ceiling_usd
        );
        assert!(d.fdv_usd <= 50_000_000.0 * 1.000_001, "fdv {}", d.fdv_usd);
    }
    // Without the cap the same demand lifts the price above it.
    let mut c = RunConfig::scenario(Market::Growth, 3, 6);
    c.assumptions.agent_tasks_per_day = 200_000.0;
    let free = Economy::new(c).run();
    let last = free.days.last().expect("a day");
    assert!(last.fdv_usd > 50_000_000.0, "fdv {}", last.fdv_usd);
}

#[test]
fn the_year_one_stress_lowers_the_allowed_value_with_time() {
    let mut c = RunConfig::scenario(Market::Flat, 4, 4);
    c.assumptions.fdv_stress_year1 = 0.7;
    let out = Economy::new(c).run();
    let launch = 0.10;
    let d = out.days.last().expect("a day");
    // The ceiling at day d is the launch value less 70% times d / 365.25.
    let expect = launch * (1.0 - 0.7 * (d.snap.day - 1.0).max(0.0) / 365.25);
    assert!(d.price_ceiling_usd < launch);
    assert!(
        (d.price_ceiling_usd / expect - 1.0).abs() < 0.01,
        "ceiling {} vs {}",
        d.price_ceiling_usd,
        expect
    );
    assert!(d.price_usd <= d.price_ceiling_usd * 1.000_001);
}

#[test]
fn the_staking_ratio_bonds_its_share_and_prices_an_attack() {
    let mut c = RunConfig::scenario(Market::Flat, 5, 2);
    c.assumptions.staking_ratio = 0.4;
    let out = Economy::new(c).run();
    assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);
    let d = out.days.last().expect("a day");
    assert!(
        (d.staking_ratio_circulating - 0.4).abs() < 0.02,
        "bonded {} of circulating",
        d.staking_ratio_circulating
    );
    let third = d.snap.bonded / 3.0;
    assert!((d.attack_cost_usd / (third * d.price_usd) - 1.0).abs() < 1e-9);
    // Far more than the thin pool holds.
    assert!(d.attack_cost_pool_usd.is_infinite());
    let base = Economy::new(RunConfig::scenario(Market::Flat, 5, 2)).run();
    assert!(base.days.last().expect("a day").staking_ratio < 0.01);
}

#[test]
fn stable_settlement_keeps_the_payments_off_the_pool() {
    let mut c = RunConfig::scenario(Market::Flat, 6, 5);
    c.assumptions.stable_settlement = true;
    let out = Economy::new(c).run();
    assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);
    let stable: f64 = out.days.iter().skip(1).map(|d| d.volume_tnzo).sum();
    let base = Economy::new(RunConfig::scenario(Market::Flat, 6, 5)).run();
    let tnzo: f64 = base.days.iter().skip(1).map(|d| d.volume_tnzo).sum();
    assert!(
        stable < tnzo,
        "stable volume {stable} not below TNZO-settled volume {tnzo}"
    );
}

#[test]
fn the_realistic_preset_runs_and_keeps_the_ledger_rule() {
    let mut c = RunConfig::scenario(Market::Growth, 7, 3);
    c.assumptions = Assumptions::preset("realistic").expect("preset");
    let out = Economy::new(c).run();
    assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);
    let d = out.days.last().expect("a day");
    assert!(d.price_ceiling_usd.is_finite());
    assert!(d.revenue_usd_year >= 0.0);
}

fn run_with(
    adv: Adversary,
    days: u32,
    rate_reports: bool,
) -> tenzro_econsim::attack::AttackOutcome {
    let mut c = RunConfig::scenario(Market::Flat, 11, days);
    c.rate_reports = rate_reports;
    c.assumptions.buyer_price_elasticity = 4.0;
    c.adversary = Some(adv);
    let out = Economy::new(c).run();
    assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);
    out.adversary.expect("adversary outcome")
}

#[test]
fn a_wash_ring_settles_and_does_not_profit() {
    let adv = Adversary::WashRing {
        start_day: 1,
        run_days: 3,
        ring: 3,
        plans_per_hour: 2,
        value_tnzo: 2_000.0,
        report_work: true,
    };
    let o = run_with(adv, 6, false);
    let settled = o.detail.get("settled_tnzo").copied().unwrap_or(0.0);
    assert!(settled > 0.0, "no wash plan settled: {:?}", o.detail);
    assert!(
        o.profit_tnzo <= 0.0,
        "the ring gained {} TNZO: {:?}",
        o.profit_tnzo,
        o.detail
    );
    assert!(!o.succeeded);
}

#[test]
fn an_honest_baseline_pairs_to_zero_gain() {
    let spec = Adversary::OracleSkew {
        start_day: 1,
        run_days: 2,
        cartel: 7,
        skew_bps: 0,
    };
    let base = run_with(spec.baseline().expect("paired"), 4, true);
    let mut same = run_with(spec, 4, true);
    pair(&mut same, &base);
    assert!(
        same.profit_tnzo.abs() < 1e-6,
        "an unskewed cartel gained {}",
        same.profit_tnzo
    );
    assert!(!same.detail.keys().any(|k| k.starts_with("val:")));
}

#[test]
fn an_oracle_skew_is_measured_against_its_baseline() {
    let spec = Adversary::OracleSkew {
        start_day: 1,
        run_days: 3,
        cartel: 10,
        skew_bps: -900,
    };
    let base = run_with(spec.baseline().expect("paired"), 5, true);
    let mut o = run_with(spec, 5, true);
    pair(&mut o, &base);
    assert!(o.profit_tnzo.is_finite());
    assert!(o.detail.contains_key("cartel_validators_gain_tnzo"));
    assert!(o.detail.contains_key("rate_max_deviation"));
    assert_eq!(o.succeeded, o.profit_tnzo > 1.0);
}

#[test]
fn colluding_providers_are_measured_against_their_baseline() {
    let spec = Adversary::ProviderCollusion {
        start_day: 1,
        run_days: 3,
        providers: 1,
        markup: 2.0,
        cartel: 8,
        honest_attest: 1.0,
    };
    let base = run_with(spec.baseline().expect("paired"), 5, false);
    let mut o = run_with(spec, 5, false);
    pair(&mut o, &base);
    let gain = o
        .detail
        .get("colluding_providers_gain_usd")
        .copied()
        .expect("provider gain");
    assert!(gain.is_finite());
    // The markup changes what the colluding provider earns.
    assert!(gain != 0.0, "{:?}", o.detail);
}

#[test]
fn a_playbook_trigger_reports_whether_the_rate_was_held() {
    let spec = Adversary::PlaybookTrigger {
        start_day: 1,
        run_days: 4,
        cartel: 14,
        skew_bps: -5_000,
        keep_skew: true,
    };
    let base = run_with(spec.baseline().expect("paired"), 6, true);
    let mut o = run_with(spec, 6, true);
    pair(&mut o, &base);
    assert!(o.detail.contains_key("days_rate_held"));
    assert!(o.detail.contains_key("cartel_stake_share"));
    assert!(o.profit_tnzo.is_finite());
}

fn rewards_pool_after(
    bps: u64,
    claim: bool,
) -> (f64, Option<tenzro_econsim::classes::LaunchEconomics>) {
    let mut c = RunConfig::scenario(Market::Flat, 12, 6);
    c.assumptions.providers_claim_rewards = claim;
    c.network_params
        .insert("fees.activity_reward_fee_bps".into(), bps);
    let out = Economy::new(c).run();
    assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);
    (
        out.days.last().expect("a day").snap.rewards_pool,
        out.launch,
    )
}

#[test]
fn providers_earn_capped_provider_rewards_once_they_claim() {
    // Unclaimed, the coupons expire in the pool.
    let (off, _) = rewards_pool_after(5_000, false);
    // Claimed, providers take the provider work their streams and sessions
    // earn out of it. The activity share goes to the app a settlement is
    // attributed to; the simulated payments name none, so it changes
    // nothing here.
    let (on0, l0) = rewards_pool_after(0, true);
    let (on5, l5) = rewards_pool_after(5_000, true);
    assert!(on5 < off, "pool {on5} claimed, {off} unclaimed");
    assert_eq!(on0, on5);
    let g = &l5.as_ref().expect("launch").gpu_rental;
    assert!(g.rewards_usd_month > 0.0);
    assert_eq!(
        l0.as_ref().expect("launch").gpu_rental.rewards_usd_month,
        g.rewards_usd_month
    );
    // The reward is capped by what the settlement paid outside the trade:
    // with no treasury leg, a share of a 0.1% fee.
    assert!(
        g.rewards_usd_month <= 0.001 * g.revenue_usd_month,
        "rewards {} of revenue {}",
        g.rewards_usd_month,
        g.revenue_usd_month
    );
}

#[test]
fn a_trace_drives_the_agent_sessions() {
    let text = "{\"t_ms\":0,\"buyer\":1,\"provider\":7,\"service\":\"compute\",\"amount_milli\":2000,\"delivered\":true}\n\
        {\"t_ms\":1000,\"buyer\":2,\"provider\":8,\"service\":\"search\",\"amount_milli\":1000,\"delivered\":true}\n";
    let t = tenzro_econsim::trace::TraceDemand::parse("t", text, 1.0).expect("parses");
    let mut c = RunConfig::scenario(Market::Flat, 13, 3);
    c.assumptions.use_trace(t);
    assert_eq!(c.assumptions.agent_task_usd, 1.5);
    assert_eq!(c.assumptions.compute_usd_per_day, 0.0);
    let out = Economy::new(c).run();
    assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);
    assert!(out.agent_sessions > 0.0);
    let l = out.launch.expect("launch");
    assert_eq!(l.users.trace_undelivered_share, Some(0.0));
}

#[test]
fn providers_sell_what_they_hold_above_their_set_days() {
    let float = |hold: f64| {
        let mut c = RunConfig::scenario(Market::Flat, 14, 12);
        c.assumptions.provider_sell_share = 0.0;
        c.assumptions.provider_hold_days = hold;
        let out = Economy::new(c).run();
        assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);
        out.days.last().expect("a day").outside_float_tnzo
    };
    // Keeping everything drains what buyers can buy from; a two-day limit
    // returns the rest to the market.
    assert!(float(2.0) > float(0.0));
}

#[test]
fn the_valuation_bound_gives_way_when_holders_have_nothing_to_sell() {
    // Heavy buying under a tight value cap drains what outside holders hold;
    // the bound then yields and the price rises above it rather than letting
    // buyers run out of TNZO.
    let mut c = RunConfig::scenario(Market::Growth, 15, 20);
    c.assumptions.agent_tasks_per_day = 20_000_000.0;
    c.assumptions.max_fdv_usd = 50_000_000.0;
    c.assumptions.staking_ratio = 0.6;
    let out = Economy::new(c).run();
    assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);
    for d in &out.days {
        let cap = 50_000_000.0 / d.snap.supply;
        assert!(d.price_ceiling_usd >= cap * 0.999, "ceiling under the cap");
        assert!(d.price_usd <= d.price_ceiling_usd * 1.000_001);
    }
    // Buyers never empty what outside holders hold.
    assert!(out.days.iter().all(|d| d.outside_float_tnzo > 0.0));
}

#[test]
fn delegated_stake_returns_to_outside_holders_when_validators_leave() {
    // At realistic costs validators leave; their delegated stake goes back
    // to outside holders instead of sitting with the operators.
    let mut c = RunConfig::scenario(Market::Flat, 16, 75);
    c.assumptions.staking_ratio = 0.4;
    c.assumptions.validator_cost_usd_month = 5_000.0;
    let out = Economy::new(c).run();
    assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);
    let last = out.days.last().expect("a day");
    let first = &out.days[0];
    assert!(last.snap.bonded_validators < first.snap.bonded_validators);
    let left_with_operators = last.held_by.validators_liquid;
    assert!(
        left_with_operators < 0.1 * (first.snap.bonded - last.snap.bonded),
        "operators still hold {left_with_operators} TNZO"
    );
}

#[test]
fn the_closed_preset_is_the_realistic_one_before_a_listing() {
    let mut a = Assumptions::default();
    a.apply_list("preset=closed,anchor_share=0.25")
        .expect("valid list");
    let r = Assumptions::preset("realistic").expect("preset");
    assert!(a.closed_phase);
    assert!(a.stable_settlement);
    assert!(a.stable_asset && a.stable_leg);
    assert_eq!(a.anchor_share, 0.25);
    assert_eq!(a.running_cost_ask_usd_month, r.running_cost_ask_usd_month);
    assert!(!Assumptions::default().closed_phase);
}

#[test]
fn the_closed_phase_has_no_market_and_the_owner_pays_the_running_costs() {
    let mut c = RunConfig::scenario(Market::Growth, 17, 6);
    c.assumptions.closed_phase = true;
    c.assumptions.agent_tasks_per_day = 200_000.0;
    c.assumptions.max_fdv_usd = 50_000_000.0;
    let out = Economy::new(c).run();
    assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);
    for d in &out.days {
        // Nothing trades: the price stays at launch and the reserve sells
        // nothing, while the owner pays every running cost asked.
        assert_eq!(d.price_usd, 0.10);
        assert_eq!(d.volume_tnzo, 0.0);
        assert_eq!(d.reserve_paid_tnzo, 0.0);
        assert_eq!(d.grants_usd, 0.0);
        assert!(
            (d.running_costs_paid_usd_30d - d.running_costs_asked_usd_30d).abs() < 1e-6,
            "paid {} of {}",
            d.running_costs_paid_usd_30d,
            d.running_costs_asked_usd_30d
        );
    }
    assert!(
        out.days
            .iter()
            .any(|d| d.validator_fee_income_usd_30d > 0.0)
    );
    assert!(out.listing_gate.is_some());
    // An open market run reports no gate.
    let open = Economy::new(RunConfig::scenario(Market::Flat, 17, 2)).run();
    assert!(open.listing_gate.is_none());
}

#[test]
fn anchor_demand_does_not_count_toward_the_listing_gate() {
    // $100,000 a day of agent demand meets the unrelated-demand item; with
    // half of it the owner's own, $50,000 does not.
    let run = |anchor: f64| {
        let mut c = RunConfig::scenario(Market::Flat, 18, 4);
        c.assumptions.closed_phase = true;
        c.assumptions.compute_usd_per_day = 0.0;
        c.assumptions.agent_tasks_per_day = 200_000.0;
        c.assumptions.anchor_share = anchor;
        let out = Economy::new(c).run();
        assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);
        out
    };
    let all = run(0.0);
    let half = run(0.5);
    let d = all.days.last().expect("a day");
    let h = half.days.last().expect("a day");
    assert!(
        d.unrelated_demand_usd_day > 90_000.0 && d.unrelated_demand_usd_day < 110_000.0,
        "unrelated {}",
        d.unrelated_demand_usd_day
    );
    assert!((h.unrelated_demand_usd_day / d.unrelated_demand_usd_day - 0.5).abs() < 0.05);
    assert!(
        all.listing_gate
            .expect("gate")
            .unrelated_demand_day
            .is_some()
    );
    assert_eq!(half.listing_gate.expect("gate").unrelated_demand_day, None);
}

#[test]
fn contracted_validators_stay_whatever_their_yield() {
    let mut c = RunConfig::scenario(Market::Flat, 16, 45);
    c.assumptions.closed_phase = true;
    c.assumptions.staking_ratio = 0.4;
    c.assumptions.validator_cost_usd_month = 5_000.0;
    let out = Economy::new(c).run();
    assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);
    let first = out.days[0].snap.bonded_validators;
    assert!(out.days.iter().all(|d| d.snap.bonded_validators == first));
    // Their fee income does not cover $5,000 a month each.
    let gate = out.listing_gate.expect("gate");
    assert_eq!(gate.validators_cover_day, None);
}
