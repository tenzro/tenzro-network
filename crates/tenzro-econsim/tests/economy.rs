//! A short economy keeps the ledger's value rule and records every day.

use tenzro_econsim::economy::{Ablation, Economy, Market, RunConfig};

#[test]
fn a_short_economy_conserves_value_and_records_each_day() {
    let out = Economy::new(RunConfig::scenario(Market::Flat, 1, 4)).run();
    assert!(
        out.ledger_failures.is_empty(),
        "ledger failures: {:?}",
        out.ledger_failures
    );
    assert_eq!(out.days.len(), 4);
    let last = out.days.last().expect("a day");
    assert!(last.snap.bonded_validators >= 4);
    assert!(last.human_fee_tnzo > 0.0, "a transfer pays a fee");
    assert!(out.applied > 0);
}

#[test]
fn a_stream_that_ran_its_course_is_closed() {
    let out = Economy::new(RunConfig::scenario(Market::Flat, 1, 4)).run();
    assert_eq!(
        out.streams_left_open, 0,
        "streams past their end still hold funds"
    );
}

#[test]
fn the_same_seed_replays_the_same_economy() {
    let a = Economy::new(RunConfig::scenario(Market::Downturn, 9, 2)).run();
    let b = Economy::new(RunConfig::scenario(Market::Downturn, 9, 2)).run();
    let (x, y) = (a.days.last().expect("day"), b.days.last().expect("day"));
    assert_eq!(x.snap.supply, y.snap.supply);
    assert_eq!(x.snap.treasury, y.snap.treasury);
    assert_eq!(x.snap.insurance_pool, y.snap.insurance_pool);
}

#[test]
fn validators_seal_and_open_rates_and_the_rate_follows_them() {
    let mut c = RunConfig::scenario(Market::Flat, 2, 3);
    c.rate_reports = true;
    let out = Economy::new(c).run();
    assert!(out.ledger_failures.is_empty(), "{:?}", out.ledger_failures);
    let refused: u64 = out
        .refusals
        .iter()
        .filter(|(k, _)| k.contains("sealed") || k.contains("opened"))
        .map(|(_, v)| *v)
        .sum();
    assert_eq!(refused, 0, "rate reports refused: {:?}", out.refusals);
    let last = out.days.last().expect("a day");
    let gap = (last.chain_rate_usd / last.price_usd - 1.0).abs();
    assert!(
        gap < 0.2,
        "chain rate {} vs price {}",
        last.chain_rate_usd,
        last.price_usd
    );
}

#[test]
fn a_cartel_under_two_thirds_cannot_move_the_banded_rate() {
    // The band is read on its own: the dispersion breaker's bounds sit at
    // their governed widest, and the cartel quotes three times the market,
    // inside the widest gap the breaker allows (500% of the governance rate).
    let mut c = RunConfig::scenario(Market::Flat, 3, 6);
    c.assumptions.outside_flow_vol = 0.0;
    c.assumptions.governance_tracks_price = false;
    c.rate_reports = true;
    c.rate_cartel = Some((11, 3.0, 1));
    c.ablation = Ablation::MedianOnly;
    c.network_params
        .insert("fees.usd_rate_breaker_gap_bps".into(), 50_000);
    c.network_params
        .insert("fees.usd_rate_breaker_spread_bps".into(), 5_000);
    // Against the same economy with no cartel: the band lets the cartel
    // hold the rate where it stood, never lift it above both that and
    // where honest reports alone would take it.
    let mut honest = c.clone();
    honest.rate_cartel = None;
    let base = Economy::new(honest).run();
    let lift = |out: &tenzro_econsim::economy::RunOutcome| {
        let start = out.days[0].chain_rate_usd;
        out.days
            .iter()
            .zip(&base.days)
            .map(|(a, b)| a.chain_rate_usd / b.chain_rate_usd.max(start))
            .fold(1.0f64, f64::max)
    };
    let out = Economy::new(c.clone()).run();
    assert!(lift(&out) < 1.02, "banded rate lifted {}", lift(&out));
    // Without the band the same cartel lifts it.
    c.ablation = Ablation::NoQuantileBand;
    let out = Economy::new(c.clone()).run();
    assert!(lift(&out) > 1.1, "median rate lifted only {}", lift(&out));
    // At ten times the market the breaker alone holds the rate, with the
    // band removed: its default gap bound is far inside that.
    let mut wild = c;
    wild.rate_cartel = Some((11, 10.0, 1));
    wild.network_params.remove("fees.usd_rate_breaker_gap_bps");
    wild.network_params
        .remove("fees.usd_rate_breaker_spread_bps");
    let out = Economy::new(wild).run();
    assert!(
        lift(&out) < 1.02,
        "the dispersion breaker let the rate lift {}",
        lift(&out)
    );
}

#[test]
fn the_price_comes_from_the_pool_the_populations_trade_on() {
    let out = Economy::new(RunConfig::scenario(Market::Growth, 4, 4)).run();
    let first = out.days.first().expect("day").price_usd;
    assert!(
        out.days.iter().any(|d| d.price_usd != first),
        "the pool price moves"
    );
    assert!(out.days.iter().all(|d| d.price_usd > 0.0));
}

#[test]
fn machine_economy_models_hold_their_criteria() {
    let rows = tenzro_econsim::machine::scenarios(&Default::default());
    assert!(rows.len() >= 12);
    let failing: Vec<_> = rows.iter().filter(|r| !r.pass).map(|r| &r.name).collect();
    assert!(failing.is_empty(), "failing: {failing:?}");
}

#[test]
fn every_ablation_runs() {
    for ab in Ablation::ALL {
        let mut c = RunConfig::scenario(Market::Flat, 5, 2);
        c.ablation = ab;
        let out = Economy::new(c).run();
        assert!(
            out.ledger_failures.is_empty(),
            "{}: {:?}",
            ab.name(),
            out.ledger_failures
        );
        assert_eq!(out.days.len(), 2, "{}", ab.name());
    }
}
