//! The chaos run: a seed replays to the same result on any thread count, a
//! known-bad parameter set breaks an invariant, and the defaults keep them.

use std::sync::Arc;

use tenzro_econsim::chaos::{self, Event, Kind, Plan, Settings};
use tenzro_econsim::economy::Ablation;

/// Short runs: the invariants are the same at any horizon.
const YEARS: f64 = 0.25;

#[test]
fn the_same_seed_gives_the_same_result_on_any_thread_count() {
    let s = Settings::new(YEARS);
    let a = chaos::run_seed(3, &s);
    let b = chaos::run_seed(3, &s);
    assert_eq!(a, b);
    assert_eq!(
        serde_json::to_string(&a).unwrap(),
        serde_json::to_string(&b).unwrap()
    );
    let mut many = Vec::new();
    chaos::run_many(&[4, 3], &s, 2, |r| many.push(r));
    many.sort_by_key(|r| r.seed);
    assert_eq!(many[0], a);
    assert_ne!(many[1].digest, a.digest);
}

#[test]
fn a_rate_cartel_without_the_quantile_band_breaks_fee_rate_stability() {
    // Known bad: the rate rule reduced to a plain median (no quantile band,
    // no challenge) and nine validators in ten reporting half again the
    // market rate for 80 days.
    let s = Settings::new(YEARS);
    let mut c = s.base.clone();
    c.seed = 5;
    c.days = s.days;
    c.ablation = Ablation::NoQuantileBand;
    // The dispersion breaker would hold the rate on its own; its bounds sit
    // at their governed widest so the plain median is what is exercised.
    c.network_params
        .insert("fees.usd_rate_breaker_gap_bps".into(), 50_000);
    c.network_params
        .insert("fees.usd_rate_breaker_spread_bps".into(), 5_000);
    c.chaos = Some(Arc::new(Plan {
        days: s.days,
        events: vec![Event {
            kind: Kind::RateCartel,
            day: 3,
            days: 80,
            size: 0.9,
            factor: 1.5,
            tail_days: 0,
            amount: 0.0,
            joint: false,
        }],
    }));
    let r = chaos::run_config(c, &s.limits);
    assert!(!r.pass, "{r:?}");
    assert!(
        r.broken.contains(&"fee_rate_stability".to_string()),
        "{r:?}"
    );
}

#[test]
fn the_defaults_keep_every_invariant() {
    let s = Settings::new(YEARS);
    let r = chaos::run_seed(1, &s);
    assert!(r.pass, "{r:?}");
    assert_eq!(r.conservation_breaks, 0);
}

#[test]
fn a_governed_proposal_raises_the_treasury_legs_mid_run_and_the_floor_still_holds() {
    // Governance can raise the treasury legs after launch, not only set
    // them as genesis parameters: Assumptions::leg_proposal_bps files the
    // same ParameterChange Settings::new bakes in at genesis, through the
    // normal propose, vote, timelock, enact path, once per leg.
    fn bare_at_zero() -> Settings {
        let mut s = Settings::new(YEARS);
        for key in [
            "fees.treasury_leg_inference_bps",
            "fees.treasury_leg_compute_bps",
        ] {
            s.base.network_params.insert(key.into(), 0);
        }
        s
    }
    let without_proposal = chaos::run_seed(1, &bare_at_zero());
    let mut governed = bare_at_zero();
    governed.base.assumptions.leg_proposal_bps = chaos::TREASURY_LEG_BPS as f64;
    governed.base.assumptions.leg_proposal_day = 1.0;
    // Raising a leg is a tightening change, so it is held for
    // governance.tightening_grace_epochs (genesis 168, i.e. 168 days, one
    // epoch per day) before it actually takes effect -- real, intentional
    // advance notice, not a defect. A 90-day run cannot observe it land at
    // the real default, so this test fast-forwards the notice period to
    // exercise the propose -> schedule -> activate -> floor-holds path
    // deterministically; it does not change the real governed default.
    governed
        .base
        .network_params
        .insert("governance.tightening_grace_epochs".into(), 1);
    let with_proposal = chaos::run_seed(1, &governed);

    assert!(
        without_proposal
            .broken
            .contains(&"validator_floor".to_string()),
        "{without_proposal:?}"
    );
    assert!(with_proposal.pass, "{with_proposal:?}");
    assert_eq!(
        with_proposal.floor_first_miss_day, None,
        "{with_proposal:?}"
    );
}

#[test]
fn a_sweep_cell_runs_the_same_on_any_thread_count() {
    let base = Settings::new(0.1);
    let picks = [chaos::sweep_cells()[0].clone(), chaos::Cell::central()];
    let settings: Vec<Settings> = picks.iter().map(|c| c.settings(&base)).collect();
    let jobs = [(0usize, 2u64), (1, 2)];
    let mut got = Vec::new();
    chaos::run_parallel(
        &jobs,
        2,
        |(k, seed)| chaos::run_seed(*seed, &settings[*k]),
        |(k, _), r| got.push((*k, r)),
    );
    got.sort_by_key(|(k, _)| *k);
    for (k, r) in &got {
        assert_eq!(r, &chaos::run_seed(2, &settings[*k]));
    }
    assert_ne!(got[0].1.digest, got[1].1.digest);
}

#[test]
fn without_the_treasury_leg_or_sponsorship_the_validator_floor_breaks_and_with_the_governed_leg_it_holds()
 {
    // Reported three ways. With the leg governance set at launch, paid usage
    // fills the validator cover reserve and the floor holds with and without
    // the stable sponsorship. With neither the leg nor the sponsorship, paid
    // usage alone does not fund the seats in this market and the floor
    // breaks.
    let s = Settings::new(YEARS);
    let with = chaos::run_seed(1, &s);
    let without = chaos::run_seed(1, &s.without_sponsorship());
    let mut bare = s.without_sponsorship();
    for key in [
        "fees.treasury_leg_inference_bps",
        "fees.treasury_leg_compute_bps",
    ] {
        bare.base.network_params.insert(key.into(), 0);
    }
    let bare = chaos::run_seed(1, &bare);
    assert!(with.pass && without.pass, "{with:?} {without:?}");
    assert_eq!(with.floor_first_miss_day, None, "{with:?}");
    assert_eq!(without.floor_first_miss_day, None, "{without:?}");
    assert!(with.sponsored_usd_total > 0.0, "{with:?}");
    assert_eq!(without.sponsored_usd_total, 0.0);
    assert_eq!(
        with.sponsored_tnzo_total, 0.0,
        "sponsorship is paid in the stable asset"
    );
    assert!(
        bare.broken.contains(&"validator_floor".to_string()),
        "{bare:?}"
    );
}

#[test]
fn sponsorship_comes_from_the_treasury_within_the_usd_caps_and_mints_nothing() {
    let s = Settings::new(YEARS);
    let r = chaos::run_seed(1, &s);
    // The stable sponsorship is paid against verified hours, in USD, inside
    // the yearly cap governance set.
    assert!(r.sponsored_usd_total > 0.0, "{r:?}");
    let cap = s.base.network_params["sponsorship.yearly_max_usd"] as f64;
    assert!(cap > 0.0 && r.sponsored_usd_total <= cap, "{r:?}");
    // Sponsorship and grants together stay under the yearly cap.
    assert!(
        r.sponsor_grant_outflow_year_max_tnzo <= r.sponsor_grant_cap_tnzo,
        "{r:?}"
    );
    // Nothing is issued: the conservation checks held and supply never rose
    // above the same run without sponsorship.
    assert_eq!(r.conservation_breaks, 0, "{r:?}");
    assert_eq!(r.burned_fell_days, 0, "{r:?}");
    let off = chaos::run_seed(1, &s.without_sponsorship());
    assert!(r.supply_max_tnzo <= off.supply_max_tnzo, "{r:?} {off:?}");
}

/// With the treasury leg taken in the stable asset, a higher leg keeps the
/// validator floor at least as long as a lower one on the same seed: a leg
/// that funds the floor cannot lose it sooner by being larger. Taken in
/// TNZO instead, the leg is bought from the outside float, and that run is
/// reported beside it so the two can be compared.
#[test]
fn a_higher_stable_leg_never_loses_the_floor_sooner() {
    let run = |leg: u64, stable: bool| {
        let mut s = Settings::new(YEARS);
        for key in [
            "fees.treasury_leg_inference_bps",
            "fees.treasury_leg_compute_bps",
        ] {
            s.base.network_params.insert(key.into(), leg);
        }
        s.base.assumptions.stable_leg = stable;
        chaos::run_seed(1, &s)
    };
    let held = |r: &chaos::SeedResult| r.floor_first_miss_day.unwrap_or(u32::MAX);
    let mut last = 0;
    for leg in [1_000, 2_500, 5_000] {
        let stable = run(leg, true);
        let tnzo = run(leg, false);
        println!(
            "leg {leg}: stable floor {:?} validators_min {}; tnzo floor {:?} validators_min {}",
            stable.floor_first_miss_day,
            stable.validators_min,
            tnzo.floor_first_miss_day,
            tnzo.validators_min
        );
        assert!(held(&stable) >= last, "leg {leg}: {stable:?}");
        last = held(&stable);
    }
}
