//! The recycling cap and the tiers: release follows the burn, a wash loses,
//! the supply never grows, and USD income under the cap does not need the
//! TNZO price to move.

use std::collections::BTreeMap;

use tenzro_econsim::recycle::{WashPayer, price_paths, wash};
use tenzro_econsim::usage::{PricePath, Recycle, Rules, Tiers, Trace, replay};
use tenzro_econsim::usage_fixtures::{MIXES, SCALES, cells, fixture};

const DAYS: u64 = 200;
/// A wash through a second wallet no check ties to the operator, with no share cap.
const OPEN: WashPayer = WashPayer::Hidden {
    volume_share: 1.0,
    share_cap: None,
};

fn baseline() -> Trace {
    let c = cells().into_iter().find(|c| c.name == "baseline").unwrap();
    fixture(&c, MIXES[1].1, SCALES[2], DAYS)
}

#[test]
fn release_never_exceeds_the_ratio_times_the_burn() {
    let t = baseline();
    for r in [0.25, 0.5, 1.0] {
        let o = replay(
            &t,
            &Rules {
                recycle: Some(Recycle::new(r)),
                ..Rules::default()
            },
        );
        assert!(o.burned_tnzo_eq > 0.0);
        assert!(
            o.released_tnzo <= r * o.burned_tnzo_eq * (1.0 + 1e-9),
            "r={r}: released {} over burned {}",
            o.released_tnzo,
            o.burned_tnzo_eq
        );
        assert!(o.pass_charter);
    }
}

#[test]
fn the_supply_never_grows_and_the_pool_only_falls() {
    let t = baseline();
    let o = replay(
        &t,
        &Rules {
            recycle: Some(Recycle::new(1.0)),
            ..Rules::default()
        },
    );
    assert!(o.supply_change_tnzo <= 0.0);
    assert!(o.pool_end_tnzo <= o.pool_start_tnzo);
    assert!(o.released_tnzo <= o.pool_start_tnzo - o.pool_end_tnzo + 1e-6);
}

#[test]
fn usd_income_under_the_cap_is_the_same_at_any_held_price() {
    let t = baseline();
    let usd = |p: f64| {
        let o = replay(
            &t,
            &Rules {
                recycle: Some(Recycle::new(0.5)),
                price_path: Some(PricePath::Held(p)),
                ..Rules::default()
            },
        );
        o.tick_book
            .iter()
            .map(|b| b.provider_release_usd)
            .sum::<f64>()
    };
    let (lo, hi) = (usd(0.03), usd(3.0));
    assert!(lo > 0.0);
    assert!((lo - hi).abs() <= 1e-6 * lo.max(hi), "{lo} against {hi}");
}

#[test]
fn a_wash_loses_money_at_a_ratio_of_one_or_less() {
    for r in [0.25, 0.5, 0.75, 0.9, 1.0] {
        for s in [0.0, 1.0 / 7.0] {
            let w = wash(Some(r), s, 0.0, OPEN);
            assert!(w["net"].as_f64().unwrap() < 0.0, "r={r} s={s}: {w}");
        }
    }
}

#[test]
fn no_burn_means_no_release_without_a_floor() {
    let t = baseline();
    let o = replay(
        &t,
        &Rules {
            recycle: Some(Recycle::new(1.0)),
            blackout: Some((0, DAYS)),
            ..Rules::default()
        },
    );
    assert_eq!(o.burned_tnzo_eq, 0.0);
    assert_eq!(o.released_tnzo, 0.0);
}

#[test]
fn tiers_keep_every_validator_at_or_under_a_third_of_the_pay() {
    let t = baseline();
    let o = replay(
        &t,
        &Rules {
            tiers: Some(Tiers {
                weights: [1.0, 2.0, 4.0],
                cost_mult: [0.5, 1.0, 2.0],
                pattern: vec![0, 0, 0, 1, 1, 2, 2],
                share_cap: 1.0 / 3.0,
            }),
            ..Rules::default()
        },
    );
    assert!(
        o.max_weight_share <= 1.0 / 3.0 + 1e-9,
        "{}",
        o.max_weight_share
    );
    assert!(o.nakamoto_min >= 2);
}

#[test]
fn usd_income_under_the_cap_is_the_same_on_every_price_path() {
    let t = baseline();
    let usd = |path: PricePath| {
        let o = replay(
            &t,
            &Rules {
                recycle: Some(Recycle::new(0.5)),
                price_path: Some(path),
                ..Rules::default()
            },
        );
        assert!(o.supply_change_tnzo <= 0.0);
        o.tick_book
            .iter()
            .map(|b| b.provider_release_usd)
            .sum::<f64>()
    };
    let held = usd(PricePath::Held(0.30));
    assert!(held > 0.0);
    for (name, path) in price_paths() {
        let moved = usd(path);
        assert!(
            (held - moved).abs() <= 1e-6 * held.max(moved),
            "{name}: {held} against {moved}"
        );
    }
}

#[test]
fn a_price_path_is_the_same_for_one_seed_and_never_at_or_under_zero() {
    for (name, path) in price_paths() {
        let days = path.daily(400);
        assert_eq!(days, path.daily(400), "{name}");
        assert_eq!(days[0], 0.30, "{name}");
        assert!(days.iter().all(|p| *p > 0.0 && p.is_finite()), "{name}");
    }
    let fall = price_paths()[1].1.daily(60);
    assert_eq!(fall[30], 0.30);
    assert!((fall[37] - 0.03).abs() < 1e-12 && (fall[59] - 0.03).abs() < 1e-12);
}

#[test]
fn the_ratio_steps_down_as_the_pool_falls() {
    let mut rc = Recycle::new(1.0);
    rc.ratio_steps = vec![(0.5, 0.7), (0.25, 0.5), (0.10, 0.25)];
    assert_eq!(rc.ratio_at(1.0), 1.0);
    assert_eq!(rc.ratio_at(0.5), 1.0);
    assert_eq!(rc.ratio_at(0.49), 0.7);
    assert_eq!(rc.ratio_at(0.2), 0.5);
    assert_eq!(rc.ratio_at(0.0), 0.25);
    // A step that is always in force holds the whole run to its ratio.
    let mut low = Recycle::new(1.0);
    low.ratio_steps = vec![(2.0, 0.25)];
    let o = replay(
        &baseline(),
        &Rules {
            recycle: Some(low),
            ..Rules::default()
        },
    );
    assert!(o.released_tnzo > 0.0);
    assert!(
        o.released_tnzo <= 0.25 * o.burned_tnzo_eq * (1.0 + 1e-9),
        "released {} over burned {}",
        o.released_tnzo,
        o.burned_tnzo_eq
    );
}

#[test]
fn a_low_pool_switches_to_paying_from_the_fees_kept() {
    let t = baseline();
    let run = |pool: Option<f64>, switch: Option<f64>| {
        let mut rc = Recycle::new(1.0);
        rc.fee_direct_below = switch;
        // Fees are paid on stable rails with the 100 bps treasury leg, so fees are kept.
        let mut rules = Rules {
            recycle: Some(rc),
            pool_tnzo: pool,
            rails: Some(BTreeMap::from([
                ("USDA".to_string(), 0.6),
                ("USDB".to_string(), 0.4),
            ])),
            ..Rules::default()
        };
        rules.overrides.insert(
            tenzro_vm::native::economy::TREASURY_LEG_INFERENCE_PARAM.into(),
            100,
        );
        replay(&t, &rules)
    };
    // A pool of half of what the run would release: it runs dry without the switch.
    let pool = run(None, None).released_tnzo / 2.0;
    assert!(pool > 0.0);
    let dry = run(Some(pool), None);
    assert_eq!(dry.direct_paid_usd, 0.0);
    assert!(dry.pool_end_tnzo < 0.10 * pool, "{}", dry.pool_end_tnzo);
    let switched = run(Some(pool), Some(0.10));
    assert!(switched.direct_paid_usd > 0.0, "{}", switched.pool_end_tnzo);
    assert!(
        switched.pool_end_tnzo > dry.pool_end_tnzo,
        "{} against {}",
        switched.pool_end_tnzo,
        dry.pool_end_tnzo
    );
    assert!(switched.supply_change_tnzo <= 0.0);
}

#[test]
fn a_wash_paid_from_the_operators_own_source_releases_nothing() {
    for r in [0.5, 1.0, 1.5, 3.0] {
        for s in [0.0, 1.0 / 7.0, 1.0 / 3.0] {
            let w = wash(Some(r), s, 0.0, WashPayer::Own);
            assert_eq!(w["release"].as_f64().unwrap(), 0.0, "r={r} s={s}: {w}");
            assert!(w["net"].as_f64().unwrap() < 0.0, "r={r} s={s}: {w}");
        }
    }
}

#[test]
fn a_share_cap_holds_a_hidden_wash_to_the_capped_share_of_the_release() {
    let open = wash(Some(1.0), 0.0, 0.0, OPEN)["release"].as_f64().unwrap();
    let capped = |volume_share: f64| {
        let payer = WashPayer::Hidden {
            volume_share,
            share_cap: Some(0.10),
        };
        wash(Some(1.0), 0.0, 0.0, payer)["release"]
            .as_f64()
            .unwrap()
    };
    assert!(open > 0.0);
    // Under the cap nothing is withheld; over it the release is cut in proportion.
    assert_eq!(capped(0.05), open);
    assert!((capped(0.50) - open * 0.2).abs() <= 1e-12 * open);
}
