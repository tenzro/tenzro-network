//! The runway: a payout needs an approved recipient and verified work or an
//! approved milestone, the supply never grows, the treasury limits hold, and
//! a wash through a sponsored validator loses.

use tenzro_econsim::runway::*;
use tenzro_econsim::usage::{PricePath, Rules, Trace, replay};
use tenzro_econsim::usage_fixtures::{MIXES, SCALES, cells, fixture};

const DAYS: u64 = 200;

fn baseline() -> Trace {
    let c = cells().into_iter().find(|c| c.name == "baseline").unwrap();
    fixture(&c, MIXES[1].1, SCALES[2], DAYS)
}

fn series(n: u32, price: f64) -> Series {
    let o = replay(
        &baseline(),
        &Rules {
            validators: n,
            standby: 0,
            exit_ratio: 0.0,
            market_share: 0.01,
            price_path: Some(PricePath::Held(price)),
            ..Rules::default()
        },
    );
    assert!(o.pass_charter);
    assert!(o.supply_change_tnzo <= 0.0);
    Series::from_outcome(n, price, COST_DAY, &o)
}

#[test]
fn nothing_is_paid_without_approval_verification_or_a_milestone() {
    assert_eq!(sponsor_payout(false, 1.0, 40.0), 0.0);
    assert_eq!(sponsor_payout(true, 0.0, 40.0), 0.0);
    assert_eq!(sponsor_payout(true, 1.0, 0.0), 0.0);
    assert_eq!(sponsor_payout(true, 1.0, 40.0), 40.0);
    assert_eq!(sponsor_payout(true, 0.5, 40.0), 20.0);
    assert_eq!(grant_payout(false, true, 1000.0), 0.0);
    assert_eq!(grant_payout(true, false, 1000.0), 0.0);
    assert_eq!(grant_payout(true, true, 1000.0), 1000.0);
}

#[test]
fn a_validator_with_no_verified_work_is_paid_nothing() {
    let mut s = series(7, 0.30);
    s.active = vec![0.0; s.active.len()];
    s.earned = vec![0.0; s.earned.len()];
    for t in 0..HORIZON {
        assert_eq!(s.need(t), 0.0);
    }
    let f = fund(
        &s,
        &FundCfg {
            r0: 1e6,
            b0: 9.5e7,
            price: 0.30,
            ..FundCfg::default()
        },
    );
    assert_eq!(f.need_usd, 0.0);
    assert_eq!(f.sponsor_tnzo_year.iter().sum::<f64>(), 0.0);
}

#[test]
fn the_treasury_only_pays_out_what_it_holds_and_stays_inside_its_limit() {
    for price in PRICES {
        let s = series(21, price);
        for pct in GRANT_PCT {
            let f = fund(
                &s,
                &FundCfg {
                    b0: 9.5e7,
                    price,
                    stable_limit: true,
                    grant_pct: pct,
                    ..FundCfg::default()
                },
            );
            assert!(f.conserved);
            assert!(f.b_final >= 0.0 && f.b_final <= 9.5e7);
            let paid: f64 = f
                .sponsor_tnzo_year
                .iter()
                .chain(f.grants_tnzo_year.iter())
                .sum();
            assert!((9.5e7 - f.b_final - paid).abs() < 1e-3);
        }
        for delay in DELAYS {
            let g = gov(
                &s,
                &GovCfg {
                    r0: 0.0,
                    b0: 9.5e7,
                    price,
                    delay,
                    buffer_days: 7,
                    tranche_days: 30,
                    grace: GRACE_DAYS,
                    statutory: true,
                },
            );
            assert!(
                g.max_cap_ratio <= PERIOD_CAP + 1e-9,
                "period limit exceeded: {}",
                g.max_cap_ratio
            );
        }
    }
}

#[test]
fn no_operator_is_paid_over_a_third_of_the_total() {
    let pay = [3.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0];
    let total: f64 = pay.iter().sum();
    let capped = cap_shares(&pay, 1.0 / 3.0);
    assert!(capped.iter().all(|p| *p <= total / 3.0 + 1e-9));
    assert!(capped.iter().sum::<f64>() <= total);
}

#[test]
fn a_wash_through_a_sponsored_validator_loses() {
    for fl in [0.0005, 0.0015, 0.011] {
        for sf in [0.0, 20.0, COST_DAY] {
            for v in [10.0, 1000.0, 1e6] {
                assert!(wash_net(v, fl, sf) < 0.0, "fl {fl} sf {sf} v {v}");
            }
        }
    }
}

#[test]
fn revocation_and_regions() {
    assert_eq!(revocation_lapse_days(7, 1, 7), 7);
    assert_eq!(revocation_lapse_days(9, 2, 7), 0);
    assert_eq!(revocation_lapse_days(9, 3, 7), 7);
    assert_eq!(region_halt_hours(4, 4, 6.0), 6.0);
    assert_eq!(region_halt_hours(5, 4, 6.0), 0.0);
}

#[test]
fn in_kind_operators_cut_the_treasury_cost_and_tenants_are_drawn_down_not_forfeited() {
    let s = series(7, 0.30);
    let none = &combos()[0];
    let ik = combos().into_iter().find(|c| c.id == "ik3").unwrap();
    let a = eval_combo(&s, none, 100, 0);
    let b = eval_combo(&s, &ik, 100, 0);
    assert!(b[5] <= a[5] * 4.0 / 7.0 + 1e-6);
    let t = combos()
        .into_iter()
        .find(|c| c.id == "t10/m2500/r0")
        .unwrap();
    let e = extra_inflow(&t, 100, 0);
    assert!(e.iter().all(|x| *x >= 0.0));
    // a no-usage launch: tenants pay nothing until usage starts
    assert_eq!(extra_inflow(&t, 100, 90)[10], 0.0);
}

/// The two break-even figures in circulation measure different things: one
/// credits each validator the stable fees the treasury kept, shared over the
/// active set; the other what the cover and the base reward paid it. Each
/// day either reports is one from which its own measure covers the cost in
/// every trailing 30 days, and it reports the paid usage of that window.
#[test]
fn each_break_even_holds_its_own_measure_from_the_day_it_reports() {
    let s = series(7, 0.30);
    let window = |t: usize, f: &dyn Fn(usize) -> f64| (t - 29..=t).map(f).sum::<f64>() / 30.0;
    let kept_each = |t: usize| s.kept[t] / s.active[t].max(1.0);
    let earned_each = |t: usize| s.earned[t];
    for (found, each) in [
        (breakeven_kept(&s), &kept_each as &dyn Fn(usize) -> f64),
        (breakeven_paid(&s), &earned_each as &dyn Fn(usize) -> f64),
    ] {
        if let (Some(day), usage) = found {
            for t in day..s.earned.len() {
                assert!(window(t, each) >= s.cost_day, "day {t}");
            }
            assert!((usage - window(day, &|t| s.paid[t])).abs() < 1e-6);
        }
    }
}
