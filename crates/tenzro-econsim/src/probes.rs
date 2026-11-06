//! Bounded probes of rules a coalition of participants could lean on, each
//! run beside a same-seed baseline and judged by a stated bound.
//!
//! ```text
//! tenzro-econsim probes [--days D] [--seed S] [--threads N]
//! ```
//!
//! Prints one `PASS probe ...` or `FAIL probe ...` line per cell and a JSON
//! summary; exits 1 when a gated cell fails.

use serde::Serialize;

use crate::attack::{Adversary, AttackOutcome};
use crate::economy::{Market, RunConfig, RunOutcome};

/// One probe cell and its verdict.
#[derive(Debug, Clone, Serialize)]
pub struct ProbeResult {
    /// Cell name.
    pub name: String,
    /// Whether the verdict gates the run (false: recorded only).
    pub gated: bool,
    /// Whether the bound held.
    pub held: bool,
    /// The measured figure the bound is on.
    pub measured: f64,
    /// The same figure in the same-seed run without the coalition.
    pub baseline: f64,
    /// The bound.
    pub bound: f64,
    /// The coalition's share of bonded stake.
    pub stake_share: f64,
    /// Detail of the run.
    pub outcome: Option<AttackOutcome>,
}

fn rate_config(seed: u64, days: u32) -> RunConfig {
    let mut c = RunConfig::scenario(Market::Flat, seed, days);
    c.rate_reports = true;
    c.network_params.insert("fees.usd_rate_mode".into(), 1);
    c
}

fn worst_deviation(o: &RunOutcome, from_day: f64) -> f64 {
    o.days
        .iter()
        .filter(|d| d.snap.day >= from_day && d.fair_price_usd > 0.0 && d.chain_rate_usd > 0.0)
        .map(|d| (d.chain_rate_usd / d.fair_price_usd - 1.0).abs())
        .fold(0.0, f64::max)
}

/// The rate-report cells: a coalition reporting one clamp step below the
/// rate in force every epoch, at stake shares below a third, between a
/// third and a half, and just under a half; and one withholding its
/// reports across a price shock.
pub fn rate_cells(seed: u64, days: u32, threads: usize) -> Vec<ProbeResult> {
    let validators = crate::economy::Assumptions::default().validators;
    let start_day = 3;
    let run_days = days.saturating_sub(start_day);
    let walk = |cartel: u32| Adversary::RateWalk {
        start_day,
        run_days,
        cartel,
        step_bps: 100,
        withhold: false,
    };
    // A third of the committee may neither hold nor move the rate: gated.
    // One more, and the largest coalition below half, can slow it, the price
    // of no group short of two thirds being able to move it: recorded, not
    // gated.
    let third = validators / 3;
    let below_half = (validators - 1) / 2;
    let mut cells: Vec<(String, Option<Adversary>, bool, Option<(u32, f64)>)> = vec![
        ("baseline".into(), None, false, None),
        (
            format!("rate-walk cartel={third}"),
            Some(walk(third)),
            true,
            None,
        ),
        (
            format!("rate-walk cartel={}", third + 1),
            Some(walk(third + 1)),
            false,
            None,
        ),
        (
            format!("rate-walk cartel={below_half}"),
            Some(walk(below_half)),
            false,
            None,
        ),
        ("baseline+shock".into(), None, false, Some((5, 2.0))),
    ];
    let withhold = |cartel: u32| Adversary::RateWalk {
        start_day,
        run_days,
        cartel,
        step_bps: 0,
        withhold: true,
    };
    cells.push((
        format!("rate-withhold cartel={third} shock x2 day 5"),
        Some(withhold(third)),
        false,
        Some((5, 2.0)),
    ));
    cells.push((
        format!("rate-withhold cartel={} shock x2 day 5", third + 1),
        Some(withhold(third + 1)),
        false,
        Some((5, 2.0)),
    ));
    let cfgs: Vec<RunConfig> = cells
        .iter()
        .map(|(_, adv, _, shock)| {
            let mut c = rate_config(seed, days);
            c.adversary = adv.clone();
            c.shock = *shock;
            c
        })
        .collect();
    let outs = crate::gsa::run_all(cfgs, threads);
    let base = worst_deviation(&outs[0], start_day as f64);
    let base_shock = worst_deviation(&outs[4], start_day as f64);
    let mut res = Vec::new();
    for ((name, adv, gated, shock), o) in cells.into_iter().zip(outs) {
        let Some(_) = adv else { continue };
        let measured = worst_deviation(&o, start_day as f64);
        let baseline = if shock.is_some() { base_shock } else { base };
        let stake_share = o
            .adversary
            .as_ref()
            .and_then(|a| a.detail.get("cartel_stake_share").copied())
            .unwrap_or(0.0);
        // Below half the stake a coalition may not hold the rate in force
        // more than five points further from the market than the
        // same-seed run without it.
        let bound = baseline + 0.05;
        res.push(ProbeResult {
            name,
            gated: gated && stake_share < 0.5,
            held: measured <= bound,
            measured,
            baseline,
            bound,
            stake_share,
            outcome: o.adversary,
        });
    }
    res
}

/// The treasury outflow cells: many grants just under the large-spend line
/// enacted in two batches inside one outflow period and across its end, and
/// three large spends just under the per-proposal cap, together over the
/// period cap, enacted in one block. Each is
/// judged by the treasury's period rule replayed over what was paid.
pub fn treasury_cells(seed: u64, threads: usize) -> Vec<ProbeResult> {
    let small = |second: f64| Adversary::SalamiGrants {
        open_day: 8,
        attackers: 15,
        grants: 60,
        grant_tnzo: 99_999.0,
        enact_day: 14.0,
        second_enact_day: second,
    };
    let cells: Vec<(String, Adversary, u32)> = vec![
        (
            "salami-grants second batch inside the period".into(),
            small(20.95),
            24,
        ),
        (
            "salami-grants second batch after the period".into(),
            small(21.05),
            24,
        ),
        (
            "large-spend grants enacted in one block".into(),
            Adversary::SalamiGrants {
                open_day: 8,
                attackers: 15,
                grants: 3,
                grant_tnzo: 900_000.0,
                enact_day: 25.6,
                second_enact_day: 25.6,
            },
            28,
        ),
    ];
    let cfgs: Vec<RunConfig> = cells
        .iter()
        .map(|(_, adv, days)| {
            let mut c = RunConfig::scenario(Market::Flat, seed, *days);
            c.assumptions.set("treasury_genesis_tnzo", 50_000_000.0);
            c.adversary = Some(adv.clone());
            c
        })
        .collect();
    let outs = crate::gsa::run_all(cfgs, threads);
    cells
        .into_iter()
        .zip(outs)
        .map(|((name, _, _), o)| {
            let get = |k: &str| {
                o.adversary
                    .as_ref()
                    .and_then(|a| a.detail.get(k).copied())
                    .unwrap_or(0.0)
            };
            let measured = get("worst_period_paid_over_cap");
            ProbeResult {
                name: format!("{name} ({} paid)", get("grants_paid")),
                gated: true,
                held: measured <= 1.001,
                measured,
                baseline: 0.0,
                bound: 1.001,
                stake_share: 15.0 / 21.0,
                outcome: o.adversary,
            }
        })
        .collect()
}
