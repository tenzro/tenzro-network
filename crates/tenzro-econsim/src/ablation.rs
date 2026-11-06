//! What each mechanism of the design contributes.
//!
//! Every mechanism is switched off one at a time against the full design,
//! on the same markets and seeds, and the change in validator cost
//! coverage, treasury runway, insurance coverage and the rate a cartel can
//! force is reported. A cartel sweep then runs the rate rule with and
//! without the quantile band across cartel sizes.

use serde::Serialize;

use crate::economy::{Ablation, Market, RunConfig};
use crate::gsa::{Metrics, run_all};

/// One ablation's figures, means over its runs, and their change from the
/// full design.
#[derive(Debug, Clone, Serialize)]
pub struct AblationRow {
    /// What was switched off.
    pub ablation: String,
    /// Runs behind the means.
    pub runs: usize,
    /// Mean share of validators covering their costs (last 90 days).
    pub validators_profitable: f64,
    /// Mean treasury runway at the end, months (capped at 1,200).
    pub treasury_runway_months: f64,
    /// Most a 52% cartel reporting ten times the price (or a pool held ten
    /// times up when the feed is the source) lifted the chain rate above
    /// both its level when the attack began and the unattacked rate.
    pub cartel_rate_ratio: f64,
    /// Changes from the full design, in the same units.
    pub d_validators_profitable: f64,
    /// Change in runway, months.
    pub d_treasury_runway_months: f64,
    /// Change in the cartel's rate ratio.
    pub d_cartel_rate_ratio: f64,
}

/// One point of the cartel sweep.
#[derive(Debug, Clone, Serialize)]
pub struct CartelPoint {
    /// Cartel share of bonded stake.
    pub stake_share: f64,
    /// Whether the quantile band was on.
    pub band: bool,
    /// Most the attack lifted the chain rate above both its level when the
    /// attack began and the unattacked rate.
    pub max_rate_ratio: f64,
    /// Days the chain rate sat more than 10% off the unattacked rate
    /// (held or moved).
    pub days_off: u32,
}

/// The ablation study.
#[derive(Debug, Clone, Serialize, Default)]
pub struct AblationStudy {
    /// Days per run.
    pub days: u32,
    /// Seeds per market.
    pub seeds: u64,
    /// One row per ablation, the full design first.
    pub rows: Vec<AblationRow>,
    /// The cartel sweep.
    pub cartel_sweep: Vec<CartelPoint>,
}

/// Validators at genesis in every run (the sweep's stake shares are of
/// these; the treasury's stake is spread evenly over them).
fn genesis_validators() -> u32 {
    crate::economy::Assumptions::default().validators
}

/// A cartel run: flat market, no outside trading, `n` validators reporting
/// `factor` times the price from day `from`.
fn cartel_cfg(ab: Ablation, n: u32, factor: f64, from: u32, days: u32) -> RunConfig {
    let mut c = RunConfig::scenario(Market::Flat, 900, from + days);
    c.assumptions.outside_flow_vol = 0.0;
    c.assumptions.governance_tracks_price = false;
    c.rate_reports = true;
    c.rate_cartel = Some((n, factor, from));
    c.ablation = ab;
    c
}

/// Worst ratio of the attacked chain rate to the same economy's rate with
/// no attack, from day `from`, and days it sat more than 10% off.
fn cartel_effect(
    o: &crate::economy::RunOutcome,
    base: &crate::economy::RunOutcome,
    from: u32,
) -> (f64, u32) {
    // Lift: above both where the rate stood when the attack began and
    // where honest reports alone took it. Held: off the honest rate.
    let start = o
        .days
        .get((from as usize).saturating_sub(1))
        .map_or(0.0, |d| d.chain_rate_usd);
    let mut worst: f64 = 1.0;
    let mut off = 0;
    for (d, b) in o.days.iter().zip(&base.days).skip(from as usize) {
        if (d.chain_rate_usd / b.chain_rate_usd.max(1e-12) - 1.0).abs() > 0.10 {
            off += 1;
        }
        let r = d.chain_rate_usd / b.chain_rate_usd.max(start).max(1e-12);
        if r > worst {
            worst = r;
        }
    }
    (worst, off)
}

fn mean(v: impl Iterator<Item = f64>) -> f64 {
    let (s, n) = v
        .filter(|x| x.is_finite())
        .fold((0.0, 0usize), |(s, n), x| (s + x, n + 1));
    if n == 0 { f64::NAN } else { s / n as f64 }
}

/// Runs every ablation on `markets` x `seeds` for `days`, a cartel run per
/// ablation over `cartel_days`, and the cartel sweep at `shares`.
pub fn study(
    markets: &[Market],
    seeds: u64,
    days: u32,
    cartel_days: u32,
    shares: &[f64],
    threads: usize,
) -> AblationStudy {
    let from = 5;
    let nv = genesis_validators();
    let cartel_n = ((0.52 * nv as f64).round() as u32).max(1);
    let mut cfgs = Vec::new();
    let mut keys = Vec::new();
    for ab in Ablation::ALL {
        for &m in markets {
            for s in 0..seeds {
                let mut c = RunConfig::scenario(m, 300 + s, days);
                c.ablation = ab;
                // The rate path under test is the validators' in every
                // run but the one that fixes fees in TNZO.
                c.rate_reports = true;
                cfgs.push(c);
                keys.push((ab, false));
            }
        }
        cfgs.push(cartel_cfg(ab, cartel_n, 10.0, from, cartel_days));
        keys.push((ab, true));
        cfgs.push(cartel_cfg(ab, 0, 1.0, from, cartel_days));
        keys.push((ab, true));
    }
    let outs = run_all(cfgs, threads);
    let mut rows: Vec<AblationRow> = Vec::new();
    for ab in Ablation::ALL {
        let runs: Vec<_> = outs
            .iter()
            .zip(&keys)
            .filter(|(_, k)| **k == (ab, false))
            .map(|(o, _)| Metrics::of(o))
            .collect();
        let pair: Vec<_> = outs
            .iter()
            .zip(&keys)
            .filter(|(_, k)| **k == (ab, true))
            .map(|(o, _)| o)
            .collect();
        let cartel = match pair.as_slice() {
            [attacked, honest] => cartel_effect(attacked, honest, from).0,
            _ => f64::NAN,
        };
        rows.push(AblationRow {
            ablation: ab.name().into(),
            runs: runs.len(),
            validators_profitable: mean(runs.iter().map(|m| m.validators_profitable)),
            treasury_runway_months: mean(
                runs.iter().map(|m| m.treasury_runway_months.min(1_200.0)),
            ),
            cartel_rate_ratio: cartel,
            d_validators_profitable: 0.0,
            d_treasury_runway_months: 0.0,
            d_cartel_rate_ratio: 0.0,
        });
    }
    if let Some(full) = rows.first().cloned() {
        for r in rows.iter_mut() {
            r.d_validators_profitable = r.validators_profitable - full.validators_profitable;
            r.d_treasury_runway_months = r.treasury_runway_months - full.treasury_runway_months;
            r.d_cartel_rate_ratio = r.cartel_rate_ratio - full.cartel_rate_ratio;
        }
    }
    // Cartel sweep, band on and off.
    let mut cfgs = Vec::new();
    let mut keys = Vec::new();
    for band in [true, false] {
        let ab = if band {
            Ablation::MedianOnly
        } else {
            Ablation::NoQuantileBand
        };
        cfgs.push(cartel_cfg(ab, 0, 1.0, from, cartel_days));
    }
    for &share in shares {
        let n = ((share * nv as f64).round() as u32).clamp(1, nv);
        for band in [true, false] {
            let ab = if band {
                Ablation::MedianOnly
            } else {
                Ablation::NoQuantileBand
            };
            cfgs.push(cartel_cfg(ab, n, 10.0, from, cartel_days));
            keys.push((n as f64 / nv as f64, band));
        }
    }
    let outs = run_all(cfgs, threads);
    let (bases, attacked) = outs.split_at(2);
    let cartel_sweep = attacked
        .iter()
        .zip(keys)
        .map(|(o, (stake_share, band))| {
            let base = if band { &bases[0] } else { &bases[1] };
            let (max_rate_ratio, days_off) = cartel_effect(o, base, from);
            CartelPoint {
                stake_share,
                band,
                max_rate_ratio,
                days_off,
            }
        })
        .collect();
    AblationStudy {
        days,
        seeds,
        rows,
        cartel_sweep,
    }
}

impl AblationStudy {
    /// The study as report sections.
    pub fn markdown(&self) -> String {
        let mut s = format!(
            "\n## What each mechanism contributes\n\nEach mechanism switched off alone against the full design; {} days, {} seeds per market, the validators' rate path in every run. Changes are from the full design.\n\n| switched off | runs | validators covering costs | change | treasury runway months | change | 52% cartel rate lift | change |\n|---|---|---|---|---|---|---|---|\n",
            self.days, self.seeds
        );
        for r in &self.rows {
            s.push_str(&format!(
                "| {} | {} | {:.2} | {:+.2} | {:.1} | {:+.1} | {:.2} | {:+.2} |\n",
                r.ablation,
                r.runs,
                r.validators_profitable,
                r.d_validators_profitable,
                r.treasury_runway_months,
                r.d_treasury_runway_months,
                r.cartel_rate_ratio,
                r.d_cartel_rate_ratio
            ));
        }
        s.push_str("\n### Cartel sweep: reports at ten times the price\n\n| cartel stake | quantile band | most lift above where it stood and the honest rate | days held or moved >10% off the honest rate |\n|---|---|---|---|\n");
        for p in &self.cartel_sweep {
            s.push_str(&format!(
                "| {:.0}% | {} | {:.2} | {} |\n",
                p.stake_share * 100.0,
                if p.band { "on" } else { "off" },
                p.max_rate_ratio,
                p.days_off
            ));
        }
        s
    }

    /// Issues for the verdict: a cartel under two thirds of stake that
    /// moves the rate with the band on.
    pub fn issues(&self) -> Vec<String> {
        self.cartel_sweep
            .iter()
            .filter(|p| p.band && p.stake_share < 0.66 && (p.max_rate_ratio - 1.0).abs() > 0.10)
            .map(|p| {
                format!(
                    "a {:.0}% cartel lifts the banded rate to {:.2}x where it stood",
                    p.stake_share * 100.0,
                    p.max_rate_ratio
                )
            })
            .collect()
    }
}
