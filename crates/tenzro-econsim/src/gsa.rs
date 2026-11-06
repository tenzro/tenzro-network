//! Global sensitivity analysis over governed parameters and behaviour
//! assumptions: a Morris screen over every factor, then variance-based
//! (Sobol) indices for the factors the screen ranks highest, and the range
//! of each key parameter where runs keep their invariants.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::Serialize;

use crate::economy::{Assumptions, Economy, Market, RunConfig, RunOutcome};

/// Where a factor lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// A governed network parameter, set at genesis.
    Param,
    /// A behaviour or cost assumption.
    Assumption,
}

/// One input the analysis varies.
#[derive(Debug, Clone, Serialize)]
pub struct Factor {
    /// Key or assumption name.
    pub name: String,
    /// Where it lives.
    pub source: Source,
    /// Lowest value swept.
    pub lo: f64,
    /// Highest value swept.
    pub hi: f64,
    /// Swept on a log scale.
    pub log: bool,
}

impl Factor {
    /// The value at unit coordinate `u`.
    pub fn at(&self, u: f64) -> f64 {
        if self.log && self.lo > 0.0 {
            (self.lo.ln() + u * (self.hi.ln() - self.lo.ln())).exp()
        } else {
            self.lo + u * (self.hi - self.lo)
        }
    }
}

/// Governed parameters with an economic effect the analysis sweeps.
pub const ECONOMIC_PARAMS: &[&str] = &[
    "fees.settlement_fee_bps",
    "fees.settlement_fee_burn_bps",
    "fees.activity_reward_fee_bps",
    "fees.insurance_pool_bps",
    "fees.min_settlement_fee_micro_usd",
    "fees.min_base_fee",
    "fees.usd_rate_max_change_bps",
    "fees.validator_burn_share_bps",
    "validator.base_cap_tnzo_month",
    "mint.base_tnzo_per_year",
    "compute_bond.var_ratio_bps",
    "insurance.max_claim_bps",
    "insurance.max_claim_tnzo",
    "sla.unavailable.penalty_gwei",
    "compute_bond.min_tnzo",
    "stake.validator_tnzo",
    "rewards.claim_liquid_bps",
    "governance.quorum_bps",
];

/// The factor set: each governed parameter from a tenth to ten times its
/// genesis value, inside its registry bounds (bps parameters across their
/// whole bound), and each assumption across its stated range.
pub fn factors() -> Vec<Factor> {
    let mut out = Vec::new();
    for key in ECONOMIC_PARAMS {
        let Some(p) = tenzro_vm::governance::governed_param(key) else {
            continue;
        };
        let g = p.genesis.max(1) as f64;
        let bps = key.ends_with("_bps");
        let (lo, hi, log) = if bps {
            (p.min as f64, p.max as f64, false)
        } else {
            (
                (g / 10.0).max(p.min as f64),
                (g * 10.0).min(p.max as f64),
                true,
            )
        };
        if hi > lo {
            out.push(Factor {
                name: key.to_string(),
                source: Source::Param,
                lo,
                hi,
                log,
            });
        }
    }
    for (name, lo, hi) in Assumptions::ranges() {
        out.push(Factor {
            name: name.into(),
            source: Source::Assumption,
            lo,
            hi,
            log: hi / lo.max(1e-9) > 20.0 && lo > 0.0,
        });
    }
    out
}

/// Scalar outputs of one run the analysis reads.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Metrics {
    /// Months of grants the treasury holds at the end.
    pub treasury_runway_months: f64,
    /// Mean share of validators covering their costs over the last 90 days.
    pub validators_profitable: f64,
    /// Bonded validators at the end.
    pub validators_end: f64,
    /// Staking ratio at the end.
    pub staking_ratio: f64,
    /// Insurance pool at the end, TNZO.
    pub insurance_pool: f64,
    /// Insurance claims refused because the pool was empty or capped out.
    pub claims_refused: f64,
    /// Mean human transfer fee, USD.
    pub human_fee_usd: f64,
    /// Share of supply burned over the run.
    pub burned_share: f64,
    /// Blocks the ledger refused or whose duties failed.
    pub ledger_failures: f64,
    /// Share of providers covering their costs at the end.
    pub providers_profitable: f64,
}

impl Metrics {
    /// From a run.
    pub fn of(o: &RunOutcome) -> Self {
        let last = o.days.last().cloned().unwrap_or_default();
        let tail: Vec<_> = o.days.iter().rev().take(90).collect();
        let vp =
            tail.iter().map(|d| d.validators_profitable).sum::<f64>() / tail.len().max(1) as f64;
        let fee = o
            .days
            .iter()
            .map(|d| d.human_fee_tnzo * d.price_usd)
            .sum::<f64>()
            / o.days.len().max(1) as f64;
        let refused = o
            .refusals
            .iter()
            .filter(|(k, _)| k.starts_with("insurance claim"))
            .map(|(_, v)| *v as f64)
            .sum();
        let first_supply = o
            .days
            .first()
            .map(|d| d.snap.supply + d.snap.burned)
            .unwrap_or(1.0);
        Self {
            treasury_runway_months: last.treasury_runway_months.min(1_200.0),
            validators_profitable: vp,
            validators_end: last.snap.bonded_validators as f64,
            staking_ratio: last.staking_ratio,
            insurance_pool: last.snap.insurance_pool,
            claims_refused: refused,
            human_fee_usd: fee,
            burned_share: last.snap.burned / first_supply.max(1.0),
            ledger_failures: o.ledger_failures.len() as f64,
            providers_profitable: last.providers_profitable,
        }
    }

    /// Named values, in a fixed order.
    pub fn named(&self) -> Vec<(&'static str, f64)> {
        vec![
            ("treasury_runway_months", self.treasury_runway_months),
            ("validators_profitable", self.validators_profitable),
            ("validators_end", self.validators_end),
            ("staking_ratio", self.staking_ratio),
            ("insurance_pool", self.insurance_pool),
            ("claims_refused", self.claims_refused),
            ("human_fee_usd", self.human_fee_usd),
            ("burned_share", self.burned_share),
            ("ledger_failures", self.ledger_failures),
            ("providers_profitable", self.providers_profitable),
        ]
    }

    /// The invariants a sound economy keeps; each failing one is named.
    pub fn failures(&self) -> Vec<&'static str> {
        let mut f = Vec::new();
        if self.ledger_failures > 0.0 {
            f.push("ledger refused a block");
        }
        if self.treasury_runway_months < 12.0 {
            f.push("treasury runway under 12 months");
        }
        if self.validators_profitable < 0.5 {
            f.push("fewer than half the validators cover their costs");
        }
        if self.validators_end < 4.0 {
            f.push("fewer than 4 validators remain bonded");
        }
        if self.claims_refused > 0.0 {
            f.push("honest insurance claims refused");
        }
        if self.human_fee_usd > 0.01 {
            f.push("a transfer costs more than one cent");
        }
        f
    }
}

/// Runs a set of configurations on `threads` threads, in input order.
pub fn run_all(cfgs: Vec<RunConfig>, threads: usize) -> Vec<RunOutcome> {
    let n = cfgs.len();
    let next = AtomicUsize::new(0);
    let out: Mutex<Vec<Option<RunOutcome>>> = Mutex::new(vec![None; n]);
    let cfgs = &cfgs;
    std::thread::scope(|s| {
        for _ in 0..threads.max(1) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    if i >= n {
                        break;
                    }
                    let o = Economy::new(cfgs[i].clone()).run();
                    out.lock().expect("results lock")[i] = Some(o);
                }
            });
        }
    });
    out.into_inner()
        .expect("results")
        .into_iter()
        .map(|o| o.expect("every run finished"))
        .collect()
}

/// A configuration at unit point `x` over `factors`.
pub fn config_at(base: &RunConfig, factors: &[Factor], x: &[f64]) -> RunConfig {
    let mut c = base.clone();
    for (f, u) in factors.iter().zip(x) {
        let v = f.at(*u);
        match f.source {
            Source::Param => {
                c.network_params
                    .insert(f.name.clone(), v.round().max(0.0) as u64);
            }
            Source::Assumption => c.assumptions.set(&f.name, v),
        }
    }
    c
}

/// Morris screen result for one factor and one output.
#[derive(Debug, Clone, Serialize)]
pub struct MorrisIndex {
    /// Factor.
    pub factor: String,
    /// Output.
    pub output: String,
    /// Mean absolute elementary effect.
    pub mu_star: f64,
    /// Standard deviation of the elementary effects.
    pub sigma: f64,
}

/// Sobol indices for one factor and one output.
#[derive(Debug, Clone, Serialize)]
pub struct SobolIndex {
    /// Factor.
    pub factor: String,
    /// Output.
    pub output: String,
    /// First-order index.
    pub first: f64,
    /// Total-order index.
    pub total: f64,
}

/// One evaluated point: unit coordinates, factor values and its metrics.
#[derive(Debug, Clone, Serialize)]
pub struct Point {
    /// Unit coordinates.
    pub x: Vec<f64>,
    /// Metrics.
    pub m: Metrics,
}

/// Everything the analysis produced.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Analysis {
    /// The factors.
    pub factors: Vec<Factor>,
    /// Morris indices.
    pub morris: Vec<MorrisIndex>,
    /// Sobol indices for the screened factors.
    pub sobol: Vec<SobolIndex>,
    /// Factors carried into the Sobol stage.
    pub screened: Vec<String>,
    /// Every evaluated point.
    pub points: Vec<Point>,
    /// Range of each key parameter where runs keep every invariant.
    pub safe_ranges: Vec<SafeRange>,
    /// Runs executed.
    pub runs: usize,
}

/// A parameter's range where the failure rate stays under the bound.
#[derive(Debug, Clone, Serialize)]
pub struct SafeRange {
    /// Factor.
    pub factor: String,
    /// Lowest safe value seen.
    pub lo: Option<f64>,
    /// Highest safe value seen.
    pub hi: Option<f64>,
    /// Failure rate per decile of the swept range.
    pub failure_by_decile: Vec<f64>,
    /// Points per decile.
    pub points_by_decile: Vec<usize>,
    /// Genesis value, for parameters.
    pub genesis: Option<f64>,
}

/// Runs the Morris screen (`r` trajectories over 4 levels), then Sobol
/// indices on the top `k` factors with `n` base samples.
#[allow(clippy::needless_range_loop)] // o indexes the named outputs of every model run
pub fn analyse(
    base: &RunConfig,
    r: usize,
    k: usize,
    n: usize,
    threads: usize,
    seed: u64,
) -> Analysis {
    let fs = factors();
    let d = fs.len();
    let mut rng = StdRng::seed_from_u64(seed);
    // Morris trajectories on a 4-level grid, step 2/3.
    let levels = [0.0, 1.0 / 3.0, 2.0 / 3.0, 1.0];
    let delta = 2.0 / 3.0;
    let mut traj: Vec<(Vec<Vec<f64>>, Vec<usize>)> = Vec::new();
    for _ in 0..r {
        let mut x: Vec<f64> = (0..d).map(|_| levels[rng.gen_range(0..2)]).collect();
        let mut order: Vec<usize> = (0..d).collect();
        for i in (1..d).rev() {
            order.swap(i, rng.gen_range(0..=i));
        }
        let mut pts = vec![x.clone()];
        for &i in &order {
            x[i] = if x[i] + delta <= 1.0 + 1e-9 {
                x[i] + delta
            } else {
                x[i] - delta
            };
            pts.push(x.clone());
        }
        traj.push((pts, order));
    }
    let mut cfgs = Vec::new();
    for (pts, _) in &traj {
        for (j, x) in pts.iter().enumerate() {
            let mut c = config_at(base, &fs, x);
            c.seed = base.seed.wrapping_add(j as u64);
            cfgs.push(c);
        }
    }
    let outs = run_all(cfgs, threads);
    let mut points = Vec::new();
    let mut idx = 0;
    let names: Vec<&'static str> = Metrics::default().named().iter().map(|(n, _)| *n).collect();
    let mut ee: BTreeMap<(usize, usize), Vec<f64>> = BTreeMap::new();
    for (pts, order) in &traj {
        let ms: Vec<Metrics> = (0..pts.len())
            .map(|j| Metrics::of(&outs[idx + j]))
            .collect();
        for (j, x) in pts.iter().enumerate() {
            points.push(Point {
                x: x.clone(),
                m: ms[j].clone(),
            });
        }
        for (step, &i) in order.iter().enumerate() {
            let dir = pts[step + 1][i] - pts[step][i];
            let y0 = ms[step].named();
            let y1 = ms[step + 1].named();
            for o in 0..names.len() {
                let e = (y1[o].1 - y0[o].1) / dir;
                ee.entry((i, o)).or_default().push(e);
            }
        }
        idx += pts.len();
    }
    let mut morris = Vec::new();
    for ((i, o), v) in &ee {
        let m = v.iter().map(|x| x.abs()).sum::<f64>() / v.len() as f64;
        let mean = v.iter().sum::<f64>() / v.len() as f64;
        let s = (v.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / v.len().max(2) as f64).sqrt();
        morris.push(MorrisIndex {
            factor: fs[*i].name.clone(),
            output: names[*o].into(),
            mu_star: m,
            sigma: s,
        });
    }
    // Rank factors by their largest normalised mu* across outputs.
    let mut scale = vec![0.0f64; names.len()];
    for m in &morris {
        let o = names.iter().position(|n| *n == m.output).expect("output");
        scale[o] = scale[o].max(m.mu_star);
    }
    let mut rank = vec![0.0f64; d];
    for m in &morris {
        let o = names.iter().position(|n| *n == m.output).expect("output");
        let i = fs.iter().position(|f| f.name == m.factor).expect("factor");
        if scale[o] > 0.0 {
            rank[i] = rank[i].max(m.mu_star / scale[o]);
        }
    }
    let mut order: Vec<usize> = (0..d).collect();
    order.sort_by(|a, b| {
        rank[*b]
            .partial_cmp(&rank[*a])
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let top: Vec<usize> = order.into_iter().take(k.min(d)).collect();
    // Sobol on the top factors; the others stay at their mid-range.
    let mut sobol = Vec::new();
    if n > 0 && !top.is_empty() {
        let kk = top.len();
        let a: Vec<Vec<f64>> = (0..n)
            .map(|_| (0..kk).map(|_| rng.gen_range(0.0..1.0)).collect())
            .collect();
        let b: Vec<Vec<f64>> = (0..n)
            .map(|_| (0..kk).map(|_| rng.gen_range(0.0..1.0)).collect())
            .collect();
        let full = |sub: &[f64]| -> Vec<f64> {
            let mut x = vec![0.5; d];
            for (j, &i) in top.iter().enumerate() {
                x[i] = sub[j];
            }
            x
        };
        let mut xs: Vec<Vec<f64>> = Vec::new();
        for row in &a {
            xs.push(full(row));
        }
        for row in &b {
            xs.push(full(row));
        }
        for j in 0..kk {
            for s in 0..n {
                let mut row = a[s].clone();
                row[j] = b[s][j];
                xs.push(full(&row));
            }
        }
        let cfgs: Vec<RunConfig> = xs
            .iter()
            .enumerate()
            .map(|(i, x)| {
                let mut c = config_at(base, &fs, x);
                c.seed = base.seed.wrapping_add(1_000 + (i % n) as u64);
                c
            })
            .collect();
        let outs = run_all(cfgs, threads);
        let ms: Vec<Metrics> = outs.iter().map(Metrics::of).collect();
        for (x, m) in xs.iter().zip(&ms) {
            points.push(Point {
                x: x.clone(),
                m: m.clone(),
            });
        }
        for o in 0..names.len() {
            let y = |i: usize| ms[i].named()[o].1;
            let fa: Vec<f64> = (0..n).map(y).collect();
            let fb: Vec<f64> = (0..n).map(|s| y(n + s)).collect();
            let all: Vec<f64> = fa.iter().chain(&fb).copied().collect();
            let mean = all.iter().sum::<f64>() / all.len() as f64;
            let var = all.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / all.len() as f64;
            for j in 0..kk {
                let fab: Vec<f64> = (0..n).map(|s| y(2 * n + j * n + s)).collect();
                let (first, total) = if var > 0.0 {
                    let s1 = (0..n).map(|s| fb[s] * (fab[s] - fa[s])).sum::<f64>() / n as f64 / var;
                    let st = (0..n).map(|s| (fa[s] - fab[s]).powi(2)).sum::<f64>()
                        / (2.0 * n as f64)
                        / var;
                    (s1, st)
                } else {
                    (0.0, 0.0)
                };
                sobol.push(SobolIndex {
                    factor: fs[top[j]].name.clone(),
                    output: names[o].into(),
                    first,
                    total,
                });
            }
        }
    }
    let safe_ranges = safe_ranges(&fs, &points);
    Analysis {
        screened: top.iter().map(|i| fs[*i].name.clone()).collect(),
        factors: fs,
        morris,
        sobol,
        runs: points.len(),
        points,
        safe_ranges,
    }
}

/// Failure rate per decile of each parameter, and the widest run of deciles
/// at or under one failure in ten.
pub fn safe_ranges(fs: &[Factor], points: &[Point]) -> Vec<SafeRange> {
    let mut out = Vec::new();
    for (i, f) in fs.iter().enumerate() {
        if f.source != Source::Param {
            continue;
        }
        let mut fails = [0usize; 10];
        let mut count = [0usize; 10];
        for p in points {
            let b = ((p.x[i] * 10.0) as usize).min(9);
            count[b] += 1;
            if !p.m.failures().is_empty() {
                fails[b] += 1;
            }
        }
        let rate: Vec<f64> = (0..10)
            .map(|b| {
                if count[b] == 0 {
                    f64::NAN
                } else {
                    fails[b] as f64 / count[b] as f64
                }
            })
            .collect();
        let ok: Vec<bool> = rate.iter().map(|r| r.is_finite() && *r <= 0.1).collect();
        let mut best = (0usize, 0usize, 0usize);
        let mut s = 0;
        while s < 10 {
            if ok[s] {
                let mut e = s;
                while e + 1 < 10 && ok[e + 1] {
                    e += 1;
                }
                if e - s + 1 > best.2 {
                    best = (s, e, e - s + 1);
                }
                s = e + 1;
            } else {
                s += 1;
            }
        }
        let (lo, hi) = if best.2 > 0 {
            (
                Some(f.at(best.0 as f64 / 10.0)),
                Some(f.at((best.1 + 1) as f64 / 10.0)),
            )
        } else {
            (None, None)
        };
        out.push(SafeRange {
            factor: f.name.clone(),
            lo,
            hi,
            failure_by_decile: rate,
            points_by_decile: count.to_vec(),
            genesis: tenzro_vm::governance::governed_param(&f.name).map(|p| p.genesis as f64),
        });
    }
    out
}

/// The base configuration of the analysis: the downturn market over
/// `days`, since a parameter set that survives the downturn survives the
/// others.
pub fn base(days: u32, seed: u64) -> RunConfig {
    RunConfig::scenario(Market::Downturn, seed, days)
}
