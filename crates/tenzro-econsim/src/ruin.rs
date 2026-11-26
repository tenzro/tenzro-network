//! Ruin of the running-cost reserve over a long horizon.
//!
//! The cover reserve pays the active set's running cost every month and is
//! refilled by its share of the fees. Everything is counted in months of
//! running cost, so the result holds at any cost level. Fee inflow follows
//! a Markov chain of regimes (normal, slump, boom); within a month it is
//! lognormal around the regime's level. Ruin is the reserve falling below
//! zero at any month of the horizon.
//!
//! The loading is how much the long-run mean inflow exceeds the cost: a
//! loading of 0.2 means fees bring in 1.2 months of cost per month on
//! average. The minimal loading is the smallest one whose ruin probability
//! over the horizon is at most the target. Every loading is run on the same
//! random draws, so the probability falls monotonically as the loading
//! rises and a bisection finds the minimal one.
//!
//! The reserve starts at the governed target (`validator.stable_cover_target_months`).
//! Results hold only for the regimes and inputs swept here.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::Serialize;
use tenzro_vm::governance::genesis_param;
use tenzro_vm::native::validator_cover as vc;

/// One inflow regime.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Regime {
    /// Name in the table.
    pub name: &'static str,
    /// Inflow level relative to the others; normalised so the long-run mean
    /// inflow is one month of cost times one plus the loading.
    pub level: f64,
    /// Monthly volatility of the inflow (lognormal sigma).
    pub sigma: f64,
    /// Probability of staying in the regime from one month to the next.
    pub stay: f64,
}

/// Inputs of one ruin study.
#[derive(Debug, Clone, Serialize)]
pub struct Inputs {
    /// Name in the table.
    pub name: String,
    /// Reserve at the start, months of cost.
    pub reserve_months: f64,
    /// Horizon, months.
    pub horizon_months: u32,
    /// Paths simulated.
    pub paths: u32,
    /// Seed of the draws.
    pub seed: u64,
    /// Ruin probability the minimal loading must reach.
    pub target: f64,
    /// The regimes; a regime leaves to each of the others with equal chance.
    pub regimes: Vec<Regime>,
}

impl Inputs {
    /// Normal, slump and boom regimes over 30 years from the governed
    /// reserve target, with a 1% ruin target.
    pub fn base() -> Self {
        Self {
            name: "base".into(),
            reserve_months: genesis_param(vc::TARGET_MONTHS_PARAM) as f64,
            horizon_months: 360,
            paths: 10_000,
            seed: 1,
            target: 0.01,
            regimes: vec![
                Regime {
                    name: "normal",
                    level: 1.0,
                    sigma: 0.25,
                    stay: 0.95,
                },
                Regime {
                    name: "slump",
                    level: 0.3,
                    sigma: 0.4,
                    stay: 0.85,
                },
                Regime {
                    name: "boom",
                    level: 1.8,
                    sigma: 0.3,
                    stay: 0.8,
                },
            ],
        }
    }
}

/// Long-run share of months spent in each regime.
pub fn stationary(regimes: &[Regime]) -> Vec<f64> {
    let n = regimes.len();
    let mut pi = vec![1.0 / n as f64; n];
    for _ in 0..10_000 {
        let mut next = vec![0.0; n];
        for (i, r) in regimes.iter().enumerate() {
            next[i] += pi[i] * r.stay;
            let leave = if n > 1 {
                (1.0 - r.stay) / (n - 1) as f64
            } else {
                0.0
            };
            for (j, x) in next.iter_mut().enumerate() {
                if j != i {
                    *x += pi[i] * leave;
                }
            }
        }
        pi = next;
    }
    pi
}

/// The random draws of one path: per month a regime-switch uniform and a
/// standard normal.
struct Path {
    switch: Vec<f64>,
    z: Vec<f64>,
}

fn draw(inputs: &Inputs) -> Vec<Path> {
    let mut rng = StdRng::seed_from_u64(inputs.seed);
    let m = inputs.horizon_months as usize;
    (0..inputs.paths)
        .map(|_| {
            let switch = (0..m).map(|_| rng.gen_range(0.0..1.0)).collect();
            let z = (0..m)
                .map(|_| {
                    // Box-Muller.
                    let u1: f64 = rng.gen_range(f64::MIN_POSITIVE..1.0);
                    let u2: f64 = rng.gen_range(0.0..1.0);
                    (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
                })
                .collect();
            Path { switch, z }
        })
        .collect()
}

/// What one loading measured.
#[derive(Debug, Clone, Serialize)]
pub struct Outcome {
    /// Loading run.
    pub loading: f64,
    /// Share of paths ruined within the horizon.
    pub ruin_probability: f64,
    /// Median month of ruin among ruined paths.
    pub median_ruin_month: Option<u32>,
    /// Fifth percentile of the reserve at the end among surviving paths,
    /// months of cost.
    pub p5_end_reserve_months: Option<f64>,
}

fn simulate(inputs: &Inputs, paths: &[Path], loading: f64) -> Outcome {
    let pi = stationary(&inputs.regimes);
    let mean_level: f64 = inputs
        .regimes
        .iter()
        .zip(&pi)
        .map(|(r, p)| r.level * p)
        .sum();
    let scale = (1.0 + loading) / mean_level.max(f64::MIN_POSITIVE);
    let n = inputs.regimes.len();
    let mut ruin_months = Vec::new();
    let mut ends = Vec::new();
    for path in paths {
        let mut regime = 0usize;
        let mut reserve = inputs.reserve_months;
        let mut ruined = None;
        for (month, (&u, &z)) in path.switch.iter().zip(&path.z).enumerate() {
            let r = &inputs.regimes[regime];
            if n > 1 && u >= r.stay {
                // Leave to one of the others, chosen by where u fell.
                let k = (((u - r.stay) / (1.0 - r.stay)) * (n - 1) as f64) as usize;
                let k = k.min(n - 2);
                regime = if k >= regime { k + 1 } else { k };
            }
            let r = &inputs.regimes[regime];
            let inflow = scale * r.level * (r.sigma * z - r.sigma * r.sigma / 2.0).exp();
            reserve += inflow - 1.0;
            if reserve < 0.0 {
                ruined = Some(month as u32 + 1);
                break;
            }
        }
        match ruined {
            Some(m) => ruin_months.push(m),
            None => ends.push(reserve),
        }
    }
    ruin_months.sort_unstable();
    ends.sort_by(f64::total_cmp);
    Outcome {
        loading,
        ruin_probability: ruin_months.len() as f64 / paths.len().max(1) as f64,
        median_ruin_month: ruin_months.get(ruin_months.len() / 2).copied(),
        p5_end_reserve_months: ends.get(ends.len() / 20).copied(),
    }
}

/// Ruin probability and its details at one loading.
pub fn at_loading(inputs: &Inputs, loading: f64) -> Outcome {
    simulate(inputs, &draw(inputs), loading)
}

/// One row of the study.
#[derive(Debug, Clone, Serialize)]
pub struct Row {
    /// The inputs.
    pub inputs: Inputs,
    /// Smallest loading whose ruin probability is at most the target,
    /// within 0.001; `None` if even a loading of 5 does not reach it.
    pub minimal_loading: Option<f64>,
    /// The outcome at that loading.
    pub at_minimal: Option<Outcome>,
    /// The outcome with fees exactly covering cost on average.
    pub at_zero: Outcome,
}

/// Bisects for the minimal loading on one set of draws.
pub fn study(inputs: &Inputs) -> Row {
    let paths = draw(inputs);
    let ok = |l: f64| simulate(inputs, &paths, l).ruin_probability <= inputs.target;
    let (mut lo, mut hi) = (-0.5, 5.0);
    let minimal = if ok(lo) {
        Some(lo)
    } else if !ok(hi) {
        None
    } else {
        while hi - lo > 1e-3 {
            let mid = (lo + hi) / 2.0;
            if ok(mid) {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        Some(hi)
    };
    Row {
        inputs: inputs.clone(),
        minimal_loading: minimal,
        at_minimal: minimal.map(|l| simulate(inputs, &paths, l)),
        at_zero: simulate(inputs, &paths, 0.0),
    }
}

/// The cases swept: the base regimes from the governed target, from an
/// empty reserve and from two years; longer slumps; and calm fees.
pub fn cases(horizon_months: u32, paths: u32, seed: u64) -> Vec<Inputs> {
    let base = Inputs {
        horizon_months,
        paths,
        seed,
        ..Inputs::base()
    };
    let mut out = vec![base.clone()];
    for months in [0.0, 24.0] {
        out.push(Inputs {
            name: format!("reserve {months:.0} months"),
            reserve_months: months,
            ..base.clone()
        });
    }
    let mut long_slump = base.clone();
    long_slump.name = "slumps last twice as long".into();
    long_slump.regimes[1].stay = 1.0 - (1.0 - long_slump.regimes[1].stay) / 2.0;
    out.push(long_slump);
    let mut calm = base.clone();
    calm.name = "one calm regime".into();
    calm.regimes.truncate(1);
    calm.regimes[0].sigma = 0.1;
    out.push(calm);
    out
}

/// Runs every case.
pub fn sweep(horizon_months: u32, paths: u32, seed: u64) -> Vec<Row> {
    cases(horizon_months, paths, seed)
        .iter()
        .map(study)
        .collect()
}

/// The study as a markdown table.
pub fn table(rows: &[Row]) -> String {
    let mut s = String::from(
        "| case | start reserve, months | horizon, years | ruin at loading 0 | minimal loading for ruin <= target | target | median month of ruin there | p5 end reserve there, months |\n|---|---|---|---|---|---|---|---|\n",
    );
    for r in rows {
        let m = r.at_minimal.as_ref();
        s.push_str(&format!(
            "| {} | {:.1} | {:.0} | {:.4} | {} | {} | {} | {} |\n",
            r.inputs.name,
            r.inputs.reserve_months,
            r.inputs.horizon_months as f64 / 12.0,
            r.at_zero.ruin_probability,
            r.minimal_loading
                .map_or("over 5".into(), |l| format!("{l:.3}")),
            r.inputs.target,
            m.and_then(|o| o.median_ruin_month)
                .map_or("-".into(), |x| x.to_string()),
            m.and_then(|o| o.p5_end_reserve_months)
                .map_or("-".into(), |x| format!("{x:.1}")),
        ));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn short() -> Inputs {
        Inputs {
            reserve_months: 3.0,
            horizon_months: 24,
            paths: 2_000,
            ..Inputs::base()
        }
    }

    #[test]
    fn the_stationary_shares_sum_to_one_and_hold_still() {
        let r = Inputs::base().regimes;
        let pi = stationary(&r);
        assert!((pi.iter().sum::<f64>() - 1.0).abs() < 1e-9);
        // The slump is the stickiest regime after normal, so it holds more
        // months than the boom.
        assert!(pi[0] > pi[1] && pi[1] > pi[2]);
    }

    #[test]
    fn ruin_falls_as_the_loading_rises() {
        let i = short();
        let paths = draw(&i);
        let p: Vec<f64> = [-0.3, 0.0, 0.3, 1.0]
            .iter()
            .map(|&l| simulate(&i, &paths, l).ruin_probability)
            .collect();
        assert!(p.windows(2).all(|w| w[1] <= w[0]), "{p:?}");
        assert!(p[0] > p[3]);
    }

    #[test]
    fn an_empty_reserve_with_short_fees_is_ruined() {
        let i = Inputs {
            reserve_months: 0.0,
            ..short()
        };
        assert!(at_loading(&i, -0.5).ruin_probability > 0.99);
    }

    #[test]
    fn the_minimal_loading_is_the_smallest_that_meets_the_target() {
        let i = short();
        let row = study(&i);
        let l = row.minimal_loading.expect("reachable");
        let paths = draw(&i);
        assert!(simulate(&i, &paths, l).ruin_probability <= i.target);
        assert!(simulate(&i, &paths, l - 0.002).ruin_probability > i.target);
        assert!(table(&[row]).contains("| base |"));
    }

    #[test]
    fn the_long_run_inflow_is_one_plus_the_loading() {
        let i = Inputs {
            horizon_months: 1_200,
            paths: 1,
            reserve_months: 1.0e9,
            ..Inputs::base()
        };
        let paths = draw(&i);
        let end = simulate(&i, &paths, 0.25)
            .p5_end_reserve_months
            .expect("survives");
        let mean_inflow = (end - i.reserve_months) / 1_200.0 + 1.0;
        assert!((mean_inflow - 1.25).abs() < 0.1, "{mean_inflow}");
    }
}
