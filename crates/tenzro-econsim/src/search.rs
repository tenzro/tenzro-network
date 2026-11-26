//! Search over adversary parameters for the most profitable strategy.
//!
//! Each family's parameters are a point in the unit box, decoded to the
//! strategy's ranges. Random restarts seed the search, then CMA-ES (the
//! covariance matrix adaptation evolution strategy: rank-one and rank-mu
//! updates with cumulative step-size control) samples each generation
//! around the best points so far and learns which directions pay. Each
//! candidate is a full run of the economy with the adversary beside the
//! honest populations, so its profit is what the ledger paid. Finding no
//! profitable point is not evidence that none exists.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::Serialize;

use crate::attack::{Adversary, AttackOutcome};
use crate::economy::{Market, RunConfig};
use crate::gsa::run_all;

/// The best result of one strategy family.
#[derive(Debug, Clone, Serialize)]
pub struct SearchResult {
    /// Strategy family.
    pub family: String,
    /// Candidates evaluated.
    pub evaluated: usize,
    /// Profitable candidates.
    pub profitable: usize,
    /// Best candidate.
    pub best: Option<AttackOutcome>,
    /// Every candidate's outcome, best first (at most 20).
    pub top: Vec<AttackOutcome>,
}

/// Reads a point of the unit box one coordinate at a time.
struct Coords<'a> {
    x: &'a [f64],
    i: usize,
}

impl Coords<'_> {
    fn next(&mut self) -> f64 {
        let v = self.x[self.i].clamp(0.0, 1.0);
        self.i += 1;
        v
    }
    fn int(&mut self, lo: i64, hi: i64) -> i64 {
        (lo + (self.next() * (hi - lo + 1) as f64) as i64).min(hi)
    }
    fn lin(&mut self, lo: f64, hi: f64) -> f64 {
        lo + self.next() * (hi - lo)
    }
    fn log(&mut self, lo: f64, hi: f64) -> f64 {
        10f64.powf(self.lin(lo, hi))
    }
    fn flag(&mut self) -> bool {
        self.next() >= 0.5
    }
}

/// Coordinates of a family's search box.
fn dims(family: &str) -> usize {
    match family {
        "governance_holdout" => 1,
        "oracle_skew" => 2,
        "governance_capture" => 3,
        "self_dealing_sla" | "cartel_false_down" | "wash_ring" | "provider_collusion"
        | "playbook_trigger" => 4,
        other => panic!("unknown strategy family {other}"),
    }
}

/// The strategy at point `x` of the family's box.
fn decode(family: &str, x: &[f64], start: u32, run: u32) -> Adversary {
    let mut c = Coords { x, i: 0 };
    let a = match family {
        "self_dealing_sla" => Adversary::SelfDealingSla {
            start_day: start,
            run_days: run,
            streams_per_hour: c.int(1, 16) as u32,
            rate_tnzo: c.log(0.0, 4.5),
            stream_hours: c.int(2, 48) as u32,
            bond_tnzo: c.log(2.0, 4.0),
        },
        "cartel_false_down" => Adversary::CartelFalseDown {
            start_day: start,
            run_days: run,
            cartel: c.int(1, 20) as u32,
            honest_attest: c.lin(0.0, 1.0),
            streams_per_hour: c.int(1, 8) as u32,
            rate_tnzo: c.log(0.0, 4.0),
        },
        "governance_capture" => Adversary::GovernanceCapture {
            start_day: start,
            attackers: c.int(1, 20) as u32,
            honest_turnout: c.lin(0.0, 1.0),
            grant_tnzo: c.log(3.0, 7.0),
            stake_share: 0.0,
        },
        "governance_holdout" => Adversary::GovernanceHoldout {
            abstain_share: c.lin(0.0, 1.0),
        },
        "wash_ring" => Adversary::WashRing {
            start_day: start,
            run_days: run,
            ring: c.int(2, 12) as u32,
            plans_per_hour: c.int(1, 8) as u32,
            value_tnzo: c.log(0.0, 4.3),
            report_work: c.flag(),
        },
        "oracle_skew" => Adversary::OracleSkew {
            start_day: start,
            run_days: run,
            cartel: c.int(1, 20) as u32,
            skew_bps: c.int(-1_000, 1_000) as i32,
        },
        "provider_collusion" => Adversary::ProviderCollusion {
            start_day: start,
            run_days: run,
            providers: c.int(1, 8) as u32,
            markup: c.lin(1.0, 5.0),
            cartel: c.int(0, 20) as u32,
            honest_attest: c.lin(0.0, 1.0),
        },
        "playbook_trigger" => {
            let cartel = c.int(1, 20) as u32;
            let sign = if c.flag() { 1 } else { -1 };
            Adversary::PlaybookTrigger {
                start_day: start,
                run_days: run,
                cartel,
                skew_bps: sign * c.int(1_000, 9_500) as i32,
                keep_skew: c.flag(),
            }
        }
        other => panic!("unknown strategy family {other}"),
    };
    debug_assert_eq!(c.i, x.len(), "{family} reads every coordinate");
    a
}

fn normal(rng: &mut StdRng) -> f64 {
    let u1: f64 = rng.gen_range(f64::MIN_POSITIVE..1.0);
    let u2: f64 = rng.gen_range(0.0..1.0);
    (-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()
}

/// Lower Cholesky factor of a symmetric positive definite matrix.
fn cholesky(a: &[Vec<f64>]) -> Vec<Vec<f64>> {
    let n = a.len();
    let mut l = vec![vec![0.0; n]; n];
    for i in 0..n {
        for j in 0..=i {
            let s: f64 = (0..j).map(|k| l[i][k] * l[j][k]).sum();
            if i == j {
                l[i][i] = (a[i][i] - s).max(1e-12).sqrt();
            } else {
                l[i][j] = (a[i][j] - s) / l[j][j];
            }
        }
    }
    l
}

/// CMA-ES state over the unit box, maximising.
struct Cma {
    mean: Vec<f64>,
    sigma: f64,
    c: Vec<Vec<f64>>,
    pc: Vec<f64>,
    ps: Vec<f64>,
    weights: Vec<f64>,
    mueff: f64,
    cc: f64,
    cs: f64,
    c1: f64,
    cmu: f64,
    damps: f64,
    chi_n: f64,
    generation: i32,
}

impl Cma {
    fn new(mean: Vec<f64>, sigma: f64, lambda: usize) -> Self {
        let n = mean.len();
        let nf = n as f64;
        let mu = (lambda / 2).max(1);
        let raw: Vec<f64> = (1..=mu)
            .map(|i| (mu as f64 + 0.5).ln() - (i as f64).ln())
            .collect();
        let total: f64 = raw.iter().sum();
        let weights: Vec<f64> = raw.iter().map(|w| w / total).collect();
        let mueff = 1.0 / weights.iter().map(|w| w * w).sum::<f64>();
        let c1 = 2.0 / ((nf + 1.3).powi(2) + mueff);
        let cs = (mueff + 2.0) / (nf + mueff + 5.0);
        Self {
            sigma,
            c: (0..n)
                .map(|i| (0..n).map(|j| if i == j { 1.0 } else { 0.0 }).collect())
                .collect(),
            pc: vec![0.0; n],
            ps: vec![0.0; n],
            mueff,
            cc: (4.0 + mueff / nf) / (nf + 4.0 + 2.0 * mueff / nf),
            cs,
            c1,
            cmu: (1.0 - c1).min(2.0 * (mueff - 2.0 + 1.0 / mueff) / ((nf + 2.0).powi(2) + mueff)),
            damps: 1.0 + 2.0 * (((mueff - 1.0) / (nf + 1.0)).sqrt() - 1.0).max(0.0) + cs,
            chi_n: nf.sqrt() * (1.0 - 1.0 / (4.0 * nf) + 1.0 / (21.0 * nf * nf)),
            weights,
            mean,
            generation: 0,
        }
    }

    /// One candidate, clipped to the box.
    fn ask(&self, rng: &mut StdRng) -> Vec<f64> {
        let l = cholesky(&self.c);
        let z: Vec<f64> = (0..self.mean.len()).map(|_| normal(rng)).collect();
        (0..self.mean.len())
            .map(|i| {
                let y: f64 = (0..=i).map(|k| l[i][k] * z[k]).sum();
                (self.mean[i] + self.sigma * y).clamp(0.0, 1.0)
            })
            .collect()
    }

    /// Moves the distribution toward `ranked`, best first.
    fn tell(&mut self, ranked: &[Vec<f64>]) {
        let n = self.mean.len();
        let mu = self.weights.len().min(ranked.len());
        if mu == 0 {
            return;
        }
        let wsum: f64 = self.weights[..mu].iter().sum();
        let w: Vec<f64> = self.weights[..mu].iter().map(|x| x / wsum).collect();
        let old = self.mean.clone();
        let ys: Vec<Vec<f64>> = ranked[..mu]
            .iter()
            .map(|x| (0..n).map(|i| (x[i] - old[i]) / self.sigma).collect())
            .collect();
        let yw: Vec<f64> = (0..n)
            .map(|i| (0..mu).map(|k| w[k] * ys[k][i]).sum())
            .collect();
        let sigma = self.sigma;
        for (m, (o, y)) in self.mean.iter_mut().zip(old.iter().zip(&yw)) {
            *m = o + sigma * y;
        }
        // Whitened step: solve L v = yw.
        let l = cholesky(&self.c);
        let mut v: Vec<f64> = Vec::with_capacity(n);
        for i in 0..n {
            let s: f64 = l[i][..i].iter().zip(&v).map(|(a, b)| a * b).sum();
            v.push((yw[i] - s) / l[i][i]);
        }
        let ks = (self.cs * (2.0 - self.cs) * self.mueff).sqrt();
        let cs = self.cs;
        for (p, vi) in self.ps.iter_mut().zip(&v) {
            *p = (1.0 - cs) * *p + ks * vi;
        }
        let ps_norm = self.ps.iter().map(|x| x * x).sum::<f64>().sqrt();
        self.generation += 1;
        let hsig = ps_norm / (1.0 - (1.0 - self.cs).powi(2 * self.generation)).sqrt() / self.chi_n
            < 1.4 + 2.0 / (n as f64 + 1.0);
        let kc = (self.cc * (2.0 - self.cc) * self.mueff).sqrt();
        for (pc, y) in self.pc.iter_mut().zip(&yw) {
            *pc = (1.0 - self.cc) * *pc + if hsig { kc * y } else { 0.0 };
        }
        let lost = if hsig { 0.0 } else { self.cc * (2.0 - self.cc) };
        for i in 0..n {
            for j in 0..n {
                let rank_mu: f64 = (0..mu).map(|k| w[k] * ys[k][i] * ys[k][j]).sum();
                self.c[i][j] = (1.0 - self.c1 - self.cmu) * self.c[i][j]
                    + self.c1 * (self.pc[i] * self.pc[j] + lost * self.c[i][j])
                    + self.cmu * rank_mu;
            }
        }
        self.sigma = (self.sigma * ((self.cs / self.damps) * (ps_norm / self.chi_n - 1.0)).exp())
            .clamp(1e-6, 1.0);
    }
}

fn by_profit(a: &AttackOutcome, b: &AttackOutcome) -> std::cmp::Ordering {
    b.profit_tnzo
        .partial_cmp(&a.profit_tnzo)
        .unwrap_or(std::cmp::Ordering::Equal)
}

/// Every strategy family the search covers.
pub const FAMILIES: &[&str] = &[
    "self_dealing_sla",
    "self_dealing_sla@funded",
    "cartel_false_down",
    "cartel_false_down@funded",
    "governance_capture",
    "governance_holdout",
    "wash_ring",
    "oracle_skew",
    "provider_collusion",
    "playbook_trigger",
];

/// How strongly buyers route by price in the provider collusion runs when
/// the configuration sets no elasticity: a provider charging 10% more is
/// chosen about a third less often.
pub const COLLUSION_ELASTICITY: f64 = 4.0;

/// Insurance pool at genesis for the `@funded` variants, whole TNZO: a pool
/// that has had time to fill, so the size of a drain shows.
pub const FUNDED_POOL_TNZO: f64 = 1_000_000.0;

/// Searches one family: `restarts` random candidates, then `generations`
/// CMA-ES generations of `per_gen` candidates from the best restart.
pub fn search(
    family: &str,
    days: u32,
    restarts: usize,
    generations: usize,
    per_gen: usize,
    threads: usize,
    seed: u64,
) -> SearchResult {
    let base = RunConfig::scenario(Market::Flat, seed, days);
    search_with(
        family,
        days,
        restarts,
        generations,
        per_gen,
        threads,
        seed,
        &base,
    )
}

/// [`search`] over the assumptions and genesis parameters of `base` (its
/// market, seed and days are replaced). The rate strategies run with
/// validators reporting the rate; the provider collusion runs with buyers
/// routing by price ([`COLLUSION_ELASTICITY`] unless `base` sets one).
/// Paired strategies are measured against one baseline run.
#[allow(clippy::too_many_arguments)]
pub fn search_with(
    family: &str,
    days: u32,
    restarts: usize,
    generations: usize,
    per_gen: usize,
    threads: usize,
    seed: u64,
    base: &RunConfig,
) -> SearchResult {
    let mut rng = StdRng::seed_from_u64(seed ^ 0x5eed);
    let (kind, funded) = match family.split_once('@') {
        Some((k, "funded")) => (k, true),
        _ => (family, false),
    };
    let start = days / 2;
    let run = (days - start).saturating_sub(3).max(1);
    let mk = |a: Adversary, s: u64| {
        let mut c = base.clone();
        c.market = Market::Flat;
        c.seed = s;
        c.days = days;
        if funded {
            c.assumptions.insurance_genesis_tnzo = FUNDED_POOL_TNZO;
        }
        match kind {
            "oracle_skew" | "playbook_trigger" => c.rate_reports = true,
            "provider_collusion" if c.assumptions.buyer_price_elasticity == 0.0 => {
                c.assumptions.buyer_price_elasticity = COLLUSION_ELASTICITY;
            }
            _ => {}
        }
        c.adversary = Some(a);
        c
    };
    let n = dims(kind);
    let xs: Vec<Vec<f64>> = (0..restarts)
        .map(|_| (0..n).map(|_| rng.gen_range(0.0..1.0)).collect())
        .collect();
    // A paired family's baseline, the same run with nobody deviating, runs
    // beside the first candidates.
    let base_spec = xs
        .first()
        .and_then(|x| decode(kind, x, start, run).baseline());
    let mut cfgs: Vec<RunConfig> = base_spec.iter().map(|b| mk(b.clone(), seed)).collect();
    cfgs.extend(xs.iter().map(|x| mk(decode(kind, x, start, run), seed)));
    let mut outs = run_all(cfgs, threads);
    let baseline = if base_spec.is_some() && !outs.is_empty() {
        outs.remove(0).adversary
    } else {
        None
    };
    let judge = |mut o: AttackOutcome| {
        if let Some(b) = &baseline {
            crate::attack::pair(&mut o, b);
        }
        o
    };
    let mut pool: Vec<(Vec<f64>, AttackOutcome)> = xs
        .into_iter()
        .zip(outs)
        .filter_map(|(x, o)| o.adversary.map(|a| (x, judge(a))))
        .collect();
    pool.sort_by(|a, b| by_profit(&a.1, &b.1));
    let mean = pool.first().map_or_else(|| vec![0.5; n], |p| p.0.clone());
    let lambda = per_gen.max(2);
    let mut cma = Cma::new(mean, 0.3, lambda);
    for _ in 0..generations {
        let kids: Vec<Vec<f64>> = (0..lambda).map(|_| cma.ask(&mut rng)).collect();
        let outs = run_all(
            kids.iter()
                .map(|x| mk(decode(kind, x, start, run), seed))
                .collect(),
            threads,
        );
        let mut scored: Vec<(Vec<f64>, AttackOutcome)> = kids
            .into_iter()
            .zip(outs)
            .filter_map(|(x, o)| o.adversary.map(|a| (x, judge(a))))
            .collect();
        scored.sort_by(|a, b| by_profit(&a.1, &b.1));
        cma.tell(&scored.iter().map(|s| s.0.clone()).collect::<Vec<_>>());
        pool.extend(scored);
    }
    pool.sort_by(|a, b| by_profit(&a.1, &b.1));
    SearchResult {
        family: family.into(),
        evaluated: pool.len(),
        profitable: pool.iter().filter(|o| o.1.succeeded).count(),
        best: pool.first().map(|p| p.1.clone()),
        top: pool.into_iter().take(20).map(|p| p.1).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_family_reads_exactly_its_coordinates_and_stays_in_range() {
        for fam in FAMILIES {
            let kind = fam.split_once('@').map_or(*fam, |(k, _)| k);
            let n = dims(kind);
            for v in [0.0, 0.5, 1.0, -3.0, 4.0] {
                let a = decode(kind, &vec![v; n], 10, 5);
                let j = serde_json::to_value(&a).expect("json");
                assert!(!j.is_null(), "{fam}");
            }
        }
        let low = decode("oracle_skew", &[0.0, 0.0], 0, 1);
        let high = decode("oracle_skew", &[1.0, 1.0], 0, 1);
        assert!(matches!(
            low,
            Adversary::OracleSkew {
                cartel: 1,
                skew_bps: -1_000,
                ..
            }
        ));
        assert!(matches!(
            high,
            Adversary::OracleSkew {
                cartel: 20,
                skew_bps: 1_000,
                ..
            }
        ));
    }

    #[test]
    fn cma_es_climbs_to_the_peak_of_a_smooth_profit() {
        let peak = [0.7, 0.2, 0.9, 0.4];
        let f = |x: &[f64]| {
            -x.iter()
                .zip(peak)
                .map(|(a, b)| (a - b).powi(2))
                .sum::<f64>()
        };
        let mut rng = StdRng::seed_from_u64(7);
        let mut cma = Cma::new(vec![0.5; 4], 0.3, 8);
        for _ in 0..60 {
            let mut kids: Vec<Vec<f64>> = (0..8).map(|_| cma.ask(&mut rng)).collect();
            kids.sort_by(|a, b| f(b).total_cmp(&f(a)));
            cma.tell(&kids);
        }
        assert!(f(&cma.mean) > -1e-4, "mean {:?}", cma.mean);
    }
}
