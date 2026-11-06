//! Search over adversary parameters for the most profitable strategy.
//!
//! Random restarts, then a few generations of mutation around the best
//! points. Each candidate is a full run of the economy with the adversary
//! beside the honest populations, so its profit is what the ledger paid.
//! Finding no profitable point is not evidence that none exists.

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

fn sample(family: &str, rng: &mut StdRng, start: u32, run: u32) -> Adversary {
    match family {
        "self_dealing_sla" => Adversary::SelfDealingSla {
            start_day: start,
            run_days: run,
            streams_per_hour: rng.gen_range(1..=8),
            rate_tnzo: 10f64.powf(rng.gen_range(0.0..4.5)),
            stream_hours: rng.gen_range(2..=24),
            bond_tnzo: 10f64.powf(rng.gen_range(2.0..4.0)),
        },
        "cartel_false_down" => Adversary::CartelFalseDown {
            start_day: start,
            run_days: run,
            cartel: rng.gen_range(4..=14),
            honest_attest: rng.gen_range(0.3..1.0),
            streams_per_hour: rng.gen_range(1..=4),
            rate_tnzo: 10f64.powf(rng.gen_range(0.0..4.0)),
        },
        "governance_capture" => Adversary::GovernanceCapture {
            start_day: start,
            attackers: rng.gen_range(4..=14),
            honest_turnout: rng.gen_range(0.0..1.0),
            grant_tnzo: 10f64.powf(rng.gen_range(3.0..7.0)),
            stake_share: 0.0,
        },
        "governance_holdout" => Adversary::GovernanceHoldout {
            abstain_share: rng.gen_range(0.0..1.0),
        },
        "wash_ring" => Adversary::WashRing {
            start_day: start,
            run_days: run,
            ring: rng.gen_range(2..=12),
            plans_per_hour: rng.gen_range(1..=4),
            value_tnzo: 10f64.powf(rng.gen_range(0.0..4.3)),
            report_work: rng.gen_bool(0.5),
        },
        "oracle_skew" => Adversary::OracleSkew {
            start_day: start,
            run_days: run,
            cartel: rng.gen_range(1..=14),
            skew_bps: rng.gen_range(-1_000..=1_000),
        },
        "provider_collusion" => Adversary::ProviderCollusion {
            start_day: start,
            run_days: run,
            providers: rng.gen_range(1..=3),
            markup: rng.gen_range(1.0..3.0),
            cartel: rng.gen_range(0..=14),
            honest_attest: rng.gen_range(0.3..1.0),
        },
        "playbook_trigger" => Adversary::PlaybookTrigger {
            start_day: start,
            run_days: run,
            cartel: rng.gen_range(4..=14),
            skew_bps: if rng.gen_bool(0.5) { 1 } else { -1 } * rng.gen_range(1_000..=9_000),
            keep_skew: rng.gen_bool(0.5),
        },
        other => panic!("unknown strategy family {other}"),
    }
}

fn mutate(a: &Adversary, rng: &mut StdRng) -> Adversary {
    let jig = |x: f64, rng: &mut StdRng| x * 10f64.powf(rng.gen_range(-0.3..0.3));
    let step = |x: u32, lo: u32, hi: u32, rng: &mut StdRng| {
        (x as i64 + rng.gen_range(-2..=2)).clamp(lo as i64, hi as i64) as u32
    };
    match a.clone() {
        Adversary::SelfDealingSla {
            start_day,
            run_days,
            streams_per_hour,
            rate_tnzo,
            stream_hours,
            bond_tnzo,
        } => Adversary::SelfDealingSla {
            start_day,
            run_days,
            streams_per_hour: step(streams_per_hour, 1, 16, rng),
            rate_tnzo: jig(rate_tnzo, rng),
            stream_hours: step(stream_hours, 2, 48, rng),
            bond_tnzo: jig(bond_tnzo, rng).max(100.0),
        },
        Adversary::CartelFalseDown {
            start_day,
            run_days,
            cartel,
            honest_attest,
            streams_per_hour,
            rate_tnzo,
        } => Adversary::CartelFalseDown {
            start_day,
            run_days,
            cartel: step(cartel, 1, 20, rng),
            honest_attest: (honest_attest + rng.gen_range(-0.1..0.1)).clamp(0.0, 1.0),
            streams_per_hour: step(streams_per_hour, 1, 8, rng),
            rate_tnzo: jig(rate_tnzo, rng),
        },
        Adversary::GovernanceCapture {
            start_day,
            attackers,
            honest_turnout,
            grant_tnzo,
            stake_share,
        } => Adversary::GovernanceCapture {
            start_day,
            attackers: step(attackers, 1, 20, rng),
            honest_turnout: (honest_turnout + rng.gen_range(-0.1..0.1)).clamp(0.0, 1.0),
            grant_tnzo: jig(grant_tnzo, rng),
            stake_share,
        },
        Adversary::GovernanceHoldout { abstain_share } => Adversary::GovernanceHoldout {
            abstain_share: (abstain_share + rng.gen_range(-0.1..0.1)).clamp(0.0, 1.0),
        },
        Adversary::RateWalk {
            start_day,
            run_days,
            cartel,
            step_bps,
            withhold,
        } => Adversary::RateWalk {
            start_day,
            run_days,
            cartel: step(cartel, 1, 20, rng),
            step_bps: step(step_bps, 1, 500, rng),
            withhold,
        },
        g @ Adversary::SalamiGrants { .. } => g,
        Adversary::WashRing {
            start_day,
            run_days,
            ring,
            plans_per_hour,
            value_tnzo,
            report_work,
        } => Adversary::WashRing {
            start_day,
            run_days,
            ring: step(ring, 2, 12, rng),
            plans_per_hour: step(plans_per_hour, 1, 8, rng),
            value_tnzo: jig(value_tnzo, rng).min(20_000.0),
            report_work: if rng.gen_bool(0.2) {
                !report_work
            } else {
                report_work
            },
        },
        Adversary::OracleSkew {
            start_day,
            run_days,
            cartel,
            skew_bps,
        } => Adversary::OracleSkew {
            start_day,
            run_days,
            cartel: step(cartel, 1, 20, rng),
            skew_bps: (skew_bps + rng.gen_range(-200..=200)).clamp(-1_000, 1_000),
        },
        Adversary::ProviderCollusion {
            start_day,
            run_days,
            providers,
            markup,
            cartel,
            honest_attest,
        } => Adversary::ProviderCollusion {
            start_day,
            run_days,
            providers: step(providers, 1, 8, rng),
            markup: (markup + rng.gen_range(-0.2..0.2)).clamp(1.0, 5.0),
            cartel: step(cartel, 0, 20, rng),
            honest_attest: (honest_attest + rng.gen_range(-0.1..0.1)).clamp(0.0, 1.0),
        },
        Adversary::PlaybookTrigger {
            start_day,
            run_days,
            cartel,
            skew_bps,
            keep_skew,
        } => Adversary::PlaybookTrigger {
            start_day,
            run_days,
            cartel: step(cartel, 1, 20, rng),
            skew_bps: (skew_bps + rng.gen_range(-500..=500)).clamp(-9_500, 9_500),
            keep_skew: if rng.gen_bool(0.2) {
                !keep_skew
            } else {
                keep_skew
            },
        },
    }
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
/// rounds of `per_gen` mutations around the best four.
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
    let mut pool: Vec<AttackOutcome> = Vec::new();
    let cands: Vec<Adversary> = (0..restarts)
        .map(|_| sample(kind, &mut rng, start, run))
        .collect();
    // A paired family's baseline, the same run with nobody deviating, runs
    // beside the first candidates.
    let base_spec = cands.first().and_then(Adversary::baseline);
    let mut cfgs: Vec<RunConfig> = base_spec.iter().map(|b| mk(b.clone(), seed)).collect();
    cfgs.extend(cands.into_iter().map(|a| mk(a, seed)));
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
    pool.extend(outs.into_iter().filter_map(|o| o.adversary).map(judge));
    for _ in 0..generations {
        pool.sort_by(|a, b| {
            b.profit_tnzo
                .partial_cmp(&a.profit_tnzo)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let parents: Vec<Adversary> = pool
            .iter()
            .take(4)
            .filter_map(|o| serde_json::from_value(o.params.clone()).ok())
            .collect();
        if parents.is_empty() {
            break;
        }
        let kids: Vec<Adversary> = (0..per_gen)
            .map(|i| mutate(&parents[i % parents.len()], &mut rng))
            .collect();
        let outs = run_all(kids.into_iter().map(|a| mk(a, seed)).collect(), threads);
        pool.extend(outs.into_iter().filter_map(|o| o.adversary).map(judge));
    }
    pool.sort_by(|a, b| {
        b.profit_tnzo
            .partial_cmp(&a.profit_tnzo)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    SearchResult {
        family: family.into(),
        evaluated: pool.len(),
        profitable: pool.iter().filter(|o| o.succeeded).count(),
        best: pool.first().cloned(),
        top: pool.into_iter().take(20).collect(),
    }
}
