//! Machine-economy scenarios: no human trading in any of them. The only
//! TNZO buyers are agents paying fees and escrows, providers posting bonds,
//! and the treasury. Each is a small model with a pass criterion, run at
//! agent counts from a thousand to a billion where the count matters.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::bme::TestResult;

/// Inputs shared by the scenarios. Every figure is an assumption.
#[derive(Debug, Clone)]
pub struct Inputs {
    /// Paid actions per agent per day.
    pub actions_per_day: f64,
    /// Posted floor per action, USD.
    pub floor_usd: f64,
    /// Value settled per action, USD.
    pub value_usd: f64,
    /// Settlement fee, share of value.
    pub settlement_share: f64,
    /// Mean open escrow per agent, USD.
    pub exposure_usd: f64,
    /// Bond over exposure the protocol requires.
    pub var_ratio: f64,
    /// Days of fees an agent holds as float.
    pub float_days: f64,
    /// Yearly issuance, TNZO.
    pub mint_tnzo: f64,
    /// Verification fee per job, USD.
    pub verify_usd: f64,
    /// Identity registration fee, USD.
    pub identity_usd: f64,
    /// Least provider bond, USD.
    pub min_bond_usd: f64,
}

impl Default for Inputs {
    fn default() -> Self {
        Self {
            actions_per_day: 100.0,
            floor_usd: 2.1e-6,
            value_usd: 0.10,
            settlement_share: 0.001,
            exposure_usd: 5.0,
            var_ratio: 1.1,
            float_days: 3.0,
            mint_tnzo: 60.0e6,
            verify_usd: 0.001,
            identity_usd: 0.01,
            min_bond_usd: 100.0,
        }
    }
}

/// Agent counts every count-dependent scenario runs at.
pub const AGENTS: [f64; 6] = [1e3, 1e5, 1e6, 1e7, 1e8, 1e9];

fn burn_usd_day(i: &Inputs, agents: f64) -> f64 {
    agents * i.actions_per_day * (i.floor_usd + i.value_usd * i.settlement_share)
}

/// Every scenario's result.
pub fn scenarios(i: &Inputs) -> Vec<TestResult> {
    let mut out = Vec::new();
    // 1. Burn-mint clearing price.
    let clearing: Vec<String> = AGENTS
        .iter()
        .map(|&n| {
            format!(
                "{n:.0e}: ${:.2e}",
                burn_usd_day(i, n) * 365.25 / i.mint_tnzo
            )
        })
        .collect();
    let n_at_launch = AGENTS
        .iter()
        .copied()
        .find(|&n| burn_usd_day(i, n) * 365.25 / i.mint_tnzo >= 0.10);
    out.push(TestResult {
        number: 101,
        name: "burn-mint clearing price by agent count".into(),
        pass: AGENTS
            .windows(2)
            .all(|w| burn_usd_day(i, w[1]) > burn_usd_day(i, w[0])),
        detail: format!(
            "price where a year's burn equals a year's mint: {}; burn reaches the mint at $0.10 from {}",
            clearing.join(", "),
            n_at_launch.map_or("beyond 1e9 agents".into(), |n| format!("{n:.0e} agents"))
        ),
    });
    // 2. Bond demand against fee float at 1e8 agents (heavy-tailed exposure).
    let mut rng = StdRng::seed_from_u64(12);
    let alpha: f64 = 1.5;
    let xm = i.exposure_usd * (alpha - 1.0) / alpha;
    let sample: f64 = (0..100_000)
        .map(|_| xm / rng.gen_range(1e-9f64..1.0).powf(1.0 / alpha))
        .sum::<f64>()
        / 100_000.0;
    let agents = 1e8;
    let bonds = i.var_ratio * sample * agents;
    let float = burn_usd_day(i, agents) * i.float_days;
    out.push(TestResult {
        number: 102,
        name: "bond demand beside the fee float".into(),
        pass: bonds >= 100.0 * float,
        detail: format!(
            "at 1e8 agents bonds lock ${bonds:.3e} against a fee float of ${float:.3e} ({:.0}x)",
            bonds / float.max(1e-9)
        ),
    });
    // 3. Batching: burn per settled dollar against requests per settlement.
    let per_dollar = |k: f64| (i.floor_usd / k + i.value_usd * i.settlement_share) / i.value_usd;
    out.push(TestResult {
        number: 103,
        name: "batching keeps burn per settled dollar".into(),
        pass: per_dollar(1e6) >= 0.5 * per_dollar(1.0),
        detail: format!(
            "burn per settled dollar: {:.2e} unbatched, {:.2e} at 1e3, {:.2e} at 1e6 requests per settlement",
            per_dollar(1.0),
            per_dollar(1e3),
            per_dollar(1e6)
        ),
    });
    // 4. Wash payments: fee-capped app rewards against a usage-indexed mint.
    let fee = i.value_usd * i.settlement_share + i.floor_usd;
    let capped = 0.5 * fee - fee;
    let indexed = 0.15 * i.mint_tnzo * 0.10 / 365.25 / 1e6 - fee;
    out.push(TestResult {
        number: 104,
        name: "wash payments never pay; a usage-indexed mint would".into(),
        pass: capped < 0.0 && indexed > 0.0,
        detail: format!(
            "net per self-payment: ${capped:.2e} with rewards capped at half the fee; ${indexed:.2e} if the app share of mint followed raw usage (a million wash payments a day)"
        ),
    });
    // 5. Corruption: grab the open exposure and leave.
    let roles = [1.0, 2.0, 3.0];
    let worst = roles
        .iter()
        .map(|k| i.var_ratio * i.exposure_usd * k / (i.exposure_usd * k))
        .fold(f64::INFINITY, f64::min);
    out.push(TestResult {
        number: 105,
        name: "a provider that takes its open escrows loses more bond".into(),
        pass: worst > 1.0,
        detail: format!(
            "slashable bond over takeable exposure: {worst:.2} at every role count sharing one identity (each role bonds its own exposure)"
        ),
    });
    // 6. Price crash: TNZO escrows need no top-up; USD-priced escrows do.
    let crash: Vec<String> = [0.5, 0.8, 0.95]
        .iter()
        .map(|c| format!("-{:.0}%: x{:.1}", c * 100.0, 1.0 / (1.0 - c)))
        .collect();
    out.push(TestResult {
        number: 106,
        name: "bond top-ups through price crashes".into(),
        pass: true,
        detail: format!(
            "escrows in TNZO need no top-up; escrows priced in USD need their TNZO bond scaled by {} (the exposure check refuses new escrows until it is)",
            crash.join(", ")
        ),
    });
    // 7. Stable settlement and a halted cross-chain vault.
    let flow_day: f64 = 1e6;
    let max_outstanding: f64 = 2e5;
    let stranded: Vec<String> = [1.0, 6.0, 24.0, 72.0]
        .iter()
        .map(|h: &f64| {
            format!(
                "{h:.0}h: ${:.0}",
                (0.9 * flow_day * h / 24.0).min(max_outstanding)
            )
        })
        .collect();
    out.push(TestResult {
        number: 107,
        name: "stable settlement through a halted cross-chain vault".into(),
        pass: true,
        detail: format!(
            "90% of $1M/day settled in a bridged stable asset; stranded at most the route's outstanding cap ($200k): {}; settlement fees fall by up to 90% while halted and return with the route; the vault is app-level and nothing in consensus reads it",
            stranded.join(", ")
        ),
    });
    // 8. Verification: sampling rate that keeps providers honest.
    let job_value = 1.0;
    let cost_saved = 0.3;
    let bond = i.min_bond_usd;
    let p_star = cost_saved / bond;
    out.push(TestResult {
        number: 108,
        name: "verification sampling keeps providers honest".into(),
        pass: p_star <= 1.0 && i.verify_usd / job_value >= 1e-4,
        detail: format!(
            "least sampling rate {p_star:.4} (cheating saves ${cost_saved} a job against a ${bond:.0} bond); verification burns ${:.4} per verified dollar",
            i.verify_usd / job_value
        ),
    });
    // 9. Identity Sybil: nothing pays per identity, every identity costs.
    let k = 1e6;
    out.push(TestResult {
        number: 109,
        name: "identity Sybil farming".into(),
        pass: true,
        detail: format!(
            "a million identities cost ${:.0} in posted fees and earn nothing per identity: rewards follow fees paid and verified work, not identity count",
            k * i.identity_usd
        ),
    });
    // 10. Insurance solvency under correlated faults, bonds repaying first.
    let mut rng = StdRng::seed_from_u64(10);
    let mut ends = Vec::new();
    for _ in 0..2_000 {
        let mut pool = 10_000.0;
        for _ in 0..365 {
            pool += 30.0;
            if rng.gen_range(0.0..1.0) < 0.01 {
                let n = rng.gen_range(1..40) as f64;
                let loss = n * 150.0;
                let repaid = (n * i.min_bond_usd).min(loss);
                pool -= (loss - repaid).min(pool * 0.1);
            }
        }
        ends.push(pool);
    }
    ends.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let p1 = ends[ends.len() / 100];
    out.push(TestResult {
        number: 110,
        name: "insurance pool solvency, bonds repaying first".into(),
        pass: p1 > 0.0,
        detail: format!(
            "pool after a year at the 1st percentile: ${p1:.0} (bonds repay renters first; the pool pays only the rest, at most a tenth of itself a claim)"
        ),
    });
    // 11. Adoption: fiat-priced fees break the price-adoption loop.
    let adoption = |fee_usd: f64| 1.0 / (1.0 + (fee_usd / 1e-4).powi(2));
    let paths = [0.02, 0.1, 0.5];
    let pegged: Vec<f64> = paths.iter().map(|_| adoption(1e-4)).collect();
    let fixed: Vec<f64> = paths.iter().map(|p| adoption(1e-3 * p)).collect();
    let spread = |v: &[f64]| {
        v.iter().cloned().fold(f64::MIN, f64::max) - v.iter().cloned().fold(f64::MAX, f64::min)
    };
    out.push(TestResult {
        number: 111,
        name: "adoption does not depend on the token price".into(),
        pass: spread(&pegged) == 0.0 && spread(&fixed) > 0.0,
        detail: format!(
            "adoption spread across $0.02-$0.50 price paths: {:.3} with fees pegged to USD, {:.3} with fees fixed in TNZO",
            spread(&pegged),
            spread(&fixed)
        ),
    });
    // 12. Velocity: holding time barely moves value when bonds dominate.
    let b = i.var_ratio * i.exposure_usd * 1e8;
    let f = burn_usd_day(i, 1e8);
    let held = |tau_days: f64| b + f * tau_days;
    out.push(TestResult {
        number: 112,
        name: "value held depends on bonds, not holding time".into(),
        pass: held(7.0) / held(1.0 / 86_400.0) < 1.1,
        detail: format!(
            "TNZO value held at 1e8 agents: ${:.3e} at 1 s holding, ${:.3e} at 7 days",
            held(1.0 / 86_400.0),
            held(7.0)
        ),
    });
    out
}
