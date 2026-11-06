//! Runs of the populations under model policies, beside the rule run, with
//! the manifest that makes them reproducible.
//!
//! A campaign runs one scenario under [`crate::decision::Rules`] and under
//! each (registry model, prompt template) pair, all through one answer
//! cache. A change against the rule run counts only when every pair moves
//! the measure the same way and the pairs span at least two models and two
//! templates; otherwise it is exploratory.

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::Serialize;

use crate::decision::{
    Cache, Decode, Mode, ModelPolicy, ModelRef, Policy, Stats, Template, Transport,
};
use crate::economy::{Economy, Market, RunConfig, RunOutcome};

/// What to run.
#[derive(Debug, Clone)]
pub struct Spec {
    /// Market scenario.
    pub market: Market,
    /// Simulated days.
    pub days: u32,
    /// Run seed.
    pub seed: u64,
    /// Deciding agents per role.
    pub agents: u32,
    /// Registry models asked.
    pub models: Vec<ModelRef>,
    /// Prompt templates.
    pub templates: Vec<Template>,
    /// Decoding settings.
    pub decode: Decode,
    /// Network use.
    pub mode: Mode,
}

/// Measures compared against the rule run.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Measures {
    /// TNZO price on the last day, USD.
    pub final_price_usd: f64,
    /// Mean fee of a plain transfer, USD.
    pub mean_transfer_fee_usd: f64,
    /// Providers serving on the last day.
    pub final_providers: f64,
    /// Mean share of providers that were profitable.
    pub providers_profitable: f64,
    /// Blocks the ledger refused or whose duties failed.
    pub ledger_failures: f64,
}

impl Measures {
    fn of(o: &RunOutcome) -> Measures {
        let n = o.days.len().max(1) as f64;
        let last = o.days.last();
        Measures {
            final_price_usd: last.map(|d| d.price_usd).unwrap_or(0.0),
            mean_transfer_fee_usd: o
                .days
                .iter()
                .map(|d| d.human_fee_tnzo * d.price_usd)
                .sum::<f64>()
                / n,
            final_providers: last.map(|d| d.providers as f64).unwrap_or(0.0),
            providers_profitable: o.days.iter().map(|d| d.providers_profitable).sum::<f64>() / n,
            ledger_failures: o.ledger_failures.len() as f64,
        }
    }

    fn named(&self) -> [(&'static str, f64); 5] {
        [
            ("final_price_usd", self.final_price_usd),
            ("mean_transfer_fee_usd", self.mean_transfer_fee_usd),
            ("final_providers", self.final_providers),
            ("providers_profitable", self.providers_profitable),
            ("ledger_failures", self.ledger_failures),
        ]
    }
}

/// One (model, template) run.
#[derive(Debug, Clone, Serialize)]
pub struct PairRun {
    /// Registry model.
    pub model: ModelRef,
    /// Template version.
    pub template: String,
    /// Decision counters, calls and metering.
    pub stats: Stats,
    /// Measures.
    pub measures: Measures,
    /// Set when a decision failed and the run stopped.
    pub decision_error: Option<String>,
}

/// Whether a measure's change against the rule run holds across the pairs.
#[derive(Debug, Clone, Serialize)]
pub struct Robustness {
    /// Measure.
    pub measure: String,
    /// Change of each pair against the rule run, in pair order.
    pub deltas: Vec<f64>,
    /// `holds`, `exploratory` (direction agrees but the pairs span fewer
    /// than two models or two templates) or `mixed`.
    pub verdict: String,
}

/// What a campaign ran and what it found; enough to reproduce it.
#[derive(Debug, Clone, Serialize)]
pub struct Manifest {
    /// SHA-256 of the binary that ran, hex.
    pub binary_sha256: String,
    /// Scenario.
    pub market: String,
    /// Simulated days.
    pub days: u32,
    /// Run seed.
    pub seed: u64,
    /// Deciding agents per role.
    pub agents: u32,
    /// Network use.
    pub mode: String,
    /// Decoding settings.
    pub decode: Decode,
    /// Cache manifest hash the runs started from.
    pub cache_hash_in: String,
    /// Cache manifest hash after the runs; equal to `cache_hash_in` unless
    /// the campaign recorded.
    pub cache_hash_out: String,
    /// Answers in the cache after the runs.
    pub cache_entries: usize,
    /// The rule run.
    pub rules: Measures,
    /// The model runs.
    pub pairs: Vec<PairRun>,
    /// Change against the rule run, per measure.
    pub robustness: Vec<Robustness>,
    /// Calls made, receipts returned, calls whose settlement the node
    /// reported, metered cost (wei), and whether the counts agree.
    pub accounting: Accounting,
}

/// Calls against what the network reported for them.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Accounting {
    /// Network calls.
    pub calls: u64,
    /// Signed receipts returned.
    pub receipts: u64,
    /// Calls the node reported settling.
    pub settled: u64,
    /// Metered cost, wei.
    pub cost_wei: String,
    /// calls = receipts = settled.
    pub agree: bool,
}

fn config(spec: &Spec, policy: Policy) -> RunConfig {
    let mut c = RunConfig::scenario(spec.market, spec.seed, spec.days);
    c.decision_agents = spec.agents.max(1);
    c.policy = policy;
    c
}

/// SHA-256 of the running executable, hex.
pub fn binary_sha256() -> String {
    use sha2::{Digest, Sha256};
    std::env::current_exe()
        .and_then(std::fs::read)
        .map(|b| hex::encode(Sha256::digest(b)))
        .unwrap_or_default()
}

/// Runs the campaign over `cache`, returning its manifest and the cache
/// after it.
pub fn run(
    spec: &Spec,
    cache: Cache,
    transport: Option<Arc<dyn Transport>>,
) -> Result<(Manifest, Cache), String> {
    let cache_hash_in = cache.manifest_hash();
    let rules = Economy::new(config(spec, Policy::default())).run();
    if let Some(e) = rules.decision_error {
        return Err(format!("rule run: {e}"));
    }
    let base = Measures::of(&rules);
    let mut cache = cache;
    let mut pairs = Vec::new();
    for model in &spec.models {
        for t in &spec.templates {
            let p = Arc::new(ModelPolicy::new(
                model.clone(),
                *t,
                spec.decode.clone(),
                spec.mode,
                cache,
                transport.clone(),
            )?);
            let o = Economy::new(config(spec, Policy(p.clone()))).run();
            cache = p.cache();
            pairs.push(PairRun {
                model: model.clone(),
                template: t.version().into(),
                stats: p.stats(),
                measures: Measures::of(&o),
                decision_error: o.decision_error,
            });
        }
    }
    let n_models = spec.models.len();
    let n_templates = spec.templates.len();
    let robustness = base
        .named()
        .iter()
        .enumerate()
        .map(|(i, (name, b))| {
            let deltas: Vec<f64> = pairs.iter().map(|p| p.measures.named()[i].1 - b).collect();
            let same = !deltas.is_empty()
                && (deltas.iter().all(|d| *d > 0.0)
                    || deltas.iter().all(|d| *d < 0.0)
                    || deltas.iter().all(|d| *d == 0.0));
            let verdict = match (same, n_models >= 2 && n_templates >= 2) {
                (true, true) => "holds",
                (true, false) => "exploratory",
                _ => "mixed",
            };
            Robustness {
                measure: (*name).into(),
                deltas,
                verdict: verdict.into(),
            }
        })
        .collect();
    let mut acc = Accounting::default();
    let mut cost = 0u128;
    for p in &pairs {
        acc.calls += p.stats.calls;
        acc.receipts += p.stats.receipts;
        acc.settled += p.stats.settled;
        cost += p.stats.cost_wei;
    }
    acc.cost_wei = cost.to_string();
    acc.agree = acc.calls == acc.receipts && acc.calls == acc.settled;
    let manifest = Manifest {
        binary_sha256: binary_sha256(),
        market: spec.market.name().into(),
        days: spec.days,
        seed: spec.seed,
        agents: spec.agents,
        mode: spec.mode.name().into(),
        decode: spec.decode.clone(),
        cache_hash_in,
        cache_hash_out: cache.manifest_hash(),
        cache_entries: cache.entries.len(),
        rules: base,
        pairs,
        robustness,
        accounting: acc,
    };
    Ok((manifest, cache))
}

/// Decisions by role and action over the pairs, for a quick read.
pub fn actions(m: &Manifest) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    for p in &m.pairs {
        for (k, v) in &p.stats.actions {
            *out.entry(k.clone()).or_default() += v;
        }
    }
    out
}
