//! The economics report: scenarios, sensitivity, adversaries and spam,
//! with a verdict and the issues to fix.

use std::fmt::Write as _;

use serde::Serialize;

use crate::economy::{Day, RunOutcome};
use crate::gsa::{Analysis, Metrics};
use crate::search::SearchResult;
use crate::spam::SpamLevel;

/// Per-scenario summary over its seeds.
#[derive(Debug, Clone, Serialize)]
pub struct ScenarioSummary {
    /// Scenario.
    pub market: String,
    /// Seeds.
    pub seeds: usize,
    /// Days simulated.
    pub days: usize,
    /// Year-end rows: (year, p10, median, p90) of each figure.
    pub yearly: Vec<YearRow>,
    /// Seeds whose run broke an invariant, with the invariant.
    pub failures: Vec<(u64, Vec<String>)>,
    /// Refusals across seeds, most common first.
    pub refusals: Vec<(String, u64)>,
    /// Ledger failures across seeds.
    pub ledger_failures: Vec<String>,
    /// Gas fees of volume the runs stood for but did not execute, TNZO (median).
    pub unexecuted_gas_fees_tnzo: f64,
}

/// One figure at one year end.
#[derive(Debug, Clone, Serialize)]
pub struct YearRow {
    /// Year (1-based).
    pub year: u32,
    /// Figure.
    pub figure: String,
    /// 10th percentile across seeds.
    pub p10: f64,
    /// Median.
    pub p50: f64,
    /// 90th percentile.
    pub p90: f64,
}

fn pct(mut v: Vec<f64>, q: f64) -> f64 {
    v.retain(|x| x.is_finite());
    if v.is_empty() {
        return f64::NAN;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let i = ((v.len() - 1) as f64 * q).round() as usize;
    v[i]
}

fn figures(d: &Day) -> Vec<(&'static str, f64)> {
    vec![
        ("price_usd", d.price_usd),
        ("supply_tnzo", d.snap.supply),
        ("burned_tnzo", d.snap.burned),
        ("treasury_tnzo", d.snap.treasury),
        (
            "treasury_runway_months",
            d.treasury_runway_months.min(1_200.0),
        ),
        ("insurance_pool_tnzo", d.snap.insurance_pool),
        ("insurance_paid_tnzo", d.snap.claims_total),
        ("rewards_pool_tnzo", d.snap.rewards_pool),
        ("bonded_tnzo", d.snap.bonded),
        ("staking_ratio", d.staking_ratio),
        ("bonded_validators", d.snap.bonded_validators as f64),
        ("validator_yield", d.validator_yield),
        ("validators_profitable", d.validators_profitable),
        ("providers", d.providers as f64),
        ("providers_profitable", d.providers_profitable),
        ("human_fee_usd", d.human_fee_tnzo * d.price_usd),
        ("agent_settlement_fee_share", d.agent_fee_share),
        ("grants_usd_day", d.grants_usd),
        ("running_costs_paid_usd_30d", d.running_costs_paid_usd_30d),
        ("running_costs_asked_usd_30d", d.running_costs_asked_usd_30d),
        ("reserve_tnzo", d.snap.reserve),
        (
            "reserve_runway_months",
            d.reserve_runway_months.min(1_200.0),
        ),
        ("mint_multiplier", d.mint_mult),
        ("chain_rate_usd", d.chain_rate_usd),
        ("revenue_usd_year", d.revenue_usd_year),
        ("fdv_usd", d.fdv_usd),
        ("staking_ratio_circulating", d.staking_ratio_circulating),
        ("attack_cost_usd", d.attack_cost_usd),
        ("attack_cost_pool_usd", d.attack_cost_pool_usd),
    ]
}

/// Summarises one scenario's seeds.
pub fn summarise(market: &str, runs: &[RunOutcome]) -> ScenarioSummary {
    let days = runs.iter().map(|r| r.days.len()).min().unwrap_or(0);
    let mut yearly = Vec::new();
    let years = (days as f64 / 365.25).floor() as u32;
    let marks: Vec<(u32, usize)> = (1..=years.max(1))
        .map(|y| {
            (
                y,
                ((y as f64 * 365.25) as usize).min(days).saturating_sub(1),
            )
        })
        .collect();
    for (y, idx) in marks {
        if runs.iter().any(|r| r.days.len() <= idx) {
            continue;
        }
        let names: Vec<&str> = figures(&runs[0].days[idx])
            .iter()
            .map(|(n, _)| *n)
            .collect();
        for (fi, name) in names.iter().enumerate() {
            let v: Vec<f64> = runs.iter().map(|r| figures(&r.days[idx])[fi].1).collect();
            yearly.push(YearRow {
                year: y,
                figure: name.to_string(),
                p10: pct(v.clone(), 0.1),
                p50: pct(v.clone(), 0.5),
                p90: pct(v, 0.9),
            });
        }
    }
    let failures = runs
        .iter()
        .map(|r| {
            (
                r.seed,
                Metrics::of(r)
                    .failures()
                    .into_iter()
                    .map(String::from)
                    .collect::<Vec<_>>(),
            )
        })
        .filter(|(_, f)| !f.is_empty())
        .collect();
    let mut refusals: std::collections::BTreeMap<String, u64> = Default::default();
    for r in runs {
        for (k, v) in &r.refusals {
            *refusals.entry(k.clone()).or_default() += v;
        }
    }
    let mut refusals: Vec<(String, u64)> = refusals.into_iter().collect();
    refusals.sort_by_key(|r| std::cmp::Reverse(r.1));
    refusals.truncate(15);
    ScenarioSummary {
        market: market.into(),
        seeds: runs.len(),
        days,
        yearly,
        failures,
        refusals,
        ledger_failures: runs
            .iter()
            .flat_map(|r| r.ledger_failures.iter().take(3).cloned())
            .take(10)
            .collect(),
        unexecuted_gas_fees_tnzo: pct(
            runs.iter().map(|r| r.unexecuted_gas_fees_tnzo).collect(),
            0.5,
        ),
    }
}

/// The whole report.
#[derive(Debug, Clone, Serialize, Default)]
pub struct Report {
    /// Commit the run built.
    pub commit: String,
    /// Scenario summaries.
    pub scenarios: Vec<ScenarioSummary>,
    /// Sensitivity analysis.
    pub analysis: Option<Analysis>,
    /// Adversary searches.
    pub searches: Vec<SearchResult>,
    /// Spam study.
    pub spam: Vec<SpamLevel>,
    /// Thin-pool study.
    pub dex: Option<crate::dex::DexStudy>,
    /// The proposed fee design's tests, run on its model.
    pub design_tests: Vec<crate::bme::TestResult>,
    /// Rewards paid on settlements against collusion (S1, S5, S6), run on
    /// the VM's own rules; a failure is an issue.
    pub settlement_tests: Vec<crate::bme::TestResult>,
    /// S1's points: wash against the provider bucket.
    pub provider_wash: Vec<crate::settlement_rewards::WashPoint>,
    /// S5's points: cheat deterrence across payment and price.
    pub cheat_deterrence: Vec<crate::settlement_rewards::CheatPoint>,
    /// Issuance target, security ratio and cold-start scenarios; a failure
    /// is an issue.
    pub staking_tests: Vec<crate::bme::TestResult>,
    /// Crash and reflexivity scenarios; a failure is an issue.
    pub crash_tests: Vec<crate::bme::TestResult>,
    /// The crash study's table.
    pub crash_table: String,
    /// What each mechanism contributes, and the cartel sweep.
    pub ablations: Option<crate::ablation::AblationStudy>,
    /// Phases the time budget left out.
    pub skipped: Vec<String>,
    /// Whether every phase ran; false in a report saved part way.
    pub complete: bool,
    /// Burn against mint over agent counts.
    pub design_equilibrium: Vec<crate::bme::Equilibrium>,
    /// Verdict: PASS, WARN or FAIL.
    pub verdict: String,
    /// Issues that need a fix, one line each.
    pub issues: Vec<String>,
    /// Issues that need watching but not a fix.
    pub warnings: Vec<String>,
    /// Wall-clock seconds.
    pub wall_s: f64,
}

impl Report {
    /// Decides the verdict from what ran.
    pub fn judge(&mut self) {
        for p in &self.skipped {
            self.warnings
                .push(format!("{p} skipped: it did not fit the time budget"));
        }
        if let Some(a) = &self.ablations {
            self.issues.extend(a.issues());
        }
        for s in &self.scenarios {
            if !s.ledger_failures.is_empty() {
                self.issues.push(format!(
                    "{}: the ledger refused blocks: {}",
                    s.market, s.ledger_failures[0]
                ));
            }
            let share = s.failures.len() as f64 / s.seeds.max(1) as f64;
            if share > 0.0 {
                let mut kinds: Vec<String> =
                    s.failures.iter().flat_map(|(_, f)| f.clone()).collect();
                kinds.sort();
                kinds.dedup();
                let line = format!(
                    "{} market: {}/{} seeds break an invariant ({})",
                    s.market,
                    s.failures.len(),
                    s.seeds,
                    kinds.join("; ")
                );
                if s.market == "downturn" && share < 0.5 {
                    self.warnings.push(line);
                } else {
                    self.issues.push(line);
                }
            }
        }
        for r in &self.searches {
            if r.family == "governance_holdout" && r.profitable > 0 {
                let least = r
                    .top
                    .iter()
                    .filter(|o| o.succeeded)
                    .filter_map(|o| o.params.get("abstain_share").and_then(|v| v.as_f64()))
                    .fold(f64::INFINITY, f64::min);
                let line = format!(
                    "governance stalls (no routine grant or fee-rate update passes) once {:.0}% of validators stop voting",
                    least * 100.0
                );
                if least < 1.0 / 3.0 {
                    self.issues.push(line);
                } else {
                    self.warnings.push(line);
                }
                continue;
            }
            if let Some(b) = &r.best
                && b.succeeded
            {
                let what = {
                    format!(
                        "profitable strategy: {} nets {:.0} TNZO (${:.0}), drains {:.0} TNZO from the insurance pool; {}/{} candidates profitable; params {}",
                        b.name,
                        b.profit_tnzo,
                        b.profit_usd,
                        b.pool_drained_tnzo,
                        r.profitable,
                        r.evaluated,
                        b.params
                    )
                };
                self.issues.push(what);
            }
        }
        if let Some(a) = &self.analysis {
            for s in &a.safe_ranges {
                if let (Some(g), Some(lo), Some(hi)) = (s.genesis, s.lo, s.hi)
                    && (g < lo || g > hi)
                {
                    self.warnings.push(format!(
                        "{}: genesis value {} lies outside the widest safe range seen [{:.3}, {:.3}]",
                        s.factor, g, lo, hi
                    ));
                }
            }
        }
        if let Some(d) = &self.dex {
            for c in &d.corruption {
                let Some(cost) = c.cost_usd else { continue };
                if c.net_usd.is_some_and(|net| net > 0.0) {
                    self.issues.push(format!(
                        "buying {:.0}% of bonded stake through a ${} pool costs ${} and the treasury and insurance pool it can take sell for ${} in the same pool",
                        c.share * 100.0,
                        num(c.depth_usd),
                        num(cost),
                        num(c.payoff_exit_usd)
                    ));
                } else if cost < crate::dex::CAPTURE_MARGIN * c.payoff_exit_usd {
                    self.issues.push(format!(
                        "buying {:.0}% of bonded stake through a ${} pool costs ${}, less than {} times the ${} that what it can take sells for in the same pool",
                        c.share * 100.0,
                        num(c.depth_usd),
                        num(cost),
                        crate::dex::CAPTURE_MARGIN,
                        num(c.payoff_exit_usd)
                    ));
                }
            }
            let mut flagged: Vec<String> = d
                .levers
                .iter()
                .filter(|r| !r.flag.is_empty() && r.stake_share > 0.0 && r.shock == 0.0)
                .map(|r| {
                    format!(
                        "treasury stake {:.0}% at handover {:.0}%: {}",
                        r.stake_share * 100.0,
                        r.handover * 100.0,
                        r.flag
                    )
                })
                .collect();
            flagged.sort();
            flagged.dedup();
            for f in flagged {
                self.warnings.push(f);
            }
            for r in &d.shocks {
                if r.validators_after < 4 || r.ledger_failures > 0 {
                    self.issues.push(format!(
                        "a {:.0}% price shock leaves {} bonded validators (agents leave: {}, fee rate path: {})",
                        r.shock * 100.0,
                        r.validators_after,
                        r.agents_leave,
                        r.rate_path
                    ));
                }
            }
        }
        for l in &self.spam {
            if l.cost_usd < 1_000.0
                && l.transfer_fee_end_usd > 10.0 * l.transfer_fee_start_usd.max(1e-12)
            {
                self.issues.push(format!(
                    "spam at {:.1}x the gas target for {:.0} s costs ${:.2} and raises a transfer's fee {:.0}x",
                    l.spam_of_target,
                    l.seconds,
                    l.cost_usd,
                    l.transfer_fee_end_usd / l.transfer_fee_start_usd.max(1e-12)
                ));
            }
        }
        for t in &self.settlement_tests {
            if !t.pass {
                self.issues.push(format!(
                    "settlement rewards, test {} ({}): {}",
                    t.number, t.name, t.detail
                ));
            }
        }
        for t in &self.staking_tests {
            if !t.pass {
                self.issues.push(format!(
                    "issuance and security, test {} ({}): {}",
                    t.number, t.name, t.detail
                ));
            }
        }
        for t in &self.crash_tests {
            if !t.pass {
                self.issues.push(format!(
                    "crash and reflexivity, test {} ({}): {}",
                    t.number, t.name, t.detail
                ));
            }
        }
        for t in &self.design_tests {
            if !t.pass {
                self.warnings.push(format!(
                    "proposed fee design, test {} ({}): {}",
                    t.number, t.name, t.detail
                ));
            }
        }
        self.verdict = if !self.issues.is_empty() {
            "FAIL".into()
        } else if !self.warnings.is_empty() {
            "WARN".into()
        } else {
            "PASS".into()
        };
    }

    /// The report as Markdown.
    pub fn markdown(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "# Economic simulation: {}\n", self.commit);
        let _ = writeln!(s, "Verdict: **{}** ({:.0} s)\n", self.verdict, self.wall_s);
        if !self.issues.is_empty() {
            let _ = writeln!(s, "## Issues\n");
            for i in &self.issues {
                let _ = writeln!(s, "- {i}");
            }
            s.push('\n');
        }
        if !self.warnings.is_empty() {
            let _ = writeln!(s, "## Warnings\n");
            for i in &self.warnings {
                let _ = writeln!(s, "- {i}");
            }
            s.push('\n');
        }
        let _ = writeln!(s, "## Scenarios\n");
        for sc in &self.scenarios {
            let _ = writeln!(
                s,
                "### {} ({} seeds, {} days)\n",
                sc.market, sc.seeds, sc.days
            );
            let _ = writeln!(
                s,
                "| year | figure | p10 | median | p90 |\n|---|---|---|---|---|"
            );
            for r in &sc.yearly {
                let _ = writeln!(
                    s,
                    "| {} | {} | {} | {} | {} |",
                    r.year,
                    r.figure,
                    num(r.p10),
                    num(r.p50),
                    num(r.p90)
                );
            }
            if !sc.refusals.is_empty() {
                let _ = writeln!(s, "\nMost common refused transactions:\n");
                for (k, v) in sc.refusals.iter().take(8) {
                    let _ = writeln!(s, "- {v} x {k}");
                }
            }
            let _ = writeln!(
                s,
                "\nGas fees of transfers stood for but not executed (median): {:.3} TNZO\n",
                sc.unexecuted_gas_fees_tnzo
            );
        }
        if let Some(a) = &self.analysis {
            let _ = writeln!(s, "## Sensitivity ({} runs)\n", a.runs);
            let _ = writeln!(
                s,
                "Screened into the variance stage: {}\n",
                a.screened.join(", ")
            );
            let _ = writeln!(
                s,
                "| factor | output | first order | total |\n|---|---|---|---|"
            );
            let mut so = a.sobol.clone();
            so.sort_by(|x, y| {
                y.total
                    .partial_cmp(&x.total)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            for x in so.iter().filter(|x| x.total > 0.05).take(30) {
                let _ = writeln!(
                    s,
                    "| {} | {} | {:.2} | {:.2} |",
                    x.factor, x.output, x.first, x.total
                );
            }
            let _ = writeln!(
                s,
                "\nSafe range per governed parameter (deciles at or under 10% failure):\n"
            );
            let _ = writeln!(
                s,
                "| parameter | genesis | safe low | safe high | failure by decile |\n|---|---|---|---|---|"
            );
            for r in &a.safe_ranges {
                let dec: Vec<String> = r
                    .failure_by_decile
                    .iter()
                    .map(|x| {
                        if x.is_finite() {
                            format!("{:.0}", x * 100.0)
                        } else {
                            "-".into()
                        }
                    })
                    .collect();
                let _ = writeln!(
                    s,
                    "| {} | {} | {} | {} | {} |",
                    r.factor,
                    r.genesis.map(num).unwrap_or_default(),
                    r.lo.map(num).unwrap_or_else(|| "none".into()),
                    r.hi.map(num).unwrap_or_else(|| "none".into()),
                    dec.join(" ")
                );
            }
            s.push('\n');
        }
        if !self.searches.is_empty() {
            let _ = writeln!(s, "## Adversaries\n");
            let _ = writeln!(
                s,
                "| strategy | evaluated | profitable | best net TNZO | best net USD | pool drained TNZO |\n|---|---|---|---|---|---|"
            );
            for r in &self.searches {
                let (p, u, d) = r
                    .best
                    .as_ref()
                    .map(|b| (b.profit_tnzo, b.profit_usd, b.pool_drained_tnzo))
                    .unwrap_or_default();
                let _ = writeln!(
                    s,
                    "| {} | {} | {} | {} | {} | {} |",
                    r.family,
                    r.evaluated,
                    r.profitable,
                    num(p),
                    num(u),
                    num(d)
                );
            }
            for r in &self.searches {
                if let Some(b) = &r.best {
                    let _ = writeln!(s, "\n{} best: `{}`", r.family, b.params);
                    for (k, v) in &b.detail {
                        let _ = writeln!(s, "- {k}: {}", num(*v));
                    }
                }
            }
            s.push('\n');
        }
        if let Some(d) = &self.dex {
            let _ = writeln!(s, "## Thin pool\n");
            let _ = writeln!(
                s,
                "Bonded {} TNZO, treasury {} TNZO, insurance pool {} TNZO, price ${}.\n",
                num(d.bonded_tnzo),
                num(d.treasury_tnzo),
                num(d.insurance_tnzo),
                d.price_usd
            );
            let _ = writeln!(
                s,
                "Payoff: what the stake can take out of the treasury within the treasury guards, plus the whole insurance pool and running-cost reserve.\n\n| depth USD | stake share | TNZO to bond | cost USD | payoff TNZO | payoff at price USD | payoff sold into pool USD | net USD |\n|---|---|---|---|---|---|---|---|"
            );
            for c in &d.corruption {
                let _ = writeln!(
                    s,
                    "| {} | {:.2} | {} | {} | {} | {} | {} | {} |",
                    num(c.depth_usd),
                    c.share,
                    num(c.stake_needed_tnzo),
                    c.cost_usd
                        .map(num)
                        .unwrap_or_else(|| "pool cannot supply".into()),
                    num(c.payoff_tnzo),
                    num(c.payoff_usd_at_price),
                    num(c.payoff_exit_usd),
                    c.net_usd.map(num).unwrap_or_else(|| "-".into())
                );
            }
            let _ = writeln!(
                s,
                "\n| depth USD | USD to double the price | TNZO to halve it |\n|---|---|---|"
            );
            for (dp, up, down) in &d.manipulation {
                let _ = writeln!(s, "| {} | {} | {} |", num(*dp), num(*up), num(*down));
            }
            if !d.levers.is_empty() {
                let _ = writeln!(
                    s,
                    "\nTreasury levers (protocol security analysis, not financial advice; treasury and listing decisions belong to the Foundation and its advisers).\n"
                );
                let mut best: Vec<_> = d
                    .levers
                    .iter()
                    .filter(|r| {
                        r.shock == 0.0 && r.handover == 0.0 && r.cost_per_treasury_usd.is_some()
                    })
                    .collect();
                best.sort_by(|a, b| {
                    b.cost_per_treasury_usd
                        .partial_cmp(&a.cost_per_treasury_usd)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
                let _ = writeln!(
                    s,
                    "Best combinations by attack cost per treasury dollar (no shock, before handover):\n"
                );
                let _ = writeln!(
                    s,
                    "| depth USD | liquidity share | stake share | cost to a third USD | treasury USD | cost per treasury USD | Nakamoto (treasury one entity) | Nakamoto (delegations locked) | largest share | flag |\n|---|---|---|---|---|---|---|---|---|---|"
                );
                for r in best.iter().take(12) {
                    let _ = writeln!(
                        s,
                        "| {} | {:.2} | {:.2} | {} | {} | {} | {} | {} | {:.2} | {} |",
                        num(r.depth_usd),
                        r.pol_share,
                        r.stake_share,
                        r.corrupt_third_usd.map(num).unwrap_or_else(|| format!(
                            ">= {} (pool cannot supply)",
                            num(r.corrupt_third_floor_usd)
                        )),
                        num(r.treasury_committed_usd),
                        r.cost_per_treasury_usd.map(num).unwrap_or_default(),
                        r.nakamoto_treasury_one_entity,
                        r.nakamoto_delegations_locked,
                        r.largest_share,
                        r.flag
                    );
                }
                let _ = writeln!(
                    s,
                    "\nProtocol-owned liquidity at a $1M third-party pool (no treasury stake):\n"
                );
                let _ = writeln!(
                    s,
                    "| liquidity share | shock | USD to lift 10% | USD to cut 50% | USD to cut 80% | impermanent loss | liquidity USD paid out |\n|---|---|---|---|---|---|---|"
                );
                for r in d.levers.iter().filter(|r| {
                    r.depth_usd == 1_000_000.0 && r.stake_share == 0.0 && r.handover == 0.0
                }) {
                    let _ = writeln!(
                        s,
                        "| {:.2} | {:.0}% | {} | {} | {} | {:.3} | {} |",
                        r.pol_share,
                        r.shock * 100.0,
                        num(r.move_up_10_usd),
                        num(r.move_down_50_usd),
                        num(r.move_down_80_usd),
                        r.pol_impermanent_loss,
                        num(r.pol_usd_depleted)
                    );
                }
                let _ = writeln!(
                    s,
                    "\nTreasury stake at a $1M third-party pool (no protocol liquidity):\n"
                );
                let _ = writeln!(
                    s,
                    "| stake share | handover | shock | cost to a third USD | cost to two thirds USD | Nakamoto (one entity) | Nakamoto (locked) | largest share | flag |\n|---|---|---|---|---|---|---|---|---|"
                );
                for r in d.levers.iter().filter(|r| {
                    r.depth_usd == 1_000_000.0
                        && r.pol_share == 0.0
                        && (r.shock == 0.0 || r.shock <= -0.95)
                }) {
                    let _ = writeln!(
                        s,
                        "| {:.2} | {:.1} | {:.0}% | {} | {} | {} | {} | {:.2} | {} |",
                        r.stake_share,
                        r.handover,
                        r.shock * 100.0,
                        r.corrupt_third_usd
                            .map(num)
                            .unwrap_or_else(|| format!(">= {}", num(r.corrupt_third_floor_usd))),
                        r.corrupt_two_thirds_usd
                            .map(num)
                            .unwrap_or_else(|| "pool cannot supply".into()),
                        r.nakamoto_treasury_one_entity,
                        r.nakamoto_delegations_locked,
                        r.largest_share,
                        r.flag
                    );
                }
            }
            let _ = writeln!(
                s,
                "\n| shock | agents leave | fee rate path | validators before | after | bonded after TNZO | transfer fee after USD | runway months | validators profitable | worst rate gap |\n|---|---|---|---|---|---|---|---|---|---|"
            );
            for r in &d.shocks {
                let _ = writeln!(
                    s,
                    "| {:.0}% | {} | {} | {} | {} | {} | {} | {} | {:.2} | {:.2} |",
                    r.shock * 100.0,
                    r.agents_leave,
                    r.rate_path,
                    r.validators_before,
                    r.validators_after,
                    num(r.bonded_after),
                    num(r.transfer_fee_usd_after),
                    num(r.treasury_runway_months),
                    r.validators_profitable,
                    r.worst_rate_gap
                );
            }
            if !d.rate_cartels.is_empty() {
                let _ = writeln!(
                    s,
                    "\nValidators misreporting the TNZO/USD rate (validator-reported rate path):\n"
                );
                let _ = writeln!(
                    s,
                    "| cartel validators | stake share | reported factor | chain/market rate day 1 | day 7 | transfer fee USD before | day 7 |\n|---|---|---|---|---|---|---|"
                );
                for r in &d.rate_cartels {
                    let _ = writeln!(
                        s,
                        "| {} | {:.2} | {} | {:.3} | {:.3} | {} | {} |",
                        r.cartel,
                        r.stake_share,
                        r.factor,
                        r.rate_ratio_day1,
                        r.rate_ratio_day7,
                        num(r.transfer_fee_usd_before),
                        num(r.transfer_fee_usd_day7)
                    );
                }
            }
            if !d.cross_chain.is_empty() {
                let _ = writeln!(
                    s,
                    "\nCross-chain liquidity: home vault pool on another chain and the native pool (no shock, 20-minute latency, 1M TNZO/hour limit, 15% bridged cap):\n"
                );
                let _ = writeln!(
                    s,
                    "| liquidity USD | home share | owned liquidity | at home | native +10% USD | home +10% USD | native -50% USD | cheapest | 50% gap hours | cost to a third USD | bridge loss cap USD | fragmentation ratio |\n|---|---|---|---|---|---|---|---|---|---|---|---|"
                );
                for r in d.cross_chain.iter().filter(|r| {
                    r.shock == 0.0
                        && r.latency_min == 20.0
                        && r.rate_limit_tnzo_hour == 1_000_000.0
                        && r.bridged_cap == 0.15
                }) {
                    let _ = writeln!(
                        s,
                        "| {} | {:.2} | {:.3} | {} | {} | {} | {} | {} | {:.2} | {} | {} | {:.2} |",
                        num(r.liquidity_usd),
                        r.home_share,
                        r.pol_share,
                        r.pol_home,
                        num(r.native_up_10_usd),
                        num(r.home_up_10_usd),
                        num(r.native_down_50_usd),
                        r.cheapest,
                        r.gap_hours,
                        r.corrupt_third_usd
                            .map(num)
                            .unwrap_or_else(|| "pool cannot supply".into()),
                        num(r.bridge_loss_cap_usd),
                        r.fragmentation_ratio
                    );
                }
                let _ = writeln!(
                    s,
                    "\nBridge loss cap by bridged-supply cap ($1M liquidity, 80% at home, no owned liquidity, no shock): "
                );
                for r in d.cross_chain.iter().filter(|r| {
                    r.shock == 0.0
                        && r.liquidity_usd == 1_000_000.0
                        && r.home_share == 0.8
                        && r.pol_share == 0.0
                        && r.latency_min == 20.0
                        && r.rate_limit_tnzo_hour == 1_000_000.0
                }) {
                    let _ = writeln!(
                        s,
                        "- cap {:.0}%: at most ${} lost if the cross-chain token fails",
                        r.bridged_cap * 100.0,
                        num(r.bridge_loss_cap_usd)
                    );
                }
            }
            s.push('\n');
        }
        if let Some(a) = &self.ablations {
            s.push_str(&a.markdown());
            s.push('\n');
        }
        if !self.skipped.is_empty() {
            let _ = writeln!(s, "## Left out by the time budget\n");
            for p in &self.skipped {
                let _ = writeln!(s, "- {p}");
            }
            s.push('\n');
        }
        if !self.settlement_tests.is_empty() {
            let _ = writeln!(s, "## Settlement rewards against collusion\n");
            let _ = writeln!(s, "| test | what | pass | measured |\n|---|---|---|---|");
            for t in &self.settlement_tests {
                let _ = writeln!(
                    s,
                    "| {} | {} | {} | {} |",
                    t.number,
                    t.name,
                    if t.pass { "yes" } else { "NO" },
                    t.detail
                );
            }
            s.push('\n');
        }
        if !self.crash_tests.is_empty() {
            let _ = writeln!(s, "## Crash and reflexivity\n");
            let _ = writeln!(s, "| test | what | pass | measured |\n|---|---|---|---|");
            for t in &self.crash_tests {
                let _ = writeln!(
                    s,
                    "| {} | {} | {} | {} |",
                    t.number,
                    t.name,
                    if t.pass { "yes" } else { "NO" },
                    t.detail
                );
            }
            let _ = writeln!(s, "\n{}", self.crash_table);
        }
        if !self.staking_tests.is_empty() {
            let _ = writeln!(s, "## Issuance target, security ratio and cold start\n");
            let _ = writeln!(s, "| test | what | pass | measured |\n|---|---|---|---|");
            for t in &self.staking_tests {
                let _ = writeln!(
                    s,
                    "| {} | {} | {} | {} |",
                    t.number,
                    t.name,
                    if t.pass { "yes" } else { "NO" },
                    t.detail
                );
            }
            s.push('\n');
        }
        if !self.design_tests.is_empty() {
            let _ = writeln!(
                s,
                "## Fee design and machine-economy models (machine-only demand; tests from 101 are the machine-economy scenarios)\n"
            );
            let _ = writeln!(s, "| test | what | pass | measured |\n|---|---|---|---|");
            for t in &self.design_tests {
                let _ = writeln!(
                    s,
                    "| {} | {} | {} | {} |",
                    t.number,
                    t.name,
                    if t.pass { "yes" } else { "NO" },
                    t.detail
                );
            }
            let _ = writeln!(
                s,
                "\n| agents | fees USD/yr | first day burn > mint | price after horizon | cost to a third USD |\n|---|---|---|---|---|"
            );
            for e in &self.design_equilibrium {
                let _ = writeln!(
                    s,
                    "| {} | {} | {} | {} | {} |",
                    num(e.agents),
                    num(e.fees_usd_year),
                    e.day_burn_exceeds_mint
                        .map(|d| d.to_string())
                        .unwrap_or_else(|| "not within horizon".into()),
                    num(e.price_end),
                    num(e.coc_end_usd)
                );
            }
            s.push('\n');
        }
        if !self.spam.is_empty() {
            let _ = writeln!(s, "## Spam at real block time\n");
            let _ = writeln!(
                s,
                "| spam / target | seconds | cost USD | transfer fee start USD | end USD | honest left out |\n|---|---|---|---|---|---|"
            );
            for l in &self.spam {
                let _ = writeln!(
                    s,
                    "| {:.2} | {:.0} | {} | {} | {} | {} |",
                    l.spam_of_target,
                    l.seconds,
                    num(l.cost_usd),
                    num(l.transfer_fee_start_usd),
                    num(l.transfer_fee_end_usd),
                    l.honest_left_out
                );
            }
        }
        s
    }
}

/// A number for a table.
pub fn num(x: f64) -> String {
    if !x.is_finite() {
        return "-".into();
    }
    let a = x.abs();
    if a == 0.0 {
        "0".into()
    } else if a >= 1e6 {
        format!("{:.3e}", x)
    } else if a >= 100.0 {
        format!("{:.0}", x)
    } else if a >= 1.0 {
        format!("{:.2}", x)
    } else if a >= 1e-3 {
        format!("{:.4}", x)
    } else {
        format!("{:.2e}", x)
    }
}
