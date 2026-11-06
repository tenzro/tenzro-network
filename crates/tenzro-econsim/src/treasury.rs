//! The running-cost reserve from a zero or tiny seed: runs across adoption
//! levels, a revenue drought and a price crash, on a thin market with an
//! empty treasury and no raised funds.
//!
//! Each run reports, within its own simulated span only: what share of the
//! asked running costs was paid, when the reserve first reached its
//! on-chain target, the reserve's months of asked costs at the end, the
//! reserve's sales as a share of the pool's traded volume, and any rule the
//! chain broke.

use serde::Serialize;

use crate::economy::{Economy, Market, RunConfig, RunOutcome};

/// One scenario.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Case {
    /// Name in the table.
    pub name: &'static str,
    /// Compute bought per day at launch, USD.
    pub compute_usd_per_day: f64,
    /// Day from which agents stop renting compute: a revenue drought.
    pub drought_day: Option<u32>,
    /// A one-off price move: (day, factor).
    pub shock: Option<(u32, f64)>,
}

/// The scenarios: low, medium and high adoption on a flat market, then the
/// medium case through a drought and through a 90% price crash.
pub fn cases(days: u32) -> Vec<Case> {
    let mid = days / 4;
    vec![
        Case {
            name: "low adoption",
            compute_usd_per_day: 500.0,
            drought_day: None,
            shock: None,
        },
        Case {
            name: "medium adoption",
            compute_usd_per_day: 5_000.0,
            drought_day: None,
            shock: None,
        },
        Case {
            name: "high adoption",
            compute_usd_per_day: 50_000.0,
            drought_day: None,
            shock: None,
        },
        Case {
            name: "revenue drought",
            compute_usd_per_day: 5_000.0,
            drought_day: Some(mid),
            shock: None,
        },
        Case {
            name: "price crash",
            compute_usd_per_day: 5_000.0,
            drought_day: None,
            shock: Some((mid, 0.1)),
        },
    ]
}

/// The two launches: nothing at all, and a tiny reserve seed.
pub const SEEDS_TNZO: [f64; 2] = [0.0, 100_000.0];

/// One run's measures.
#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    pub case: String,
    pub reserve_seed_tnzo: f64,
    pub days: u32,
    /// Asked running costs paid over the whole run, share.
    pub cost_coverage: f64,
    /// Same, over the last 30 days.
    pub cost_coverage_last_30d: f64,
    /// First day the reserve held its on-chain target (a target above zero).
    pub reserve_fill_day: Option<f64>,
    /// First day the trailing 30 days paid the asked running costs in full.
    pub full_cover_day: Option<f64>,
    /// Reserve at the end, TNZO.
    pub reserve_end_tnzo: f64,
    /// Reserve at the end, months of asked running costs at the end price.
    pub reserve_runway_end_months: f64,
    /// Reserve sales over the run as a share of the pool's traded volume.
    pub sale_share_of_volume: f64,
    /// Largest one-day share of the reserve's sales in the day's volume.
    pub sale_share_max_day: f64,
    /// Largest one-day share of the reserve's payouts (what the chain
    /// released) in the day's volume.
    pub release_share_max_day: f64,
    /// Price at the end, USD.
    pub price_end_usd: f64,
    /// Days the sale cap allowed any payout.
    pub sale_cap_days: u32,
    /// Last day the sale cap allowed any payout.
    pub last_sale_cap_day: Option<f64>,
    /// Validators bonded at the end.
    pub validators_end: u32,
    /// Running costs enacted and still unpaid at the end, TNZO.
    pub owed_end_tnzo: f64,
    /// Most frequent refused transactions, by reason.
    pub top_refusals: Vec<(String, u64)>,
    /// Rules broken: reserve rules, value conservation, failed block duties.
    pub invariant_breaks: Vec<String>,
    pub wall_s: f64,
}

/// The configuration of one run.
pub fn config(case: &Case, seed_tnzo: f64, days: u32, seed: u64, ask_usd_month: f64) -> RunConfig {
    let mut c = RunConfig::scenario(Market::Flat, seed, days);
    let a = &mut c.assumptions;
    a.compute_usd_per_day = case.compute_usd_per_day;
    a.reserve_seed_tnzo = seed_tnzo;
    a.running_cost_ask_usd_month = ask_usd_month;
    // Nothing raised, nothing set aside: an empty treasury, no owned
    // liquidity, no treasury stake, a thin third-party pool.
    a.treasury_genesis_tnzo = 0.0;
    a.pol_usd = 0.0;
    a.treasury_stake_tnzo = 0.0;
    a.pool_depth_usd = 50_000.0;
    c.agents_leave_day = case.drought_day;
    c.shock = case.shock;
    c
}

/// Measures one finished run.
pub fn measure(case: &Case, seed_tnzo: f64, o: &RunOutcome) -> CaseResult {
    let days = &o.days;
    let (mut paid, mut asked, mut sold, mut volume, mut max_share) = (0.0, 0.0, 0.0, 0.0, 0.0f64);
    let mut max_release = 0.0f64;
    let mut fill = None;
    let mut cover = None;
    for d in days {
        sold += d.reserve_sold_tnzo;
        volume += d.volume_tnzo;
        if d.volume_tnzo > 0.0 {
            max_share = max_share.max(d.reserve_sold_tnzo / d.volume_tnzo);
            max_release = max_release.max(d.reserve_paid_tnzo / d.volume_tnzo);
        }
        if fill.is_none() && d.reserve_target_tnzo > 0.0 && d.snap.reserve >= d.reserve_target_tnzo
        {
            fill = Some(d.snap.day);
        }
        if cover.is_none()
            && d.snap.day >= 30.0
            && d.running_costs_asked_usd_30d > 0.0
            && d.running_costs_paid_usd_30d >= 0.999 * d.running_costs_asked_usd_30d
        {
            cover = Some(d.snap.day);
        }
    }
    if let Some(d) = days.last() {
        paid = d.running_costs_paid_usd_total;
        asked = d.running_costs_asked_usd_total;
    }
    let last = days.last();
    let mut refusals: Vec<(String, u64)> =
        o.refusals.iter().map(|(k, v)| (k.clone(), *v)).collect();
    refusals.sort_by_key(|r| std::cmp::Reverse(r.1));
    refusals.truncate(12);
    let mut breaks = o.reserve_breaks.clone();
    breaks.extend(o.ledger_failures.iter().cloned());
    CaseResult {
        case: case.name.to_string(),
        reserve_seed_tnzo: seed_tnzo,
        days: days.len() as u32,
        cost_coverage: if asked > 0.0 {
            (paid / asked).min(1.0)
        } else {
            0.0
        },
        cost_coverage_last_30d: last
            .filter(|d| d.running_costs_asked_usd_30d > 0.0)
            .map(|d| (d.running_costs_paid_usd_30d / d.running_costs_asked_usd_30d).min(1.0))
            .unwrap_or(0.0),
        reserve_fill_day: fill,
        full_cover_day: cover,
        reserve_end_tnzo: last.map(|d| d.snap.reserve).unwrap_or(0.0),
        reserve_runway_end_months: last.map(|d| d.reserve_runway_months).unwrap_or(0.0),
        sale_share_of_volume: if volume > 0.0 { sold / volume } else { 0.0 },
        sale_share_max_day: max_share,
        release_share_max_day: max_release,
        price_end_usd: last.map(|d| d.price_usd).unwrap_or(0.0),
        sale_cap_days: days.iter().filter(|d| d.sale_cap_epoch_tnzo > 0.0).count() as u32,
        last_sale_cap_day: days
            .iter()
            .rev()
            .find(|d| d.sale_cap_epoch_tnzo > 0.0)
            .map(|d| d.snap.day),
        validators_end: last.map(|d| d.snap.bonded_validators).unwrap_or(0),
        owed_end_tnzo: last.map(|d| d.running_costs_owed_tnzo).unwrap_or(0.0),
        top_refusals: refusals,
        invariant_breaks: breaks,
        wall_s: o.wall_s,
    }
}

/// Runs every case from every seed, `threads` at a time.
pub fn study(
    days: u32,
    seed: u64,
    threads: usize,
    only: Option<&str>,
    ask_usd_month: f64,
) -> Vec<CaseResult> {
    let mut jobs = Vec::new();
    for case in cases(days)
        .into_iter()
        .filter(|c| only.is_none_or(|o| c.name.contains(o)))
    {
        for s in SEEDS_TNZO {
            jobs.push((case, s));
        }
    }
    let jobs = std::sync::Mutex::new(jobs.into_iter().enumerate().collect::<Vec<_>>());
    let out = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|sc| {
        for _ in 0..threads.max(1) {
            sc.spawn(|| {
                loop {
                    let Some((i, (case, s))) = jobs.lock().expect("jobs").pop() else {
                        break;
                    };
                    let o = Economy::new(config(&case, s, days, seed, ask_usd_month)).run();
                    let r = measure(&case, s, &o);
                    eprintln!(
                        "{} seed {} TNZO: coverage {:.3}, breaks {}, {:.0}s",
                        r.case,
                        r.reserve_seed_tnzo,
                        r.cost_coverage,
                        r.invariant_breaks.len(),
                        r.wall_s
                    );
                    out.lock().expect("out").push((i, r));
                }
            });
        }
    });
    let mut v = out.into_inner().expect("out");
    v.sort_by_key(|(i, _)| *i);
    v.into_iter().map(|(_, r)| r).collect()
}

fn opt_day(d: Option<f64>) -> String {
    d.map(|d| format!("{d:.0}"))
        .unwrap_or_else(|| "not within run".into())
}

/// The results as a Markdown table.
pub fn table(results: &[CaseResult]) -> String {
    let mut s = String::from(
        "| case | reserve seed TNZO | days | costs paid (run) | costs paid (last 30 d) | reserve at target from day | costs fully paid from day | reserve end TNZO | reserve end, months of asked costs | sales / traded volume (run) | worst day sold | worst day released | price end USD | invariant breaks |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n",
    );
    for r in results {
        s.push_str(&format!(
            "| {} | {:.0} | {} | {:.1}% | {:.1}% | {} | {} | {:.0} | {:.2} | {:.2}% | {:.2}% | {:.2}% | {:.4} | {} |\n",
            r.case,
            r.reserve_seed_tnzo,
            r.days,
            100.0 * r.cost_coverage,
            100.0 * r.cost_coverage_last_30d,
            opt_day(r.reserve_fill_day),
            opt_day(r.full_cover_day),
            r.reserve_end_tnzo,
            r.reserve_runway_end_months,
            100.0 * r.sale_share_of_volume,
            100.0 * r.sale_share_max_day,
            100.0 * r.release_share_max_day,
            r.price_end_usd,
            r.invariant_breaks.len(),
        ));
    }
    s
}
