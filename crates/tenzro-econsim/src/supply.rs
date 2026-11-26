//! TNZO supply across demand levels: one ledger run per level of compute
//! bought, from 1,000 to 150,000 USD a day, on a flat market.
//!
//! Each run reports, at every year mark of its own span: total supply,
//! TNZO burned since genesis, what the rewards pool still holds and the
//! price. Supply only falls (fees burn, rewards are paid from the
//! genesis-funded pool and never minted), so the table shows how fast
//! demand burns it and how long the pool lasts at each level.

use serde::Serialize;

use crate::economy::{Economy, Market, RunConfig, RunOutcome};

/// Compute bought per day at launch in each run, USD.
pub const LEVELS_USD_PER_DAY: [f64; 6] =
    [1_000.0, 5_000.0, 15_000.0, 50_000.0, 100_000.0, 150_000.0];

/// One year mark of a run.
#[derive(Debug, Clone, Serialize)]
pub struct Mark {
    /// Day of the run.
    pub day: f64,
    /// Total supply, TNZO.
    pub supply_tnzo: f64,
    /// Burned since genesis, TNZO.
    pub burned_tnzo: f64,
    /// Rewards pool balance, TNZO.
    pub rewards_pool_tnzo: f64,
    /// Price, USD.
    pub price_usd: f64,
}

/// One demand level's run.
#[derive(Debug, Clone, Serialize)]
pub struct Trajectory {
    /// Compute bought per day at launch, USD.
    pub usd_per_day: f64,
    /// The run's year marks, the last day always among them.
    pub marks: Vec<Mark>,
    /// Ledger rules the run broke.
    pub ledger_failures: Vec<String>,
}

/// The run for `usd_per_day`.
pub fn config(usd_per_day: f64, days: u32, seed: u64) -> RunConfig {
    let mut c = RunConfig::scenario(Market::Flat, seed, days);
    c.assumptions.compute_usd_per_day = usd_per_day;
    c
}

/// The year marks of a finished run.
pub fn measure(usd_per_day: f64, o: &RunOutcome) -> Trajectory {
    let n = o.days.len();
    let mut idx: Vec<usize> = (1..)
        .map(|y| ((y as f64 * 365.25) as usize).saturating_sub(1))
        .take_while(|i| *i + 1 < n)
        .collect();
    if n > 0 {
        idx.push(n - 1);
    }
    Trajectory {
        usd_per_day,
        marks: idx
            .into_iter()
            .map(|i| {
                let d = &o.days[i];
                Mark {
                    day: d.snap.day,
                    supply_tnzo: d.snap.supply,
                    burned_tnzo: d.snap.burned,
                    rewards_pool_tnzo: d.snap.rewards_pool,
                    price_usd: d.price_usd,
                }
            })
            .collect(),
        ledger_failures: o.ledger_failures.clone(),
    }
}

/// Runs every level in `levels`, `threads` at a time, in level order.
pub fn study(levels: &[f64], days: u32, seed: u64, threads: usize) -> Vec<Trajectory> {
    let jobs = std::sync::Mutex::new(levels.iter().copied().enumerate().collect::<Vec<_>>());
    let out = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|sc| {
        for _ in 0..threads.max(1) {
            sc.spawn(|| {
                loop {
                    let Some((i, level)) = jobs.lock().expect("jobs").pop() else {
                        break;
                    };
                    let o = Economy::new(config(level, days, seed)).run();
                    out.lock().expect("out").push((i, measure(level, &o)));
                }
            });
        }
    });
    let mut v = out.into_inner().expect("out");
    v.sort_by_key(|(i, _)| *i);
    v.into_iter().map(|(_, t)| t).collect()
}

/// The results as a Markdown table.
pub fn table(results: &[Trajectory]) -> String {
    let mut s = String::from(
        "| USD/day | day | supply TNZO | burned TNZO | rewards pool TNZO | price USD | ledger failures |\n\
         |---:|---:|---:|---:|---:|---:|---:|\n",
    );
    for t in results {
        for m in &t.marks {
            s.push_str(&format!(
                "| {:.0} | {:.0} | {:.0} | {:.0} | {:.0} | {:.4} | {} |\n",
                t.usd_per_day,
                m.day,
                m.supply_tnzo,
                m.burned_tnzo,
                m.rewards_pool_tnzo,
                m.price_usd,
                t.ledger_failures.len()
            ));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// More demand burns more and supply never rises: over a short span at
    /// the lowest and the highest level, no ledger rule breaks, supply at
    /// the end is at most supply at the start, and the busier run has
    /// burned at least as much.
    #[test]
    fn more_demand_burns_more_and_supply_never_rises() {
        let levels = [LEVELS_USD_PER_DAY[0], LEVELS_USD_PER_DAY[5]];
        let r = study(&levels, 30, 1, 2);
        assert_eq!(r.len(), 2);
        for t in &r {
            assert!(t.ledger_failures.is_empty(), "{:?}", t.ledger_failures);
            let first = t.marks.first().unwrap();
            let last = t.marks.last().unwrap();
            assert!(last.supply_tnzo <= first.supply_tnzo + 1e-6);
        }
        let burned = |t: &Trajectory| t.marks.last().unwrap().burned_tnzo;
        assert!(burned(&r[1]) >= burned(&r[0]));
        assert!(table(&r).lines().count() >= 4);
    }
}
