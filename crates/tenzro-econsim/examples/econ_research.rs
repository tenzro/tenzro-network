//! Funding-mechanism study: runs the chaos defaults with changed assumptions
//! or governed parameters and prints how the validator floor and the
//! treasury's stable holdings behave.
//! usage: econ_research LABEL YEARS SEED [k=v,..assume] [k=v,..params]
use tenzro_econsim::chaos::{self, Settings};
use tenzro_econsim::economy::Economy;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let label = &a[1];
    let years: f64 = a[2].parse().unwrap();
    let seed: u64 = a[3].parse().unwrap();
    let mut s = Settings::new(years);
    if let Some(list) = a.get(4).filter(|x| !x.is_empty()) {
        s.base.assumptions.apply_list(list).expect("assume");
    }
    if let Some(list) = a.get(5).filter(|x| !x.is_empty()) {
        for kv in list.split(",") {
            let (k, v) = kv.split_once("=").expect("k=v");
            s.base.network_params.insert(k.into(), v.parse().unwrap());
        }
    }
    if s.base.assumptions.sponsor_gated {
        s.govern_sponsorship();
    }
    let c = s.config(seed);
    let plan = c.chaos.clone().unwrap();
    let mut l = s.limits.clone();
    l.validators_floor = l.validators_floor.min(c.assumptions.validators);
    let o = Economy::new(c).run();
    let r = chaos::measure(seed, &plan, &o, &l);
    let d = o.days.last().unwrap();
    let max_stable = o
        .days
        .iter()
        .map(|d| d.treasury_stable_usd)
        .fold(0.0, f64::max);
    let unrel: f64 = o.days.iter().map(|d| d.unrelated_demand_usd_day).sum();
    println!(
        "{label}: pass={} broken={:?} floor_miss={:?} vmin={} sponsoredUSD={:.0} sponsoredTNZO={:.0} stableLegsUSD={:.0} stableMaxUSD={:.0} stableEndUSD={:.0} paidUSD={:.0} revYr={:.0} priceEnd={:.4} treasuryEnd={:.0} reserveRunway={:.1} costPaid={:.0} given={:.0} coverReserve={:.0} coverPaid={:.0}",
        r.pass,
        r.broken,
        r.floor_first_miss_day,
        r.validators_min,
        d.sponsored_usd_total,
        d.sponsored_tnzo_total,
        d.stable_legs_usd_total,
        max_stable,
        d.treasury_stable_usd,
        unrel,
        d.revenue_usd_year,
        d.price_usd,
        d.snap.treasury,
        d.reserve_runway_months,
        d.running_costs_paid_usd_total,
        d.stable_given_usd,
        d.cover_reserve_usd,
        d.cover_paid_usd_total
    );
    let mut rf: Vec<_> = o.refusals.iter().collect();
    rf.sort_by_key(|(_, n)| std::cmp::Reverse(**n));
    for (k, n) in rf.iter().take(14) {
        println!("  refused {n}x {}", &k[..k.len().min(160)]);
    }
    if std::env::var("DAILY").is_ok() {
        for (i, d) in o.days.iter().enumerate().filter(|(i, _)| i % 15 == 0) {
            println!(
                "  day {i}: val={} price={:.4} stable={:.0} legs={:.0} unrel/day={:.0} spUSD={:.0} spTNZO={:.0} treasury={:.0} reserve={:.0} cover={:.0} coverPaid={:.0}",
                d.snap.bonded_validators,
                d.price_usd,
                d.treasury_stable_usd,
                d.stable_legs_usd_total,
                d.unrelated_demand_usd_day,
                d.sponsored_usd_total,
                d.sponsored_tnzo_total,
                d.snap.treasury,
                d.snap.reserve,
                d.cover_reserve_usd,
                d.cover_paid_usd_total
            );
        }
    }
}
