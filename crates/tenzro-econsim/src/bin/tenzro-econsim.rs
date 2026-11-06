//! Runs the economic simulation and writes its report.
//!
//! ```text
//! tenzro-econsim all --out DIR [--commit SHA] [--budget-s S] [--threads N] [--scenario-threads N]
//!                    [--years Y] [--seeds S] [--ablation-days D] [--ablation-seeds S]
//!                    [--cartel-days D] [--cartel-step F] [--dex-seeds S] [--dex-days D]
//!                    [--morris R] [--sobol-top K] [--sobol-n N] [--gsa-days D]
//!                    [--search-days D] [--restarts N] [--generations G] [--per-gen P]
//!                    [--spam-blocks B]
//! tenzro-econsim eval [--threads N] [--factors]   (JSON lines in, JSON lines out)
//! tenzro-econsim one --market growth|flat|downturn --days D --seed S [--daily CSV] [--assume k=v,..] [--params k=v,..]
//! tenzro-econsim attack --family F --days D [--restarts N] [--generations G] [--per-gen P]
//!                       [--assume k=v,..] [--params k=v,..]
//! tenzro-econsim probes [--days D] [--seed S] [--threads N]
//! tenzro-econsim settlement [--threads N]
//! tenzro-econsim hwlevels [--seed S] [--epochs E] [--mix L0,L1,L2,L3] [--cap BPS] [--arrivals N] [--every K]
//! tenzro-econsim treasury --days D [--seed S] [--threads N] [--out DIR] [--case NAME] [--ask USD_MONTH]
//! tenzro-econsim admission [--seconds S] [--defaults 1 --blocks B --price USD]
//! tenzro-econsim population --seed S --actors N --hours H --scenario NAME --out FILE
//! tenzro-econsim agents --mode record|replay|live-probe --cache FILE --out DIR
//!                       --models ID=HASH[,ID=HASH] [--templates lines-1,json-1,prose-1]
//!                       [--market M] [--days D] [--seed S] [--agents K] [--probe-per-mille N]
//!                       [--cli PATH --rpc URL [--agent-rpc URL --channel HEX
//!                        --ceiling-wei N --spent-wei N]]
//! ```
//!
//! `all` writes report.json, report.md and verdict.json into DIR and exits
//! 0 on PASS or WARN, 1 on FAIL.

use std::collections::HashMap;
use std::path::PathBuf;

use tenzro_econsim::economy::{Market, RunConfig};
use tenzro_econsim::gsa;
use tenzro_econsim::report::{Report, summarise};
use tenzro_econsim::search;
use tenzro_econsim::spam;

fn args() -> (String, HashMap<String, String>) {
    let mut it = std::env::args().skip(1);
    let cmd = it.next().unwrap_or_else(|| "all".into());
    let mut m = HashMap::new();
    while let Some(k) = it.next() {
        if let Some(k) = k.strip_prefix("--") {
            m.insert(k.to_string(), it.next().unwrap_or_default());
        }
    }
    (cmd, m)
}

fn get<T: std::str::FromStr>(m: &HashMap<String, String>, k: &str, d: T) -> T {
    m.get(k).and_then(|v| v.parse().ok()).unwrap_or(d)
}

const USAGE: &str = "\
tenzro-econsim usage [--lw DIR | --manifest F --trace F] [--days D] [--threads N] [--out DIR] [--write-sample DIR]
tenzro-econsim all --out DIR [--commit SHA] [--budget-s S] [--threads N] [--scenario-threads N]
                   [--years Y] [--seeds S] [--ablation-days D] [--ablation-seeds S]
                   [--cartel-days D] [--cartel-step F] [--dex-seeds S] [--dex-days D]
                   [--morris R] [--sobol-top K] [--sobol-n N] [--gsa-days D]
                   [--search-days D] [--restarts N] [--generations G] [--per-gen P]
                   [--spam-blocks B]
tenzro-econsim eval [--threads N] [--factors]   (JSON lines in, JSON lines out)
tenzro-econsim one --market growth|flat|downturn --days D --seed S [--daily CSV] [--assume k=v,..] [--params k=v,..]
tenzro-econsim attack --family F --days D [--restarts N] [--generations G] [--per-gen P]
                      [--assume k=v,..] [--params k=v,..]
tenzro-econsim probes [--days D] [--seed S] [--threads N]
tenzro-econsim settlement [--threads N]
tenzro-econsim treasury --days D [--seed S] [--threads N] [--out DIR] [--case NAME] [--ask USD_MONTH]
tenzro-econsim earnings [--days D] [--seed S] [--out DIR]   (spot/standby/readiness-reward sweep)
tenzro-econsim admission [--seconds S] [--defaults 1 --blocks B --price USD]
tenzro-econsim population --seed S --actors N --hours H --scenario calm|outage|defect|surge|reprice|stress|adversarial --out FILE
                      (writes a market trace: POPULATION_TRACE_CMD for scripts/testnet/stages.sh's stage_population)
tenzro-econsim agents --mode record|replay|live-probe --cache FILE --out DIR
                      --models ID=HASH[,ID=HASH] [--templates lines-1,json-1,prose-1]
                      [--market M] [--days D] [--seed S] [--agents K] [--probe-per-mille N]
                      [--cli PATH --rpc URL [--agent-rpc URL --channel HEX
                       --ceiling-wei N --spent-wei N]]

With no subcommand or an unrecognized one, runs the full `all` sweep. Use
-h / --help / help with no other arguments to print this instead.
";

const ONE_HELP: &str = "\
tenzro-econsim one: one economy run; prints the last day, refusals and failures as JSON.

  --market growth|flat|downturn   market path (default flat)
  --days D                        simulated days (default 30)
  --seed S                        seed (default 1)
  --assume k=v,..                 assumptions; preset=default|realistic sets them all
                                  first, wherever it is in the list; only the last
                                  --assume flag counts
  --params k=v,..                 governed parameters at genesis
  --daily CSV                     write the daily price, chain rate and transfer fee
  --trace FILE                    demand from a population market trace (JSON lines)
  --trace-days D                  calendar days the trace's span is laid over (default 720)
  --streams N                     sampled compute streams (default 16)
  --sla 0|1                       validators attest SLA outcomes (default 1)

Assumptions added for launch decisions (all off or unchanged by default):
  max_price_to_revenue  fully diluted value at most this multiple of annualised fee revenue
  max_fdv_usd           fully diluted value cap, USD
  fdv_stress_year1      share of the launch value lost over year one (0.7: -70%)
  staking_ratio         share of circulating supply bonded at genesis (0: about 0.5% of supply)
  validator_commission  share of delegated rewards a validator keeps
  validator_cost_usd_month, validator_exit_yield, provider_hours_per_day,
  provider_sell_share, compute_usd_per_day, agent_tasks_per_day,
  demand_growth_per_year, running_cost_ask_usd_month
  stable_settlement     1: payments settle in a stable unit, TNZO pays fees, gas and bonds
  stable_asset          1: that stable unit is a token on the ledger: escrows and payments
                        to providers in it; the treasury leg charged in TNZO as the VM does
  stable_leg            1: the treasury leg of a stable payment is taken in the token
                        (implies stable_asset)
  treasury_sellback     1: governance grants the treasury's TNZO above
                        sellback_target_tnzo (default 50M) to a desk each month, within
                        the treasury's outflow limits; the desk sells at most
                        sellback_max_tnzo_day (default 1M) a day
  closed_phase          1: before a listing: stable token with the leg in it, no public TNZO market,
                        owner-funded running costs, validators contracted in USD; the
                        output adds the day each listing-gate item is first met
  anchor_share          share of the demand that is related-party anchor demand
  preset=closed         the realistic preset in the closed phase";

/// Year-end figures of one run: price, treasury, runways, profitability,
/// validators, attack cost and burn.
fn yearly(o: &tenzro_econsim::economy::RunOutcome) -> Vec<serde_json::Value> {
    let n = o.days.len();
    let mut marks: Vec<usize> = (1..)
        .map(|y| ((y as f64 * 365.25) as usize).min(n).saturating_sub(1))
        .take_while(|i| *i + 1 < n)
        .collect();
    if n > 0 {
        marks.push(n - 1);
    }
    marks.dedup();
    marks
        .into_iter()
        .map(|i| {
            let d = &o.days[i];
            serde_json::json!({
                "day": d.snap.day,
                "price_usd": d.price_usd,
                "fdv_usd": d.fdv_usd,
                "price_ceiling_usd": d.price_ceiling_usd,
                "revenue_usd_year": d.revenue_usd_year,
                "treasury_tnzo": d.snap.treasury,
                "treasury_runway_months": d.treasury_runway_months.min(1_200.0),
                "reserve_tnzo": d.snap.reserve,
                "reserve_runway_months": d.reserve_runway_months.min(1_200.0),
                "providers": d.providers,
                "providers_profitable": d.providers_profitable,
                "validators_profitable": d.validators_profitable,
                "bonded_validators": d.snap.bonded_validators,
                "staking_ratio": d.staking_ratio,
                "staking_ratio_circulating": d.staking_ratio_circulating,
                "attack_cost_usd": d.attack_cost_usd,
                "attack_cost_pool_usd": d.attack_cost_pool_usd,
                "burned_tnzo": d.snap.burned,
                "outside_float_tnzo": d.outside_float_tnzo,
                "held_by": d.held_by,
                "supply_tnzo": d.snap.supply,
                "treasury_tnzo_now": d.snap.treasury,
                "insurance_pool_tnzo": d.snap.insurance_pool,
                "rewards_pool_tnzo": d.snap.rewards_pool,
                "bonded_tnzo": d.snap.bonded,
                "running_costs_paid_usd_30d": d.running_costs_paid_usd_30d,
                "running_costs_asked_usd_30d": d.running_costs_asked_usd_30d,
                "unrelated_demand_usd_day": d.unrelated_demand_usd_day,
                "validator_fee_income_usd_30d": d.validator_fee_income_usd_30d,
                "validator_cost_usd_30d": d.validator_cost_usd_30d,
                "treasury_stable_usd": d.treasury_stable_usd,
                "stable_legs_usd_total": d.stable_legs_usd_total,
                "stable_outside_usd": d.stable_outside_usd,
                "sellback_sold_tnzo_total": d.sellback_sold_tnzo_total,
            })
        })
        .collect()
}

/// The machine-economy loop: a base run, the run without related-party
/// demand, the demand threshold, failure modes and the price frontier.
fn growth(m: &HashMap<String, String>) {
    use tenzro_econsim::growth::{self as g, GrowthInputs};
    let mut base = GrowthInputs {
        days: get(m, "days", 3652),
        potential_usd_day: get(m, "potential", 50_000.0),
        potential_growth: get(m, "potential-growth", 2.0),
        tariff: get(m, "tariff", 1.0),
        owner_swarm_usd_day: get(m, "swarm", 5_000.0),
        bootstrap_days: get(m, "boot-days", 730.0),
        running_cost_usd_month: get(m, "running-cost", 200_000.0),
        ..GrowthInputs::default()
    };
    if let Some(x) = m
        .get("mtok-per-gpu-hour")
        .and_then(|v| v.parse::<f64>().ok())
    {
        for c in &mut base.classes {
            if c.class == g::Class::Inference {
                c.units_per_provider_day = x * 24.0;
            }
        }
    }
    if m.contains_key("harness") {
        base.harness = Some(g::Harness::default());
    }
    if let Some(r) = m.get("related").and_then(|v| v.parse::<f64>().ok()) {
        for ch in &mut base.channels {
            if ch.related_share > 0.0 {
                ch.related_share = r;
            }
        }
    }
    apply_package(&mut base, m);
    let mut trace_note = serde_json::Value::Null;
    if let Some(path) = m.get("trace") {
        let t = tenzro_econsim::trace::TraceDemand::load(path, get(m, "trace-days", 720.0))
            .unwrap_or_else(|e| {
                eprintln!("--trace: {e}");
                std::process::exit(2)
            });
        base.potential_usd_day = t.payments_per_day * t.mean_usd;
        trace_note = serde_json::json!({
            "source": t.source, "payments_per_day": t.payments_per_day,
            "mean_usd": t.mean_usd, "delivered_share": t.delivered_share,
            "service_share": t.service_share,
        });
    }
    let without_related = {
        let mut i = base.clone();
        for ch in &mut i.channels {
            ch.related_share = 0.0;
        }
        g::run(&i)
    };
    let unrelated_only = {
        let mut i = base.clone();
        i.channels.retain(|ch| ch.related_share == 0.0);
        g::run(&i)
    };
    let mode = |f: &dyn Fn(&mut GrowthInputs)| {
        let mut i = base.clone();
        f(&mut i);
        g::run(&i)
    };
    let frontier = g::frontier(&base);
    let best = frontier
        .iter()
        .find(|p| p.providers_profitable && p.platforms_profitable)
        .cloned();
    let at_current = frontier
        .iter()
        .find(|p| {
            p.tariff == 1.0
                && p.take_inference == 0.10
                && p.take_compute == 0.10
                && p.commission == 0.15
        })
        .cloned();
    // Each class's place in the per-class figures.
    let place = |c: g::Class| base.classes.iter().position(|x| x.class == c);
    let (k_pi, k_jetson, k_agx, k_rtx) = (
        place(g::Class::Edge),
        place(g::Class::EdgeGpu),
        place(g::Class::EdgeAgx),
        place(g::Class::ConsumerGpu),
    );
    let edge_by_demand: Vec<serde_json::Value> = [
        1_000.0,
        10_000.0,
        50_000.0,
        200_000.0,
        1_000_000.0,
        10_000_000.0,
    ]
    .iter()
    .map(|d| {
        let r = mode(&|i| i.potential_usd_day = *d);
        let at = |y: usize| {
            r.years.get(y).map(|p| {
                serde_json::json!({
                    "year": p.year,
                    "pi_devices": k_pi.and_then(|k| p.providers.get(k)),
                    "pi_profitable_share": k_pi.and_then(|k| p.profitable_share.get(k)),
                    "pi_margin_usd_month": k_pi.and_then(|k| p.margin_usd_month.get(k)),
                    "pi_break_even_slots_day": p.edge_break_even_slots,
                    "jetson_devices": k_jetson.and_then(|k| p.providers.get(k)),
                    "jetson_profitable_share": k_jetson.and_then(|k| p.profitable_share.get(k)),
                    "jetson_margin_usd_month": k_jetson.and_then(|k| p.margin_usd_month.get(k)),
                    "jetson_break_even_slots_day": p.edge_gpu_break_even_slots,
                    "agx_devices": k_agx.and_then(|k| p.providers.get(k)),
                    "agx_profitable_share": k_agx.and_then(|k| p.profitable_share.get(k)),
                    "agx_margin_usd_month": k_agx.and_then(|k| p.margin_usd_month.get(k)),
                    "agx_break_even_slots_day": p.edge_agx_break_even_slots,
                    "rtx_devices": k_rtx.and_then(|k| p.providers.get(k)),
                    "rtx_profitable_share": k_rtx.and_then(|k| p.profitable_share.get(k)),
                    "rtx_margin_usd_month": k_rtx.and_then(|k| p.margin_usd_month.get(k)),
                })
            })
        };
        serde_json::json!({
            "potential_usd_day": d, "outcome": r.outcome,
            "year1": at(0), "year5": at(4), "year10": at(9),
        })
    })
    .collect();
    let threshold_without_swarm = {
        let mut i = base.clone();
        i.owner_swarm_usd_day = 0.0;
        g::threshold(&i, 100.0, 1e8)
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "inputs": base,
            "trace": trace_note,
            "base": g::run(&base),
            "consumer_all_unrelated": without_related,
            "without_consumer_platforms": unrelated_only,
            "threshold_potential_usd_day": g::threshold(&base, 100.0, 1e8),
            "threshold_without_swarm": threshold_without_swarm,
            "failure_thin_demand": mode(&|i| i.potential_usd_day = 1_000.0),
            "failure_price_above_alternatives": mode(&|i| i.tariff = 2.0),
            "failure_reward_farming": mode(&|i| {
                i.potential_usd_day = 0.0;
                i.farming_usd_day = 1_000_000.0;
            }),
            "edge_by_demand": edge_by_demand,
            "ladder": g::ladder(&base, &g::LadderInputs::default(), &[0.0, 0.3, 0.6, 0.8]),
            "ladder_inputs": g::LadderInputs::default(),
            "tiers": g::compare_tiers(&base),
            "frontier_best": best,
            "frontier_at_current_tariff": at_current,
            "frontier_top": frontier.iter().take(25).collect::<Vec<_>>(),
            "frontier_points": frontier.len(),
        }))
        .expect("json")
    );
}

/// The multi-tier scenarios with their pass rules: break-even surface,
/// price competitiveness, utilisation P&L, cold start, 30-year runs,
/// Sobol analysis and reseller concentration.
fn research(m: &HashMap<String, String>) {
    use tenzro_econsim::growth::{self as g, GrowthInputs, Harness};
    use tenzro_econsim::research as r;
    let mut base = GrowthInputs {
        harness: Some(Harness::default()),
        ..GrowthInputs::default()
    };
    if let Some(x) = m
        .get("mtok-per-gpu-hour")
        .and_then(|v| v.parse::<f64>().ok())
    {
        for c in &mut base.classes {
            if c.class == g::Class::Inference {
                c.units_per_provider_day = x * 24.0;
            }
        }
    }
    // The per-class take governance could set: inference 8%, the rest 5%.
    for c in &mut base.classes {
        c.take = if c.class == g::Class::Inference {
            0.08
        } else {
            0.05
        };
    }
    apply_package(&mut base, m);
    let surface = r::break_even_surface();
    let pick = |run: f64, take: f64| -> Vec<f64> {
        surface
            .iter()
            .filter(|p| p.running_cost_usd_month == run && p.take == take && p.deflation == 0.0)
            .map(|p| p.break_even_usd_day)
            .collect()
    };
    let span = |v: Vec<f64>| {
        let lo = v.iter().cloned().fold(f64::INFINITY, f64::min);
        let hi = v.iter().cloned().fold(0.0, f64::max);
        serde_json::json!([lo, hi])
    };
    let prices = r::price_competitiveness(0.10, 0.10);
    let prices_class = r::price_competitiveness(0.08, 0.10);
    let pnl = r::utilisation_pnl(0.10);
    let gpu60 = pnl
        .iter()
        .find(|p| p.tier.starts_with("GPU") && (p.utilisation - 0.6).abs() < 1e-9)
        .map(|p| p.margin);
    let cold = g::run(&GrowthInputs {
        potential_usd_day: 2_000.0,
        ..base.clone()
    });
    let n = get(m, "sobol-n", 256usize);
    // With the package set, its own settings stay fixed and the rest of
    // the inputs vary.
    let gsa = if m.contains_key("fix-package") {
        r::sobol_fixed(
            &base,
            n,
            21,
            &[
                "tariff",
                "take",
                "commission",
                "running_cost_usd_month",
                "hardware_charge",
                "root_task_fee_usd",
            ],
        )
    } else {
        r::sobol(&base, n, 21)
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "break_even": {
                "expected": "infra $7.5-12k/day at a 5-8% take; $42-67k/day at $100-200k/month",
                "infra_18k_take_5pct_usd_day": span(pick(18_000.0, 0.05)),
                "infra_18k_take_8pct_usd_day": span(pick(18_000.0, 0.08)),
                "staffed_100k_take_8pct_usd_day": span(pick(100_000.0, 0.08)),
                "staffed_200k_take_5pct_usd_day": span(pick(200_000.0, 0.05)),
                "surface": surface,
            },
            "price_competitiveness": {
                "rule": "buyer price below centralised for at least 4 of 6 workloads at 10% commission (a seventh, image generation, added)",
                "take_10pct": prices,
                "below_both_take_10pct": prices.iter().filter(|p| p.below_both).count(),
                "below_direct_take_10pct": prices.iter().filter(|p| p.below_direct).count(),
                "take_8pct": prices_class,
                "below_both_take_8pct": prices_class.iter().filter(|p| p.below_both).count(),
            },
            "utilisation_pnl": {
                "rule": "GPU margin at least 15% at 60% utilisation",
                "gpu_margin_at_60pct": gpu60,
                "pass": gpu60.is_some_and(|x| x >= 0.15),
                "tiers": pnl,
            },
            "cold_start_2k_usd_day": cold,
            "decades_30y": r::decades(&base),
            "sobol": gsa,
            "reseller_concentration": r::concentration(&base),
            "pi_levers": r::pi_levers(),
            "root_fee_checks": r::root_fee_checks(&[0.0001, 0.0005, 0.001]),
        }))
        .expect("json")
    );
}

/// Applies the price and take flags to a loop-model run: `--tariff`,
/// `--take-inference`, `--take-compute` (every other class), `--commission`
/// (channels that charge one) and `--running-cost`.
fn apply_package(i: &mut tenzro_econsim::growth::GrowthInputs, m: &HashMap<String, String>) {
    use tenzro_econsim::growth::Class;
    let f = |k: &str| m.get(k).and_then(|v| v.parse::<f64>().ok());
    if let Some(x) = f("tariff") {
        i.tariff = x;
    }
    if let Some(x) = f("running-cost") {
        i.running_cost_usd_month = x;
    }
    for c in &mut i.classes {
        let take = if c.class == Class::Inference {
            f("take-inference")
        } else {
            f("take-compute")
        };
        if let Some(x) = take {
            c.take = x;
        }
    }
    if let Some(x) = f("hardware-charge") {
        i.sunk_hardware = true;
        i.hardware_charge = x;
    }
    if let Some(x) = f("root-task-fee") {
        i.root_task_fee_usd = x;
    }
    if m.contains_key("sunk") {
        i.sunk_hardware = true;
    }
    if m.contains_key("fill-busy-first") {
        i.fill_busy_first = true;
    }
    if let Some(x) = f("commission") {
        for ch in &mut i.channels {
            if ch.commission > 0.0 {
                ch.commission = x;
            }
        }
    }
}

/// Applies `--assume` to a run's assumptions.
fn apply_assume(c: &mut RunConfig, m: &HashMap<String, String>) {
    if let Some(list) = m.get("assume")
        && let Err(e) = c.assumptions.apply_list(list)
    {
        eprintln!("--assume: {e}");
        std::process::exit(2);
    }
    if let Some(path) = m.get("trace") {
        match tenzro_econsim::trace::TraceDemand::load(path, get(m, "trace-days", 720.0)) {
            Ok(t) => c.assumptions.use_trace(t),
            Err(e) => {
                eprintln!("--trace: {e}");
                std::process::exit(2);
            }
        }
    }
}

/// Applies `--params` to a run's governed parameters at genesis.
fn apply_params(c: &mut RunConfig, m: &HashMap<String, String>) {
    for kv in m.get("params").map(String::as_str).unwrap_or("").split(',') {
        if let Some((k, v)) = kv.split_once('=') {
            c.network_params
                .insert(k.to_string(), v.parse().expect("parameter value"));
        }
    }
}

const CHAOS_HELP: &str = "\
tenzro-econsim chaos: combined and correlated shocks over decades on the economy's ledger,
many seeds; per-seed invariants, percentiles and the worst seeds.

  --seeds N           seeds to run (default 20000)
  --first S           first seed (default 1)
  --years Y           simulated years per seed (default 30)
  --market M          growth|flat|downturn (default flat)
  --assume k=v,..     assumptions on top of the realistic preset with stable settlement
  --params k=v,..     governed parameters at genesis
  --independent 1     draw every shock independently (no crash correlation)
  --humans N          sampled human transfers per block at most (default 1)
  --streams N         sampled compute streams open at once at most (default 2)
  --calm 1            no shocks: the same runs without any (a baseline)
  --rate-reports 0    validators do not report the rate (the governed rate holds)
  --cell I            run the inputs of sweep cell I (0-80; `central` for the middle cell)
  --sweep 1           every sweep cell (or --cell I alone) times --seeds seeds; DIR/sweep.jsonl,
                      sweep.json and sweep.md: the cells where every invariant held; with
                      --replay SEED --cell I, compare with the line in DIR/sweep.jsonl
  --threads T         worker threads (default: every core)
  --worst W           worst seeds listed (default 20)
  --out DIR           seeds.jsonl (one line per seed, appended as each finishes; seeds
                      already there are skipped), summary.json and summary.md
  --replay SEED       run one seed and print its result line; with --out, compare it with
                      the line in DIR/seeds.jsonl";

fn chaos_cell(c: &str) -> tenzro_econsim::chaos::Cell {
    use tenzro_econsim::chaos::{Cell, sweep_cells};
    if c == "central" {
        return Cell::central();
    }
    let i: usize = c.parse().expect("--cell I or central");
    sweep_cells()
        .into_iter()
        .nth(i)
        .expect("--cell out of range")
}

fn chaos_sweep(m: &HashMap<String, String>, s: &tenzro_econsim::chaos::Settings, threads: usize) {
    use std::io::Write;
    use tenzro_econsim::chaos::{self, Cell, SeedResult};
    #[derive(serde::Serialize, serde::Deserialize)]
    struct Line {
        cell: usize,
        result: SeedResult,
    }
    let cells: Vec<Cell> = match m.get("cell") {
        Some(c) => vec![chaos_cell(c)],
        None => chaos::sweep_cells(),
    };
    let settings: Vec<chaos::Settings> = cells.iter().map(|c| c.settings(s)).collect();
    let out = m.get("out").map(PathBuf::from);
    let path = out.as_ref().map(|d| d.join("sweep.jsonl"));
    let recorded: Vec<Line> = path
        .as_ref()
        .map(|p| std::fs::read_to_string(p).unwrap_or_default())
        .unwrap_or_default()
        .lines()
        .filter_map(|l| serde_json::from_str::<Line>(l).ok())
        .collect();
    if let Some(seed) = m.get("replay") {
        let seed: u64 = seed.parse().expect("--replay SEED");
        let line = serde_json::to_string(&Line {
            cell: cells[0].index,
            result: chaos::run_seed(seed, &settings[0]),
        })
        .expect("json");
        println!("{line}");
        let old = recorded
            .iter()
            .find(|l| l.cell == cells[0].index && l.result.seed == seed)
            .map(|l| serde_json::to_string(l).expect("json"));
        match old {
            Some(o) if o == line => eprintln!(
                "cell {} seed {seed}: identical to the recorded line",
                cells[0].index
            ),
            Some(_) => {
                eprintln!(
                    "cell {} seed {seed}: DIFFERS from the recorded line",
                    cells[0].index
                );
                std::process::exit(1);
            }
            None => eprintln!("cell {} seed {seed}: not recorded", cells[0].index),
        }
        return;
    }
    let first: u64 = get(m, "first", 1);
    let n: u64 = get(m, "seeds", 200);
    let done: std::collections::BTreeSet<(usize, u64)> =
        recorded.iter().map(|l| (l.cell, l.result.seed)).collect();
    let mut results: std::collections::BTreeMap<usize, Vec<SeedResult>> = Default::default();
    for l in recorded {
        if (first..first + n).contains(&l.result.seed) {
            results.entry(l.cell).or_default().push(l.result);
        }
    }
    let jobs: Vec<(usize, u64)> = (0..cells.len())
        .flat_map(|k| (first..first + n).map(move |seed| (k, seed)))
        .filter(|(k, seed)| !done.contains(&(cells[*k].index, *seed)))
        .collect();
    let mut file = out.as_ref().map(|d| {
        std::fs::create_dir_all(d).expect("out dir");
        std::fs::write(
            d.join("sweep-settings.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "days": s.days, "first": first, "seeds": n, "cells": cells,
                "market": s.base.market, "assumptions": s.base.assumptions,
                "network_params": s.base.network_params, "shocks": s.shocks, "limits": s.limits,
            }))
            .expect("json"),
        )
        .expect("write sweep settings");
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(d.join("sweep.jsonl"))
            .expect("open sweep.jsonl")
    });
    eprintln!(
        "chaos sweep: {} cells x {n} seeds, {} runs to go ({} done), {} days each, {threads} threads",
        cells.len(),
        jobs.len(),
        done.len(),
        s.days
    );
    let t = std::time::Instant::now();
    let total = jobs.len();
    let mut count = 0usize;
    chaos::run_parallel(
        &jobs,
        threads,
        |(k, seed)| chaos::run_seed(*seed, &settings[*k]),
        |(k, _), r| {
            let line = Line {
                cell: cells[*k].index,
                result: r,
            };
            if let Some(f) = file.as_mut() {
                writeln!(f, "{}", serde_json::to_string(&line).expect("json"))
                    .expect("append sweep.jsonl");
                f.flush().expect("flush");
            }
            count += 1;
            if count.is_multiple_of(100) || count == total {
                eprintln!(
                    "chaos sweep: {count}/{total} in {:.0} s",
                    t.elapsed().as_secs_f64()
                );
            }
            results.entry(line.cell).or_default().push(line.result);
        },
    );
    let summaries: Vec<chaos::CellSummary> = cells
        .iter()
        .map(|c| {
            let mut rs = results.remove(&c.index).unwrap_or_default();
            rs.sort_by_key(|r| r.seed);
            chaos::summarise_cell(c, &rs)
        })
        .collect();
    let table = chaos::sweep_table(&summaries, s.days);
    println!("{table}");
    if let Some(d) = &out {
        std::fs::write(d.join("sweep.md"), &table).expect("write sweep.md");
        std::fs::write(
            d.join("sweep.json"),
            serde_json::to_string_pretty(&summaries).expect("json"),
        )
        .expect("write sweep.json");
    }
}

fn chaos(m: &HashMap<String, String>, threads: usize) {
    use std::io::Write;
    use tenzro_econsim::chaos::{self, SeedResult, Settings};
    let mut s = Settings::new(get(m, "years", 30.0));
    s.base.market = market(m.get("market").map(String::as_str).unwrap_or("flat"));
    apply_assume(&mut s.base, m);
    apply_params(&mut s.base, m);
    s.shocks.correlated = get(m, "independent", 0u32) == 0;
    s.base.rate_reports = get(m, "rate-reports", 1u32) == 1;
    s.base.human_sample_per_block = get(m, "humans", s.base.human_sample_per_block);
    s.base.stream_sample = get(m, "streams", s.base.stream_sample);
    if get(m, "calm", 0u32) == 1 {
        s.shocks = chaos::Shocks::calm();
    }
    if get(m, "sweep", 0u32) == 1 {
        chaos_sweep(m, &s, threads);
        return;
    }
    if let Some(c) = m.get("cell") {
        s = chaos_cell(c).settings(&s);
    }
    let out = m.get("out").map(PathBuf::from);
    if let Some(seed) = m.get("replay") {
        let seed: u64 = seed.parse().expect("--replay SEED");
        let line = serde_json::to_string(&chaos::run_seed(seed, &s)).expect("json");
        println!("{line}");
        if let Some(dir) = &out {
            let recorded = std::fs::read_to_string(dir.join("seeds.jsonl"))
                .unwrap_or_default()
                .lines()
                .find(|l| serde_json::from_str::<SeedResult>(l).is_ok_and(|r| r.seed == seed))
                .map(String::from);
            match recorded {
                Some(r) if r == line => eprintln!("seed {seed}: identical to the recorded line"),
                Some(_) => {
                    eprintln!("seed {seed}: DIFFERS from the recorded line");
                    std::process::exit(1);
                }
                None => eprintln!("seed {seed}: not in {}", dir.join("seeds.jsonl").display()),
            }
        }
        return;
    }
    let first: u64 = get(m, "first", 1);
    let n: u64 = get(m, "seeds", 20_000);
    let mut results: Vec<SeedResult> = Vec::new();
    let mut file = None;
    let mut skip = std::collections::BTreeSet::new();
    if let Some(dir) = &out {
        std::fs::create_dir_all(dir).expect("out dir");
        let path = dir.join("seeds.jsonl");
        skip = chaos::done_seeds(&path);
        results.extend(
            std::fs::read_to_string(&path)
                .unwrap_or_default()
                .lines()
                .filter_map(|l| serde_json::from_str::<SeedResult>(l).ok())
                .filter(|r| (first..first + n).contains(&r.seed)),
        );
        file = Some(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .expect("open seeds.jsonl"),
        );
        std::fs::write(
            dir.join("settings.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "days": s.days, "first": first, "seeds": n,
                "market": s.base.market, "assumptions": s.base.assumptions,
                "network_params": s.base.network_params,
                "shocks": s.shocks, "limits": s.limits,
            }))
            .expect("json"),
        )
        .expect("write settings");
    }
    let seeds: Vec<u64> = (first..first + n).filter(|x| !skip.contains(x)).collect();
    eprintln!(
        "chaos: {} seeds to run ({} already done), {} days each, {threads} threads",
        seeds.len(),
        skip.len(),
        s.days
    );
    let t = std::time::Instant::now();
    let total = seeds.len();
    let mut done = 0usize;
    chaos::run_many(&seeds, &s, threads, |r| {
        if let Some(f) = file.as_mut() {
            let line = serde_json::to_string(&r).expect("json");
            writeln!(f, "{line}").expect("append seeds.jsonl");
            f.flush().expect("flush");
        }
        done += 1;
        if done.is_multiple_of(100) || done == total {
            eprintln!(
                "chaos: {done}/{total} in {:.0} s",
                t.elapsed().as_secs_f64()
            );
        }
        results.push(r);
    });
    results.sort_by_key(|r| r.seed);
    let summary = chaos::summarise(&results, get(m, "worst", 20usize));
    let table = chaos::table(&summary, &s);
    println!("{table}");
    if let Some(dir) = &out {
        std::fs::write(dir.join("summary.md"), &table).expect("write summary.md");
        std::fs::write(
            dir.join("summary.json"),
            serde_json::to_string_pretty(&summary).expect("json"),
        )
        .expect("write summary.json");
    }
}

fn market(s: &str) -> Market {
    match s {
        "growth" => Market::Growth,
        "downturn" => Market::Downturn,
        _ => Market::Flat,
    }
}

const POPULATION_HELP: &str = "\
tenzro-econsim population: a population market trace (JSON lines) for the network simulator's
trace replay and for --trace demand.

  --seed S          seed of the population and of what happens to it (default 1)
  --actors N        providers and buyers together, at least 20 (default 20000)
  --hours H         span (default 2)
  --scenario NAME   calm, outage, defect, surge, reprice, stress or adversarial (default calm)
  --out FILE        where the trace is written (required)

Prints one line: the counts and the trace's SHA-256.";

fn die(e: String) -> ! {
    eprintln!("tenzro-econsim population: {e}");
    std::process::exit(2)
}

fn population(m: &HashMap<String, String>) {
    use tenzro_econsim::population::{Population, PopulationConfig, Scenario, generate};
    let Some(out) = m.get("out").filter(|o| !o.is_empty()) else {
        die("population needs --out FILE".into())
    };
    let name = m.get("scenario").map(String::as_str).unwrap_or("calm");
    let Some(scenario) = Scenario::parse(name) else {
        let names: Vec<&str> = Scenario::ALL.iter().map(|s| s.name()).collect();
        die(format!(
            "unknown scenario {name} (one of {})",
            names.join(", ")
        ))
    };
    let config = PopulationConfig {
        seed: get(m, "seed", 1),
        actors: get(m, "actors", 20_000),
        hours: get(m, "hours", 2.0),
        scenario,
    };
    let p = generate(config).unwrap_or_else(|e| die(e));
    let text = p.trace();
    std::fs::write(out, &text).unwrap_or_else(|e| die(format!("{out}: {e}")));
    let s = &p.stats;
    println!(
        "population scenario={} seed={} actors={} hours={} providers={} buyers={} payments={} undelivered={} wash={} subcontracted={} unserved={} budget_spent={} dropped={} value_milli={} sha256={}",
        scenario.name(),
        config.seed,
        config.actors,
        config.hours,
        s.providers,
        s.buyers,
        s.payments,
        s.undelivered,
        s.wash,
        s.subcontracted,
        s.unserved,
        s.budget_spent,
        s.dropped,
        s.value_milli,
        Population::digest(&text)
    );
}

/// `-h`/`--help`/`help` as the first argument used to fall through to the
/// `_` arm below (the full default "all" sweep), so a plain help probe
/// silently ran the heaviest workload this binary has instead of printing
/// usage -- that is what spun whole cores for hours on a shared host.
/// Short-circuit it here before anything else runs.
fn is_help_request(cmd: &str) -> bool {
    matches!(cmd, "-h" | "--help" | "help")
}

fn main() {
    let (cmd, m) = args();
    if is_help_request(&cmd) {
        println!("{}", USAGE.trim_start());
        return;
    }
    // Never call std::thread::available_parallelism() here: on some hosts
    // in this fleet it spins (confirmed via strace: concurrent threads
    // cycling the cgroup v2 parent walk, burning whole cores indefinitely)
    // instead of returning. --threads always overrides; absent that, a
    // fixed safe default costs nothing to call and can never hang.
    const DEFAULT_THREADS: usize = 4;
    let threads: usize = get(&m, "threads", DEFAULT_THREADS);
    match cmd.as_str() {
        "one" if m.contains_key("help") => println!("{ONE_HELP}"),
        "one" => {
            let c = RunConfig::scenario(
                market(m.get("market").map(String::as_str).unwrap_or("flat")),
                get(&m, "seed", 1),
                get(&m, "days", 30),
            );
            let mut c = c;
            apply_assume(&mut c, &m);
            apply_params(&mut c, &m);
            c.stream_sample = get(&m, "streams", c.stream_sample);
            let c_trace = c.assumptions.trace.as_ref().map(|t| {
                serde_json::json!({
                    "source": t.source, "span_days": t.span_days, "payments": t.payments,
                    "payments_per_day": t.payments_per_day, "mean_usd": t.mean_usd,
                    "delivered_share": t.delivered_share, "service_share": t.service_share,
                    "providers": t.providers, "buyers": t.buyers,
                })
            });
            c.sla_attest = get(&m, "sla", 1u32) == 1;
            let o = tenzro_econsim::economy::Economy::new(c).run_with(|e| {
                let st = e.chain.state();
                let get = |k: &str| {
                    st.get_storage(&tenzro_vm::native::SYSTEM_ADDRESS, k.as_bytes())
                        .map(|b| {
                            String::from_utf8_lossy(&b)
                                .chars()
                                .take(600)
                                .collect::<String>()
                        })
                };
                eprintln!("reward_state: {:?}", get("reward_state"));
                eprintln!("reward_votes_pending: {:?}", get("reward_votes_pending"));
                let a0 = hex::encode(tenzro_sim::ledger::account(0));
                eprintln!(
                    "coupons of validator 0: {:?}",
                    get(&format!("reward_coupons_of:{a0}"))
                );
                eprintln!(
                    "vesting of validator 0: {:?}",
                    get(&format!("vesting:{a0}"))
                );
            });
            if let Some(path) = m.get("daily") {
                let mut csv = String::from("day,price_usd,chain_rate_usd,transfer_fee_usd\n");
                for (i, d) in o.days.iter().enumerate() {
                    csv.push_str(&format!(
                        "{i},{},{},{}\n",
                        d.price_usd,
                        d.chain_rate_usd,
                        d.human_fee_tnzo * d.price_usd
                    ));
                }
                std::fs::write(path, csv).expect("write daily figures");
            }
            let s = summarise(&o.market, std::slice::from_ref(&o));
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "wall_s": o.wall_s,
                    "applied": o.applied,
                    "last_day": o.days.last(),
                    "launch": o.launch,
                    "trace": c_trace,
                    "agent_sessions_sent": o.agent_sessions_sent,
                    "agent_sessions_settled": o.agent_sessions_settled,
                    "years": yearly(&o),
                    "listing_gate": o.listing_gate,
                    "refusals": o.refusals,
                    "ledger_failures": o.ledger_failures,
                    "failures": s.failures,
                }))
                .expect("json")
            );
        }
        "treasury" => {
            let days = get(&m, "days", 365u32);
            let r = tenzro_econsim::treasury::study(
                days,
                get(&m, "seed", 1),
                threads.min(4),
                m.get("case").map(String::as_str),
                get(&m, "ask", 18_000.0),
            );
            let table = tenzro_econsim::treasury::table(&r);
            println!("{table}");
            if let Some(dir) = m.get("out") {
                let dir = PathBuf::from(dir);
                std::fs::create_dir_all(&dir).expect("out dir");
                std::fs::write(dir.join("treasury.md"), &table).expect("write table");
                std::fs::write(
                    dir.join("treasury.json"),
                    serde_json::to_string_pretty(&r).expect("json"),
                )
                .expect("write results");
            }
        }
        "staking" => {
            let si = tenzro_econsim::staking::SecurityInputs {
                validators_start: get(&m, "validators", 21.0),
                restake: get(&m, "restake", 0.5),
                k: get(&m, "k", 1.5),
                window_epochs: get(&m, "window", 24.0),
                ..Default::default()
            };
            let ci = tenzro_econsim::staking::ColdInputs {
                demand0_usd_day: get(&m, "demand", 50.0),
                elasticity: get(&m, "elasticity", 1.0),
                idle_caught: get(&m, "caught", 0.5),
                ..Default::default()
            };
            let tests = tenzro_econsim::staking::scenarios();
            let mut md = tenzro_econsim::staking::tables(&si, &ci);
            md.push_str("\n## Scenarios\n\n| test | what | pass | measured |\n|---|---|---|---|\n");
            for t in &tests {
                md.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    t.number,
                    t.name,
                    if t.pass { "yes" } else { "NO" },
                    t.detail
                ));
            }
            println!("{md}");
            if let Some(dir) = m.get("out") {
                let dir = PathBuf::from(dir);
                std::fs::create_dir_all(&dir).expect("out dir");
                std::fs::write(dir.join("staking.md"), &md).expect("write table");
            }
            if tests.iter().any(|t| !t.pass) {
                std::process::exit(1);
            }
        }
        "earnings" => {
            let days = get(&m, "days", 730u32);
            let seed = get(&m, "seed", 1u64);
            let results = tenzro_econsim::earnings::sweep(days, seed);
            let table = tenzro_econsim::earnings::table(&results);
            println!("{table}");
            if let Some(dir) = m.get("out") {
                let dir = PathBuf::from(dir);
                std::fs::create_dir_all(&dir).expect("out dir");
                std::fs::write(dir.join("earnings.md"), &table).expect("write table");
                std::fs::write(
                    dir.join("earnings.json"),
                    serde_json::to_string_pretty(&results).expect("json"),
                )
                .expect("write results");
            }
        }
        "crash" => {
            let rows = tenzro_econsim::crash::measured();
            let tests = tenzro_econsim::crash::scenarios(&rows);
            let mut md = tenzro_econsim::crash::table(&rows);
            md.push_str("\n| test | what | pass | measured |\n|---|---|---|---|\n");
            for t in &tests {
                md.push_str(&format!(
                    "| {} | {} | {} | {} |\n",
                    t.number,
                    t.name,
                    if t.pass { "yes" } else { "NO" },
                    t.detail
                ));
            }
            println!("{md}");
            if let Some(dir) = m.get("out") {
                let dir = PathBuf::from(dir);
                std::fs::create_dir_all(&dir).expect("out dir");
                std::fs::write(dir.join("crash.md"), &md).expect("write table");
            }
            if tests.iter().any(|t| !t.pass) {
                std::process::exit(1);
            }
        }
        "chaos" if m.contains_key("help") => println!("{CHAOS_HELP}"),
        "chaos" => chaos(&m, threads),
        "usage" => usage_cmd(&m, threads),
        "devices" => devices_cmd(&m, threads),
        "eval" => eval(threads),
        "probes" => {
            let seed = get(&m, "seed", 7);
            let mut r = tenzro_econsim::probes::rate_cells(seed, get(&m, "days", 21), threads);
            r.extend(tenzro_econsim::probes::treasury_cells(seed, threads));
            let mut failed = false;
            for p in &r {
                let verdict = if p.held { "PASS" } else { "FAIL" };
                failed |= p.gated && !p.held;
                println!(
                    "{verdict} probe {}: measured {:.4} (baseline {:.4}, bound {:.4}) at stake share {:.3}{}",
                    p.name,
                    p.measured,
                    p.baseline,
                    p.bound,
                    p.stake_share,
                    if p.gated {
                        ""
                    } else {
                        " (recorded, not gated)"
                    }
                );
            }
            println!("{}", serde_json::to_string(&r).expect("json"));
            if failed {
                std::process::exit(1);
            }
        }
        "settlement" => {
            let (tests, s1, s5) = tenzro_econsim::settlement_rewards::tests(threads);
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "tests": tests.iter().map(|t| serde_json::json!({
                        "number": t.number, "name": t.name, "pass": t.pass, "detail": t.detail,
                    })).collect::<Vec<_>>(),
                    "s1": s1,
                    "s5": s5,
                }))
                .expect("json")
            );
        }
        "hwlevels" => {
            let mut cfg = tenzro_econsim::hardware_levels::HwConfig::default();
            cfg.seed = get(&m, "seed", cfg.seed);
            cfg.epochs = get(&m, "epochs", cfg.epochs);
            cfg.cap_bps = get(&m, "cap", cfg.cap_bps);
            cfg.arrivals = get(&m, "arrivals", cfg.arrivals);
            if let Some(mix) = m.get("mix") {
                let v: Vec<u32> = mix
                    .split(',')
                    .filter_map(|x| x.trim().parse().ok())
                    .collect();
                if v.len() == 4 {
                    cfg.mix = [v[0], v[1], v[2], v[3]];
                }
            }
            let (tests, on, off) = tenzro_econsim::hardware_levels::tests(&cfg);
            let failed = tests.iter().any(|t| !t.pass);
            let every = get(&m, "every", 30u64).max(1);
            let pick = |v: &[tenzro_econsim::hardware_levels::HwPoint]| {
                v.iter()
                    .filter(|p| p.epoch % every == 0 || p.epoch + 1 == cfg.epochs)
                    .cloned()
                    .collect::<Vec<_>>()
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "config": cfg,
                    "tests": tests.iter().map(|t| serde_json::json!({
                        "number": t.number, "name": t.name, "pass": t.pass, "detail": t.detail,
                    })).collect::<Vec<_>>(),
                    "bonus_on": pick(&on),
                    "bonus_off": pick(&off),
                }))
                .expect("json")
            );
            if failed {
                std::process::exit(1);
            }
        }
        "agents" => agents(&m),
        "growth" => growth(&m),
        "research" => research(&m),
        "attack" => {
            let fam = m
                .get("family")
                .cloned()
                .unwrap_or_else(|| "self_dealing_sla".into());
            let mut base = RunConfig::scenario(Market::Flat, 0, 0);
            apply_assume(&mut base, &m);
            apply_params(&mut base, &m);
            let r = search::search_with(
                &fam,
                get(&m, "days", 30),
                get(&m, "restarts", threads),
                get(&m, "generations", 0),
                get(&m, "per-gen", 0),
                threads,
                get(&m, "seed", 7),
                &base,
            );
            println!("{}", serde_json::to_string_pretty(&r).expect("json"));
        }
        "admission" if m.contains_key("defaults") => {
            let r = tenzro_econsim::admission::defaults_study(
                get(&m, "seconds", 60),
                get(&m, "blocks", 600),
                get(&m, "price", 0.10),
                threads,
            );
            println!("{}", serde_json::to_string_pretty(&r).expect("json"));
        }
        "admission" => {
            let r = tenzro_econsim::admission::study(get(&m, "seconds", 60));
            println!("{}", serde_json::to_string_pretty(&r).expect("json"));
        }
        "population" if m.contains_key("help") => println!("{POPULATION_HELP}"),
        "population" => population(&m),
        "spam" => {
            let r = spam::study(
                &[0.5, 1.0, 1.5, 2.0],
                get(&m, "blocks", 240),
                get(&m, "honest", 50),
                0.10,
            );
            println!("{}", serde_json::to_string_pretty(&r).expect("json"));
        }
        _ => {
            let t = std::time::Instant::now();
            let out = PathBuf::from(
                m.get("out")
                    .cloned()
                    .unwrap_or_else(|| "econsim-out".into()),
            );
            std::fs::create_dir_all(&out).expect("output directory");
            let mut rep = Report {
                commit: m.get("commit").cloned().unwrap_or_default(),
                ..Report::default()
            };
            let years: f64 = get(&m, "years", 5.0);
            let seeds: u64 = get(&m, "seeds", 8);
            let days = (years * 365.25) as u32;
            // Each phase rewrites report.json and report.md, so a run cut
            // short keeps what it finished; verdict.json is written last.
            let save = |rep: &Report| {
                let mut r = rep.clone();
                r.wall_s = t.elapsed().as_secs_f64();
                r.judge();
                std::fs::write(
                    out.join("report.json"),
                    serde_json::to_vec_pretty(&r).expect("json"),
                )
                .expect("write report.json");
                std::fs::write(out.join("report.md"), r.markdown()).expect("write report.md");
                write_verdict(&out, &r);
            };
            // Scenarios, in rounds of seeds: each round adds a seed per
            // market and rewrites the verdict, and a round that would not
            // finish within 60% of the time budget is not started.
            let budget = get(&m, "budget-s", f64::INFINITY);
            let scen_threads = get(&m, "scenario-threads", threads.min(3)).max(1);
            let per_round = (scen_threads / Market::ALL.len()).max(1) as u64;
            let mut skipped: Vec<String> = Vec::new();
            let mut outs = Vec::new();
            let mut done_seeds = 0u64;
            while done_seeds < seeds {
                let round_start = t.elapsed().as_secs_f64();
                let n = per_round.min(seeds - done_seeds);
                let mut cfgs = Vec::new();
                for mk in Market::ALL {
                    for s in done_seeds..done_seeds + n {
                        let mut c = RunConfig::scenario(mk, 100 + s, days);
                        apply_assume(&mut c, &m);
                        cfgs.push(c);
                    }
                }
                // Multi-year runs hold years of chain state each, so few run at once.
                outs.extend(gsa::run_all(cfgs, scen_threads));
                done_seeds += n;
                rep.scenarios = Market::ALL
                    .into_iter()
                    .map(|mk| {
                        let runs: Vec<_> = outs
                            .iter()
                            .filter(|o: &&tenzro_econsim::economy::RunOutcome| {
                                o.market == mk.name()
                            })
                            .cloned()
                            .collect();
                        summarise(mk.name(), &runs)
                    })
                    .collect();
                save(&rep);
                let round = t.elapsed().as_secs_f64() - round_start;
                if done_seeds < seeds && t.elapsed().as_secs_f64() + round * 1.2 > budget * 0.6 {
                    skipped.push(format!("scenario seeds beyond {done_seeds} of {seeds}"));
                    break;
                }
            }
            eprintln!("scenarios done in {:.0} s", t.elapsed().as_secs_f64());
            // Every later phase runs only while the time budget allows,
            // sized from the measured cost of a simulated day; a phase that
            // does not fit is skipped with a warning, never left half done.
            let run_days = (Market::ALL.len() as f64) * done_seeds as f64 * days as f64;
            let scen_threads = scen_threads as f64;
            let day_s = if run_days > 0.0 {
                (t.elapsed().as_secs_f64() * scen_threads / run_days).max(1e-3)
            } else {
                0.3
            };
            let left = |t: &std::time::Instant| budget - t.elapsed().as_secs_f64();
            let fits = |t: &std::time::Instant, sim_days: f64, par: f64| {
                sim_days * day_s * 1.5 / par.max(1.0) < left(t)
            };
            // Design and machine-economy models: seconds.
            if get(&m, "design", 1u32) == 1 {
                rep.design_tests = tenzro_econsim::bme::tests();
                rep.design_tests
                    .extend(tenzro_econsim::machine::scenarios(&Default::default()));
                rep.staking_tests = tenzro_econsim::staking::scenarios();
                let crash = tenzro_econsim::crash::measured();
                rep.crash_tests = tenzro_econsim::crash::scenarios(&crash);
                rep.crash_table = tenzro_econsim::crash::table(&crash);
                rep.design_equilibrium = tenzro_econsim::bme::equilibrium(
                    &[1.0e3, 1.0e4, 1.0e5, 1.0e6, 1.0e7, 1.0e8, 1.0e9],
                    1_826,
                );
                save(&rep);
            }
            // Settlement rewards against collusion: seconds.
            if get(&m, "settlement", 1u32) == 1 {
                let (tests, s1, s5) = tenzro_econsim::settlement_rewards::tests(threads);
                rep.settlement_tests = tests;
                rep.provider_wash = s1;
                rep.cheat_deterrence = s5;
                save(&rep);
            }
            // Ablations and the cartel sweep.
            let ab_days: u32 = get(&m, "ablation-days", 180);
            let ab_seeds: u64 = get(&m, "ablation-seeds", 1);
            let cartel_days: u32 = get(&m, "cartel-days", 10);
            let step: f64 = get(&m, "cartel-step", 0.05);
            let shares: Vec<f64> = (0..)
                .map(|i| 0.30 + step * i as f64)
                .take_while(|x| *x <= 0.80 + 1e-9)
                .collect();
            if ab_days > 0 {
                let n = tenzro_econsim::economy::Ablation::ALL.len() as f64;
                let cost = n
                    * (Market::ALL.len() as f64 * ab_seeds as f64 * ab_days as f64
                        + (cartel_days + 5) as f64)
                    + shares.len() as f64 * 2.0 * (cartel_days + 5) as f64;
                if fits(&t, cost, threads as f64) {
                    rep.ablations = Some(tenzro_econsim::ablation::study(
                        &Market::ALL,
                        ab_seeds,
                        ab_days,
                        cartel_days,
                        &shares,
                        threads,
                    ));
                    eprintln!("ablations done in {:.0} s", t.elapsed().as_secs_f64());
                    save(&rep);
                } else {
                    skipped.push(format!(
                        "ablations (about {:.0} s)",
                        cost * day_s * 1.5 / threads as f64
                    ));
                }
            }
            // Spam at real block time: minutes.
            let blocks: u32 = get(&m, "spam-blocks", 240);
            if blocks > 0 {
                rep.spam = spam::study(&[0.5, 1.0, 1.5, 2.0], blocks, 50, 0.10);
                save(&rep);
            }
            // Thin pool: corruption cost, shocks, cartels, levers.
            let dex_seeds: u64 = get(&m, "dex-seeds", 2);
            let dex_days: u32 = get(&m, "dex-days", 270);
            if dex_seeds > 0 {
                let cost = 3.0 * 2.0 * dex_seeds as f64 * dex_days as f64 + 40.0 * 100.0;
                if fits(&t, cost, threads as f64) {
                    rep.dex = Some(tenzro_econsim::dex::study(
                        &[50_000.0, 250_000.0, 1_000_000.0, 5_000_000.0],
                        get(&m, "dex-at-day", 90),
                        &[-0.5, -0.8, -0.95],
                        dex_days,
                        dex_seeds,
                        threads,
                    ));
                    eprintln!("thin pool done in {:.0} s", t.elapsed().as_secs_f64());
                    save(&rep);
                } else {
                    skipped.push("thin-pool study".into());
                }
            }
            // Sensitivity: Morris then Sobol, scaled down to fit.
            let mut r: usize = get(&m, "morris", 6);
            let mut sobol_n: usize = get(&m, "sobol-n", 24);
            let sobol_top: usize = get(&m, "sobol-top", 6);
            let gsa_days: u32 = get(&m, "gsa-days", 365);
            if r > 0 {
                let d = gsa::factors().len() as f64;
                let cost = |r: usize, n: usize| {
                    (r as f64 * (d + 1.0) + n as f64 * (sobol_top as f64 + 2.0)) * gsa_days as f64
                };
                while r > 2 && !fits(&t, cost(r, sobol_n), threads as f64) {
                    r -= 1;
                    sobol_n = (sobol_n * 3 / 4).max(4);
                }
                if fits(&t, cost(r, sobol_n), threads as f64) {
                    let base = gsa::base(gsa_days, 500);
                    rep.analysis = Some(gsa::analyse(&base, r, sobol_top, sobol_n, threads, 900));
                    eprintln!(
                        "sensitivity (r {r}, n {sobol_n}) done in {:.0} s",
                        t.elapsed().as_secs_f64()
                    );
                    save(&rep);
                } else {
                    skipped.push("sensitivity analysis".into());
                }
            }
            // Adversaries, families in turn while time allows.
            let restarts: usize = get(&m, "restarts", threads);
            if restarts > 0 {
                let gens: usize = get(&m, "generations", 2);
                let per_gen: usize = get(&m, "per-gen", threads);
                let sdays: u32 = get(&m, "search-days", 60);
                let each = (restarts + gens * per_gen) as f64 * sdays as f64;
                let mut done = 0;
                for fam in search::FAMILIES {
                    if !fits(&t, each, threads as f64) {
                        break;
                    }
                    rep.searches.push(search::search(
                        fam, sdays, restarts, gens, per_gen, threads, 11,
                    ));
                    done += 1;
                    save(&rep);
                }
                if done < search::FAMILIES.len() {
                    skipped.push(format!(
                        "adversary search ({} of {} families run)",
                        done,
                        search::FAMILIES.len()
                    ));
                }
                eprintln!("adversaries done in {:.0} s", t.elapsed().as_secs_f64());
            }
            rep.skipped = skipped;
            rep.complete = true;
            rep.wall_s = t.elapsed().as_secs_f64();
            rep.judge();
            std::fs::write(
                out.join("report.json"),
                serde_json::to_vec_pretty(&rep).expect("json"),
            )
            .expect("write report.json");
            std::fs::write(out.join("report.md"), rep.markdown()).expect("write report.md");
            write_verdict(&out, &rep);
            println!("{}", rep.verdict);
            if rep.verdict == "FAIL" {
                std::process::exit(1);
            }
        }
    }
}

/// Writes verdict.json for `rep` as it stands.
fn write_verdict(out: &std::path::Path, rep: &Report) {
    let verdict = serde_json::json!({
        "verdict": rep.verdict,
        "commit": rep.commit,
        "issues": rep.issues,
        "warnings": rep.warnings,
        "wall_s": rep.wall_s,
        "complete": rep.complete,
    });
    std::fs::write(
        out.join("verdict.json"),
        serde_json::to_vec_pretty(&verdict).expect("json"),
    )
    .expect("write verdict.json");
}

/// `eval`: one JSON run request per line on stdin, one JSON result per line
/// on stdout in request order. `eval --factors` prints the swept factors.
///
/// Request: {"id", "market", "seed", "days", "x": {factor: unit value},
/// "params": {key: value}, "assumptions": {name: value}, "adversary",
/// "ablation": name, "rate_reports": bool}. Result: {"id", "metrics",
/// "failures", "adversary"}.
fn eval(threads: usize) {
    use std::io::{BufRead, Write};
    use tenzro_econsim::economy::Ablation;
    if std::env::args().any(|a| a == "--factors") {
        println!("{}", serde_json::to_string(&gsa::factors()).expect("json"));
        return;
    }
    let factors = gsa::factors();
    let mut ids = Vec::new();
    let mut cfgs = Vec::new();
    for line in std::io::stdin().lock().lines() {
        let line = line.expect("stdin");
        if line.trim().is_empty() {
            continue;
        }
        let r: serde_json::Value = serde_json::from_str(&line).expect("a JSON request per line");
        let mut c = RunConfig::scenario(
            market(r["market"].as_str().unwrap_or("flat")),
            r["seed"].as_u64().expect("seed"),
            r["days"].as_u64().expect("days") as u32,
        );
        if let Some(x) = r["x"].as_object() {
            for f in &factors {
                if let Some(u) = x.get(&f.name).and_then(|v| v.as_f64()) {
                    c = gsa::config_at(&c, std::slice::from_ref(f), &[u]);
                }
            }
        }
        if let Some(p) = r["params"].as_object() {
            for (k, v) in p {
                let v = v.as_f64().expect("numeric parameter").round().max(0.0) as u64;
                c.network_params.insert(k.clone(), v);
            }
        }
        if let Some(p) = r["assumptions"].as_object() {
            for (k, v) in p {
                c.assumptions
                    .set(k, v.as_f64().expect("numeric assumption"));
            }
        }
        if !r["adversary"].is_null() {
            c.adversary = Some(serde_json::from_value(r["adversary"].clone()).expect("adversary"));
        }
        if let Some(name) = r["ablation"].as_str() {
            c.ablation = Ablation::ALL
                .into_iter()
                .find(|a| a.name() == name)
                .expect("a known ablation name");
        }
        if let Some(b) = r["rate_reports"].as_bool() {
            c.rate_reports = b;
        }
        ids.push(r["id"].clone());
        cfgs.push(c);
    }
    let outs = gsa::run_all(cfgs, threads);
    let mut so = std::io::stdout().lock();
    for (id, o) in ids.into_iter().zip(outs) {
        let m = gsa::Metrics::of(&o);
        let j = serde_json::json!({
            "id": id,
            "metrics": m,
            "failures": m.failures(),
            "adversary": o.adversary,
        });
        writeln!(so, "{}", serde_json::to_string(&j).expect("json")).expect("stdout");
    }
}

/// Runs a campaign of model-driven decisions and writes manifest.json into
/// `--out`; exits 1 when a decision failed.
fn agents(m: &HashMap<String, String>) {
    use std::sync::Arc;
    use tenzro_econsim::campaign::{Spec, run};
    use tenzro_econsim::decision::{
        Cache, Channel, CliTransport, Decode, Mode, ModelRef, Template, Transport,
    };
    let fail = |e: String| -> ! {
        eprintln!("agents: {e}");
        std::process::exit(2)
    };
    let mode = match m.get("mode").map(String::as_str).unwrap_or("replay") {
        "record" => Mode::Record,
        "replay" => Mode::Replay,
        "live-probe" => Mode::LiveProbe {
            per_mille: get(m, "probe-per-mille", 100),
        },
        other => fail(format!("unknown mode {other}")),
    };
    let models: Vec<ModelRef> = m
        .get("models")
        .map(String::as_str)
        .unwrap_or("")
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| match s.rsplit_once('=') {
            Some((id, hash)) => ModelRef {
                id: id.into(),
                hash: hash.to_ascii_lowercase(),
            },
            None => fail(format!("model {s} needs ID=HASH from the registry")),
        })
        .collect();
    if models.is_empty() {
        fail("--models is required".into());
    }
    let templates: Vec<Template> = m
        .get("templates")
        .map(String::as_str)
        .unwrap_or("lines-1")
        .split(',')
        .map(|t| Template::parse(t).unwrap_or_else(|| fail(format!("unknown template {t}"))))
        .collect();
    let cache_path = PathBuf::from(
        m.get("cache")
            .cloned()
            .unwrap_or_else(|| fail("--cache is required".into())),
    );
    let out = PathBuf::from(
        m.get("out")
            .cloned()
            .unwrap_or_else(|| fail("--out is required".into())),
    );
    let cache = Cache::load(&cache_path).unwrap_or_else(|e| fail(e));
    let transport: Option<Arc<dyn Transport>> = m.get("rpc").map(|rpc| {
        let channel = m.get("channel").map(|id| Channel {
            agent_rpc: m.get("agent-rpc").cloned().unwrap_or_else(|| rpc.clone()),
            channel_id: id.clone(),
            ceiling_wei: get(m, "ceiling-wei", 0u128),
            spent_wei: get(m, "spent-wei", 0u128),
        });
        Arc::new(CliTransport::new(
            PathBuf::from(m.get("cli").cloned().unwrap_or_else(|| "tenzro".into())),
            rpc.clone(),
            channel,
        )) as Arc<dyn Transport>
    });
    let spec = Spec {
        market: market(m.get("market").map(String::as_str).unwrap_or("flat")),
        days: get(m, "days", 365),
        seed: get(m, "seed", 1),
        agents: get(m, "agents", 5),
        models,
        templates,
        decode: Decode::default(),
        mode,
    };
    let (manifest, cache) = run(&spec, cache, transport).unwrap_or_else(|e| fail(e));
    if mode == Mode::Record {
        cache.save(&cache_path).unwrap_or_else(|e| fail(e));
    }
    std::fs::create_dir_all(&out).expect("out dir");
    std::fs::write(
        out.join("manifest.json"),
        serde_json::to_string_pretty(&manifest).expect("manifest"),
    )
    .expect("write manifest");
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "cache_hash": manifest.cache_hash_out,
            "accounting": manifest.accounting,
            "actions": tenzro_econsim::campaign::actions(&manifest),
            "robustness": manifest.robustness,
        }))
        .expect("json")
    );
    if manifest.pairs.iter().any(|p| p.decision_error.is_some()) {
        for p in &manifest.pairs {
            if let Some(e) = &p.decision_error {
                eprintln!("{} {}: {e}", p.model.id, p.template);
            }
        }
        std::process::exit(1);
    }
}
/// `--lw DIR [--edge-tps 6,20]`: every market-stress trace under DIR split
/// between the operator device classes, as Markdown and records.
fn devices_cmd(m: &HashMap<String, String>, threads: usize) {
    use std::io::Write as _;
    use tenzro_econsim::device_classes as dc;
    let out = PathBuf::from(
        m.get("out")
            .cloned()
            .unwrap_or_else(|| "devices-out".into()),
    );
    std::fs::create_dir_all(&out).expect("create --out");
    let Some(root) = m.get("lw") else {
        eprintln!("devices: --lw DIR is needed");
        std::process::exit(2);
    };
    let tps: Vec<f64> = m
        .get("edge-tps")
        .map(|v| v.split(',').filter_map(|x| x.trim().parse().ok()).collect())
        .unwrap_or_else(|| vec![dc::DeviceSettings::default().edge_tokens_per_s]);
    let dirs = tenzro_econsim::usage_lw::seed_dirs(std::path::Path::new(root));
    let mut recs = Vec::new();
    let mut bad = Vec::new();
    let mut w = std::io::BufWriter::new(
        std::fs::File::create(out.join("device-records.jsonl")).expect("device-records.jsonl"),
    );
    dc::sweep(
        &dirs,
        threads,
        &tps,
        |r| {
            writeln!(w, "{}", serde_json::to_string(&r).expect("json")).expect("write");
            recs.push(r);
        },
        |e| bad.push(e),
    );
    w.flush().expect("flush");
    let report = dc::report(&recs, &bad, dirs.len());
    std::fs::write(out.join("device-report.md"), &report).expect("device-report.md");
    let viol: u64 = recs.iter().map(|r| r.run.charter_violations).sum();
    println!(
        "devices: {} runs, {} left out, charter violations {viol}",
        recs.len(),
        bad.len()
    );
    std::process::exit(if viol == 0 && !recs.is_empty() { 0 } else { 1 });
}

/// `usage`: replays usage traces through the chain's accounting. With
/// `--manifest F --trace F`, one trace (a market-stress simulation export) under every
/// availability setting, treasury leg and mechanism; otherwise the fixture
/// cells, whose results are provisional.
fn usage_cmd(m: &HashMap<String, String>, threads: usize) {
    use std::io::Write as _;
    use tenzro_econsim::{usage, usage_fixtures as fx};
    let out = PathBuf::from(m.get("out").cloned().unwrap_or_else(|| "usage-out".into()));
    std::fs::create_dir_all(&out).expect("create --out");
    if let (Some(man), Some(tr)) = (m.get("manifest"), m.get("trace")) {
        let trace = match usage::Trace::read(std::path::Path::new(man), std::path::Path::new(tr)) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("usage: {e}");
                std::process::exit(2);
            }
        };
        let mut w = std::fs::File::create(out.join("replay.jsonl")).expect("replay.jsonl");
        let mut all = true;
        for leg in fx::LEGS {
            for avail in fx::AVAILABILITY {
                for (name, mech) in usage::Mechanisms::sweep() {
                    let mut rules = usage::Rules {
                        availability_tnzo_hour: avail,
                        mechanisms: mech,
                        ..usage::Rules::default()
                    };
                    rules.overrides.insert(
                        tenzro_vm::native::economy::TREASURY_LEG_INFERENCE_PARAM.into(),
                        leg,
                    );
                    let o = usage::replay(&trace, &rules);
                    all &= name != "none" || o.holds();
                    println!(
                        "{} leg={leg} availability={avail} mechanism={name} validators_min={} cover={:.3} operators_min={} charter_violations={}",
                        if o.holds() { "HOLDS" } else { "BREAKS" },
                        o.validators_min,
                        o.cover_ratio_mean,
                        o.operators_min,
                        o.charter_violations
                    );
                    let line = serde_json::json!({"leg_bps": leg, "availability": avail, "mechanism": name, "outcome": o});
                    writeln!(w, "{line}").expect("write");
                }
            }
        }
        std::process::exit(if all { 0 } else { 1 });
    }
    if let Some(root) = m.get("lw") {
        let dirs = tenzro_econsim::usage_lw::seed_dirs(std::path::Path::new(root));
        let mut recs = Vec::new();
        let mut bad = Vec::new();
        let mut w = std::io::BufWriter::new(
            std::fs::File::create(out.join("lw-records.jsonl")).expect("lw-records.jsonl"),
        );
        tenzro_econsim::usage_lw::sweep(
            &dirs,
            threads,
            |r| {
                writeln!(w, "{}", serde_json::to_string(&r).expect("json")).expect("write");
                recs.push(r);
            },
            |e| bad.push(e),
        );
        w.flush().expect("flush");
        let rep = tenzro_econsim::usage_lw::report(&recs, &bad, dirs.len());
        std::fs::write(out.join("lw-report.md"), &rep).expect("lw-report.md");
        println!("{rep}");
        std::process::exit(if bad.is_empty() { 0 } else { 1 });
    }
    let days: u64 = get(m, "days", 1_826);
    if let Some(dir) = m.get("write-sample") {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir).expect("create --write-sample");
        for c in fx::cells() {
            let t = fx::fixture(&c, fx::MIXES[1].1, fx::SCALES[1], days);
            t.write(
                &dir.join(format!("fixture-{}.manifest.json", c.name)),
                &dir.join(format!("fixture-{}.jsonl", c.name)),
            )
            .expect("write fixture");
        }
        println!("fixture traces written to {}", dir.display());
        return;
    }
    let mut recs = Vec::new();
    let mut w = std::io::BufWriter::new(
        std::fs::File::create(out.join("records.jsonl")).expect("records.jsonl"),
    );
    fx::sweep(days, threads, |r| {
        writeln!(w, "{}", serde_json::to_string(&r).expect("json")).expect("write");
        recs.push(r);
    });
    w.flush().expect("flush");
    let rep = fx::report(&recs);
    std::fs::write(out.join("report.md"), &rep).expect("report.md");
    println!("{rep}");
}

#[cfg(test)]
mod main_dispatch_tests {
    use super::*;

    #[test]
    fn help_requests_are_recognized_and_never_fall_through_to_the_default_sweep() {
        assert!(is_help_request("-h"));
        assert!(is_help_request("--help"));
        assert!(is_help_request("help"));
        // Anything else -- including "all" and typos -- keeps falling
        // through to the default sweep, unchanged from before this fix.
        assert!(!is_help_request("all"));
        assert!(!is_help_request("earnings"));
        assert!(!is_help_request(""));
    }

    #[test]
    fn threads_default_resolves_without_any_available_parallelism_call() {
        // Regression guard for the spin: resolving a thread count with no
        // --threads flag present must be a plain, fast map lookup, never a
        // call into std::thread::available_parallelism().
        let empty = HashMap::new();
        const DEFAULT_THREADS: usize = 4;
        let start = std::time::Instant::now();
        let threads: usize = get(&empty, "threads", DEFAULT_THREADS);
        assert_eq!(threads, DEFAULT_THREADS);
        assert!(
            start.elapsed() < std::time::Duration::from_millis(50),
            "resolving the thread-count default should be instant, not a syscall-bound detection"
        );

        let mut m = HashMap::new();
        m.insert("threads".to_string(), "7".to_string());
        assert_eq!(get::<usize>(&m, "threads", DEFAULT_THREADS), 7);
    }
}
