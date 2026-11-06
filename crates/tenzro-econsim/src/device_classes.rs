//! Operator device classes on the usage accounting: which kinds of machine
//! do the paid work in a usage trace, what each earns and what it costs.
//!
//! Classes:
//! - edge: a single-board computer (a Raspberry Pi 5, 8 GB, the edge tier's
//!   reference device) serving a small model on its CPU;
//! - desktop: an RTX 4090 host serving 7-8B models;
//! - server: the trace's own accelerator providers;
//! - validator: the accounting's own validator set.
//!
//! The chain's rules come from one [`replay`] of the trace: what buyers
//! settled each tick, the share a provider keeps after the fee and the leg,
//! the providers' pool release (pegged to paid settlements; the supply is
//! fixed and nothing is minted) and each active validator's income. This
//! module only says who did the paid work: each tick's settled units are
//! split between the classes able to do them, and a class is paid the
//! service payment and the provider release for exactly the units it
//! delivered. A class with no delivered unit in a tick is paid nothing in
//! it, and nothing is paid for being online.
//!
//! The number of edge and desktop devices moves only with their trailing
//! income from that paid work against their running cost: devices join when
//! a month's income per device clears the join ratio of its cost and leave
//! when it falls under the exit ratio. Server capacity is the trace's own,
//! and the validator count is the accounting's.
//!
//! Units are the trace's (accelerator-hours a day). A small-model device's
//! tokens are turned into units at the market value of small-model tokens
//! ([`SMALL_MODEL_REFERENCE_USD_MTOK`]) over the reference accelerator-hour
//! rate ([`LIST_RATE_USD_GPU_HOUR`]). Throughputs, costs and the share of
//! paid work a small model can do are inputs with ranges, not predictions.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Serialize;

use crate::earnings::LIST_RATE_USD_GPU_HOUR;
use crate::growth::{
    PI_COST_USD_DAY, RTX_COST_USD_DAY, RTX_MTOK_DAY, SMALL_MODEL_REFERENCE_USD_MTOK,
};
use crate::usage::{Rules, TickBook, Trace, replay};

/// The device classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceClass {
    Edge,
    Desktop,
    Server,
    Validator,
}

impl DeviceClass {
    pub const ALL: [DeviceClass; 4] = [
        DeviceClass::Edge,
        DeviceClass::Desktop,
        DeviceClass::Server,
        DeviceClass::Validator,
    ];

    pub fn name(self) -> &'static str {
        match self {
            DeviceClass::Edge => "edge",
            DeviceClass::Desktop => "desktop",
            DeviceClass::Server => "server",
            DeviceClass::Validator => "validator",
        }
    }
}

/// How a tick's work is split between the classes able to do it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Dispatch {
    /// In proportion to the capacity each class has free.
    ProRata,
    /// The lowest marginal cost a unit first.
    Merit,
}

/// Units a device delivers a day at full use, from its tokens a second on
/// small-model work.
pub fn units_per_day(tokens_per_s: f64) -> f64 {
    tokens_per_s * 86_400.0 / 1e6 * SMALL_MODEL_REFERENCE_USD_MTOK / LIST_RATE_USD_GPU_HOUR
}

/// An edge device's power, W, low and high (a Pi 5 under load).
pub const EDGE_POWER_W: (f64, f64) = (5.0, 10.0);
/// A desktop's power, W, low and high (an RTX 4090 host under load).
pub const DESKTOP_POWER_W: (f64, f64) = (450.0, 600.0);
/// Energy price, USD a kWh, the device costs assume.
pub const ENERGY_USD_KWH: f64 = 0.15;

/// The settings of one device-class run.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceSettings {
    pub dispatch: Dispatch,
    /// An edge device's small-model tokens a second.
    pub edge_tokens_per_s: f64,
    /// Share of the non-critical paid units a small model can do (edge,
    /// desktop and server may take them).
    pub small_share: f64,
    /// Share of the non-critical paid units a 7-8B model can do (desktop
    /// and server). Critical units and the rest are server work only:
    /// they need an attested enclave or a larger model.
    pub medium_share: f64,
    /// Devices at the start.
    pub edge_start: f64,
    pub desktop_start: f64,
    /// Largest monthly move of a class's device count, share.
    pub monthly_move: f64,
    pub join_ratio: f64,
    pub exit_ratio: f64,
}

impl Default for DeviceSettings {
    fn default() -> Self {
        DeviceSettings {
            dispatch: Dispatch::ProRata,
            edge_tokens_per_s: 20.0,
            small_share: 0.2,
            medium_share: 0.4,
            edge_start: 100.0,
            desktop_start: 10.0,
            monthly_move: 0.25,
            join_ratio: 1.2,
            exit_ratio: 1.0,
        }
    }
}

/// One class over a run.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ClassBook {
    pub devices_start: f64,
    pub devices_end: f64,
    pub devices_max: f64,
    /// Mean devices over the run.
    pub devices_mean: f64,
    /// Paid units delivered, and their share of all.
    pub units: f64,
    pub units_share: f64,
    /// Service payments (buyers' money less the fee and the leg), USD.
    pub service_usd: f64,
    /// Provider pool release for the delivered units, TNZO and USD at the
    /// tick's price; for validators, their income from the accounting.
    pub release_tnzo: f64,
    pub release_usd: f64,
    /// Running cost, USD, at the low and high end of the class's range.
    pub cost_lo_usd: f64,
    pub cost_hi_usd: f64,
    /// Income per device a month, USD, and cost per device a month at the
    /// low and high end.
    pub income_device_month: f64,
    pub cost_device_month_lo: f64,
    pub cost_device_month_hi: f64,
    /// Income over cost, at the high and low cost.
    pub ratio_at_hi_cost: f64,
    pub ratio_at_lo_cost: f64,
    /// Share of all operator income.
    pub income_share: f64,
    /// Ticks the class was paid with no delivered unit in the tick.
    pub violations: u64,
}

/// One run: a trace under one setting.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceRun {
    pub ticks: u64,
    pub paid_usd: f64,
    pub classes: BTreeMap<DeviceClass, ClassBook>,
    /// Concentration of operator income: Herfindahl index over operators
    /// and the ten largest operators' share.
    pub hhi: f64,
    pub top10_share: f64,
    /// Provider release paid to the classes over the accounting's own,
    /// TNZO (must be 0).
    pub release_split_error_tnzo: f64,
    pub charter_violations: u64,
}

struct Live {
    n: f64,
    units_day: f64,
    marginal_usd_unit: f64,
    cost_day: (f64, f64),
    income: Vec<f64>,
}

impl Live {
    fn capacity(&self) -> f64 {
        self.n * self.units_day
    }
}

/// The accounting's book of a trace under `rules`.
pub fn book(trace: &Trace, rules: &Rules) -> Vec<TickBook> {
    replay(trace, rules).tick_book
}

/// Fixed cost of server capacity, USD a unit of capacity: the trace's mean
/// provider capital cost, or the reference rate's when the trace gives none.
fn server_capex(trace: &Trace) -> f64 {
    let v: Vec<f64> = trace
        .manifest
        .parameters
        .get("lw.providers")
        .and_then(|p| p.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|p| p.get("capex").and_then(|c| c.as_f64()))
                .collect()
        })
        .unwrap_or_default();
    if v.is_empty() {
        LIST_RATE_USD_GPU_HOUR * 0.75
    } else {
        v.iter().sum::<f64>() / v.len() as f64
    }
}

/// Splits `pool` units between the classes `who` (indices into `live`) in
/// the dispatch order, at most each class's free capacity; returns what is
/// left over.
fn split(
    live: &[Live],
    free: &mut [f64],
    who: &[usize],
    pool: f64,
    d: Dispatch,
    got: &mut [f64],
) -> f64 {
    let mut left = pool;
    match d {
        Dispatch::ProRata => {
            // Repeated so a class that fills hands its share to the rest.
            for _ in 0..4 {
                let cap: f64 = who.iter().map(|i| free[*i]).sum();
                if left <= 1e-12 || cap <= 1e-12 {
                    break;
                }
                let take_all = left.min(cap);
                for i in who {
                    let x = (take_all * free[*i] / cap).min(free[*i]);
                    got[*i] += x;
                    free[*i] -= x;
                    left -= x;
                }
            }
        }
        Dispatch::Merit => {
            let mut order = who.to_vec();
            order.sort_by(|a, b| {
                live[*a]
                    .marginal_usd_unit
                    .total_cmp(&live[*b].marginal_usd_unit)
            });
            for i in order {
                let x = left.min(free[i]);
                got[i] += x;
                free[i] -= x;
                left -= x;
            }
        }
    }
    left.max(0.0)
}

/// Splits the paid work in `ticks` between the classes under `s`.
pub fn run(ticks: &[TickBook], capex_unit: f64, s: &DeviceSettings) -> DeviceRun {
    const EDGE: usize = 0;
    const DESKTOP: usize = 1;
    const SERVER: usize = 2;
    let edge_units = units_per_day(s.edge_tokens_per_s);
    let desk_units = RTX_MTOK_DAY * SMALL_MODEL_REFERENCE_USD_MTOK / LIST_RATE_USD_GPU_HOUR;
    let energy = |w: f64| w * 24.0 / 1000.0 * ENERGY_USD_KWH;
    let mut live = vec![
        Live {
            n: s.edge_start,
            units_day: edge_units,
            marginal_usd_unit: energy((EDGE_POWER_W.0 + EDGE_POWER_W.1) / 2.0)
                / edge_units.max(1e-12),
            cost_day: PI_COST_USD_DAY,
            income: Vec::new(),
        },
        Live {
            n: s.desktop_start,
            units_day: desk_units,
            marginal_usd_unit: energy((DESKTOP_POWER_W.0 + DESKTOP_POWER_W.1) / 2.0) / desk_units,
            cost_day: RTX_COST_USD_DAY,
            income: Vec::new(),
        },
        Live {
            n: 0.0,
            units_day: 24.0,
            marginal_usd_unit: 0.0,
            cost_day: (0.0, 0.0),
            income: Vec::new(),
        },
    ];
    let mut books: BTreeMap<DeviceClass, ClassBook> = DeviceClass::ALL
        .iter()
        .map(|c| (*c, ClassBook::default()))
        .collect();
    let classes = [DeviceClass::Edge, DeviceClass::Desktop, DeviceClass::Server];
    for (i, c) in classes.iter().enumerate().take(2) {
        let b = books.get_mut(c).expect("class");
        b.devices_start = live[i].n;
        b.devices_max = live[i].n;
    }
    let mut provider_income: BTreeMap<String, f64> = BTreeMap::new();
    let mut paid_usd = 0.0;
    let mut release_total = 0.0;
    let mut release_paid = 0.0;
    let mut validator_n_sum = 0.0;
    let mut server_n_sum = 0.0;
    let mut n_sum = [0.0f64; 2];
    let window = 30usize;
    for (t, tb) in ticks.iter().enumerate() {
        paid_usd += tb.paid_usd;
        release_total += tb.provider_release_tnzo;
        // Server capacity is the trace's; its marginal cost is the trace's.
        live[SERVER].n = tb.provider_capacity_units / 24.0;
        let server_served: f64 = tb.served_by.iter().map(|x| x.1).sum();
        live[SERVER].marginal_usd_unit = if server_served > 0.0 {
            tb.provider_cost_usd / server_served
        } else {
            0.0
        };
        server_n_sum += live[SERVER].n;
        n_sum[EDGE] += live[EDGE].n;
        n_sum[DESKTOP] += live[DESKTOP].n;

        let mut free: Vec<f64> = live.iter().map(Live::capacity).collect();
        // The trace's providers can always do what they did.
        free[SERVER] = free[SERVER].max(tb.units);
        let mut got = [0.0f64; 3];
        let non_critical = (tb.units - tb.critical_units).max(0.0);
        let small = non_critical * s.small_share;
        let medium = non_critical * s.medium_share;
        let rest = (tb.units - small - medium).max(0.0);
        let left = split(
            &live,
            &mut free,
            &[EDGE, DESKTOP, SERVER],
            small,
            s.dispatch,
            &mut got,
        );
        let left = split(
            &live,
            &mut free,
            &[DESKTOP, SERVER],
            medium + left,
            s.dispatch,
            &mut got,
        );
        let left = split(
            &live,
            &mut free,
            &[SERVER],
            rest + left,
            s.dispatch,
            &mut got,
        );
        got[SERVER] += left;

        let price_unit = if tb.units > 0.0 {
            tb.paid_usd / tb.units
        } else {
            0.0
        };
        let total_units: f64 = got.iter().sum();
        for (i, c) in classes.iter().enumerate() {
            let units = got[i];
            let service = units * price_unit * tb.provider_share;
            let (rel_tnzo, rel_usd) = if total_units > 0.0 {
                (
                    tb.provider_release_tnzo * units / total_units,
                    tb.provider_release_usd * units / total_units,
                )
            } else {
                (0.0, 0.0)
            };
            release_paid += rel_tnzo;
            let (cost_lo, cost_hi) = if i == SERVER {
                let c = units * live[SERVER].marginal_usd_unit
                    + tb.provider_capacity_units * capex_unit;
                (c, c)
            } else {
                (
                    live[i].n * live[i].cost_day.0,
                    live[i].n * live[i].cost_day.1,
                )
            };
            let b = books.get_mut(c).expect("class");
            b.units += units;
            b.service_usd += service;
            b.release_tnzo += rel_tnzo;
            b.release_usd += rel_usd;
            b.cost_lo_usd += cost_lo;
            b.cost_hi_usd += cost_hi;
            if (service > 0.0 || rel_tnzo > 0.0) && units <= 0.0 {
                b.violations += 1;
            }
            let income = service + rel_usd;
            if i == SERVER {
                if units > 0.0 && server_served > 0.0 {
                    for (id, u) in &tb.served_by {
                        *provider_income.entry(id.clone()).or_default() +=
                            income * u / server_served;
                    }
                }
            } else {
                let per_device = if live[i].n > 0.0 {
                    income / live[i].n
                } else {
                    0.0
                };
                live[i].income.push(per_device);
            }
        }
        // Validators: the accounting's own set and income.
        let vb = books.get_mut(&DeviceClass::Validator).expect("class");
        let vn = tb.validators_active as f64;
        validator_n_sum += vn;
        vb.release_usd += tb.validator_income_each_usd * vn;
        vb.cost_lo_usd += tb.validator_cost_each_usd * vn;
        vb.cost_hi_usd += tb.validator_cost_each_usd * vn;
        // Their cover may pay from fees of earlier ticks, never before any.
        if tb.validator_income_each_usd > 0.0 && paid_usd <= 0.0 {
            vb.violations += 1;
        }

        // Monthly: devices follow their paid income.
        if (t + 1) % window == 0 {
            for i in [EDGE, DESKTOP] {
                let l = &mut live[i];
                if l.income.len() < window {
                    continue;
                }
                let inc: f64 = l.income[l.income.len() - window..].iter().sum();
                let cost = (l.cost_day.0 + l.cost_day.1) / 2.0 * window as f64;
                let r = if cost > 0.0 { inc / cost } else { 0.0 };
                if r >= s.join_ratio {
                    l.n *= 1.0 + s.monthly_move;
                } else if r < s.exit_ratio {
                    l.n = (l.n * (1.0 - s.monthly_move)).max(1.0);
                }
                let b = books.get_mut(&classes[i]).expect("class");
                b.devices_max = b.devices_max.max(l.n);
            }
        }
    }
    let n_ticks = ticks.len().max(1) as f64;
    let all_units: f64 = classes.iter().map(|c| books[c].units).sum();
    let incomes: BTreeMap<DeviceClass, f64> = books
        .iter()
        .map(|(c, b)| (*c, b.service_usd + b.release_usd))
        .collect();
    let total_income: f64 = incomes.values().sum();
    let means = [
        n_sum[EDGE] / n_ticks,
        n_sum[DESKTOP] / n_ticks,
        server_n_sum / n_ticks,
        validator_n_sum / n_ticks,
    ];
    let months = n_ticks / 30.44;
    for (k, c) in DeviceClass::ALL.iter().enumerate() {
        let b = books.get_mut(c).expect("class");
        b.devices_mean = means[k];
        match c {
            DeviceClass::Edge => b.devices_end = live[EDGE].n,
            DeviceClass::Desktop => b.devices_end = live[DESKTOP].n,
            DeviceClass::Server => {
                b.devices_start = ticks
                    .first()
                    .map_or(0.0, |t| t.provider_capacity_units / 24.0);
                b.devices_end = live[SERVER].n;
            }
            DeviceClass::Validator => {
                b.devices_start = ticks.first().map_or(0.0, |t| t.validators_active as f64);
                b.devices_end = ticks.last().map_or(0.0, |t| t.validators_active as f64);
            }
        }
        if b.devices_max == 0.0 {
            b.devices_max = b.devices_start.max(b.devices_end);
        }
        b.units_share = if all_units > 0.0 {
            b.units / all_units
        } else {
            0.0
        };
        let inc = incomes[c];
        let dm = (means[k] * months).max(1e-12);
        b.income_device_month = inc / dm;
        b.cost_device_month_lo = b.cost_lo_usd / dm;
        b.cost_device_month_hi = b.cost_hi_usd / dm;
        b.ratio_at_hi_cost = if b.cost_hi_usd > 0.0 {
            inc / b.cost_hi_usd
        } else {
            0.0
        };
        b.ratio_at_lo_cost = if b.cost_lo_usd > 0.0 {
            inc / b.cost_lo_usd
        } else {
            0.0
        };
        b.income_share = if total_income > 0.0 {
            inc / total_income
        } else {
            0.0
        };
    }
    // Concentration over operators: each trace provider, and each device or
    // validator of the other classes with an equal part of its class.
    let mut shares: Vec<f64> = provider_income
        .values()
        .map(|v| v / total_income.max(1e-12))
        .collect();
    for (class, k) in [
        DeviceClass::Edge,
        DeviceClass::Desktop,
        DeviceClass::Validator,
    ]
    .into_iter()
    .zip([0usize, 1, 3])
    {
        let n = means[k].round().max(1.0) as usize;
        let each = incomes[&class] / total_income.max(1e-12) / n as f64;
        if each > 0.0 {
            shares.extend(std::iter::repeat_n(each, n.min(100_000)));
        }
    }
    shares.sort_by(|a, b| b.total_cmp(a));
    let hhi = shares.iter().map(|s| s * s).sum();
    let top10 = shares.iter().take(10).sum();
    let charter_violations = books.values().map(|b| b.violations).sum();
    DeviceRun {
        ticks: ticks.len() as u64,
        paid_usd,
        classes: books,
        hhi,
        top10_share: top10,
        release_split_error_tnzo: release_paid - release_total,
        charter_violations,
    }
}

/// Market shares, TNZO pool depths, dispatch rules, edge throughputs and
/// small-model work shares the sweep runs.
pub const SHARES: [f64; 3] = [0.001, 0.01, 0.1];
pub const DEPTHS: [(&str, f64); 2] = [("thin", 20_000.0), ("deep", 1_000_000.0)];
pub const DISPATCH: [Dispatch; 2] = [Dispatch::ProRata, Dispatch::Merit];
pub const SMALL_SHARES: [f64; 2] = [0.1, 0.3];

/// One run's record.
#[derive(Debug, Clone, Serialize)]
pub struct DeviceRec {
    pub seed: u64,
    pub scenario: String,
    pub variant: String,
    pub share: f64,
    pub depth: String,
    pub dispatch: Dispatch,
    pub edge_tokens_per_s: f64,
    pub small_share: f64,
    pub run: DeviceRun,
}

/// Runs every trace under `dirs` (the market-stress format) in every
/// setting, on `threads` threads, with each edge throughput in
/// `edge_tokens_per_s`. Traces outside the validated band and traces that do
/// not read are reported through `bad` and skipped.
pub fn sweep(
    dirs: &[PathBuf],
    threads: usize,
    edge_tokens_per_s: &[f64],
    mut sink: impl FnMut(DeviceRec),
    mut bad: impl FnMut(String),
) {
    let files = crate::usage_lw::find(dirs);
    crate::chaos::run_parallel(
        &files,
        threads,
        |(m, t): &(PathBuf, PathBuf)| -> Result<Vec<DeviceRec>, String> {
            let trace = Trace::read_lw(m, t)?;
            let p = &trace.manifest.parameters;
            let get = |k: &str| {
                p.get("lw.scenario")
                    .and_then(|s| s.get(k))
                    .and_then(|s| s.as_str())
                    .unwrap_or("?")
                    .to_string()
            };
            if !p
                .get("lw.inside_band")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                return Err("outside the validated band".into());
            }
            let (scenario, variant) = (get("name"), get("variant"));
            let capex = server_capex(&trace);
            let mut out = Vec::new();
            for share in SHARES {
                for (depth, usd) in DEPTHS {
                    let rules = Rules {
                        market_share: share,
                        pool_depth_usd: Some(usd),
                        ..Rules::default()
                    };
                    let ticks = book(&trace, &rules);
                    for dispatch in DISPATCH {
                        for tps in edge_tokens_per_s {
                            for small in SMALL_SHARES {
                                let s = DeviceSettings {
                                    dispatch,
                                    edge_tokens_per_s: *tps,
                                    small_share: small,
                                    ..DeviceSettings::default()
                                };
                                out.push(DeviceRec {
                                    seed: trace.manifest.seed,
                                    scenario: scenario.clone(),
                                    variant: variant.clone(),
                                    share,
                                    depth: depth.into(),
                                    dispatch,
                                    edge_tokens_per_s: *tps,
                                    small_share: small,
                                    run: run(&ticks, capex, &s),
                                });
                            }
                        }
                    }
                }
            }
            Ok(out)
        },
        |(m, _), r| match r {
            Ok(v) => v.into_iter().for_each(&mut sink),
            Err(e) => bad(format!("{}: {e}", m.display())),
        },
    );
}

fn range(v: impl Iterator<Item = f64>) -> String {
    let mut v: Vec<f64> = v.filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return "-".into();
    }
    v.sort_by(f64::total_cmp);
    let f = |x: f64| {
        if x.abs() >= 1e6 {
            format!("{x:.2e}")
        } else if x.abs() >= 100.0 {
            format!("{x:.0}")
        } else if x.abs() >= 1.0 {
            format!("{x:.2}")
        } else {
            format!("{x:.3}")
        }
    };
    let lo = v[0];
    let hi = v[v.len() - 1];
    let med = v[v.len() / 2];
    if (hi - lo).abs() < 1e-12 {
        f(lo)
    } else {
        format!("{}..{} (median {})", f(lo), f(hi), f(med))
    }
}

/// The sweep as Markdown.
pub fn report(recs: &[DeviceRec], bad: &[String], seeds: usize) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(s, "# Device classes on usage traces\n");
    let _ = writeln!(
        s,
        "Traces: {seeds} seed(s); {} runs; {} trace(s) left out (listed at the end). Ranges are over seeds, \
         scenario variants, TNZO pool depth, dispatch rule and the small-model work share, by the share of the \
         market that pays through the network. Income is paid work only: service payments less the fee and the \
         leg, and the provider pool release for delivered units; validators' income is the accounting's. No figure \
         is a forecast or a price.\n",
        recs.len(),
        bad.len()
    );
    let viol: u64 = recs.iter().map(|r| r.run.charter_violations).sum();
    let split = recs
        .iter()
        .map(|r| r.run.release_split_error_tnzo.abs())
        .fold(0.0, f64::max);
    let _ = writeln!(
        s,
        "Charter: payouts with no delivered paid unit in the tick: {viol}. Largest gap between the release paid to \
         classes and the accounting's provider release: {split:.3e} TNZO.\n"
    );
    let mut tps: Vec<f64> = recs.iter().map(|r| r.edge_tokens_per_s).collect();
    tps.sort_by(f64::total_cmp);
    tps.dedup();
    for share in SHARES {
        for t in &tps {
            let sel: Vec<&DeviceRec> = recs
                .iter()
                .filter(|r| r.share == share && r.edge_tokens_per_s == *t)
                .collect();
            if sel.is_empty() {
                continue;
            }
            let _ = writeln!(
                s,
                "## Market share {:.1}%, edge {} tokens/s ({} runs)\n",
                share * 100.0,
                t,
                sel.len()
            );
            let _ = writeln!(
                s,
                "| class | devices start | devices end | units share | income USD/device-month | cost USD/device-month (low..high) | income/cost at high cost | income/cost at low cost | income share |"
            );
            let _ = writeln!(s, "|---|---|---|---|---|---|---|---|---|");
            for c in DeviceClass::ALL {
                let b = |f: fn(&ClassBook) -> f64| range(sel.iter().map(|r| f(&r.run.classes[&c])));
                let _ = writeln!(
                    s,
                    "| {} | {} | {} | {} | {} | {} .. {} | {} | {} | {} |",
                    c.name(),
                    b(|x| x.devices_start),
                    b(|x| x.devices_end),
                    b(|x| x.units_share),
                    b(|x| x.income_device_month),
                    b(|x| x.cost_device_month_lo),
                    b(|x| x.cost_device_month_hi),
                    b(|x| x.ratio_at_hi_cost),
                    b(|x| x.ratio_at_lo_cost),
                    b(|x| x.income_share),
                );
            }
            let _ = writeln!(
                s,
                "\nConcentration of operator income: HHI {}, ten largest operators {}.\n",
                range(sel.iter().map(|r| r.run.hhi)),
                range(sel.iter().map(|r| r.run.top10_share))
            );
            for d in DISPATCH {
                let e: Vec<&&DeviceRec> = sel.iter().filter(|r| r.dispatch == d).collect();
                let covers = e
                    .iter()
                    .filter(|r| r.run.classes[&DeviceClass::Edge].ratio_at_hi_cost >= 1.0)
                    .count();
                let covers_lo = e
                    .iter()
                    .filter(|r| r.run.classes[&DeviceClass::Edge].ratio_at_lo_cost >= 1.0)
                    .count();
                let _ = writeln!(
                    s,
                    "- {:?} dispatch: edge income covers its high cost in {covers} of {} runs, its low cost in {covers_lo}; edge income {} USD/device-month.",
                    d,
                    e.len(),
                    range(
                        e.iter()
                            .map(|r| r.run.classes[&DeviceClass::Edge].income_device_month)
                    )
                );
            }
            let _ = writeln!(s);
        }
    }
    if !bad.is_empty() {
        let _ = writeln!(s, "## Left out\n");
        for b in bad {
            let _ = writeln!(s, "- {b}");
        }
    }
    s
}
