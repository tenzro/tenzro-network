//! FIXTURES: fixed usage traces for the stress cells, in the trace format of
//! [`crate::usage`]. They are written by hand as fixed paths, with no
//! actors, no decisions and no randomness: every buyer row is a segment's
//! demand in a region times a scripted multiple, every provider row a fixed
//! share of the region's capacity at a fixed cost. Results replayed from
//! them are provisional; the cells are rerun on market-stress simulation traces, which
//! replace these.

use std::collections::BTreeMap;

use crate::usage::{Manifest, SEGMENTS, ShockEntry, Trace, TraceRow};

/// Regions and their share of demand.
pub const REGIONS: [(&str, f64); 5] = [
    ("na", 0.35),
    ("eu", 0.25),
    ("apac", 0.25),
    ("mea", 0.08),
    ("latam", 0.07),
];

/// Segment mixes: shares of paid usage by segment, in [`SEGMENTS`] order.
pub const MIXES: [(&str, [f64; 4]); 3] = [
    ("critical_heavy", [0.40, 0.25, 0.15, 0.20]),
    ("balanced", [0.25, 0.25, 0.25, 0.25]),
    ("volume_heavy", [0.10, 0.20, 0.40, 0.30]),
];

/// Paid usage at the start of a fixture, USD a day.
pub const SCALES: [f64; 3] = [5_000.0, 50_000.0, 500_000.0];

/// Share of a downturn's cut each segment takes: verifiable critical uses
/// least, developers and resellers most; autonomous use also answers the
/// compute price.
pub const SENSITIVITY: [f64; 4] = [0.35, 0.75, 0.6, 1.0];
/// Autonomous units answer the compute price with this elasticity.
pub const AUTONOMOUS_ELASTICITY: f64 = 1.2;

const PRICE: f64 = 2.0;
const HEADROOM: f64 = 1.8;

/// One provider of a region in the fixtures: kind, share of capacity,
/// marginal cost per unit (energy and operation; the hardware is sunk).
const PROVIDERS: [(&str, f64, f64); 6] = [
    ("independent-1", 0.15, 0.45),
    ("independent-2", 0.15, 0.45),
    ("independent-3", 0.15, 0.45),
    ("datacenter", 0.25, 0.40),
    ("neocloud-1", 0.15, 0.35),
    ("neocloud-2", 0.15, 0.35),
];

/// A fixture cell: its name, the family it reports under, and its script.
#[derive(Debug, Clone)]
pub struct FixtureCell {
    pub name: String,
    pub family: &'static str,
    script: Script,
}

#[derive(Debug, Clone)]
enum Script {
    Baseline,
    Launch,
    Burst { cut: f64, months: f64 },
    Glut { fall: f64 },
    LiquidityDry,
    Depeg,
    RecessionTail,
    Neocloud { share: f64, cheap: bool },
    SupplyCut,
    ExportControls,
    Sanction,
    Cable { days: u64 },
    Energy,
    RegionOffline,
    EuFactoryIdle,
    EuConsortium { cheap: bool },
    EuResidency,
}

/// Every fixture cell.
pub fn cells() -> Vec<FixtureCell> {
    let mut v = vec![
        cell("baseline", "baseline", Script::Baseline),
        cell("launch_thin_liquidity", "launch", Script::Launch),
    ];
    for cut in [0.30, 0.60, 0.85] {
        for months in [6.0, 12.0, 18.0] {
            v.push(cell(
                &format!("burst_{:.0}pct_{months:.0}m", cut * 100.0),
                "bubble_burst",
                Script::Burst { cut, months },
            ));
        }
    }
    for fall in [0.5, 0.8] {
        v.push(cell(
            &format!("gpu_glut_{:.0}pct", fall * 100.0),
            "bubble_burst",
            Script::Glut { fall },
        ));
    }
    v.push(cell(
        "tnzo_liquidity_dry",
        "bubble_burst",
        Script::LiquidityDry,
    ));
    v.push(cell("stable_depeg_suspend", "bubble_burst", Script::Depeg));
    v.push(cell(
        "recession_tail",
        "bubble_burst",
        Script::RecessionTail,
    ));
    for share in [0.10, 0.30, 0.60] {
        for cheap in [false, true] {
            v.push(cell(
                &format!(
                    "neocloud_{:.0}pct_{}",
                    share * 100.0,
                    if cheap { "resold_cheap" } else { "dark" }
                ),
                "neocloud",
                Script::Neocloud { share, cheap },
            ));
        }
    }
    v.push(cell("geo_supply_cut", "geopolitical", Script::SupplyCut));
    v.push(cell(
        "geo_export_controls",
        "geopolitical",
        Script::ExportControls,
    ));
    v.push(cell(
        "geo_sanctioned_rail",
        "geopolitical",
        Script::Sanction,
    ));
    for days in [7, 21] {
        v.push(cell(
            &format!("geo_cable_cut_{days}d"),
            "geopolitical",
            Script::Cable { days },
        ));
    }
    v.push(cell("geo_energy_spike", "geopolitical", Script::Energy));
    v.push(cell(
        "geo_region_offline",
        "geopolitical",
        Script::RegionOffline,
    ));
    v.push(cell("eu_factory_idle", "eu", Script::EuFactoryIdle));
    v.push(cell(
        "eu_consortium_dark",
        "eu",
        Script::EuConsortium { cheap: false },
    ));
    v.push(cell(
        "eu_consortium_resold",
        "eu",
        Script::EuConsortium { cheap: true },
    ));
    v.push(cell("eu_residency", "eu", Script::EuResidency));
    v
}

fn cell(name: &str, family: &'static str, script: Script) -> FixtureCell {
    FixtureCell {
        name: name.to_string(),
        family,
        script,
    }
}

fn shock(tick: u64, until: Option<u64>, kind: &str) -> ShockEntry {
    ShockEntry {
        tick,
        until,
        kind: kind.into(),
        region: None,
        regions: None,
        asset: None,
        value: None,
    }
}

/// The fixture trace of `c` over `days` daily ticks at `scale_usd_day` of
/// paid usage in segment mix `mix`.
pub fn fixture(c: &FixtureCell, mix: [f64; 4], scale_usd_day: f64, days: u64) -> Trace {
    let scale = if matches!(c.script, Script::Launch) {
        SCALES[0]
    } else {
        scale_usd_day
    };
    let mut m = Manifest {
        seed: 0,
        tick_seconds: 86_400,
        parameters: BTreeMap::new(),
        shock_schedule: Vec::new(),
    };
    m.parameters
        .insert("fixture".into(), serde_json::json!(c.name));
    m.parameters.insert(
        "rails".into(),
        serde_json::json!(
            REGIONS
                .iter()
                .map(|(r, _)| (r.to_string(), serde_json::json!({"USDC": 0.6, "USDT": 0.4})))
                .collect::<BTreeMap<_, _>>()
        ),
    );
    let depth = if matches!(c.script, Script::Launch) {
        20_000.0
    } else {
        1_000_000.0
    };
    m.parameters
        .insert("pool_depth_usd".into(), serde_json::json!(depth));
    let at = 120u64;
    match &c.script {
        Script::LiquidityDry => {
            let mut s = shock(90, None, "liquidity");
            s.value = Some(0.05);
            m.shock_schedule.push(s);
        }
        Script::Depeg => {
            let mut s = shock(at, Some(at + 10), "stable_depeg");
            s.asset = Some("USDC".into());
            s.value = Some(0.90);
            m.shock_schedule.push(s);
        }
        Script::Sanction => {
            let mut s = shock(90, Some(455), "sanction");
            s.asset = Some("USDT".into());
            s.region = Some("mea".into());
            m.shock_schedule.push(s);
        }
        Script::Cable { days } => {
            let mut s = shock(at, Some(at + days), "partition");
            s.regions = Some(vec!["apac".into()]);
            m.shock_schedule.push(s);
        }
        Script::RegionOffline => {
            let mut s = shock(at, Some(at + 60), "region_offline");
            s.region = Some("mea".into());
            m.shock_schedule.push(s);
        }
        Script::Energy => {
            for r in ["eu", "apac"] {
                let mut s = shock(at, Some(at + 180), "energy");
                s.region = Some(r.into());
                s.value = Some(2.5);
                m.shock_schedule.push(s);
            }
        }
        _ => {}
    }

    let mut rows = Vec::new();
    for t in 0..days {
        let d = t as f64;
        // The cell's script for this day.
        let mut cut = 0.0;
        let mut price_mult = 1.0;
        let ramp = |start: f64, months: f64| ((d - start) / (months * 30.44)).clamp(0.0, 1.0);
        match &c.script {
            Script::Burst { cut: k, months } => cut = k * ramp(at as f64, *months),
            Script::Glut { fall } => price_mult = 1.0 - fall * ramp(at as f64, 6.0),
            Script::RecessionTail => cut = 0.40 * ramp(at as f64, 12.0),
            Script::SupplyCut => price_mult = 1.0 + 0.4 * ramp(at as f64, 3.0),
            _ => {}
        }
        for (region, rshare) in REGIONS {
            let r = region.to_string();
            let mut demand_units = 0.0;
            let mut region_price = PRICE * price_mult;
            if matches!(
                c.script,
                Script::EuFactoryIdle | Script::EuConsortium { .. }
            ) && region == "eu"
                && d >= 60.0
            {
                region_price *= 0.75;
            }
            let mut seg_units = [0.0; 4];
            for (i, s) in SEGMENTS.iter().enumerate() {
                let mut mult = (1.0 - (cut * SENSITIVITY[i]).min(0.95)).max(0.0);
                if *s == "autonomous" && region_price < PRICE {
                    mult *= (region_price / PRICE).powf(-AUTONOMOUS_ELASTICITY);
                }
                if matches!(c.script, Script::EuResidency) && region == "eu" && i == 0 {
                    mult *= 2.0;
                }
                let usd0 = scale * rshare * mix[i];
                seg_units[i] = usd0 / PRICE * mult;
                demand_units += seg_units[i];
                let _ = s;
            }
            // Capacity, sized to launch demand with headroom.
            let base_units = scale * rshare / PRICE;
            let mut providers: Vec<(String, f64, f64)> = PROVIDERS
                .iter()
                .map(|(k, sh, cost)| (format!("{region}-{k}"), base_units * HEADROOM * sh, *cost))
                .collect();
            let energy = matches!(c.script, Script::Energy)
                && (region == "eu" || region == "apac")
                && d >= at as f64
                && d < at as f64 + 180.0;
            if energy {
                for p in &mut providers {
                    p.2 *= 1.0 + (2.5 - 1.0) / 3.0;
                }
            }
            match &c.script {
                Script::Neocloud { share, cheap } if d >= at as f64 => {
                    // `share` of capacity leaves: neoclouds first, then the
                    // data centre.
                    let mut left = *share;
                    let mut gone = 0.0;
                    for p in providers.iter_mut().rev() {
                        let frac = p.1 / (base_units * HEADROOM);
                        if left <= 0.0 || p.0.contains("independent") {
                            continue;
                        }
                        let take = frac.min(left);
                        gone += take * base_units * HEADROOM;
                        p.1 -= take * base_units * HEADROOM;
                        left -= take;
                    }
                    if *cheap && d >= at as f64 + 30.0 {
                        providers.push((format!("{region}-independent-ex-neocloud"), gone, 0.30));
                        region_price *= 0.8;
                    }
                }
                Script::SupplyCut if region == "apac" && d >= at as f64 => {
                    for p in &mut providers {
                        p.1 *= 0.6;
                    }
                }
                Script::ExportControls
                    if (region == "apac" || region == "mea") && d >= at as f64 =>
                {
                    for p in providers.iter_mut().filter(|p| p.0.contains("neocloud")) {
                        p.1 *= 0.5;
                    }
                }
                Script::EuFactoryIdle if region == "eu" && d >= 60.0 => {
                    providers.push(("eu-ai-factory".into(), base_units * 3.0, 0.55));
                }
                Script::EuConsortium { cheap } if region == "eu" && d >= 60.0 => {
                    if d < 240.0 {
                        providers.push(("eu-ai-factory".into(), base_units * 3.0, 0.55));
                    } else if *cheap && d >= 300.0 {
                        providers.push((
                            "eu-independent-ex-factory".into(),
                            base_units * 3.0,
                            0.35,
                        ));
                    }
                }
                Script::EuResidency if region == "eu" => {
                    providers.push(("eu-ai-factory".into(), base_units * 2.0, 0.55));
                }
                _ => {}
            }
            // Serve in region, cheapest first.
            providers.sort_by(|a, b| a.2.total_cmp(&b.2).then(a.0.cmp(&b.0)));
            let cap: f64 = providers.iter().map(|p| p.1).sum();
            let served = demand_units.min(cap);
            let unmet_share = if demand_units > 0.0 {
                1.0 - served / demand_units
            } else {
                0.0
            };
            for (i, s) in SEGMENTS.iter().enumerate() {
                rows.push(TraceRow {
                    tick: t,
                    actor_id: format!("{region}-{s}"),
                    actor_kind: "buyer".into(),
                    segment: Some(s.to_string()),
                    region: r.clone(),
                    demand: seg_units[i],
                    supply: 0.0,
                    clearing_price: region_price,
                    utilisation: 0.0,
                    unmet_demand: seg_units[i] * unmet_share,
                    capacity: None,
                    cost: None,
                    residency: Some(i == 0 || matches!(c.script, Script::ExportControls)),
                });
            }
            let mut left = served;
            for (id, capacity, cost) in providers {
                if capacity <= 0.0 {
                    continue;
                }
                let supply = left.min(capacity);
                left -= supply;
                rows.push(TraceRow {
                    tick: t,
                    actor_id: id,
                    actor_kind: "provider".into(),
                    segment: None,
                    region: r.clone(),
                    demand: 0.0,
                    supply,
                    clearing_price: region_price,
                    utilisation: supply / capacity,
                    unmet_demand: 0.0,
                    capacity: Some(capacity),
                    cost: Some(cost),
                    residency: None,
                });
            }
        }
    }
    Trace::from_rows(m, rows)
}

/// One replay of the fixture sweep.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Record {
    pub cell: String,
    pub family: String,
    pub mix: String,
    pub scale_usd_day: f64,
    pub treasury_leg_bps: u64,
    pub availability_tnzo_hour: f64,
    pub mechanism: String,
    pub outcome: crate::usage::Outcome,
}

/// Treasury legs (governed, bps of paid value) and verified-availability
/// settings (TNZO a validator-hour) every cell runs under.
pub const LEGS: [u64; 2] = [0, 100];
pub const AVAILABILITY: [f64; 2] = [0.0, 1.0];

/// Replays every fixture cell under every mix, scale, leg, availability
/// setting and mechanism switch, on `threads` threads.
pub fn sweep(days: u64, threads: usize, mut sink: impl FnMut(Record)) {
    use crate::usage::{Mechanisms, Rules, replay};
    let mut jobs = Vec::new();
    for c in cells() {
        for (mix_name, mix) in MIXES {
            let scales: &[f64] = if c.family == "launch" {
                &SCALES[..1]
            } else {
                &SCALES
            };
            for &scale in scales {
                jobs.push((c.clone(), mix_name, mix, scale));
            }
        }
    }
    crate::chaos::run_parallel(
        &jobs,
        threads,
        |(c, mix_name, mix, scale)| {
            let trace = fixture(c, *mix, *scale, days);
            let mut out = Vec::new();
            for leg in LEGS {
                for avail in AVAILABILITY {
                    for (mech_name, mech) in Mechanisms::sweep() {
                        let mut rules = Rules {
                            availability_tnzo_hour: avail,
                            mechanisms: mech,
                            ..Rules::default()
                        };
                        rules.overrides.insert(
                            tenzro_vm::native::economy::TREASURY_LEG_INFERENCE_PARAM.into(),
                            leg,
                        );
                        out.push(Record {
                            cell: c.name.clone(),
                            family: c.family.to_string(),
                            mix: mix_name.to_string(),
                            scale_usd_day: *scale,
                            treasury_leg_bps: leg,
                            availability_tnzo_hour: avail,
                            mechanism: mech_name.to_string(),
                            outcome: replay(&trace, &rules),
                        });
                    }
                }
            }
            out
        },
        |_, rs| {
            for r in rs {
                sink(r);
            }
        },
    );
}

fn range(v: impl Iterator<Item = f64>) -> String {
    let v: Vec<f64> = v.filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return "-".into();
    }
    let lo = v.iter().copied().fold(f64::INFINITY, f64::min);
    let hi = v.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let f = |x: f64| {
        if x.abs() >= 1e6 {
            format!("{:.2e}", x)
        } else if x.abs() >= 100.0 {
            format!("{x:.0}")
        } else {
            format!("{x:.3}")
        }
    };
    if (hi - lo).abs() < 1e-12 {
        f(lo)
    } else {
        format!("{}..{}", f(lo), f(hi))
    }
}

/// The sweep as Markdown, labelled provisional.
pub fn report(recs: &[Record]) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    s.push_str("# Usage-driven stress cells (PROVISIONAL: fixture traces)\n\n");
    s.push_str("Fixture traces, not simulation traces: every figure here is provisional and is rerun on market-stress simulation traces. Ranges are over segment mix, paid-usage scale, treasury leg and availability setting; no figure is a forecast or a price.\n\n");
    s.push_str("Checks: floor = bonded validators never under 7 after warmup; treasury = never negative, no availability forfeit; operators = every region with demand keeps a provider online at or above its marginal cost; charter = every payout tick tied to a paid, verified unit; finality, residency and payments (suspend, never fall back).\n\n");
    // Per mechanism.
    s.push_str("## Mechanisms: do all cells hold?\n\n| mechanism | runs | runs holding | cells where every run holds | cells with a failing run |\n|---|---|---|---|---|\n");
    let mechs: Vec<String> = crate::usage::Mechanisms::sweep()
        .iter()
        .map(|m| m.0.to_string())
        .collect();
    let cellnames: Vec<String> = cells().iter().map(|c| c.name.clone()).collect();
    for m in &mechs {
        let rs: Vec<&Record> = recs.iter().filter(|r| &r.mechanism == m).collect();
        let hold = rs.iter().filter(|r| r.outcome.holds()).count();
        let mut ok = 0;
        let mut bad = Vec::new();
        for c in &cellnames {
            let cr: Vec<&&Record> = rs.iter().filter(|r| &r.cell == c).collect();
            if !cr.is_empty() && cr.iter().all(|r| r.outcome.holds()) {
                ok += 1;
            } else if !cr.is_empty() {
                bad.push(c.clone());
            }
        }
        let _ = writeln!(
            s,
            "| {m} | {} | {hold} | {ok}/{} | {} |",
            rs.len(),
            cellnames.len(),
            if bad.len() > 6 {
                format!("{} cells", bad.len())
            } else {
                bad.join(", ")
            }
        );
    }
    // What holds the floor, by scale and leg (baseline, no mechanism).
    s.push_str("\n## Validator cover from stable fees alone (baseline cell, no mechanism)\n\n| paid usage USD/day | treasury leg bps | availability TNZO/h | cover of 7 seats (mean) | income/cost least month | validators least | floor holds |\n|---|---|---|---|---|---|---|\n");
    for scale in SCALES {
        for leg in LEGS {
            for a in AVAILABILITY {
                let rs: Vec<&Record> = recs
                    .iter()
                    .filter(|r| {
                        r.cell == "baseline"
                            && r.mechanism == "none"
                            && r.scale_usd_day == scale
                            && r.treasury_leg_bps == leg
                            && r.availability_tnzo_hour == a
                    })
                    .collect();
                if rs.is_empty() {
                    continue;
                }
                let _ = writeln!(
                    s,
                    "| {scale:.0} | {leg} | {a} | {} | {} | {} | {}/{} |",
                    range(rs.iter().map(|r| r.outcome.cover_ratio_mean)),
                    range(rs.iter().map(|r| r.outcome.validator_income_ratio_min)),
                    range(rs.iter().map(|r| r.outcome.validators_min as f64)),
                    rs.iter().filter(|r| r.outcome.pass_floor).count(),
                    rs.len()
                );
            }
        }
    }
    // Per cell, no mechanism.
    s.push_str("\n## Cells (no mechanism)\n\n| cell | family | runs holding | floor | treasury | operators | charter | finality | residency | validators least | cover mean | income/cost least | operators online least | utilisation | price end USD | treasury end USD | unmet share | suspended USD | stranded prepaid USD |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    for c in cells() {
        let rs: Vec<&Record> = recs
            .iter()
            .filter(|r| r.cell == c.name && r.mechanism == "none")
            .collect();
        if rs.is_empty() {
            continue;
        }
        let n = rs.len();
        let cnt = |f: &dyn Fn(&crate::usage::Outcome) -> bool| {
            rs.iter().filter(|r| f(&r.outcome)).count()
        };
        let _ = writeln!(
            s,
            "| {} | {} | {}/{n} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            c.name,
            c.family,
            cnt(&|o| o.holds()),
            cnt(&|o| o.pass_floor),
            cnt(&|o| o.pass_treasury),
            cnt(&|o| o.pass_operators),
            cnt(&|o| o.pass_charter),
            cnt(&|o| o.pass_finality),
            cnt(&|o| o.pass_residency),
            range(rs.iter().map(|r| r.outcome.validators_min as f64)),
            range(rs.iter().map(|r| r.outcome.cover_ratio_mean)),
            range(rs.iter().map(|r| r.outcome.validator_income_ratio_min)),
            range(rs.iter().map(|r| r.outcome.operators_min as f64)),
            range(rs.iter().map(|r| r.outcome.utilisation_mean)),
            range(rs.iter().map(|r| r.outcome.price_end)),
            range(rs.iter().map(|r| r.outcome.treasury_value_end_usd)),
            range(rs.iter().map(|r| r.outcome.unmet_share)),
            range(rs.iter().map(|r| r.outcome.suspended_usd)),
            range(rs.iter().map(|r| r.outcome.stranded_prepaid_usd))
        );
    }
    // Per segment.
    s.push_str("\n## Paid usage by segment (no mechanism): least day after warmup / last day, USD\n\n| cell |");
    for seg in crate::usage::SEGMENTS {
        let _ = write!(s, " {seg} |");
    }
    s.push_str("\n|---|---|---|---|---|\n");
    for c in cells() {
        let rs: Vec<&Record> = recs
            .iter()
            .filter(|r| {
                r.cell == c.name
                    && r.mechanism == "none"
                    && r.treasury_leg_bps == 0
                    && r.availability_tnzo_hour == 0.0
            })
            .collect();
        if rs.is_empty() {
            continue;
        }
        let _ = write!(s, "| {} |", c.name);
        for seg in crate::usage::SEGMENTS {
            let _ = write!(
                s,
                " {} / {} |",
                range(
                    rs.iter()
                        .map(|r| r.outcome.segment_min_tick.get(seg).copied().unwrap_or(0.0))
                ),
                range(
                    rs.iter()
                        .map(|r| r.outcome.segment_last_tick.get(seg).copied().unwrap_or(0.0))
                )
            );
        }
        s.push('\n');
    }
    // Operators per region.
    s.push_str("\n## Operator margin per delivered unit at the end, USD (no mechanism)\n\n| cell | na | eu | apac | mea | latam | regions without an operator at cost |\n|---|---|---|---|---|---|---|\n");
    for c in cells() {
        let rs: Vec<&Record> = recs
            .iter()
            .filter(|r| r.cell == c.name && r.mechanism == "none")
            .collect();
        if rs.is_empty() {
            continue;
        }
        let _ = write!(s, "| {} |", c.name);
        for (reg, _) in REGIONS {
            let _ = write!(
                s,
                " {} |",
                range(
                    rs.iter()
                        .filter_map(|r| r.outcome.operator_margin_by_region.get(reg).copied())
                )
            );
        }
        let mut without: std::collections::BTreeSet<String> = Default::default();
        for r in &rs {
            without.extend(r.outcome.regions_without_operator.iter().cloned());
        }
        let _ = writeln!(
            s,
            " {} |",
            if without.is_empty() {
                "none".into()
            } else {
                without.into_iter().collect::<Vec<_>>().join(", ")
            }
        );
    }
    // Charter by path.
    s.push_str("\n## Charter check by payout path (all runs, no mechanism)\n\n| path | tied to | USD paid (range per run) | ticks paid with no unit of its tie |\n|---|---|---|---|\n");
    for p in crate::usage::Payout::ALL {
        let rs: Vec<&Record> = recs.iter().filter(|r| r.mechanism == "none").collect();
        let v: u64 = rs
            .iter()
            .map(|r| r.outcome.paths.get(&p).map_or(0, |b| b.violations))
            .sum();
        let _ = writeln!(
            s,
            "| {p:?} | {} | {} | {v} |",
            p.tie(),
            range(
                rs.iter()
                    .map(|r| r.outcome.paths.get(&p).map_or(0.0, |b| b.paid_usd))
            )
        );
    }
    s
}
