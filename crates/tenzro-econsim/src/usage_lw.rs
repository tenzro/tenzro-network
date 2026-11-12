//! The stress cells on market-stress simulation traces.
//!
//! Each trace (a scenario variant at a seed) is replayed through the
//! chain's accounting ([`crate::usage::replay`]) under every setting the
//! market cannot tell us: the share of the market that pays through the
//! network, the governed treasury leg, the verified-availability reward,
//! the TNZO pool's depth at the start, where validators sit, and two
//! payment-rail shocks laid over the trace (a depeg that suspends one
//! stable asset, a sanction on one asset in one region). Every setting runs
//! with each post-downturn mechanism off and on.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::usage::{Mechanisms, Outcome, Rules, SEGMENTS, ShockEntry, Trace, replay};

/// Shares of the market's paid usage that settle on the network.
pub const SHARES: [f64; 3] = [0.001, 0.01, 0.1];
/// Treasury legs, bps of paid value (governed).
pub const LEGS: [u64; 2] = [0, 100];
/// Verified-availability reward, TNZO a validator-hour (the governed most
/// is 1).
pub const AVAILABILITY: [f64; 2] = [0.0, 1.0];
/// TNZO pool depth at the start, USD: launch-thin and deep.
pub const DEPTHS: [(&str, f64); 2] = [("thin", 20_000.0), ("deep", 1_000_000.0)];
/// Payment-rail overlays.
pub const OVERLAYS: [&str; 3] = ["none", "depeg", "sanction"];

/// One replay, its settings and the figures the report reads.
#[derive(Debug, Clone, Serialize)]
pub struct Rec {
    pub seed: u64,
    pub scenario: String,
    pub variant: String,
    pub inside_band: bool,
    pub overlay: String,
    pub share: f64,
    pub leg_bps: u64,
    pub availability: f64,
    pub depth: String,
    pub placement: String,
    pub mechanism: String,
    pub holds: bool,
    pub floor: bool,
    pub treasury: bool,
    pub operators: bool,
    pub charter: bool,
    pub finality: bool,
    pub residency: bool,
    pub payments: bool,
    pub validators_min: u32,
    pub cover_mean: f64,
    pub income_ratio_min: f64,
    pub operators_min: u32,
    pub utilisation: f64,
    pub price_min: f64,
    pub price_end: f64,
    pub treasury_end_usd: f64,
    pub paid_usd: f64,
    pub segment_usd: BTreeMap<String, f64>,
    pub segment_min_tick: BTreeMap<String, f64>,
    pub unmet_share: f64,
    pub suspended_usd: f64,
    pub operator_margin_min: f64,
    pub operator_earnings_usd: f64,
    pub finality_lost_ticks: u64,
    pub charter_violations: u64,
    pub availability_over_fees: f64,
    pub circulating_change_tnzo: f64,
    pub pool_end_tnzo: f64,
}

impl Rec {
    /// The cell a replay reports under: the scenario variant and overlay.
    pub fn cell(&self) -> String {
        if self.overlay == "none" {
            format!("{}/{}", self.scenario, self.variant)
        } else {
            format!("{}/{}+{}", self.scenario, self.variant, self.overlay)
        }
    }
}

/// Every (manifest, trace) pair under `dirs`.
pub fn find(dirs: &[PathBuf]) -> Vec<(PathBuf, PathBuf)> {
    let mut v = Vec::new();
    for d in dirs {
        let Ok(rd) = std::fs::read_dir(d) else {
            continue;
        };
        let mut names: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
        names.sort();
        for p in names {
            let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if let Some(stem) = n.strip_suffix(".manifest.json") {
                v.push((p.clone(), d.join(format!("{stem}.jsonl"))));
            }
        }
    }
    v
}

fn overlay_shocks(overlay: &str) -> Vec<ShockEntry> {
    let e = |kind: &str| ShockEntry {
        tick: 400,
        until: None,
        kind: kind.into(),
        region: None,
        regions: None,
        asset: None,
        value: None,
    };
    match overlay {
        "depeg" => {
            let mut s = e("stable_depeg");
            s.until = Some(410);
            s.asset = Some("USDA".into());
            s.value = Some(0.90);
            vec![s]
        }
        "sanction" => {
            let mut s = e("sanction");
            s.until = Some(765);
            s.asset = Some("USDB".into());
            s.region = Some("region-c".into());
            vec![s]
        }
        _ => Vec::new(),
    }
}

fn rec(trace: &Trace, base: &Rec, rules: &Rules) -> Rec {
    let o: Outcome = replay(trace, rules);
    let mut r = base.clone();
    r.holds = o.holds();
    r.floor = o.pass_floor;
    r.treasury = o.pass_treasury;
    r.operators = o.pass_operators;
    r.charter = o.pass_charter;
    r.finality = o.pass_finality;
    r.residency = o.pass_residency;
    r.payments = o.pass_payments;
    r.validators_min = o.validators_min;
    r.cover_mean = o.cover_ratio_mean;
    r.income_ratio_min = o.validator_income_ratio_min;
    r.operators_min = o.operators_min;
    r.utilisation = o.utilisation_mean;
    r.price_min = o.price_min;
    r.price_end = o.price_end;
    r.treasury_end_usd = o.treasury_value_end_usd;
    r.paid_usd = o.paid_usd;
    r.segment_usd = o.paid_by_segment.clone();
    r.segment_min_tick = o.segment_min_tick.clone();
    r.unmet_share = o.unmet_share;
    r.suspended_usd = o.suspended_usd;
    r.operator_margin_min = o
        .operator_margin_by_region
        .values()
        .copied()
        .fold(f64::INFINITY, f64::min);
    r.operator_earnings_usd = o.operator_earnings_usd;
    r.finality_lost_ticks = o.finality_lost_ticks;
    r.charter_violations = o.charter_violations;
    r.availability_over_fees = o.availability_over_fees;
    r.circulating_change_tnzo = o.circulating_change_tnzo;
    r.pool_end_tnzo = o.pool_end_tnzo;
    r
}

/// Replays every trace under `dirs` under every setting, on `threads`
/// threads. A trace that does not read (its sha256 differs, a row is
/// malformed) is reported through `bad` and skipped.
pub fn sweep(
    dirs: &[PathBuf],
    threads: usize,
    mut sink: impl FnMut(Rec),
    mut bad: impl FnMut(String),
) {
    let files = find(dirs);
    crate::chaos::run_parallel(
        &files,
        threads,
        |(m, t): &(PathBuf, PathBuf)| -> Result<Vec<Rec>, String> {
            let trace = Trace::read_lw(m, t)?;
            let p = &trace.manifest.parameters;
            let scenario = p
                .get("lw.scenario")
                .and_then(|s| s.get("name"))
                .and_then(|s| s.as_str())
                .unwrap_or("?")
                .to_string();
            let variant = p
                .get("lw.scenario")
                .and_then(|s| s.get("variant"))
                .and_then(|s| s.as_str())
                .unwrap_or("?")
                .to_string();
            let inside_band = p
                .get("lw.inside_band")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let placements: Vec<(&str, Option<Vec<String>>)> = if scenario == "partition" {
                vec![
                    ("market_regions", None),
                    (
                        "plus_one_region",
                        Some(
                            ["region-a", "region-b", "region-c", "region-v"]
                                .iter()
                                .map(|s| s.to_string())
                                .collect(),
                        ),
                    ),
                ]
            } else {
                vec![("market_regions", None)]
            };
            let mut out = Vec::new();
            for overlay in OVERLAYS {
                for share in SHARES {
                    for leg in LEGS {
                        for availability in AVAILABILITY {
                            for (depth, usd) in DEPTHS {
                                for (placement, vr) in &placements {
                                    for (mech_name, mech) in Mechanisms::sweep() {
                                        let mut rules = Rules {
                                            availability_tnzo_hour: availability,
                                            mechanisms: mech,
                                            market_share: share,
                                            pool_depth_usd: Some(usd),
                                            rails: Some(BTreeMap::from([
                                                ("USDA".to_string(), 0.6),
                                                ("USDB".to_string(), 0.4),
                                            ])),
                                            extra_shocks: overlay_shocks(overlay),
                                            validator_regions: vr.clone(),
                                            ..Rules::default()
                                        };
                                        rules.overrides.insert(
                                            tenzro_vm::native::economy::TREASURY_LEG_INFERENCE_PARAM.into(),
                                            leg,
                                        );
                                        let base = Rec {
                                            seed: trace.manifest.seed,
                                            scenario: scenario.clone(),
                                            variant: variant.clone(),
                                            inside_band,
                                            overlay: overlay.into(),
                                            share,
                                            leg_bps: leg,
                                            availability,
                                            depth: depth.into(),
                                            placement: placement.to_string(),
                                            mechanism: mech_name.into(),
                                            holds: false,
                                            floor: false,
                                            treasury: false,
                                            operators: false,
                                            charter: false,
                                            finality: false,
                                            residency: false,
                                            payments: false,
                                            validators_min: 0,
                                            cover_mean: 0.0,
                                            income_ratio_min: 0.0,
                                            operators_min: 0,
                                            utilisation: 0.0,
                                            price_min: 0.0,
                                            price_end: 0.0,
                                            treasury_end_usd: 0.0,
                                            paid_usd: 0.0,
                                            segment_usd: BTreeMap::new(),
                                            segment_min_tick: BTreeMap::new(),
                                            unmet_share: 0.0,
                                            suspended_usd: 0.0,
                                            operator_margin_min: 0.0,
                                            operator_earnings_usd: 0.0,
                                            finality_lost_ticks: 0,
                                            charter_violations: 0,
                                            availability_over_fees: 0.0,
                                            circulating_change_tnzo: 0.0,
                                            pool_end_tnzo: 0.0,
                                        };
                                        out.push(rec(&trace, &base, &rules));
                                    }
                                }
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
    let v: Vec<f64> = v.filter(|x| x.is_finite()).collect();
    if v.is_empty() {
        return "-".into();
    }
    let lo = v.iter().copied().fold(f64::INFINITY, f64::min);
    let hi = v.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let f = |x: f64| {
        if x.abs() >= 1e6 {
            format!("{x:.2e}")
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

/// The sweep as Markdown.
pub fn report(recs: &[Rec], bad: &[String], seeds: usize) -> String {
    use std::fmt::Write as _;
    let mut s = String::new();
    let _ = writeln!(
        s,
        "# Usage-driven stress cells on market-stress simulation traces\n"
    );
    let _ = writeln!(
        s,
        "Traces: lw.market-stress/1, {seeds} seed(s), every scenario variant; {} replays. Ranges are over seeds, treasury leg, availability setting, TNZO pool depth and validator placement, by the share of the market that pays through the network. No figure is a forecast or a price.\n",
        recs.len()
    );
    let _ = writeln!(
        s,
        "Simulation caveats: only provider exit and rebuild up to about 60% is backtested (the 2021 hashrate exit); elasticities, costs and energy exposure are assumptions; the order book is not backtested. Rows outside the validated band are reported separately below.\n"
    );
    if !bad.is_empty() {
        let _ = writeln!(s, "Traces refused ({}): {}\n", bad.len(), bad.join("; "));
    }
    let out_band: Vec<&Rec> = recs.iter().filter(|r| !r.inside_band).collect();
    let _ = writeln!(
        s,
        "Replays on traces outside the validated band: {} (kept out of every table below).\n",
        out_band.len()
    );
    let inb: Vec<&Rec> = recs.iter().filter(|r| r.inside_band).collect();

    // Mechanisms.
    s.push_str("## Mechanisms\n\nStrict gate: every replay of every cell holds every check with the mechanism on. No-regression: in every cell and setting where the mechanism-off replay holds, the mechanism-on replay holds too; rescued: settings that fail off and hold on.\n\n| mechanism | replays | holding | strict: cells all holding | no-regression | rescued | cells with a failing replay |\n|---|---|---|---|---|---|---|\n");
    let key = |r: &Rec| {
        format!(
            "{}|{}|{}|{}|{}|{}|{}|{}",
            r.seed,
            r.cell(),
            r.share,
            r.leg_bps,
            r.availability,
            r.depth,
            r.placement,
            r.inside_band
        )
    };
    let off: BTreeMap<String, bool> = inb
        .iter()
        .filter(|r| r.mechanism == "none")
        .map(|r| (key(r), r.holds))
        .collect();
    let cells: std::collections::BTreeSet<String> = inb.iter().map(|r| r.cell()).collect();
    for (m, _) in Mechanisms::sweep() {
        let rs: Vec<&&Rec> = inb.iter().filter(|r| r.mechanism == m).collect();
        let holding = rs.iter().filter(|r| r.holds).count();
        let mut all_ok = 0;
        let mut bad_cells = Vec::new();
        for c in &cells {
            let cr: Vec<&&&Rec> = rs.iter().filter(|r| &r.cell() == c).collect();
            if !cr.is_empty() && cr.iter().all(|r| r.holds) {
                all_ok += 1;
            } else {
                bad_cells.push(c.clone());
            }
        }
        let regress = rs
            .iter()
            .filter(|r| off.get(&key(r)).copied().unwrap_or(false) && !r.holds)
            .count();
        let rescued = rs
            .iter()
            .filter(|r| !off.get(&key(r)).copied().unwrap_or(true) && r.holds)
            .count();
        let _ = writeln!(
            s,
            "| {m} | {} | {holding} | {all_ok}/{} | {} | {rescued} | {} |",
            rs.len(),
            cells.len(),
            if regress == 0 {
                "yes".to_string()
            } else {
                format!("no ({regress} regressions)")
            },
            if bad_cells.len() > 5 {
                format!("{} cells", bad_cells.len())
            } else {
                bad_cells.join(", ")
            }
        );
    }

    // Cells by share, no mechanism.
    s.push_str("\n## Cells (no mechanism), by market share\n\n| cell | share | replays holding | floor | treasury | operators | charter | finality | residency | validators least | cover of 7 seats (mean) | income/cost least month | price least USD | price end USD | treasury end USD | operator margin least USD/unit | utilisation | unmet share | suspended USD |\n|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|\n");
    for c in &cells {
        for share in SHARES {
            let rs: Vec<&&Rec> = inb
                .iter()
                .filter(|r| &r.cell() == c && r.share == share && r.mechanism == "none")
                .collect();
            if rs.is_empty() {
                continue;
            }
            let n = rs.len();
            let cnt = |f: &dyn Fn(&Rec) -> bool| rs.iter().filter(|r| f(r)).count();
            let _ = writeln!(
                s,
                "| {c} | {share} | {}/{n} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
                cnt(&|r| r.holds),
                cnt(&|r| r.floor),
                cnt(&|r| r.treasury),
                cnt(&|r| r.operators),
                cnt(&|r| r.charter),
                cnt(&|r| r.finality),
                cnt(&|r| r.residency),
                range(rs.iter().map(|r| r.validators_min as f64)),
                range(rs.iter().map(|r| r.cover_mean)),
                range(rs.iter().map(|r| r.income_ratio_min)),
                range(rs.iter().map(|r| r.price_min)),
                range(rs.iter().map(|r| r.price_end)),
                range(rs.iter().map(|r| r.treasury_end_usd)),
                range(rs.iter().map(|r| r.operator_margin_min)),
                range(rs.iter().map(|r| r.utilisation)),
                range(rs.iter().map(|r| r.unmet_share)),
                range(rs.iter().map(|r| r.suspended_usd))
            );
        }
    }

    // What holds the floor: share x leg x availability, all cells.
    s.push_str("\n## Validator floor by share, treasury leg and availability (no mechanism, every cell)\n\n| share | leg bps | availability TNZO/h | replays | floor holds | cover of 7 seats (mean) | income/cost least |\n|---|---|---|---|---|---|---|\n");
    for share in SHARES {
        for leg in LEGS {
            for a in AVAILABILITY {
                let rs: Vec<&&Rec> = inb
                    .iter()
                    .filter(|r| {
                        r.share == share
                            && r.leg_bps == leg
                            && r.availability == a
                            && r.mechanism == "none"
                    })
                    .collect();
                if rs.is_empty() {
                    continue;
                }
                let _ = writeln!(
                    s,
                    "| {share} | {leg} | {a} | {} | {} | {} | {} |",
                    rs.len(),
                    rs.iter().filter(|r| r.floor).count(),
                    range(rs.iter().map(|r| r.cover_mean)),
                    range(rs.iter().map(|r| r.income_ratio_min))
                );
            }
        }
    }

    // Segments.
    s.push_str("\n## Paid usage by segment (no mechanism, share 1%): whole run USD / least day USD\n\n| cell |");
    for seg in SEGMENTS {
        let _ = write!(s, " {seg} |");
    }
    s.push_str("\n|---|---|---|---|---|\n");
    for c in &cells {
        let rs: Vec<&&Rec> = inb
            .iter()
            .filter(|r| &r.cell() == c && r.share == 0.01 && r.mechanism == "none")
            .collect();
        if rs.is_empty() {
            continue;
        }
        let _ = write!(s, "| {c} |");
        for seg in SEGMENTS {
            let _ = write!(
                s,
                " {} / {} |",
                range(
                    rs.iter()
                        .map(|r| r.segment_usd.get(seg).copied().unwrap_or(0.0))
                ),
                range(
                    rs.iter()
                        .map(|r| r.segment_min_tick.get(seg).copied().unwrap_or(0.0) * r.share)
                )
            );
        }
        s.push('\n');
    }

    // Charter and supply.
    s.push_str("\n## Charter and supply (every replay)\n\n");
    let viol = recs
        .iter()
        .filter(|r| r.mechanism != "leverage" && !r.charter)
        .count();
    let lev = recs
        .iter()
        .filter(|r| r.mechanism == "leverage" && !r.charter)
        .count();
    let _ = writeln!(
        s,
        "Replays with a payout not tied to paid, verified work: {viol} (leverage switched on is counted as a violation by rule: {lev} replays).\n"
    );
    let _ = writeln!(
        s,
        "Circulating supply change over the run (pool releases less burns), TNZO: {}; rewards pool left at the end, TNZO: {}; verified-availability paid over stable fees kept: {}.\n",
        range(
            inb.iter()
                .filter(|r| r.mechanism == "none")
                .map(|r| r.circulating_change_tnzo)
        ),
        range(
            inb.iter()
                .filter(|r| r.mechanism == "none")
                .map(|r| r.pool_end_tnzo)
        ),
        range(
            inb.iter()
                .filter(|r| r.mechanism == "none" && r.availability > 0.0)
                .map(|r| r.availability_over_fees)
        )
    );

    if !out_band.is_empty() {
        s.push_str("## Outside the validated band (not validated by the simulation)\n\n| cell | replays | holding |\n|---|---|---|\n");
        let ob: std::collections::BTreeSet<String> = out_band.iter().map(|r| r.cell()).collect();
        for c in ob {
            let rs: Vec<&&Rec> = out_band
                .iter()
                .filter(|r| r.cell() == c && r.mechanism == "none")
                .collect();
            let _ = writeln!(
                s,
                "| {c} | {} | {} |",
                rs.len(),
                rs.iter().filter(|r| r.holds).count()
            );
        }
    }
    s
}

/// Seed directories under `root` (every directory holding an index.json),
/// or `root` itself.
pub fn seed_dirs(root: &Path) -> Vec<PathBuf> {
    if root.join("index.json").exists() {
        return vec![root.to_path_buf()];
    }
    let mut v: Vec<PathBuf> = std::fs::read_dir(root)
        .map(|rd| {
            rd.filter_map(|e| e.ok().map(|e| e.path()))
                .filter(|p| p.join("index.json").exists())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}
