//! Runs the network simulator.
//!
//! ```text
//! tenzro-sim run    --profile <name> [--seed N] [--days D] [--validators N] [--out DIR]
//! tenzro-sim gate   [--seeds K] [--base-seed N] [--out DIR]      every gate profile, K seeds each
//! tenzro-sim ladder [--counts 4,21,50,100,200] [--seed N] [--budget-s S] [--out DIR]
//! tenzro-sim explore [--budget-s S] [--base-seed N] [--profile swarm] [--out DIR]
//!                                                  seed after seed until the budget is spent
//! tenzro-sim verify-cost                                        one signature verification, microseconds
//! ```
//!
//! Profiles: see `SimConfig::profile`. Each run writes `<out>/<profile>-<seed>.json`
//! and keeps `<out>/STATUS` current; every violation prints with its seed and
//! the command that replays it. Exit status 1 when any run broke an
//! invariant.

use std::path::{Path, PathBuf};

use tenzro_sim::{Report, SimConfig};

#[derive(Clone)]
struct Args {
    cmd: String,
    profile: String,
    seed: Option<u64>,
    seeds: u64,
    base_seed: u64,
    days: Option<f64>,
    validators: Option<u32>,
    counts: Vec<u32>,
    out: PathBuf,
    verify_us: Option<u64>,
    budget_s: u64,
    /// Whether `--budget-s` was given: the ladder runs every rung unless it was.
    budget_given: bool,
    trace: Option<PathBuf>,
    users: Option<u32>,
}

fn parse() -> Args {
    let mut a = std::env::args().skip(1);
    let mut args = Args {
        cmd: a.next().unwrap_or_else(|| "help".into()),
        profile: "ci".into(),
        seed: None,
        seeds: 1,
        base_seed: 1,
        days: None,
        validators: None,
        counts: SimConfig::LADDER.to_vec(),
        out: PathBuf::from("sim-out"),
        verify_us: None,
        budget_s: 3_600,
        budget_given: false,
        trace: None,
        users: None,
    };
    while let Some(k) = a.next() {
        let v = a.next().unwrap_or_default();
        match k.as_str() {
            "--profile" => args.profile = v,
            "--seed" => args.seed = v.parse().ok(),
            "--seeds" => args.seeds = v.parse().unwrap_or(1),
            "--base-seed" => args.base_seed = v.parse().unwrap_or(1),
            "--days" => args.days = v.parse().ok(),
            "--validators" => args.validators = v.parse().ok(),
            "--counts" => args.counts = v.split(',').filter_map(|s| s.parse().ok()).collect(),
            "--out" => args.out = PathBuf::from(v),
            "--verify-us" => args.verify_us = v.parse().ok(),
            "--budget-s" => {
                args.budget_s = v.parse().unwrap_or(3_600);
                args.budget_given = true;
            }
            "--trace" => args.trace = Some(PathBuf::from(v)),
            "--users" => args.users = v.parse().ok(),
            other => {
                eprintln!("unknown option {other}");
                std::process::exit(2);
            }
        }
    }
    args
}

fn write(path: &Path, body: &str) {
    if let Some(d) = path.parent() {
        let _ = std::fs::create_dir_all(d);
    }
    let tmp = path.with_extension("tmp");
    if std::fs::write(&tmp, body).is_ok() {
        let _ = std::fs::rename(&tmp, path);
    }
}

fn status(out: &Path, what: &str, r: &Report) {
    write(
        &out.join("STATUS"),
        &format!(
            "{what}\nprofile={} seed={} sim_s={} calendar_days={:.1} epochs={} height={} violations={} wall_s={:.0}\n",
            r.profile,
            r.seed,
            r.sim_ms / 1_000,
            r.calendar_days,
            r.epochs,
            r.height,
            r.violations.len(),
            r.wall_s
        ),
    );
}

fn run_one(mut cfg: SimConfig, a: &Args) -> Report {
    if let Some(d) = a.days {
        cfg.calendar_days = d;
    }
    if let Some(n) = a.validators {
        cfg.validators = n;
    }
    if let Some(v) = a.verify_us {
        cfg.verify_us = v;
    }
    if let Some(u) = a.users {
        cfg.workload.users = u;
    }
    let mut drivers: Vec<Box<dyn tenzro_sim::world::ClientDriver>> = Vec::new();
    let mut trace_stats = None;
    if let Some(path) = &a.trace {
        let file = std::fs::File::open(path).unwrap_or_else(|e| {
            eprintln!("--trace {}: {e}", path.display());
            std::process::exit(2)
        });
        let events =
            tenzro_sim::trace::read_trace(std::io::BufReader::new(file)).unwrap_or_else(|e| {
                eprintln!("--trace {}: {e}", path.display());
                std::process::exit(2)
            });
        eprintln!("trace {}: {} payments", path.display(), events.len());
        let (driver, stats) = tenzro_sim::trace::TraceDriver::new(events, cfg.workload.users);
        drivers.push(Box::new(driver));
        trace_stats = Some(stats);
    }
    let out = a.out.clone();
    eprintln!(
        "run profile={} seed={} validators={} calendar_days={} block_time_s={}",
        cfg.profile,
        cfg.seed,
        cfg.validators,
        cfg.calendar_days,
        cfg.duration_ms() / 1_000
    );
    let r = tenzro_sim::run_with_drivers(cfg, drivers, |r| {
        status(&out, "RUNNING", r);
        eprintln!(
            "  sim_s={} calendar_days={:.1} epochs={} height={} violations={} wall_s={:.0}",
            r.sim_ms / 1_000,
            r.calendar_days,
            r.epochs,
            r.height,
            r.violations.len(),
            r.wall_s
        );
    });
    if let Some(stats) = &trace_stats {
        println!("{}", stats.line());
    }
    let json = r.to_json();
    write(
        &a.out.join(format!("{}-{}.json", r.profile, r.seed)),
        &serde_json::to_string_pretty(&json).expect("json"),
    );
    for l in r.failure_lines() {
        println!("{l}");
    }
    println!(
        "{} profile={} seed={} epochs={} height={} calendar_days={:.1} tps={:.1} max_commit_gap_ms={} max_finality_gap_ms={} violations={} wall_s={:.0}",
        if r.passed { "PASS" } else { "FAIL" },
        r.profile,
        r.seed,
        r.epochs,
        r.height,
        r.calendar_days,
        r.tps,
        r.max_commit_gap_ms,
        r.max_finality_gap_ms,
        r.violations.len(),
        r.wall_s
    );
    r
}

fn seed_or_random(s: Option<u64>) -> u64 {
    s.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1)
    })
}

fn main() {
    let a = parse();
    let ok = match a.cmd.as_str() {
        "run" => {
            let seed = seed_or_random(a.seed);
            let Some(cfg) = SimConfig::profile(&a.profile, seed) else {
                eprintln!("unknown profile {}", a.profile);
                std::process::exit(2);
            };
            let r = run_one(cfg, &a);
            status(&a.out, if r.passed { "PASS" } else { "FAIL" }, &r);
            r.passed
        }
        "gate" => {
            let mut all = true;
            let mut lines = Vec::new();
            for p in SimConfig::GATE {
                for k in 0..a.seeds {
                    let seed = a.base_seed + k;
                    let cfg = SimConfig::profile(p, seed).expect("gate profile");
                    let r = run_one(cfg, &a);
                    all &= r.passed;
                    lines.push(format!(
                        "{} {} seed={} violations={} first={}",
                        if r.passed { "PASS" } else { "FAIL" },
                        p,
                        seed,
                        r.violations.len(),
                        r.violations
                            .first()
                            .map(|v| format!("{}: {}", v.kind, v.detail))
                            .unwrap_or_default()
                    ));
                    status(&a.out, "RUNNING", &r);
                }
            }
            write(&a.out.join("gate-summary.txt"), &(lines.join("\n") + "\n"));
            all
        }
        "ladder" => {
            let verify = a
                .verify_us
                .unwrap_or_else(|| tenzro_sim::measure_verify_us(200));
            eprintln!("composite signature verification: {verify} us");
            let seed = seed_or_random(a.seed);
            let mut rows = Vec::new();
            let mut best = None;
            let started = std::time::Instant::now();
            let mut last: Option<(u32, f64)> = None;
            let mut stopped = None;
            for n in &a.counts {
                // A rung's wall time grows about with the cube of the validator
                // count; one that would end past the budget is not started, so
                // the ladder ends with what held rather than being cut off.
                if let (true, Some((last_n, last_wall))) = (a.budget_given, last) {
                    let projected = last_wall * (f64::from(*n) / f64::from(last_n)).powi(3);
                    let elapsed = started.elapsed().as_secs_f64();
                    if elapsed + projected > a.budget_s as f64 {
                        stopped = Some(format!(
                            "{n} validators would need about {projected:.0} s more, past the {} s budget",
                            a.budget_s
                        ));
                        eprintln!("ladder stopped: {}", stopped.as_deref().unwrap_or_default());
                        break;
                    }
                }
                let mut cfg =
                    SimConfig::profile(&format!("scale-{n}"), seed).expect("scale profile");
                cfg.verify_us = verify;
                let a2 = Args {
                    verify_us: Some(verify),
                    ..a.clone()
                };
                let r = run_one(cfg.clone(), &a2);
                last = Some((*n, r.wall_s as f64));
                let p99 = r
                    .to_json()
                    .get("latency")
                    .and_then(|l| l.get(1))
                    .and_then(|c| c.get(3))
                    .and_then(|v| v.as_f64())
                    .unwrap_or(f64::INFINITY);
                let holds = r.passed && r.max_commit_gap_ms <= 30_000 && p99 <= 10_000.0;
                let limit = if r.cpu_busy_pct > 70.0 {
                    "verification CPU"
                } else if r.bandwidth_out_mbps * 1e6 > 0.7 * cfg.uplink_bps as f64 {
                    "uplink bandwidth"
                } else if !r.passed {
                    "invariant violations"
                } else if p99 > 10_000.0 {
                    "finality latency"
                } else {
                    "none reached"
                };
                if holds {
                    best = Some(*n);
                }
                rows.push(serde_json::json!({
                    "validators": n,
                    "holds_targets": holds,
                    "tps": r.tps,
                    "finality_p99_ms": p99,
                    "max_commit_gap_ms": r.max_commit_gap_ms,
                    "bandwidth_out_mbps_per_node": r.bandwidth_out_mbps,
                    "cpu_busy_pct_per_node": r.cpu_busy_pct,
                    "max_core_bytes": r.max_core_bytes,
                    "violations": r.violations.len(),
                    "limit": limit,
                    "wall_s": r.wall_s,
                }));
                // Written after every rung, so a stage timeout keeps what ran.
                let partial = serde_json::json!({
                    "verify_us": verify,
                    "targets": {"max_commit_gap_ms": 30000, "finality_p99_ms": 10000},
                    "largest_holding": best,
                    "rows": rows,
                    "complete": false,
                });
                write(
                    &a.out.join("ladder.json"),
                    &serde_json::to_string_pretty(&partial).expect("json"),
                );
            }
            let doc = serde_json::json!({
                "verify_us": verify,
                "targets": {"max_commit_gap_ms": 30000, "finality_p99_ms": 10000},
                "largest_holding": best,
                "rows": rows,
                "complete": stopped.is_none(),
                "stopped": stopped,
            });
            write(
                &a.out.join("ladder.json"),
                &serde_json::to_string_pretty(&doc).expect("json"),
            );
            println!("{}", serde_json::to_string_pretty(&doc).expect("json"));
            best.is_some()
        }
        "explore" => {
            // One seed after another of a seed-drawn profile, until the
            // budget is spent; a run is started only while budget remains.
            let profile = if a.profile == "ci" {
                "swarm".to_string()
            } else {
                a.profile.clone()
            };
            let started = std::time::Instant::now();
            let mut all = true;
            let mut lines = Vec::new();
            let (mut runs, mut failed) = (0u64, 0u64);
            let mut seed = a.base_seed;
            while started.elapsed().as_secs() < a.budget_s {
                let Some(cfg) = SimConfig::profile(&profile, seed) else {
                    eprintln!("unknown profile {profile}");
                    std::process::exit(2);
                };
                let r = run_one(cfg, &a);
                runs += 1;
                if !r.passed {
                    failed += 1;
                    all = false;
                    lines.push(format!(
                        "FAIL {profile} seed={seed} violations={} first={} | replay: {}",
                        r.violations.len(),
                        r.violations
                            .first()
                            .map(|v| format!("{}: {}", v.kind, v.detail))
                            .unwrap_or_default(),
                        r.replay
                    ));
                }
                write(
                    &a.out.join("explore-summary.txt"),
                    &format!(
                        "{runs} runs, {failed} failed, seeds {}..={seed}, {} s\n{}\n",
                        a.base_seed,
                        started.elapsed().as_secs(),
                        lines.join("\n")
                    ),
                );
                seed += 1;
            }
            println!(
                "EXPLORE profile={profile} runs={runs} failed={failed} seeds={}..{seed}",
                a.base_seed
            );
            all
        }
        "verify-cost" => {
            println!("{}", tenzro_sim::measure_verify_us(500));
            true
        }
        _ => {
            eprintln!(
                "usage: tenzro-sim run|gate|ladder|explore|verify-cost [options]; see the source header"
            );
            std::process::exit(2);
        }
    };
    std::process::exit(if ok { 0 } else { 1 });
}
