//! Long emulated runs, one per measured criterion. Ignored by default; run
//! with `cargo test --release -p tenzro-consensus gate_ -- --ignored
//! --nocapture --test-threads 1`. Each prints one `GATE {json}` line.
//!
//! Environment:
//! - `TDC_N` committee size (default 100)
//! - `TDC_SECONDS` run length (default 60)
//! - `TDC_TPS` offered load (default 50000)
//! - `TDC_SIGN_MS` modeled hardware checkpoint-signing latency (default 50)
//! - `TDC_LEADER_TIMEOUT_MS` leader timeout (default 600)
//! - `TDC_EGRESS_GBPS` per-node uplink, Gbit/s (default 1)
//! - `TDC_CHECKPOINT_MS` checkpoint interval (default: the node default)
//! - `TDC_GC_DEPTH` DAG rounds kept below the last commit (default: the node
//!   default). The emulator hosts every node in one process, so at n = 100
//!   a shallower depth keeps it inside a test's memory cap; a node process
//!   holds one node's state.
//! - `TDC_MYSTICETI_WAIT_MS`, `TDC_MYSTICETI_LEADERS` the uncertified
//!   baseline's leader wait (default 100) and leader slots per round
//!   (default 1)
//! - `TDC_MEM_TRACE` if set, one `MEM` line per simulated second: process
//!   RSS, simulator queues and node 0's state sizes

use super::baselines::{mysticeti_nodes, sailfish_nodes};
use super::driver::{Partition, Report, Scenario, run};
use super::tdc::{Behaviour, TdcParams, nodes};

fn env(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn scenario() -> Scenario {
    let n = env("TDC_N", 100.0) as usize;
    let secs = env("TDC_SECONDS", 60.0) as u64;
    let mut sc = Scenario::wan(n, env("TDC_TPS", 50_000.0), secs * 1_000);
    sc.wan.egress_bps = env("TDC_EGRESS_GBPS", 1.0) * 1e9;
    sc
}

fn params() -> TdcParams {
    let mut p = TdcParams::honest();
    p.sign_latency_ms = env("TDC_SIGN_MS", 50.0) as u64;
    p.config.leader_timeout_ms = env("TDC_LEADER_TIMEOUT_MS", 600.0) as u64;
    p.time.checkpoint_interval_ms =
        env("TDC_CHECKPOINT_MS", p.time.checkpoint_interval_ms as f64) as u64;
    p.config.gc_depth = env("TDC_GC_DEPTH", p.config.gc_depth as f64) as u64;
    p
}

fn emit(name: &str, sc: &Scenario, r: &Report, extra: &str) {
    println!(
        "GATE {{\"gate\":\"{name}\",\"n\":{},\"seconds\":{},\"offered_tps\":{},\"ordered_mean_ms\":{:.1},\"ordered_p50_ms\":{:.1},\"ordered_p99_ms\":{:.1},\
         \"certified_p50_ms\":{:.1},\"certified_p99_ms\":{:.1},\"ordered_tps\":{:.0},\"max_stall_ms\":{:.0},\
         \"safety_violations\":{},\"certificate_conflicts\":{},\"common_height\":{},\"metadata_mbps\":{:.1},\
         \"payload_mbps\":{:.1},\"journal_mb_per_s\":{:.2},\"events\":{}{extra}}}",
        sc.n,
        sc.duration_ms / 1_000,
        sc.offered_tps,
        r.ordered.mean,
        r.ordered.p50,
        r.ordered.p99,
        r.certified.p50,
        r.certified.p99,
        r.ordered_tps,
        r.max_stall_ms,
        r.safety_violations,
        r.certificate_conflicts,
        r.common_height,
        r.metadata_mbps,
        r.payload_mbps,
        r.journal_mb_per_s,
        r.events,
    );
}

fn byzantine(n: usize, behaviour: Behaviour) -> Vec<Behaviour> {
    let f = (n - 1) / 3;
    (0..n)
        .map(|i| {
            if i % 3 == 0 && i / 3 < f {
                behaviour
            } else {
                Behaviour::Honest
            }
        })
        .collect()
}

#[test]
#[ignore]
fn gate_tdc_fault_free() {
    let sc = scenario();
    let r = run(&sc, nodes(sc.n, &params()));
    emit("tdc_fault_free", &sc, &r, "");
}

#[test]
#[ignore]
fn gate_sailfish_baseline() {
    let sc = scenario();
    let r = run(
        &sc,
        sailfish_nodes(sc.n, env("TDC_LEADER_TIMEOUT_MS", 600.0) as u64),
    );
    emit("sailfish_baseline", &sc, &r, "");
}

#[test]
#[ignore]
fn gate_mysticeti_baseline() {
    let sc = scenario();
    let r = run(
        &sc,
        mysticeti_nodes(
            sc.n,
            env("TDC_MYSTICETI_WAIT_MS", 100.0) as u64,
            env("TDC_MYSTICETI_LEADERS", 1.0) as usize,
        ),
    );
    emit("mysticeti_baseline", &sc, &r, "");
}

#[test]
#[ignore]
fn gate_tdc_crashed_third() {
    let mut sc = scenario();
    let f = (sc.n - 1) / 3;
    sc.crashed = (0..f as u16).map(|i| i * 3).collect();
    let r = run(&sc, nodes(sc.n, &params()));
    emit("tdc_crashed_third", &sc, &r, &format!(",\"crashed\":{f}"));
}

#[test]
#[ignore]
fn gate_tdc_partition() {
    let mut sc = scenario();
    let secs = sc.duration_ms / 1_000;
    let part = env("TDC_PARTITION_S", 20.0) as u64;
    let start = (secs.saturating_sub(part)) / 2;
    sc.partition = Some(Partition {
        from_ms: start * 1_000,
        until_ms: (start + part) * 1_000,
        side_a: (0..sc.n as u16 / 2).collect(),
    });
    let r = run(&sc, nodes(sc.n, &params()));
    let series: Vec<String> = r
        .ordered_p50_by_second
        .iter()
        .map(|(s, p)| format!("[{s},{p:.0}]"))
        .collect();
    emit(
        "tdc_partition",
        &sc,
        &r,
        &format!(
            ",\"partition_from_s\":{start},\"partition_s\":{part},\"p50_by_second\":[{}]",
            series.join(",")
        ),
    );
}

#[test]
#[ignore]
fn gate_tdc_equivocation() {
    let sc = scenario();
    let mut p = params();
    p.behaviour = byzantine(sc.n, Behaviour::Equivocate);
    let r = run(&sc, nodes(sc.n, &p));
    emit("tdc_equivocation", &sc, &r, "");
}

#[test]
#[ignore]
fn gate_tdc_withholding() {
    let sc = scenario();
    let mut p = params();
    p.behaviour = byzantine(sc.n, Behaviour::Withhold);
    let r = run(&sc, nodes(sc.n, &p));
    emit("tdc_withholding", &sc, &r, "");
}

#[test]
#[ignore]
fn gate_tdc_byzantine_leaders() {
    let sc = scenario();
    let mut p = params();
    p.behaviour = byzantine(sc.n, Behaviour::WithholdLeaderVertex);
    let r = run(&sc, nodes(sc.n, &p));
    emit("tdc_byzantine_leaders", &sc, &r, "");
}

#[test]
#[ignore]
fn gate_tdc_whole_committee_restart() {
    let sc = scenario();
    let at_s = sc.duration_ms / 2_000;
    let mut p = params();
    p.restart = Some((at_s * 1_000, (0..sc.n as u16).collect()));
    let r = run(&sc, nodes(sc.n, &p));
    let series: Vec<String> = r
        .ordered_p50_by_second
        .iter()
        .map(|(s, p)| format!("[{s},{p:.0}]"))
        .collect();
    emit(
        "tdc_whole_committee_restart",
        &sc,
        &r,
        &format!(
            ",\"restart_at_s\":{at_s},\"p50_by_second\":[{}]",
            series.join(",")
        ),
    );
}

#[test]
#[ignore]
fn gate_tdc_double_signers() {
    let sc = scenario();
    let mut p = params();
    p.behaviour = byzantine(sc.n, Behaviour::DoubleSign);
    let expected: Vec<u16> = p
        .behaviour
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == Behaviour::DoubleSign)
        .map(|(i, _)| i as u16)
        .collect();
    let r = run(&sc, nodes(sc.n, &p));
    let mut got = r.convicted.clone();
    got.sort_unstable();
    emit(
        "tdc_double_signers",
        &sc,
        &r,
        &format!(
            ",\"double_signers\":{},\"convicted\":{},\"convicted_exactly\":{}",
            expected.len(),
            got.len(),
            got == expected
        ),
    );
}
