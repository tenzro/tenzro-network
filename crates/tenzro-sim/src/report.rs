//! What a run measured, its violations and its verdict.

use serde::Serialize;

use crate::config::SimConfig;
use crate::ledger::LedgerStats;

/// One broken invariant.
#[derive(Debug, Clone, Serialize)]
pub struct Violation {
    /// `safety`, `liveness`, `memory`, `storage`, `value` or `rejoin`.
    pub kind: &'static str,
    /// Simulated time, milliseconds.
    pub at_ms: u64,
    /// Latest epoch the network had entered.
    pub epoch: u64,
    /// The validator concerned, if one.
    pub node: Option<u32>,
    /// What happened.
    pub detail: String,
}

/// Faults the run injected.
#[derive(Debug, Clone, Default, Serialize)]
pub struct FaultCounts {
    /// Crashes.
    pub crashes: u64,
    /// Crashes that stayed down for whole epochs.
    pub long_downtimes: u64,
    /// Restarts too far behind for kept certificates, which synced instead.
    pub synced_restarts: u64,
    /// Validators that fell further behind than peers keep the DAG and
    /// took a certified checkpoint's ordering state to order on in the same
    /// epoch.
    pub fast_forwards: u64,
    /// Validators that took an epoch's handover from a certificate without
    /// having ordered the epoch's last blocks, and entered the next epoch
    /// from the blocks they imported.
    pub late_handovers: u64,
    /// Partitions.
    pub partitions: u64,
    /// Partitions that left no side a quorum.
    pub quorum_losses: u64,
    /// Partitions healed.
    pub partitions_healed: u64,
    /// Delay spikes.
    pub delay_spikes: u64,
    /// Disk stalls.
    pub disk_stalls: u64,
}

/// Governance the clients ran.
#[derive(Debug, Clone, Default, Serialize)]
pub struct GovernanceCounts {
    /// Proposals accepted.
    pub proposed: u64,
    /// Ballots applied.
    pub votes: u64,
    /// Proposals enacted.
    pub enacted: u64,
    /// Enacted, by kind.
    pub by_kind: Vec<(String, u64)>,
    /// Latest refusals.
    pub failures: Vec<String>,
}

/// The run's report.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    /// Profile.
    pub profile: String,
    /// Seed.
    pub seed: u64,
    /// Validators at genesis.
    pub validators: u32,
    /// Command that replays the run.
    pub replay: String,
    /// The settings the run drew, for reading a seed-drawn run.
    pub config: serde_json::Value,
    /// Largest block store any validator's node layer held, bytes.
    pub node_store_peak_bytes: u64,
    /// Transactions that ran ahead of their nonce with their predecessor in
    /// flight, and went back to the mempool.
    pub ahead_of_nonce: u64,
    /// Passed: no violation.
    pub passed: bool,
    /// Why the run ended before its length, if it did.
    pub ended_early: Option<String>,
    /// Simulated block time, milliseconds.
    pub sim_ms: u64,
    /// Calendar days the chain reached.
    pub calendar_days: f64,
    /// Wall-clock seconds the run took.
    pub wall_s: f64,
    /// Latest epoch entered.
    pub epochs: u64,
    /// Highest committed height.
    pub height: u64,
    /// Checkpoints certified.
    pub checkpoints_certified: u64,
    /// Transactions clients submitted.
    pub txs_submitted: u64,
    /// Transactions applied after warm-up.
    pub txs_in_window: u64,
    /// Applied transactions per second after warm-up.
    pub tps: f64,
    /// Submit-to-ordered latency samples, milliseconds (summarised on
    /// output).
    #[serde(skip)]
    pub ordered_ms: Vec<f64>,
    /// Submit-to-certified latency samples, milliseconds.
    #[serde(skip)]
    pub finality_ms: Vec<f64>,
    /// Restart-to-caught-up samples, milliseconds.
    #[serde(skip)]
    pub rejoin_ms: Vec<f64>,
    /// Latency summaries: (name, count, p50, p99, max).
    pub latency: Vec<(String, usize, f64, f64, f64)>,
    /// Longest commit gap with a quorum up, milliseconds.
    pub max_commit_gap_ms: u64,
    /// Longest certification gap with a quorum up, milliseconds.
    pub max_finality_gap_ms: u64,
    /// Mean consensus traffic sent per seated validator, megabits per second.
    pub bandwidth_out_mbps: f64,
    /// Mean message-processing busy share per seated validator, percent.
    pub cpu_busy_pct: f64,
    /// Largest consensus state any validator held: entries.
    pub max_core_entries: u64,
    /// Largest consensus buffer any validator held: bytes.
    pub max_core_bytes: u64,
    /// Per epoch: (epoch, max entries, max bytes) across validators.
    pub mem_by_epoch: Vec<(u64, u64, u64)>,
    /// Per epoch: (epoch, max journal bytes).
    pub journal_by_epoch: Vec<(u64, u64)>,
    /// Bytes of the chain's executed-height index.
    pub ledger_index_bytes: u64,
    /// Ledger totals.
    pub ledger: LedgerStats,
    /// Recorded total supply.
    pub total_supply: String,
    /// Total supply genesis allocated; `total_supply` never exceeds it.
    pub genesis_supply: String,
    /// Governance.
    pub governance: GovernanceCounts,
    /// Validators that bonded and joined.
    pub stake_joins: u64,
    /// Validators that started unbonding.
    pub stake_exits: u64,
    /// Unbonded stake withdrawn.
    pub stake_withdrawals: u64,
    /// Bond top-ups.
    pub stake_top_ups: u64,
    /// Validators seated after genesis or a long absence.
    pub joins: u64,
    /// Equivocations detected.
    pub equivocations_detected: u64,
    /// Validators halted because their two ML-DSA-65 implementations
    /// disagreed on a consensus signature.
    pub verifier_disagreements: u64,
    /// Slashes applied.
    pub slashes: u64,
    /// Faults injected.
    pub faults: FaultCounts,
    /// Client operations the chain refused (not invariant breaches).
    pub workload_errors: Vec<String>,
    /// Broken invariants.
    pub violations: Vec<Violation>,
    /// What epoch observers added.
    pub extra: serde_json::Map<String, serde_json::Value>,
}

fn summary(name: &str, v: &[f64]) -> (String, usize, f64, f64, f64) {
    if v.is_empty() {
        return (name.into(), 0, 0.0, 0.0, 0.0);
    }
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.total_cmp(b));
    let at = |q: f64| s[((s.len() - 1) as f64 * q) as usize];
    (
        name.into(),
        s.len(),
        at(0.5),
        at(0.99),
        *s.last().expect("non-empty"),
    )
}

impl Report {
    /// An empty report for `cfg`.
    pub fn new(cfg: &SimConfig) -> Self {
        Self {
            profile: cfg.profile.clone(),
            seed: cfg.seed,
            validators: cfg.validators,
            replay: format!(
                "tenzro-sim run --profile {} --seed {}",
                cfg.profile, cfg.seed
            ),
            config: serde_json::to_value(cfg).unwrap_or_default(),
            node_store_peak_bytes: 0,
            ahead_of_nonce: 0,
            passed: false,
            ended_early: None,
            sim_ms: 0,
            calendar_days: 0.0,
            wall_s: 0.0,
            epochs: 0,
            height: 0,
            checkpoints_certified: 0,
            txs_submitted: 0,
            txs_in_window: 0,
            tps: 0.0,
            ordered_ms: Vec::new(),
            finality_ms: Vec::new(),
            rejoin_ms: Vec::new(),
            latency: Vec::new(),
            max_commit_gap_ms: 0,
            max_finality_gap_ms: 0,
            bandwidth_out_mbps: 0.0,
            cpu_busy_pct: 0.0,
            max_core_entries: 0,
            max_core_bytes: 0,
            mem_by_epoch: Vec::new(),
            journal_by_epoch: Vec::new(),
            ledger_index_bytes: 0,
            ledger: LedgerStats::default(),
            total_supply: String::new(),
            genesis_supply: String::new(),
            governance: GovernanceCounts::default(),
            stake_joins: 0,
            stake_exits: 0,
            stake_withdrawals: 0,
            stake_top_ups: 0,
            joins: 0,
            equivocations_detected: 0,
            verifier_disagreements: 0,
            slashes: 0,
            faults: FaultCounts::default(),
            workload_errors: Vec::new(),
            violations: Vec::new(),
            extra: serde_json::Map::new(),
        }
    }

    /// JSON of the report, latency summarised and long series thinned.
    pub fn to_json(&self) -> serde_json::Value {
        let mut r = self.clone();
        r.latency = vec![
            summary("ordered", &self.ordered_ms),
            summary("certified", &self.finality_ms),
            summary("rejoin", &self.rejoin_ms),
        ];
        let thin = |n: usize| (n / 400).max(1);
        let k = thin(r.mem_by_epoch.len());
        r.mem_by_epoch = r.mem_by_epoch.into_iter().step_by(k).collect();
        let k = thin(r.journal_by_epoch.len());
        r.journal_by_epoch = r.journal_by_epoch.into_iter().step_by(k).collect();
        serde_json::to_value(&r).expect("report encodes")
    }

    /// One line per violation, each with the replay command.
    pub fn failure_lines(&self) -> Vec<String> {
        self.violations
            .iter()
            .map(|v| {
                format!(
                    "FAIL {} at {} ms (epoch {}{}): {} | seed {} | replay: {}",
                    v.kind,
                    v.at_ms,
                    v.epoch,
                    v.node
                        .map(|n| format!(", validator {n}"))
                        .unwrap_or_default(),
                    v.detail,
                    self.seed,
                    self.replay
                )
            })
            .collect()
    }
}
