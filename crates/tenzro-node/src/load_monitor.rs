//! The node's load monitor and the order work is shed in.
//!
//! One [`LoadSample`] is a set of measurements of the host and of this
//! process: CPU load per core, Linux pressure stall information (PSI) for
//! CPU, memory and I/O, memory and swap, the run queue, threads, the lag of
//! the async event loop, and the latency of the TPM and of the disk.
//! [`LoadLadder`] turns samples into a [`LoadLevel`] with hysteresis: a level
//! is entered after [`ENTER_SAMPLES`] consecutive samples at or above its
//! enter threshold and left, one level at a time, after [`LEAVE_SAMPLES`]
//! consecutive samples below its leave threshold. Nothing here reads a clock
//! to decide a level, and a change is logged when it happens and not on a
//! timer.
//!
//! [`WorkClass`] is the priority order of the node's work, highest first.
//! [`capacity_percent`] says how much of its normal capacity a class keeps at
//! each level; consensus and key custody always keep all of it, and
//! shedding goes from the lowest class up. [`LoadMonitor`] runs the sampler,
//! publishes the level through [`current_level`], and calls the registered
//! [`Reclaimer`]s when memory runs short.
//!
//! The disk side of resource protection (free bytes, runway) lives in the
//! shared `tenzro_storage::resources` module; its level reaches this ladder
//! through [`LoadSample::disk_level`].

use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Consecutive samples at or above a level's enter threshold before the node
/// enters it. A single spike does not change the level.
pub const ENTER_SAMPLES: u32 = 2;
/// Consecutive samples below a level's leave threshold before the node leaves
/// it, one level at a time.
pub const LEAVE_SAMPLES: u32 = 3;
/// A leave threshold is this share of its enter threshold, so a reading that
/// hovers at the edge does not flap.
pub const LEAVE_RATIO: f64 = 0.8;

/// How loaded the node is.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum LoadLevel {
    /// Normal operation: nothing is shed.
    #[default]
    Green,
    /// Busy: background work is throttled and public limits tighten.
    Elevated,
    /// Overloaded: model serving and relay forwarding pause, caches drop.
    High,
    /// At the edge: only consensus, key custody, block import and a trickle
    /// of transactions and reads are served.
    Critical,
}

impl LoadLevel {
    /// Uppercase name for logs and status output.
    pub fn name(self) -> &'static str {
        match self {
            LoadLevel::Green => "GREEN",
            LoadLevel::Elevated => "ELEVATED",
            LoadLevel::High => "HIGH",
            LoadLevel::Critical => "CRITICAL",
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            0 => LoadLevel::Green,
            1 => LoadLevel::Elevated,
            2 => LoadLevel::High,
            _ => LoadLevel::Critical,
        }
    }

    fn index(self) -> usize {
        self as usize
    }

    /// Seconds a shed client is told to wait before it retries.
    pub fn retry_after_secs(self) -> u64 {
        match self {
            LoadLevel::Green => 1,
            LoadLevel::Elevated => 2,
            LoadLevel::High => 5,
            LoadLevel::Critical => 10,
        }
    }
}

/// The node's work in priority order, highest first. Under load the node
/// sheds from the bottom of this list; the first three are never shed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkClass {
    /// Votes, proposals, certificates and the signing of them, and key
    /// custody. Never shed.
    ConsensusAndCustody,
    /// Block import and sync. Never shed.
    BlockImportSync,
    /// Transaction admission into the mempool.
    TransactionAdmission,
    /// Public RPC and API reads.
    PublicRpc,
    /// Relay forwarding, provider workloads and non-essential gossip.
    RelayAndProvider,
    /// Model serving and the assistant.
    ModelServing,
    /// Compaction, snapshot production, indexing and telemetry.
    Background,
}

impl WorkClass {
    /// Every class, highest priority first.
    pub const ALL: [WorkClass; 7] = [
        WorkClass::ConsensusAndCustody,
        WorkClass::BlockImportSync,
        WorkClass::TransactionAdmission,
        WorkClass::PublicRpc,
        WorkClass::RelayAndProvider,
        WorkClass::ModelServing,
        WorkClass::Background,
    ];

    /// Lowercase name for logs and status output.
    pub fn name(self) -> &'static str {
        match self {
            WorkClass::ConsensusAndCustody => "consensus_and_custody",
            WorkClass::BlockImportSync => "block_import_sync",
            WorkClass::TransactionAdmission => "transaction_admission",
            WorkClass::PublicRpc => "public_rpc",
            WorkClass::RelayAndProvider => "relay_and_provider",
            WorkClass::ModelServing => "model_serving",
            WorkClass::Background => "background",
        }
    }

    /// Whether a level may ever reduce this class.
    pub fn sheddable(self) -> bool {
        !matches!(
            self,
            WorkClass::ConsensusAndCustody | WorkClass::BlockImportSync
        )
    }
}

/// Share of its normal capacity a class keeps at a level, in percent. Zero
/// means the class is paused: new work of that class is refused with 503 and
/// a Retry-After. Rows are classes in priority order, columns are Green,
/// Elevated, High and Critical.
const CAPACITY: [[u8; 4]; 7] = [
    [100, 100, 100, 100], // consensus and custody
    [100, 100, 100, 100], // block import and sync
    [100, 100, 75, 50],   // transaction admission
    [100, 75, 40, 10],    // public RPC
    [100, 100, 0, 0],     // relay and provider
    [100, 100, 25, 0],    // model serving
    [100, 50, 0, 0],      // background
];

/// The share of its normal capacity `class` keeps at `level`, in percent.
pub fn capacity_percent(class: WorkClass, level: LoadLevel) -> u8 {
    CAPACITY[class as usize][level.index()]
}

/// The classes the node is shedding or throttling at `level`, lowest
/// priority first.
pub fn shed_classes(level: LoadLevel) -> Vec<WorkClass> {
    WorkClass::ALL
        .iter()
        .rev()
        .copied()
        .filter(|c| capacity_percent(*c, level) < 100)
        .collect()
}

/// An enter threshold for each of the three raised levels.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Steps {
    /// Enter ELEVATED at or past this value.
    pub elevated: f64,
    /// Enter HIGH at or past this value.
    pub high: f64,
    /// Enter CRITICAL at or past this value.
    pub critical: f64,
}

impl Steps {
    const fn new(elevated: f64, high: f64, critical: f64) -> Self {
        Self {
            elevated,
            high,
            critical,
        }
    }

    fn enter(&self, level: LoadLevel) -> f64 {
        match level {
            LoadLevel::Green => f64::NEG_INFINITY,
            LoadLevel::Elevated => self.elevated,
            LoadLevel::High => self.high,
            LoadLevel::Critical => self.critical,
        }
    }

    /// The highest level whose enter threshold `v` reaches.
    fn reached(&self, v: f64) -> LoadLevel {
        if v >= self.critical {
            LoadLevel::Critical
        } else if v >= self.high {
            LoadLevel::High
        } else if v >= self.elevated {
            LoadLevel::Elevated
        } else {
            LoadLevel::Green
        }
    }

    /// The highest level whose leave threshold `v` is still at or above:
    /// the level a node already in a level stays in.
    fn held(&self, v: f64) -> LoadLevel {
        let mut held = LoadLevel::Green;
        for l in [LoadLevel::Elevated, LoadLevel::High, LoadLevel::Critical] {
            if v >= self.enter(l) * LEAVE_RATIO {
                held = l;
            }
        }
        held
    }
}

/// Thresholds of every signal.
#[derive(Debug, Clone, PartialEq)]
pub struct LoadThresholds {
    /// Load average over one minute, per core. Used when PSI is absent.
    pub load_per_core: Steps,
    /// Runnable tasks per core. Used when PSI is absent.
    pub runnable_per_core: Steps,
    /// CPU pressure, percent of the last ten seconds some task waited.
    pub cpu_psi: Steps,
    /// Memory pressure, percent some task waited.
    pub mem_psi_some: Steps,
    /// Memory pressure, percent all tasks waited.
    pub mem_psi_full: Steps,
    /// I/O pressure, percent some task waited.
    pub io_psi: Steps,
    /// Memory in use, percent of the total (100 minus available).
    pub mem_used_pct: Steps,
    /// Swap in use, percent of the swap size.
    pub swap_used_pct: Steps,
    /// Memory in use inside this process's cgroup, percent of the lower of
    /// `memory.high` and `memory.max`.
    pub cgroup_used_pct: Steps,
    /// Event loop scheduling delay, milliseconds.
    pub loop_lag_ms: Steps,
    /// Recent TPM signing latency, milliseconds.
    pub tpm_ms: Steps,
    /// Disk sync latency of the data volume, milliseconds.
    pub disk_ms: Steps,
}

impl Default for LoadThresholds {
    fn default() -> Self {
        Self {
            load_per_core: Steps::new(1.0, 1.75, 3.0),
            runnable_per_core: Steps::new(1.5, 3.0, 6.0),
            cpu_psi: Steps::new(25.0, 50.0, 80.0),
            mem_psi_some: Steps::new(10.0, 25.0, 50.0),
            mem_psi_full: Steps::new(2.0, 8.0, 20.0),
            io_psi: Steps::new(25.0, 50.0, 80.0),
            mem_used_pct: Steps::new(85.0, 92.0, 97.0),
            swap_used_pct: Steps::new(60.0, 90.0, 100.1),
            cgroup_used_pct: Steps::new(85.0, 93.0, 98.0),
            loop_lag_ms: Steps::new(50.0, 250.0, 1000.0),
            tpm_ms: Steps::new(1500.0, 4000.0, 8000.0),
            disk_ms: Steps::new(100.0, 400.0, 1500.0),
        }
    }
}

/// One set of measurements. A field that cannot be measured is `None` and
/// contributes nothing.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LoadSample {
    /// Logical cores.
    pub cores: u32,
    /// One-minute load average divided by cores.
    pub load_per_core: Option<f64>,
    /// Tasks runnable now divided by cores.
    pub runnable_per_core: Option<f64>,
    /// CPU pressure, `some avg10`, percent.
    pub cpu_psi: Option<f64>,
    /// Memory pressure, `some avg10`, percent.
    pub mem_psi_some: Option<f64>,
    /// Memory pressure, `full avg10`, percent.
    pub mem_psi_full: Option<f64>,
    /// I/O pressure, `some avg10`, percent.
    pub io_psi: Option<f64>,
    /// Physical memory, bytes.
    pub mem_total: u64,
    /// Memory available without swapping, bytes.
    pub mem_available: u64,
    /// Swap size, bytes.
    pub swap_total: u64,
    /// Swap still free, bytes.
    pub swap_free: u64,
    /// Memory in use in this process's cgroup as a percent of its limit.
    pub cgroup_used_pct: Option<f64>,
    /// Threads of this process.
    pub threads: Option<u32>,
    /// Event loop scheduling delay, milliseconds.
    pub loop_lag_ms: Option<f64>,
    /// Recent TPM signing latency, milliseconds.
    pub tpm_ms: Option<f64>,
    /// Disk sync latency, milliseconds.
    pub disk_ms: Option<f64>,
    /// The disk ladder's level as 0 (ok) to 3 (last reserve), from the
    /// shared resource module.
    pub disk_level: Option<u8>,
}

impl LoadSample {
    fn mem_used_pct(&self) -> Option<f64> {
        (self.mem_total > 0)
            .then(|| 100.0 - self.mem_available as f64 * 100.0 / self.mem_total as f64)
    }

    fn swap_used_pct(&self) -> Option<f64> {
        (self.swap_total > 0)
            .then(|| 100.0 - self.swap_free as f64 * 100.0 / self.swap_total as f64)
    }

    /// Swap in use, as a load signal. A swap partition that is full of
    /// pages nothing is asking for is a standing condition of the host, not
    /// pressure, so swap counts only while memory itself is short: when
    /// memory use is known and below the leave line of the first level,
    /// the reading is ignored.
    fn swap_signal(&self, t: &LoadThresholds) -> Option<f64> {
        let memory_short = self
            .mem_used_pct()
            .is_none_or(|m| m >= t.mem_used_pct.elevated * LEAVE_RATIO);
        memory_short.then(|| self.swap_used_pct()).flatten()
    }

    /// Memory or swap is short enough that the node must give memory back.
    pub fn memory_short(&self, t: &LoadThresholds) -> bool {
        self.mem_used_pct()
            .is_some_and(|v| v >= t.mem_used_pct.high)
            || self
                .swap_signal(t)
                .is_some_and(|v| v >= t.swap_used_pct.high)
            || self
                .cgroup_used_pct
                .is_some_and(|v| v >= t.cgroup_used_pct.high)
            || self.mem_psi_full.is_some_and(|v| v >= t.mem_psi_full.high)
    }
}

/// A signal that holds the level where it is.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Cause {
    /// Which signal.
    pub signal: &'static str,
    /// Its value.
    pub value: f64,
}

/// A change of level.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Transition {
    /// The level left.
    pub from: LoadLevel,
    /// The level entered.
    pub to: LoadLevel,
    /// The signal that drove the highest level, when raising.
    pub cause: Option<Cause>,
}

/// The level each signal asks for under `pick`, with the signal's name and
/// value, for the highest one.
fn evaluate(
    s: &LoadSample,
    t: &LoadThresholds,
    pick: impl Fn(&Steps, f64) -> LoadLevel,
) -> (LoadLevel, Option<Cause>) {
    let mut best = (LoadLevel::Green, None::<Cause>);
    // The host's CPU signals describe the whole machine, not this node, and
    // a busy host must not stop the node from opening its keys: they raise
    // the level to HIGH at most. Memory, I/O and the node's own signals
    // still reach CRITICAL.
    let cpu_ceiling = |signal: &'static str, l: LoadLevel| {
        if matches!(signal, "cpu_psi" | "load_per_core" | "runnable_per_core") {
            l.min(LoadLevel::High)
        } else {
            l
        }
    };
    let mut consider = |signal: &'static str, value: Option<f64>, steps: &Steps| {
        if let Some(v) = value {
            let l = cpu_ceiling(signal, pick(steps, v));
            if l > best.0 {
                best = (l, Some(Cause { signal, value: v }));
            }
        }
    };
    // Pressure stall information measures waiting directly; the load average
    // and run queue stand in for it only where it is not reported.
    if s.cpu_psi.is_some() {
        consider("cpu_psi", s.cpu_psi, &t.cpu_psi);
    } else {
        consider("load_per_core", s.load_per_core, &t.load_per_core);
        consider(
            "runnable_per_core",
            s.runnable_per_core,
            &t.runnable_per_core,
        );
    }
    consider("mem_psi_some", s.mem_psi_some, &t.mem_psi_some);
    consider("mem_psi_full", s.mem_psi_full, &t.mem_psi_full);
    consider("io_psi", s.io_psi, &t.io_psi);
    consider("mem_used_pct", s.mem_used_pct(), &t.mem_used_pct);
    consider("swap_used_pct", s.swap_signal(t), &t.swap_used_pct);
    consider("cgroup_used_pct", s.cgroup_used_pct, &t.cgroup_used_pct);
    consider("loop_lag_ms", s.loop_lag_ms, &t.loop_lag_ms);
    consider("tpm_ms", s.tpm_ms, &t.tpm_ms);
    consider("disk_ms", s.disk_ms, &t.disk_ms);
    if let Some(d) = s.disk_level {
        // A disk at its refuse level or past it is a reason to stop taking
        // work that writes.
        let l = match d {
            0 | 1 => LoadLevel::Green,
            2 => LoadLevel::Elevated,
            _ => LoadLevel::High,
        };
        if l > best.0 {
            best = (
                l,
                Some(Cause {
                    signal: "disk_level",
                    value: d as f64,
                }),
            );
        }
    }
    best
}

/// Turns samples into levels with hysteresis.
#[derive(Debug)]
pub struct LoadLadder {
    thresholds: LoadThresholds,
    level: LoadLevel,
    up: u32,
    down: u32,
}

impl LoadLadder {
    /// A ladder at GREEN.
    pub fn new(thresholds: LoadThresholds) -> Self {
        Self {
            thresholds,
            level: LoadLevel::Green,
            up: 0,
            down: 0,
        }
    }

    /// The current level.
    pub fn level(&self) -> LoadLevel {
        self.level
    }

    /// The thresholds in force.
    pub fn thresholds(&self) -> &LoadThresholds {
        &self.thresholds
    }

    /// Takes one sample and returns the change it causes, if any.
    pub fn observe(&mut self, s: &LoadSample) -> Option<Transition> {
        let (reached, cause) = evaluate(s, &self.thresholds, Steps::reached);
        let (held, _) = evaluate(s, &self.thresholds, Steps::held);
        if reached > self.level {
            self.down = 0;
            self.up += 1;
            if self.up >= ENTER_SAMPLES {
                self.up = 0;
                let from = std::mem::replace(&mut self.level, reached);
                return Some(Transition {
                    from,
                    to: reached,
                    cause,
                });
            }
        } else if held < self.level {
            self.up = 0;
            self.down += 1;
            if self.down >= LEAVE_SAMPLES {
                self.down = 0;
                let from = self.level;
                // One level at a time, and never below what is still held.
                let to = LoadLevel::from_u8((from as u8 - 1).max(held as u8));
                self.level = to;
                return Some(Transition {
                    from,
                    to,
                    cause: None,
                });
            }
        } else {
            self.up = 0;
            self.down = 0;
        }
        None
    }
}

static LEVEL: AtomicU8 = AtomicU8::new(0);
static LOOP_LAG_US: AtomicU64 = AtomicU64::new(0);
static LAST_SAMPLE: OnceLock<Mutex<Option<LoadReport>>> = OnceLock::new();

/// The load level every part of the node reads. GREEN until a monitor runs.
pub fn current_level() -> LoadLevel {
    LoadLevel::from_u8(LEVEL.load(Ordering::Relaxed))
}

/// Sets the published level. The monitor calls this; tests use it to hold
/// the node at a level.
pub fn publish_level(level: LoadLevel) {
    LEVEL.store(level as u8, Ordering::Relaxed);
}

/// Returns every published load signal to GREEN, for when the monitor that
/// set them ends.
fn reset_published() {
    publish_level(LoadLevel::Green);
    MEMORY_SHORT.store(0, Ordering::Relaxed);
    tenzro_device_key::tpm_exec::set_pressure(0);
}

/// The share of `class`'s capacity available at the current level.
pub fn current_capacity(class: WorkClass) -> u8 {
    capacity_percent(class, current_level())
}

/// Whether new work of `class` may start at the current level.
pub fn admits(class: WorkClass) -> bool {
    current_capacity(class) > 0
}

/// What the monitor publishes for status, doctor and the assistant.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct LoadReport {
    /// The level now.
    pub level: LoadLevel,
    /// Classes of work being shed or throttled, lowest priority first.
    pub shedding: Vec<&'static str>,
    /// The signal that raised the level, while it is raised.
    pub cause: Option<Cause>,
    /// The last sample.
    pub sample: LoadSample,
}

/// The latest report, if a monitor has produced one.
pub fn latest_report() -> Option<LoadReport> {
    LAST_SAMPLE.get()?.lock().ok()?.clone()
}

impl LoadReport {
    /// One line for the status bar and the logs.
    pub fn summary(&self) -> String {
        if self.level == LoadLevel::Green {
            return "load GREEN".to_string();
        }
        let why = self
            .cause
            .as_ref()
            .map(|c| format!(" ({} {:.1})", c.signal, c.value))
            .unwrap_or_default();
        format!(
            "load {}{}; shedding {}",
            self.level.name(),
            why,
            self.shedding.join(", ")
        )
    }
}

/// Something the node can give back under memory pressure: a cache that
/// rebuilds, an index, a loaded model.
pub trait Reclaimer: Send + Sync {
    /// Name for the log line.
    fn name(&self) -> &'static str;
    /// Releases what can be released at `level` and returns the bytes freed,
    /// or zero when unknown.
    fn reclaim(&self, level: LoadLevel) -> u64;
    /// Called when the level falls below HIGH again: restore what
    /// [`reclaim`](Reclaimer::reclaim) reduced.
    fn relax(&self) {}
}

/// True while the node refuses requests that need much memory (loading a
/// model, a large import, a wide query): the level is HIGH or worse and
/// memory or swap is the reason.
pub fn refuses_memory_heavy() -> bool {
    MEMORY_SHORT.load(Ordering::Relaxed) != 0 && current_level() >= LoadLevel::High
}

static MEMORY_SHORT: AtomicU8 = AtomicU8::new(0);

/// Reads `/proc` and the cgroup for one sample. Measurements that are not
/// available stay `None`.
pub fn read_host(sample: &mut LoadSample) {
    sample.cores = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1);
    let cores = sample.cores.max(1) as f64;
    if let Ok(s) = std::fs::read_to_string("/proc/loadavg") {
        sample.load_per_core = s
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<f64>().ok())
            .map(|l| l / cores);
    }
    if let Ok(s) = std::fs::read_to_string("/proc/stat") {
        sample.runnable_per_core = s
            .lines()
            .find_map(|l| l.strip_prefix("procs_running "))
            .and_then(|v| v.trim().parse::<f64>().ok())
            // This reader is itself running.
            .map(|r| (r - 1.0).max(0.0) / cores);
    }
    if let Ok(s) = std::fs::read_to_string("/proc/meminfo") {
        let kb = |key: &str| {
            s.lines()
                .find_map(|l| l.strip_prefix(key))
                .and_then(|r| r.split_whitespace().next())
                .and_then(|v| v.parse::<u64>().ok())
                .map_or(0, |v| v << 10)
        };
        sample.mem_total = kb("MemTotal:");
        sample.mem_available = kb("MemAvailable:");
        sample.swap_total = kb("SwapTotal:");
        sample.swap_free = kb("SwapFree:");
    }
    sample.cpu_psi = psi("/proc/pressure/cpu", "some");
    sample.mem_psi_some = psi("/proc/pressure/memory", "some");
    sample.mem_psi_full = psi("/proc/pressure/memory", "full");
    sample.io_psi = psi("/proc/pressure/io", "some");
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        sample.threads = s
            .lines()
            .find_map(|l| l.strip_prefix("Threads:"))
            .and_then(|v| v.trim().parse().ok());
    }
    sample.cgroup_used_pct = cgroup_used_pct();
}

/// `avg10` of the `some` or `full` line of a PSI file.
fn psi(path: &str, kind: &str) -> Option<f64> {
    parse_psi(&std::fs::read_to_string(path).ok()?, kind)
}

/// Parses the `avg10` value of the `kind` line of PSI text.
pub fn parse_psi(text: &str, kind: &str) -> Option<f64> {
    text.lines()
        .find(|l| l.split_whitespace().next() == Some(kind))?
        .split_whitespace()
        .find_map(|t| t.strip_prefix("avg10="))?
        .parse()
        .ok()
}

fn cgroup_used_pct() -> Option<f64> {
    let rel = std::fs::read_to_string("/proc/self/cgroup")
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("0::"))?
        .trim()
        .to_string();
    let dir = Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
    let num = |f: &str| {
        std::fs::read_to_string(dir.join(f))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
    };
    let current = num("memory.current")?;
    let limit = [num("memory.high"), num("memory.max")]
        .into_iter()
        .flatten()
        .min()?;
    (limit > 0).then(|| current as f64 * 100.0 / limit as f64)
}

/// Disk sync latency: how long a small durable write to `dir` takes.
pub fn probe_disk_latency(dir: &Path) -> Option<Duration> {
    use std::io::Write;
    let path = dir.join(".load-probe");
    let started = Instant::now();
    let mut f = std::fs::File::create(&path).ok()?;
    f.write_all(&[0u8; 4096]).ok()?;
    f.sync_all().ok()?;
    let took = started.elapsed();
    let _ = std::fs::remove_file(&path);
    Some(took)
}

/// Runs the sampler, the event loop lag probe and the level publication.
pub struct LoadMonitor {
    reclaimers: Mutex<Vec<Arc<dyn Reclaimer>>>,
    data_dir: Option<std::path::PathBuf>,
    disk_level: Arc<AtomicU8>,
}

/// How often the sampler runs.
pub const SAMPLE_EVERY: Duration = Duration::from_secs(2);

impl LoadMonitor {
    /// A monitor that probes disk latency in `data_dir` when given.
    pub fn new(data_dir: Option<std::path::PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            reclaimers: Mutex::new(Vec::new()),
            data_dir,
            disk_level: Arc::new(AtomicU8::new(u8::MAX)),
        })
    }

    /// Registers something to release under memory pressure.
    pub fn register(&self, r: Arc<dyn Reclaimer>) {
        if let Ok(mut g) = self.reclaimers.lock() {
            g.push(r);
        }
    }

    /// The disk ladder's level (0 to 3) for the shared resource module to
    /// feed in.
    pub fn set_disk_level(&self, level: u8) {
        self.disk_level.store(level, Ordering::Relaxed);
    }

    /// Runs every reclaimer and returns the bytes they report freed.
    pub fn reclaim(&self, level: LoadLevel) -> u64 {
        let list: Vec<_> = self
            .reclaimers
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        let mut total = 0;
        for r in list {
            let freed = r.reclaim(level);
            info!(
                reclaimer = r.name(),
                freed_bytes = freed,
                "memory guard released"
            );
            total += freed;
        }
        total
    }

    /// Tells every reclaimer the pressure has passed.
    pub fn relax(&self) {
        let list: Vec<_> = self
            .reclaimers
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default();
        for r in list {
            r.relax();
        }
    }

    /// Builds the next sample from the host and the process probes.
    pub fn sample(&self, disk_ms: Option<f64>) -> LoadSample {
        let mut s = LoadSample::default();
        read_host(&mut s);
        s.loop_lag_ms = Some(LOOP_LAG_US.load(Ordering::Relaxed) as f64 / 1000.0);
        let tpm = tenzro_device_key::tpm_exec::recent_sign_latency();
        s.tpm_ms = (!tpm.is_zero()).then_some(tpm.as_secs_f64() * 1000.0);
        s.disk_ms = disk_ms;
        let d = self.disk_level.load(Ordering::Relaxed);
        s.disk_level = (d != u8::MAX).then_some(d);
        s
    }

    /// Applies one sample: advances the ladder, publishes, logs a change and
    /// runs the memory guard on entering HIGH or CRITICAL.
    pub fn apply(&self, ladder: &mut LoadLadder, s: LoadSample) -> Option<Transition> {
        let t = ladder.observe(&s);
        let level = ladder.level();
        MEMORY_SHORT.store(s.memory_short(ladder.thresholds()) as u8, Ordering::Relaxed);
        publish_level(level);
        tenzro_device_key::tpm_exec::set_pressure(level as u8);
        let cause = t.as_ref().and_then(|t| t.cause.clone());
        let previous = latest_report().and_then(|r| r.cause);
        let report = LoadReport {
            level,
            shedding: shed_classes(level).into_iter().map(|c| c.name()).collect(),
            cause: cause.or(if level > LoadLevel::Green {
                previous
            } else {
                None
            }),
            sample: s,
        };
        if let Some(t) = &t {
            if t.to > t.from {
                warn!(
                    from = t.from.name(),
                    to = t.to.name(),
                    cause = t.cause.as_ref().map(|c| c.signal),
                    value = t.cause.as_ref().map(|c| c.value),
                    shedding = %report.shedding.join(","),
                    "load level raised"
                );
            } else {
                info!(from = t.from.name(), to = t.to.name(), "load level lowered");
            }
            if t.from >= LoadLevel::High && t.to < LoadLevel::High {
                self.relax();
            }
            if t.to >= LoadLevel::High && t.to > t.from && MEMORY_SHORT.load(Ordering::Relaxed) != 0
            {
                self.reclaim(t.to);
            }
        }
        if let Ok(mut g) = LAST_SAMPLE.get_or_init(|| Mutex::new(None)).lock() {
            *g = Some(report);
        }
        t
    }

    /// Starts the event loop lag probe and the sampler on a dedicated OS
    /// thread, so a runtime saturated by work cannot keep the monitor from
    /// seeing it and acting. The lag probe sends a no-op task to the calling
    /// runtime and times how long it waits to run; while it has not run, the
    /// lag reading is the time waited so far. A sample is taken every
    /// `every`; `adjust` may change each one before it is applied. The
    /// thread ends when the returned handle is stopped or the runtime shuts
    /// down.
    pub fn spawn_with(
        self: &Arc<Self>,
        every: Duration,
        mut adjust: impl FnMut(&mut LoadSample) + Send + 'static,
    ) -> MonitorThread {
        /// Flips to false when the runtime drops the task holding it.
        struct Alive(Arc<AtomicBool>);
        impl Drop for Alive {
            fn drop(&mut self) {
                self.0.store(false, Ordering::Relaxed);
            }
        }
        const PING_EVERY: Duration = Duration::from_millis(100);
        let handle = tokio::runtime::Handle::current();
        let runtime_alive = Arc::new(AtomicBool::new(true));
        let guard = Alive(runtime_alive.clone());
        handle.spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        let stop = Arc::new(AtomicBool::new(false));
        let peak = Arc::new(AtomicU8::new(0));
        let me = self.clone();
        let (stop_t, peak_t) = (stop.clone(), peak.clone());
        let join = std::thread::Builder::new()
            .name("load-monitor".into())
            .spawn(move || {
                LOOP_LAG_US.store(0, Ordering::Relaxed);
                let mut ladder = LoadLadder::new(LoadThresholds::default());
                let mut pending: Option<(Instant, Arc<AtomicBool>)> = None;
                let mut last_ping = Instant::now() - PING_EVERY;
                let mut last_sample = Instant::now() - every;
                while !stop_t.load(Ordering::Relaxed) && runtime_alive.load(Ordering::Relaxed) {
                    match &pending {
                        Some((sent, ran)) if ran.load(Ordering::Acquire) => {
                            let us = sent.elapsed().as_micros().min(u64::MAX as u128) as u64;
                            let prev = LOOP_LAG_US.load(Ordering::Relaxed);
                            // Peaks are kept, calm decays by a quarter each probe.
                            let next = if us >= prev {
                                us
                            } else {
                                prev - (prev - us) / 4
                            };
                            LOOP_LAG_US.store(next, Ordering::Relaxed);
                            pending = None;
                        }
                        Some((sent, _)) => {
                            let us = sent.elapsed().as_micros().min(u64::MAX as u128) as u64;
                            if us > LOOP_LAG_US.load(Ordering::Relaxed) {
                                LOOP_LAG_US.store(us, Ordering::Relaxed);
                            }
                        }
                        None if last_ping.elapsed() >= PING_EVERY => {
                            let ran = Arc::new(AtomicBool::new(false));
                            let flag = ran.clone();
                            handle.spawn(async move {
                                flag.store(true, Ordering::Release);
                            });
                            pending = Some((Instant::now(), ran));
                            last_ping = Instant::now();
                        }
                        None => {}
                    }
                    if last_sample.elapsed() >= every {
                        let disk = me
                            .data_dir
                            .as_deref()
                            .and_then(probe_disk_latency)
                            .map(|d| d.as_secs_f64() * 1000.0);
                        let mut s = me.sample(disk);
                        adjust(&mut s);
                        me.apply(&mut ladder, s);
                        peak_t.fetch_max(current_level() as u8, Ordering::Relaxed);
                        last_sample = Instant::now();
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                // The level belongs to the node this monitor watched: a node
                // started after it must not begin under it.
                reset_published();
            })
            .expect("the load monitor thread starts");
        MonitorThread {
            stop,
            peak,
            join: Some(join),
        }
    }
}

/// The monitor's OS thread.
pub struct MonitorThread {
    stop: Arc<AtomicBool>,
    peak: Arc<AtomicU8>,
    join: Option<std::thread::JoinHandle<()>>,
}

impl MonitorThread {
    /// The highest level the thread has published.
    pub fn peak(&self) -> LoadLevel {
        LoadLevel::from_u8(self.peak.load(Ordering::Relaxed))
    }

    /// Ends the thread and waits for it.
    pub fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn calm() -> LoadSample {
        LoadSample {
            cores: 8,
            cpu_psi: Some(1.0),
            mem_total: 100,
            mem_available: 60,
            swap_total: 100,
            swap_free: 100,
            loop_lag_ms: Some(1.0),
            ..Default::default()
        }
    }

    fn drive(l: &mut LoadLadder, s: &LoadSample, n: u32) -> Vec<Transition> {
        (0..n).filter_map(|_| l.observe(s)).collect()
    }

    #[test]
    fn one_spike_does_not_change_the_level() {
        let mut l = LoadLadder::new(LoadThresholds::default());
        let mut hot = calm();
        hot.cpu_psi = Some(90.0);
        assert!(l.observe(&hot).is_none());
        assert!(l.observe(&calm()).is_none());
        assert_eq!(l.level(), LoadLevel::Green);
    }

    #[test]
    fn sustained_pressure_raises_and_calm_lowers_one_level_at_a_time() {
        let mut l = LoadLadder::new(LoadThresholds::default());
        let mut hot = calm();
        hot.cpu_psi = Some(90.0);
        let up = drive(&mut l, &hot, ENTER_SAMPLES);
        assert_eq!(up.len(), 1);
        assert_eq!(up[0].to, LoadLevel::High);
        assert_eq!(up[0].cause.as_ref().unwrap().signal, "cpu_psi");
        let down = drive(&mut l, &calm(), LEAVE_SAMPLES * 4);
        let path: Vec<_> = down.iter().map(|t| t.to).collect();
        assert_eq!(path, vec![LoadLevel::Elevated, LoadLevel::Green]);
    }

    #[test]
    fn host_cpu_pressure_raises_the_level_to_high_and_no_further() {
        let mut l = LoadLadder::new(LoadThresholds::default());
        let mut busy = calm();
        busy.cpu_psi = Some(72.98);
        let up = drive(&mut l, &busy, ENTER_SAMPLES);
        assert_eq!(up.len(), 1);
        assert_eq!(up[0].to, LoadLevel::High);
        assert_eq!(up[0].cause.as_ref().unwrap().signal, "cpu_psi");
        busy.cpu_psi = Some(100.0);
        assert!(drive(&mut l, &busy, ENTER_SAMPLES * 4).is_empty());
        assert_eq!(l.level(), LoadLevel::High);
    }

    #[test]
    fn the_load_average_stand_in_is_held_to_high_too() {
        let mut s = calm();
        s.cpu_psi = None;
        s.load_per_core = Some(9.0);
        s.runnable_per_core = Some(20.0);
        let mut l = LoadLadder::new(LoadThresholds::default());
        drive(&mut l, &s, ENTER_SAMPLES);
        assert_eq!(l.level(), LoadLevel::High);
    }

    #[test]
    fn memory_and_node_signals_still_reach_critical() {
        let mut s = calm();
        s.cpu_psi = Some(100.0);
        s.mem_psi_full = Some(30.0);
        let mut l = LoadLadder::new(LoadThresholds::default());
        drive(&mut l, &s, ENTER_SAMPLES * 2);
        assert_eq!(l.level(), LoadLevel::Critical);
        let mut s = calm();
        s.tpm_ms = Some(9000.0);
        let mut l = LoadLadder::new(LoadThresholds::default());
        drive(&mut l, &s, ENTER_SAMPLES * 2);
        assert_eq!(l.level(), LoadLevel::Critical);
    }

    #[tokio::test]
    async fn a_stopped_monitor_leaves_the_next_node_at_green() {
        let monitor = LoadMonitor::new(None).spawn_with(Duration::from_millis(20), |s| {
            s.mem_psi_full = Some(30.0);
        });
        let until = Instant::now() + Duration::from_secs(10);
        while tenzro_device_key::tpm_exec::pressure() < 3 {
            assert!(Instant::now() < until, "the monitor never reached CRITICAL");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(current_level(), LoadLevel::Critical);
        monitor.stop();
        assert_eq!(current_level(), LoadLevel::Green);
        assert_eq!(tenzro_device_key::tpm_exec::pressure(), 0);
    }

    #[test]
    fn a_value_between_leave_and_enter_holds_the_level() {
        let mut l = LoadLadder::new(LoadThresholds::default());
        let mut s = calm();
        s.cpu_psi = Some(30.0);
        drive(&mut l, &s, ENTER_SAMPLES);
        assert_eq!(l.level(), LoadLevel::Elevated);
        // 22 is under the enter threshold (25) and over the leave one (20).
        s.cpu_psi = Some(22.0);
        assert!(drive(&mut l, &s, 20).is_empty());
        assert_eq!(l.level(), LoadLevel::Elevated);
        s.cpu_psi = Some(15.0);
        assert_eq!(drive(&mut l, &s, LEAVE_SAMPLES).len(), 1);
        assert_eq!(l.level(), LoadLevel::Green);
    }

    #[test]
    fn a_high_snapshot_reading_is_reported_as_high() {
        // Load 14 on 8 cores, swap 7.9 of 8 GB used, 2.6 GB free of 16 GB.
        let s = LoadSample {
            cores: 8,
            load_per_core: Some(14.0 / 8.0),
            mem_total: 16 << 30,
            mem_available: 26 * (1 << 30) / 10,
            swap_total: 8 << 30,
            swap_free: (8 << 30) / 80,
            ..Default::default()
        };
        let mut l = LoadLadder::new(LoadThresholds::default());
        drive(&mut l, &s, ENTER_SAMPLES);
        assert!(l.level() >= LoadLevel::High, "{:?}", l.level());
        assert!(s.memory_short(l.thresholds()));
    }

    #[test]
    fn load_average_stands_in_when_psi_is_absent() {
        let mut s = calm();
        s.cpu_psi = None;
        s.load_per_core = Some(2.0);
        let mut l = LoadLadder::new(LoadThresholds::default());
        drive(&mut l, &s, ENTER_SAMPLES);
        assert_eq!(l.level(), LoadLevel::High);
    }

    #[test]
    fn event_loop_lag_and_tpm_latency_raise_the_level() {
        let mut l = LoadLadder::new(LoadThresholds::default());
        let mut s = calm();
        s.tpm_ms = Some(5000.0);
        drive(&mut l, &s, ENTER_SAMPLES);
        assert_eq!(l.level(), LoadLevel::High);
        let mut l = LoadLadder::new(LoadThresholds::default());
        let mut s = calm();
        s.loop_lag_ms = Some(300.0);
        drive(&mut l, &s, ENTER_SAMPLES);
        assert_eq!(l.level(), LoadLevel::High);
    }

    #[test]
    fn consensus_custody_and_import_are_never_shed() {
        for level in [
            LoadLevel::Green,
            LoadLevel::Elevated,
            LoadLevel::High,
            LoadLevel::Critical,
        ] {
            for c in WorkClass::ALL {
                if !c.sheddable() {
                    assert_eq!(capacity_percent(c, level), 100, "{c:?} at {level:?}");
                }
            }
        }
    }

    #[test]
    fn capacity_never_rises_with_load() {
        for c in WorkClass::ALL {
            let row: Vec<u8> = [
                LoadLevel::Green,
                LoadLevel::Elevated,
                LoadLevel::High,
                LoadLevel::Critical,
            ]
            .iter()
            .map(|l| capacity_percent(c, *l))
            .collect();
            assert!(row.windows(2).all(|w| w[0] >= w[1]), "{c:?}: {row:?}");
        }
        assert!(shed_classes(LoadLevel::Green).is_empty());
    }

    #[test]
    fn shedding_goes_from_the_bottom() {
        let high = shed_classes(LoadLevel::High);
        assert_eq!(high.first(), Some(&WorkClass::Background));
        assert!(!high.contains(&WorkClass::BlockImportSync));
        assert!(!high.contains(&WorkClass::ConsensusAndCustody));
    }

    #[test]
    fn psi_text_parses() {
        let t = "some avg10=12.50 avg60=3.00 avg300=1.00 total=100\nfull avg10=0.75 avg60=0.00 avg300=0.00 total=5\n";
        assert_eq!(parse_psi(t, "some"), Some(12.5));
        assert_eq!(parse_psi(t, "full"), Some(0.75));
        assert_eq!(parse_psi("", "some"), None);
    }

    #[test]
    fn the_host_reading_works_here() {
        let mut s = LoadSample::default();
        read_host(&mut s);
        assert!(s.cores >= 1);
        if std::path::Path::new("/proc/meminfo").exists() {
            assert!(s.mem_total > 0);
        }
    }

    struct Counter(std::sync::atomic::AtomicU32);
    impl Reclaimer for Counter {
        fn name(&self) -> &'static str {
            "counter"
        }
        fn reclaim(&self, _: LoadLevel) -> u64 {
            self.0.fetch_add(1, Ordering::SeqCst);
            1000
        }
    }

    #[test]
    fn a_full_swap_with_comfortable_memory_is_not_load() {
        let mut l = LoadLadder::new(LoadThresholds::default());
        let s = LoadSample {
            cores: 8,
            mem_total: 100,
            mem_available: 60,
            swap_total: 100,
            swap_free: 1,
            ..Default::default()
        };
        for _ in 0..6 {
            l.observe(&s);
        }
        assert_eq!(l.level(), LoadLevel::Green);
        assert!(!s.memory_short(l.thresholds()));
    }

    #[test]
    fn entering_high_with_short_memory_runs_the_reclaimers_once() {
        let monitor = LoadMonitor::new(None);
        let c = Arc::new(Counter(Default::default()));
        monitor.register(c.clone());
        let mut ladder = LoadLadder::new(LoadThresholds::default());
        let squeezed = LoadSample {
            cores: 8,
            mem_total: 100,
            mem_available: 5,
            swap_total: 100,
            swap_free: 2,
            ..Default::default()
        };
        for _ in 0..6 {
            monitor.apply(&mut ladder, squeezed.clone());
        }
        assert!(ladder.level() >= LoadLevel::High);
        assert_eq!(
            c.0.load(Ordering::SeqCst),
            1,
            "once per entry, not per sample"
        );
        assert!(refuses_memory_heavy());
        // Calm returns the node to GREEN and lifts the refusal.
        for _ in 0..(LEAVE_SAMPLES * 4) {
            monitor.apply(&mut ladder, calm());
        }
        assert_eq!(ladder.level(), LoadLevel::Green);
        assert!(!refuses_memory_heavy());
        assert_eq!(current_level(), LoadLevel::Green);
    }
}
