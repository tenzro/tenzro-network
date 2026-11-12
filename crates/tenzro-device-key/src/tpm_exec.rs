//! Every TPM command this process sends goes through one executor.
//!
//! - One dedicated thread does all TPM I/O, so the process never has two TPM
//!   commands in flight and no async worker ever blocks on the chip.
//! - Each call has a deadline ([`Limits::call_timeout`], 10 s unless
//!   configured). A caller whose command has not answered by then gets an
//!   error; the command it queued is skipped if it has not started. While the
//!   thread is stuck on a command older than the deadline, new calls fail at
//!   once instead of queueing behind it.
//! - Signing and quoting are rate-limited by token buckets, so a burst of
//!   requests cannot monopolise a chip other processes share. A call that
//!   cannot get a token before its deadline fails.
//! - Commands queued while [`high_priority`] is held on the calling thread
//!   (consensus signing) run before commands queued without it, so block and
//!   vote signing is not delayed by a batch of announcement signatures. A
//!   normal command that has waited [`AGING`] is served first, so it cannot
//!   starve. Commands queued under [`deferred`] (endpoint record binding,
//!   heartbeats) run after both.
//! - Consensus commands get [`Limits::consensus_timeout`], the longest budget;
//!   every other command gets [`Limits::call_timeout`].
//! - A circuit breaker watches for a TPM that stops answering. After
//!   [`Limits::breaker_trip_after`] unanswered commands in a row it opens:
//!   normal and deferred commands are refused at once, with a hint of when to
//!   ask again, and one probe is let through after a pause that doubles with
//!   each failed probe (with jitter, capped at [`Limits::breaker_cap`]).
//!   Consensus commands are never refused by the breaker, only queued, so a
//!   vote still goes out the moment the chip answers. The breaker closes the
//!   moment any command comes back, including one that outlived its caller.
//!   [`health`] reports the state; the stall and the recovery are each logged
//!   once, with a reminder once a minute while the stall lasts.
//! - Both queues are bounded, and the bounds and deadlines follow the node's
//!   load level ([`set_pressure`]): under load a consensus command gets a
//!   longer deadline, so a slow chip does not turn into a missed vote, and
//!   normal commands (heartbeats, announcements) are refused first, so they
//!   never take the chip from consensus.

use std::cell::Cell;
use std::collections::VecDeque;
use std::panic::AssertUnwindSafe;
use std::sync::Condvar;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::{DeviceKeyError, Result};

/// The executor's limits, set once per process with [`configure`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Limits {
    /// The longest one TPM command may take before its caller gets an error.
    pub call_timeout: Duration,
    /// The same for a command queued under [`high_priority`]: block and vote
    /// signing, whose deadline is the consensus round.
    pub consensus_timeout: Duration,
    /// Unanswered commands in a row that open the circuit breaker.
    pub breaker_trip_after: u32,
    /// The pause before the first probe once the breaker opened; it doubles
    /// with each failed probe.
    pub breaker_base: Duration,
    /// The longest pause between probes.
    pub breaker_cap: Duration,
    /// Sustained `TPM2_Sign` commands per second (the burst is the same).
    pub signs_per_second: u32,
    /// Sustained `TPM2_Quote` and `TPM2_Certify` commands per second.
    pub quotes_per_second: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            call_timeout: Duration::from_secs(10),
            consensus_timeout: Duration::from_secs(30),
            breaker_trip_after: 3,
            breaker_base: Duration::from_secs(1),
            breaker_cap: Duration::from_secs(20),
            signs_per_second: 30,
            quotes_per_second: 2,
        }
    }
}

static LIMITS: OnceLock<Limits> = OnceLock::new();

/// Set this process's TPM limits. Must run before the first TPM command;
/// refused afterwards, or when a value is zero.
pub fn configure(limits: Limits) -> Result<()> {
    if limits.call_timeout.is_zero()
        || limits.consensus_timeout < limits.call_timeout
        || limits.breaker_trip_after == 0
        || limits.breaker_base.is_zero()
        || limits.breaker_cap < limits.breaker_base
        || limits.signs_per_second == 0
        || limits.quotes_per_second == 0
    {
        return Err(DeviceKeyError::Tpm(
            "TPM limits must be non-zero: a call timeout (the consensus timeout no shorter), \
             a breaker trip count and base pause (the cap no shorter), signs per second and \
             quotes per second"
                .into(),
        ));
    }
    let set = LIMITS.get_or_init(|| limits);
    if *set != limits {
        return Err(DeviceKeyError::Tpm(format!(
            "TPM limits already in use ({set:?}); set them before the first TPM command"
        )));
    }
    Ok(())
}

/// The process-wide executor.
pub(crate) fn global() -> &'static Executor {
    EXEC.get_or_init(|| Executor::new(*LIMITS.get_or_init(Limits::default)))
}

static EXEC: OnceLock<Executor> = OnceLock::new();

/// How this process's TPM is answering. A process that never sent a TPM
/// command reports a healthy, idle chip.
pub fn health() -> Health {
    match EXEC.get() {
        Some(e) => e.health(),
        None => Health::idle(),
    }
}

/// Which rate limit a command counts against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    Sign,
    Quote,
    Other,
}

impl Class {
    pub(crate) fn of(command: &[u8]) -> Self {
        use crate::tpm_wire::{
            TPM2_CC_CERTIFY, TPM2_CC_QUOTE, TPM2_CC_SIGN, TPM2_CC_SIGN_SEQUENCE_COMPLETE,
            command_code,
        };
        match command_code(command) {
            Some(TPM2_CC_SIGN | TPM2_CC_SIGN_SEQUENCE_COMPLETE) => Self::Sign,
            Some(TPM2_CC_QUOTE | TPM2_CC_CERTIFY) => Self::Quote,
            _ => Self::Other,
        }
    }
}

struct Bucket {
    per_second: f64,
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn new(per_second: u32) -> Self {
        Self {
            per_second: f64::from(per_second),
            tokens: f64::from(per_second),
            last: Instant::now(),
        }
    }

    /// Take a token, returning how long to wait for it. The token is taken
    /// even when it is still owed, so waiters are served in order.
    fn take(&mut self, now: Instant) -> Duration {
        let burst = self.per_second.max(1.0);
        self.tokens = (self.tokens + now.duration_since(self.last).as_secs_f64() * self.per_second)
            .min(burst);
        self.last = now;
        self.tokens -= 1.0;
        if self.tokens >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-self.tokens / self.per_second)
        }
    }

    fn give_back(&mut self) {
        self.tokens += 1.0;
    }
}

type Job = Box<dyn FnOnce() + Send>;

/// Most consensus-priority commands waiting at once.
pub const HIGH_QUEUE_CAP: usize = 1024;

/// Places kept for normal-priority commands at CRITICAL. A command holds a
/// place only while it waits, and the commands of one thread go one after
/// another, so each thread holds at most one. A node start opens its keys
/// from a handful of threads (the batch ticker, the consensus, machine and
/// wallet identities, the observer and issuer keys) and a batch flush is one
/// thread sending its sign and sequence commands in turn; eight places hold
/// both at once and stay under the 16 of HIGH, so shedding still tightens.
const CRITICAL_NORMAL_FLOOR: usize = 8;

/// Most normal-priority commands waiting at each load level, GREEN to
/// CRITICAL. At CRITICAL a few places stay open: the chip is kept for
/// consensus, but a node can still open its identity and sign its batches.
const NORMAL_QUEUE_CAP: [usize; 4] = [256, 128, 16, CRITICAL_NORMAL_FLOOR];

/// Most normal-priority commands that may wait for a caller at `level`. A
/// lifecycle caller (see [`lifecycle`]) is held to the GREEN bound whatever
/// the level.
fn normal_cap(level: usize, lifecycle: bool) -> usize {
    NORMAL_QUEUE_CAP[if lifecycle { 0 } else { level }]
}

/// How much longer a consensus-priority command may take at each load level.
const HIGH_DEADLINE_SCALE: [f64; 4] = [1.0, 1.5, 2.0, 3.0];

static PRESSURE: AtomicU8 = AtomicU8::new(0);
static SIGN_LATENCY_US: AtomicU64 = AtomicU64::new(0);

/// Tells the executor the node's load level, 0 (GREEN) to 3 (CRITICAL).
pub fn set_pressure(level: u8) {
    PRESSURE.store(level.min(3), Ordering::Relaxed);
}

/// The load level the executor works under, 0 to 3.
pub fn pressure() -> u8 {
    PRESSURE.load(Ordering::Relaxed)
}

/// How long recent signatures took from queueing to answer: a decaying
/// maximum, so one slow command stays visible for a few calls. The load
/// monitor reads it.
pub fn recent_sign_latency() -> Duration {
    Duration::from_micros(SIGN_LATENCY_US.load(Ordering::Relaxed))
}

fn note_sign_latency(d: Duration) {
    let us = d.as_micros().min(u64::MAX as u128) as u64;
    let prev = SIGN_LATENCY_US.load(Ordering::Relaxed);
    let next = if us >= prev {
        us
    } else {
        prev - (prev - us) / 4
    };
    SIGN_LATENCY_US.store(next, Ordering::Relaxed);
}

/// How long a normal-priority command may wait behind high-priority ones
/// before it is served first.
pub const AGING: Duration = Duration::from_secs(2);

thread_local! {
    static HIGH: Cell<u32> = const { Cell::new(0) };
    static DEFER: Cell<u32> = const { Cell::new(0) };
}

/// Number of live lifecycle guards in this process.
static LIFECYCLE: AtomicU32 = AtomicU32::new(0);

/// Keeps the process's normal TPM commands out of the load shedding until
/// dropped. Nests, and may be held across an await.
pub struct LifecycleGuard(());

/// Marks a node in this process as starting or stopping. While any guard
/// lives, normal TPM commands of the whole process wait in the queue as at
/// GREEN instead of being shed: a node that cannot open its key cannot
/// start, and a node that is shedding load still has to stop. The counter
/// is process-wide, so a production process runs one node.
pub fn lifecycle() -> LifecycleGuard {
    LIFECYCLE.fetch_add(1, Ordering::SeqCst);
    LifecycleGuard(())
}

impl Drop for LifecycleGuard {
    fn drop(&mut self) {
        LIFECYCLE.fetch_sub(1, Ordering::SeqCst);
    }
}

fn current_is_lifecycle() -> bool {
    LIFECYCLE.load(Ordering::SeqCst) > 0
}

/// Keeps the calling thread's TPM commands in the high-priority queue until
/// dropped. Nests.
pub struct PriorityGuard(());

/// Queues the TPM commands this thread sends ahead of normal-priority ones
/// while the returned guard lives: for signing a vote or a block, whose
/// deadline is the consensus round.
pub fn high_priority() -> PriorityGuard {
    HIGH.with(|h| h.set(h.get() + 1));
    PriorityGuard(())
}

impl Drop for PriorityGuard {
    fn drop(&mut self) {
        HIGH.with(|h| h.set(h.get().saturating_sub(1)));
    }
}

fn current_is_high() -> bool {
    HIGH.with(|h| h.get() > 0)
}

/// Keeps the calling thread's TPM commands in the deferred queue until
/// dropped: work whose result nobody is waiting on under a deadline, such as
/// binding an endpoint record or signing a heartbeat. It yields to every
/// other command and is refused first when the TPM stalls. A
/// [`high_priority`] guard on the same thread wins. Nests.
pub struct DeferGuard(());

/// Queues the TPM commands this thread sends behind all others while the
/// returned guard lives.
pub fn deferred() -> DeferGuard {
    DEFER.with(|h| h.set(h.get() + 1));
    DeferGuard(())
}

impl Drop for DeferGuard {
    fn drop(&mut self) {
        DEFER.with(|h| h.set(h.get().saturating_sub(1)));
    }
}

/// How urgent the calling thread's TPM commands are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tier {
    Consensus = 0,
    Normal = 1,
    Deferred = 2,
}

pub(crate) fn current_tier() -> Tier {
    if current_is_high() {
        Tier::Consensus
    } else if DEFER.with(|d| d.get() > 0) {
        Tier::Deferred
    } else {
        Tier::Normal
    }
}

/// How long a deferred command may wait behind others before it is served
/// first.
pub const DEFERRED_AGING: Duration = Duration::from_secs(10);

type Line = VecDeque<(Instant, Job)>;

/// The three-tier job queue the TPM thread drains.
#[derive(Default)]
struct JobQueue {
    tiers: Mutex<[Line; 3]>,
    ready: Condvar,
}

impl JobQueue {
    fn depth(&self, tier: Tier) -> usize {
        lock(&self.tiers)[tier as usize].len()
    }

    fn push(&self, tier: Tier, job: Job) {
        let mut t = lock(&self.tiers);
        t[tier as usize].push_back((Instant::now(), job));
        self.ready.notify_one();
    }

    fn len(&self) -> usize {
        lock(&self.tiers).iter().map(VecDeque::len).sum()
    }

    /// The next job: a normal one that has aged, else a deferred one that
    /// has aged, else a consensus one, else a normal one, else a deferred
    /// one. Blocks while all are empty.
    fn pop(&self) -> Job {
        let mut t = lock(&self.tiers);
        loop {
            let aged = |line: &Line, limit: Duration| {
                line.front().is_some_and(|(at, _)| at.elapsed() >= limit)
            };
            let pick = if aged(&t[1], AGING) {
                1
            } else if aged(&t[2], DEFERRED_AGING) {
                2
            } else {
                (0..3).find(|i| !t[*i].is_empty()).unwrap_or(3)
            };
            if pick < 3
                && let Some((_, job)) = t[pick].pop_front()
            {
                return job;
            }
            t = self.ready.wait(t).unwrap_or_else(|e| e.into_inner());
        }
    }
}

/// A sign command whose queue wait or chip time reaches this is logged at
/// `info`; faster ones at `debug`.
const SLOW_SIGN: Duration = Duration::from_millis(100);

/// Log how long one TPM sign command waited for the TPM thread and how long
/// the chip took to run it. `/dev/tpmrm0` serializes commands from every
/// process and swaps objects in and out of the chip, so the chip time here
/// includes time spent behind other processes' commands. Logging only.
fn record_sign_timing(command: &str, queue_wait: Duration, exec: Duration) {
    let queue_wait_ms = queue_wait.as_secs_f64() * 1000.0;
    let exec_ms = exec.as_secs_f64() * 1000.0;
    if queue_wait >= SLOW_SIGN || exec >= SLOW_SIGN {
        tracing::info!(
            op = "sign",
            command,
            queue_wait_ms,
            exec_ms,
            "TPM sign timing"
        );
    } else {
        tracing::debug!(
            op = "sign",
            command,
            queue_wait_ms,
            exec_ms,
            "TPM sign timing"
        );
    }
}

pub use crate::retry::{RetryGate, backoff, jitter_unit};

/// The text a refusal or timeout carries when the TPM did not answer, so a
/// caller can tell a stalled chip from one that lost a key.
const STALL_MARKERS: [&str; 3] = [
    "did not answer within",
    "has not answered a command",
    "TPM stalled",
];

/// Whether `e` says the TPM did not answer (a timeout, or a refusal while it
/// is stalled). A key is not lost in that case: asking the chip to load it
/// again only adds to the queue behind the stuck command.
pub fn is_stall(e: &DeviceKeyError) -> bool {
    let m = e.to_string();
    STALL_MARKERS.iter().any(|s| m.contains(s))
}

/// How the TPM is answering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HealthState {
    /// Commands come back in time.
    Healthy,
    /// Some command did not come back in time, or one was slow, but the
    /// circuit breaker has not opened.
    Degraded,
    /// The TPM stopped answering: the breaker is open, or a command has been
    /// running longer than its deadline.
    Stalled,
}

impl HealthState {
    /// The word `doctor` and `status` print.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Stalled => "stalled",
        }
    }
}

/// A command this slow marks the TPM degraded for a minute.
const SLOW_EXEC: Duration = Duration::from_secs(2);

/// What [`health`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Health {
    /// The summary.
    pub state: HealthState,
    /// Commands in a row that did not answer in time.
    pub consecutive_timeouts: u32,
    /// Commands that did not answer in time since the process started.
    pub timeouts_total: u64,
    /// Commands refused without reaching the chip because it was stalled.
    pub refused_total: u64,
    /// Times the breaker opened.
    pub trips_total: u64,
    /// Times a stalled chip answered again.
    pub recoveries_total: u64,
    /// How long the current stall has lasted.
    pub stalled_for: Option<Duration>,
    /// When the next probe is let through, while the breaker is open.
    pub next_probe_in: Option<Duration>,
    /// Time since any command came back.
    pub since_last_answer: Option<Duration>,
    /// How long the running command has been running.
    pub busy_for: Option<Duration>,
    /// Commands waiting for the chip.
    pub queue_depth: usize,
    /// Chip time of the last command, in milliseconds.
    pub last_exec_ms: u64,
}

impl Health {
    fn idle() -> Self {
        Self {
            state: HealthState::Healthy,
            consecutive_timeouts: 0,
            timeouts_total: 0,
            refused_total: 0,
            trips_total: 0,
            recoveries_total: 0,
            stalled_for: None,
            next_probe_in: None,
            since_last_answer: None,
            busy_for: None,
            queue_depth: 0,
            last_exec_ms: 0,
        }
    }

    /// The report as the JSON object `status` and the admin page carry.
    pub fn to_json(&self) -> serde_json::Value {
        let secs = |d: Option<Duration>| d.map(|d| d.as_secs_f64());
        serde_json::json!({
            "state": self.state.as_str(),
            "consecutive_timeouts": self.consecutive_timeouts,
            "timeouts_total": self.timeouts_total,
            "refused_total": self.refused_total,
            "trips_total": self.trips_total,
            "recoveries_total": self.recoveries_total,
            "stalled_for_secs": secs(self.stalled_for),
            "next_probe_in_secs": secs(self.next_probe_in),
            "since_last_answer_secs": secs(self.since_last_answer),
            "busy_for_secs": secs(self.busy_for),
            "queue_depth": self.queue_depth,
            "last_exec_ms": self.last_exec_ms,
            "summary": self.describe(),
        })
    }

    /// One line for `doctor` and `status`.
    pub fn describe(&self) -> String {
        let mut line = format!(
            "{} ({} timeouts, {} refused, {} stalls, {} recoveries, {} queued)",
            self.state.as_str(),
            self.timeouts_total,
            self.refused_total,
            self.trips_total,
            self.recoveries_total,
            self.queue_depth
        );
        if let Some(s) = self.stalled_for {
            line.push_str(&format!("; stalled for {}s", s.as_secs()));
        }
        if let Some(p) = self.next_probe_in {
            line.push_str(&format!("; next probe in {:.1}s", p.as_secs_f64()));
        }
        line
    }
}

#[derive(Debug, Clone, Copy)]
enum Gate {
    Closed,
    Open { until: Instant },
    Probing { since: Instant },
}

/// The circuit breaker's counters and state.
struct Breaker {
    gate: Gate,
    consecutive: u32,
    /// Trips since the breaker last closed: the backoff exponent.
    streak: u32,
    timeouts_total: u64,
    refused_total: u64,
    trips_total: u64,
    recoveries_total: u64,
    refused_in_stall: u64,
    stalled_since: Option<Instant>,
    last_reminder: Option<Instant>,
    last_answer: Option<Instant>,
    last_slow: Option<Instant>,
}

/// How often a stall that goes on is mentioned again.
const REMINDER: Duration = Duration::from_secs(60);

impl Breaker {
    fn new() -> Self {
        Self {
            gate: Gate::Closed,
            consecutive: 0,
            streak: 0,
            timeouts_total: 0,
            refused_total: 0,
            trips_total: 0,
            recoveries_total: 0,
            refused_in_stall: 0,
            stalled_since: None,
            last_reminder: None,
            last_answer: None,
            last_slow: None,
        }
    }

    /// Whether a normal or deferred command may go to the chip now: `Ok(true)`
    /// when it is the probe, `Err` with the time to wait when it is refused.
    fn admit(&mut self, now: Instant, limits: &Limits) -> std::result::Result<bool, Duration> {
        let refuse = |b: &mut Self, wait: Duration| {
            b.refused_total += 1;
            b.refused_in_stall += 1;
            Err(wait)
        };
        match self.gate {
            Gate::Closed => Ok(false),
            Gate::Open { until } if now >= until => {
                self.gate = Gate::Probing { since: now };
                Ok(true)
            }
            Gate::Open { until } => refuse(self, until - now),
            Gate::Probing { since } if now.duration_since(since) > limits.consensus_timeout * 2 => {
                // The probe's caller never reported; try again.
                self.gate = Gate::Probing { since: now };
                Ok(true)
            }
            Gate::Probing { .. } => refuse(self, limits.breaker_base),
        }
    }

    /// A command did not answer in time. Returns what to log, if anything.
    fn timed_out(&mut self, now: Instant, limits: &Limits) -> Option<String> {
        self.timeouts_total += 1;
        self.consecutive += 1;
        let probing = matches!(self.gate, Gate::Probing { .. });
        if !probing && (self.consecutive < limits.breaker_trip_after || self.is_open()) {
            return None;
        }
        self.trip(now, limits)
    }

    /// A command has been running longer than its deadline and a caller found
    /// the chip busy with it: that is a stall in itself. Counts the refusal
    /// and opens the breaker when it is closed.
    fn stuck(&mut self, now: Instant, limits: &Limits) -> Option<String> {
        self.refused_total += 1;
        self.refused_in_stall += 1;
        if self.is_open() {
            return None;
        }
        self.consecutive = self.consecutive.max(limits.breaker_trip_after);
        self.trip(now, limits)
    }

    /// Opens the breaker for the next pause; the text to log when the stall is
    /// new, or has gone on for a minute since it was last said.
    fn trip(&mut self, now: Instant, limits: &Limits) -> Option<String> {
        self.streak += 1;
        let pause = backoff(
            limits.breaker_base,
            limits.breaker_cap,
            self.streak,
            jitter_unit(),
        );
        self.gate = Gate::Open { until: now + pause };
        self.trips_total += 1;
        let first = self.stalled_since.is_none();
        let since = *self.stalled_since.get_or_insert(now);
        let remind = self
            .last_reminder
            .is_none_or(|at| now.duration_since(at) >= REMINDER);
        if !(first || remind) {
            return None;
        }
        self.last_reminder = Some(now);
        Some(if first {
            format!(
                "TPM stalled: it stopped answering commands; refusing normal commands and \
                 probing again in {:.1}s (consensus signing keeps waiting for the chip)",
                pause.as_secs_f64()
            )
        } else {
            format!(
                "TPM still stalled after {}s ({} commands refused); next probe in {:.1}s",
                now.duration_since(since).as_secs(),
                self.refused_in_stall,
                pause.as_secs_f64()
            )
        })
    }

    fn is_open(&self) -> bool {
        !matches!(self.gate, Gate::Closed)
    }

    /// A command came back. Returns what to log when that ends a stall.
    fn answered(&mut self, now: Instant, exec: Duration) -> Option<String> {
        self.last_answer = Some(now);
        if exec >= SLOW_EXEC {
            self.last_slow = Some(now);
        }
        self.consecutive = 0;
        let since = self.stalled_since.take()?;
        self.gate = Gate::Closed;
        self.streak = 0;
        self.last_reminder = None;
        self.recoveries_total += 1;
        let refused = std::mem::take(&mut self.refused_in_stall);
        Some(format!(
            "TPM answering again after a stall of {}s ({refused} commands refused)",
            now.duration_since(since).as_secs()
        ))
    }
}

/// State the TPM thread and the callers share.
struct Shared {
    limits: Limits,
    breaker: Mutex<Breaker>,
    /// When the command the thread is running started; `None` when idle.
    busy_since: Mutex<Option<Instant>>,
    last_exec_ms: std::sync::atomic::AtomicU64,
}

impl Shared {
    fn answered(&self, exec: Duration) {
        self.last_exec_ms
            .store(exec.as_millis() as u64, Ordering::Relaxed);
        let said = lock(&self.breaker).answered(Instant::now(), exec);
        if let Some(said) = said {
            tracing::info!("{said}");
        }
    }
}

/// Lets the TPM thread's commands win the CPU against the rest of a loaded
/// machine, when the process may. Best effort: refused without privilege, and
/// then the thread keeps the priority of the process.
#[cfg(target_os = "linux")]
fn raise_thread_priority() {
    // SAFETY: plain calls with constant arguments on this thread only.
    let rc = unsafe {
        let tid = libc::syscall(libc::SYS_gettid) as libc::id_t;
        libc::setpriority(libc::PRIO_PROCESS, tid, -10)
    };
    if rc != 0 {
        tracing::debug!("the TPM thread keeps the process's priority (raising it was refused)");
    }
}

#[cfg(not(target_os = "linux"))]
fn raise_thread_priority() {}

/// The serializing TPM executor: one thread, a deadline per call, rate
/// limits for signing and quoting, and a circuit breaker.
pub(crate) struct Executor {
    jobs: Arc<JobQueue>,
    shared: Arc<Shared>,
    signs: Mutex<Bucket>,
    quotes: Mutex<Bucket>,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Executor {
    pub(crate) fn new(limits: Limits) -> Self {
        let jobs = Arc::new(JobQueue::default());
        let queue = jobs.clone();
        let shared = Arc::new(Shared {
            limits,
            breaker: Mutex::new(Breaker::new()),
            busy_since: Mutex::new(None),
            last_exec_ms: std::sync::atomic::AtomicU64::new(0),
        });
        let sh = shared.clone();
        std::thread::Builder::new()
            .name("tpm".into())
            .spawn(move || {
                raise_thread_priority();
                loop {
                    let job = queue.pop();
                    let started = Instant::now();
                    *lock(&sh.busy_since) = Some(started);
                    // A panicking command must not take TPM access down with it.
                    let ran = std::panic::catch_unwind(AssertUnwindSafe(job));
                    *lock(&sh.busy_since) = None;
                    // A command that came back, even late and even to a caller
                    // that gave up, shows the chip answers.
                    if ran.is_ok() {
                        sh.answered(started.elapsed());
                    }
                }
            })
            .expect("spawn the TPM thread");
        Self {
            jobs,
            shared,
            signs: Mutex::new(Bucket::new(limits.signs_per_second)),
            quotes: Mutex::new(Bucket::new(limits.quotes_per_second)),
        }
    }

    /// How the TPM is answering now.
    pub(crate) fn health(&self) -> Health {
        let now = Instant::now();
        let limits = &self.shared.limits;
        let b = lock(&self.shared.breaker);
        let busy_for = lock(&self.shared.busy_since).map(|s| now.duration_since(s));
        let next_probe_in = match b.gate {
            Gate::Open { until } => Some(until.saturating_duration_since(now)),
            _ => None,
        };
        let stuck = busy_for.is_some_and(|d| d >= limits.call_timeout);
        let state = if b.is_open() || stuck {
            HealthState::Stalled
        } else if b.consecutive > 0
            || b.last_slow
                .is_some_and(|at| now.duration_since(at) < Duration::from_secs(60))
        {
            HealthState::Degraded
        } else {
            HealthState::Healthy
        };
        Health {
            state,
            consecutive_timeouts: b.consecutive,
            timeouts_total: b.timeouts_total,
            refused_total: b.refused_total,
            trips_total: b.trips_total,
            recoveries_total: b.recoveries_total,
            stalled_for: b.stalled_since.map(|s| now.duration_since(s)),
            next_probe_in,
            since_last_answer: b.last_answer.map(|a| now.duration_since(a)),
            busy_for,
            queue_depth: self.jobs.len(),
            last_exec_ms: self.shared.last_exec_ms.load(Ordering::Relaxed),
        }
    }

    /// Run `job` on the TPM thread and wait for it until the call deadline of
    /// the calling thread's tier.
    pub(crate) fn run<R: Send + 'static>(
        &self,
        what: &str,
        class: Class,
        job: impl FnOnce() -> Result<R> + Send + 'static,
    ) -> Result<R> {
        let start = Instant::now();
        let limits = self.shared.limits;
        let tier = current_tier();
        let level = pressure() as usize;
        let timeout = if tier == Tier::Consensus {
            limits.consensus_timeout.mul_f64(HIGH_DEADLINE_SCALE[level])
        } else {
            limits.call_timeout
        };
        let deadline = start + timeout;
        let cap = if tier == Tier::Consensus {
            HIGH_QUEUE_CAP
        } else {
            normal_cap(level, current_is_lifecycle())
        };
        if self.jobs.depth(tier) >= cap {
            return Err(DeviceKeyError::Tpm(format!(
                "{what}: the TPM queue is full or closed to this priority while the node is under load"
            )));
        }
        if let Some(since) = *lock(&self.shared.busy_since) {
            let stuck = since.elapsed();
            if stuck >= timeout {
                let said = lock(&self.shared.breaker).stuck(Instant::now(), &limits);
                if let Some(said) = said {
                    tracing::warn!("{said}");
                }
                return Err(DeviceKeyError::Tpm(format!(
                    "{what}: the TPM has not answered a command for {}s; refusing new commands until it does",
                    stuck.as_secs()
                )));
            }
        }
        self.admit(what, class, start, deadline)?;
        // Consensus commands only queue behind a stalled chip; the rest wait
        // for the breaker's next probe.
        if tier != Tier::Consensus {
            let verdict = lock(&self.shared.breaker).admit(start, &limits);
            if let Err(wait) = verdict {
                return Err(DeviceKeyError::Tpm(format!(
                    "{what}: TPM stalled; refusing normal commands, next probe in {:.1}s",
                    wait.as_secs_f64()
                )));
            }
        }

        let (reply, answer) = mpsc::sync_channel::<Result<R>>(1);
        let cancelled = Arc::new(AtomicBool::new(false));
        let skip = cancelled.clone();
        // Observability only: label and queue time for the sign timing line.
        let sign_label = (class == Class::Sign).then(|| what.to_string());
        let queued_at = Instant::now();
        self.jobs.push(
            tier,
            Box::new(move || {
                if !skip.load(Ordering::Acquire) {
                    let result = match sign_label {
                        Some(command) => {
                            let started = Instant::now();
                            let result = job();
                            note_sign_latency(queued_at.elapsed());
                            record_sign_timing(
                                &command,
                                started.duration_since(queued_at),
                                started.elapsed(),
                            );
                            result
                        }
                        None => job(),
                    };
                    let _ = reply.send(result);
                }
            }),
        );
        match answer.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(r) => r,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                cancelled.store(true, Ordering::Release);
                tracing::debug!(
                    command = what,
                    timeout_secs = timeout.as_secs_f64(),
                    "TPM command timed out"
                );
                let said = lock(&self.shared.breaker).timed_out(Instant::now(), &limits);
                if let Some(said) = said {
                    tracing::warn!("{said}");
                }
                Err(DeviceKeyError::Tpm(format!(
                    "{what}: the TPM did not answer within {}s",
                    timeout.as_secs_f64()
                )))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(DeviceKeyError::Tpm(format!(
                "{what}: the TPM command panicked"
            ))),
        }
    }

    /// Queue `job` without waiting for it: releasing a descriptor or a
    /// transient object, which nobody waits on and which must not block the
    /// caller when the chip is slow.
    pub(crate) fn detach(&self, job: impl FnOnce() + Send + 'static) {
        self.jobs.push(Tier::Normal, Box::new(job));
    }

    fn admit(&self, what: &str, class: Class, now: Instant, deadline: Instant) -> Result<()> {
        let bucket = match class {
            Class::Sign => &self.signs,
            Class::Quote => &self.quotes,
            Class::Other => return Ok(()),
        };
        let wait = lock(bucket).take(now);
        if wait.is_zero() {
            return Ok(());
        }
        if now + wait >= deadline {
            lock(bucket).give_back();
            return Err(DeviceKeyError::Tpm(format!(
                "{what}: TPM {} rate limit reached; retry later",
                if class == Class::Sign {
                    "signing"
                } else {
                    "quote"
                }
            )));
        }
        std::thread::sleep(wait);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    fn limits(timeout_ms: u64) -> Limits {
        Limits {
            call_timeout: Duration::from_millis(timeout_ms),
            consensus_timeout: Duration::from_millis(timeout_ms),
            signs_per_second: 1000,
            quotes_per_second: 1000,
            ..Limits::default()
        }
    }

    #[test]
    fn a_hung_call_times_out_and_later_calls_fail_fast_until_it_returns() {
        let exec = Executor::new(limits(200));
        let (release, hung) = mpsc::channel::<()>();
        let started = Instant::now();
        let err = exec
            .run("hang", Class::Other, move || {
                let _ = hung.recv();
                Ok(())
            })
            .unwrap_err();
        let waited = started.elapsed();
        assert!(err.to_string().contains("did not answer"), "{err}");
        assert!(
            waited >= Duration::from_millis(200) && waited < Duration::from_secs(2),
            "{waited:?}"
        );

        // The thread is still stuck: a new call fails at once rather than
        // queueing behind it, once the stuck command is older than the deadline.
        std::thread::sleep(Duration::from_millis(20));
        let t = Instant::now();
        let ran = Arc::new(AtomicBool::new(false));
        let r = ran.clone();
        let err = exec
            .run("next", Class::Other, move || {
                r.store(true, Ordering::SeqCst);
                Ok(())
            })
            .unwrap_err();
        assert!(err.to_string().contains("has not answered"), "{err}");
        assert!(t.elapsed() < Duration::from_millis(100));

        // Once the chip answers, the executor serves again.
        release.send(()).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert_eq!(exec.run("after", Class::Other, || Ok(7)).unwrap(), 7);
        assert!(!ran.load(Ordering::SeqCst), "a refused call never runs");
    }

    #[test]
    fn a_call_that_timed_out_while_queued_is_skipped() {
        let exec = Arc::new(Executor::new(limits(150)));
        let (release, hung) = mpsc::channel::<()>();
        let e = exec.clone();
        let first = std::thread::spawn(move || {
            e.run("slow", Class::Other, move || {
                let _ = hung.recv();
                Ok(())
            })
        });
        std::thread::sleep(Duration::from_millis(20));
        let ran = Arc::new(AtomicBool::new(false));
        let r = ran.clone();
        assert!(
            exec.run("queued", Class::Other, move || {
                r.store(true, Ordering::SeqCst);
                Ok(())
            })
            .is_err()
        );
        release.send(()).unwrap();
        assert!(first.join().unwrap().is_err());
        std::thread::sleep(Duration::from_millis(50));
        assert!(!ran.load(Ordering::SeqCst));
    }

    #[test]
    fn a_high_priority_command_runs_before_queued_normal_ones() {
        let exec = Arc::new(Executor::new(limits(5_000)));
        let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        let (started_tx, started) = mpsc::channel::<()>();
        let (release_tx, release) = mpsc::channel::<()>();
        // Occupy the TPM thread so the next commands queue up.
        let blocker = {
            let exec = exec.clone();
            std::thread::spawn(move || {
                exec.run("block", Class::Other, move || {
                    started_tx.send(()).unwrap();
                    release.recv().unwrap();
                    Ok(())
                })
                .unwrap();
            })
        };
        started.recv().unwrap();
        let spawn = |name: &'static str, high: bool| {
            let (exec, order) = (exec.clone(), order.clone());
            std::thread::spawn(move || {
                let _g = high.then(high_priority);
                exec.run(name, Class::Other, move || {
                    lock(&order).push(name);
                    Ok(())
                })
                .unwrap();
            })
        };
        let normal = spawn("normal", false);
        std::thread::sleep(Duration::from_millis(100));
        let high = spawn("high", true);
        std::thread::sleep(Duration::from_millis(100));
        release_tx.send(()).unwrap();
        for t in [blocker, normal, high] {
            t.join().unwrap();
        }
        assert_eq!(*lock(&order), vec!["high", "normal"]);
    }

    /// The load level is process-wide; tests that set it run one at a time.
    static LEVEL_TEST: Mutex<()> = Mutex::new(());

    #[test]
    fn at_critical_a_normal_command_still_gets_a_place_in_an_idle_queue() {
        let _serial = lock(&LEVEL_TEST);
        let exec = Executor::new(limits(1_000));
        set_pressure(3);
        let got = exec.run("open", Class::Other, || Ok(5));
        set_pressure(0);
        assert_eq!(got.unwrap(), 5);
    }

    #[test]
    fn at_critical_the_normal_queue_is_bounded_and_a_lifecycle_command_is_not() {
        let _serial = lock(&LEVEL_TEST);
        let exec = Arc::new(Executor::new(limits(5_000)));
        let (started_tx, started) = mpsc::channel::<()>();
        let (release_tx, release) = mpsc::channel::<()>();
        let blocker = {
            let exec = exec.clone();
            std::thread::spawn(move || {
                exec.run("block", Class::Other, move || {
                    started_tx.send(()).unwrap();
                    release.recv().unwrap();
                    Ok(())
                })
                .unwrap();
            })
        };
        started.recv().unwrap();
        set_pressure(3);
        let waiting: Vec<_> = (0..CRITICAL_NORMAL_FLOOR)
            .map(|_| {
                let exec = exec.clone();
                std::thread::spawn(move || exec.run("wait", Class::Other, || Ok(())).unwrap())
            })
            .collect();
        std::thread::sleep(Duration::from_millis(200));
        let err = exec.run("shed", Class::Other, || Ok(())).unwrap_err();
        assert!(err.to_string().contains("queue is full"), "{err}");
        let lifecycle_call = {
            let exec = exec.clone();
            std::thread::spawn(move || {
                let _g = lifecycle();
                exec.run("open", Class::Other, || Ok(1)).unwrap()
            })
        };
        std::thread::sleep(Duration::from_millis(100));
        release_tx.send(()).unwrap();
        blocker.join().unwrap();
        for t in waiting {
            t.join().unwrap();
        }
        assert_eq!(lifecycle_call.join().unwrap(), 1);
        set_pressure(0);
    }

    #[test]
    fn once_the_lifecycle_guard_is_dropped_a_normal_command_is_shed_again() {
        let _serial = lock(&LEVEL_TEST);
        let exec = Arc::new(Executor::new(limits(5_000)));
        let (started_tx, started) = mpsc::channel::<()>();
        let (release_tx, release) = mpsc::channel::<()>();
        let blocker = {
            let exec = exec.clone();
            std::thread::spawn(move || {
                exec.run("block", Class::Other, move || {
                    started_tx.send(()).unwrap();
                    release.recv().unwrap();
                    Ok(())
                })
                .unwrap();
            })
        };
        started.recv().unwrap();
        set_pressure(3);
        drop(lifecycle());
        let waiting: Vec<_> = (0..CRITICAL_NORMAL_FLOOR)
            .map(|_| {
                let exec = exec.clone();
                std::thread::spawn(move || exec.run("wait", Class::Other, || Ok(())).unwrap())
            })
            .collect();
        std::thread::sleep(Duration::from_millis(200));
        let err = exec.run("shed", Class::Other, || Ok(())).unwrap_err();
        assert!(err.to_string().contains("queue is full"), "{err}");
        release_tx.send(()).unwrap();
        blocker.join().unwrap();
        for t in waiting {
            t.join().unwrap();
        }
        set_pressure(0);
    }

    #[test]
    fn shedding_tightens_with_each_level() {
        assert!(normal_cap(0, false) > normal_cap(1, false));
        assert!(normal_cap(1, false) > normal_cap(2, false));
        assert!(normal_cap(2, false) > normal_cap(3, false));
        assert!(normal_cap(3, false) > 0);
        assert_eq!(normal_cap(3, true), normal_cap(0, false));
    }

    #[test]
    fn the_lifecycle_guard_nests_and_clears() {
        let _serial = lock(&LEVEL_TEST);
        assert!(!current_is_lifecycle());
        let a = lifecycle();
        let b = lifecycle();
        drop(a);
        assert!(current_is_lifecycle());
        drop(b);
        assert!(!current_is_lifecycle());
    }

    #[test]
    fn the_priority_guard_nests_and_clears() {
        assert!(!current_is_high());
        let a = high_priority();
        let b = high_priority();
        drop(a);
        assert!(current_is_high());
        drop(b);
        assert!(!current_is_high());
    }

    #[test]
    fn commands_never_overlap() {
        let exec = Arc::new(Executor::new(limits(5_000)));
        let inside = Arc::new(AtomicUsize::new(0));
        let overlapped = Arc::new(AtomicBool::new(false));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let (exec, inside, overlapped) = (exec.clone(), inside.clone(), overlapped.clone());
                std::thread::spawn(move || {
                    for _ in 0..10 {
                        let (inside, overlapped) = (inside.clone(), overlapped.clone());
                        exec.run("op", Class::Other, move || {
                            if inside.fetch_add(1, Ordering::SeqCst) != 0 {
                                overlapped.store(true, Ordering::SeqCst);
                            }
                            std::thread::sleep(Duration::from_micros(200));
                            inside.fetch_sub(1, Ordering::SeqCst);
                            Ok(())
                        })
                        .unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert!(!overlapped.load(Ordering::SeqCst));
    }

    #[test]
    fn signing_is_rate_limited() {
        let exec = Executor::new(Limits {
            call_timeout: Duration::from_millis(300),
            consensus_timeout: Duration::from_millis(300),
            signs_per_second: 2,
            quotes_per_second: 1000,
            ..Limits::default()
        });
        let sign = crate::tpm_wire::sign_command(0x8000_0000, &[0u8; 32]);
        assert_eq!(Class::of(&sign), Class::Sign);
        // The burst of two passes; the third would wait 500 ms, past the
        // 300 ms deadline, so it is refused without reaching the chip.
        for _ in 0..2 {
            exec.run("sign", Class::Sign, || Ok(())).unwrap();
        }
        let err = exec.run("sign", Class::Sign, || Ok(())).unwrap_err();
        assert!(err.to_string().contains("rate limit"), "{err}");
        // Other commands are not held back by the signing limit.
        exec.run("read", Class::Other, || Ok(())).unwrap();
    }

    #[test]
    fn a_panicking_command_does_not_stop_the_thread() {
        let exec = Executor::new(limits(1_000));
        assert!(
            exec.run::<()>("boom", Class::Other, || panic!("boom"))
                .is_err()
        );
        assert_eq!(exec.run("ok", Class::Other, || Ok(1)).unwrap(), 1);
    }

    /// Collects `tracing` events (level and `key=value` fields) from any
    /// thread, so a test can read what the TPM thread logged.
    mod capture {
        use std::sync::{Mutex, OnceLock};
        use tracing::field::{Field, Visit};
        use tracing::{Event, Metadata, Subscriber, span};

        pub(super) static LINES: OnceLock<Mutex<Vec<String>>> = OnceLock::new();

        struct Fields(String);
        impl Visit for Fields {
            fn record_debug(&mut self, f: &Field, v: &dyn std::fmt::Debug) {
                self.0.push_str(&format!(" {}={:?}", f.name(), v));
            }
        }

        struct Capture;
        impl Subscriber for Capture {
            fn enabled(&self, _: &Metadata<'_>) -> bool {
                true
            }
            fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
                span::Id::from_u64(1)
            }
            fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
            fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
            fn enter(&self, _: &span::Id) {}
            fn exit(&self, _: &span::Id) {}
            fn event(&self, e: &Event<'_>) {
                let mut f = Fields(format!("{}", e.metadata().level()));
                e.record(&mut f);
                LINES
                    .get_or_init(Default::default)
                    .lock()
                    .unwrap()
                    .push(f.0);
            }
        }

        pub(super) fn install() {
            let _ = tracing::subscriber::set_global_default(Capture);
        }

        pub(super) fn lines_with(needle: &str) -> Vec<String> {
            LINES
                .get_or_init(Default::default)
                .lock()
                .unwrap()
                .iter()
                .filter(|l| l.contains(needle))
                .cloned()
                .collect()
        }
    }

    #[test]
    fn a_sign_command_logs_its_queue_wait_and_chip_time_and_other_commands_do_not() {
        capture::install();
        let exec = Executor::new(limits(5_000));
        // A real sign command's bytes, so the class comes from the same
        // classification the TPM device uses; the closure stands in for the
        // chip and takes about 30 ms.
        let sign = crate::tpm_wire::sign_command(0x8100_0001, &[7u8; 32]);
        assert_eq!(Class::of(&sign), Class::Sign);
        exec.run("sign-timing-fast", Class::of(&sign), || {
            std::thread::sleep(Duration::from_millis(30));
            Ok(())
        })
        .unwrap();
        // One that takes longer than the slow threshold logs at info.
        exec.run("sign-timing-slow", Class::Sign, || {
            std::thread::sleep(Duration::from_millis(150));
            Ok(())
        })
        .unwrap();
        // A non-sign command, equally slow, logs nothing.
        exec.run("read-timing-other", Class::Other, || {
            std::thread::sleep(Duration::from_millis(30));
            Ok(())
        })
        .unwrap();

        let ms = |line: &str, key: &str| -> f64 {
            let at = line.find(&format!(" {key}=")).unwrap() + key.len() + 2;
            line[at..]
                .split_whitespace()
                .next()
                .unwrap()
                .parse()
                .unwrap()
        };
        let fast = capture::lines_with("sign-timing-fast");
        assert_eq!(fast.len(), 1, "{fast:?}");
        assert!(
            fast[0].starts_with("DEBUG") && fast[0].contains("op=\"sign\""),
            "{fast:?}"
        );
        let exec_ms = ms(&fast[0], "exec_ms");
        assert!((30.0..1_000.0).contains(&exec_ms), "{fast:?}");
        assert!(ms(&fast[0], "queue_wait_ms") < 100.0, "{fast:?}");
        let slow = capture::lines_with("sign-timing-slow");
        assert_eq!(slow.len(), 1, "{slow:?}");
        assert!(slow[0].starts_with("INFO"), "{slow:?}");
        assert!(ms(&slow[0], "exec_ms") >= 150.0, "{slow:?}");
        assert!(capture::lines_with("read-timing-other").is_empty());
        println!("captured: {fast:?} {slow:?}");
    }

    #[test]
    fn zero_limits_are_refused() {
        assert!(
            configure(Limits {
                call_timeout: Duration::ZERO,
                ..Limits::default()
            })
            .is_err()
        );
    }

    fn stall_limits() -> Limits {
        Limits {
            call_timeout: Duration::from_millis(100),
            consensus_timeout: Duration::from_millis(3_000),
            breaker_trip_after: 3,
            breaker_base: Duration::from_millis(40),
            breaker_cap: Duration::from_millis(160),
            ..limits(100)
        }
    }

    /// A job that holds the TPM thread until `release` is sent. It is on the
    /// TPM thread by the time this returns, so the caller's next command
    /// queues behind it however the threads are scheduled.
    fn stall(
        exec: &Arc<Executor>,
        name: &'static str,
    ) -> (mpsc::Sender<()>, std::thread::JoinHandle<()>) {
        let (release, hold) = mpsc::channel::<()>();
        let (holding, held) = mpsc::channel::<()>();
        let exec = exec.clone();
        let t = std::thread::spawn(move || {
            let _ = exec.run(name, Class::Other, move || {
                let _ = holding.send(());
                let _ = hold.recv();
                Ok(())
            });
        });
        let _ = held.recv();
        (release, t)
    }

    #[test]
    fn a_stalled_tpm_opens_the_breaker_refuses_normal_commands_and_recovers_on_its_own() {
        let exec = Arc::new(Executor::new(stall_limits()));
        let (release, first) = stall(&exec, "stuck");
        // Three callers in a row wait their deadline and get no answer.
        for _ in 0..3 {
            let err = exec.run("next", Class::Other, || Ok(())).unwrap_err();
            assert!(is_stall(&err), "{err}");
        }
        first.join().unwrap_or_default();
        let h = exec.health();
        assert_eq!(h.state, HealthState::Stalled, "{h:?}");
        assert_eq!(h.trips_total, 1);
        assert!(h.timeouts_total >= 1);

        // Normal and deferred commands are refused at once while it is open.
        let t = Instant::now();
        let ran = Arc::new(AtomicBool::new(false));
        let r = ran.clone();
        let err = exec
            .run("normal", Class::Other, move || {
                r.store(true, Ordering::SeqCst);
                Ok(())
            })
            .unwrap_err();
        assert!(is_stall(&err), "{err}");
        assert!(
            t.elapsed() < Duration::from_millis(50),
            "refused without waiting"
        );
        assert!(!ran.load(Ordering::SeqCst));
        let t = Instant::now();
        let err = {
            let _d = deferred();
            exec.run("deferred", Class::Other, || Ok(())).unwrap_err()
        };
        assert!(
            is_stall(&err) && t.elapsed() < Duration::from_millis(50),
            "{err}"
        );
        assert!(exec.health().refused_total >= 2);

        // The chip answers again: the stuck command returns, and with it the
        // breaker closes and every class is served, with no restart.
        release.send(()).unwrap();
        let until = Instant::now() + Duration::from_secs(2);
        while exec.health().state != HealthState::Healthy && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(5));
        }
        let h = exec.health();
        assert_eq!(h.state, HealthState::Healthy, "{h:?}");
        assert_eq!(h.recoveries_total, 1);
        assert_eq!(exec.run("after", Class::Other, || Ok(5)).unwrap(), 5);
    }

    #[test]
    fn a_consensus_command_waits_out_a_stall_that_refuses_the_rest() {
        let exec = Arc::new(Executor::new(stall_limits()));
        let (release, first) = stall(&exec, "stuck");
        std::thread::sleep(Duration::from_millis(20));
        for _ in 0..3 {
            assert!(exec.run("n", Class::Other, || Ok(())).is_err());
        }
        assert_eq!(exec.health().state, HealthState::Stalled);
        let vote = {
            let exec = exec.clone();
            std::thread::spawn(move || {
                let _g = high_priority();
                exec.run("vote", Class::Other, || Ok(1))
            })
        };
        std::thread::sleep(Duration::from_millis(300));
        // Past the normal deadline and still waiting, not refused.
        assert!(!vote.is_finished(), "the vote keeps waiting for the chip");
        release.send(()).unwrap();
        assert_eq!(vote.join().unwrap().unwrap(), 1);
        first.join().unwrap_or_default();
    }

    #[test]
    fn the_consensus_budget_is_longer_than_the_normal_one() {
        let exec = Executor::new(stall_limits());
        let slow = || {
            std::thread::sleep(Duration::from_millis(300));
            Ok(())
        };
        assert!(exec.run("normal", Class::Other, slow).is_err());
        std::thread::sleep(Duration::from_millis(300));
        let _g = high_priority();
        assert!(exec.run("vote", Class::Other, slow).is_ok());
    }

    #[test]
    fn deferred_commands_run_after_normal_ones() {
        let exec = Arc::new(Executor::new(limits(5_000)));
        let order = Arc::new(Mutex::new(Vec::<&'static str>::new()));
        let (started_tx, started) = mpsc::channel::<()>();
        let (release_tx, release) = mpsc::channel::<()>();
        let blocker = {
            let exec = exec.clone();
            std::thread::spawn(move || {
                exec.run("block", Class::Other, move || {
                    started_tx.send(()).unwrap();
                    release.recv().unwrap();
                    Ok(())
                })
                .unwrap();
            })
        };
        started.recv().unwrap();
        let spawn = |name: &'static str, defer: bool| {
            let (exec, order) = (exec.clone(), order.clone());
            std::thread::spawn(move || {
                let _g = defer.then(deferred);
                exec.run(name, Class::Other, move || {
                    lock(&order).push(name);
                    Ok(())
                })
                .unwrap();
            })
        };
        let d = spawn("deferred", true);
        std::thread::sleep(Duration::from_millis(100));
        let n = spawn("normal", false);
        std::thread::sleep(Duration::from_millis(100));
        release_tx.send(()).unwrap();
        for t in [blocker, d, n] {
            t.join().unwrap();
        }
        assert_eq!(*lock(&order), vec!["normal", "deferred"]);
    }

    #[test]
    fn the_breaker_probes_once_after_a_pause_and_backs_off_when_the_probe_fails() {
        let l = stall_limits();
        let mut b = Breaker::new();
        let t0 = Instant::now();
        assert!(b.timed_out(t0, &l).is_none() && b.timed_out(t0, &l).is_none());
        let said = b.timed_out(t0, &l).expect("the stall is said once");
        assert!(said.contains("TPM stalled"), "{said}");
        assert!(b.admit(t0, &l).is_err(), "refused while open");
        let first_pause = match b.gate {
            Gate::Open { until } => until - t0,
            _ => panic!("open"),
        };
        let t1 = t0 + Duration::from_millis(200);
        assert_eq!(b.admit(t1, &l), Ok(true), "one probe after the pause");
        assert!(b.admit(t1, &l).is_err(), "only one probe at a time");
        // The probe fails: open again, with a longer pause, and no new line.
        assert!(
            b.timed_out(t1, &l).is_none(),
            "a stall already said is not said again"
        );
        let second_pause = match b.gate {
            Gate::Open { until } => until - t1,
            _ => panic!("open"),
        };
        assert!(
            second_pause > first_pause.mul_f64(1.2),
            "{first_pause:?} {second_pause:?}"
        );
        // A probe that succeeds closes it and says so once.
        let t2 = t1 + Duration::from_secs(1);
        assert_eq!(b.admit(t2, &l), Ok(true));
        let said = b
            .answered(t2, Duration::from_millis(5))
            .expect("recovery said");
        assert!(said.contains("answering again"), "{said}");
        assert!(b.answered(t2, Duration::from_millis(5)).is_none());
        assert_eq!(b.admit(t2, &l), Ok(false));
    }

    #[test]
    fn the_backoff_doubles_is_capped_and_is_spread_by_jitter() {
        let (base, cap) = (Duration::from_secs(1), Duration::from_secs(20));
        assert_eq!(backoff(base, cap, 1, 0.5), Duration::from_secs(1));
        assert_eq!(backoff(base, cap, 3, 0.5), Duration::from_secs(4));
        assert_eq!(backoff(base, cap, 30, 0.5), cap);
        assert_eq!(backoff(base, cap, 2, 0.0), Duration::from_millis(1_500));
        assert_eq!(backoff(base, cap, 2, 1.0), Duration::from_millis(2_500));
        assert!(backoff(base, cap, 30, 1.0) <= Duration::from_secs(25));
        let a: Vec<f64> = (0..8).map(|_| jitter_unit()).collect();
        assert!(a.iter().all(|u| (0.0..1.0).contains(u)));
        assert!(a.windows(2).any(|w| w[0] != w[1]));
    }

    #[test]
    fn a_stall_is_told_apart_from_a_lost_key() {
        assert!(is_stall(&DeviceKeyError::Tpm(
            "sign: the TPM did not answer within 10s".into()
        )));
        assert!(is_stall(&DeviceKeyError::Tpm(
            "x: TPM stalled; refusing".into()
        )));
        assert!(!is_stall(&DeviceKeyError::Tpm("TPM_RC_HANDLE".into())));
    }

    #[test]
    fn a_retry_gate_refuses_attempts_inside_the_pause_and_starts_over_on_success() {
        let mut g = RetryGate::new(Duration::from_millis(100), Duration::from_secs(1));
        let t = Instant::now();
        assert!(g.check(t).is_ok());
        let first = g.failed(t);
        assert!(g.check(t).is_err());
        assert!(g.check(t + first + Duration::from_millis(1)).is_ok());
        let second = g.failed(t);
        assert!(second > first.mul_f64(1.2), "{first:?} {second:?}");
        assert_eq!(g.failures(), 2);
        g.succeeded();
        assert!(g.check(t).is_ok());
        assert_eq!(g.failures(), 0);
    }
}
