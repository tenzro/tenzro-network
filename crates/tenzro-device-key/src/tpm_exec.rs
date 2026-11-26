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
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

use crate::{DeviceKeyError, Result};

/// The executor itself: queues, rate limits, circuit breaker and the TPM
/// thread. Built only where a TPM backend exists; elsewhere the load level,
/// the priority guards and the health report of this module still work, and
/// nothing ever runs a TPM command.
#[cfg(any(target_os = "linux", windows, test))]
mod engine;
#[cfg(any(target_os = "linux", windows, test))]
pub(crate) use engine::{Class, global};

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

/// How this process's TPM is answering. A process that never sent a TPM
/// command reports a healthy, idle chip.
pub fn health() -> Health {
    #[cfg(any(target_os = "linux", windows, test))]
    if let Some(e) = engine::EXEC.get() {
        return e.health();
    }
    Health::idle()
}

/// Most consensus-priority commands waiting at once.
pub const HIGH_QUEUE_CAP: usize = 1024;

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

/// How long a deferred command may wait behind others before it is served
/// first.
pub const DEFERRED_AGING: Duration = Duration::from_secs(10);

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
