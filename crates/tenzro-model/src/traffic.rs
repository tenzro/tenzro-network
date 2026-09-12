//! Node-level traffic admission: deciding what to run, what to queue, and
//! what to refuse.
//!
//! # Why per-model limits are not enough
//!
//! The batching engine already bounds each model: a fixed slot pool, and
//! [`MAX_INFLIGHT_PER_MODEL`](crate::runtime) requests before it sheds. That
//! protects a model from its own traffic. It does nothing about the machine.
//!
//! Eight models each sitting at their own limit is eight times the intended
//! load on one CPU, one memory bus, one GPU. Nobody exceeded a limit; the box
//! died anyway. The missing bound is the one nothing owned: total concurrent
//! work across every model and every modality.
//!
//! # What the literature says to do
//!
//! Serving stacks optimise for throughput, and under overload that is exactly
//! wrong: greedy admission inflates queueing delay until *every* request
//! misses its deadline. Nothing completes usefully, but the throughput graph
//! looks busy. The corrective, consistent across the 2024–2026 SLO-serving
//! work (QLM, SLOs-Serve, SCORPIO), is:
//!
//! - **Put the SLO on the wait, not the answer.** Queue-wait and time to
//!   first token are the deadlines; total generation is the caller's choice.
//!   Predict when a slot frees, from what is running and a cost model that
//!   prices prefill and decode separately; hold the caller while that ETA is
//!   inside its budget, refuse only when it is not. (This module once
//!   predicted end-to-end time against a fixed 30 s and refused nearly every
//!   real coding turn on a 30 tok/s decoder; see
//!   `praecise_runtime::admission`, which now owns the model.)
//! - **Order by deadline, not arrival.** Least-deadline-first, because FIFO
//!   under load makes the tightest deadlines wait behind the loosest.
//! - **Separate the classes.** Interactive and batch traffic in one queue is
//!   an overload amplifier: a batch embedding job of 10,000 rows should never
//!   sit in front of a chat turn.
//! - **Prefer soft refusal.** Delay, demote, or reroute before hard-rejecting.
//! - **Measure goodput.** Requests completed *within SLO*, not requests
//!   completed. Shedding lowers throughput and raises goodput, so a
//!   throughput dashboard reads correct shedding as a regression.
//!
//! # Goodput is the number that matters
//!
//! [`TrafficStats::goodput_pct`] is the headline. If it falls while
//! throughput holds, the node is accepting work it cannot finish on time —
//! the failure mode this module exists to prevent, and the one that is
//! invisible on a throughput chart.
//!
//! # Relationship to the other two bounds
//!
//! Three separate limits, three separate questions:
//!
//! | Module | Question |
//! |---|---|
//! | [`memory_budget`](crate::memory_budget) | Does this model *fit*? |
//! | [`lifecycle`](crate::lifecycle) | Is this model *loaded*? |
//! | this module | Can we *finish this request in time*? |
//!
//! A request can pass all three, or fail any one. They are not substitutes.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use praecise_runtime::{AdmissionClass, AdmissionPolicy, CostModel, Scheduler};
// Re-exported so hosts speak the scheduler's vocabulary without depending
// on the engine crate themselves.
pub use praecise_runtime::{AdmissionDecision, AdmissionRefusal, Shape};
use serde::{Deserialize, Serialize};

/// Latency expectation attached to a request.
///
/// The split is about deadline tightness, not about which model runs. A
/// chat turn and a single embedding are both interactive; a 10,000-row
/// embedding job and an overnight batch summarisation are both batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum QosClass {
    /// A human or agent is waiting. Tight deadline, small share of capacity
    /// reserved so a batch flood cannot starve it.
    Interactive,
    /// Throughput work with a loose deadline. Yields to interactive traffic
    /// and is the first to be shed.
    Batch,
}

impl QosClass {
    /// Default *queue-wait* budget for this class: how long a caller will
    /// sit before its first token, not how long the answer may take.
    ///
    /// Interactive is 30s: past that a caller has usually given up, so
    /// admitting the work spends capacity on a result nobody will read.
    /// Batch is 10 minutes. Neither bounds generation length — a caller that
    /// asked for 4,096 tokens has asked for a long answer, and refusing it
    /// because thirty is a round number protects no one. That mistake, and
    /// what it did to a 30 tok/s decoder, is written up in
    /// `praecise_runtime::admission`.
    pub fn default_deadline(self) -> Duration {
        AdmissionPolicy::default().wait_budget(self.into())
    }
}

impl From<QosClass> for AdmissionClass {
    fn from(c: QosClass) -> Self {
        match c {
            QosClass::Interactive => AdmissionClass::Interactive,
            QosClass::Batch => AdmissionClass::Batch,
        }
    }
}

/// Why a request was not admitted.
///
/// Every variant is retryable and carries a hint, because a client that
/// cannot tell "retry shortly" from "never going to work" will either hammer
/// the node or give up on work that would have succeeded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "kebab-case")]
pub enum Refusal {
    /// The node is at its concurrency ceiling.
    AtCapacity {
        /// Concurrent requests in flight right now.
        in_flight: u32,
        /// The ceiling that was hit.
        limit: u32,
        /// When to come back.
        retry_after_ms: u64,
    },
    /// Every slot for this model is busy and none is predicted to free
    /// within what this class will wait. The caller would have sat past its
    /// own patience, so it is told now — with the ETA, so it can decide
    /// whether to come back or go elsewhere.
    QueueWaitTooLong {
        /// Predicted milliseconds until a slot frees for this request.
        eta_ms: u64,
        /// The wait this class tolerates.
        budget_ms: u64,
        /// When to come back.
        retry_after_ms: u64,
    },
    /// The per-model queue is at its depth limit. Nothing about this request
    /// is wrong; there are simply too many ahead of it.
    QueueFull {
        /// Callers already waiting.
        depth: u32,
        /// The depth limit.
        limit: u32,
        /// When to come back.
        retry_after_ms: u64,
    },
    /// Batch work shed to protect interactive traffic. Interactive requests
    /// are never refused for this reason.
    ShedForInteractive {
        /// When to come back.
        retry_after_ms: u64,
    },
}

impl Refusal {
    /// Milliseconds a client should wait before retrying.
    pub fn retry_after_ms(&self) -> u64 {
        match self {
            Self::AtCapacity { retry_after_ms, .. }
            | Self::QueueWaitTooLong { retry_after_ms, .. }
            | Self::QueueFull { retry_after_ms, .. }
            | Self::ShedForInteractive { retry_after_ms } => *retry_after_ms,
        }
    }

    /// Seconds for a `Retry-After` header. Never rounds down to zero, which
    /// would produce a hot retry loop precisely when the node is busiest.
    pub fn retry_after_secs(&self) -> u64 {
        self.retry_after_ms().div_ceil(1000).max(1)
    }

    /// Operator-facing explanation.
    pub fn message(&self) -> String {
        match self {
            Self::AtCapacity {
                in_flight, limit, ..
            } => format!("node at capacity: {in_flight} of {limit} concurrent requests in flight"),
            Self::QueueWaitTooLong {
                eta_ms, budget_ms, ..
            } => format!(
                "every slot is busy and the next is predicted to free in {eta_ms} ms, past the \
                 {budget_ms} ms this class will wait; generation length is not the limit"
            ),
            Self::QueueFull { depth, limit, .. } => {
                format!("queue full: {depth} of {limit} callers already waiting for this model")
            }
            Self::ShedForInteractive { .. } => {
                "batch work shed to protect interactive capacity".to_string()
            }
        }
    }
}

/// Configuration for the admission layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficConfig {
    /// Hard ceiling on concurrent requests across every model and modality.
    ///
    /// This is the bound nothing else owns. Sized against cores rather than
    /// models: the work is CPU/GPU-bound and models share one machine.
    pub max_concurrent: u32,
    /// Of `max_concurrent`, how many slots batch traffic may occupy.
    ///
    /// The remainder is reserved for interactive traffic and cannot be taken
    /// by batch at any load. Without this reservation a large batch job
    /// starves interactive callers for as long as it runs.
    pub max_concurrent_batch: u32,
    /// Requests may queue this deep before admission starts refusing.
    pub max_queue_depth: u32,
    /// Slots that must remain available to unleased traffic no matter how
    /// much capacity is sold to leases.
    ///
    /// Without a floor an operator can sell every slot and the node becomes
    /// unreachable to everyone else — including the public traffic that
    /// network discovery routes to it. Reservations are refused once they
    /// would eat into this.
    pub public_floor: u32,
}

impl TrafficConfig {
    /// Derive a configuration from the machine's core count.
    ///
    /// Two concurrent requests per core: inference alternates between
    /// compute and memory stalls, so a little oversubscription raises
    /// utilisation, while more than that just deepens queues without
    /// finishing anything sooner. Batch gets half, leaving half of the
    /// machine always available to interactive traffic.
    pub fn for_cores(cores: u32) -> Self {
        let max_concurrent = (cores * 2).max(4);
        Self {
            max_concurrent,
            max_concurrent_batch: (max_concurrent / 2).max(1),
            max_queue_depth: max_concurrent * 4,
            // A quarter of the node stays public. An operator can sell the
            // rest, but a node that has sold everything is invisible to the
            // network that routes work to it.
            public_floor: (max_concurrent / 4).max(1),
        }
    }
}

impl Default for TrafficConfig {
    fn default() -> Self {
        Self::for_cores(
            std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(4),
        )
    }
}

/// Why a capacity reservation could not be granted.
///
/// Both variants mean "do not open this lease". Selling capacity the node
/// does not have degrades every existing lease silently, which is worse than
/// declining the sale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "kebab-case")]
pub enum ReservationError {
    /// Granting this would leave less than [`TrafficConfig::public_floor`]
    /// for unleased traffic.
    WouldBreachPublicFloor {
        /// Slots asked for.
        requested: u32,
        /// Slots that could still be granted.
        grantable: u32,
        /// The floor being defended.
        public_floor: u32,
    },
    /// A reservation already exists under this lease id.
    AlreadyReserved {
        /// The lease in question.
        lease_id: String,
        /// What it already holds.
        existing_slots: u32,
    },
}

impl fmt::Display for ReservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WouldBreachPublicFloor {
                requested,
                grantable,
                public_floor,
            } => write!(
                f,
                "cannot reserve {requested} slots: only {grantable} are sellable while keeping \
                 {public_floor} for public traffic"
            ),
            Self::AlreadyReserved {
                lease_id,
                existing_slots,
            } => write!(
                f,
                "lease {lease_id} already holds {existing_slots} reserved slots; revoke it before \
                 reserving again"
            ),
        }
    }
}

impl std::error::Error for ReservationError {}

/// A lease's guaranteed share of the node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reservation {
    /// The lease this belongs to.
    pub lease_id: String,
    /// Concurrent requests guaranteed to it.
    pub slots: u32,
    /// How many of those are in use right now.
    pub in_use: u32,
}

/// Milliseconds on a process-local monotonic clock, for the praecise scheduler.
/// It wants a plain number so its arithmetic stays deterministic under test;
/// the epoch is whenever this is first called.
fn now_ms() -> u64 {
    static EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    EPOCH.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Holds a concurrency slot for the life of a request.
///
/// Releases on drop, so a panicking or early-returning handler cannot leak a
/// slot. A leaked slot is permanent: the node's effective capacity would drop
/// by one every time a request failed, until it admitted nothing at all.
#[derive(Debug)]
pub struct RequestGuard {
    model_id: String,
    class: QosClass,
    /// The praecise scheduler's ticket for this request, so its slot and its
    /// cost sample are released against the right entry.
    ticket: u64,
    /// What the request actually produced, when the handler reported it via
    /// [`RequestGuard::record`]. Zero teaches the cost model nothing — a
    /// request that never generated is a refusal, not a sample.
    generated_tokens: u64,
    /// Time to first token, when the handler measured it. This is what lets
    /// the cost model separate prefill from decode.
    first_token_ms: Option<u64>,
    /// Set when the request never actually ran, so its slot is returned
    /// without being recorded as a completion.
    aborted: bool,
    /// Set when this request drew on a lease's reserved capacity, so the
    /// slot returns to that lease rather than to the public pool.
    lease_id: Option<String>,
    started: Instant,
    deadline: Duration,
    inner: Arc<TrafficInner>,
}

impl RequestGuard {
    /// Give the slot back without recording a completion.
    ///
    /// For a request admitted here but then refused by a bound further down
    /// — a per-model capacity cap, say. Counting it as completed and on-time
    /// would make [`TrafficStats::goodput_pct`] report success for work that
    /// never ran, which is precisely the metric failure this module exists to
    /// prevent.
    pub fn abort(mut self) {
        self.aborted = true;
    }

    /// Report what the request produced, so the cost model learns from real
    /// output rather than from the `max_tokens` it was admitted against.
    ///
    /// Call once the result (or the end of the stream) is known. A guard
    /// dropped without this frees its slot and records nothing — better no
    /// sample than one that prices a 1,000-token answer as a 20-token prompt,
    /// which is the mistake that had this node refusing 200-token requests.
    pub fn record(&mut self, generated_tokens: u64, first_token_ms: Option<u64>) {
        self.generated_tokens = generated_tokens;
        self.first_token_ms = first_token_ms;
    }

    /// The model this request is running against.
    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    /// Which class it was admitted under.
    pub fn class(&self) -> QosClass {
        self.class
    }

    /// How long it has been running.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

impl Drop for RequestGuard {
    fn drop(&mut self) {
        if self.aborted {
            self.inner.release_aborted(
                &self.model_id,
                self.class,
                self.lease_id.as_deref(),
                self.ticket,
            );
            return;
        }
        self.inner.release(
            &self.model_id,
            self.class,
            self.lease_id.as_deref(),
            self.ticket,
            self.generated_tokens,
            self.first_token_ms,
            self.deadline,
        );
    }
}

#[derive(Debug, Default)]
struct Counters {
    admitted: AtomicU64,
    refused: AtomicU64,
    completed: AtomicU64,
    /// Completed *within* their deadline. The numerator of goodput.
    on_time: AtomicU64,
}

#[derive(Debug)]
struct TrafficInner {
    config: TrafficConfig,
    state: Mutex<TrafficState>,
    counters: Counters,
}

#[derive(Debug, Default)]
struct TrafficState {
    in_flight_interactive: u32,
    in_flight_batch: u32,
    /// Per-model scheduler from praecise: the two-term cost model, what is
    /// running on that model and how many callers are waiting for it. Slot
    /// count is whatever the caller last declared (the per-model serving
    /// capacity), defaulting to one until it does.
    scheds: HashMap<String, Scheduler>,
    /// Guaranteed capacity sold to leases, by lease id.
    reservations: HashMap<String, Reservation>,
}

impl TrafficState {
    fn sched(&mut self, model_id: &str) -> &mut Scheduler {
        self.scheds
            .entry(model_id.to_string())
            .or_insert_with(|| Scheduler::new(1, AdmissionPolicy::default()))
    }

    fn total_in_flight(&self) -> u32 {
        self.in_flight_interactive + self.in_flight_batch
    }

    /// Slots promised to leases, whether or not they are being used.
    fn total_reserved(&self) -> u32 {
        self.reservations.values().map(|r| r.slots).sum()
    }

    /// Reserved slots standing idle.
    ///
    /// These are the cost of the guarantee. Lending them to public traffic
    /// would mean a lease holder arriving to find its own capacity occupied
    /// by a request that cannot be preempted — which is exactly the promise
    /// the lease was sold on.
    fn reserved_idle(&self) -> u32 {
        self.reservations
            .values()
            .map(|r| r.slots.saturating_sub(r.in_use))
            .sum()
    }

    /// Ceiling on concurrent unleased requests.
    ///
    /// Public traffic may use everything except the slots standing ready for
    /// lease holders. It is bounded by idle reserved capacity rather than by
    /// total reserved, so a lease that is not using its share does not shrink
    /// the node twice.
    fn public_ceiling(&self, max_concurrent: u32) -> u32 {
        max_concurrent.saturating_sub(self.reserved_idle())
    }
}

impl TrafficInner {
    /// Return a slot for a request that never ran.
    ///
    /// Frees the concurrency and the lease charge, and feeds nothing into the
    /// cost model or the goodput counters — an aborted request carries no
    /// information about how long the model takes, and counting it would
    /// corrupt both.
    fn release_aborted(&self, model_id: &str, class: QosClass, lease_id: Option<&str>, ticket: u64) {
        // A request that never ran was never really admitted. Undo the admit
        // and record the refusal, so `admitted - completed` stays a real
        // measure of work in flight rather than drifting by one per abort.
        self.counters.admitted.fetch_sub(1, Ordering::Relaxed);
        self.counters.refused.fetch_add(1, Ordering::Relaxed);

        let mut state = self.state.lock();
        // Zero generated tokens: frees the scheduler slot, teaches nothing.
        state.sched(model_id).finish(ticket, 0, None, now_ms());
        if let Some(id) = lease_id
            && let Some(r) = state.reservations.get_mut(id)
        {
            r.in_use = r.in_use.saturating_sub(1);
        }
        match class {
            QosClass::Interactive => {
                state.in_flight_interactive = state.in_flight_interactive.saturating_sub(1);
            }
            QosClass::Batch => {
                state.in_flight_batch = state.in_flight_batch.saturating_sub(1);
            }
        }
    }

    fn release(
        &self,
        model_id: &str,
        class: QosClass,
        lease_id: Option<&str>,
        ticket: u64,
        generated_tokens: u64,
        first_token_ms: Option<u64>,
        deadline: Duration,
    ) {
        {
            let mut state = self.state.lock();
            state
                .sched(model_id)
                .finish(ticket, generated_tokens, first_token_ms, now_ms());
            if let Some(id) = lease_id
                && let Some(r) = state.reservations.get_mut(id)
            {
                r.in_use = r.in_use.saturating_sub(1);
            }
            match class {
                QosClass::Interactive => {
                    state.in_flight_interactive = state.in_flight_interactive.saturating_sub(1);
                }
                QosClass::Batch => {
                    state.in_flight_batch = state.in_flight_batch.saturating_sub(1);
                }
            }
        }
        self.counters.completed.fetch_add(1, Ordering::Relaxed);
        // On time means the caller got its first token inside the wait budget
        // it was admitted under. The answer's total length is the caller's
        // choice, not a service failure — so it is not what goodput measures.
        // A handler that did not measure TTFT is counted on time: it was
        // admitted within budget, which is all this layer promised.
        if first_token_ms.is_none_or(|t| t <= deadline.as_millis() as u64) {
            self.counters.on_time.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Observable state of the admission layer.
///
/// Not `Eq`: `goodput_pct` is a ratio, and exact float equality is not a
/// meaningful comparison on it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TrafficStats {
    /// Concurrent interactive requests.
    pub in_flight_interactive: u32,
    /// Concurrent batch requests.
    pub in_flight_batch: u32,
    /// Global concurrency ceiling.
    pub max_concurrent: u32,
    /// Requests admitted since start.
    pub admitted: u64,
    /// Requests refused since start.
    pub refused: u64,
    /// Requests completed since start.
    pub completed: u64,
    /// Completed within their deadline.
    pub on_time: u64,
    /// Percentage of completed requests that met their deadline.
    ///
    /// **The primary overload signal.** Throughput can hold steady while this
    /// collapses, which is the state where the node is busy producing results
    /// that arrive too late to be useful.
    pub goodput_pct: f64,
    /// Slots sold to leases, whether or not currently in use.
    pub reserved_slots: u32,
    /// Reserved slots standing idle — the cost of the dedicated guarantee.
    pub reserved_idle: u32,
    /// Ceiling on concurrent unleased requests right now.
    pub public_ceiling: u32,
    /// Slots still sellable while keeping the public floor intact.
    pub sellable_slots: u32,
}

/// Node-level admission control.
///
/// Cheap to clone; all clones share one set of counters.
#[derive(Debug, Clone)]
pub struct TrafficManager {
    inner: Arc<TrafficInner>,
}

impl Default for TrafficManager {
    fn default() -> Self {
        Self::new(TrafficConfig::default())
    }
}

impl TrafficManager {
    /// Build a manager with the given limits.
    pub fn new(config: TrafficConfig) -> Self {
        Self {
            inner: Arc::new(TrafficInner {
                config,
                state: Mutex::new(TrafficState::default()),
                counters: Counters::default(),
            }),
        }
    }

    /// Take a slot for a request now.
    ///
    /// `deadline` is how long the caller was willing to wait for its first
    /// token; `None` takes the class default. It is recorded for goodput,
    /// not enforced here — whether to hold the caller or turn it away is
    /// [`TrafficManager::queue_decision`]'s question, asked by the host
    /// before it calls this. `shape` is what the request will cost: prompt
    /// tokens and the output ceiling it was given. The scheduler prices the
    /// slot by it, and by what the request actually produced once the guard
    /// [`records`](RequestGuard::record) that.
    ///
    /// Checks run cheapest-first and most-protective-first: the global
    /// ceiling, then the batch reservation.
    pub fn admit(
        &self,
        model_id: &str,
        class: QosClass,
        deadline: Option<Duration>,
        shape: Shape,
    ) -> Result<RequestGuard, Refusal> {
        self.admit_for_lease(model_id, class, deadline, None, shape)
    }

    /// Ask the per-model scheduler what to do with a request that found the
    /// model busy, without changing anything.
    ///
    /// `Admit` when a slot is free; `Wait { eta, .. }` when one is predicted
    /// to free inside the class's wait budget, in which case the host should
    /// [`enter_queue`](Self::enter_queue), sleep about `eta` (or until
    /// something finishes) and ask again; `Refuse` only when the ETA is past
    /// the budget or the queue is at depth. This is the queue that used to be
    /// thrown away: the batching engine underneath already holds requests
    /// until a slot frees, and refusing above it with a `retry_after` the
    /// caller could not act on discarded that.
    pub fn queue_decision(&self, model_id: &str, class: QosClass, shape: Shape) -> AdmissionDecision {
        let mut state = self.inner.state.lock();
        state.sched(model_id).decide(class.into(), shape, now_ms())
    }

    /// Record that a caller is now waiting for this model. Its presence
    /// lengthens the ETA quoted to callers behind it.
    pub fn enter_queue(&self, model_id: &str) {
        self.inner.state.lock().sched(model_id).enqueue();
    }

    /// The caller has stopped waiting — admitted, refused or gone.
    pub fn leave_queue(&self, model_id: &str) {
        self.inner.state.lock().sched(model_id).dequeue();
    }

    /// Declare how many requests the model can decode at once — the batching
    /// engine's slot count. The scheduler uses it to tell "a slot is free"
    /// from "hold on": until declared it assumes one.
    pub fn declare_capacity(&self, model_id: &str, slots: u32) {
        self.inner.state.lock().sched(model_id).set_slots(slots.max(1));
    }

    /// Translate a scheduler refusal into this layer's vocabulary, counting
    /// it. For hosts that got `Refuse` from [`queue_decision`](Self::queue_decision).
    pub fn refuse_from_queue(&self, r: AdmissionRefusal) -> Refusal {
        self.refuse(match r {
            AdmissionRefusal::QueueFull { depth, limit, retry_after_ms } => Refusal::QueueFull {
                depth,
                limit,
                retry_after_ms: retry_after_ms.max(1_000),
            },
            AdmissionRefusal::WaitTooLong { eta_ms, budget_ms } => Refusal::QueueWaitTooLong {
                eta_ms,
                budget_ms,
                // Come back once the predicted wait has passed, not instantly.
                retry_after_ms: eta_ms.saturating_sub(budget_ms).max(1_000),
            },
        })
    }

    /// Admit a request, drawing on a lease's guaranteed capacity when one is
    /// named.
    ///
    /// A lease holder draws from its own reservation first and falls back to
    /// the public pool once that is spent — so a renter is never worse off
    /// than an unleased caller, and gets slots nobody else can take.
    ///
    /// Unleased traffic is bounded by [`TrafficState::public_ceiling`], which
    /// excludes reserved-but-idle slots. That idle capacity is the cost of
    /// the guarantee: lending it out would mean a lease holder arriving to
    /// find its own slots occupied by a request that cannot be preempted,
    /// which is exactly what the lease was sold against.
    pub fn admit_for_lease(
        &self,
        model_id: &str,
        class: QosClass,
        deadline: Option<Duration>,
        lease_id: Option<&str>,
        shape: Shape,
    ) -> Result<RequestGuard, Refusal> {
        let deadline = deadline.unwrap_or_else(|| class.default_deadline());
        let mut state = self.inner.state.lock();
        let cfg = &self.inner.config;

        // Does this caller hold reserved capacity that is still free?
        let drew_on_lease = lease_id
            .and_then(|id| state.reservations.get(id))
            .is_some_and(|r| r.in_use < r.slots);

        // 1. Global ceiling. The bound that per-model limits cannot express.
        //    A lease drawing on its own reservation is exempt: those slots
        //    were set aside for it and counting them against the public
        //    ceiling would deny a renter the capacity they paid for.
        if !drew_on_lease && state.total_in_flight() >= state.public_ceiling(cfg.max_concurrent) {
            let limit = state.public_ceiling(cfg.max_concurrent);
            let in_flight = state.total_in_flight();
            drop(state);
            return Err(self.refuse(Refusal::AtCapacity {
                in_flight,
                limit,
                retry_after_ms: 1_000,
            }));
        }

        // 2. Batch reservation. Interactive traffic is never shed here — the
        //    whole point of the reservation is that batch load cannot starve
        //    a waiting human.
        if !drew_on_lease
            && class == QosClass::Batch
            && state.in_flight_batch >= cfg.max_concurrent_batch
        {
            drop(state);
            return Err(self.refuse(Refusal::ShedForInteractive {
                retry_after_ms: 5_000,
            }));
        }

        // 3. There is no deadline prediction here any more. Predicting
        //    end-to-end time against a fixed deadline, from a cost model that
        //    had never seen an output length, refused nearly every real
        //    coding turn on a 30 tok/s decoder and got worse the longer it
        //    ran. The scheduler below prices prefill and decode separately,
        //    the SLO is on queue wait, and a busy model answers with an ETA
        //    through `queue_decision` before this is ever called. Here, a
        //    slot is a slot: taking one is unconditional.
        let ticket = state.sched(model_id).start(shape, now_ms());

        match class {
            QosClass::Interactive => state.in_flight_interactive += 1,
            QosClass::Batch => state.in_flight_batch += 1,
        }
        let charged_lease = if drew_on_lease {
            let id = lease_id.expect("drew_on_lease implies a lease id");
            if let Some(r) = state.reservations.get_mut(id) {
                r.in_use += 1;
            }
            Some(id.to_string())
        } else {
            None
        };
        drop(state);
        self.inner.counters.admitted.fetch_add(1, Ordering::Relaxed);

        Ok(RequestGuard {
            model_id: model_id.to_string(),
            class,
            ticket,
            generated_tokens: 0,
            first_token_ms: None,
            aborted: false,
            lease_id: charged_lease,
            started: Instant::now(),
            deadline,
            inner: Arc::clone(&self.inner),
        })
    }

    fn refuse(&self, r: Refusal) -> Refusal {
        self.inner.counters.refused.fetch_add(1, Ordering::Relaxed);
        r
    }

    /// Sell `slots` of guaranteed concurrency to a lease.
    ///
    /// Fails rather than overselling. A lease opened against capacity the
    /// node does not have degrades every existing lease silently, which is a
    /// worse outcome than declining the sale — so this is the check that
    /// belongs at lease-open time, not at first request.
    pub fn reserve_for_lease(
        &self,
        lease_id: &str,
        slots: u32,
    ) -> Result<Reservation, ReservationError> {
        let mut state = self.inner.state.lock();

        if let Some(existing) = state.reservations.get(lease_id) {
            return Err(ReservationError::AlreadyReserved {
                lease_id: lease_id.to_string(),
                existing_slots: existing.slots,
            });
        }

        let floor = self.inner.config.public_floor;
        let grantable = self
            .inner
            .config
            .max_concurrent
            .saturating_sub(state.total_reserved())
            .saturating_sub(floor);

        if slots > grantable {
            return Err(ReservationError::WouldBreachPublicFloor {
                requested: slots,
                grantable,
                public_floor: floor,
            });
        }

        let reservation = Reservation {
            lease_id: lease_id.to_string(),
            slots,
            in_use: 0,
        };
        state
            .reservations
            .insert(lease_id.to_string(), reservation.clone());
        Ok(reservation)
    }

    /// Return a lease's capacity to the public pool.
    ///
    /// In-flight requests already charged to the lease keep running — a
    /// revocation must not tear down work mid-generation. Their slots return
    /// to the public pool as they finish, because [`RequestGuard`]'s release
    /// tolerates a reservation that has since been dropped.
    pub fn release_lease(&self, lease_id: &str) -> Option<Reservation> {
        self.inner.state.lock().reservations.remove(lease_id)
    }

    /// Every live reservation.
    pub fn reservations(&self) -> Vec<Reservation> {
        let state = self.inner.state.lock();
        let mut out: Vec<Reservation> = state.reservations.values().cloned().collect();
        out.sort_by(|a, b| a.lease_id.cmp(&b.lease_id));
        out
    }

    /// Slots that could still be sold while keeping the public floor intact.
    ///
    /// The number an operator needs before quoting a lease.
    pub fn sellable_slots(&self) -> u32 {
        let state = self.inner.state.lock();
        self.inner
            .config
            .max_concurrent
            .saturating_sub(state.total_reserved())
            .saturating_sub(self.inner.config.public_floor)
    }

    /// Seed the cost model from a model's measured rates, so the first
    /// callers are quoted a real ETA rather than the default's.
    ///
    /// `prefill_tok_per_s` and `decode_tok_per_s` are solo-request figures
    /// (the numbers a benchmark reports at concurrency one); the scheduler
    /// scales decode by concurrency itself.
    pub fn declare_rates(&self, model_id: &str, prefill_tok_per_s: u64, decode_tok_per_s: u64) {
        self.inner
            .state
            .lock()
            .sched(model_id)
            .set_cost(CostModel::from_rates(prefill_tok_per_s.max(1), decode_tok_per_s.max(1)));
    }

    /// Seed the cost model from the expected time of a nominal request: one
    /// thousand tokens of output on a short prompt. Kept for operators who
    /// think in "about ten seconds a turn"; [`declare_rates`](Self::declare_rates)
    /// is the precise form.
    pub fn declare_expected_cost(&self, model_id: &str, expected: Duration) {
        let ms = (expected.as_millis() as u64).max(1);
        // 1,000 output tokens in `expected`; prefill stays at the default.
        let decode_tok_per_s = (1_000_000 / ms).max(1);
        self.declare_rates(
            model_id,
            1_000_000 / CostModel::DEFAULT_PREFILL_US_PER_TOK,
            decode_tok_per_s,
        );
    }

    /// What the scheduler currently believes about a model's speed, for
    /// status endpoints and tests.
    pub fn rates(&self, model_id: &str) -> (u64, u64) {
        let mut state = self.inner.state.lock();
        let c = state.sched(model_id).cost();
        (c.prefill_tok_per_s(), c.decode_tok_per_s())
    }

    /// Current admission state.
    pub fn stats(&self) -> TrafficStats {
        let state = self.inner.state.lock();
        let c = &self.inner.counters;
        let completed = c.completed.load(Ordering::Relaxed);
        let on_time = c.on_time.load(Ordering::Relaxed);
        TrafficStats {
            in_flight_interactive: state.in_flight_interactive,
            in_flight_batch: state.in_flight_batch,
            max_concurrent: self.inner.config.max_concurrent,
            admitted: c.admitted.load(Ordering::Relaxed),
            refused: c.refused.load(Ordering::Relaxed),
            completed,
            on_time,
            goodput_pct: if completed == 0 {
                100.0
            } else {
                (on_time as f64 / completed as f64) * 100.0
            },
            reserved_slots: state.total_reserved(),
            reserved_idle: state.reserved_idle(),
            public_ceiling: state.public_ceiling(self.inner.config.max_concurrent),
            sellable_slots: self
                .inner
                .config
                .max_concurrent
                .saturating_sub(state.total_reserved())
                .saturating_sub(self.inner.config.public_floor),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(max: u32, batch: u32) -> TrafficConfig {
        TrafficConfig {
            max_concurrent: max,
            max_concurrent_batch: batch,
            max_queue_depth: 64,
            // Most tests predate reservations and assert on the full pool, so
            // the default here keeps everything sellable-agnostic.
            public_floor: 0,
        }
    }

    /// A config with a public floor, for the reservation tests.
    fn leased_cfg(max: u32, batch: u32, floor: u32) -> TrafficConfig {
        TrafficConfig {
            max_concurrent: max,
            max_concurrent_batch: batch,
            max_queue_depth: 64,
            public_floor: floor,
        }
    }

    /// A nominal request shape for tests that do not care about cost.
    fn sh() -> Shape {
        Shape::new(1_000, 256)
    }

    #[test]
    fn a_lease_holder_gets_capacity_public_traffic_cannot_take() {
        // The whole point of #55: before this, a renter paying for dedicated
        // access competed in the same pool as free traffic.
        let tm = TrafficManager::new(leased_cfg(8, 4, 2));
        tm.reserve_for_lease("lease-a", 4)
            .expect("4 of 8 with a floor of 2");

        // Public traffic fills everything it is allowed to reach. The four
        // reserved-and-idle slots are not available to it.
        let mut public = Vec::new();
        while let Ok(g) = tm.admit("m", QosClass::Interactive, None, sh()) {
            public.push(g);
        }
        assert_eq!(public.len(), 4, "public is capped at 8 - 4 reserved-idle");

        // The lease holder still gets every slot it paid for.
        let mut leased = Vec::new();
        for _ in 0..4 {
            leased.push(
                tm.admit_for_lease("m", QosClass::Interactive, None, Some("lease-a"), sh())
                    .expect("reserved capacity is guaranteed"),
            );
        }
        assert_eq!(leased.len(), 4);
    }

    #[test]
    fn a_lease_falls_back_to_the_public_pool_once_its_own_is_spent() {
        // A renter must never be worse off than an unleased caller.
        let tm = TrafficManager::new(leased_cfg(8, 4, 2));
        tm.reserve_for_lease("lease-a", 2).expect("fits");

        let mut held = Vec::new();
        for _ in 0..2 {
            held.push(
                tm.admit_for_lease("m", QosClass::Interactive, None, Some("lease-a"), sh())
                    .expect("own reservation"),
            );
        }
        // Reservation spent; the next one draws on the public pool.
        held.push(
            tm.admit_for_lease("m", QosClass::Interactive, None, Some("lease-a"), sh())
                .expect("falls back rather than being refused"),
        );
        assert_eq!(held.len(), 3);
    }

    #[test]
    fn capacity_cannot_be_oversold_past_the_public_floor() {
        // A node that has sold every slot is invisible to the network that
        // routes work to it. Refusing the sale is better than degrading every
        // existing lease silently.
        let tm = TrafficManager::new(leased_cfg(8, 4, 2));
        assert_eq!(tm.sellable_slots(), 6, "8 total minus a floor of 2");

        tm.reserve_for_lease("a", 4).expect("fits");
        assert_eq!(tm.sellable_slots(), 2);

        let err = tm
            .reserve_for_lease("b", 4)
            .expect_err("only 2 remain sellable");
        match err {
            ReservationError::WouldBreachPublicFloor {
                requested,
                grantable,
                public_floor,
            } => {
                assert_eq!((requested, grantable, public_floor), (4, 2, 2));
            }
            other => panic!("expected WouldBreachPublicFloor, got {other:?}"),
        }
        // The exactly-fitting sale still succeeds.
        tm.reserve_for_lease("b", 2).expect("2 is grantable");
        assert_eq!(tm.sellable_slots(), 0);
    }

    #[test]
    fn reserving_twice_under_one_lease_is_refused() {
        // Otherwise a re-open silently doubles a lease's share.
        let tm = TrafficManager::new(leased_cfg(8, 4, 0));
        tm.reserve_for_lease("a", 2).expect("first");
        let err = tm.reserve_for_lease("a", 2).expect_err("second");
        assert!(matches!(err, ReservationError::AlreadyReserved { .. }));
    }

    #[test]
    fn releasing_a_lease_returns_its_capacity_to_the_public_pool() {
        let tm = TrafficManager::new(leased_cfg(8, 4, 0));
        tm.reserve_for_lease("a", 6).expect("fits");
        assert_eq!(tm.stats().public_ceiling, 2);

        let freed = tm.release_lease("a").expect("was reserved");
        assert_eq!(freed.slots, 6);
        assert_eq!(tm.stats().public_ceiling, 8);
        assert_eq!(tm.sellable_slots(), 8);
    }

    #[test]
    fn revoking_a_lease_does_not_tear_down_its_running_requests() {
        // A revocation mid-generation would kill work the renter already
        // paid for. Slots return as requests finish instead.
        let tm = TrafficManager::new(leased_cfg(8, 4, 0));
        tm.reserve_for_lease("a", 2).expect("fits");
        let running = tm
            .admit_for_lease("m", QosClass::Interactive, None, Some("a"), sh())
            .expect("admitted");

        tm.release_lease("a");
        assert_eq!(tm.stats().in_flight_interactive, 1, "still running");

        // Releasing a guard whose reservation is gone must not panic or
        // corrupt the counters.
        drop(running);
        assert_eq!(tm.stats().in_flight_interactive, 0);
        assert_eq!(tm.stats().reserved_slots, 0);
    }

    #[test]
    fn a_lease_drawing_on_its_own_slots_is_not_shed_as_batch() {
        // Batch shedding protects interactive traffic in the public pool. It
        // must not apply to capacity a renter bought outright.
        let tm = TrafficManager::new(leased_cfg(8, 1, 0));
        tm.reserve_for_lease("a", 4).expect("fits");

        let _public_batch = tm
            .admit("m", QosClass::Batch, None, sh())
            .expect("first batch");
        assert!(
            tm.admit("m", QosClass::Batch, None, sh()).is_err(),
            "public batch is capped at 1"
        );

        let mut leased = Vec::new();
        for _ in 0..4 {
            leased.push(
                tm.admit_for_lease("m", QosClass::Batch, None, Some("a"), sh())
                    .expect("reserved capacity ignores the public batch cap"),
            );
        }
        assert_eq!(leased.len(), 4);
    }

    #[test]
    fn stats_report_what_is_sold_idle_and_still_sellable() {
        let tm = TrafficManager::new(leased_cfg(8, 4, 2));
        tm.reserve_for_lease("a", 4).expect("fits");
        let _g = tm
            .admit_for_lease("m", QosClass::Interactive, None, Some("a"), sh())
            .expect("admitted");

        let stats = tm.stats();
        assert_eq!(stats.reserved_slots, 4);
        assert_eq!(stats.reserved_idle, 3, "one of the four is in use");
        assert_eq!(stats.public_ceiling, 5, "8 minus 3 idle-reserved");
        assert_eq!(stats.sellable_slots, 2);
    }

    #[test]
    fn an_unknown_lease_id_simply_draws_on_the_public_pool() {
        // A stale or forged lease id must not grant capacity, and must not
        // error either — it is just an ordinary caller.
        let tm = TrafficManager::new(leased_cfg(2, 1, 0));
        let _a = tm
            .admit_for_lease(
                "m",
                QosClass::Interactive,
                None,
                Some("no-such-lease"),
                sh(),
            )
            .expect("public pool");
        let _b = tm
            .admit_for_lease(
                "m",
                QosClass::Interactive,
                None,
                Some("no-such-lease"),
                sh(),
            )
            .expect("public pool");
        assert!(
            tm.admit_for_lease(
                "m",
                QosClass::Interactive,
                None,
                Some("no-such-lease"),
                sh(),
            )
            .is_err(),
            "an unknown lease gets no more than the public ceiling"
        );
    }

    #[test]
    fn the_default_config_keeps_a_quarter_of_the_node_public() {
        for cores in [2u32, 8, 20] {
            let c = TrafficConfig::for_cores(cores);
            assert!(c.public_floor >= 1, "a node must never be fully sellable");
            assert!(c.public_floor < c.max_concurrent);
        }
    }

    #[test]
    fn the_global_ceiling_bounds_every_model_together() {
        // The bug this module exists for: per-model limits let N models each
        // sit at their own bound and collectively flatten the machine.
        let tm = TrafficManager::new(cfg(4, 2));
        let mut held = Vec::new();
        for i in 0..4 {
            held.push(
                tm.admit(&format!("model-{i}"), QosClass::Interactive, None, sh())
                    .expect("within the ceiling"),
            );
        }
        // A fifth request against a fifth, entirely idle model still fails —
        // the ceiling is the machine's, not the model's.
        let refused = tm
            .admit("model-4", QosClass::Interactive, None, sh())
            .expect_err("global ceiling must bind across models");
        assert!(matches!(refused, Refusal::AtCapacity { .. }));
    }

    #[test]
    fn batch_traffic_cannot_starve_interactive() {
        let tm = TrafficManager::new(cfg(4, 2));
        let _b1 = tm
            .admit("embed", QosClass::Batch, None, sh())
            .expect("first batch");
        let _b2 = tm
            .admit("embed", QosClass::Batch, None, sh())
            .expect("second batch");

        let shed = tm
            .admit("embed", QosClass::Batch, None, sh())
            .expect_err("batch is capped at its reservation");
        assert!(matches!(shed, Refusal::ShedForInteractive { .. }));

        // The reserved half is still there for a waiting human.
        let _i = tm
            .admit("chat", QosClass::Interactive, None, sh())
            .expect("interactive capacity is reserved, not shared");
    }

    #[test]
    fn interactive_traffic_is_never_shed_for_being_interactive() {
        let tm = TrafficManager::new(cfg(4, 2));
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(
                tm.admit("chat", QosClass::Interactive, None, sh())
                    .expect("interactive may fill the whole node"),
            );
        }
        let refused = tm
            .admit("chat", QosClass::Interactive, None, sh())
            .expect_err("at capacity");
        assert!(
            matches!(refused, Refusal::AtCapacity { .. }),
            "interactive refusal must be capacity, never ShedForInteractive"
        );
    }

    #[test]
    fn a_busy_model_answers_with_an_eta_not_a_refusal() {
        // The defect this replaced: with every slot busy the old gate refused
        // up front, and the queue the batching engine already holds was
        // never used. Now the answer is "wait about this long".
        let tm = TrafficManager::new(cfg(8, 4));
        tm.declare_capacity("m", 1);
        tm.declare_rates("m", 730, 31); // spark, flash-next
        let _running = tm
            .admit("m", QosClass::Interactive, None, Shape::new(20, 200))
            .expect("a free slot admits");

        match tm.queue_decision("m", QosClass::Interactive, Shape::new(20, 200)) {
            AdmissionDecision::Wait { eta, position } => {
                assert_eq!(position, 0);
                // 200 tokens at 31 tok/s is ~6.5 s; the ETA is that minus
                // nothing (it just started), and well inside 30 s.
                assert!(eta.as_millis() < 10_000, "eta {eta:?}");
            }
            other => panic!("expected Wait, got {other:?}"),
        }
    }

    #[test]
    fn a_free_slot_admits_whatever_the_estimate_says() {
        // The deadlock found on real hardware, from the other side: an
        // estimate can only be corrected by running something. A free slot is
        // capacity; there is nothing to protect.
        let tm = TrafficManager::new(cfg(8, 4));
        tm.declare_expected_cost("m", Duration::from_secs(300));
        assert!(matches!(
            tm.queue_decision("m", QosClass::Interactive, Shape::new(20, 4_096)),
            AdmissionDecision::Admit
        ));
        tm.admit(
            "m",
            QosClass::Interactive,
            Some(Duration::from_secs(5)),
            Shape::new(20, 4_096),
        )
        .expect("an idle model must admit");
    }

    #[test]
    fn a_long_generation_does_not_poison_the_next_short_one() {
        // A 1,000-token answer must not teach the model that a 200-token
        // request is 32 s of work. It was priced by prompt bytes before,
        // which is exactly what happened.
        let tm = TrafficManager::new(cfg(8, 4));
        tm.declare_capacity("m", 1);
        tm.declare_rates("m", 730, 31);
        let (_, decode_before) = tm.rates("m");

        let mut g = tm
            .admit("m", QosClass::Interactive, None, Shape::new(20, 1_000))
            .expect("free");
        g.record(1_000, Some(30));
        drop(g);

        let (_, decode_after) = tm.rates("m");
        // The sample ran in ~0 ms, so if anything decode looks faster; the
        // point is it did not collapse toward "128 s per kilotoken".
        assert!(
            decode_after >= decode_before / 2,
            "{decode_before} -> {decode_after}"
        );
    }

    #[test]
    fn a_wait_past_the_class_budget_is_refused_with_the_eta() {
        // Only when a slot will not free inside the class's patience does the
        // caller get turned away — and it is told when to come back.
        let tm = TrafficManager::new(cfg(8, 4));
        tm.declare_capacity("m", 1);
        tm.declare_rates("m", 730, 1); // one token a second
        // ~300 s of decode ahead: past the 30 s an interactive caller will
        // wait, inside the ten minutes a batch caller will.
        let _running = tm
            .admit("m", QosClass::Interactive, None, Shape::new(20, 300))
            .expect("free");

        let decision = tm.queue_decision("m", QosClass::Interactive, Shape::new(20, 10));
        let AdmissionDecision::Refuse(r) = decision else {
            panic!("expected Refuse, got {decision:?}")
        };
        let refusal = tm.refuse_from_queue(r);
        match refusal {
            Refusal::QueueWaitTooLong {
                eta_ms,
                budget_ms,
                retry_after_ms,
            } => {
                assert!(eta_ms > budget_ms, "{eta_ms} vs {budget_ms}");
                assert_eq!(budget_ms, 30_000);
                assert!(retry_after_ms >= 1_000);
            }
            other => panic!("expected QueueWaitTooLong, got {other:?}"),
        }
        // A batch caller will wait ten minutes for the same slot.
        assert!(matches!(
            tm.queue_decision("m", QosClass::Batch, Shape::new(20, 10)),
            AdmissionDecision::Wait { .. }
        ));
        assert_eq!(tm.stats().refused, 1);
    }

    #[test]
    fn waiting_callers_lengthen_the_eta_quoted_behind_them() {
        // One request fits the budget; the same request behind a queue of
        // others sees a longer ETA. Ignoring the queue is what makes naive
        // admission accept work it cannot start.
        let tm = TrafficManager::new(cfg(64, 32));
        tm.declare_capacity("m", 1);
        tm.declare_rates("m", 730, 100);
        let _running = tm
            .admit("m", QosClass::Interactive, None, Shape::new(20, 500))
            .expect("free");

        let alone = match tm.queue_decision("m", QosClass::Interactive, Shape::new(20, 500)) {
            AdmissionDecision::Wait { eta, .. } => eta,
            other => panic!("{other:?}"),
        };
        for _ in 0..4 {
            tm.enter_queue("m");
        }
        let behind = match tm.queue_decision("m", QosClass::Interactive, Shape::new(20, 500)) {
            AdmissionDecision::Wait { eta, position } => {
                assert_eq!(position, 4);
                eta
            }
            other => panic!("{other:?}"),
        };
        assert!(behind > alone, "{behind:?} should exceed {alone:?}");
        for _ in 0..4 {
            tm.leave_queue("m");
        }
        assert!(matches!(
            tm.queue_decision("m", QosClass::Interactive, Shape::new(20, 500)),
            AdmissionDecision::Wait { position: 0, .. }
        ));
    }

    #[test]
    fn the_queue_has_a_depth_limit() {
        let tm = TrafficManager::new(cfg(64, 32));
        tm.declare_capacity("m", 1);
        let _running = tm
            .admit("m", QosClass::Batch, None, Shape::new(20, 10))
            .expect("free");
        let limit = AdmissionPolicy::default().max_queue_depth;
        for _ in 0..limit {
            tm.enter_queue("m");
        }
        let AdmissionDecision::Refuse(r) =
            tm.queue_decision("m", QosClass::Batch, Shape::new(20, 10))
        else {
            panic!("queue at depth must refuse")
        };
        assert!(matches!(
            tm.refuse_from_queue(r),
            Refusal::QueueFull { depth, .. } if depth == limit
        ));
    }

    #[test]
    fn a_slot_is_returned_when_the_request_finishes() {
        let tm = TrafficManager::new(cfg(1, 1));
        {
            let _g = tm
                .admit("m", QosClass::Interactive, None, sh())
                .expect("fits");
            assert!(
                tm.admit("m", QosClass::Interactive, None, sh())
                    .is_err(),
                "the single slot is taken"
            );
        }
        tm.admit("m", QosClass::Interactive, None, sh())
            .expect("slot returned on drop");
    }

    #[test]
    fn an_aborted_request_is_counted_as_refused_not_completed() {
        // Found in bring-up: a request admitted here but refused by a bound
        // further down had its guard dropped as a COMPLETION, so goodput
        // reported success for work that never ran.
        let tm = TrafficManager::new(cfg(4, 2));
        let g = tm
            .admit("m", QosClass::Interactive, None, sh())
            .expect("admitted");
        assert_eq!(tm.stats().admitted, 1);

        g.abort();

        let s = tm.stats();
        assert_eq!(s.completed, 0, "an aborted request did not complete");
        assert_eq!(s.on_time, 0, "and must not count toward goodput");
        assert_eq!(s.refused, 1, "it was refused");
        assert_eq!(s.admitted, 0, "and was never really admitted");
        assert_eq!(s.in_flight_interactive, 0, "its slot came back");
    }

    #[test]
    fn aborting_returns_a_leases_reserved_slot() {
        let tm = TrafficManager::new(leased_cfg(8, 4, 0));
        tm.reserve_for_lease("a", 2).expect("fits");
        let g = tm
            .admit_for_lease("m", QosClass::Interactive, None, Some("a"), sh())
            .expect("admitted");
        assert_eq!(tm.reservations()[0].in_use, 1);
        g.abort();
        assert_eq!(
            tm.reservations()[0].in_use,
            0,
            "the lease gets its slot back"
        );
    }

    #[test]
    fn an_abort_does_not_teach_the_cost_model_anything() {
        // An aborted request carries no information about how long the model
        // takes; folding its near-zero duration in would make the predictor
        // wildly optimistic and quote ETAs nothing can meet.
        let tm = TrafficManager::new(cfg(8, 4));
        tm.declare_rates("m", 730, 31);
        for _ in 0..20 {
            tm.admit("m", QosClass::Interactive, None, sh())
                .expect("admitted")
                .abort();
        }
        assert_eq!(
            tm.rates("m"),
            (730, 31),
            "aborts must not have moved the rates"
        );
    }

    #[test]
    fn a_guard_dropped_without_a_record_teaches_nothing_either() {
        // Zero generated tokens frees the slot and is not a sample: better no
        // sample than one that prices a 1,000-token answer as a 20-token
        // prompt, which is the mistake that had this node refusing 200-token
        // requests.
        let tm = TrafficManager::new(cfg(8, 4));
        tm.declare_rates("m", 730, 31);
        for _ in 0..20 {
            drop(
                tm.admit("m", QosClass::Interactive, None, sh())
                    .expect("admitted"),
            );
        }
        assert_eq!(tm.rates("m"), (730, 31));
    }

    #[test]
    fn a_panicking_handler_does_not_leak_its_slot() {
        // Leaked slots are permanent: capacity would fall by one per failure
        // until nothing could be admitted.
        let tm = TrafficManager::new(cfg(2, 1));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
            let tm = tm.clone();
            move || {
                let _g = tm
                    .admit("m", QosClass::Interactive, None, sh())
                    .expect("fits");
                panic!("handler blew up");
            }
        }));
        assert!(outcome.is_err());
        assert_eq!(
            tm.stats().in_flight_interactive,
            0,
            "drop ran during unwind"
        );
    }

    #[test]
    fn every_refusal_tells_the_client_when_to_come_back() {
        // A refusal without a hint produces either a hammering client or one
        // that gives up on work that would have succeeded.
        let tm = TrafficManager::new(cfg(1, 1));
        let _held = tm
            .admit("m", QosClass::Interactive, None, sh())
            .expect("fits");

        let refusals = [
            tm.admit("m", QosClass::Interactive, None, sh())
                .unwrap_err(),
            tm.admit("m", QosClass::Batch, None, sh()).unwrap_err(),
        ];
        for r in refusals {
            assert!(r.retry_after_ms() > 0, "{r:?}");
            assert!(r.retry_after_secs() >= 1, "{r:?} must not round to zero");
            assert!(!r.message().is_empty());
        }
    }

    #[test]
    fn goodput_falls_when_work_misses_its_deadline_even_as_throughput_holds() {
        // The signal this module exists to expose. Both runs complete the
        // same number of requests; only goodput distinguishes them. The
        // deadline is on the first token, not the whole answer.
        let tm = TrafficManager::new(cfg(8, 4));
        for _ in 0..4 {
            let mut g = tm
                .admit(
                    "fast",
                    QosClass::Interactive,
                    Some(Duration::from_secs(30)),
                    sh(),
                )
                .expect("fits");
            g.record(100, Some(50));
            drop(g);
        }
        assert_eq!(tm.stats().goodput_pct, 100.0);

        // Now four whose first token came after the wait they were promised.
        for _ in 0..4 {
            let mut g = tm
                .admit(
                    "fast",
                    QosClass::Interactive,
                    Some(Duration::from_secs(1)),
                    sh(),
                )
                .expect("admitted");
            g.record(100, Some(5_000));
            drop(g);
        }
        let stats = tm.stats();
        assert_eq!(stats.completed, 8, "throughput is unchanged");
        assert_eq!(stats.goodput_pct, 50.0);
    }

    #[test]
    fn the_cost_model_learns_from_recorded_output() {
        // ETA quality depends on the rates tracking reality rather than
        // staying at the seed. A handler that records generated tokens and
        // TTFT is what moves them.
        let tm = TrafficManager::new(cfg(8, 4));
        tm.declare_rates("m", 730, 31);
        let (_, before) = tm.rates("m");
        for _ in 0..8 {
            let mut g = tm
                .admit("m", QosClass::Interactive, None, Shape::new(20, 500))
                .expect("fits");
            // Pretend the decoder is far faster than the seed says.
            std::thread::sleep(Duration::from_millis(5));
            g.record(500, Some(1));
            drop(g);
        }
        let (_, after) = tm.rates("m");
        assert!(
            after > before,
            "decode rate should have risen: {before} -> {after}"
        );
    }

    #[test]
    fn defaults_scale_with_the_machine() {
        let small = TrafficConfig::for_cores(2);
        let big = TrafficConfig::for_cores(20);
        assert!(big.max_concurrent > small.max_concurrent);
        // Batch can never claim the whole node.
        for c in [small, big] {
            assert!(
                c.max_concurrent_batch < c.max_concurrent,
                "interactive capacity must always be reserved"
            );
        }
    }

    #[test]
    fn concurrent_admissions_never_exceed_the_ceiling() {
        // The ceiling has to hold under real contention, not just in
        // sequential calls.
        use std::sync::atomic::AtomicUsize;

        let tm = TrafficManager::new(cfg(8, 4));
        let peak = Arc::new(AtomicUsize::new(0));
        std::thread::scope(|s| {
            for _ in 0..64 {
                let tm = tm.clone();
                let peak = Arc::clone(&peak);
                s.spawn(move || {
                    if let Ok(g) = tm.admit("m", QosClass::Interactive, None, sh()) {
                        let now = tm.stats().in_flight_interactive as usize;
                        peak.fetch_max(now, std::sync::atomic::Ordering::SeqCst);
                        std::thread::sleep(Duration::from_millis(1));
                        drop(g);
                    }
                });
            }
        });
        assert!(
            peak.load(std::sync::atomic::Ordering::SeqCst) <= 8,
            "peak {} exceeded the ceiling",
            peak.load(std::sync::atomic::Ordering::SeqCst)
        );
        assert_eq!(tm.stats().in_flight_interactive, 0, "all slots returned");
    }
}
