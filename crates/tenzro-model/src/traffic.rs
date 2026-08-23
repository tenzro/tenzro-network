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
//! - **Admit on predicted deadline, not on free capacity.** Estimate the
//!   request's completion time including current queue depth; if it cannot
//!   meet its SLO, say so immediately rather than accepting it and missing.
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
    /// Default end-to-end deadline for this class.
    ///
    /// Interactive is 30s: past that a caller has usually given up, so
    /// admitting the work spends capacity on a result nobody will read.
    /// Batch is 10 minutes, which is a job-completion target rather than a
    /// per-token one — per-token SLOs are meaningless for bulk work.
    pub fn default_deadline(self) -> Duration {
        match self {
            Self::Interactive => Duration::from_secs(30),
            Self::Batch => Duration::from_secs(600),
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
    /// Admitting this would miss its deadline, so it is refused now rather
    /// than accepted and missed later. Refusing early is what keeps the
    /// already-admitted requests on time.
    DeadlineUnattainable {
        /// Predicted milliseconds to completion, including queue wait.
        predicted_ms: u64,
        /// The deadline it had to meet.
        deadline_ms: u64,
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
            | Self::DeadlineUnattainable { retry_after_ms, .. }
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
            Self::DeadlineUnattainable {
                predicted_ms,
                deadline_ms,
                ..
            } => format!(
                "refused up front: predicted {predicted_ms} ms exceeds the {deadline_ms} ms \
                 deadline, so admitting it would miss and cost the requests already running"
            ),
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

/// Rolling cost model for one model's requests.
///
/// Predicting completion time is what makes deadline-based admission
/// possible. The prediction does not need to be precise — it needs to be
/// *calibrated enough* to tell a request that will finish in 2 seconds from
/// one that will take 5 minutes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct CostModel {
    /// Cost per thousand tokens, not per request.
    ///
    /// A per-request mean cannot tell a twenty-token prompt from a
    /// hundred-thousand-token agent turn, so one long turn taught the model
    /// that *every* request costs what it cost — and every small request behind
    /// it was then refused as deadline-unattainable. Observed on this node: an
    /// agent turn carrying 172k tokens trained the mean to ~70s, after which a
    /// "hello world" prompt was predicted at 73s and refused.
    ///
    /// Normalising by size is what makes the estimate transferable between
    /// requests of different shapes.
    mean_ms_per_kilotoken: u64,
    samples: u32,
}

impl CostModel {
    /// Cost of a request we have no samples for, per thousand tokens.
    const DEFAULT_MS_PER_KTOK: u64 = 2_000;
    /// Below this a request is all fixed overhead and the per-token rate says
    /// nothing useful, so sizes are floored rather than dividing by ~zero.
    const MIN_KILOTOKENS_X1000: u64 = 250;

    /// Size in thousandths of a kilotoken (i.e. tokens), floored.
    fn scale(tokens: u64) -> u64 {
        tokens.max(Self::MIN_KILOTOKENS_X1000)
    }

    fn observe(&mut self, ms: u64, tokens: u64) {
        let per_ktok = ms.saturating_mul(1_000) / Self::scale(tokens);
        if self.samples == 0 {
            self.mean_ms_per_kilotoken = per_ktok;
        } else {
            // 25% on the newest sample: converges within a handful of
            // requests without one pathological long generation poisoning
            // every subsequent admission decision.
            self.mean_ms_per_kilotoken = (per_ktok * 25 + self.mean_ms_per_kilotoken * 75) / 100;
        }
        self.samples = self.samples.saturating_add(1);
    }

    fn predict_ms(&self, tokens: u64) -> u64 {
        let rate = if self.samples == 0 {
            Self::DEFAULT_MS_PER_KTOK
        } else {
            self.mean_ms_per_kilotoken
        };
        rate.saturating_mul(Self::scale(tokens)) / 1_000
    }
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
    /// Size this request was admitted against, so its cost is recorded per
    /// token rather than per request.
    est_tokens: u64,
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
        let elapsed_ms = self.started.elapsed().as_millis() as u64;
        if self.aborted {
            self.inner
                .release_aborted(&self.model_id, self.class, self.lease_id.as_deref());
            return;
        }
        self.inner.release(
            &self.model_id,
            self.class,
            self.lease_id.as_deref(),
            elapsed_ms,
            self.deadline,
            self.est_tokens,
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
    costs: HashMap<String, CostModel>,
    /// Guaranteed capacity sold to leases, by lease id.
    reservations: HashMap<String, Reservation>,
}

impl TrafficState {
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
    fn release_aborted(&self, _model_id: &str, class: QosClass, lease_id: Option<&str>) {
        // A request that never ran was never really admitted. Undo the admit
        // and record the refusal, so `admitted - completed` stays a real
        // measure of work in flight rather than drifting by one per abort.
        self.counters.admitted.fetch_sub(1, Ordering::Relaxed);
        self.counters.refused.fetch_add(1, Ordering::Relaxed);

        let mut state = self.state.lock();
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
        elapsed_ms: u64,
        deadline: Duration,
        est_tokens: u64,
    ) {
        {
            let mut state = self.state.lock();
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
            state
                .costs
                .entry(model_id.to_string())
                .or_default()
                .observe(elapsed_ms, est_tokens);
        }
        self.counters.completed.fetch_add(1, Ordering::Relaxed);
        if elapsed_ms <= deadline.as_millis() as u64 {
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

    /// Decide whether to run a request now.
    ///
    /// `deadline` is how long the caller is willing to wait end to end;
    /// `None` takes the class default. `queue_ahead` is how many requests are
    /// already waiting for this model, which is what turns a per-request cost
    /// estimate into a completion-time prediction.
    ///
    /// Checks run cheapest-first and most-protective-first: the global
    /// ceiling, then the batch reservation, then the deadline prediction.
    pub fn admit(
        &self,
        model_id: &str,
        class: QosClass,
        deadline: Option<Duration>,
        queue_ahead: u32,
        est_tokens: u64,
    ) -> Result<RequestGuard, Refusal> {
        self.admit_for_lease(model_id, class, deadline, queue_ahead, None, est_tokens)
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
        queue_ahead: u32,
        lease_id: Option<&str>,
        est_tokens: u64,
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

        // 3. Deadline prediction. Cost of this request, plus the queue it
        //    must wait behind. Refusing here is what protects the requests
        //    already admitted — accepting work that will miss does not help
        //    the new caller and hurts everyone ahead of them.
        let per_request_ms = state
            .costs
            .get(model_id)
            .map(|c| c.predict_ms(est_tokens))
            .unwrap_or_else(|| CostModel::default().predict_ms(est_tokens));
        let predicted_ms = per_request_ms.saturating_mul(u64::from(queue_ahead) + 1);
        let deadline_ms = deadline.as_millis() as u64;

        // An idle node always admits, whatever the estimate says.
        //
        // Without this the predictor can deadlock itself, and did on real
        // hardware: a burst of 24 concurrent requests each took ~30s, the cost
        // model learned 30s as the per-request cost, and every subsequent
        // request was then refused as deadline-unattainable — including the
        // ones that would have run alone in three. Refusing everything means
        // nothing completes, nothing completes means no new samples, and the
        // estimate can never come down. A permanent outage from a transient
        // spike.
        //
        // The underlying error is that elapsed time measures *sojourn* — how
        // long a request took including waiting behind others — while the
        // prediction uses it as *service* time. Until those are measured
        // separately, an idle node is the one case where the estimate is
        // knowably wrong and reality can correct it.
        let idle = state.total_in_flight() == 0;
        if !idle && predicted_ms > deadline_ms {
            drop(state);
            return Err(self.refuse(Refusal::DeadlineUnattainable {
                predicted_ms,
                deadline_ms,
                // Come back after roughly the queue draining, not instantly.
                retry_after_ms: per_request_ms.max(1_000),
            }));
        }

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
            est_tokens,
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

    /// Seed the cost model for a model whose requests have not been measured.
    ///
    /// Lets an operator calibrate before serving traffic instead of letting
    /// the first few callers absorb a wrong prediction.
    /// `expected` is the cost of a *typical* request for this model; it is
    /// stored as a per-token rate against a nominal one-kilotoken request, so a
    /// declared figure calibrates requests of any size rather than only ones
    /// the same shape as the operator imagined.
    pub fn declare_expected_cost(&self, model_id: &str, expected: Duration) {
        self.inner.state.lock().costs.insert(
            model_id.to_string(),
            CostModel {
                mean_ms_per_kilotoken: expected.as_millis() as u64,
                samples: 1,
            },
        );
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
        while let Ok(g) = tm.admit("m", QosClass::Interactive, None, 0, 1_000) {
            public.push(g);
        }
        assert_eq!(public.len(), 4, "public is capped at 8 - 4 reserved-idle");

        // The lease holder still gets every slot it paid for.
        let mut leased = Vec::new();
        for _ in 0..4 {
            leased.push(
                tm.admit_for_lease("m", QosClass::Interactive, None, 0, Some("lease-a"), 1_000)
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
                tm.admit_for_lease("m", QosClass::Interactive, None, 0, Some("lease-a"), 1_000)
                    .expect("own reservation"),
            );
        }
        // Reservation spent; the next one draws on the public pool.
        held.push(
            tm.admit_for_lease("m", QosClass::Interactive, None, 0, Some("lease-a"), 1_000)
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
            .admit_for_lease("m", QosClass::Interactive, None, 0, Some("a"), 1_000)
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
            .admit("m", QosClass::Batch, None, 0, 1_000)
            .expect("first batch");
        assert!(
            tm.admit("m", QosClass::Batch, None, 0, 1_000).is_err(),
            "public batch is capped at 1"
        );

        let mut leased = Vec::new();
        for _ in 0..4 {
            leased.push(
                tm.admit_for_lease("m", QosClass::Batch, None, 0, Some("a"), 1_000)
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
            .admit_for_lease("m", QosClass::Interactive, None, 0, Some("a"), 1_000)
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
            .admit_for_lease("m", QosClass::Interactive, None, 0, Some("no-such-lease"), 1_000)
            .expect("public pool");
        let _b = tm
            .admit_for_lease("m", QosClass::Interactive, None, 0, Some("no-such-lease"), 1_000)
            .expect("public pool");
        assert!(
            tm.admit_for_lease("m", QosClass::Interactive, None, 0, Some("no-such-lease"), 1_000)
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
                tm.admit(&format!("model-{i}"), QosClass::Interactive, None, 0, 1_000)
                    .expect("within the ceiling"),
            );
        }
        // A fifth request against a fifth, entirely idle model still fails —
        // the ceiling is the machine's, not the model's.
        let refused = tm
            .admit("model-4", QosClass::Interactive, None, 0, 1_000)
            .expect_err("global ceiling must bind across models");
        assert!(matches!(refused, Refusal::AtCapacity { .. }));
    }

    #[test]
    fn batch_traffic_cannot_starve_interactive() {
        let tm = TrafficManager::new(cfg(4, 2));
        let _b1 = tm
            .admit("embed", QosClass::Batch, None, 0, 1_000)
            .expect("first batch");
        let _b2 = tm
            .admit("embed", QosClass::Batch, None, 0, 1_000)
            .expect("second batch");

        let shed = tm
            .admit("embed", QosClass::Batch, None, 0, 1_000)
            .expect_err("batch is capped at its reservation");
        assert!(matches!(shed, Refusal::ShedForInteractive { .. }));

        // The reserved half is still there for a waiting human.
        let _i = tm
            .admit("chat", QosClass::Interactive, None, 0, 1_000)
            .expect("interactive capacity is reserved, not shared");
    }

    #[test]
    fn interactive_traffic_is_never_shed_for_being_interactive() {
        let tm = TrafficManager::new(cfg(4, 2));
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(
                tm.admit("chat", QosClass::Interactive, None, 0, 1_000)
                    .expect("interactive may fill the whole node"),
            );
        }
        let refused = tm
            .admit("chat", QosClass::Interactive, None, 0, 1_000)
            .expect_err("at capacity");
        assert!(
            matches!(refused, Refusal::AtCapacity { .. }),
            "interactive refusal must be capacity, never ShedForInteractive"
        );
    }

    #[test]
    fn a_request_that_cannot_meet_its_deadline_is_refused_up_front() {
        // Accepting it would miss anyway, and inflate the queue for everyone
        // already admitted.
        let tm = TrafficManager::new(cfg(8, 4));
        tm.declare_expected_cost("slow", Duration::from_secs(10));

        // An idle node always admits a probe, so hold one in flight: the
        // deadline guard exists to protect requests already running, and with
        // none running there is nothing to protect.
        let _running = tm
            .admit(
                "slow",
                QosClass::Interactive,
                Some(Duration::from_secs(30)),
                0,
            1_000,)
            .expect("probe");

        let refused = tm
            .admit(
                "slow",
                QosClass::Interactive,
                Some(Duration::from_secs(5)),
                0,
            1_000,)
            .expect_err("10s of work cannot meet a 5s deadline");
        match refused {
            Refusal::DeadlineUnattainable {
                predicted_ms,
                deadline_ms,
                ..
            } => {
                assert_eq!(predicted_ms, 10_000);
                assert_eq!(deadline_ms, 5_000);
            }
            other => panic!("expected DeadlineUnattainable, got {other:?}"),
        }
    }

    #[test]
    fn an_idle_node_admits_even_when_the_estimate_says_it_cannot() {
        // The deadlock found on real hardware. A saturated burst taught the
        // cost model a 30s per-request time; every later request was then
        // refused, so nothing ran, so the estimate never corrected. An idle
        // node must always take work — it is the one case where reality can
        // falsify the estimate.
        let tm = TrafficManager::new(cfg(8, 4));
        tm.declare_expected_cost("m", Duration::from_secs(300));

        let g = tm
            .admit("m", QosClass::Interactive, Some(Duration::from_secs(5)), 0, 1_000)
            .expect("an idle node must admit a probe");
        assert_eq!(tm.stats().in_flight_interactive, 1);

        // With that probe in flight the node is no longer idle, so the
        // deadline check applies again and protects the running request.
        assert!(
            tm.admit("m", QosClass::Interactive, Some(Duration::from_secs(5)), 0, 1_000)
                .is_err(),
            "a busy node still refuses work it cannot finish in time"
        );
        drop(g);
    }

    #[test]
    fn the_estimate_can_recover_after_a_pessimistic_spike() {
        // End to end: a bad estimate must be correctable by observed reality,
        // or a transient spike becomes a permanent refusal.
        let tm = TrafficManager::new(cfg(8, 4));
        tm.declare_expected_cost("m", Duration::from_secs(300));

        // Idle probes run fast and teach the model the truth.
        for _ in 0..12 {
            let g = tm
                .admit("m", QosClass::Interactive, Some(Duration::from_secs(30)), 0, 1_000)
                .expect("idle admits");
            drop(g);
        }

        // Now two can be in flight at once without the second being refused,
        // which was impossible while the estimate stood at 300s.
        let _first = tm
            .admit("m", QosClass::Interactive, Some(Duration::from_secs(30)), 0, 1_000)
            .expect("first");
        tm.admit("m", QosClass::Interactive, Some(Duration::from_secs(30)), 0, 1_000)
            .expect("the estimate has recovered, so a busy node admits again");
    }

    #[test]
    fn queue_depth_is_part_of_the_prediction() {
        // One request fits the deadline; the same request behind nine others
        // does not. Ignoring the queue is what makes naive admission accept
        // work it cannot finish.
        let tm = TrafficManager::new(cfg(64, 32));
        tm.declare_expected_cost("m", Duration::from_secs(1));

        // Bound, not dropped: an idle node always admits a probe, so the
        // queue-depth check only applies once something is actually running.
        let _running = tm
            .admit("m", QosClass::Interactive, Some(Duration::from_secs(5)), 0, 1_000)
            .expect("alone, 1s fits inside 5s");

        let refused = tm
            .admit("m", QosClass::Interactive, Some(Duration::from_secs(5)), 9, 1_000)
            .expect_err("behind nine others it is 10s of work");
        assert!(matches!(refused, Refusal::DeadlineUnattainable { .. }));
    }

    #[test]
    fn a_slot_is_returned_when_the_request_finishes() {
        let tm = TrafficManager::new(cfg(1, 1));
        {
            let _g = tm.admit("m", QosClass::Interactive, None, 0, 1_000).expect("fits");
            assert!(
                tm.admit("m", QosClass::Interactive, None, 0, 1_000).is_err(),
                "the single slot is taken"
            );
        }
        tm.admit("m", QosClass::Interactive, None, 0, 1_000)
            .expect("slot returned on drop");
    }

    #[test]
    fn an_aborted_request_is_counted_as_refused_not_completed() {
        // Found in bring-up: a request admitted here but refused by a bound
        // further down had its guard dropped as a COMPLETION, so goodput
        // reported success for work that never ran.
        let tm = TrafficManager::new(cfg(4, 2));
        let g = tm
            .admit("m", QosClass::Interactive, None, 0, 1_000)
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
            .admit_for_lease("m", QosClass::Interactive, None, 0, Some("a"), 1_000)
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
        // wildly optimistic and admit work that cannot finish.
        let tm = TrafficManager::new(cfg(8, 4));
        tm.declare_expected_cost("m", Duration::from_secs(10));
        for _ in 0..20 {
            tm.admit("m", QosClass::Interactive, None, 0, 1_000)
                .expect("admitted")
                .abort();
        }
        // The 10s estimate must survive: a 5s deadline is still unattainable.
        // Checked with a request in flight, since an idle node admits a probe
        // regardless of the estimate.
        let _running = tm
            .admit("m", QosClass::Interactive, Some(Duration::from_secs(30)), 0, 1_000)
            .expect("probe");
        assert!(
            tm.admit("m", QosClass::Interactive, Some(Duration::from_secs(5)), 0, 1_000)
                .is_err(),
            "aborts must not have dragged the cost estimate down"
        );
    }

    #[test]
    fn a_panicking_handler_does_not_leak_its_slot() {
        // Leaked slots are permanent: capacity would fall by one per failure
        // until nothing could be admitted.
        let tm = TrafficManager::new(cfg(2, 1));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe({
            let tm = tm.clone();
            move || {
                let _g = tm.admit("m", QosClass::Interactive, None, 0, 1_000).expect("fits");
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
        let _held = tm.admit("m", QosClass::Interactive, None, 0, 1_000).expect("fits");

        let refusals = [
            tm.admit("m", QosClass::Interactive, None, 0, 1_000).unwrap_err(),
            tm.admit("m", QosClass::Batch, None, 0, 1_000).unwrap_err(),
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
        // same number of requests; only goodput distinguishes them.
        let tm = TrafficManager::new(cfg(8, 4));
        for _ in 0..4 {
            let g = tm
                .admit(
                    "fast",
                    QosClass::Interactive,
                    Some(Duration::from_secs(30)),
                    0,
                1_000,)
                .expect("fits");
            drop(g);
        }
        assert_eq!(tm.stats().goodput_pct, 100.0);

        // Now four requests with a deadline they cannot possibly meet.
        for _ in 0..4 {
            let g = tm
                .admit("fast", QosClass::Interactive, Some(Duration::ZERO), 0, 1_000)
                .expect("admitted: a zero deadline predicts nothing ahead of it");
            std::thread::sleep(Duration::from_millis(2));
            drop(g);
        }
        let stats = tm.stats();
        assert_eq!(stats.completed, 8, "throughput is unchanged");
        assert!(
            stats.goodput_pct < 100.0,
            "goodput must fall: {}%",
            stats.goodput_pct
        );
    }

    #[test]
    fn a_big_turn_does_not_make_small_requests_unschedulable() {
        // The failure this normalisation exists for. An agent turn carrying
        // 172k tokens took ~70s; under a per-request mean that taught the node
        // that *every* request costs 70s, and the next twenty-token prompt was
        // predicted at 73s and refused as deadline-unattainable whenever
        // anything else was in flight. Observed on a live node.
        let mut c = CostModel::default();
        c.observe(70_000, 172_000);

        let big = c.predict_ms(172_000);
        let small = c.predict_ms(20);
        assert!(big > 30_000, "a 172k-token turn is still expensive: {big}ms");
        assert!(
            small < 5_000,
            "a 20-token prompt must not inherit the big turn's cost, got {small}ms"
        );
    }

    #[test]
    fn cost_is_carried_between_differently_shaped_requests() {
        // Normalising by size is what makes one request's measurement useful
        // for predicting another of a different shape.
        let mut c = CostModel::default();
        c.observe(10_000, 10_000);
        let doubled = c.predict_ms(20_000);
        assert!(
            (18_000..=22_000).contains(&doubled),
            "twice the tokens should predict about twice the time, got {doubled}ms"
        );
    }

    #[test]
    fn a_tiny_request_is_not_predicted_as_free() {
        // Below the floor a request is all fixed overhead; dividing by a
        // near-zero size would predict ~0ms and admit without bound.
        let mut c = CostModel::default();
        c.observe(2_000, 1);
        assert!(
            c.predict_ms(1) >= 1_000,
            "a one-token sample must not collapse the rate"
        );
    }

    #[test]
    fn the_cost_model_learns_from_completed_requests() {
        // Admission quality depends on prediction quality, so predictions
        // have to track reality rather than stay at the default.
        let tm = TrafficManager::new(cfg(8, 4));

        // Default is 2s, so a 1s deadline is unattainable before any
        // measurement — visible only once something is in flight, since an
        // idle node always admits a probe.
        let running = tm
            .admit("m", QosClass::Interactive, Some(Duration::from_secs(30)), 0, 1_000)
            .expect("probe");
        assert!(
            tm.admit(
                "m",
                QosClass::Interactive,
                Some(Duration::from_millis(1_000)),
                0
            , 1_000)
            .is_err()
        );
        drop(running);

        // Run some genuinely fast requests.
        for _ in 0..8 {
            let g = tm
                .admit("m", QosClass::Interactive, Some(Duration::from_secs(30)), 0, 1_000)
                .expect("fits under a loose deadline");
            drop(g);
        }

        // Having learned they are fast, the tight deadline is now attainable.
        tm.admit(
            "m",
            QosClass::Interactive,
            Some(Duration::from_millis(1_000)),
            0,
        1_000,)
        .expect("measured cost should now be well under 1s");
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
                    if let Ok(g) = tm.admit("m", QosClass::Interactive, None, 0, 1_000) {
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
