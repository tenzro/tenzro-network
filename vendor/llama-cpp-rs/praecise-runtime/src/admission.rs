//! Admission and queueing for a bandwidth-bound decoder.
//!
//! Backend-agnostic: nothing here touches a model. It is the arithmetic a
//! serving layer needs to decide, for each arriving request, whether to run it
//! now, hold it until a slot frees, or turn it away — and to be honest about
//! how long "until a slot frees" is.
//!
//! ## What was wrong before this existed
//!
//! The host that first used Praecise admitted on a *predicted end-to-end
//! time* against a fixed 30-second deadline, and it predicted that time from
//! a single learned rate of milliseconds per kilotoken **of prompt**. On a
//! decoder running at ~30 tok/s that fails in three independent ways, and
//! all three were observed on a DGX Spark serving a 125B MoE:
//!
//! 1. **Output was never in the estimate.** A 20-token prompt that generates
//!    1,000 tokens costs 32 s of decode. Charged as 20 tokens of prompt, one
//!    such request taught the model "128 s per kilotoken". Every request after
//!    it — including a 200-token prompt asking for 200 tokens — was predicted
//!    at 30–50 s and refused.
//! 2. **The deadline was fixed while the work was not.** A caller asking for
//!    4,096 tokens at 30 tok/s has asked for a two-minute answer. Refusing it
//!    because thirty is a nice number does not protect anyone; it converts
//!    every long generation into an error.
//! 3. **Refusal instead of a queue.** The batching engine underneath holds a
//!    channel and admits into slots as they free. Turning callers away above
//!    it, with a "retry after" they cannot act on, threw away the queue that
//!    already existed.
//!
//! ## The model this module uses instead
//!
//! - **Cost has two terms.** Prefill is priced per prompt token and decode per
//!   generated token, learned separately, because on this hardware they differ
//!   by more than an order of magnitude (measured on GB10: ~730 tok/s prefill,
//!   ~31 tok/s decode for the same model). A request's service time is
//!   `prompt × prefill_rate + expected_output × decode_rate`.
//! - **The SLO is on the wait, not the answer.** Interactive traffic gets a
//!   budget for how long it may sit in the queue before its first token; the
//!   generation itself runs for as long as `max_tokens` asks. This is the
//!   convention every large serving deployment uses (time-to-first-token and
//!   queue timeout, never a cap on total generation) and it is the one that
//!   makes long completions possible at all on a slow decoder.
//! - **Queue, then refuse.** When every slot is busy the answer is an ETA,
//!   derived from the remaining work of the requests already running, and the
//!   host waits that long. Only an ETA beyond the class budget, or a queue
//!   already at its depth limit, is a refusal — and the refusal says why.
//!
//! The host owns locking, timers and the actual wait; this module is pure
//! state and arithmetic so it can be tested with the numbers above.

use std::collections::BTreeMap;
use std::time::Duration;

/// Which kind of caller is waiting, and therefore how long they will tolerate
/// sitting in the queue before their first token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// A person or an agent loop is blocked on the answer. Short queue budget.
    Interactive,
    /// Throughput work. Long queue budget; yields to interactive traffic.
    Batch,
}

/// The size of a request as far as admission cares: how much must be read,
/// and how much may be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Shape {
    /// Tokens in the prompt. A byte-length estimate is fine; this drives an
    /// ETA, not a bill.
    pub prompt_tokens: u64,
    /// The most tokens the caller allowed the model to generate.
    pub max_output_tokens: u64,
}

impl Shape {
    pub fn new(prompt_tokens: u64, max_output_tokens: u64) -> Self {
        Self { prompt_tokens, max_output_tokens }
    }
}

/// What a completed request actually cost, fed back to the cost model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    pub prompt_tokens: u64,
    /// Tokens the model produced. Zero means the request did not run and
    /// teaches nothing.
    pub generated_tokens: u64,
    /// The most tokens the caller allowed (`Shape::max_output_tokens`). With
    /// `generated_tokens` this teaches how much of a budget requests really
    /// use, which is what turns a ceiling into an expected length.
    pub budget_tokens: u64,
    /// Wall time from start of service (not arrival) to completion.
    pub service_ms: u64,
    /// Time to the first generated token, when the host can measure it. This
    /// is what separates the two rates cleanly; without it the prefill term is
    /// only inferred.
    pub first_token_ms: Option<u64>,
    /// How many requests shared the decoder while this one ran, including
    /// itself. Batched decode is slower per request than solo decode, so the
    /// learned decode rate is normalised to a solo-equivalent before storage
    /// and re-scaled at prediction time.
    pub concurrency: u32,
}

/// Per-model cost model: microseconds per token, for prefill and decode.
///
/// Stored per token rather than per request so that a value learned from a
/// long agent turn transfers to a short chat message. Stored as microseconds
/// so that integer arithmetic keeps four digits of precision on a decode step
/// that costs ~32,000 µs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CostModel {
    prefill_us_per_tok: u64,
    /// Solo-equivalent decode cost per token.
    decode_us_per_tok: u64,
    /// Share of the caller's output budget that requests actually use, in
    /// percent. `max_output_tokens` is a ceiling and most generations stop
    /// well short of it; pricing every request at its ceiling makes a
    /// 2,000-token budget look like a minute of decode when the answer takes
    /// ten seconds, and refuses the caller behind it for a wait that never
    /// happens. Learned per model, since chat and agent traffic differ.
    budget_use_pct: u64,
    samples: u32,
}

impl CostModel {
    /// Prior for prefill: 500 tok/s. Deliberately pessimistic for a GPU; a
    /// prior that is too optimistic under-estimates ETAs and makes the host
    /// promise waits it cannot keep.
    pub const DEFAULT_PREFILL_US_PER_TOK: u64 = 2_000;
    /// Prior for decode: 25 tok/s. Same reasoning.
    pub const DEFAULT_DECODE_US_PER_TOK: u64 = 40_000;
    /// Prior for budget use: the whole budget. Pessimistic on purpose, for
    /// the same reason as the rates — an ETA promised short and kept long
    /// is worse than one promised long. The truth arrives with the first
    /// completions.
    pub const DEFAULT_BUDGET_USE_PCT: u64 = 100;
    /// Never predict less output than this, however small the learned share:
    /// a run of one-word answers must not make the next real question look
    /// free.
    const MIN_EXPECTED_OUTPUT_TOKENS: u64 = 32;
    /// Weight of the newest sample in the moving average. A quarter converges
    /// in a handful of requests without one outlier owning the estimate.
    const NEW_SAMPLE_PCT: u64 = 25;

    pub fn new() -> Self {
        Self {
            prefill_us_per_tok: Self::DEFAULT_PREFILL_US_PER_TOK,
            decode_us_per_tok: Self::DEFAULT_DECODE_US_PER_TOK,
            budget_use_pct: Self::DEFAULT_BUDGET_USE_PCT,
            samples: 0,
        }
    }

    /// Seed from a known throughput instead of the prior — e.g. a benchmark
    /// the operator ran on this hardware.
    pub fn from_rates(prefill_tok_per_s: u64, decode_tok_per_s: u64) -> Self {
        Self {
            prefill_us_per_tok: 1_000_000 / prefill_tok_per_s.max(1),
            decode_us_per_tok: 1_000_000 / decode_tok_per_s.max(1),
            budget_use_pct: Self::DEFAULT_BUDGET_USE_PCT,
            samples: 1,
        }
    }

    pub fn samples(&self) -> u32 {
        self.samples
    }

    /// Learned solo decode throughput, tokens per second.
    pub fn decode_tok_per_s(&self) -> u64 {
        1_000_000 / self.decode_us_per_tok.max(1)
    }

    /// Learned prefill throughput, tokens per second.
    pub fn prefill_tok_per_s(&self) -> u64 {
        1_000_000 / self.prefill_us_per_tok.max(1)
    }

    /// Learned share of the output budget that requests use, in percent.
    pub fn budget_use_pct(&self) -> u64 {
        self.budget_use_pct
    }

    fn ema(old: u64, new: u64, first: bool) -> u64 {
        if first {
            new
        } else {
            (new * Self::NEW_SAMPLE_PCT + old * (100 - Self::NEW_SAMPLE_PCT)) / 100
        }
    }

    /// Fold a completed request into the estimate.
    ///
    /// Only a request that generated something teaches anything; a refused or
    /// aborted request carries no service time and is ignored.
    pub fn observe(&mut self, o: Observation) {
        if o.generated_tokens == 0 || o.service_ms == 0 {
            return;
        }
        let first = self.samples == 0;
        let conc = u64::from(o.concurrency.max(1));

        // Prefill: measured directly when the host reports first-token time,
        // otherwise left alone. Inferring it from a total that is 95% decode
        // would only add noise to the smaller term.
        let prefill_ms = match o.first_token_ms {
            Some(ttft) if o.prompt_tokens > 0 => {
                let us_per_tok = ttft.saturating_mul(1_000) / o.prompt_tokens;
                if us_per_tok > 0 {
                    self.prefill_us_per_tok = Self::ema(self.prefill_us_per_tok, us_per_tok, first);
                }
                ttft
            }
            _ => self.prefill_us_per_tok.saturating_mul(o.prompt_tokens) / 1_000,
        };

        // Decode: whatever was not prefill, per generated token, normalised to
        // a solo-equivalent by the concurrency it ran under. At c=2 on a
        // bandwidth-bound decoder each request sees roughly half the solo
        // rate, so dividing the per-token wall time by c recovers the solo
        // figure this model stores.
        let decode_ms = o.service_ms.saturating_sub(prefill_ms);
        let us_per_tok = decode_ms.saturating_mul(1_000) / o.generated_tokens / conc;
        if us_per_tok > 0 {
            self.decode_us_per_tok = Self::ema(self.decode_us_per_tok, us_per_tok, first);
        }

        // Budget use: how much of what the caller allowed was actually
        // generated. A request that hit its ceiling counts as 100%, not more.
        if o.budget_tokens > 0 {
            let pct = (o.generated_tokens.saturating_mul(100) / o.budget_tokens).min(100);
            self.budget_use_pct = Self::ema(self.budget_use_pct, pct, first);
        }
        self.samples = self.samples.saturating_add(1);
    }

    /// Predicted service time for `shape` if it ran alongside `concurrency - 1`
    /// other requests.
    ///
    /// `max_output_tokens` is an upper bound, and most generations stop
    /// early, so the decode term is priced at the share of the budget this
    /// model's requests have been using — the whole budget until something
    /// has been observed. Over-estimating an ETA costs a caller a little
    /// extra wait; under-estimating it costs them a broken promise, so the
    /// prior is the ceiling and the floor is never zero.
    pub fn predict(&self, shape: Shape, concurrency: u32) -> Estimate {
        let conc = u64::from(concurrency.max(1));
        let prefill_ms = self.prefill_us_per_tok.saturating_mul(shape.prompt_tokens) / 1_000;
        let decode_ms =
            self.decode_us_per_tok.saturating_mul(self.expected_output(shape)).saturating_mul(conc) / 1_000;
        Estimate { prefill_ms, decode_ms }
    }

    /// Tokens this request is expected to generate: its budget scaled by the
    /// learned use, floored so a run of short answers cannot make the next
    /// request look free, and never more than the budget itself.
    fn expected_output(&self, shape: Shape) -> u64 {
        let scaled = shape.max_output_tokens.saturating_mul(self.budget_use_pct) / 100;
        scaled.max(Self::MIN_EXPECTED_OUTPUT_TOKENS).min(shape.max_output_tokens)
    }
}

impl Default for CostModel {
    fn default() -> Self {
        Self::new()
    }
}

/// A predicted service time, split so a host can report time-to-first-token
/// separately from total.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Estimate {
    pub prefill_ms: u64,
    pub decode_ms: u64,
}

impl Estimate {
    pub fn total_ms(&self) -> u64 {
        self.prefill_ms.saturating_add(self.decode_ms)
    }
}

/// How long each class may wait in the queue, and how deep the queue may get.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// Queue budget for interactive callers. Thirty seconds is the point past
    /// which a person has usually given up on a blank screen — but this is a
    /// wait for the *first* token, not for the whole answer.
    pub interactive_wait: Duration,
    /// Queue budget for batch callers.
    pub batch_wait: Duration,
    /// Requests allowed to wait at once. Beyond this, refuse immediately so a
    /// burst fails fast instead of timing out one by one.
    pub max_queue_depth: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            interactive_wait: Duration::from_secs(30),
            batch_wait: Duration::from_secs(600),
            max_queue_depth: 64,
        }
    }
}

impl Policy {
    pub fn wait_budget(&self, class: Class) -> Duration {
        match class {
            Class::Interactive => self.interactive_wait,
            Class::Batch => self.batch_wait,
        }
    }
}

/// Why a request was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Every slot is busy and the queue is full. Come back after roughly one
    /// service time.
    QueueFull { depth: u32, limit: u32, retry_after_ms: u64 },
    /// A slot will free, but not within what this class will wait.
    WaitTooLong { eta_ms: u64, budget_ms: u64 },
}

impl Refusal {
    pub fn retry_after_ms(&self) -> u64 {
        match self {
            Refusal::QueueFull { retry_after_ms, .. } => *retry_after_ms,
            Refusal::WaitTooLong { eta_ms, .. } => *eta_ms,
        }
    }
}

/// The scheduler's answer for one arriving request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// A slot is free. Start now.
    Admit,
    /// Every slot is busy; one is expected to free in about `eta`. The host
    /// should hold the request and ask again — the ETA shrinks as running
    /// requests finish.
    Wait { eta: Duration, position: u32 },
    Refuse(Refusal),
}

/// One request the decoder is currently serving, as the scheduler sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Running {
    shape: Shape,
    /// Milliseconds since the scheduler's epoch when service began.
    started_ms: u64,
}

/// Slot accounting for one model.
///
/// Time is passed in by the host as milliseconds on any monotonic clock, so
/// this stays deterministic under test.
#[derive(Debug, Clone)]
pub struct Scheduler {
    slots: u32,
    policy: Policy,
    cost: CostModel,
    running: BTreeMap<u64, Running>,
    next_id: u64,
    waiting: u32,
}

impl Scheduler {
    pub fn new(slots: u32, policy: Policy) -> Self {
        Self {
            slots: slots.max(1),
            policy,
            cost: CostModel::new(),
            running: BTreeMap::new(),
            next_id: 1,
            waiting: 0,
        }
    }

    pub fn with_cost(mut self, cost: CostModel) -> Self {
        self.cost = cost;
        self
    }

    /// Replace the cost model in place — e.g. seeding from an operator's
    /// declared throughput after the scheduler already exists.
    pub fn set_cost(&mut self, cost: CostModel) {
        self.cost = cost;
    }

    pub fn cost(&self) -> &CostModel {
        &self.cost
    }

    pub fn slots(&self) -> u32 {
        self.slots
    }

    /// Change the slot count — e.g. after a model reload with a different
    /// `n_seq_max`. Running requests are unaffected.
    pub fn set_slots(&mut self, slots: u32) {
        self.slots = slots.max(1);
    }

    pub fn running(&self) -> u32 {
        self.running.len() as u32
    }

    pub fn waiting(&self) -> u32 {
        self.waiting
    }

    /// Milliseconds until the `k`-th slot frees (0-indexed), from the remaining
    /// work of what is running. Requests that overran their estimate count
    /// as freeing now: the estimate was wrong, not the request.
    fn eta_ms(&self, k: u32, now_ms: u64) -> u64 {
        let conc = self.running.len() as u32;
        let mut remaining: Vec<u64> = self
            .running
            .values()
            .map(|r| {
                let predicted = self.cost.predict(r.shape, conc).total_ms();
                predicted.saturating_sub(now_ms.saturating_sub(r.started_ms))
            })
            .collect();
        remaining.sort_unstable();
        if remaining.is_empty() {
            return 0;
        }
        // Slot k frees when the k-th running request does; past the running
        // set, every further position costs one more mean service time on
        // the slot that frees first.
        let n = remaining.len() as u32;
        if k < n {
            remaining[k as usize]
        } else {
            let mean = remaining.iter().sum::<u64>() / u64::from(n);
            remaining[0].saturating_add(mean.saturating_mul(u64::from(k - n + 1)))
        }
    }

    /// Decide for a request of `shape` and `class` arriving at `now_ms`.
    ///
    /// Pure: nothing changes until the host calls [`Scheduler::start`] or
    /// [`Scheduler::enqueue`]. A host that got `Wait` should enqueue, sleep
    /// for about the ETA (or until something finishes), and decide again.
    pub fn decide(&self, class: Class, shape: Shape, now_ms: u64) -> Decision {
        let _ = shape; // shape is not yet used for placement; kept for the API
        if self.running() < self.slots {
            return Decision::Admit;
        }
        if self.waiting >= self.policy.max_queue_depth {
            let conc = self.running.len() as u32;
            let mean = self
                .running
                .values()
                .map(|r| self.cost.predict(r.shape, conc).total_ms())
                .sum::<u64>()
                / u64::from(conc.max(1));
            return Decision::Refuse(Refusal::QueueFull {
                depth: self.waiting,
                limit: self.policy.max_queue_depth,
                retry_after_ms: mean.max(1_000),
            });
        }
        let position = self.waiting;
        let eta_ms = self.eta_ms(position, now_ms);
        let budget_ms = self.policy.wait_budget(class).as_millis() as u64;
        if eta_ms > budget_ms {
            return Decision::Refuse(Refusal::WaitTooLong { eta_ms, budget_ms });
        }
        Decision::Wait { eta: Duration::from_millis(eta_ms.max(50)), position }
    }

    /// Record that a request has joined the queue. Pair with
    /// [`Scheduler::dequeue`] whether it is later admitted or abandoned.
    pub fn enqueue(&mut self) {
        self.waiting = self.waiting.saturating_add(1);
    }

    pub fn dequeue(&mut self) {
        self.waiting = self.waiting.saturating_sub(1);
    }

    /// Record that service began. Returns a ticket for [`Scheduler::finish`].
    pub fn start(&mut self, shape: Shape, now_ms: u64) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.running.insert(id, Running { shape, started_ms: now_ms });
        id
    }

    /// Record completion and teach the cost model. `generated_tokens == 0`
    /// frees the slot without learning anything (the request never ran).
    pub fn finish(&mut self, ticket: u64, generated_tokens: u64, first_token_ms: Option<u64>, now_ms: u64) {
        let concurrency = self.running.len() as u32;
        let Some(r) = self.running.remove(&ticket) else {
            return;
        };
        self.cost.observe(Observation {
            prompt_tokens: r.shape.prompt_tokens,
            generated_tokens,
            budget_tokens: r.shape.max_output_tokens,
            service_ms: now_ms.saturating_sub(r.started_ms),
            first_token_ms,
            concurrency,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The spark, as measured 2026-09-01: 730 tok/s prefill, 31.6 tok/s decode.
    fn spark() -> CostModel {
        CostModel::from_rates(730, 31)
    }

    #[test]
    fn output_tokens_dominate_the_estimate() {
        let e = spark().predict(Shape::new(20, 1_000), 1);
        // 1,000 tokens at 31 tok/s is ~32 s; 20 tokens of prefill is nothing.
        assert!((31_000..34_000).contains(&e.total_ms()), "{e:?}");
        assert!(e.prefill_ms < 100);
    }

    #[test]
    fn a_long_generation_does_not_poison_the_next_short_one() {
        // The failure this module exists to fix: one 1,000-token answer must
        // not make a 200-token request look like 30 seconds of work.
        let mut c = spark();
        c.observe(Observation {
            prompt_tokens: 20,
            generated_tokens: 1_000,
            budget_tokens: 1_000,
            service_ms: 32_300,
            first_token_ms: Some(30),
            concurrency: 1,
        });
        let short = c.predict(Shape::new(200, 200), 1).total_ms();
        assert!(short < 8_000, "200 tokens predicted at {short} ms");
    }

    #[test]
    fn decode_rate_is_learned_from_scratch() {
        let mut c = CostModel::new();
        for _ in 0..8 {
            c.observe(Observation {
                prompt_tokens: 100,
                generated_tokens: 500,
                budget_tokens: 500,
                service_ms: 16_300, // 500 / 31 tok/s + a little prefill
                first_token_ms: Some(140),
                concurrency: 1,
            });
        }
        assert!((29..=33).contains(&c.decode_tok_per_s()), "{}", c.decode_tok_per_s());
        assert!((600..=800).contains(&c.prefill_tok_per_s()), "{}", c.prefill_tok_per_s());
    }

    #[test]
    fn concurrency_is_normalised_out_of_the_learned_rate() {
        // Two requests sharing the decoder each see ~half the solo rate.
        let mut c = CostModel::new();
        for _ in 0..8 {
            c.observe(Observation {
                prompt_tokens: 50,
                generated_tokens: 500,
                budget_tokens: 500,
                service_ms: 32_300,
                first_token_ms: Some(100),
                concurrency: 2,
            });
        }
        assert!((29..=33).contains(&c.decode_tok_per_s()), "{}", c.decode_tok_per_s());
        // And predicting for c=2 gives the wall time actually seen.
        let e = c.predict(Shape::new(50, 500), 2).total_ms();
        assert!((30_000..35_000).contains(&e), "{e}");
    }

    #[test]
    fn the_budget_asked_for_is_not_the_time_it_takes() {
        // Callers ask for 2,000 tokens and answer in 200. Until that has been
        // seen, the ceiling is the estimate; once seen, the estimate follows
        // the answers, and the caller behind a big budget is told a wait it
        // will actually get.
        let mut c = spark();
        let ceiling = c.predict(Shape::new(20, 2_000), 1).total_ms();
        assert!(ceiling > 60_000, "prior should price the whole budget: {ceiling}");
        for _ in 0..8 {
            c.observe(Observation {
                prompt_tokens: 20,
                generated_tokens: 200,
                budget_tokens: 2_000,
                service_ms: 6_500,
                first_token_ms: Some(30),
                concurrency: 1,
            });
        }
        assert!(c.budget_use_pct() < 30, "{}", c.budget_use_pct());
        let learned = c.predict(Shape::new(20, 2_000), 1).total_ms();
        assert!((5_000..20_000).contains(&learned), "{learned}");
    }

    #[test]
    fn short_answers_never_make_the_next_request_free() {
        let mut c = spark();
        for _ in 0..16 {
            c.observe(Observation {
                prompt_tokens: 20,
                generated_tokens: 1,
                budget_tokens: 4_000,
                service_ms: 60,
                first_token_ms: Some(30),
                concurrency: 1,
            });
        }
        // Floor: at least MIN_EXPECTED_OUTPUT_TOKENS of decode, ~1 s here.
        let e = c.predict(Shape::new(20, 4_000), 1).decode_ms;
        assert!(e >= 900, "{e}");
        // And never more than the budget asks for.
        let tiny = c.predict(Shape::new(20, 8), 1).decode_ms;
        assert!(tiny <= 300, "{tiny}");
    }

    #[test]
    fn a_free_slot_admits_regardless_of_the_estimate() {
        let s = Scheduler::new(2, Policy::default()).with_cost(spark());
        // 8k tokens is over four minutes of decode. It is still admitted:
        // the caller asked for it and a slot is free.
        assert_eq!(s.decide(Class::Interactive, Shape::new(1_000, 8_192), 0), Decision::Admit);
    }

    #[test]
    fn full_slots_give_an_eta_not_a_refusal() {
        let mut s = Scheduler::new(2, Policy::default()).with_cost(spark());
        s.start(Shape::new(100, 300), 0); // ~19 s at c=2
        s.start(Shape::new(100, 600), 0); // ~39 s at c=2
        match s.decide(Class::Interactive, Shape::new(200, 200), 5_000) {
            Decision::Wait { eta, position } => {
                assert_eq!(position, 0);
                // The first slot frees when the 300-token request does:
                // ~19.5 s predicted, 5 s elapsed.
                let ms = eta.as_millis() as u64;
                assert!((12_000..17_000).contains(&ms), "eta {ms}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn interactive_refuses_only_when_the_wait_itself_is_too_long() {
        let mut s = Scheduler::new(1, Policy::default()).with_cost(spark());
        s.start(Shape::new(100, 4_000), 0); // ~2 min of decode
        match s.decide(Class::Interactive, Shape::new(10, 10), 1_000) {
            Decision::Refuse(Refusal::WaitTooLong { eta_ms, budget_ms }) => {
                assert_eq!(budget_ms, 30_000);
                assert!(eta_ms > 100_000, "{eta_ms}");
            }
            other => panic!("{other:?}"),
        }
        // Batch will wait for it.
        assert!(matches!(s.decide(Class::Batch, Shape::new(10, 10), 1_000), Decision::Wait { .. }));
    }

    #[test]
    fn queue_positions_stack_behind_each_other() {
        let mut s = Scheduler::new(1, Policy::default()).with_cost(spark());
        s.start(Shape::new(100, 300), 0);
        let first = match s.decide(Class::Batch, Shape::new(10, 10), 0) {
            Decision::Wait { eta, .. } => eta,
            o => panic!("{o:?}"),
        };
        s.enqueue();
        let second = match s.decide(Class::Batch, Shape::new(10, 10), 0) {
            Decision::Wait { eta, position } => {
                assert_eq!(position, 1);
                eta
            }
            o => panic!("{o:?}"),
        };
        assert!(second > first, "{second:?} should follow {first:?}");
    }

    #[test]
    fn a_full_queue_fails_fast() {
        let mut s = Scheduler::new(1, Policy { max_queue_depth: 2, ..Policy::default() });
        s.start(Shape::new(10, 10), 0);
        s.enqueue();
        s.enqueue();
        assert!(matches!(
            s.decide(Class::Batch, Shape::new(10, 10), 0),
            Decision::Refuse(Refusal::QueueFull { depth: 2, limit: 2, .. })
        ));
    }

    #[test]
    fn overrunning_requests_count_as_about_to_free() {
        let mut s = Scheduler::new(1, Policy::default()).with_cost(spark());
        s.start(Shape::new(10, 100), 0); // ~3 s predicted
        // 60 s later it is still running: the estimate was wrong. Do not
        // punish the next caller for it.
        match s.decide(Class::Interactive, Shape::new(10, 10), 60_000) {
            Decision::Wait { eta, .. } => assert!(eta.as_millis() <= 50),
            o => panic!("{o:?}"),
        }
    }

    #[test]
    fn finish_frees_the_slot_and_teaches() {
        let mut s = Scheduler::new(1, Policy::default());
        let t = s.start(Shape::new(100, 500), 0);
        s.finish(t, 500, Some(140), 16_300);
        assert_eq!(s.running(), 0);
        assert_eq!(s.cost().samples(), 1);
        assert!((29..=33).contains(&s.cost().decode_tok_per_s()));
    }
}
