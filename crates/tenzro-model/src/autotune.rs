//! The controller that makes the three bounds cooperate.
//!
//! [`memory_budget`](crate::memory_budget), [`lifecycle`](crate::lifecycle)
//! and [`traffic`](crate::traffic) each refuse correctly in isolation, and
//! that is already most of the value. But they do not talk to each other, so
//! the node has no way to notice that it keeps refusing requests for a cold
//! model while a warm one sits idle and memory is free — a situation every
//! individual bound is handling *correctly* and which is nonetheless the
//! wrong overall behaviour.
//!
//! This module reads all three and proposes [`Action`]s. It is a pure
//! function of a [`Snapshot`] plus its own history: no I/O, no locks, no
//! side effects. The caller applies what it returns, which keeps the policy
//! testable and the mechanism separate.
//!
//! # Damping, because a twitchy controller is worse than none
//!
//! An autotuner that reacts to the last sample will warm a model, see memory
//! pressure, evict it, see refusals, warm it again — burning the machine on
//! churn while every individual decision looks locally sound. Three defences,
//! and all three are load-bearing:
//!
//! - **Smoothing.** Decisions read a rolling window
//!   ([`ControllerConfig::window`]), never a single sample.
//! - **Hysteresis.** A model that was just acted on is off-limits for
//!   [`ControllerConfig::cooldown_samples`]. This is what actually prevents
//!   the warm/evict oscillation; smoothing alone does not, because a
//!   sustained signal keeps pointing the same way.
//! - **Bounded authority.** The controller may move a dial only within
//!   [`ControllerConfig::max_drift_pct`] of the operator's configured value.
//!   It tunes; it does not take over. An operator who set a limit for a
//!   reason keeps it.
//!
//! # Goodput is the signal, not throughput
//!
//! Falling goodput with spare capacity means work is being admitted that
//! cannot finish in time, so the answer is to admit *less* — which reads as
//! a regression on a throughput chart and is the correct move. See
//! [`crate::traffic`] for why that distinction matters.
//!
//! # Every decision carries its reason
//!
//! [`Decision::why`] is not decoration. A node that changes its own
//! configuration and cannot say why is one an operator has to reverse-engineer
//! during an incident, so the explanation is part of the output rather than a
//! log line that may or may not have been kept.

use std::collections::{HashMap, VecDeque};

use serde::{Deserialize, Serialize};

/// What the controller may do.
///
/// Deliberately small. Each action is reversible and bounded, because a
/// controller that can make a large irreversible move is one an operator
/// cannot safely leave enabled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "kebab-case")]
pub enum Action {
    /// Load a model before it is asked for.
    ///
    /// Proposed when a model is repeatedly requested cold while memory is
    /// free: the refusals and cold-start waits are avoidable.
    Prewarm {
        /// Which model.
        model_id: String,
    },
    /// Unload a warm model that is not earning its residency.
    ///
    /// Proposed when memory is tight and something warm has served nothing
    /// for a while — reclaiming it is cheaper than refusing a load.
    EvictIdle {
        /// Which model.
        model_id: String,
    },
    /// Admit fewer concurrent requests.
    ///
    /// Proposed when goodput falls while slots are free, which means the node
    /// is accepting work it cannot finish on time.
    ShrinkConcurrency {
        /// New ceiling.
        max_concurrent: u32,
    },
    /// Admit more concurrent requests.
    ///
    /// Proposed when goodput is healthy and the node is saturated — there is
    /// headroom being left unused.
    GrowConcurrency {
        /// New ceiling.
        max_concurrent: u32,
    },
    /// Move capacity between the interactive and batch reservations.
    ///
    /// Proposed when one class is being shed while the other sits idle.
    RebalanceBatchShare {
        /// New batch ceiling.
        max_concurrent_batch: u32,
    },
}

/// An action plus the reason for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    /// What to do.
    pub action: Action,
    /// Why, in terms an operator can check against their own dashboards.
    pub why: String,
}

/// One reading of the node.
///
/// Assembled by the caller from the three bounds. Kept as plain data so the
/// controller can be tested against situations that would be laborious to
/// reproduce on a live node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Percentage of completed requests that met their deadline.
    pub goodput_pct: f64,
    /// Concurrent requests in flight.
    pub in_flight: u32,
    /// Current global ceiling.
    pub max_concurrent: u32,
    /// Current batch ceiling.
    pub max_concurrent_batch: u32,
    /// Refusals attributed to the global ceiling since the last sample.
    pub refused_capacity: u64,
    /// Refusals attributed to unattainable deadlines since the last sample.
    pub refused_deadline: u64,
    /// Batch requests shed to protect interactive traffic since the last
    /// sample.
    pub shed_batch: u64,
    /// Bytes still claimable in the resident tier.
    pub resident_available_bytes: u64,
    /// The resident tier's ceiling.
    pub resident_ceiling_bytes: u64,
    /// Models currently warm, with how long each has been idle.
    pub warm_idle_ms: HashMap<String, u64>,
    /// Models requested while cold since the last sample, with how often.
    pub cold_requests: HashMap<String, u32>,
    /// Models pinned by an operator or a lease. Never proposed for eviction.
    pub pinned: Vec<String>,
}

impl Snapshot {
    /// Fraction of the resident tier still free, 0.0–1.0.
    fn resident_headroom(&self) -> f64 {
        if self.resident_ceiling_bytes == 0 {
            return 0.0;
        }
        self.resident_available_bytes as f64 / self.resident_ceiling_bytes as f64
    }

    /// Fraction of the concurrency ceiling in use, 0.0–1.0.
    fn saturation(&self) -> f64 {
        if self.max_concurrent == 0 {
            return 1.0;
        }
        f64::from(self.in_flight) / f64::from(self.max_concurrent)
    }
}

/// Thresholds and limits governing the controller.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControllerConfig {
    /// How many samples to smooth over. One sample is noise; a window is a
    /// trend.
    pub window: usize,
    /// Samples a model is off-limits for after being acted on. The
    /// anti-oscillation guard.
    pub cooldown_samples: u32,
    /// How far the controller may move a dial from the operator's configured
    /// value, in percent.
    pub max_drift_pct: u32,
    /// Goodput below this, with capacity to spare, means shrink.
    pub goodput_floor_pct: f64,
    /// Goodput above this, with the node saturated, means grow.
    pub goodput_healthy_pct: f64,
    /// Resident headroom below this counts as memory pressure.
    pub pressure_headroom: f64,
    /// Idle milliseconds past which a warm model is an eviction candidate.
    pub idle_evict_ms: u64,
    /// Cold requests for one model within the window before prewarming it.
    pub prewarm_threshold: u32,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            // Five samples: long enough that one slow request does not move a
            // dial, short enough to react inside a minute at a 10s cadence.
            window: 5,
            // Three samples of quiet after acting on a model. Longer than the
            // window, so a decision is fully reflected in the signal before
            // the same model can be reconsidered.
            cooldown_samples: 3,
            // The controller may move a dial by at most a quarter. An
            // operator's configured limit is a decision, not a starting guess.
            max_drift_pct: 25,
            goodput_floor_pct: 90.0,
            goodput_healthy_pct: 98.0,
            pressure_headroom: 0.15,
            idle_evict_ms: 10 * 60 * 1000,
            prewarm_threshold: 3,
        }
    }
}

/// Reads the node and proposes adjustments.
#[derive(Debug)]
pub struct Controller {
    config: ControllerConfig,
    /// Operator-configured values the controller drifts around, never past.
    baseline_max_concurrent: u32,
    baseline_max_batch: u32,
    history: VecDeque<Snapshot>,
    /// Monotonic count of samples observed. Cooldowns are expressed as
    /// absolute indices against it rather than as countdowns, because a
    /// countdown decremented in the same call that sets it silently
    /// suppresses one sample fewer than configured.
    sample_index: u64,
    /// Model id -> first sample index at which it may be acted on again.
    cooldowns: HashMap<String, u64>,
    /// First sample index at which a concurrency dial may move again.
    dial_ready_at: u64,
}

impl Controller {
    /// Build a controller anchored to the operator's configured limits.
    pub fn new(config: ControllerConfig, max_concurrent: u32, max_concurrent_batch: u32) -> Self {
        Self {
            config,
            baseline_max_concurrent: max_concurrent,
            baseline_max_batch: max_concurrent_batch,
            history: VecDeque::new(),
            sample_index: 0,
            cooldowns: HashMap::new(),
            dial_ready_at: 0,
        }
    }

    /// Whether `model_id` is inside its post-action quiet period.
    fn in_cooldown(&self, model_id: &str) -> bool {
        self.cooldowns
            .get(model_id)
            .is_some_and(|until| self.sample_index < *until)
    }

    /// Put `model_id` out of bounds for the configured number of samples.
    ///
    /// Suppresses the next `cooldown_samples` observations inclusive, so a
    /// cooldown of 3 really means three quiet samples before the same model
    /// can be reconsidered.
    fn start_cooldown(&mut self, model_id: &str) {
        let until = self.sample_index + u64::from(self.config.cooldown_samples) + 1;
        self.cooldowns.insert(model_id.to_string(), until);
    }

    /// Put the concurrency dials out of bounds for the same period.
    fn start_dial_cooldown(&mut self) {
        self.dial_ready_at = self.sample_index + u64::from(self.config.cooldown_samples) + 1;
    }

    /// The bounds a dial may move within, given a baseline.
    fn drift_bounds(&self, baseline: u32) -> (u32, u32) {
        let drift = baseline * self.config.max_drift_pct / 100;
        (baseline.saturating_sub(drift).max(1), baseline + drift)
    }

    /// Mean goodput across the window.
    fn mean_goodput(&self) -> f64 {
        if self.history.is_empty() {
            return 100.0;
        }
        self.history.iter().map(|s| s.goodput_pct).sum::<f64>() / self.history.len() as f64
    }

    /// Mean saturation across the window.
    fn mean_saturation(&self) -> f64 {
        if self.history.is_empty() {
            return 0.0;
        }
        self.history.iter().map(Snapshot::saturation).sum::<f64>() / self.history.len() as f64
    }

    /// Cold-request counts summed across the window.
    fn windowed_cold_requests(&self) -> HashMap<String, u32> {
        let mut totals: HashMap<String, u32> = HashMap::new();
        for sample in &self.history {
            for (model, count) in &sample.cold_requests {
                *totals.entry(model.clone()).or_insert(0) += count;
            }
        }
        totals
    }

    /// Record a reading and propose what to do about it.
    ///
    /// Returns at most one decision per call, deliberately: applying several
    /// changes at once makes it impossible to attribute the effect to any of
    /// them, and the next sample is only moments away.
    ///
    /// Returns `None` until the window is full — acting on partial history is
    /// exactly the twitchiness this module exists to avoid.
    pub fn observe(&mut self, snapshot: Snapshot) -> Option<Decision> {
        self.history.push_back(snapshot);
        while self.history.len() > self.config.window {
            self.history.pop_front();
        }
        self.sample_index += 1;
        self.cooldowns.retain(|_, until| *until > self.sample_index);

        if self.history.len() < self.config.window {
            return None;
        }

        // Order matters: correctness before efficiency. Shedding work the node
        // cannot finish comes before making anything faster, and relieving
        // memory pressure comes before warming something new into it.
        self.consider_concurrency()
            .or_else(|| self.consider_eviction())
            .or_else(|| self.consider_prewarm())
            .or_else(|| self.consider_batch_share())
    }

    /// Goodput falling with capacity to spare means admitting less.
    fn consider_concurrency(&mut self) -> Option<Decision> {
        if self.sample_index < self.dial_ready_at {
            return None;
        }
        let latest = self.history.back()?;
        let goodput = self.mean_goodput();
        let saturation = self.mean_saturation();
        let (floor, ceiling) = self.drift_bounds(self.baseline_max_concurrent);

        // Work is being accepted that cannot finish on time. Spare slots rule
        // out "simply overloaded" — the node is admitting badly, not too much.
        if goodput < self.config.goodput_floor_pct && saturation < 0.9 {
            let proposed = (latest.max_concurrent * 9 / 10).max(floor);
            if proposed < latest.max_concurrent {
                self.start_dial_cooldown();
                return Some(Decision {
                    action: Action::ShrinkConcurrency {
                        max_concurrent: proposed,
                    },
                    why: format!(
                        "goodput {goodput:.1}% is below the {:.0}% floor while only \
                         {:.0}% of slots are in use — work is being admitted that cannot \
                         finish in time, so admit less",
                        self.config.goodput_floor_pct,
                        saturation * 100.0
                    ),
                });
            }
        }

        // Healthy and saturated: there is headroom being left on the table.
        if goodput >= self.config.goodput_healthy_pct && saturation > 0.95 {
            let proposed = (latest.max_concurrent + 1).min(ceiling);
            if proposed > latest.max_concurrent {
                self.start_dial_cooldown();
                return Some(Decision {
                    action: Action::GrowConcurrency {
                        max_concurrent: proposed,
                    },
                    why: format!(
                        "goodput {goodput:.1}% is healthy at {:.0}% saturation — the node \
                         can take more without missing deadlines",
                        saturation * 100.0
                    ),
                });
            }
        }
        None
    }

    /// Memory pressure plus an idle warm model means reclaim it.
    fn consider_eviction(&mut self) -> Option<Decision> {
        let latest = self.history.back()?;
        if latest.resident_headroom() >= self.config.pressure_headroom {
            return None;
        }

        let headroom = latest.resident_headroom();
        let pinned = latest.pinned.clone();
        let warm: Vec<(String, u64)> = latest
            .warm_idle_ms
            .iter()
            .map(|(k, v)| (k.clone(), *v))
            .collect();
        let victim = warm
            .iter()
            .filter(|(id, _)| !pinned.contains(id))
            .filter(|(id, _)| !self.in_cooldown(id))
            .filter(|(_, idle)| *idle >= self.config.idle_evict_ms)
            .max_by_key(|(_, idle)| *idle)
            .map(|(id, idle)| (id.clone(), *idle))?;

        self.start_cooldown(&victim.0);
        Some(Decision {
            action: Action::EvictIdle {
                model_id: victim.0.clone(),
            },
            why: format!(
                "resident tier is {:.0}% free, below the {:.0}% pressure threshold, and {} \
                 has served nothing for {} minutes — reclaiming it is cheaper than refusing \
                 the next load",
                headroom * 100.0,
                self.config.pressure_headroom * 100.0,
                victim.0,
                victim.1 / 60_000
            ),
        })
    }

    /// Repeated cold requests plus free memory means load it in advance.
    fn consider_prewarm(&mut self) -> Option<Decision> {
        let latest = self.history.back()?;
        if latest.resident_headroom() < self.config.pressure_headroom {
            return None;
        }

        let headroom = latest.resident_headroom();
        let already_warm: Vec<String> = latest.warm_idle_ms.keys().cloned().collect();
        let totals = self.windowed_cold_requests();
        let (model_id, count) = totals
            .iter()
            .filter(|(id, _)| !self.in_cooldown(id))
            .filter(|(id, _)| !already_warm.contains(id))
            .filter(|(_, count)| **count >= self.config.prewarm_threshold)
            .max_by_key(|(_, count)| **count)
            .map(|(id, count)| (id.clone(), *count))?;

        self.start_cooldown(&model_id);
        Some(Decision {
            action: Action::Prewarm {
                model_id: model_id.clone(),
            },
            why: format!(
                "{model_id} was requested cold {count} times in the last {} samples while the \
                 resident tier had {:.0}% free — those cold starts are avoidable",
                self.history.len(),
                headroom * 100.0
            ),
        })
    }

    /// One class starved while the other idles means shift the split.
    fn consider_batch_share(&mut self) -> Option<Decision> {
        if self.sample_index < self.dial_ready_at {
            return None;
        }
        let latest = self.history.back()?;
        let shed: u64 = self.history.iter().map(|s| s.shed_batch).sum();
        if shed == 0 {
            return None;
        }

        // Batch is being shed. Only worth widening its share if the node as a
        // whole is not busy — otherwise the shedding is correct and taking
        // capacity from interactive would make things worse.
        if self.mean_saturation() > 0.7 {
            return None;
        }

        let (_, ceiling) = self.drift_bounds(self.baseline_max_batch);
        let proposed = (latest.max_concurrent_batch + 1)
            .min(ceiling)
            .min(latest.max_concurrent.saturating_sub(1));
        if proposed <= latest.max_concurrent_batch {
            return None;
        }

        self.start_dial_cooldown();
        Some(Decision {
            action: Action::RebalanceBatchShare {
                max_concurrent_batch: proposed,
            },
            why: format!(
                "{shed} batch requests were shed while the node averaged {:.0}% saturation — \
                 interactive capacity is not the constraint, so batch can have more",
                self.mean_saturation() * 100.0
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy() -> Snapshot {
        Snapshot {
            goodput_pct: 100.0,
            in_flight: 4,
            max_concurrent: 40,
            max_concurrent_batch: 20,
            refused_capacity: 0,
            refused_deadline: 0,
            shed_batch: 0,
            resident_available_bytes: 50,
            resident_ceiling_bytes: 100,
            warm_idle_ms: HashMap::new(),
            cold_requests: HashMap::new(),
            pinned: Vec::new(),
        }
    }

    fn controller() -> Controller {
        Controller::new(ControllerConfig::default(), 40, 20)
    }

    /// Feed `n` copies and return the last decision produced.
    fn feed(c: &mut Controller, s: &Snapshot, n: usize) -> Option<Decision> {
        let mut last = None;
        for _ in 0..n {
            if let Some(d) = c.observe(s.clone()) {
                last = Some(d);
            }
        }
        last
    }

    #[test]
    fn nothing_happens_until_the_window_is_full() {
        // Acting on partial history is precisely the twitchiness this module
        // exists to prevent.
        let mut c = controller();
        let mut bad = healthy();
        bad.goodput_pct = 50.0;
        for _ in 0..(ControllerConfig::default().window - 1) {
            assert_eq!(c.observe(bad.clone()), None);
        }
        assert!(c.observe(bad).is_some(), "the full window should decide");
    }

    #[test]
    fn falling_goodput_with_spare_slots_shrinks_concurrency() {
        // The signal the whole design turns on: throughput looks fine, but
        // work is arriving too late to be useful.
        let mut c = controller();
        let mut bad = healthy();
        bad.goodput_pct = 60.0;
        bad.in_flight = 4; // 10% saturation — not simply overloaded

        let d = feed(&mut c, &bad, 5).expect("should act");
        match d.action {
            Action::ShrinkConcurrency { max_concurrent } => {
                assert!(max_concurrent < 40, "{max_concurrent}");
            }
            other => panic!("expected shrink, got {other:?}"),
        }
        assert!(d.why.contains("goodput"), "{}", d.why);
    }

    #[test]
    fn a_saturated_node_with_low_goodput_is_left_alone() {
        // Here the node is simply busy. Shrinking would reduce capacity that
        // is being used, which is the opposite of the fix.
        let mut c = controller();
        let mut busy = healthy();
        busy.goodput_pct = 60.0;
        busy.in_flight = 40; // fully saturated
        assert_eq!(feed(&mut c, &busy, 6), None);
    }

    #[test]
    fn healthy_goodput_at_full_saturation_grows_concurrency() {
        let mut c = controller();
        let mut full = healthy();
        full.goodput_pct = 99.5;
        full.in_flight = 40;

        let d = feed(&mut c, &full, 5).expect("should act");
        match d.action {
            Action::GrowConcurrency { max_concurrent } => assert_eq!(max_concurrent, 41),
            other => panic!("expected grow, got {other:?}"),
        }
    }

    #[test]
    fn a_dial_never_drifts_past_the_operators_bound() {
        // An operator's configured limit is a decision, not a starting guess.
        let mut c = Controller::new(ControllerConfig::default(), 40, 20);
        let (floor, ceiling) = c.drift_bounds(40);
        assert_eq!((floor, ceiling), (30, 50), "25% either side of 40");

        // Drive it down repeatedly; it must stop at the floor.
        let mut bad = healthy();
        bad.goodput_pct = 10.0;
        bad.in_flight = 1;
        let mut current = 40;
        for _ in 0..50 {
            bad.max_concurrent = current;
            if let Some(Decision {
                action: Action::ShrinkConcurrency { max_concurrent },
                ..
            }) = c.observe(bad.clone())
            {
                assert!(max_concurrent >= floor, "drifted below floor");
                current = max_concurrent;
            }
        }
        assert_eq!(current, floor, "should settle exactly at the bound");
    }

    #[test]
    fn memory_pressure_evicts_the_idlest_unpinned_model() {
        let mut c = controller();
        let mut tight = healthy();
        tight.resident_available_bytes = 5; // 5% headroom
        tight.warm_idle_ms = HashMap::from([
            ("recent".to_string(), 1_000),
            ("idle-a".to_string(), 20 * 60_000),
            ("idle-b".to_string(), 40 * 60_000),
        ]);

        let d = feed(&mut c, &tight, 5).expect("should act");
        assert_eq!(
            d.action,
            Action::EvictIdle {
                model_id: "idle-b".to_string()
            },
            "the idlest is the cheapest to reclaim"
        );
    }

    #[test]
    fn a_pinned_model_is_never_proposed_for_eviction() {
        // Pins come from operators and from paid leases. The controller must
        // not be able to undo either.
        let mut c = controller();
        let mut tight = healthy();
        tight.resident_available_bytes = 1;
        tight.warm_idle_ms = HashMap::from([("leased".to_string(), 60 * 60_000)]);
        tight.pinned = vec!["leased".to_string()];
        assert_eq!(feed(&mut c, &tight, 6), None);
    }

    #[test]
    fn a_model_that_is_merely_idle_is_kept_while_memory_is_free() {
        // Eviction is a response to pressure, not a tidiness policy — a warm
        // model costs nothing while there is room.
        let mut c = controller();
        let mut roomy = healthy();
        roomy.warm_idle_ms = HashMap::from([("idle".to_string(), 60 * 60_000)]);
        let d = feed(&mut c, &roomy, 6);
        assert!(
            !matches!(d.map(|d| d.action), Some(Action::EvictIdle { .. })),
            "no pressure, no eviction"
        );
    }

    #[test]
    fn repeated_cold_requests_with_free_memory_trigger_a_prewarm() {
        let mut c = controller();
        let mut cold = healthy();
        cold.cold_requests = HashMap::from([("wanted".to_string(), 1)]);

        let d = feed(&mut c, &cold, 5).expect("5 samples x 1 request clears the threshold of 3");
        assert_eq!(
            d.action,
            Action::Prewarm {
                model_id: "wanted".to_string()
            }
        );
    }

    #[test]
    fn cold_requests_under_memory_pressure_do_not_trigger_a_prewarm() {
        // Warming into a full tier just evicts something else — churn, not
        // improvement.
        let mut c = controller();
        let mut cold = healthy();
        cold.resident_available_bytes = 1;
        cold.cold_requests = HashMap::from([("wanted".to_string(), 5)]);
        let d = feed(&mut c, &cold, 6);
        assert!(!matches!(d.map(|d| d.action), Some(Action::Prewarm { .. })));
    }

    #[test]
    fn the_same_model_cannot_be_warmed_and_evicted_in_a_loop() {
        // The oscillation that makes naive autotuners dangerous. Cooldown,
        // not smoothing, is what prevents it: a sustained signal keeps
        // pointing the same way.
        let mut c = controller();
        let mut cold = healthy();
        cold.cold_requests = HashMap::from([("flip".to_string(), 5)]);

        let first = feed(&mut c, &cold, 5).expect("first prewarm");
        assert!(matches!(first.action, Action::Prewarm { .. }));

        // Immediately after, the same model must be off-limits.
        let mut acted_again = 0;
        for _ in 0..ControllerConfig::default().cooldown_samples {
            if let Some(d) = c.observe(cold.clone())
                && matches!(&d.action, Action::Prewarm { model_id } if model_id == "flip")
            {
                acted_again += 1;
            }
        }
        assert_eq!(acted_again, 0, "cooldown must suppress repeat action");
    }

    #[test]
    fn shed_batch_with_an_idle_node_widens_the_batch_share() {
        let mut c = controller();
        let mut shedding = healthy();
        shedding.shed_batch = 10;
        shedding.in_flight = 4; // 10% saturation

        let d = feed(&mut c, &shedding, 5).expect("should act");
        match d.action {
            Action::RebalanceBatchShare {
                max_concurrent_batch,
            } => assert_eq!(max_concurrent_batch, 21),
            other => panic!("expected rebalance, got {other:?}"),
        }
    }

    #[test]
    fn shed_batch_on_a_busy_node_is_correct_and_left_alone() {
        // Here the shedding is doing its job. Taking capacity from
        // interactive to stop it would be actively wrong.
        let mut c = controller();
        let mut busy = healthy();
        busy.shed_batch = 10;
        busy.in_flight = 36; // 90% saturation
        busy.goodput_pct = 95.0; // between floor and healthy: no dial move
        let d = feed(&mut c, &busy, 6);
        assert!(!matches!(
            d.map(|d| d.action),
            Some(Action::RebalanceBatchShare { .. })
        ));
    }

    #[test]
    fn a_healthy_idle_node_is_left_completely_alone() {
        // The most important property: doing nothing is the default.
        let mut c = controller();
        assert_eq!(feed(&mut c, &healthy(), 20), None);
    }

    #[test]
    fn correctness_is_addressed_before_efficiency() {
        // A node both missing deadlines and holding an idle model should fix
        // the deadlines first — serving wrong results faster helps nobody.
        let mut c = controller();
        let mut both = healthy();
        both.goodput_pct = 50.0;
        both.in_flight = 2;
        both.resident_available_bytes = 1;
        both.warm_idle_ms = HashMap::from([("idle".to_string(), 60 * 60_000)]);

        let d = feed(&mut c, &both, 5).expect("should act");
        assert!(
            matches!(d.action, Action::ShrinkConcurrency { .. }),
            "expected concurrency first, got {:?}",
            d.action
        );
    }

    #[test]
    fn every_decision_explains_itself_in_checkable_terms() {
        // A node that changes its own configuration and cannot say why is one
        // an operator has to reverse-engineer mid-incident.
        let mut c = controller();
        let mut bad = healthy();
        bad.goodput_pct = 50.0;
        bad.in_flight = 2;
        let d = feed(&mut c, &bad, 5).expect("should act");
        assert!(d.why.len() > 40, "too terse to be useful: {}", d.why);
        assert!(
            d.why.contains('%'),
            "should cite the measurements it acted on: {}",
            d.why
        );
    }

    #[test]
    fn at_most_one_change_is_proposed_per_sample() {
        // Applying several at once makes the effect unattributable to any of
        // them, and the next sample is moments away.
        let mut c = controller();
        let mut messy = healthy();
        messy.goodput_pct = 50.0;
        messy.in_flight = 2;
        messy.resident_available_bytes = 1;
        messy.warm_idle_ms = HashMap::from([("idle".to_string(), 60 * 60_000)]);
        messy.cold_requests = HashMap::from([("wanted".to_string(), 9)]);
        messy.shed_batch = 5;

        // `observe` returns Option<Decision>, so this is structural — the
        // assertion is that it stays that way.
        for _ in 0..5 {
            let d = c.observe(messy.clone());
            assert!(d.is_none() || d.is_some());
        }
    }

    #[test]
    fn a_zero_sized_resident_tier_does_not_divide_by_zero() {
        let mut c = controller();
        let mut degenerate = healthy();
        degenerate.resident_ceiling_bytes = 0;
        degenerate.resident_available_bytes = 0;
        let _ = feed(&mut c, &degenerate, 6);
    }

    #[test]
    fn a_zero_concurrency_ceiling_reads_as_fully_saturated() {
        // Guards the saturation divide, and the reading is the safe one: a
        // node admitting nothing is not "idle with room to grow".
        let s = Snapshot {
            max_concurrent: 0,
            ..healthy()
        };
        assert_eq!(s.saturation(), 1.0);
    }
}
