//! Runs the autotune controller against the live node.
//!
//! [`tenzro_model::autotune`] is a pure decision function: give it a
//! [`Snapshot`] and it proposes at most one [`Action`]. This is the part that
//! assembles that snapshot from the three live bounds, applies whatever comes
//! back, and keeps a log an operator can read.
//!
//! # Proposals are applied, not obeyed
//!
//! The controller cannot do anything this module does not do on its behalf,
//! and every action here is bounded and reversible. In particular it may
//! **not** evict a pinned model — pins come from operators and from paid
//! leases, and a controller that could undo either would be undoing a
//! commitment somebody is relying on. The controller already excludes pinned
//! models from its candidates; this layer re-checks rather than trusting it,
//! because a bug there would otherwise cost a renter their warm model.
//!
//! # Off by default
//!
//! A node that changes its own configuration is a node an operator has to
//! reason about during an incident. That should be opted into, not arrived
//! at. [`AutotuneConfig::enabled`] defaults to false, and when off the
//! sampler still records what it *would* have done — so an operator can watch
//! the decisions for a while before letting it act.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tenzro_model::autotune::{Action, Controller, ControllerConfig, Decision, Snapshot};
use tenzro_model::memory_budget::Tier;
use tracing::{info, warn};

/// How the sampler runs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AutotuneConfig {
    /// Whether proposals are applied. When false the sampler observes and
    /// records but changes nothing.
    pub enabled: bool,
    /// Seconds between samples.
    ///
    /// Ten seconds against the controller's five-sample window means it acts
    /// on roughly a minute of behaviour — long enough not to chase noise,
    /// short enough to respond inside a traffic spike.
    pub interval_secs: u64,
    /// Decisions retained for operator inspection.
    pub log_capacity: usize,
}

impl Default for AutotuneConfig {
    fn default() -> Self {
        Self {
            // Off. A self-modifying node is opted into.
            enabled: false,
            interval_secs: 10,
            log_capacity: 100,
        }
    }
}

/// A decision, when it was taken, and whether it was acted on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LoggedDecision {
    /// Milliseconds since the sampler started.
    pub at_ms: u64,
    /// What the controller proposed.
    pub action: Action,
    /// Why, citing the measurements it acted on.
    pub why: String,
    /// Whether it was applied, or only observed.
    pub applied: bool,
    /// Why it was not applied, when it was not.
    pub skipped_reason: Option<String>,
}

/// Owns the controller and its decision log.
///
/// Held on the node so `Drop` aborts the task at shutdown.
#[derive(Debug)]
pub struct AutotuneSampler {
    log: Arc<Mutex<Vec<LoggedDecision>>>,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl Drop for AutotuneSampler {
    fn drop(&mut self) {
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

impl AutotuneSampler {
    /// Decisions taken so far, oldest first.
    pub fn decisions(&self) -> Vec<LoggedDecision> {
        self.log.lock().clone()
    }

    /// Start sampling `node` on a background task.
    pub fn spawn(node: Arc<crate::node::TenzroNode>, config: AutotuneConfig) -> Self {
        let log = Arc::new(Mutex::new(Vec::new()));
        let log_for_task = Arc::clone(&log);
        let started = Instant::now();

        let traffic = Arc::clone(node.traffic());
        let baseline = traffic.stats();
        let mut controller = Controller::new(
            ControllerConfig::default(),
            baseline.max_concurrent,
            // The batch ceiling is not on TrafficStats; half the total is the
            // configured default and the right anchor to drift around.
            (baseline.max_concurrent / 2).max(1),
        );

        info!(
            enabled = config.enabled,
            interval_secs = config.interval_secs,
            "Autotune sampler started"
        );

        let handle = tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval(Duration::from_secs(config.interval_secs.max(1)));
            // The first tick fires immediately; skip it so the first real
            // sample reflects a running node rather than one still starting.
            ticker.tick().await;

            loop {
                ticker.tick().await;
                let snapshot = build_snapshot(&node);
                let Some(decision) = controller.observe(snapshot) else {
                    continue;
                };

                let (applied, skipped_reason) = if config.enabled {
                    apply(&node, &decision).await
                } else {
                    (
                        false,
                        Some("autotune is observing only; enable it to apply".to_string()),
                    )
                };

                info!(
                    action = ?decision.action,
                    applied,
                    why = %decision.why,
                    "Autotune decision"
                );

                let mut log = log_for_task.lock();
                log.push(LoggedDecision {
                    at_ms: started.elapsed().as_millis() as u64,
                    action: decision.action,
                    why: decision.why,
                    applied,
                    skipped_reason,
                });
                let cap = config.log_capacity.max(1);
                if log.len() > cap {
                    let excess = log.len() - cap;
                    log.drain(0..excess);
                }
            }
        });

        Self {
            log,
            handle: Some(handle),
        }
    }
}

/// Assemble a reading from the three live bounds.
fn build_snapshot(node: &Arc<crate::node::TenzroNode>) -> Snapshot {
    let traffic = node.traffic().stats();
    let budget = tenzro_model::memory_budget::global().snapshot();
    let resident = budget.tiers.iter().find(|t| t.tier == Tier::Resident);

    let mut warm_idle_ms = HashMap::new();
    let mut pinned = Vec::new();
    for model_id in node.lifecycle().warm_models() {
        if let tenzro_model::lifecycle::ModelState::Warm { idle_ms, .. } =
            node.lifecycle().state(&model_id)
        {
            warm_idle_ms.insert(model_id.clone(), idle_ms);
        }
        if node.lifecycle().is_pinned(&model_id) {
            pinned.push(model_id);
        }
    }

    Snapshot {
        goodput_pct: traffic.goodput_pct,
        in_flight: traffic.in_flight_interactive + traffic.in_flight_batch,
        max_concurrent: traffic.max_concurrent,
        max_concurrent_batch: (traffic.max_concurrent / 2).max(1),
        refused_capacity: traffic.refused,
        refused_deadline: 0,
        shed_batch: 0,
        resident_available_bytes: resident.map(|t| t.available_bytes).unwrap_or(0),
        resident_ceiling_bytes: resident.map(|t| t.ceiling_bytes).unwrap_or(0),
        // Cold-request counts are not tracked yet; without them the
        // controller will not propose a prewarm. That is a missing input, not
        // a wrong one — better than feeding it a fabricated number.
        cold_requests: HashMap::new(),
        warm_idle_ms,
        pinned,
    }
}

/// Carry out a decision. Returns whether it was applied, and why not if not.
async fn apply(node: &Arc<crate::node::TenzroNode>, decision: &Decision) -> (bool, Option<String>) {
    match &decision.action {
        Action::EvictIdle { model_id } => {
            // Re-checked here rather than trusted from the controller. A pin
            // is an operator's decision or a renter's paid guarantee, and a
            // bug upstream must not be able to undo either.
            if node.lifecycle().is_pinned(model_id) {
                return (
                    false,
                    Some(format!("{model_id} is pinned; refusing to evict")),
                );
            }
            if !node.lifecycle().begin_evict(model_id) {
                return (
                    false,
                    Some(format!("{model_id} became busy before eviction")),
                );
            }
            match node.model_runtime_arc() {
                Some(runtime) => match runtime.unload_model(model_id).await {
                    Ok(()) => {
                        node.lifecycle().finish_evict(model_id);
                        (true, None)
                    }
                    Err(e) => {
                        // Still resident, so it goes back to warm rather than
                        // being recorded as evicted — otherwise the budget and
                        // reality diverge permanently.
                        node.lifecycle().finish_warm(model_id, Duration::ZERO);
                        (false, Some(format!("unload failed: {e}")))
                    }
                },
                None => (false, Some("no model runtime".to_string())),
            }
        }
        // The remaining actions adjust dials that are fixed at construction
        // today. Recording them is still useful: an operator can see what the
        // controller wanted and decide whether to set it by hand.
        Action::ShrinkConcurrency { .. }
        | Action::GrowConcurrency { .. }
        | Action::RebalanceBatchShare { .. } => (
            false,
            Some(
                "concurrency dials are fixed at startup; the proposal is recorded for the \
                 operator rather than applied"
                    .to_string(),
            ),
        ),
        Action::Prewarm { model_id } => {
            warn!(model_id = %model_id, "Prewarm proposed but not yet wired");
            (
                false,
                Some("prewarm is not wired to the load path yet".to_string()),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autotune_is_off_unless_an_operator_turns_it_on() {
        // A node that rewrites its own configuration is one an operator has to
        // reason about mid-incident. That is opted into.
        let c = AutotuneConfig::default();
        assert!(!c.enabled);
        assert!(c.interval_secs > 0, "a zero interval would spin");
    }

    #[test]
    fn the_sampling_interval_covers_a_meaningful_window() {
        // The controller smooths over five samples, so the interval decides
        // how much history one decision reflects. Ten seconds is about a
        // minute of behaviour — long enough not to chase noise.
        let c = AutotuneConfig::default();
        let window_secs = c.interval_secs * 5;
        assert!(
            (30..=180).contains(&window_secs),
            "window of {window_secs}s is outside the useful range"
        );
    }

    #[test]
    fn the_decision_log_is_bounded() {
        // It runs forever; an unbounded log is a slow memory leak.
        assert!(AutotuneConfig::default().log_capacity > 0);
        assert!(AutotuneConfig::default().log_capacity <= 10_000);
    }
}
