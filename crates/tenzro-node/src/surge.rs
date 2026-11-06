//! Opt-in surge loading.
//!
//! An operator who enables `[surge]` lets the node load a catalogued model
//! when a forecast of demand in the node's region rises above the
//! operator's threshold, and unload it once demand falls. Demand in the
//! region is the requests in flight at the providers that announce the
//! node's own region and serve one of the operator's surge models. A load
//! goes through the node's ordinary serve path (catalog fetch, then the
//! model host's admitted load); a surge never introduces a loader of its own.
//!
//! A surge load must fit what is left of the memory budget after the models
//! of the active and next scheduled stacks are set aside, and the network's
//! observed price for the model must meet the operator's floor. Anything else
//! is refused with a warning and nothing is loaded.

use std::collections::HashSet;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tenzro_model::memory_budget::{MemoryBudget, Tier};
use tracing::{info, warn};

use crate::node::TenzroNode;

/// A quantile forecast of regional demand: per step, the lower, median and
/// upper values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Band {
    pub lower: Vec<f32>,
    pub median: Vec<f32>,
    pub upper: Vec<f32>,
}

/// Operator surge policy. Off unless the operator turns it on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SurgeConfig {
    /// Whether surge loading runs at all.
    pub enabled: bool,
    /// Catalog ids the node may load for a surge.
    pub models: Vec<String>,
    /// Forecast regional requests in flight above which a surge model loads.
    pub demand_threshold: f32,
    /// A surge model unloads once the forecast's upper band stays below
    /// `demand_threshold * unload_ratio`.
    pub unload_ratio: f32,
    /// Least observed network price per request, in the settlement asset's
    /// smallest unit, at which the operator serves a surge. 0 accepts any
    /// price, including none observed yet.
    pub min_market_price: u64,
}

impl Default for SurgeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            models: Vec::new(),
            demand_threshold: 32.0,
            unload_ratio: 0.5,
            min_market_price: 0,
        }
    }
}

/// One surge model as the node sees it now.
#[derive(Debug, Clone, PartialEq)]
pub struct Candidate {
    /// Catalog id.
    pub model_id: String,
    /// Requests in flight for it across the region.
    pub regional_demand: f32,
    /// Loaded on this node.
    pub loaded: bool,
    /// Memory its load would claim.
    pub bytes: u64,
    /// The average price per request this node has seen calls to it
    /// charged, when it has seen any.
    pub market_price: Option<u128>,
}

/// What surge loading does this round.
#[derive(Debug, Clone, PartialEq)]
pub enum Plan {
    /// Load this model.
    Load(String),
    /// Unload this surge-loaded model.
    Unload(String),
    /// Demand called for this model, and policy refused it.
    Refuse { model_id: String, reason: String },
}

/// Models this node loaded for a surge, and so may unload.
#[derive(Debug, Default)]
pub struct SurgeState {
    loaded: Mutex<HashSet<String>>,
}

/// Plans one round from the forecast `band` of regional demand. The model
/// with the most regional demand that is not loaded is the one a surge loads;
/// `reserved` is memory the scheduled stacks hold back.
pub fn plan(
    config: &SurgeConfig,
    band: &Band,
    candidates: &[Candidate],
    surge_loaded: &HashSet<String>,
    budget: &MemoryBudget,
    reserved: u64,
) -> Vec<Plan> {
    let peak_median = band.median.iter().copied().fold(f32::MIN, f32::max);
    let peak_upper = band.upper.iter().copied().fold(f32::MIN, f32::max);
    let mut out = Vec::new();
    if peak_median > config.demand_threshold {
        let pick = candidates
            .iter()
            .filter(|c| !c.loaded)
            .max_by(|a, b| a.regional_demand.total_cmp(&b.regional_demand));
        if let Some(c) = pick {
            let price_ok = config.min_market_price == 0
                || c.market_price
                    .is_some_and(|p| p >= config.min_market_price as u128);
            if !price_ok {
                out.push(Plan::Refuse {
                    model_id: c.model_id.clone(),
                    reason: format!(
                        "the network price ({}) is below the operator's floor of {}",
                        c.market_price
                            .map_or("unobserved".to_string(), |p| p.to_string()),
                        config.min_market_price
                    ),
                });
            } else if !budget.would_admit(Tier::Resident, c.bytes.saturating_add(reserved)) {
                out.push(Plan::Refuse {
                    model_id: c.model_id.clone(),
                    reason: format!(
                        "loading it needs {} bytes and the scheduled stacks hold {} more; the memory budget has {}",
                        c.bytes,
                        reserved,
                        budget.available_in(Tier::Resident)
                    ),
                });
            } else {
                out.push(Plan::Load(c.model_id.clone()));
            }
        }
    } else if peak_upper < config.demand_threshold * config.unload_ratio {
        for c in candidates
            .iter()
            .filter(|c| c.loaded && surge_loaded.contains(&c.model_id))
        {
            out.push(Plan::Unload(c.model_id.clone()));
        }
    }
    out
}

/// Requests in flight for `models` at the providers announcing this node's region,
/// this node's own included.
pub fn regional_demand(node: &TenzroNode, models: &[String]) -> Vec<(String, f32)> {
    let region = node.config().region.clone();
    models
        .iter()
        .map(|m| {
            let remote: u32 = node
                .network_providers
                .iter()
                .filter(|e| {
                    let a = &e.value().announcement;
                    region.is_some() && a.region == region && a.served_models.contains(m)
                })
                .map(|e| e.value().announcement.capacity.active_requests)
                .sum();
            let local = node
                .load_tracker
                .snapshot(m)
                .map_or(0, |s| s.active_requests);
            (m.clone(), remote.saturating_add(local) as f32)
        })
        .collect()
}

/// All surge models' regional demand, the series the forecaster reads.
pub fn total_demand(node: &TenzroNode) -> Option<f32> {
    let config = &node.config().surge;
    config.enabled.then(|| {
        regional_demand(node, &config.models)
            .into_iter()
            .map(|(_, d)| d)
            .sum()
    })
}

/// Plans and carries out one round against the forecast `band`.
#[cfg(feature = "inference")]
pub async fn act(node: &Arc<TenzroNode>, band: &Band) {
    let config = node.config().surge.clone();
    if !config.enabled {
        return;
    }
    let Some(runtime) = node.model_runtime.as_ref() else {
        return;
    };
    let usage = node.usage_tracker().cloned();
    let candidates: Vec<Candidate> = regional_demand(node, &config.models)
        .into_iter()
        .filter_map(|(model_id, regional_demand)| {
            let bytes = tenzro_model::catalog::entry(&model_id)?.gguf()?.size_bytes;
            Some(Candidate {
                loaded: runtime.is_loaded(&model_id),
                bytes: MemoryBudget::with_headroom(bytes),
                market_price: usage
                    .as_ref()
                    .and_then(|t| t.get_model_stats(&model_id))
                    .filter(|s| s.inference_count > 0)
                    .map(|s| s.avg_cost()),
                model_id,
                regional_demand,
            })
        })
        .collect();
    let reserved = scheduled_reservation(node, runtime);
    let surge_loaded = node.surge_state().loaded.lock().clone();
    for step in plan(
        &config,
        band,
        &candidates,
        &surge_loaded,
        tenzro_model::memory_budget::global(),
        reserved,
    ) {
        match step {
            Plan::Load(model_id) => match recorded(node, "tenzro_serveModel", &model_id).await {
                Ok(()) => {
                    node.surge_state().loaded.lock().insert(model_id.clone());
                    info!(
                        model_id,
                        "surge: regional demand forecast over the threshold; model loaded"
                    );
                }
                Err(e) => warn!(model_id, error = %e, "surge: load failed"),
            },
            Plan::Unload(model_id) => match recorded(node, "tenzro_stopModel", &model_id).await {
                Ok(()) => {
                    node.surge_state().loaded.lock().remove(&model_id);
                    info!(model_id, "surge: regional demand fell; model unloaded");
                }
                Err(e) => warn!(model_id, error = %e, "surge: unload failed"),
            },
            Plan::Refuse { model_id, reason } => warn!(model_id, %reason, "surge: load refused"),
        }
    }
}

/// Serve (`tenzro_serveModel`) or stop (`tenzro_stopModel`) `model_id` as
/// the surge planner. The action is written to the administrative audit log
/// first, with the planner as its actor, and is not taken when that record
/// cannot be written. Only a build that serves models has these calls.
#[cfg(feature = "inference")]
async fn recorded(node: &Arc<TenzroNode>, method: &str, model_id: &str) -> Result<(), String> {
    let params = serde_json::json!({ "model_id": model_id });
    let record = crate::admin_audit::record_node_action(node, "surge", method, &params)?;
    let started = std::time::Instant::now();
    let result = if method == "tenzro_serveModel" {
        crate::rpc::handle_serve_model(node, Some(params)).await
    } else {
        crate::rpc::handle_stop_model(node, Some(params)).await
    };
    crate::admin_audit::record_node_completion(node, record, method, &result, started);
    result.map(|_| ()).map_err(|e| e.message)
}

/// Memory the active and next scheduled stacks need that is not loaded yet.
#[cfg(feature = "inference")]
fn scheduled_reservation(node: &TenzroNode, runtime: &tenzro_model::ModelRuntime) -> u64 {
    let now = chrono::Utc::now();
    let schedule = node.provider_schedule.read();
    let models: HashSet<String> = schedule
        .active_window_at(now)
        .map(|w| w.models.clone())
        .unwrap_or_default()
        .into_iter()
        .chain(
            schedule
                .next_window_at(now)
                .map(|(w, _)| w.models.clone())
                .unwrap_or_default(),
        )
        .collect();
    models
        .iter()
        .filter(|m| !runtime.is_loaded(m))
        .filter_map(|m| {
            tenzro_model::catalog::entry(m)?
                .gguf()
                .map(|g| MemoryBudget::with_headroom(g.size_bytes))
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_model::memory_budget::BudgetConfig;

    fn band(level: f32) -> Band {
        Band {
            lower: vec![level * 0.8; 4],
            median: vec![level; 4],
            upper: vec![level * 1.2; 4],
        }
    }

    fn candidate(id: &str, demand: f32, loaded: bool, bytes: u64) -> Candidate {
        Candidate {
            model_id: id.into(),
            regional_demand: demand,
            loaded,
            bytes,
            market_price: Some(10),
        }
    }

    /// The machine has what the budget has.
    #[derive(Debug)]
    struct Machine(u64);
    impl tenzro_model::memory_budget::MachineMemory for Machine {
        fn available_bytes(&self) -> u64 {
            self.0
        }
    }

    fn budget(total: u64) -> MemoryBudget {
        MemoryBudget::new(BudgetConfig::with_total(total))
            .unwrap()
            .with_machine_memory(Box::new(Machine(total)))
    }

    #[test]
    fn a_forecast_over_the_threshold_loads_within_budget_and_refuses_over_it() {
        let config = SurgeConfig {
            enabled: true,
            models: vec!["a".into(), "b".into()],
            ..SurgeConfig::default()
        };
        let budget = budget(64 << 30);
        let fits = budget.available_in(Tier::Resident) / 4;
        let cands = [
            candidate("a", 5.0, false, fits),
            candidate("b", 40.0, false, fits),
        ];

        // Below the threshold: nothing.
        assert!(plan(&config, &band(10.0), &cands, &HashSet::new(), &budget, 0).is_empty());

        // Over it: the model the region wants most loads.
        assert_eq!(
            plan(&config, &band(50.0), &cands, &HashSet::new(), &budget, 0),
            vec![Plan::Load("b".into())]
        );

        // Over it, but the scheduled stacks leave too little: refused.
        let reserved = budget.available_in(Tier::Resident);
        match plan(
            &config,
            &band(50.0),
            &cands,
            &HashSet::new(),
            &budget,
            reserved,
        )
        .as_slice()
        {
            [Plan::Refuse { model_id, reason }] => {
                assert_eq!(model_id, "b");
                assert!(reason.contains("memory budget"), "{reason}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }

        // A model larger than the whole budget: refused.
        let huge = [candidate("b", 40.0, false, u64::MAX / 2)];
        assert!(matches!(
            plan(&config, &band(50.0), &huge, &HashSet::new(), &budget, 0).as_slice(),
            [Plan::Refuse { .. }]
        ));
    }

    #[test]
    fn the_price_floor_and_falling_demand_are_honoured() {
        let config = SurgeConfig {
            enabled: true,
            min_market_price: 20,
            ..SurgeConfig::default()
        };
        let budget = budget(64 << 30);
        let cands = [candidate("a", 40.0, false, 1 << 20)];
        assert!(matches!(
            plan(&config, &band(50.0), &cands, &HashSet::new(), &budget, 0).as_slice(),
            [Plan::Refuse { reason, .. }] if reason.contains("floor")
        ));

        // Demand fell: only models the surge loaded are unloaded.
        let loaded = [
            candidate("a", 1.0, true, 1 << 20),
            candidate("b", 1.0, true, 1 << 20),
        ];
        let surge: HashSet<String> = ["a".to_string()].into();
        assert_eq!(
            plan(&config, &band(2.0), &loaded, &surge, &budget, 0),
            vec![Plan::Unload("a".into())]
        );
    }
}
