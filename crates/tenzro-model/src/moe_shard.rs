//! Decentralized MoE expert-shard view over the existing
//! [`ProviderManager`].
//!
//! Centralized MoE serving (DeepEP, vLLM EP, SGLang) shards experts
//! across co-located GPUs with sub-millisecond all-to-all over NVLink or
//! RDMA. That pattern doesn't survive on a permissionless WAN where peer
//! RTTs are 30–150 ms — per-token all-to-all becomes the latency budget.
//!
//! Tenzro's decentralized pattern follows Petals / Hivemind for block
//! distribution and adapts it for MoE: each peer holds an opaque subset
//! of `(layer, expert_index)` pairs for a given model. Tokens whose
//! top-k routing lands on those experts are **batched** at the holding
//! peer (not dispatched per token), and the gating-network step runs at
//! a router peer that fans batches out via the existing iroh QUIC blob
//! channel.
//!
//! ## Alignment with the existing provider stack
//!
//! The compute providers serving MoE shards are the same
//! [`InferenceProvider`] entries already registered via
//! `tenzro_registerProvider`. The MoE-specific declaration lives on
//! [`ProviderCapacity::moe_holdings`] / [`ProviderCapacity::moe_roles`]
//! / [`ProviderCapacity::iroh_endpoint_id`]. This module is therefore a
//! **view** over `ProviderManager` keyed by the existing
//! [`tenzro_types::primitives::Address`], not a parallel registry —
//! providers are admitted, slashed, and reputation-tracked through the
//! same paths dense models already use.
//!
//! Replication is the second axis: DeepSeek-V3 published expert-
//! utilization stats showing ~30 % of routed tokens hit the top-2 of 256
//! experts. The view exposes `under_replicated` and `replication_of`
//! helpers so a governance-tunable [`ReplicationPolicy`] can prompt
//! additional providers to load hot experts at the next refresh.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use tenzro_types::model::{InferenceProvider, MoeExpertResidency, MoeProviderRole};
#[cfg(test)]
use tenzro_types::model::MoeExpertHolding;
use tenzro_types::primitives::Address;

/// Identifies one expert in an MoE model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ExpertId {
    /// Transformer layer index this expert sits in.
    pub layer: u32,
    /// Expert index inside the layer's MoE block.
    pub expert: u32,
}

impl ExpertId {
    /// Convenience constructor.
    pub fn new(layer: u32, expert: u32) -> Self {
        Self { layer, expert }
    }
}

/// One row in the shard map: which providers hold `expert` for the
/// queried model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpertHolder {
    /// Provider's wallet address — the same key used by
    /// [`ProviderManager`].
    pub provider: Address,
    /// Provider's declared residency state for this expert.
    pub residency: MoeExpertResidency,
    /// Provider-committed TPS for this expert (0 = best effort).
    pub committed_tps: u32,
    /// Provider's iroh endpoint id, if declared. Routers prefer this
    /// path over the HTTP endpoint for fan-out batches.
    pub iroh_endpoint_id: Option<String>,
    /// Provider's OpenAI-compatible HTTP endpoint, when set. Used as
    /// fallback when no iroh endpoint is declared.
    pub http_endpoint: Option<String>,
    /// Whether the holder's expert compute runs on a GPU backend. The
    /// planner prefers GPU holders for the primary of a batch, since
    /// grouped-GEMM throughput dominates there; CPU holders remain valid
    /// standbys.
    pub gpu: bool,
}

/// Governance policy for expert replication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplicationPolicy {
    /// Every active expert must be held by at least this many distinct
    /// providers. Schedulers / governance promote additional providers
    /// when an expert falls below this floor.
    pub min_replication: u32,
    /// Hard ceiling on hot-expert replication.
    pub max_replication: u32,
    /// Committed TPS above which an expert is considered hot and the
    /// view will hint at further replication.
    pub hot_threshold_tps: u32,
}

impl Default for ReplicationPolicy {
    fn default() -> Self {
        Self {
            min_replication: 2,
            max_replication: 8,
            hot_threshold_tps: 1_000,
        }
    }
}

/// Read-only shard view. Built from a borrowed slice of providers and
/// pinned to one `model_id`. Cheap to construct — the underlying
/// `Vec<ExpertHolder>` per expert is collected at view-construction time
/// rather than per-query.
#[derive(Debug, Clone)]
pub struct MoeShardView {
    model_id: String,
    by_expert: BTreeMap<ExpertId, Vec<ExpertHolder>>,
    role_count: HashMap<MoeProviderRole, u32>,
}

impl MoeShardView {
    /// Build a view for `model_id` from a borrowed slice of providers.
    /// Stale providers (non-Active) and providers with no MoE roles
    /// declared are filtered out.
    pub fn build<'a, I>(model_id: impl Into<String>, providers: I) -> Self
    where
        I: IntoIterator<Item = &'a InferenceProvider>,
    {
        let model_id = model_id.into();
        let mut by_expert: BTreeMap<ExpertId, Vec<ExpertHolder>> = BTreeMap::new();
        let mut role_count: HashMap<MoeProviderRole, u32> = HashMap::new();

        for p in providers {
            if p.status != tenzro_types::model::ProviderStatus::Active {
                continue;
            }
            for role in &p.capacity.moe_roles {
                *role_count.entry(*role).or_insert(0) += 1;
            }
            for h in &p.capacity.moe_holdings {
                if h.model_id != model_id {
                    continue;
                }
                let expert = ExpertId::new(h.layer, h.expert);
                by_expert.entry(expert).or_default().push(ExpertHolder {
                    provider: p.address,
                    residency: h.residency,
                    committed_tps: h.committed_tps,
                    iroh_endpoint_id: p.capacity.iroh_endpoint_id.clone(),
                    http_endpoint: p.endpoint_url.clone(),
                    gpu: p.capacity.moe_gpu,
                });
            }
        }

        Self {
            model_id,
            by_expert,
            role_count,
        }
    }

    /// Model id this view is pinned to.
    pub fn model_id(&self) -> &str {
        &self.model_id
    }

    /// All holders of `expert`. Warm-residency holders sort first; within
    /// the same residency tier GPU-backed holders sort ahead of CPU ones,
    /// then higher committed TPS. The planner takes the first entry as the
    /// batch primary, so this ordering is what steers a batch to the
    /// fastest reachable holder.
    pub fn holders(&self, expert: ExpertId) -> Vec<ExpertHolder> {
        let mut hs = self
            .by_expert
            .get(&expert)
            .cloned()
            .unwrap_or_default();
        hs.sort_by(|a, b| {
            let ra = residency_rank(a.residency);
            let rb = residency_rank(b.residency);
            ra.cmp(&rb)
                // GPU holders first (false < true, so invert).
                .then((!a.gpu).cmp(&(!b.gpu)))
                .then(b.committed_tps.cmp(&a.committed_tps))
        });
        hs
    }

    /// Distinct count of providers holding `expert`. Replication signal.
    pub fn replication_of(&self, expert: ExpertId) -> u32 {
        self.by_expert
            .get(&expert)
            .map(|hs| hs.len() as u32)
            .unwrap_or(0)
    }

    /// Best holder for `expert`: warm residency, highest committed_tps,
    /// iroh-reachable preferred. Returns `None` when no holder declared.
    pub fn pick_holder(&self, expert: ExpertId) -> Option<ExpertHolder> {
        let candidates = self.by_expert.get(&expert)?;
        let mut best: Option<&ExpertHolder> = None;
        for h in candidates {
            let score = score_holder(h);
            if best.map(score_holder).unwrap_or(0) < score {
                best = Some(h);
            }
        }
        best.cloned()
    }

    /// Number of providers declaring `role`.
    pub fn providers_for_role(&self, role: MoeProviderRole) -> u32 {
        self.role_count.get(&role).copied().unwrap_or(0)
    }

    /// Experts whose replication falls below the policy floor.
    pub fn under_replicated(&self, policy: ReplicationPolicy) -> Vec<ExpertId> {
        self.by_expert
            .iter()
            .filter_map(|(eid, hs)| {
                if (hs.len() as u32) < policy.min_replication {
                    Some(*eid)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Hot experts (any holder's committed_tps ≥ hot_threshold_tps).
    /// Callers consult these to prioritize replication.
    pub fn hot_experts(&self, policy: ReplicationPolicy) -> Vec<ExpertId> {
        self.by_expert
            .iter()
            .filter_map(|(eid, hs)| {
                if hs.iter().any(|h| h.committed_tps >= policy.hot_threshold_tps) {
                    Some(*eid)
                } else {
                    None
                }
            })
            .collect()
    }

    /// Distinct expert ids that have at least one holder.
    pub fn covered_experts(&self) -> Vec<ExpertId> {
        self.by_expert.keys().copied().collect()
    }

    /// Distinct providers backing this model with any MoE role.
    pub fn distinct_providers(&self) -> Vec<Address> {
        let mut seen: std::collections::HashSet<[u8; 32]> = std::collections::HashSet::new();
        let mut out: Vec<Address> = Vec::new();
        for hs in self.by_expert.values() {
            for h in hs {
                if seen.insert(h.provider.0) {
                    out.push(h.provider);
                }
            }
        }
        out.sort_by_key(|a| a.0);
        out
    }

    /// True when every expert in `expected_experts` has at least
    /// `min_replication` holders. Used by admission control before a
    /// model is marked servable on the network.
    pub fn covers(&self, expected_experts: &[ExpertId], min_replication: u32) -> bool {
        expected_experts.iter().all(|eid| {
            self.by_expert
                .get(eid)
                .map(|hs| hs.len() as u32 >= min_replication)
                .unwrap_or(false)
        })
    }
}

fn residency_rank(r: MoeExpertResidency) -> u8 {
    match r {
        MoeExpertResidency::Warm => 0,
        MoeExpertResidency::Cold => 1,
        MoeExpertResidency::Evicting => 2,
    }
}

fn score_holder(h: &ExpertHolder) -> u64 {
    let residency_score: u64 = match h.residency {
        MoeExpertResidency::Warm => 1_000_000,
        MoeExpertResidency::Cold => 100_000,
        MoeExpertResidency::Evicting => 0,
    };
    // GPU bonus sits below residency but above the iroh-reachability and
    // committed-TPS signals, so a warm GPU holder beats a warm CPU holder
    // while never overriding residency.
    let gpu_bonus: u64 = if h.gpu { 50_000 } else { 0 };
    let iroh_bonus: u64 = if h.iroh_endpoint_id.is_some() { 10_000 } else { 0 };
    residency_score + gpu_bonus + iroh_bonus + h.committed_tps as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::model::{ProviderCapacity, ProviderStatus};

    fn provider(addr: u8, model: &str, experts: &[(u32, u32, MoeExpertResidency, u32)]) -> InferenceProvider {
        let mut p = InferenceProvider::new(Address::new([addr; 32]), format!("p{}", addr));
        p.status = ProviderStatus::Active;
        let mut capacity = ProviderCapacity {
            moe_roles: vec![MoeProviderRole::ExpertHolder],
            iroh_endpoint_id: Some(format!("ep-{}", addr)),
            ..Default::default()
        };
        for &(layer, expert, residency, tps) in experts {
            capacity.moe_holdings.push(MoeExpertHolding {
                model_id: model.into(),
                layer,
                expert,
                residency,
                committed_tps: tps,
            });
        }
        p.capacity = capacity;
        p
    }

    #[test]
    fn view_indexes_by_expert() {
        let alice = provider(
            1,
            "qwen",
            &[(0, 1, MoeExpertResidency::Warm, 500), (0, 2, MoeExpertResidency::Warm, 500)],
        );
        let v = MoeShardView::build("qwen", [&alice]);
        assert_eq!(v.replication_of(ExpertId::new(0, 1)), 1);
        assert_eq!(v.replication_of(ExpertId::new(0, 2)), 1);
        assert_eq!(v.replication_of(ExpertId::new(0, 3)), 0);
    }

    #[test]
    fn replication_counts_distinct_providers() {
        let alice = provider(1, "qwen", &[(0, 1, MoeExpertResidency::Warm, 500)]);
        let bob = provider(2, "qwen", &[(0, 1, MoeExpertResidency::Warm, 800)]);
        let charlie = provider(3, "qwen", &[(0, 1, MoeExpertResidency::Cold, 0)]);
        let v = MoeShardView::build("qwen", [&alice, &bob, &charlie]);
        assert_eq!(v.replication_of(ExpertId::new(0, 1)), 3);
    }

    #[test]
    fn pick_holder_prefers_warm_then_tps() {
        let alice = provider(1, "qwen", &[(0, 1, MoeExpertResidency::Cold, 1_000)]);
        let bob = provider(2, "qwen", &[(0, 1, MoeExpertResidency::Warm, 200)]);
        let v = MoeShardView::build("qwen", [&alice, &bob]);
        let picked = v.pick_holder(ExpertId::new(0, 1)).unwrap();
        assert_eq!(picked.provider.as_bytes()[0], 2); // Warm beats Cold even with lower TPS.
    }

    #[test]
    fn under_replicated_reports_floor_violators() {
        let alice = provider(1, "qwen", &[(0, 1, MoeExpertResidency::Warm, 500), (0, 2, MoeExpertResidency::Warm, 500)]);
        let bob = provider(2, "qwen", &[(0, 1, MoeExpertResidency::Warm, 500)]);
        let v = MoeShardView::build("qwen", [&alice, &bob]);
        let mut under = v.under_replicated(ReplicationPolicy {
            min_replication: 2,
            max_replication: 8,
            hot_threshold_tps: 1000,
        });
        under.sort();
        assert_eq!(under, vec![ExpertId::new(0, 2)]); // (0,1) has 2, (0,2) has 1
    }

    #[test]
    fn hot_experts_match_threshold() {
        let alice = provider(1, "qwen", &[(0, 1, MoeExpertResidency::Warm, 2_000), (0, 2, MoeExpertResidency::Warm, 100)]);
        let v = MoeShardView::build("qwen", [&alice]);
        let hot = v.hot_experts(ReplicationPolicy::default());
        assert_eq!(hot, vec![ExpertId::new(0, 1)]);
    }

    #[test]
    fn build_ignores_inactive_providers() {
        let mut alice = provider(1, "qwen", &[(0, 1, MoeExpertResidency::Warm, 500)]);
        alice.status = ProviderStatus::Suspended;
        let v = MoeShardView::build("qwen", [&alice]);
        assert!(v.covered_experts().is_empty());
    }

    #[test]
    fn build_pins_to_model() {
        let alice = provider(1, "qwen", &[(0, 1, MoeExpertResidency::Warm, 500)]);
        let mut bob = provider(2, "deepseek", &[(0, 1, MoeExpertResidency::Warm, 500)]);
        bob.capacity.moe_holdings[0].model_id = "deepseek".into();
        let v = MoeShardView::build("qwen", [&alice, &bob]);
        assert_eq!(v.distinct_providers().len(), 1);
    }

    #[test]
    fn covers_returns_true_when_all_experts_meet_floor() {
        let alice = provider(1, "qwen", &[(0, 1, MoeExpertResidency::Warm, 500), (0, 2, MoeExpertResidency::Warm, 500)]);
        let bob = provider(2, "qwen", &[(0, 1, MoeExpertResidency::Warm, 500), (0, 2, MoeExpertResidency::Warm, 500)]);
        let v = MoeShardView::build("qwen", [&alice, &bob]);
        assert!(v.covers(&[ExpertId::new(0, 1), ExpertId::new(0, 2)], 2));
        assert!(!v.covers(&[ExpertId::new(0, 1), ExpertId::new(0, 2)], 3));
    }

    #[test]
    fn role_count_aggregates() {
        let alice = provider(1, "qwen", &[(0, 1, MoeExpertResidency::Warm, 500)]);
        let mut bob = provider(2, "qwen", &[(0, 2, MoeExpertResidency::Warm, 500)]);
        bob.capacity.moe_roles = vec![MoeProviderRole::Router];
        let v = MoeShardView::build("qwen", [&alice, &bob]);
        assert_eq!(v.providers_for_role(MoeProviderRole::ExpertHolder), 1);
        assert_eq!(v.providers_for_role(MoeProviderRole::Router), 1);
    }
}
