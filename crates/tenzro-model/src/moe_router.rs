//! Distributed MoE dispatch planner.
//!
//! Takes a per-token top-k expert routing decision and turns it into a
//! fan-out plan: which provider receives which batch of tokens for which
//! experts. The plan is the contract between the router peer (gating
//! network) and the expert holders.
//!
//! The planner is **pure** — it accepts a [`MoeShardView`] and a list of
//! per-token routing decisions and returns the dispatch plan. It does
//! not perform I/O, sign messages, or settle payments; those wire
//! through the consuming `tenzro-node` layer.
//!
//! ## Per-token vs per-batch
//!
//! Centralized MoE serving dispatches all-to-all per token. On a
//! permissionless WAN with 30–150 ms RTTs that pattern explodes the
//! latency budget. The Tenzro plan **batches per holder**: every token
//! whose top-k landed on the same (expert, holder) tuple is bundled
//! into one fan-out call. Token throughput rises linearly with batch
//! size while RTT cost amortises across the batch.
//!
//! ## Failure mode
//!
//! When an expert has no warm holder reachable, the planner falls back
//! to the next-best cold holder. When neither is available, the planner
//! returns a [`MoeDispatchError::UnreachableExpert`] so the caller can
//! pick a fallback strategy (round to a Replica provider, queue, etc.).

use std::collections::HashMap;
#[cfg(test)]
use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::moe_shard::{ExpertHolder, ExpertId, MoeShardView};
use tenzro_types::primitives::Address;

/// Per-token top-k decision the gating network emitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRouting {
    /// Token index inside the request (used to reassemble outputs).
    pub token_index: u32,
    /// Top-k expert ids selected by the gating network.
    pub experts: Vec<ExpertId>,
}

/// One reachable holder endpoint for an expert. The primary is carried
/// inline on [`ExpertBatch`]; the remaining reachable holders are carried
/// in [`ExpertBatch::backups`] so the dispatcher can redispatch the same
/// token batch to a standby when the primary holder errors or times out.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HolderEndpoint {
    /// Holder's wallet address.
    pub provider: Address,
    /// iroh endpoint id when available — dispatched over QUIC directly.
    pub iroh_endpoint_id: Option<String>,
    /// HTTP endpoint fallback (OpenAI-compatible).
    pub http_endpoint: Option<String>,
}

/// Batch routed to one holder for one expert.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpertBatch {
    /// Expert this batch is destined for.
    pub expert: ExpertId,
    /// Holder that owns the expert.
    pub provider: Address,
    /// iroh endpoint id when available — routers dispatch over QUIC
    /// directly when set.
    pub iroh_endpoint_id: Option<String>,
    /// HTTP endpoint fallback (OpenAI-compatible).
    pub http_endpoint: Option<String>,
    /// Token indices whose top-k landed on this `(expert, provider)`
    /// tuple.
    pub token_indices: Vec<u32>,
    /// Standby holders of the same expert, in the same warm-first order
    /// as [`MoeShardView::holders`], excluding the primary. The
    /// dispatcher redispatches this batch to the next standby when the
    /// primary holder fails.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backups: Vec<HolderEndpoint>,
}

/// Full dispatch plan returned by the planner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchPlan {
    /// Model this plan applies to.
    pub model_id: String,
    /// Per-holder per-expert batches the router must fan out.
    pub batches: Vec<ExpertBatch>,
    /// Token-level mapping: which expert decisions landed on which
    /// holder. Used by the combiner step to reassemble per-token
    /// outputs from the holder responses.
    pub token_assignments: Vec<TokenAssignment>,
}

/// One token's full assignment across its top-k experts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenAssignment {
    /// Token index.
    pub token_index: u32,
    /// `(expert, provider)` tuples for every top-k slot of this token.
    pub slots: Vec<TokenSlot>,
}

/// One top-k slot of one token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenSlot {
    /// Expert this slot selected.
    pub expert: ExpertId,
    /// Provider that will serve the expert. `None` when no holder is
    /// reachable; the caller may queue or replan.
    pub provider: Option<Address>,
}

/// Reasons a plan cannot be built.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum MoeDispatchError {
    /// At least one expert has no holder reachable in the view.
    #[error("expert l{layer}/e{expert} has no reachable holder")]
    UnreachableExpert {
        /// Layer the unreachable expert sits in.
        layer: u32,
        /// Expert index inside the layer.
        expert: u32,
    },
    /// Routing decisions are empty.
    #[error("token routing list is empty")]
    EmptyRouting,
}

/// Build a dispatch plan from a [`MoeShardView`] and a list of per-token
/// routing decisions. `allow_cold` controls fallback: when `false` the
/// planner only picks warm holders; when `true` it falls back to cold
/// holders before declaring an expert unreachable.
pub fn plan_dispatch(
    view: &MoeShardView,
    routings: &[TokenRouting],
    allow_cold: bool,
) -> Result<DispatchPlan, MoeDispatchError> {
    if routings.is_empty() {
        return Err(MoeDispatchError::EmptyRouting);
    }

    // Aggregate token indices per (expert, provider). `Address` is not
    // `Ord` in this workspace so we use a `HashMap` keyed by the
    // provider's 32-byte bytes and remember the canonical Address on
    // insert.
    let mut batches_map: HashMap<(ExpertId, [u8; 32]), ExpertBatchKey> = HashMap::new();
    let mut token_assignments = Vec::with_capacity(routings.len());

    for routing in routings {
        let mut slots = Vec::with_capacity(routing.experts.len());
        for &expert in &routing.experts {
            // Full warm-first candidate list, filtered by residency
            // policy. The first entry is the primary holder; the rest
            // become redispatch backups on the batch.
            let candidates = candidates_for_dispatch(view, expert, allow_cold);
            match candidates.split_first() {
                Some((primary, rest)) => {
                    let key = (expert, primary.provider.0);
                    let entry = batches_map.entry(key).or_insert_with(|| ExpertBatchKey {
                        provider: primary.provider,
                        iroh_endpoint_id: primary.iroh_endpoint_id.clone(),
                        http_endpoint: primary.http_endpoint.clone(),
                        backups: rest
                            .iter()
                            .map(|h| HolderEndpoint {
                                provider: h.provider,
                                iroh_endpoint_id: h.iroh_endpoint_id.clone(),
                                http_endpoint: h.http_endpoint.clone(),
                            })
                            .collect(),
                        tokens: Vec::new(),
                    });
                    entry.tokens.push(routing.token_index);
                    slots.push(TokenSlot {
                        expert,
                        provider: Some(primary.provider),
                    });
                }
                None => {
                    return Err(MoeDispatchError::UnreachableExpert {
                        layer: expert.layer,
                        expert: expert.expert,
                    });
                }
            }
        }
        token_assignments.push(TokenAssignment {
            token_index: routing.token_index,
            slots,
        });
    }

    let mut batches: Vec<ExpertBatch> = batches_map
        .into_iter()
        .map(|((expert, _addr), key)| ExpertBatch {
            expert,
            provider: key.provider,
            iroh_endpoint_id: key.iroh_endpoint_id,
            http_endpoint: key.http_endpoint,
            token_indices: key.tokens,
            backups: key.backups,
        })
        .collect();
    // HashMap iteration order is non-deterministic. Sort the batch list
    // by (expert, provider) so the plan output is deterministic per
    // input — important for tests, audit, and replay.
    batches.sort_by(|a, b| {
        a.expert
            .cmp(&b.expert)
            .then(a.provider.0.cmp(&b.provider.0))
    });

    Ok(DispatchPlan {
        model_id: view.model_id().to_string(),
        batches,
        token_assignments,
    })
}

struct ExpertBatchKey {
    provider: Address,
    iroh_endpoint_id: Option<String>,
    http_endpoint: Option<String>,
    backups: Vec<HolderEndpoint>,
    tokens: Vec<u32>,
}

/// Warm-first ordered candidate holders for `expert`, filtered by the
/// `allow_cold` residency policy. The first entry is the primary; the
/// rest are redispatch backups. Empty when no holder satisfies the
/// policy.
fn candidates_for_dispatch(
    view: &MoeShardView,
    expert: ExpertId,
    allow_cold: bool,
) -> Vec<ExpertHolder> {
    let holders = view.holders(expert);
    if allow_cold {
        holders
    } else {
        holders
            .into_iter()
            .filter(|h| {
                matches!(
                    h.residency,
                    tenzro_types::model::MoeExpertResidency::Warm
                )
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::model::{
        InferenceProvider, MoeExpertHolding, MoeExpertResidency, MoeProviderRole,
        ProviderCapacity, ProviderStatus,
    };

    fn provider(
        addr: u8,
        experts: &[(u32, u32, MoeExpertResidency, u32)],
    ) -> InferenceProvider {
        let mut p = InferenceProvider::new(Address::new([addr; 32]), format!("p{}", addr));
        p.status = ProviderStatus::Active;
        let mut capacity = ProviderCapacity {
            moe_roles: vec![MoeProviderRole::ExpertHolder],
            iroh_endpoint_id: Some(format!("ep-{}", addr)),
            ..Default::default()
        };
        for &(layer, expert, residency, tps) in experts {
            capacity.moe_holdings.push(MoeExpertHolding {
                model_id: "qwen".into(),
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
    fn plan_batches_tokens_per_holder() {
        let alice = provider(
            1,
            &[
                (0, 1, MoeExpertResidency::Warm, 500),
                (0, 2, MoeExpertResidency::Warm, 500),
            ],
        );
        let view = MoeShardView::build("qwen", [&alice]);
        let routings = vec![
            TokenRouting {
                token_index: 0,
                experts: vec![ExpertId::new(0, 1), ExpertId::new(0, 2)],
            },
            TokenRouting {
                token_index: 1,
                experts: vec![ExpertId::new(0, 1)],
            },
        ];
        let plan = plan_dispatch(&view, &routings, false).unwrap();
        // Two batches: one for (l0/e1) with tokens [0, 1], one for
        // (l0/e2) with tokens [0].
        let by_expert: BTreeMap<ExpertId, Vec<u32>> = plan
            .batches
            .iter()
            .map(|b| (b.expert, b.token_indices.clone()))
            .collect();
        assert_eq!(by_expert.get(&ExpertId::new(0, 1)).unwrap(), &vec![0, 1]);
        assert_eq!(by_expert.get(&ExpertId::new(0, 2)).unwrap(), &vec![0]);
    }

    #[test]
    fn unreachable_expert_errors_out() {
        let alice = provider(1, &[(0, 1, MoeExpertResidency::Warm, 500)]);
        let view = MoeShardView::build("qwen", [&alice]);
        let routings = vec![TokenRouting {
            token_index: 0,
            experts: vec![ExpertId::new(0, 99)],
        }];
        let err = plan_dispatch(&view, &routings, true).unwrap_err();
        assert!(matches!(err, MoeDispatchError::UnreachableExpert { .. }));
    }

    #[test]
    fn empty_routing_errors_out() {
        let alice = provider(1, &[(0, 1, MoeExpertResidency::Warm, 500)]);
        let view = MoeShardView::build("qwen", [&alice]);
        let err = plan_dispatch(&view, &[], false).unwrap_err();
        assert!(matches!(err, MoeDispatchError::EmptyRouting));
    }

    #[test]
    fn warm_only_mode_rejects_cold_holders() {
        let alice = provider(1, &[(0, 1, MoeExpertResidency::Cold, 500)]);
        let view = MoeShardView::build("qwen", [&alice]);
        let routings = vec![TokenRouting {
            token_index: 0,
            experts: vec![ExpertId::new(0, 1)],
        }];
        // allow_cold=false → no warm holder available → fail.
        let err = plan_dispatch(&view, &routings, false).unwrap_err();
        assert!(matches!(err, MoeDispatchError::UnreachableExpert { .. }));
        // allow_cold=true → cold holder accepted.
        let plan = plan_dispatch(&view, &routings, true).unwrap();
        assert_eq!(plan.batches.len(), 1);
    }

    #[test]
    fn token_assignments_track_per_slot_provider() {
        let alice = provider(1, &[(0, 1, MoeExpertResidency::Warm, 500)]);
        let bob = provider(2, &[(0, 2, MoeExpertResidency::Warm, 500)]);
        let view = MoeShardView::build("qwen", [&alice, &bob]);
        let routings = vec![TokenRouting {
            token_index: 0,
            experts: vec![ExpertId::new(0, 1), ExpertId::new(0, 2)],
        }];
        let plan = plan_dispatch(&view, &routings, false).unwrap();
        let ass = &plan.token_assignments[0];
        assert_eq!(ass.slots.len(), 2);
        // Slot 0 → alice, slot 1 → bob.
        assert_eq!(ass.slots[0].provider.unwrap().as_bytes()[0], 1);
        assert_eq!(ass.slots[1].provider.unwrap().as_bytes()[0], 2);
    }

    #[test]
    fn backups_carry_remaining_holders_warm_first() {
        // Three holders of the same expert: alice cold, bob warm, carol
        // warm. allow_cold=true → warm-first order is [bob, carol, alice];
        // primary=bob, backups=[carol, alice].
        let alice = provider(1, &[(0, 1, MoeExpertResidency::Cold, 100)]);
        let bob = provider(2, &[(0, 1, MoeExpertResidency::Warm, 500)]);
        let carol = provider(3, &[(0, 1, MoeExpertResidency::Warm, 300)]);
        let view = MoeShardView::build("qwen", [&alice, &bob, &carol]);
        let routings = vec![TokenRouting {
            token_index: 0,
            experts: vec![ExpertId::new(0, 1)],
        }];
        let plan = plan_dispatch(&view, &routings, true).unwrap();
        assert_eq!(plan.batches.len(), 1);
        let batch = &plan.batches[0];
        // Primary is a warm holder (bob or carol — holders() is stable
        // sort so warm entries keep insertion order: bob then carol).
        assert_eq!(batch.provider.as_bytes()[0], 2);
        let backup_addrs: Vec<u8> = batch.backups.iter().map(|b| b.provider.as_bytes()[0]).collect();
        assert_eq!(backup_addrs, vec![3, 1]);
    }

    #[test]
    fn warm_only_mode_excludes_cold_from_backups() {
        // allow_cold=false → cold alice is filtered out entirely, so she
        // never appears as a backup.
        let alice = provider(1, &[(0, 1, MoeExpertResidency::Cold, 100)]);
        let bob = provider(2, &[(0, 1, MoeExpertResidency::Warm, 500)]);
        let view = MoeShardView::build("qwen", [&alice, &bob]);
        let routings = vec![TokenRouting {
            token_index: 0,
            experts: vec![ExpertId::new(0, 1)],
        }];
        let plan = plan_dispatch(&view, &routings, false).unwrap();
        assert_eq!(plan.batches[0].provider.as_bytes()[0], 2);
        assert!(plan.batches[0].backups.is_empty());
    }

    #[test]
    fn batches_are_deterministic_per_input() {
        let alice = provider(
            1,
            &[
                (0, 1, MoeExpertResidency::Warm, 500),
                (0, 2, MoeExpertResidency::Warm, 500),
            ],
        );
        let view = MoeShardView::build("qwen", [&alice]);
        let routings = vec![
            TokenRouting {
                token_index: 0,
                experts: vec![ExpertId::new(0, 1), ExpertId::new(0, 2)],
            },
            TokenRouting {
                token_index: 1,
                experts: vec![ExpertId::new(0, 2), ExpertId::new(0, 1)],
            },
        ];
        let a = plan_dispatch(&view, &routings, false).unwrap();
        let b = plan_dispatch(&view, &routings, false).unwrap();
        assert_eq!(a, b);
    }
}
