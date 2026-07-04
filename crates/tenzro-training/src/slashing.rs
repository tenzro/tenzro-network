//! Trainer slashing + eviction for rejected outer-gradient contributions.
//!
//! Two distinct rejection signals feed this path:
//!
//! 1. **Accept-time rejection** — a submission that fails
//!    [`accept_outer_gradient`](crate::runtime::SyncerState::accept_outer_gradient)
//!    (bad signature, wrong quantization, out-of-shard fragment, missing
//!    attestation at a Verified/Confidential tier). The submitter proved intent
//!    to poison the round.
//! 2. **Post-aggregation rejection** — a buffered contribution that, once
//!    decoded, either exceeded the round's norm budget (the `was_clipped` flag
//!    from [`clip_gradients`](crate::aggregation::clip_gradients)) or disagreed
//!    with the aggregate below an agreement floor (per-trainer cosine similarity
//!    from [`gradient_agreement`](crate::outer_optimizer::gradient_agreement)).
//!
//! This mirrors the INTELLECT-2 (Prime Intellect, May 2025) slash-eviction
//! discipline: a contribution that fails verification or falls outside the
//! agreement band is slashed and the trainer is evicted from the run, rather
//! than folded in with a down-weighted reputation score. Eviction is the
//! terminal action; there is no rehabilitation within a run.
//!
//! The trait lives in this crate (not the node) so `tenzro-training` stays free
//! of node-level cross-crate refs — the node bridges it to the staking / bond
//! primitives, exactly as `ProviderSlashingCallback` bridges the SLA fault
//! detector to `ComputeBondManager`.

use async_trait::async_trait;

/// Why a trainer was slashed + evicted. Carried into the callback so the node
/// layer can stamp the on-chain slash event with a machine-readable cause.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvictionReason {
    /// A submission failed accept-time validation (bad signature, wrong
    /// quantization, out-of-shard fragment, missing attestation, …).
    AcceptRejected,
    /// A buffered contribution exceeded the round's L2-norm budget and was
    /// clipped by the syncer — an honest trainer that honored the same cap in
    /// its Python outer step never trips this.
    NormBudgetExceeded,
    /// A buffered contribution's cosine similarity to the round aggregate fell
    /// below the agreement floor.
    AgreementBelowFloor,
}

impl EvictionReason {
    /// Stable machine-readable tag for the slash-event audit trail.
    pub fn tag(self) -> &'static str {
        match self {
            EvictionReason::AcceptRejected => "train:accept_rejected",
            EvictionReason::NormBudgetExceeded => "train:norm_budget_exceeded",
            EvictionReason::AgreementBelowFloor => "train:agreement_below_floor",
        }
    }
}

/// Node-provided hook that slashes a trainer's bond and evicts it. Async to
/// mirror `tenzro_consensus::SlashingCallback` / `ProviderSlashingCallback`, so
/// the node can await an on-chain / bond-manager write.
#[async_trait]
pub trait TrainerSlashingCallback: Send + Sync {
    /// Slash the trainer identified by `trainer_did` in run `task_id` for
    /// `reason`. The syncer has already removed the DID from the run's active
    /// trainer set before this is called; the callback owns the bond debit +
    /// on-chain audit event. Errors are logged by the caller and do not roll
    /// back the eviction (an evicted trainer stays evicted even if the bond
    /// debit fails — fail-closed on participation).
    async fn slash_and_evict(&self, task_id: &str, trainer_did: &str, reason: EvictionReason);
}

/// Decide, from per-contributor post-aggregation signals, which trainers to
/// evict. Pure + allocation-light so it is unit-testable without a syncer.
///
/// `contributors` pairs each accepted trainer DID (in aggregation order) with
/// its `was_clipped` flag and its cosine agreement with the aggregate.
/// `agreement_floor` is the minimum acceptable cosine similarity; a contributor
/// at or below it is evicted for [`EvictionReason::AgreementBelowFloor`].
/// Clipping is evaluated first, so a contribution that is both over-budget and
/// disagreeing is attributed to the norm budget (the stronger, unambiguous
/// signal).
pub fn eviction_decisions(
    contributors: &[(String, bool, f32)],
    agreement_floor: f32,
) -> Vec<(String, EvictionReason)> {
    let mut out = Vec::new();
    for (did, was_clipped, agreement) in contributors {
        if *was_clipped {
            out.push((did.clone(), EvictionReason::NormBudgetExceeded));
        } else if *agreement <= agreement_floor {
            out.push((did.clone(), EvictionReason::AgreementBelowFloor));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipped_contributor_is_evicted_for_norm_budget() {
        let c = vec![("did:t1".to_string(), true, 0.99)];
        let d = eviction_decisions(&c, 0.0);
        assert_eq!(d, vec![("did:t1".to_string(), EvictionReason::NormBudgetExceeded)]);
    }

    #[test]
    fn disagreeing_contributor_is_evicted_for_agreement() {
        // Not clipped, but cosine -0.4 <= floor 0.0 → agreement eviction.
        let c = vec![("did:t1".to_string(), false, -0.4)];
        let d = eviction_decisions(&c, 0.0);
        assert_eq!(d, vec![("did:t1".to_string(), EvictionReason::AgreementBelowFloor)]);
    }

    #[test]
    fn honest_contributor_is_kept() {
        let c = vec![("did:t1".to_string(), false, 0.95)];
        assert!(eviction_decisions(&c, 0.0).is_empty());
    }

    #[test]
    fn norm_budget_takes_precedence_over_agreement() {
        // Both clipped AND disagreeing → attributed to norm budget.
        let c = vec![("did:t1".to_string(), true, -0.9)];
        let d = eviction_decisions(&c, 0.0);
        assert_eq!(d, vec![("did:t1".to_string(), EvictionReason::NormBudgetExceeded)]);
    }

    #[test]
    fn agreement_floor_is_inclusive() {
        // agreement exactly at floor → evicted (<=).
        let c = vec![("did:t1".to_string(), false, 0.25)];
        let d = eviction_decisions(&c, 0.25);
        assert_eq!(d, vec![("did:t1".to_string(), EvictionReason::AgreementBelowFloor)]);
    }
}
