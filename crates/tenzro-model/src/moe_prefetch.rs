//! Deciding which experts to fetch before they are asked for.
//!
//! # The problem
//!
//! Offloaded MoE inference is I/O bound, not compute bound. Published
//! breakdowns put roughly 98.9% of Mixtral-8x7B's time in fetching experts
//! over PCIe, with the compute units idle. The residency tier in
//! [`crate::moe_exec`] loads on demand, so every miss stalls on that fetch.
//!
//! # The approach, and its limits
//!
//! Systems divide into two families. Fiddler and KTransformers are
//! "prefetch-blind": they allow CPU execution of experts missing from cache
//! but do not schedule the hot ones. The predictive family — Pre-gated MoE,
//! MoE-Infinity, MoE-SpeQ, MoE-Beyond — hides the latency instead, by working
//! out layer N+1's experts while layer N computes.
//!
//! What is worth being honest about is where this does *not* pay. Expert
//! activation is diffuse: there are no consistently hot experts across layers,
//! and **batching makes it worse**, because parallel requests densify
//! activation and dilute the sparsity prefetching depends on. This node runs
//! continuous batching by default, so the benefit here will be smaller than
//! single-stream papers report.
//!
//! That shapes the design. Rather than a learned predictor — which needs
//! trace data, generalises poorly under domain shift, and is exactly what
//! degrades under batching — this tracks observed co-activation and only acts
//! when the evidence is strong enough to beat the cost of a wasted fetch. A
//! prefetch that misses is not free: it occupies bandwidth the demand path
//! needs.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// One expert, addressed the way the shard view addresses it.
pub type ExpertKey = (u32, u32);

/// Observations before a co-activation ratio is trusted.
///
/// Two tokens routing to the same pair proves nothing — top-k routing puts
/// several experts together on every token. The threshold is what separates a
/// pattern from an accident, and setting it too low is how a predictor starts
/// issuing fetches that displace the demand path.
pub const MIN_OBSERVATIONS: u32 = 32;

/// Co-activation ratio below which a pair is not worth prefetching.
///
/// Deliberately high. A wasted prefetch is not neutral: it spends bandwidth
/// the demand path is competing for, so the bar is "usually right", not
/// "better than chance".
pub const MIN_CONFIDENCE: f32 = 0.6;

/// Prefetches allowed in flight at once.
///
/// The demand path and the prefetch path share one link. Past a small number,
/// speculative fetches delay the fetch something is actually blocked on, and
/// the prefetcher makes things worse than doing nothing.
pub const MAX_IN_FLIGHT: usize = 4;

/// What the prefetcher thinks is worth fetching next.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrefetchHint {
    /// The expert to fetch.
    pub expert: ExpertKey,
    /// Which observed expert triggered it.
    pub because_of: ExpertKey,
    /// How often they have co-activated, 0–100.
    pub confidence_pct: u32,
    /// How many times the pair has been seen.
    pub observations: u32,
}

/// Tracks which experts activate together and proposes prefetches.
///
/// Deliberately not a model. It is a counter table with a confidence bar,
/// which is cheap enough to run on the routing path and — because it learns
/// only what this node has actually served — does not carry the domain-shift
/// failure that trace-trained predictors do.
#[derive(Debug, Default)]
pub struct CoActivationTracker {
    /// (observed, candidate) -> times seen together.
    pairs: HashMap<(ExpertKey, ExpertKey), u32>,
    /// observed -> times seen at all, the denominator for confidence.
    totals: HashMap<ExpertKey, u32>,
}

impl CoActivationTracker {
    /// A tracker with no history.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record the set of experts one token routed to.
    ///
    /// Every ordered pair within the set is counted, because prefetching is
    /// directional: seeing A should suggest B, and seeing B should suggest A,
    /// and those are different questions with different denominators.
    pub fn observe(&mut self, activated: &[ExpertKey]) {
        for &a in activated {
            *self.totals.entry(a).or_insert(0) += 1;
            for &b in activated {
                if a != b {
                    *self.pairs.entry((a, b)).or_insert(0) += 1;
                }
            }
        }
    }

    /// How often `candidate` follows `observed`, as a ratio.
    pub fn confidence(&self, observed: ExpertKey, candidate: ExpertKey) -> f32 {
        let total = self.totals.get(&observed).copied().unwrap_or(0);
        if total < MIN_OBSERVATIONS {
            return 0.0;
        }
        let together = self.pairs.get(&(observed, candidate)).copied().unwrap_or(0);
        together as f32 / total as f32
    }

    /// What to prefetch given that `observed` just activated.
    ///
    /// `resident` is what is already in memory — prefetching something held
    /// is pure waste. Returns at most [`MAX_IN_FLIGHT`] entries, strongest
    /// first, and an empty vector when nothing clears the bar. Returning
    /// nothing is the common and correct answer: activation is diffuse, and a
    /// prefetcher that always finds something to fetch is one that has set its
    /// bar too low.
    pub fn hints(&self, observed: ExpertKey, resident: &[ExpertKey]) -> Vec<PrefetchHint> {
        let total = self.totals.get(&observed).copied().unwrap_or(0);
        if total < MIN_OBSERVATIONS {
            return Vec::new();
        }

        let mut hints: Vec<PrefetchHint> = self
            .pairs
            .iter()
            .filter(|((from, _), _)| *from == observed)
            .filter(|((_, to), _)| !resident.contains(to))
            .filter_map(|((_, to), &count)| {
                let confidence = count as f32 / total as f32;
                (confidence >= MIN_CONFIDENCE).then_some(PrefetchHint {
                    expert: *to,
                    because_of: observed,
                    confidence_pct: (confidence * 100.0) as u32,
                    observations: count,
                })
            })
            .collect();

        hints.sort_by(|a, b| {
            b.confidence_pct
                .cmp(&a.confidence_pct)
                .then(b.observations.cmp(&a.observations))
                // Deterministic on ties, so two nodes with identical history
                // propose identical prefetches and a difference in behaviour
                // means a difference in history.
                .then(a.expert.cmp(&b.expert))
        });
        hints.truncate(MAX_IN_FLIGHT);
        hints
    }

    /// How many distinct experts have been seen.
    pub fn tracked_experts(&self) -> usize {
        self.totals.len()
    }

    /// Whether enough has been seen for any hint to be possible.
    ///
    /// Lets a caller skip the work entirely while the table is still cold,
    /// rather than calling [`Self::hints`] on every token to be told no.
    pub fn is_warmed_up(&self) -> bool {
        self.totals.values().any(|&n| n >= MIN_OBSERVATIONS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: ExpertKey = (0, 1);
    const B: ExpertKey = (0, 2);
    const C: ExpertKey = (0, 3);
    const D: ExpertKey = (0, 4);

    fn observe_pair_n(t: &mut CoActivationTracker, a: ExpertKey, b: ExpertKey, n: u32) {
        for _ in 0..n {
            t.observe(&[a, b]);
        }
    }

    #[test]
    fn nothing_is_proposed_before_the_evidence_threshold() {
        // Two tokens routing to the same pair proves nothing — top-k puts
        // several experts together on every token.
        let mut t = CoActivationTracker::new();
        observe_pair_n(&mut t, A, B, MIN_OBSERVATIONS - 1);
        assert!(t.hints(A, &[]).is_empty());
        assert!(!t.is_warmed_up());

        t.observe(&[A, B]);
        assert!(t.is_warmed_up());
        assert!(!t.hints(A, &[]).is_empty());
    }

    #[test]
    fn a_consistently_co_activating_expert_is_proposed() {
        let mut t = CoActivationTracker::new();
        observe_pair_n(&mut t, A, B, 50);
        let hints = t.hints(A, &[]);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0].expert, B);
        assert_eq!(hints[0].because_of, A);
        assert_eq!(hints[0].confidence_pct, 100);
    }

    #[test]
    fn a_weakly_correlated_expert_is_not_worth_the_bandwidth() {
        // The bar is "usually right", not "better than chance", because a
        // wasted prefetch spends bandwidth the demand path is competing for.
        let mut t = CoActivationTracker::new();
        observe_pair_n(&mut t, A, B, 40);
        // C appears with A only a fifth of the time.
        for _ in 0..10 {
            t.observe(&[A, C]);
        }
        let proposed: Vec<ExpertKey> = t.hints(A, &[]).iter().map(|h| h.expert).collect();
        assert!(proposed.contains(&B));
        assert!(!proposed.contains(&C), "20% correlation is not enough");
    }

    #[test]
    fn an_already_resident_expert_is_never_prefetched() {
        // Fetching something already held is pure waste, and the residency
        // tier is the only thing that knows.
        let mut t = CoActivationTracker::new();
        observe_pair_n(&mut t, A, B, 50);
        assert!(t.hints(A, &[B]).is_empty());
    }

    #[test]
    fn hints_are_bounded_so_speculation_cannot_starve_the_demand_path() {
        // Both paths share one link. Past a small number, speculative fetches
        // delay the one something is actually blocked on.
        let mut t = CoActivationTracker::new();
        for _ in 0..50 {
            t.observe(&[A, B, C, D, (0, 5), (0, 6), (0, 7)]);
        }
        assert!(t.hints(A, &[]).len() <= MAX_IN_FLIGHT);
    }

    #[test]
    fn hints_come_back_strongest_first() {
        let mut t = CoActivationTracker::new();
        // A always with B, usually also with C.
        //
        // Observed together rather than in separate tokens, which matters:
        // separate observations share A's denominator and compete, so two
        // candidates at 50 and 35 sightings land at 59% and 41% — both under
        // the bar. Genuine co-activation within one token's top-k is the case
        // where several candidates can each be worth fetching.
        for _ in 0..50 {
            t.observe(&[A, B, C]);
        }
        for _ in 0..10 {
            t.observe(&[A, B]);
        }
        let hints = t.hints(A, &[]);
        assert!(hints.len() >= 2);
        assert_eq!(hints[0].expert, B, "the certain one first");
        for w in hints.windows(2) {
            assert!(w[0].confidence_pct >= w[1].confidence_pct);
        }
    }

    #[test]
    fn ordering_is_deterministic_on_ties() {
        // Two nodes with identical history should propose identical
        // prefetches, so a difference in behaviour means a difference in
        // history rather than a hash-order accident.
        let build = || {
            let mut t = CoActivationTracker::new();
            for _ in 0..50 {
                t.observe(&[A, B, C]);
            }
            t
        };
        let first: Vec<ExpertKey> = build().hints(A, &[]).iter().map(|h| h.expert).collect();
        for _ in 0..5 {
            let again: Vec<ExpertKey> = build().hints(A, &[]).iter().map(|h| h.expert).collect();
            assert_eq!(first, again);
        }
    }

    #[test]
    fn co_activation_is_directional() {
        // Seeing A suggests B, and seeing B suggests A, but the denominators
        // differ — B may activate far more often than A does.
        let mut t = CoActivationTracker::new();
        observe_pair_n(&mut t, A, B, 40);
        // B also activates a lot on its own, so A follows it rarely.
        for _ in 0..200 {
            t.observe(&[B, C]);
        }
        assert!(
            t.confidence(A, B) > MIN_CONFIDENCE,
            "A almost always brings B"
        );
        assert!(
            t.confidence(B, A) < MIN_CONFIDENCE,
            "B usually appears without A"
        );
    }

    #[test]
    fn an_unseen_expert_produces_no_hints_rather_than_a_guess() {
        let t = CoActivationTracker::new();
        assert!(t.hints((9, 9), &[]).is_empty());
        assert_eq!(t.confidence((9, 9), (9, 8)), 0.0);
        assert_eq!(t.tracked_experts(), 0);
    }

    #[test]
    fn a_single_expert_activation_records_no_pairs() {
        // Top-1 routing has nothing to correlate, and inventing a pair from
        // one expert would be fabricating evidence.
        let mut t = CoActivationTracker::new();
        for _ in 0..50 {
            t.observe(&[A]);
        }
        assert_eq!(t.tracked_experts(), 1);
        assert!(t.hints(A, &[]).is_empty());
    }

    #[test]
    fn diffuse_activation_produces_no_hints() {
        // The honest case, and the reason this is a counter table rather than
        // a model: when every token routes somewhere different — which is what
        // batching does to activation — there is nothing to predict, and the
        // right answer is to propose nothing rather than to fetch at random.
        let mut t = CoActivationTracker::new();
        for i in 0..200u32 {
            t.observe(&[A, (0, 10 + i % 64)]);
        }
        assert!(
            t.hints(A, &[]).is_empty(),
            "no candidate should clear the bar when activation is spread across 64 experts"
        );
    }
}
