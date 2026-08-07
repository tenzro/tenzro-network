//! Settling the same thing in more than one place, and surviving the primary.
//!
//! Tenzro settles on its own ledger and treats every other chain as a
//! **secondary** layer. A settler may want the same settlement recorded on
//! several of them at once — an EVM chain for a counterparty who lives there,
//! Canton for an auditor who needs delivery-versus-payment, the Tenzro Ledger
//! because it is the primary. This module is the fan-out that does it.
//!
//! # The requirement that shapes everything here
//!
//! Tenzro is on testnet. A testnet can be reset, and a mainnet migration can
//! renumber or discard chain state. **A settlement mirrored to another chain
//! must remain meaningful and usable after that happens** — the settler owns
//! that record, not Tenzro.
//!
//! That single requirement rules out the obvious design. Writing a Tenzro
//! reference to the external chain — a settlement id, a receipt hash — produces
//! a record that is only interpretable by asking Tenzro what the reference
//! meant. When Tenzro's state is gone, so is the meaning, and the settler is
//! left holding a hash of nothing.
//!
//! So a mirror carries [`MirrorDurability`], and the distinction is the point
//! of the module rather than a detail of it:
//!
//! - [`MirrorDurability::SelfContained`] — the external record embeds the
//!   canonical settlement bytes. Anyone holding it can recompute the
//!   commitment and read the parties, asset and amount **with no Tenzro node
//!   in existence**. This survives a testnet reset and a mainnet cutover.
//! - [`MirrorDurability::DigestOnly`] — the external record holds the
//!   commitment and nothing else. Cheaper, and it proves *that* something was
//!   settled and that a payload you already hold matches it. It cannot tell
//!   you *what* was settled, so on its own it does not survive losing Tenzro.
//!
//! Both are legitimate; only one is durable. The type makes a caller say which
//! it is choosing, and [`MirrorPlan::survives_primary_loss`] answers whether a
//! given plan actually meets the requirement above.
//!
//! # Mirrors are parallel and independent
//!
//! Each target settles on its own. One chain being congested, reorganising, or
//! rejecting a transaction must not roll back a settlement that already
//! committed elsewhere — there is no two-phase commit across chains that do not
//! know about each other, and pretending otherwise produces a system that is
//! atomic in the happy path and silently inconsistent everywhere else.
//!
//! So [`MirrorOutcome`] is per target, a plan reports partial success honestly,
//! and the primary is tracked separately from the secondaries: losing a
//! secondary is a degraded mirror, while losing the primary is a failed
//! settlement.

use serde::{Deserialize, Serialize};
use tenzro_types::provenance::SecondarySettlement;
use tenzro_types::settlement_network::{NetworkFamily, network_by_caip2};

/// How much of the settlement the external record carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirrorDurability {
    /// The external record embeds the canonical settlement bytes. Readable and
    /// verifiable with no Tenzro node — this is what survives a testnet reset
    /// or a mainnet cutover.
    SelfContained,
    /// The external record holds only the commitment. Proves a payload you
    /// already have is the one that settled; cannot tell you what settled.
    DigestOnly,
}

impl MirrorDurability {
    /// Whether a record written this way is still usable once the Tenzro
    /// Ledger's state is gone.
    pub fn survives_primary_loss(self) -> bool {
        matches!(self, MirrorDurability::SelfContained)
    }

    /// Stable wire form.
    pub fn as_str(self) -> &'static str {
        match self {
            MirrorDurability::SelfContained => "self_contained",
            MirrorDurability::DigestOnly => "digest_only",
        }
    }
}

/// Where one mirror got to.
///
/// `Pending` is a real state rather than an absence: a mirror dispatched and
/// not yet confirmed is different from one never attempted, and collapsing
/// them loses the ability to retry exactly the ones that need it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum MirrorState {
    /// Dispatched, awaiting confirmation on that chain.
    Pending,
    /// Confirmed, with the identifier that chain assigned.
    Confirmed {
        /// Transaction hash, Canton contract id, or bridge message id.
        reference: String,
        /// Unix ms the confirmation was observed.
        confirmed_at_ms: u64,
    },
    /// The chain refused it, or the dispatch failed.
    ///
    /// Carries the reason because a failed mirror is something an operator has
    /// to act on, and "mirroring failed" without a cause is not actionable.
    Failed {
        /// Why it failed.
        reason: String,
    },
}

impl MirrorState {
    /// Whether this mirror is durable on its chain.
    pub fn is_confirmed(&self) -> bool {
        matches!(self, MirrorState::Confirmed { .. })
    }

    /// Stable wire form.
    pub fn as_str(&self) -> &'static str {
        match self {
            MirrorState::Pending => "pending",
            MirrorState::Confirmed { .. } => "confirmed",
            MirrorState::Failed { .. } => "failed",
        }
    }
}

/// One chain a settlement is mirrored onto.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorTarget {
    /// CAIP-2 identifier of the chain. Canton is identified by its
    /// synchronizer rather than a CAIP-2 id, and uses `canton:global` here so
    /// one key type covers every target.
    pub caip2: String,
    /// How much of the settlement the record on that chain carries.
    pub durability: MirrorDurability,
}

impl MirrorTarget {
    /// A self-contained mirror — the durable choice.
    pub fn self_contained(caip2: impl Into<String>) -> Self {
        Self {
            caip2: caip2.into(),
            durability: MirrorDurability::SelfContained,
        }
    }

    /// A digest-only mirror.
    pub fn digest_only(caip2: impl Into<String>) -> Self {
        Self {
            caip2: caip2.into(),
            durability: MirrorDurability::DigestOnly,
        }
    }

    /// The family this target belongs to, if Tenzro knows the chain.
    pub fn family(&self) -> Option<NetworkFamily> {
        network_by_caip2(&self.caip2).map(|n| n.family)
    }
}

/// The result of mirroring onto one target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorOutcome {
    /// The target this outcome is for.
    pub target: MirrorTarget,
    /// Where it got to.
    pub state: MirrorState,
}

impl MirrorOutcome {
    /// Project into the provenance record's [`SecondarySettlement`].
    ///
    /// Returns `None` for anything not yet confirmed: the provenance record
    /// lists settlements that *happened*, and putting a pending or failed
    /// mirror in it would claim a settlement that does not exist on that chain.
    pub fn to_secondary(&self) -> Option<SecondarySettlement> {
        match &self.state {
            MirrorState::Confirmed { reference, .. } => Some(SecondarySettlement {
                layer: self
                    .target
                    .family()
                    .map(|f| f.as_str().to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                chain: self.target.caip2.clone(),
                reference: reference.clone(),
            }),
            _ => None,
        }
    }
}

/// Why a plan was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MirrorPlanError {
    /// The plan named the same chain twice.
    DuplicateTarget(String),
    /// The plan named a chain Tenzro does not settle on.
    UnknownChain(String),
    /// The plan named the Tenzro Ledger as a secondary target.
    PrimaryAsSecondary,
}

impl core::fmt::Display for MirrorPlanError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::DuplicateTarget(c) => write!(
                f,
                "chain `{c}` is named twice; mirroring the same settlement onto one chain twice \
                 double-counts it there"
            ),
            Self::UnknownChain(c) => write!(
                f,
                "chain `{c}` is not a settlement network Tenzro knows, so no adapter can carry a \
                 record to it"
            ),
            Self::PrimaryAsSecondary => write!(
                f,
                "the Tenzro Ledger is the primary settlement layer and cannot also be a secondary \
                 mirror of itself"
            ),
        }
    }
}

impl std::error::Error for MirrorPlanError {}

/// CAIP-2 of the primary settlement layer.
pub const PRIMARY_CAIP2: &str = "tenzro:1337";

/// A settlement's mirror plan: the primary, plus the secondaries it fans out to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorPlan {
    /// Secondary targets. The primary is implicit and always the Tenzro Ledger.
    pub targets: Vec<MirrorTarget>,
}

impl MirrorPlan {
    /// A plan that settles only on the Tenzro Ledger.
    ///
    /// The single-accounting-layer choice, and a legitimate one: a settler who
    /// wants exactly one book keeps exactly one.
    pub fn primary_only() -> Self {
        Self {
            targets: Vec::new(),
        }
    }

    /// Build and validate a plan against the chains this node can actually
    /// reach.
    ///
    /// `reachable` is supplied by the caller rather than read from the
    /// settlement registry alone, because Tenzro reaches far more chains than
    /// it settles on natively. The registry holds the ten networks with a
    /// direct settlement path; the bridge adapters — LayerZero, Chainlink
    /// CCIP, Wormhole, deBridge, Li.Fi, Hyperlane, Axelar, Stargate, IBC
    /// Eureka, Hyperbridge, NEAR chain signatures, Canton — reach well over a
    /// hundred more between them. Validating against the registry alone would
    /// refuse a mirror to almost everywhere Tenzro can actually write.
    ///
    /// The node builds this set from both sources: `SETTLEMENT_NETWORKS` plus
    /// every registered adapter's `supported_chains()`. Passing it in keeps
    /// this module from holding a second chain list that drifts from the
    /// router's.
    ///
    /// Note that the two sources identify chains differently — the settlement
    /// registry uses CAIP-2 (`eip155:8453`) while `ChainInfo::chain_id` uses
    /// plain names (`base`). Both forms are accepted here because both are
    /// real; a caller that has only one of them is not made to invent the
    /// other.
    pub fn new<S: AsRef<str>>(
        targets: Vec<MirrorTarget>,
        reachable: &[S],
    ) -> Result<Self, MirrorPlanError> {
        let mut seen = std::collections::HashSet::new();
        for t in &targets {
            if t.caip2 == PRIMARY_CAIP2 {
                return Err(MirrorPlanError::PrimaryAsSecondary);
            }
            let known = network_by_caip2(&t.caip2).is_some()
                || reachable.iter().any(|r| r.as_ref() == t.caip2);
            if !known {
                return Err(MirrorPlanError::UnknownChain(t.caip2.clone()));
            }
            if !seen.insert(t.caip2.clone()) {
                return Err(MirrorPlanError::DuplicateTarget(t.caip2.clone()));
            }
        }
        Ok(Self { targets })
    }

    /// Build a plan restricted to the networks Tenzro settles on natively.
    ///
    /// The conservative constructor, for callers with no live bridge router to
    /// enumerate.
    pub fn native_only(targets: Vec<MirrorTarget>) -> Result<Self, MirrorPlanError> {
        Self::new(targets, &[] as &[&str])
    }

    /// Whether this settlement is recorded anywhere other than the primary.
    pub fn is_mirrored(&self) -> bool {
        !self.targets.is_empty()
    }

    /// Whether the settlement remains readable if the Tenzro Ledger's state is
    /// lost — a testnet reset, or a mainnet cutover.
    ///
    /// True only when at least one target is [`MirrorDurability::SelfContained`].
    /// A plan of nothing but digest-only mirrors leaves the settler holding
    /// commitments they can no longer interpret, which is the failure this
    /// whole module exists to prevent.
    pub fn survives_primary_loss(&self) -> bool {
        self.targets
            .iter()
            .any(|t| t.durability.survives_primary_loss())
    }

    /// The targets that would not survive losing the primary.
    ///
    /// For warning an operator specifically, rather than failing a plan that
    /// may be deliberate.
    pub fn fragile_targets(&self) -> Vec<&MirrorTarget> {
        self.targets
            .iter()
            .filter(|t| !t.durability.survives_primary_loss())
            .collect()
    }
}

/// The result of executing a plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MirrorReport {
    /// Whether the primary settlement committed. A settlement whose primary
    /// failed is a failed settlement regardless of how many mirrors landed.
    pub primary_committed: bool,
    /// Per-target outcomes, one per plan target.
    pub outcomes: Vec<MirrorOutcome>,
}

impl MirrorReport {
    /// Every mirror that confirmed.
    pub fn confirmed(&self) -> impl Iterator<Item = &MirrorOutcome> {
        self.outcomes.iter().filter(|o| o.state.is_confirmed())
    }

    /// Whether every target confirmed.
    pub fn fully_mirrored(&self) -> bool {
        self.outcomes.iter().all(|o| o.state.is_confirmed())
    }

    /// Whether the settlement is durable beyond the primary: the primary
    /// committed **and** at least one self-contained mirror confirmed.
    ///
    /// Both halves are required. A confirmed digest-only mirror is not
    /// durability, and a self-contained mirror whose primary never committed
    /// is a record of a settlement that did not happen.
    pub fn is_durable_beyond_primary(&self) -> bool {
        self.primary_committed
            && self
                .confirmed()
                .any(|o| o.target.durability == MirrorDurability::SelfContained)
    }

    /// The `SecondarySettlement` entries for the provenance record.
    pub fn secondaries(&self) -> Vec<SecondarySettlement> {
        self.outcomes
            .iter()
            .filter_map(|o| o.to_secondary())
            .collect()
    }

    /// Targets that failed, for retry. Pending ones are excluded: they have not
    /// failed yet, and retrying a pending dispatch risks double-recording.
    pub fn failed(&self) -> Vec<&MirrorOutcome> {
        self.outcomes
            .iter()
            .filter(|o| matches!(o.state, MirrorState::Failed { .. }))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn confirmed(caip2: &str, d: MirrorDurability) -> MirrorOutcome {
        MirrorOutcome {
            target: MirrorTarget {
                caip2: caip2.into(),
                durability: d,
            },
            state: MirrorState::Confirmed {
                reference: format!("{caip2}-tx"),
                confirmed_at_ms: 1_700_000_000_000,
            },
        }
    }

    #[test]
    fn a_plan_may_settle_only_on_the_primary() {
        // One book is a legitimate choice, not a degenerate plan.
        let p = MirrorPlan::primary_only();
        assert!(!p.is_mirrored());
        assert!(!p.survives_primary_loss());
    }

    #[test]
    fn the_primary_cannot_be_its_own_secondary() {
        let e =
            MirrorPlan::native_only(vec![MirrorTarget::self_contained(PRIMARY_CAIP2)]).unwrap_err();
        assert_eq!(e, MirrorPlanError::PrimaryAsSecondary);
    }

    #[test]
    fn a_chain_named_twice_is_refused() {
        // Two records of one settlement on one chain is double-counting there.
        let e = MirrorPlan::native_only(vec![
            MirrorTarget::self_contained("eip155:8453"),
            MirrorTarget::digest_only("eip155:8453"),
        ])
        .unwrap_err();
        assert!(matches!(e, MirrorPlanError::DuplicateTarget(_)));
    }

    #[test]
    fn an_unknown_chain_is_refused_with_the_reason() {
        let e = MirrorPlan::native_only(vec![MirrorTarget::self_contained("bitcoin:mainnet")])
            .unwrap_err();
        assert!(e.to_string().contains("no adapter"), "unhelpful: {e}");
    }

    #[test]
    fn a_plan_spanning_evm_canton_and_xrpl_is_valid() {
        // The generalized case: one settlement, several unrelated layers.
        let p = MirrorPlan::native_only(vec![
            MirrorTarget::self_contained("eip155:8453"),
            MirrorTarget::self_contained("canton:global"),
            MirrorTarget::digest_only("xrpl:0"),
        ])
        .unwrap();
        assert!(p.is_mirrored());
        assert_eq!(p.targets.len(), 3);
    }

    #[test]
    fn only_self_contained_mirrors_survive_losing_the_primary() {
        // The requirement the module exists for: a testnet reset must not take
        // the settler's record with it.
        let fragile =
            MirrorPlan::native_only(vec![MirrorTarget::digest_only("eip155:8453")]).unwrap();
        assert!(!fragile.survives_primary_loss());
        assert_eq!(fragile.fragile_targets().len(), 1);

        let durable =
            MirrorPlan::native_only(vec![MirrorTarget::self_contained("eip155:8453")]).unwrap();
        assert!(durable.survives_primary_loss());
        assert!(durable.fragile_targets().is_empty());
    }

    #[test]
    fn a_mixed_plan_survives_and_still_names_its_fragile_targets() {
        // Survivability is satisfied by one durable target, but the operator
        // should still be told which of the others cannot stand alone.
        let p = MirrorPlan::native_only(vec![
            MirrorTarget::self_contained("canton:global"),
            MirrorTarget::digest_only("eip155:8453"),
        ])
        .unwrap();
        assert!(p.survives_primary_loss());
        assert_eq!(p.fragile_targets()[0].caip2, "eip155:8453");
    }

    #[test]
    fn a_failed_mirror_does_not_appear_in_provenance() {
        // The provenance record lists settlements that happened. Listing a
        // failed mirror would claim one that does not exist on that chain.
        let o = MirrorOutcome {
            target: MirrorTarget::self_contained("eip155:8453"),
            state: MirrorState::Failed {
                reason: "reverted".into(),
            },
        };
        assert!(o.to_secondary().is_none());
    }

    #[test]
    fn a_pending_mirror_does_not_appear_in_provenance_either() {
        let o = MirrorOutcome {
            target: MirrorTarget::self_contained("eip155:8453"),
            state: MirrorState::Pending,
        };
        assert!(o.to_secondary().is_none());
    }

    #[test]
    fn a_confirmed_mirror_projects_with_its_family_and_reference() {
        let s = confirmed("eip155:8453", MirrorDurability::SelfContained)
            .to_secondary()
            .unwrap();
        assert_eq!(s.layer, "evm");
        assert_eq!(s.chain, "eip155:8453");
        assert_eq!(s.reference, "eip155:8453-tx");

        let c = confirmed("canton:global", MirrorDurability::SelfContained)
            .to_secondary()
            .unwrap();
        assert_eq!(c.layer, "canton");
    }

    #[test]
    fn one_failing_chain_does_not_invalidate_the_others() {
        // No two-phase commit exists across chains that do not know about each
        // other. Partial success is reported honestly rather than rolled back.
        let report = MirrorReport {
            primary_committed: true,
            outcomes: vec![
                confirmed("eip155:8453", MirrorDurability::SelfContained),
                MirrorOutcome {
                    target: MirrorTarget::self_contained("xrpl:0"),
                    state: MirrorState::Failed {
                        reason: "fee too low".into(),
                    },
                },
            ],
        };
        assert!(!report.fully_mirrored());
        assert_eq!(report.confirmed().count(), 1);
        assert_eq!(report.failed().len(), 1);
        // Still durable: a self-contained mirror landed.
        assert!(report.is_durable_beyond_primary());
        assert_eq!(report.secondaries().len(), 1);
    }

    #[test]
    fn durability_requires_the_primary_to_have_committed() {
        // A self-contained mirror of a settlement that never committed is a
        // record of something that did not happen.
        let report = MirrorReport {
            primary_committed: false,
            outcomes: vec![confirmed("eip155:8453", MirrorDurability::SelfContained)],
        };
        assert!(!report.is_durable_beyond_primary());
    }

    #[test]
    fn confirmed_digest_only_mirrors_are_not_durability() {
        // They prove a payload you already hold is the one that settled. They
        // cannot tell you what settled, so they do not survive alone.
        let report = MirrorReport {
            primary_committed: true,
            outcomes: vec![confirmed("eip155:8453", MirrorDurability::DigestOnly)],
        };
        assert!(report.fully_mirrored());
        assert!(!report.is_durable_beyond_primary());
    }

    #[test]
    fn failed_lists_only_failures_never_pending() {
        // Retrying a pending dispatch risks recording the settlement twice.
        let report = MirrorReport {
            primary_committed: true,
            outcomes: vec![
                MirrorOutcome {
                    target: MirrorTarget::self_contained("eip155:8453"),
                    state: MirrorState::Pending,
                },
                MirrorOutcome {
                    target: MirrorTarget::self_contained("xrpl:0"),
                    state: MirrorState::Failed {
                        reason: "rejected".into(),
                    },
                },
            ],
        };
        assert_eq!(report.failed().len(), 1);
        assert_eq!(report.failed()[0].target.caip2, "xrpl:0");
    }

    #[test]
    fn a_target_resolves_its_family_from_the_network_registry() {
        // One registry decides which chains exist; this module does not keep a
        // second list that can drift from it.
        assert_eq!(
            MirrorTarget::self_contained("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp").family(),
            Some(NetworkFamily::Svm)
        );
        assert_eq!(MirrorTarget::self_contained("nope:1").family(), None);
    }

    #[test]
    fn a_bridge_reachable_chain_is_accepted_even_though_it_is_not_a_settlement_network() {
        // Tenzro settles natively on ten networks and *reaches* well over a
        // hundred through LayerZero, CCIP, Wormhole, deBridge, Li.Fi,
        // Hyperlane, Axelar and the rest. Validating against the settlement
        // registry alone would refuse a mirror to almost everywhere it can
        // actually write.
        let reachable = ["eip155:10", "avalanche", "sui:mainnet"];
        let p = MirrorPlan::new(
            vec![
                MirrorTarget::self_contained("eip155:10"),
                MirrorTarget::self_contained("sui:mainnet"),
            ],
            &reachable,
        )
        .unwrap();
        assert_eq!(p.targets.len(), 2);
        // And it is still refused when nothing can carry it.
        assert!(
            MirrorPlan::new(
                vec![MirrorTarget::self_contained("eip155:10")],
                &[] as &[&str]
            )
            .is_err()
        );
    }

    #[test]
    fn plain_chain_names_are_accepted_alongside_caip2() {
        // The bridge layer identifies chains by name (`ChainInfo::chain_id`)
        // while the settlement registry uses CAIP-2. Both are real, so a
        // caller holding only one form is not made to invent the other.
        let p = MirrorPlan::new(
            vec![MirrorTarget::self_contained("avalanche")],
            &["avalanche"],
        )
        .unwrap();
        assert_eq!(p.targets[0].caip2, "avalanche");
        // A name with no registry entry resolves no family, which is honest
        // rather than a guess.
        assert!(p.targets[0].family().is_none());
    }

    #[test]
    fn native_settlement_networks_need_no_reachability_list() {
        // The ten networks with a direct settlement path are always mirrorable.
        for caip2 in [
            "eip155:8453",
            "canton:global",
            "xrpl:0",
            "stellar:pubnet",
            "eip155:98866",
            "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        ] {
            assert!(
                MirrorPlan::native_only(vec![MirrorTarget::self_contained(caip2)]).is_ok(),
                "{caip2} must be mirrorable without a bridge list"
            );
        }
    }
}
