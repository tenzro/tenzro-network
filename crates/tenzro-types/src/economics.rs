//! The network's economic policy: who is paid, how much, and in what asset.
//!
//! One module, one answer. Before this existed the workspace held five
//! mutually-unaware notions of "the network's cut" — a revenue split, a
//! settlement-engine fee, a commission-rate table, a marketplace constant and a
//! developer margin — each with its own hardcoded rate, each reached from a
//! different call site, and two of them stacking on the same payment. A caller
//! reading a receipt could not tell what had actually moved.
//!
//! # A node's economic mode follows from what it does, not what it declares
//!
//! [`NodeEconomicMode`] is *derived* (see [`NodeEconomicMode::resolve`]) from two
//! facts the node already knows: whether the capability serving the request is
//! advertised to the network, and whether this node validates. An operator
//! cannot select a mode that pays them more than their participation earns,
//! because there is no field for them to set.
//!
//! - **[`NodeEconomicMode::Private`]** — the node is connected to the network but
//!   does not advertise. Its resources are reached through API keys and service
//!   keys the operator issues. Nobody discovered it, and no validator was
//!   engaged on the caller's behalf, so the whole payment is the operator's.
//!   Ledger gas is still owed on any transaction it settles; that is a separate
//!   stream and is not a commission.
//! - **[`NodeEconomicMode::PublicValidating`]** — advertised, and the node runs
//!   the validator role. Two parties: the operator, and the treasury.
//! - **[`NodeEconomicMode::PublicDelegated`]** — advertised, but the node does not
//!   validate, so some RPC provider validates for its users. Three parties: the
//!   operator, that RPC provider, and the treasury.
//!
//! The RPC provider is paid here *only* in the delegated mode, and only for the
//! validation it actually performs on this node's behalf. That is distinct from
//! the RPC provider's own business — brokering external networks such as Canton
//! to their own tenants — which they bill for separately under
//! [`crate::access_tier::RpcServiceGrant`] and which never touches this split.
//!
//! # Every rate is governance-settable, and none is a constant
//!
//! [`EconomicPolicy`] is the single parameter block. It is serialisable,
//! persisted, and reachable by governance proposal. A rate that lives in a
//! `const` has to be found and changed in a release, with every node that has
//! not upgraded still charging the old one — which is the failure this module
//! exists to remove.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Basis points in a whole. Every share in this module is denominated in these.
pub const BPS_DENOMINATOR: u32 = 10_000;

/// A party that can receive part of a settled payment.
///
/// Ordered by settlement precedence: the operator's leg moves first because it
/// is the one that funds the work, and a failure on a downstream leg must not
/// leave the party that did the work unpaid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayeeRole {
    /// The node operator that served the request.
    Operator,
    /// The RPC provider validating on this node's behalf. Present only in
    /// [`NodeEconomicMode::PublicDelegated`].
    RpcProvider,
    /// The Tenzro Network treasury.
    Treasury,
}

impl PayeeRole {
    /// Stable wire form.
    pub fn as_str(&self) -> &'static str {
        match self {
            PayeeRole::Operator => "operator",
            PayeeRole::RpcProvider => "rpc_provider",
            PayeeRole::Treasury => "treasury",
        }
    }

    /// Parse the wire form. Unknown values are refused rather than defaulted —
    /// a typo that silently became "pay the treasury" is the wrong way to be
    /// wrong.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "operator" => Some(PayeeRole::Operator),
            "rpc_provider" => Some(PayeeRole::RpcProvider),
            "treasury" => Some(PayeeRole::Treasury),
            _ => None,
        }
    }
}

impl fmt::Display for PayeeRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How a node participates in the network, and therefore how its revenue
/// divides.
///
/// Deliberately has no `Deserialize`-from-operator-config path into a
/// settlement: it is produced by [`NodeEconomicMode::resolve`] from observed
/// participation. It is `Serialize`/`Deserialize` so a receipt can record which
/// mode was live when a payment settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeEconomicMode {
    /// Connected but not advertised. Reached through operator-issued API keys
    /// and service keys. The operator takes the whole payment.
    Private,
    /// Advertised, and validating. Operator and treasury.
    PublicValidating,
    /// Advertised, not validating — an RPC provider validates for this node's
    /// users. Operator, that RPC provider, and treasury.
    PublicDelegated,
}

impl NodeEconomicMode {
    /// Derive the mode from participation.
    ///
    /// `advertised` is whether the capability that served this request is
    /// published to the network ([`crate::node_visibility::Visibility::Network`]).
    /// `validating` is whether this node runs the validator role.
    ///
    /// A node that does not advertise is private *whether or not it validates*:
    /// validating earns consensus rewards, which is a different stream, and it
    /// does not entitle the network to a share of revenue from callers the
    /// network never introduced.
    pub fn resolve(advertised: bool, validating: bool) -> Self {
        match (advertised, validating) {
            (false, _) => NodeEconomicMode::Private,
            (true, true) => NodeEconomicMode::PublicValidating,
            (true, false) => NodeEconomicMode::PublicDelegated,
        }
    }

    /// Stable wire form.
    pub fn as_str(&self) -> &'static str {
        match self {
            NodeEconomicMode::Private => "private",
            NodeEconomicMode::PublicValidating => "public_validating",
            NodeEconomicMode::PublicDelegated => "public_delegated",
        }
    }

    /// Parse the wire form; unknown values are refused.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "private" => Some(NodeEconomicMode::Private),
            "public_validating" => Some(NodeEconomicMode::PublicValidating),
            "public_delegated" => Some(NodeEconomicMode::PublicDelegated),
            _ => None,
        }
    }

    /// The roles paid in this mode, in settlement order.
    pub fn payees(&self) -> &'static [PayeeRole] {
        match self {
            NodeEconomicMode::Private => &[PayeeRole::Operator],
            NodeEconomicMode::PublicValidating => &[PayeeRole::Operator, PayeeRole::Treasury],
            NodeEconomicMode::PublicDelegated => &[
                PayeeRole::Operator,
                PayeeRole::RpcProvider,
                PayeeRole::Treasury,
            ],
        }
    }

    /// Whether this mode needs an RPC provider address to settle.
    ///
    /// Asked before settlement so a node in delegated mode that cannot name its
    /// RPC provider is refused loudly rather than quietly paying that share to
    /// someone else.
    pub fn requires_rpc_provider(&self) -> bool {
        matches!(self, NodeEconomicMode::PublicDelegated)
    }
}

impl fmt::Display for NodeEconomicMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why an economic policy was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EconomicPolicyError {
    /// Shares for a mode did not sum to [`BPS_DENOMINATOR`].
    SharesDoNotSum {
        /// The mode whose schedule is wrong.
        mode: NodeEconomicMode,
        /// What the shares actually summed to.
        total: u32,
    },
    /// The operator's share was not a strict majority.
    OperatorNotMajority {
        /// The mode whose schedule is wrong.
        mode: NodeEconomicMode,
        /// The operator share that was offered.
        operator_bps: u32,
    },
    /// A rate exceeded 100%.
    RateOutOfRange {
        /// Which rate.
        name: &'static str,
        /// The value offered.
        bps: u32,
    },
}

impl fmt::Display for EconomicPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SharesDoNotSum { mode, total } => write!(
                f,
                "{mode} shares must sum to exactly {BPS_DENOMINATOR} bps, got {total}: a schedule \
                 that sums low strands value with no owner, and one that sums high pays out more \
                 than came in"
            ),
            Self::OperatorNotMajority { mode, operator_bps } => write!(
                f,
                "{mode} gives the serving operator {operator_bps} bps, which is not more than half \
                 of {BPS_DENOMINATOR}. The party doing the work has to earn most of the payment or \
                 there is no reason to serve"
            ),
            Self::RateOutOfRange { name, bps } => {
                write!(f, "{name} is {bps} bps, above 100%")
            }
        }
    }
}

impl std::error::Error for EconomicPolicyError {}

/// The division of one payment in [`NodeEconomicMode::PublicValidating`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatingSchedule {
    /// Share to the operator that served the request.
    pub operator_bps: u32,
    /// Share to the network treasury.
    pub treasury_bps: u32,
}

impl Default for ValidatingSchedule {
    /// 90% operator, 10% treasury.
    ///
    /// A validating node already earns consensus rewards for the validation it
    /// performs, so the network's cut of its *service* revenue is the smaller
    /// one — the node is paying for discovery and settlement, not for a
    /// validator someone else ran.
    fn default() -> Self {
        Self {
            operator_bps: 9_000,
            treasury_bps: 1_000,
        }
    }
}

/// The division of one payment in [`NodeEconomicMode::PublicDelegated`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegatedSchedule {
    /// Share to the operator that served the request.
    pub operator_bps: u32,
    /// Share to the RPC provider validating on this node's behalf.
    pub rpc_provider_bps: u32,
    /// Share to the network treasury.
    pub treasury_bps: u32,
}

impl Default for DelegatedSchedule {
    /// 80% operator, 10% RPC provider, 10% treasury.
    ///
    /// The operator's share is 10 points lower than in the validating schedule,
    /// and that difference is exactly the RPC provider's leg: the node is
    /// buying validation it does not perform itself. The treasury's cut is
    /// unchanged, because what the treasury does for the payment — discovery,
    /// settlement, the registry — is the same either way.
    fn default() -> Self {
        Self {
            operator_bps: 8_000,
            rpc_provider_bps: 1_000,
            treasury_bps: 1_000,
        }
    }
}

/// What the network does with an inbound asset that is not TNZO.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConversionPolicy {
    /// Convert to TNZO at settlement. The network's default: TNZO is the unit
    /// the ledger accounts in, and a treasury holding forty stablecoins is a
    /// treasury nobody can value.
    #[default]
    ConvertToTnzo,
    /// Settle in whatever asset arrived. Selected per payee, for operators who
    /// would rather hold the stablecoin they were paid in than take conversion
    /// risk on every microtransaction.
    KeepInbound,
}

impl ConversionPolicy {
    /// Stable wire form.
    pub fn as_str(&self) -> &'static str {
        match self {
            ConversionPolicy::ConvertToTnzo => "convert_to_tnzo",
            ConversionPolicy::KeepInbound => "keep_inbound",
        }
    }

    /// Parse the wire form; unknown values are refused.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "convert_to_tnzo" => Some(ConversionPolicy::ConvertToTnzo),
            "keep_inbound" => Some(ConversionPolicy::KeepInbound),
            _ => None,
        }
    }
}

impl fmt::Display for ConversionPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Every rate the network charges, in one governance-settable block.
///
/// Persisted and hydrated by the node; mutated only through a governance
/// proposal. Nothing in this struct has a `const` twin elsewhere in the
/// workspace — where a constant used to hold a rate, the call site now reads
/// this.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EconomicPolicy {
    /// Division when the serving node validates for itself.
    pub validating: ValidatingSchedule,
    /// Division when an RPC provider validates on the serving node's behalf.
    pub delegated: DelegatedSchedule,
    /// Commission on marketplace invocations (agent templates, skills, tools),
    /// taken from the creator's price.
    pub marketplace_commission_bps: u32,
    /// The network's default disposition of a non-TNZO inbound asset. A payee
    /// may override it for their own receipts; this is what applies when they
    /// have expressed no preference.
    pub default_conversion: ConversionPolicy,
    /// Smallest charge the meter will settle on its own rather than accumulate.
    ///
    /// A per-token charge can be worth less than the gas to move it. Below this
    /// floor the meter accrues into a channel and settles the aggregate — the
    /// charge is still metered exactly, it is just not moved on its own.
    pub micro_settlement_floor: u128,
}

impl Default for EconomicPolicy {
    fn default() -> Self {
        Self {
            validating: ValidatingSchedule::default(),
            delegated: DelegatedSchedule::default(),
            marketplace_commission_bps: 500,
            default_conversion: ConversionPolicy::ConvertToTnzo,
            // 10^13 of 10^18 — one ten-thousandth of a TNZO. Chosen so a single
            // token of a cheap model accrues rather than settling alone, while a
            // media-generation call settles immediately.
            micro_settlement_floor: 10_000_000_000_000,
        }
    }
}

impl EconomicPolicy {
    /// Check every schedule is payable and incentive-sound.
    ///
    /// # Errors
    ///
    /// - a schedule's shares do not sum to exactly [`BPS_DENOMINATOR`]
    /// - a schedule does not leave the serving operator a strict majority
    /// - a commission rate exceeds 100%
    pub fn validate(&self) -> Result<(), EconomicPolicyError> {
        let validating_total = self
            .validating
            .operator_bps
            .saturating_add(self.validating.treasury_bps);
        if validating_total != BPS_DENOMINATOR {
            return Err(EconomicPolicyError::SharesDoNotSum {
                mode: NodeEconomicMode::PublicValidating,
                total: validating_total,
            });
        }
        if !is_strict_majority(self.validating.operator_bps) {
            return Err(EconomicPolicyError::OperatorNotMajority {
                mode: NodeEconomicMode::PublicValidating,
                operator_bps: self.validating.operator_bps,
            });
        }

        let delegated_total = self
            .delegated
            .operator_bps
            .saturating_add(self.delegated.rpc_provider_bps)
            .saturating_add(self.delegated.treasury_bps);
        if delegated_total != BPS_DENOMINATOR {
            return Err(EconomicPolicyError::SharesDoNotSum {
                mode: NodeEconomicMode::PublicDelegated,
                total: delegated_total,
            });
        }
        if !is_strict_majority(self.delegated.operator_bps) {
            return Err(EconomicPolicyError::OperatorNotMajority {
                mode: NodeEconomicMode::PublicDelegated,
                operator_bps: self.delegated.operator_bps,
            });
        }

        if self.marketplace_commission_bps > BPS_DENOMINATOR {
            return Err(EconomicPolicyError::RateOutOfRange {
                name: "marketplace_commission_bps",
                bps: self.marketplace_commission_bps,
            });
        }

        Ok(())
    }

    /// The share `role` takes under `mode`, in basis points.
    ///
    /// Zero for a role the mode does not pay, which is what makes a caller's
    /// arithmetic over [`NodeEconomicMode::payees`] total correctly without a
    /// per-mode branch.
    pub fn share_bps(&self, mode: NodeEconomicMode, role: PayeeRole) -> u32 {
        match (mode, role) {
            (NodeEconomicMode::Private, PayeeRole::Operator) => BPS_DENOMINATOR,
            (NodeEconomicMode::Private, _) => 0,

            (NodeEconomicMode::PublicValidating, PayeeRole::Operator) => {
                self.validating.operator_bps
            }
            (NodeEconomicMode::PublicValidating, PayeeRole::Treasury) => {
                self.validating.treasury_bps
            }
            (NodeEconomicMode::PublicValidating, PayeeRole::RpcProvider) => 0,

            (NodeEconomicMode::PublicDelegated, PayeeRole::Operator) => self.delegated.operator_bps,
            (NodeEconomicMode::PublicDelegated, PayeeRole::RpcProvider) => {
                self.delegated.rpc_provider_bps
            }
            (NodeEconomicMode::PublicDelegated, PayeeRole::Treasury) => self.delegated.treasury_bps,
        }
    }
}

/// Strictly more than half, so an exact 50/50 is rejected too: at half, the
/// operator is not being paid to serve, they are splitting with parties that
/// did not do the work.
fn is_strict_majority(bps: u32) -> bool {
    bps.saturating_mul(2) > BPS_DENOMINATOR
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_node_that_does_not_advertise_is_private_however_it_participates() {
        // Validating earns consensus rewards — a different stream. It does not
        // entitle the network to revenue from callers it never introduced.
        assert_eq!(
            NodeEconomicMode::resolve(false, true),
            NodeEconomicMode::Private
        );
        assert_eq!(
            NodeEconomicMode::resolve(false, false),
            NodeEconomicMode::Private
        );
    }

    #[test]
    fn advertising_splits_two_ways_when_validating_and_three_when_not() {
        assert_eq!(
            NodeEconomicMode::resolve(true, true),
            NodeEconomicMode::PublicValidating
        );
        assert_eq!(
            NodeEconomicMode::resolve(true, false),
            NodeEconomicMode::PublicDelegated
        );
        assert_eq!(NodeEconomicMode::PublicValidating.payees().len(), 2);
        assert_eq!(NodeEconomicMode::PublicDelegated.payees().len(), 3);
        assert_eq!(NodeEconomicMode::Private.payees(), &[PayeeRole::Operator]);
    }

    #[test]
    fn only_the_delegated_mode_needs_an_rpc_provider() {
        assert!(NodeEconomicMode::PublicDelegated.requires_rpc_provider());
        assert!(!NodeEconomicMode::PublicValidating.requires_rpc_provider());
        assert!(!NodeEconomicMode::Private.requires_rpc_provider());
    }

    #[test]
    fn a_private_node_keeps_the_whole_payment() {
        let policy = EconomicPolicy::default();
        assert_eq!(
            policy.share_bps(NodeEconomicMode::Private, PayeeRole::Operator),
            BPS_DENOMINATOR
        );
        assert_eq!(
            policy.share_bps(NodeEconomicMode::Private, PayeeRole::Treasury),
            0
        );
        assert_eq!(
            policy.share_bps(NodeEconomicMode::Private, PayeeRole::RpcProvider),
            0
        );
    }

    /// The difference between the two public schedules is exactly the RPC
    /// provider's leg — the node is buying validation it does not perform.
    #[test]
    fn the_rpc_providers_leg_comes_out_of_the_operators_share() {
        let policy = EconomicPolicy::default();
        assert_eq!(
            policy.validating.operator_bps - policy.delegated.operator_bps,
            policy.delegated.rpc_provider_bps
        );
        // What the treasury does for the payment is the same either way.
        assert_eq!(
            policy.validating.treasury_bps,
            policy.delegated.treasury_bps
        );
    }

    #[test]
    fn every_mode_totals_the_whole_payment() {
        let policy = EconomicPolicy::default();
        for mode in [
            NodeEconomicMode::Private,
            NodeEconomicMode::PublicValidating,
            NodeEconomicMode::PublicDelegated,
        ] {
            let total: u32 = mode
                .payees()
                .iter()
                .map(|role| policy.share_bps(mode, *role))
                .sum();
            assert_eq!(total, BPS_DENOMINATOR, "{mode} did not total");
        }
    }

    #[test]
    fn the_default_policy_is_valid() {
        EconomicPolicy::default().validate().unwrap();
    }

    #[test]
    fn a_schedule_that_does_not_sum_is_refused() {
        let mut policy = EconomicPolicy::default();
        policy.validating.treasury_bps = 500;
        assert!(matches!(
            policy.validate(),
            Err(EconomicPolicyError::SharesDoNotSum {
                mode: NodeEconomicMode::PublicValidating,
                ..
            })
        ));

        let mut policy = EconomicPolicy::default();
        policy.delegated.treasury_bps = 2_000;
        assert!(matches!(
            policy.validate(),
            Err(EconomicPolicyError::SharesDoNotSum {
                mode: NodeEconomicMode::PublicDelegated,
                ..
            })
        ));
    }

    /// The incentive constraint, enforced rather than documented — and it holds
    /// for governance too.
    #[test]
    fn the_operator_must_hold_a_strict_majority_in_both_public_modes() {
        let mut policy = EconomicPolicy::default();
        policy.validating = ValidatingSchedule {
            operator_bps: 5_000,
            treasury_bps: 5_000,
        };
        let err = policy.validate().expect_err("50/50 is not a majority");
        assert!(format!("{err}").contains("not more than half"));

        let mut policy = EconomicPolicy::default();
        policy.delegated = DelegatedSchedule {
            operator_bps: 4_000,
            rpc_provider_bps: 3_000,
            treasury_bps: 3_000,
        };
        assert!(matches!(
            policy.validate(),
            Err(EconomicPolicyError::OperatorNotMajority { .. })
        ));

        // One bp over half is a majority.
        let mut policy = EconomicPolicy::default();
        policy.validating = ValidatingSchedule {
            operator_bps: 5_001,
            treasury_bps: 4_999,
        };
        policy.validate().unwrap();
    }

    #[test]
    fn a_commission_above_one_hundred_percent_is_refused() {
        let mut policy = EconomicPolicy::default();
        policy.marketplace_commission_bps = BPS_DENOMINATOR + 1;
        assert!(matches!(
            policy.validate(),
            Err(EconomicPolicyError::RateOutOfRange {
                name: "marketplace_commission_bps",
                ..
            })
        ));
    }

    /// TNZO is the unit the ledger accounts in, so it is what the network takes
    /// unless a payee says otherwise.
    #[test]
    fn the_network_converts_to_tnzo_by_default() {
        assert_eq!(
            EconomicPolicy::default().default_conversion,
            ConversionPolicy::ConvertToTnzo
        );
    }

    #[test]
    fn wire_forms_round_trip() {
        for mode in [
            NodeEconomicMode::Private,
            NodeEconomicMode::PublicValidating,
            NodeEconomicMode::PublicDelegated,
        ] {
            assert_eq!(NodeEconomicMode::parse(mode.as_str()), Some(mode));
        }
        for role in [
            PayeeRole::Operator,
            PayeeRole::RpcProvider,
            PayeeRole::Treasury,
        ] {
            assert_eq!(PayeeRole::parse(role.as_str()), Some(role));
        }
        for policy in [
            ConversionPolicy::ConvertToTnzo,
            ConversionPolicy::KeepInbound,
        ] {
            assert_eq!(ConversionPolicy::parse(policy.as_str()), Some(policy));
        }
        assert_eq!(NodeEconomicMode::parse("public"), None);
        assert_eq!(PayeeRole::parse("custodian"), None);
        assert_eq!(ConversionPolicy::parse("tnzo"), None);
    }

    #[test]
    fn the_policy_survives_serialization() {
        let policy = EconomicPolicy::default();
        let json = serde_json::to_string(&policy).expect("serializes");
        let back: EconomicPolicy = serde_json::from_str(&json).expect("parses");
        assert_eq!(back, policy);
    }
}
