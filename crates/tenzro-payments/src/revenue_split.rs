//! Dividing one settled payment among the parties that earned it.
//!
//! [`crate::settlement_asset`] decides *what asset* settles; this module decides
//! *who receives it*, and in what proportion. The proportions themselves are
//! [`tenzro_types::economics::EconomicPolicy`] — governance's, not this
//! module's.
//!
//! # The mode decides the payees, and participation decides the mode
//!
//! There is no configuration here that lets an operator choose to be paid more.
//! [`tenzro_types::economics::NodeEconomicMode`] is derived from whether the
//! node advertises the capability that served the request and whether it
//! validates:
//!
//! - **Private** — connected but not advertised, reached through the operator's
//!   own API keys and service keys. Nobody discovered the node and no validator
//!   was engaged for the caller, so the operator keeps the payment.
//! - **Public, validating** — operator and treasury.
//! - **Public, not validating** — operator, the RPC provider validating on this
//!   node's behalf, and treasury.
//!
//! # This is the only place a service payment is divided
//!
//! Previously a payment could be divided here *and* have a network fee taken
//! again inside the settlement engine, so a receipt reported an operator share
//! the operator never received. [`split_revenue`] now produces the complete
//! division, every leg is paid from it, and nothing downstream takes a second
//! cut. [`RevenueSplit::total`] equalling the input is the invariant that keeps
//! it that way, and it is asserted rather than assumed.
//!
//! # An RPC provider's own tenants are billed elsewhere
//!
//! The RPC-provider leg pays for *validation performed on this node's behalf*,
//! and appears only in the delegated mode. It is not payment for brokering
//! external networks — that is the provider's own business with their own
//! tenants, under
//! [`tenzro_types::access_tier::RpcServiceGrant`], and it never touches this
//! split. Charging both here and there would be charging twice for two
//! different things and calling it one.

use serde::{Deserialize, Serialize};
use tenzro_types::economics::{BPS_DENOMINATOR, EconomicPolicy, NodeEconomicMode, PayeeRole};

use crate::error::{PaymentError, Result};

/// Where each role's share is paid.
///
/// Addresses are opaque strings so the same split works whether the payout is a
/// TNZO account, an EVM address or a Solana pubkey — the settlement asset is
/// [`crate::settlement_asset`]'s decision and this type must not constrain it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitPayees {
    /// The operator that served the request.
    pub operator: String,
    /// The RPC provider validating on this node's behalf.
    ///
    /// Required in [`NodeEconomicMode::PublicDelegated`] and meaningless in the
    /// other two. A delegated split with no RPC provider named is refused
    /// rather than quietly redirected — paying that leg to the treasury because
    /// the provider could not be resolved would be paying the wrong party and
    /// reporting it as if nothing were wrong.
    pub rpc_provider: Option<String>,
    /// The network treasury.
    ///
    /// Supplied by the caller from the derived treasury account. Keyless, so
    /// value that arrives there moves only through the treasury's authorised
    /// withdrawal path.
    pub treasury: String,
}

impl SplitPayees {
    /// Payees for a node that keeps the whole payment.
    pub fn private(operator: impl Into<String>) -> Self {
        Self {
            operator: operator.into(),
            rpc_provider: None,
            treasury: String::new(),
        }
    }

    /// Payees for a node that validates for itself.
    pub fn validating(operator: impl Into<String>, treasury: impl Into<String>) -> Self {
        Self {
            operator: operator.into(),
            rpc_provider: None,
            treasury: treasury.into(),
        }
    }

    /// Payees for a node whose validation is performed by an RPC provider.
    pub fn delegated(
        operator: impl Into<String>,
        rpc_provider: impl Into<String>,
        treasury: impl Into<String>,
    ) -> Self {
        Self {
            operator: operator.into(),
            rpc_provider: Some(rpc_provider.into()),
            treasury: treasury.into(),
        }
    }

    /// The address for `role`, if this set names one.
    fn address_for(&self, role: PayeeRole) -> Option<&str> {
        match role {
            PayeeRole::Operator => Some(self.operator.as_str()),
            PayeeRole::RpcProvider => self.rpc_provider.as_deref(),
            PayeeRole::Treasury => Some(self.treasury.as_str()),
        }
    }
}

/// One party's cut of a payment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitShare {
    /// Which role is being paid.
    pub role: PayeeRole,
    /// Who is paid.
    pub payee: String,
    /// How much, in the settled asset's smallest unit.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub amount: u128,
    /// The share in basis points, carried so a receipt can be audited without
    /// re-deriving it from a policy that may since have changed.
    pub bps: u32,
}

/// The complete division of one payment.
///
/// Complete is the load-bearing word: every party that will be paid appears
/// here, and nothing downstream takes a further cut.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevenueSplit {
    /// The mode that produced this division, recorded so a receipt explains
    /// itself.
    pub mode: NodeEconomicMode,
    /// Each party's cut, in settlement order — the operator first, so a failure
    /// on a downstream leg cannot leave the party that did the work unpaid.
    pub shares: Vec<SplitShare>,
}

impl RevenueSplit {
    /// Total paid out. Always equals the amount that was split — see
    /// [`split_revenue`].
    pub fn total(&self) -> u128 {
        self.shares.iter().map(|s| s.amount).sum()
    }

    /// The share paid to `role`, if this mode pays it.
    pub fn share(&self, role: PayeeRole) -> Option<&SplitShare> {
        self.shares.iter().find(|s| s.role == role)
    }

    /// The amount paid to `role`, or zero if this mode does not pay it.
    pub fn amount_for(&self, role: PayeeRole) -> u128 {
        self.share(role).map_or(0, |s| s.amount)
    }

    /// The operator's share, which every mode pays.
    ///
    /// Infallible because [`split_revenue`] always emits it: there is no mode in
    /// which the party that served the request is not paid.
    pub fn operator(&self) -> &SplitShare {
        self.share(PayeeRole::Operator)
            .expect("every mode pays the operator")
    }
}

/// Divide `amount` according to `mode` and `policy`.
///
/// # Conservation
///
/// The shares sum to exactly `amount`, always. Integer division discards a
/// remainder of up to one smallest-unit per non-operator leg; rather than let
/// that vanish it is given to the operator — the majority party, whose share is
/// least distorted by it, and the one already receiving the residual.
///
/// This matters more than the rounding. Value that neither arrives nor is
/// accounted for is the kind of leak that surfaces months later as a balance
/// nobody can reconcile, on a path that runs on every settled request.
///
/// # Errors
///
/// - `policy` fails [`EconomicPolicy::validate`]
/// - `mode` is [`NodeEconomicMode::PublicDelegated`] and `payees` names no RPC
///   provider
/// - a mode that pays the treasury is given an empty treasury address
pub fn split_revenue(
    amount: u128,
    mode: NodeEconomicMode,
    policy: &EconomicPolicy,
    payees: &SplitPayees,
) -> Result<RevenueSplit> {
    policy
        .validate()
        .map_err(|e| PaymentError::ConfigError(e.to_string()))?;

    if mode.requires_rpc_provider() && payees.rpc_provider.is_none() {
        return Err(PaymentError::ConfigError(
            "a node whose validation is performed by an RPC provider must name that provider \
             before it can settle: paying their leg to anyone else would pay the wrong party and \
             report it as if nothing were wrong"
                .to_string(),
        ));
    }

    let mut shares = Vec::with_capacity(mode.payees().len());
    let mut tail_total: u128 = 0;

    // Every leg but the operator's is computed directly; the operator takes the
    // residual, which is what makes conservation exact by construction rather
    // than by a rounding rule that has to be got right.
    for role in mode.payees().iter().copied() {
        if role == PayeeRole::Operator {
            continue;
        }
        let bps = policy.share_bps(mode, role);
        let payee = payees.address_for(role).ok_or_else(|| {
            PaymentError::ConfigError(format!(
                "the {mode} split pays {role} but no {role} address was supplied"
            ))
        })?;
        if payee.is_empty() {
            return Err(PaymentError::ConfigError(format!(
                "the {mode} split pays {role} but the {role} address is empty; settling would \
                 send that share nowhere"
            )));
        }
        let share_amount = apply_bps(amount, bps);
        tail_total = tail_total
            .checked_add(share_amount)
            .ok_or_else(|| PaymentError::ConfigError("revenue split shares overflow".into()))?;
        shares.push(SplitShare {
            role,
            payee: payee.to_string(),
            amount: share_amount,
            bps,
        });
    }

    // Whatever is left, including the rounding dust. Subtraction rather than a
    // further multiply is what makes the total exact.
    let operator_amount = amount.checked_sub(tail_total).ok_or_else(|| {
        PaymentError::ConfigError(
            "revenue split tail exceeded the amount being split; the policy is not payable".into(),
        )
    })?;
    shares.insert(
        0,
        SplitShare {
            role: PayeeRole::Operator,
            payee: payees.operator.clone(),
            amount: operator_amount,
            bps: policy.share_bps(mode, PayeeRole::Operator),
        },
    );

    Ok(RevenueSplit { mode, shares })
}

/// `amount * bps / 10_000`, decomposed so it cannot overflow for any `u128`.
///
/// The naive `amount * bps` overflows above `u128::MAX / 10_000`. Quotient and
/// remainder are handled separately, matching the convention
/// `tenzro_types::fees::split_settlement_authorization` already uses.
fn apply_bps(amount: u128, bps: u32) -> u128 {
    let bps = u128::from(bps);
    let denominator = u128::from(BPS_DENOMINATOR);
    (amount / denominator) * bps + (amount % denominator) * bps / denominator
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_types::economics::{DelegatedSchedule, ValidatingSchedule};

    fn treasury() -> String {
        "did:tenzro:system:treasury".to_string()
    }

    // ---- private ----------------------------------------------------------

    /// Nobody discovered the node and no validator was engaged for the caller,
    /// so there is no network share to take.
    #[test]
    fn a_private_node_keeps_the_whole_payment() {
        let split = split_revenue(
            1_000_000,
            NodeEconomicMode::Private,
            &EconomicPolicy::default(),
            &SplitPayees::private("operator"),
        )
        .unwrap();

        assert_eq!(split.shares.len(), 1);
        assert_eq!(split.operator().amount, 1_000_000);
        assert_eq!(split.operator().bps, BPS_DENOMINATOR);
        assert_eq!(split.amount_for(PayeeRole::Treasury), 0);
        assert_eq!(split.total(), 1_000_000);
    }

    /// A private node needs no treasury address, so an empty one must not be
    /// treated as a misconfiguration.
    #[test]
    fn a_private_split_does_not_require_a_treasury() {
        let payees = SplitPayees::private("operator");
        assert!(payees.treasury.is_empty());
        assert!(
            split_revenue(
                1,
                NodeEconomicMode::Private,
                &EconomicPolicy::default(),
                &payees
            )
            .is_ok()
        );
    }

    // ---- public, validating -----------------------------------------------

    #[test]
    fn a_validating_node_splits_two_ways() {
        let split = split_revenue(
            1_000_000,
            NodeEconomicMode::PublicValidating,
            &EconomicPolicy::default(),
            &SplitPayees::validating("operator", treasury()),
        )
        .unwrap();

        assert_eq!(split.shares.len(), 2);
        assert_eq!(split.amount_for(PayeeRole::Operator), 900_000);
        assert_eq!(split.amount_for(PayeeRole::Treasury), 100_000);
        assert_eq!(split.amount_for(PayeeRole::RpcProvider), 0);
        assert_eq!(split.total(), 1_000_000);
    }

    // ---- public, delegated ------------------------------------------------

    #[test]
    fn a_delegated_node_splits_three_ways() {
        let split = split_revenue(
            1_000_000,
            NodeEconomicMode::PublicDelegated,
            &EconomicPolicy::default(),
            &SplitPayees::delegated("operator", "rpc", treasury()),
        )
        .unwrap();

        assert_eq!(split.shares.len(), 3);
        assert_eq!(split.amount_for(PayeeRole::Operator), 800_000);
        assert_eq!(split.amount_for(PayeeRole::RpcProvider), 100_000);
        assert_eq!(split.amount_for(PayeeRole::Treasury), 100_000);
        assert_eq!(split.total(), 1_000_000);
    }

    /// Paying that leg to the treasury because the provider could not be
    /// resolved would pay the wrong party and report it as if nothing were
    /// wrong.
    #[test]
    fn a_delegated_split_without_an_rpc_provider_is_refused() {
        let err = split_revenue(
            1_000,
            NodeEconomicMode::PublicDelegated,
            &EconomicPolicy::default(),
            &SplitPayees::validating("operator", treasury()),
        )
        .expect_err("must refuse");
        assert!(
            format!("{err}").contains("must name that provider"),
            "{err}"
        );
    }

    /// The difference between the two public schedules is exactly the RPC
    /// provider's leg: the operator is buying validation it does not perform.
    #[test]
    fn delegating_validation_costs_the_operator_exactly_the_rpc_leg() {
        let policy = EconomicPolicy::default();
        let validating = split_revenue(
            1_000_000,
            NodeEconomicMode::PublicValidating,
            &policy,
            &SplitPayees::validating("operator", treasury()),
        )
        .unwrap();
        let delegated = split_revenue(
            1_000_000,
            NodeEconomicMode::PublicDelegated,
            &policy,
            &SplitPayees::delegated("operator", "rpc", treasury()),
        )
        .unwrap();

        assert_eq!(
            validating.amount_for(PayeeRole::Operator) - delegated.amount_for(PayeeRole::Operator),
            delegated.amount_for(PayeeRole::RpcProvider)
        );
        // The treasury's cut is the same either way — what it does for the
        // payment does not change.
        assert_eq!(
            validating.amount_for(PayeeRole::Treasury),
            delegated.amount_for(PayeeRole::Treasury)
        );
    }

    // ---- conservation -----------------------------------------------------

    /// The property that matters. On a path that runs on every settled request,
    /// a lost smallest-unit becomes an unreconcilable balance later.
    #[test]
    fn every_amount_is_conserved_exactly_in_every_mode() {
        let policy = EconomicPolicy::default();
        let cases = [
            (NodeEconomicMode::Private, SplitPayees::private("op")),
            (
                NodeEconomicMode::PublicValidating,
                SplitPayees::validating("op", treasury()),
            ),
            (
                NodeEconomicMode::PublicDelegated,
                SplitPayees::delegated("op", "rpc", treasury()),
            ),
        ];
        for (mode, payees) in cases {
            for amount in [
                0,
                1,
                2,
                3,
                7,
                99,
                101,
                9_999,
                10_001,
                123_456_789,
                u64::MAX as u128,
                u128::MAX,
            ] {
                let split = split_revenue(amount, mode, &policy, &payees).unwrap();
                assert_eq!(
                    split.total(),
                    amount,
                    "{mode} did not conserve {amount}: {split:?}"
                );
            }
        }
    }

    /// The naive `amount * bps` overflows above `u128::MAX / 10_000`. The
    /// decomposition is what lets the largest representable payment settle.
    #[test]
    fn the_largest_representable_amount_does_not_overflow() {
        let split = split_revenue(
            u128::MAX,
            NodeEconomicMode::PublicDelegated,
            &EconomicPolicy::default(),
            &SplitPayees::delegated("op", "rpc", treasury()),
        )
        .unwrap();
        assert_eq!(split.total(), u128::MAX);
        // And the shares are still roughly the configured proportions.
        assert!(split.amount_for(PayeeRole::Operator) > u128::MAX / 2);
    }

    /// Rounding dust goes to the operator — the majority party, whose share is
    /// least distorted by it.
    #[test]
    fn rounding_dust_goes_to_the_operator() {
        // 7 units at 80/10/10: both tail legs floor to 0, so the operator takes
        // all 7 rather than value vanishing.
        let split = split_revenue(
            7,
            NodeEconomicMode::PublicDelegated,
            &EconomicPolicy::default(),
            &SplitPayees::delegated("op", "rpc", treasury()),
        )
        .unwrap();
        assert_eq!(split.amount_for(PayeeRole::RpcProvider), 0);
        assert_eq!(split.amount_for(PayeeRole::Treasury), 0);
        assert_eq!(split.amount_for(PayeeRole::Operator), 7);
        assert_eq!(split.total(), 7);
    }

    #[test]
    fn a_zero_payment_splits_to_zeroes() {
        let split = split_revenue(
            0,
            NodeEconomicMode::PublicValidating,
            &EconomicPolicy::default(),
            &SplitPayees::validating("op", treasury()),
        )
        .unwrap();
        assert_eq!(split.total(), 0);
        assert!(split.shares.iter().all(|s| s.amount == 0));
    }

    // ---- ordering and audit -----------------------------------------------

    /// The operator is paid first so a failure on a downstream leg cannot leave
    /// the party that did the work unpaid.
    #[test]
    fn the_operator_leg_comes_first() {
        let split = split_revenue(
            1_000,
            NodeEconomicMode::PublicDelegated,
            &EconomicPolicy::default(),
            &SplitPayees::delegated("op", "rpc", treasury()),
        )
        .unwrap();
        assert_eq!(split.shares[0].role, PayeeRole::Operator);
    }

    #[test]
    fn shares_carry_their_role_payee_and_bps_for_audit() {
        let policy = EconomicPolicy::default();
        let split = split_revenue(
            1_000_000,
            NodeEconomicMode::PublicDelegated,
            &policy,
            &SplitPayees::delegated("op", "rpc", treasury()),
        )
        .unwrap();

        let rpc = split.share(PayeeRole::RpcProvider).unwrap();
        assert_eq!(rpc.payee, "rpc");
        assert_eq!(rpc.bps, policy.delegated.rpc_provider_bps);
        assert_eq!(split.share(PayeeRole::Treasury).unwrap().payee, treasury());
        assert_eq!(split.mode, NodeEconomicMode::PublicDelegated);
    }

    /// The treasury is whatever the caller supplies, so handing it from Labs
    /// administration to a permissionless treasury is a configuration change
    /// with no code motion.
    #[test]
    fn the_treasury_payee_is_not_fixed_by_the_code() {
        let policy = EconomicPolicy::default();
        let labs = split_revenue(
            1_000_000,
            NodeEconomicMode::PublicValidating,
            &policy,
            &SplitPayees::validating("op", "did:tenzro:human:tenzro-labs"),
        )
        .unwrap();
        let permissionless = split_revenue(
            1_000_000,
            NodeEconomicMode::PublicValidating,
            &policy,
            &SplitPayees::validating("op", "did:tenzro:system:treasury"),
        )
        .unwrap();

        assert_eq!(
            labs.share(PayeeRole::Treasury).unwrap().payee,
            "did:tenzro:human:tenzro-labs"
        );
        // Only the recipient moves; the economics are identical.
        assert_eq!(
            labs.amount_for(PayeeRole::Treasury),
            permissionless.amount_for(PayeeRole::Treasury)
        );
    }

    // ---- refusals ---------------------------------------------------------

    #[test]
    fn an_invalid_policy_refuses_to_split() {
        let policy = EconomicPolicy {
            validating: ValidatingSchedule {
                operator_bps: 1_000,
                treasury_bps: 1_000,
            },
            ..EconomicPolicy::default()
        };
        assert!(
            split_revenue(
                1_000,
                NodeEconomicMode::PublicValidating,
                &policy,
                &SplitPayees::validating("op", treasury())
            )
            .is_err()
        );
    }

    /// Settling would send that share nowhere, so it is refused at the split
    /// rather than discovered in a receipt.
    #[test]
    fn a_public_split_with_no_treasury_address_is_refused() {
        let err = split_revenue(
            1_000,
            NodeEconomicMode::PublicValidating,
            &EconomicPolicy::default(),
            &SplitPayees::validating("op", ""),
        )
        .expect_err("must refuse");
        assert!(
            format!("{err}").contains("treasury address is empty"),
            "{err}"
        );
    }

    /// Governance can move the proportions, and the split follows without a
    /// code change — but it still cannot invert the incentive.
    #[test]
    fn a_governance_set_policy_is_honoured_within_the_invariant() {
        let mut policy = EconomicPolicy {
            delegated: DelegatedSchedule {
                operator_bps: 7_000,
                rpc_provider_bps: 2_000,
                treasury_bps: 1_000,
            },
            ..EconomicPolicy::default()
        };
        let split = split_revenue(
            1_000_000,
            NodeEconomicMode::PublicDelegated,
            &policy,
            &SplitPayees::delegated("op", "rpc", treasury()),
        )
        .unwrap();
        assert_eq!(split.amount_for(PayeeRole::RpcProvider), 200_000);
        assert_eq!(split.amount_for(PayeeRole::Operator), 700_000);

        // An operator minority is still refused, however governance sets it.
        policy.delegated = DelegatedSchedule {
            operator_bps: 4_000,
            rpc_provider_bps: 3_000,
            treasury_bps: 3_000,
        };
        assert!(
            split_revenue(
                1_000,
                NodeEconomicMode::PublicDelegated,
                &policy,
                &SplitPayees::delegated("op", "rpc", treasury())
            )
            .is_err()
        );
    }
}
