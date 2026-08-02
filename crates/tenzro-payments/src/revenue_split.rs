//! Revenue split for settled inference and TEE payments.
//!
//! One payment funds the party that did the work and the network that made it
//! findable and settleable. [`crate::settlement_asset`] decides *what asset*
//! settles; this module decides *who receives it*.
//!
//! # The network share has an interim custodian
//!
//! There are three slots, but only two economic parties. The **serving
//! operator** earns the majority for running the model or the enclave. The
//! remainder is the **network share**, and it is split between a custodian and
//! the treasury only because, during testnet, the decentralized governance /
//! DAO / treasury that should receive it is not yet operational.
//!
//! The custodian slot is therefore a temporary stand-in, not a permanent
//! payee. When governance is live, [`SplitConfig::governed`] folds the
//! custodian's share into the treasury and the slot goes to zero — a config
//! change, not a code change, which is the whole reason it is a configured
//! address rather than a constant.
//!
//! # RPC providers are not paid from this split
//!
//! An RPC provider monetises the way every other chain's RPC operator does:
//! they bill their own tenants for API access, quotas, and SLA tiers, on terms
//! they set. That revenue never touches this split, and conflating the two
//! would mean a provider was paid twice for one request — once by their tenant
//! and once out of the serving operator's earnings.
//!
//! # The treasury address is configured, never hardcoded
//!
//! A hardcoded address would have to be found and changed in a release the day
//! governance takes the treasury over — with every node that had not upgraded
//! still paying the old one. Carrying it as configuration makes that handover
//! a config change with no code motion, which is the point.
//!
//! # The operator's share is constrained to be the majority
//!
//! Enforced by [`SplitConfig::validate`], not merely documented. The party
//! doing the work has to be the party earning most of the payment, or the
//! incentive that makes anyone serve a model at all is gone. A config that
//! inverts it is rejected at construction rather than discovered in a receipt.

use serde::{Deserialize, Serialize};

use crate::error::{PaymentError, Result};

/// Basis points in a whole. Shares must sum to exactly this.
pub const BPS_DENOMINATOR: u32 = 10_000;

/// How one payment divides, in basis points.
///
/// Shares must sum to exactly [`BPS_DENOMINATOR`]. Not "approximately" and not
/// "at most": a split that sums low silently strands value with no owner, and
/// one that sums high pays out more than came in. Both are caught by
/// [`Self::validate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitConfig {
    /// Share to the operator that served the request.
    pub operator_bps: u32,
    /// Share to the interim custodian of the network's cut.
    ///
    /// A testnet stand-in for the treasury, which is not yet operational. Set
    /// to zero by [`Self::governed`] once governance can receive it directly.
    pub custodian_bps: u32,
    /// Share to the network treasury.
    pub treasury_bps: u32,
}

impl Default for SplitConfig {
    /// Testnet default: 80% operator, 10% interim custodian, 10% treasury.
    ///
    /// The operator majority is the load-bearing part; the 10/10 tail is a
    /// starting point for governance to tune, and the custodian half of it
    /// disappears at the governance handover — see [`SplitConfig::governed`].
    fn default() -> Self {
        Self {
            operator_bps: 8_000,
            custodian_bps: 1_000,
            treasury_bps: 1_000,
        }
    }
}

impl SplitConfig {
    /// The split once governance can receive the network's cut directly.
    ///
    /// Folds the interim custodian's share into the treasury and zeroes the
    /// custodian slot. The operator's share is unchanged — the handover moves
    /// who holds the network's cut, not how much of the payment it is.
    ///
    /// This is the one line that has to change at the handover, and it is a
    /// config selection rather than a code edit, which is why the custodian
    /// was a configured address from the start.
    pub fn governed(&self) -> Self {
        Self {
            operator_bps: self.operator_bps,
            custodian_bps: 0,
            treasury_bps: self.treasury_bps + self.custodian_bps,
        }
    }

    /// Whether the network's cut still passes through an interim custodian.
    ///
    /// Surfaced so a receipt, a dashboard, or an operator can tell a testnet
    /// split from a governed one without inferring it from the numbers.
    pub fn has_interim_custodian(&self) -> bool {
        self.custodian_bps > 0
    }

    /// Check the split is payable and incentive-sound.
    ///
    /// # Errors
    ///
    /// - shares do not sum to exactly [`BPS_DENOMINATOR`]
    /// - the operator does not hold a strict majority
    pub fn validate(&self) -> Result<()> {
        let total = self
            .operator_bps
            .checked_add(self.custodian_bps)
            .and_then(|s| s.checked_add(self.treasury_bps))
            .ok_or_else(|| {
                PaymentError::ConfigError("revenue split shares overflow".to_string())
            })?;

        if total != BPS_DENOMINATOR {
            return Err(PaymentError::ConfigError(format!(
                "revenue split must sum to {BPS_DENOMINATOR} bps, got {total} \
                 (operator {} + rpc {} + treasury {})",
                self.operator_bps, self.custodian_bps, self.treasury_bps
            )));
        }

        // Strictly more than half, so an exact 50/50 is rejected too: at half,
        // the operator is not being paid to serve, they are splitting with
        // parties that did not do the work.
        if self.operator_bps * 2 <= BPS_DENOMINATOR {
            return Err(PaymentError::ConfigError(format!(
                "the serving operator must take the majority: operator {} bps is not more than \
                 half of {BPS_DENOMINATOR}. The party doing the work has to earn most of the \
                 payment or there is no reason to serve",
                self.operator_bps
            )));
        }

        Ok(())
    }
}

/// Where each share is paid.
///
/// Addresses are opaque strings so the same split works whether the payout is a
/// TNZO account, an EVM address, or a Solana pubkey — the settlement asset is
/// [`crate::settlement_asset`]'s decision, and this type should not constrain
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitPayees {
    /// The operator that served the request.
    pub operator: String,
    /// The interim custodian of the network's cut.
    ///
    /// During testnet this is the node operator standing in for a treasury
    /// that does not yet exist. It is not the RPC provider's fee — RPC
    /// providers bill their own tenants separately, the way every other
    /// chain's RPC operators do.
    pub custodian: String,
    /// The network treasury.
    ///
    /// Supplied by configuration. See the module docs for why this is not a
    /// constant.
    pub treasury: String,
}

/// One party's cut of a payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitShare {
    /// Who is paid.
    pub payee: String,
    /// How much, in the settled asset's smallest unit.
    pub amount: u128,
    /// The share in basis points, carried so a receipt can be audited without
    /// re-deriving it from the config that was live at the time.
    pub bps: u32,
}

/// The full division of one payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevenueSplit {
    /// The serving operator's share — always the largest.
    pub operator: SplitShare,
    /// The interim custodian's share of the network cut. Zero once governance
    /// is live.
    pub custodian: SplitShare,
    /// The treasury's share.
    pub treasury: SplitShare,
}

impl RevenueSplit {
    /// Total paid out. Always equals the input amount — see [`split_revenue`].
    pub fn total(&self) -> u128 {
        self.operator.amount + self.custodian.amount + self.treasury.amount
    }
}

/// Divide `amount` three ways.
///
/// # Conservation
///
/// The three shares sum to exactly `amount`, always. Integer division discards
/// a remainder of up to two smallest-units, and rather than let that vanish it
/// is given to the operator — the majority party, and the one whose share is
/// least distorted by it.
///
/// This matters more than the rounding: value that neither arrives nor is
/// accounted for is the kind of leak that shows up as an unreconcilable
/// balance months later, on a path that runs on every settled inference.
///
/// # Errors
///
/// Propagates [`SplitConfig::validate`].
pub fn split_revenue(
    amount: u128,
    config: &SplitConfig,
    payees: &SplitPayees,
) -> Result<RevenueSplit> {
    config.validate()?;

    let denominator = u128::from(BPS_DENOMINATOR);
    let custodian_amount = amount * u128::from(config.custodian_bps) / denominator;
    let treasury_amount = amount * u128::from(config.treasury_bps) / denominator;

    // Whatever is left, including the rounding dust. Subtraction rather than a
    // third multiply is what makes conservation exact by construction.
    let operator_amount = amount - custodian_amount - treasury_amount;

    Ok(RevenueSplit {
        operator: SplitShare {
            payee: payees.operator.clone(),
            amount: operator_amount,
            bps: config.operator_bps,
        },
        custodian: SplitShare {
            payee: payees.custodian.clone(),
            amount: custodian_amount,
            bps: config.custodian_bps,
        },
        treasury: SplitShare {
            payee: payees.treasury.clone(),
            amount: treasury_amount,
            bps: config.treasury_bps,
        },
    })
}

#[cfg(test)]
mod tests {

    /// The handover: governance goes live, the custodian slot disappears, and
    /// the operator's share is untouched. The network's cut moved custodian,
    /// it did not change size.
    #[test]
    fn governance_handover_folds_the_custodian_share_into_the_treasury() {
        let testnet = SplitConfig::default();
        assert!(testnet.has_interim_custodian());

        let governed = testnet.governed();
        assert!(!governed.has_interim_custodian());
        assert_eq!(governed.operator_bps, testnet.operator_bps);
        assert_eq!(
            governed.treasury_bps,
            testnet.treasury_bps + testnet.custodian_bps
        );
        assert_eq!(
            governed.operator_bps + governed.custodian_bps + governed.treasury_bps,
            BPS_DENOMINATOR
        );
        governed.validate().unwrap();
    }

    /// The amount reaching each economic party is the same before and after
    /// the handover — only who holds the network's cut changes.
    #[test]
    fn the_handover_does_not_change_what_the_operator_earns() {
        let payees = SplitPayees {
            operator: "op".to_string(),
            custodian: "custodian".to_string(),
            treasury: "treasury".to_string(),
        };
        let before = split_revenue(1_000_000, &SplitConfig::default(), &payees).unwrap();
        let after = split_revenue(1_000_000, &SplitConfig::default().governed(), &payees).unwrap();

        assert_eq!(before.operator.amount, after.operator.amount);
        assert_eq!(after.custodian.amount, 0);
        assert_eq!(
            after.treasury.amount,
            before.treasury.amount + before.custodian.amount
        );
        assert_eq!(before.total(), after.total());
    }

    /// Governance is still governance: it cannot take the majority.
    #[test]
    fn a_governed_split_still_leaves_the_operator_the_majority() {
        let greedy = SplitConfig {
            operator_bps: 4_000,
            custodian_bps: 3_000,
            treasury_bps: 3_000,
        };
        assert!(greedy.governed().validate().is_err());
    }
    use super::*;

    fn payees() -> SplitPayees {
        SplitPayees {
            operator: "did:tenzro:machine:operator".into(),
            custodian: "did:tenzro:machine:rpc".into(),
            treasury: "did:tenzro:human:treasury".into(),
        }
    }

    // ---- config validation ------------------------------------------------

    #[test]
    fn the_default_split_is_valid_and_operator_majority() {
        let cfg = SplitConfig::default();
        cfg.validate().unwrap();
        assert!(cfg.operator_bps * 2 > BPS_DENOMINATOR);
    }

    #[test]
    fn shares_must_sum_to_exactly_ten_thousand() {
        // Sums low — value would be stranded with no owner.
        let low = SplitConfig {
            operator_bps: 8_000,
            custodian_bps: 1_000,
            treasury_bps: 500,
        };
        assert!(low.validate().is_err());

        // Sums high — would pay out more than came in.
        let high = SplitConfig {
            operator_bps: 8_000,
            custodian_bps: 1_500,
            treasury_bps: 1_000,
        };
        assert!(high.validate().is_err());
    }

    /// The incentive constraint, enforced rather than documented.
    #[test]
    fn the_operator_must_hold_a_strict_majority() {
        let minority = SplitConfig {
            operator_bps: 4_000,
            custodian_bps: 3_000,
            treasury_bps: 3_000,
        };
        let err = minority
            .validate()
            .expect_err("an operator minority must be refused");
        assert!(
            format!("{err}").contains("must take the majority"),
            "got {err}"
        );

        // Exactly half is not a majority either.
        let half = SplitConfig {
            operator_bps: 5_000,
            custodian_bps: 2_500,
            treasury_bps: 2_500,
        };
        assert!(half.validate().is_err(), "50% is not a majority");

        // One bp over half is.
        let just_over = SplitConfig {
            operator_bps: 5_001,
            custodian_bps: 2_500,
            treasury_bps: 2_499,
        };
        just_over.validate().unwrap();
    }

    // ---- splitting ---------------------------------------------------------

    #[test]
    fn splits_a_clean_amount_by_the_configured_shares() {
        let split = split_revenue(1_000_000, &SplitConfig::default(), &payees()).unwrap();
        assert_eq!(split.operator.amount, 800_000);
        assert_eq!(split.custodian.amount, 100_000);
        assert_eq!(split.treasury.amount, 100_000);
        assert_eq!(split.total(), 1_000_000);
    }

    /// Conservation is the property that matters: on a path that runs on every
    /// settled inference, a lost smallest-unit becomes an unreconcilable
    /// balance later.
    #[test]
    fn every_amount_is_conserved_exactly() {
        let cfg = SplitConfig::default();
        let p = payees();
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
        ] {
            let split = split_revenue(amount, &cfg, &p).unwrap();
            assert_eq!(
                split.total(),
                amount,
                "amount {amount} was not conserved: {split:?}"
            );
        }
    }

    /// Rounding dust goes to the operator — the majority party, whose share is
    /// least distorted by it.
    #[test]
    fn rounding_dust_goes_to_the_operator() {
        // 7 units at 80/10/10: rpc and treasury each floor to 0, so the
        // operator takes all 7 rather than 4 vanishing.
        let split = split_revenue(7, &SplitConfig::default(), &payees()).unwrap();
        assert_eq!(split.custodian.amount, 0);
        assert_eq!(split.treasury.amount, 0);
        assert_eq!(split.operator.amount, 7);
        assert_eq!(split.total(), 7);
    }

    #[test]
    fn a_zero_payment_splits_to_zeroes() {
        let split = split_revenue(0, &SplitConfig::default(), &payees()).unwrap();
        assert_eq!(split.total(), 0);
        assert_eq!(split.operator.amount, 0);
    }

    #[test]
    fn shares_carry_their_bps_for_audit() {
        let cfg = SplitConfig::default();
        let split = split_revenue(1_000_000, &cfg, &payees()).unwrap();
        assert_eq!(split.operator.bps, cfg.operator_bps);
        assert_eq!(split.custodian.bps, cfg.custodian_bps);
        assert_eq!(split.treasury.bps, cfg.treasury_bps);
    }

    #[test]
    fn payees_are_carried_through_to_their_shares() {
        let p = payees();
        let split = split_revenue(1_000, &SplitConfig::default(), &p).unwrap();
        assert_eq!(split.operator.payee, p.operator);
        assert_eq!(split.custodian.payee, p.custodian);
        assert_eq!(split.treasury.payee, p.treasury);
    }

    /// The treasury is whatever configuration says, so handing it to a DAO is a
    /// config change with no code motion.
    #[test]
    fn the_treasury_payee_is_not_fixed_by_the_code() {
        let labs = SplitPayees {
            treasury: "did:tenzro:human:tenzro-labs".into(),
            ..payees()
        };
        let dao = SplitPayees {
            treasury: "did:tenzro:machine:network-dao".into(),
            ..payees()
        };
        let cfg = SplitConfig::default();

        let a = split_revenue(1_000_000, &cfg, &labs).unwrap();
        let b = split_revenue(1_000_000, &cfg, &dao).unwrap();

        assert_eq!(a.treasury.payee, "did:tenzro:human:tenzro-labs");
        assert_eq!(b.treasury.payee, "did:tenzro:machine:network-dao");
        // Only the recipient moves; the economics are identical.
        assert_eq!(a.treasury.amount, b.treasury.amount);
    }

    #[test]
    fn an_invalid_config_refuses_to_split() {
        let bad = SplitConfig {
            operator_bps: 1_000,
            custodian_bps: 1_000,
            treasury_bps: 1_000,
        };
        assert!(split_revenue(1_000, &bad, &payees()).is_err());
    }
}
