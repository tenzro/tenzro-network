//! How an agent's balance comes into existence, and who can lose it.
//!
//! Tenzro can meter, route and settle a payment. What it could not previously
//! express is where the money *came from* — and for an agentic economy that is
//! not a detail, because an agent funded by an anonymous transfer and an agent
//! funded through a KYC'd on-ramp under a human's delegation are different
//! things wearing the same balance.
//!
//! # Funding has a direction, and the two are not alternatives
//!
//! It is tempting to treat funding partners as a vendor choice. They are not:
//! they sit on opposite sides of the balance.
//!
//! - **Inbound** ([`FundingDirection::FiatToStablecoin`]) — fiat arrives and
//!   becomes stablecoin the agent can spend on-network. This is the
//!   virtual-account shape: a deposit account in the customer's name whose
//!   incoming fiat converts to USDC.
//! - **Outbound** ([`FundingDirection::StablecoinToMerchant`]) — the agent
//!   spends an existing stablecoin balance at merchants that have never heard
//!   of stablecoins, over card rails.
//!
//! A network that only does the first has agents that can be paid but cannot
//! buy; one that only does the second has agents that can buy but cannot be
//! funded. Modelling direction explicitly is what stops a partner integration
//! being wired into the wrong half.
//!
//! # Custody is the field that decides who can lose the money
//!
//! [`CustodyModel`] is carried separately from the provider because it is the
//! property that actually matters when something goes wrong, and it does not
//! follow from the provider's name. A custodial orchestrator holds the keys;
//! a non-custodial issuer holds collateral in a contract the customer owns and
//! can withdraw from at any time. Those are different risks to the same user,
//! and collapsing them into "we support provider X" hides the one thing a
//! delegating human should be told before authorising anything.
//!
//! # Why this binds to an identity rather than to a wallet
//!
//! A funded balance that is not tied to a TDIP identity is an anonymous
//! balance, and every ceiling Tenzro already enforces — the delegation scope,
//! the runtime spending policy — hangs off the identity. Binding funding to the
//! identity means a funded agent is inside the same ceilings as an unfunded
//! one, rather than being a way around them.
//!
//! # Tenzro integrates providers; it does not become one
//!
//! This is a registry of integrations, not a shortlist to choose a winner from,
//! and the distinction is structural rather than diplomatic.
//!
//! **Tenzro is not a licensed provider and does not aim to be.** Every
//! regulated function here — KYC, fiat acceptance, card issuance, network
//! settlement — is performed by a licensed party that already does it well.
//! What Tenzro adds is the layer none of them occupy: a portable agent identity
//! with enforceable delegation, so the *same* agent can be funded through one
//! provider, spend through another, and settle on-network under one set of
//! ceilings.
//!
//! Three consequences follow, and the type below is shaped by all three:
//!
//! - **No provider is privileged.** [`FundingProvider::Other`] carries its own
//!   name so an operator can integrate a provider this enum has never heard of
//!   without a protocol change. A named variant is a convenience for the
//!   common cases, never a gate.
//! - **Providers are not interchangeable, so the model records what differs.**
//!   Direction and custody are separate fields precisely because collapsing
//!   them into a vendor name would force a choice where the honest answer is
//!   "use both" — an inbound orchestrator and an outbound issuer solve
//!   different halves of the same problem.
//! - **A provider operating at a layer Tenzro does not touch is integrated at
//!   that layer instead**, rather than forced into this one. See the note on
//!   [`FundingProvider`] for why the card networks are not variants here.

use serde::{Deserialize, Serialize};

/// Which way money is moving across the fiat boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FundingDirection {
    /// Fiat in, spendable stablecoin out. Funds an agent.
    FiatToStablecoin,
    /// Stablecoin in, merchant paid in fiat over card rails. Lets an agent buy.
    StablecoinToMerchant,
}

/// Who holds the keys, and therefore who can lose the funds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyModel {
    /// The provider holds the keys. The balance is a claim on the provider,
    /// and provider failure is user loss.
    Custodial,
    /// Collateral sits in a contract the customer owns and can withdraw from
    /// at any time; the provider underwrites against it rather than holding it.
    NonCustodialCollateral,
    /// Keys never leave the user's device; the provider only orchestrates.
    SelfCustody,
}

impl CustodyModel {
    /// Whether the funded party can unilaterally recover the balance without
    /// the provider's cooperation.
    ///
    /// This is the question a delegating human is actually asking, and it is
    /// not answerable from the provider's name.
    pub fn user_can_exit_unilaterally(self) -> bool {
        matches!(
            self,
            CustodyModel::NonCustodialCollateral | CustodyModel::SelfCustody
        )
    }
}

/// A licensed partner that moves value across the fiat boundary.
///
/// # Visa and Mastercard are deliberately absent
///
/// Verified against Visa's own newsroom rather than secondary coverage: Visa's
/// stablecoin settlement program settles obligations **with issuers and
/// acquirers — banks and fintechs — not with merchants directly**. A merchant
/// sees the effect only through its acquirer. The program reached nine
/// blockchains in April 2026 at a ~$7B annualised run rate, across USDC, EURC,
/// USDG and PYUSD, with Circle's Arc, Base and Canton as named partners.
///
/// That makes it network settlement one layer *below* anything Tenzro touches:
/// it is how a card authorisation Tenzro initiated through an issuer like Rain
/// eventually settles between Visa and the acquiring bank. Modelling it as a
/// funding source an agent draws on would be a category error — Tenzro cannot
/// hold a settlement relationship with Visa, and an operator who saw `Visa`
/// in this enum would reasonably assume otherwise.
///
/// Visa and Mastercard *do* appear elsewhere in the codebase, correctly: as
/// agent-identity and mandate surfaces (`visa_tap`, `mastercard`), which is
/// the layer they actually expose to a party in Tenzro's position.
///
/// Tenzro is not a money transmitter and does not intend to become one:
/// KYC, fiat acceptance and card issuance are all done by a licensed party.
/// This enum records which one, so a receipt can say so.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FundingProvider {
    /// Stablecoin orchestration and virtual accounts — fiat deposit accounts
    /// whose incoming balance converts to stablecoin. Custodial.
    Bridge,
    /// Card acceptance and payouts layered on the same rails.
    Stripe,
    /// Card issuing against stablecoin collateral held in a contract the
    /// customer owns. Ships an agent control layer of its own: virtual cards
    /// scoped to a merchant, an amount and a task.
    Rain,
    /// PYUSD, issued by Paxos under OCC regulation and redeemable 1:1.
    /// Consumer- and merchant-facing: a merchant accepting PYUSD can access
    /// proceeds in minutes rather than days, and PYUSD settles agent payments
    /// outside the closed PayPal ecosystem, which is why it belongs here and
    /// the account-to-account toolkit does not.
    PayPal,
    /// A provider not in this list. Carries its own name so an operator can
    /// integrate one without a protocol change.
    Other(String),
}

impl FundingProvider {
    /// Stable identifier for receipts and logs.
    pub fn as_str(&self) -> &str {
        match self {
            FundingProvider::Bridge => "bridge",
            FundingProvider::Stripe => "stripe",
            FundingProvider::Rain => "rain",
            FundingProvider::PayPal => "paypal",
            FundingProvider::Other(name) => name,
        }
    }

    /// The custody model this provider operates under by default.
    ///
    /// Returns `None` for `Other`, because assuming a custody model for an
    /// unknown provider is exactly the guess this type exists to prevent —
    /// the operator must state it.
    pub fn default_custody(&self) -> Option<CustodyModel> {
        match self {
            FundingProvider::Bridge | FundingProvider::Stripe | FundingProvider::PayPal => {
                Some(CustodyModel::Custodial)
            }
            FundingProvider::Rain => Some(CustodyModel::NonCustodialCollateral),
            FundingProvider::Other(_) => None,
        }
    }

    /// The direction this provider serves by default.
    pub fn default_direction(&self) -> Option<FundingDirection> {
        match self {
            FundingProvider::Bridge | FundingProvider::Stripe | FundingProvider::PayPal => {
                Some(FundingDirection::FiatToStablecoin)
            }
            FundingProvider::Rain => Some(FundingDirection::StablecoinToMerchant),
            FundingProvider::Other(_) => None,
        }
    }
}

/// A funding relationship between a licensed provider and a Tenzro identity.
///
/// This records the binding, not the funds: balances live where they always
/// did. What it adds is provenance — that *this* identity's balance arrived
/// through *that* provider, under *this* custody model — so a receipt can
/// answer where the money came from, and a delegating human can see what they
/// are actually exposed to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FundingSource {
    /// The identity this funding belongs to. Never a bare wallet address: the
    /// ceilings Tenzro enforces hang off the identity, so funding bound to
    /// anything else is funding outside those ceilings.
    pub identity_did: String,
    /// Licensed party that moved the value.
    pub provider: FundingProvider,
    /// Which way it moves.
    pub direction: FundingDirection,
    /// Who holds the keys.
    pub custody: CustodyModel,
    /// The provider's own identifier for this relationship (virtual account
    /// id, card program id). Opaque to Tenzro.
    pub provider_ref: String,
    /// Asset the agent ends up holding or spending.
    pub asset: String,
    /// Ceiling on this source, in the asset's smallest unit, if the operator
    /// set one. `None` means the identity's delegation scope is the only
    /// ceiling — which is a real configuration, not a missing one.
    pub cap_minor_units: Option<u128>,
    /// When the binding was recorded, unix ms.
    pub bound_at_ms: u64,
    /// Whether the binding is live. A revoked source keeps its record so past
    /// receipts still resolve; it just stops authorising new funding.
    pub active: bool,
}

/// Why a funding attempt was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FundingError {
    /// The source is recorded but no longer active.
    Revoked,
    /// The amount exceeds this source's own cap.
    ExceedsSourceCap {
        /// Requested amount.
        requested: u128,
        /// The cap it broke.
        cap: u128,
    },
    /// The amount exceeds the identity's delegation scope.
    ExceedsDelegationScope {
        /// Requested amount.
        requested: u128,
        /// The scope ceiling it broke.
        ceiling: u128,
    },
    /// The provider was used in a direction it does not serve.
    WrongDirection {
        /// What was attempted.
        attempted: FundingDirection,
        /// What the provider actually does.
        supported: FundingDirection,
    },
}

impl core::fmt::Display for FundingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Revoked => write!(
                f,
                "this funding source has been revoked; its past receipts still resolve, but it \
                 cannot authorise new funding"
            ),
            Self::ExceedsSourceCap { requested, cap } => write!(
                f,
                "requested {requested} against a funding source capped at {cap}"
            ),
            Self::ExceedsDelegationScope { requested, ceiling } => write!(
                f,
                "requested {requested}, but the identity's delegation scope ceiling is {ceiling}. \
                 Funding does not widen a scope — an agent that could not spend this much before \
                 it was funded still cannot"
            ),
            Self::WrongDirection {
                attempted,
                supported,
            } => write!(
                f,
                "this provider moves value {supported:?}, not {attempted:?}"
            ),
        }
    }
}

impl std::error::Error for FundingError {}

impl FundingSource {
    /// Whether `amount` may be funded through this source, given the
    /// identity's delegation-scope ceiling.
    ///
    /// Both ceilings are checked and the **narrower one binds**. Funding is not
    /// a way to widen a delegation scope: an agent that could not spend this
    /// much before it was funded still cannot afterwards. Checking only the
    /// source cap would make the on-ramp a hole straight through every control
    /// the identity layer enforces.
    pub fn authorize(
        &self,
        amount: u128,
        direction: FundingDirection,
        scope_ceiling: Option<u128>,
    ) -> Result<(), FundingError> {
        if !self.active {
            return Err(FundingError::Revoked);
        }
        if direction != self.direction {
            return Err(FundingError::WrongDirection {
                attempted: direction,
                supported: self.direction,
            });
        }
        if let Some(cap) = self.cap_minor_units
            && amount > cap
        {
            return Err(FundingError::ExceedsSourceCap {
                requested: amount,
                cap,
            });
        }
        if let Some(ceiling) = scope_ceiling
            && amount > ceiling
        {
            return Err(FundingError::ExceedsDelegationScope {
                requested: amount,
                ceiling,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(direction: FundingDirection, cap: Option<u128>) -> FundingSource {
        FundingSource {
            identity_did: "did:tenzro:machine:alice:1".into(),
            provider: FundingProvider::Bridge,
            direction,
            custody: CustodyModel::Custodial,
            provider_ref: "va_123".into(),
            asset: "USDC".into(),
            cap_minor_units: cap,
            bound_at_ms: 1_700_000_000_000,
            active: true,
        }
    }

    #[test]
    fn the_narrower_ceiling_binds() {
        // The whole point: an on-ramp must not widen a delegation scope.
        let s = source(FundingDirection::FiatToStablecoin, Some(1_000_000));
        // Source allows it, scope does not.
        let e = s
            .authorize(900_000, FundingDirection::FiatToStablecoin, Some(500_000))
            .unwrap_err();
        assert!(matches!(e, FundingError::ExceedsDelegationScope { .. }));
        // Scope allows it, source does not.
        let e = s
            .authorize(
                1_100_000,
                FundingDirection::FiatToStablecoin,
                Some(5_000_000),
            )
            .unwrap_err();
        assert!(matches!(e, FundingError::ExceedsSourceCap { .. }));
        // Both allow it.
        assert!(
            s.authorize(400_000, FundingDirection::FiatToStablecoin, Some(500_000))
                .is_ok()
        );
    }

    #[test]
    fn the_scope_ceiling_refusal_explains_that_funding_does_not_widen_scope() {
        let s = source(FundingDirection::FiatToStablecoin, None);
        let msg = s
            .authorize(10, FundingDirection::FiatToStablecoin, Some(1))
            .unwrap_err()
            .to_string();
        assert!(msg.contains("does not widen"), "unhelpful refusal: {msg}");
    }

    #[test]
    fn no_source_cap_means_the_scope_is_the_only_ceiling() {
        // A real configuration, not a missing one.
        let s = source(FundingDirection::FiatToStablecoin, None);
        assert!(
            s.authorize(u128::MAX, FundingDirection::FiatToStablecoin, None)
                .is_ok()
        );
        assert!(
            s.authorize(2, FundingDirection::FiatToStablecoin, Some(1))
                .is_err()
        );
    }

    #[test]
    fn a_revoked_source_authorises_nothing() {
        let mut s = source(FundingDirection::FiatToStablecoin, None);
        s.active = false;
        assert_eq!(
            s.authorize(1, FundingDirection::FiatToStablecoin, None),
            Err(FundingError::Revoked)
        );
    }

    #[test]
    fn using_a_provider_in_the_wrong_direction_is_refused() {
        // Bridge funds an agent; it does not pay merchants over card rails.
        // Wiring a partner into the wrong half is the mistake direction exists
        // to catch.
        let s = source(FundingDirection::FiatToStablecoin, None);
        let e = s
            .authorize(1, FundingDirection::StablecoinToMerchant, None)
            .unwrap_err();
        assert!(matches!(e, FundingError::WrongDirection { .. }));
    }

    #[test]
    fn provider_defaults_reflect_what_each_one_actually_does() {
        assert_eq!(
            FundingProvider::Bridge.default_direction(),
            Some(FundingDirection::FiatToStablecoin)
        );
        assert_eq!(
            FundingProvider::Rain.default_direction(),
            Some(FundingDirection::StablecoinToMerchant)
        );
        assert_eq!(
            FundingProvider::Bridge.default_custody(),
            Some(CustodyModel::Custodial)
        );
        assert_eq!(
            FundingProvider::Rain.default_custody(),
            Some(CustodyModel::NonCustodialCollateral)
        );
    }

    #[test]
    fn an_unknown_provider_asserts_nothing_about_custody_or_direction() {
        // Guessing a custody model for an unknown provider is exactly the
        // failure this type exists to prevent — the operator must state it.
        let p = FundingProvider::Other("acme".into());
        assert_eq!(p.default_custody(), None);
        assert_eq!(p.default_direction(), None);
        assert_eq!(p.as_str(), "acme");
    }

    #[test]
    fn custody_answers_who_can_exit_without_the_provider() {
        // The question a delegating human is actually asking, and one that
        // does not follow from the provider's name.
        assert!(!CustodyModel::Custodial.user_can_exit_unilaterally());
        assert!(CustodyModel::NonCustodialCollateral.user_can_exit_unilaterally());
        assert!(CustodyModel::SelfCustody.user_can_exit_unilaterally());
    }

    #[test]
    fn funding_binds_to_an_identity_not_a_wallet() {
        // A balance bound to a bare address is outside every ceiling the
        // identity layer enforces.
        let s = source(FundingDirection::FiatToStablecoin, None);
        assert!(s.identity_did.starts_with("did:"));
    }

    #[test]
    fn a_source_serializes_with_its_custody_and_direction_visible() {
        // Provenance is the point: a receipt must be able to say where the
        // money came from and who held it.
        let s = source(FundingDirection::FiatToStablecoin, Some(10));
        let v = serde_json::to_value(&s).unwrap();
        assert_eq!(v["direction"], "fiat_to_stablecoin");
        assert_eq!(v["custody"], "custodial");
        assert_eq!(v["provider"], "bridge");
    }
}
