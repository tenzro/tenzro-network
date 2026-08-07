//! TNZO fee structures for Tenzro Ledger operations
//!
//! This module defines fee schedules and commission rates for services
//! on the Tenzro Ledger. All fees are denominated in TNZO (the governance token).
//!
//! # Fee Streams
//!
//! The Tenzro Network has two primary fee streams:
//!
//! 1. **Ledger fees** - Transaction gas fees paid in TNZO that flow to validators
//! 2. **Network commissions** - Percentage of AI/TEE provider payments that flow to treasury
//!
//! # Architecture
//!
//! - **Tenzro Network** = Decentralized protocol for the AI age
//! - **Tenzro Ledger** = L1 settlement layer (identity, verification, settlement in TNZO)
//! - **TNZO** = Governance token used for ledger fees and network settlements

use serde::{Deserialize, Serialize};

use crate::primitives::Address;

/// Domain tag for the derived network treasury address.
const TREASURY_DOMAIN: &[u8] = b"tenzro/treasury";

/// The account network revenue accumulates at.
///
/// Derived rather than configured: `SHA-256("tenzro/treasury")`. Every replica
/// computes the same 32 bytes, so a commission credited on one node lands at
/// the same account as one credited on another — no genesis field, no
/// per-operator setting, nothing an operator can point at their own wallet.
///
/// No private key exists for these bytes, so the balance moves only through
/// the treasury's authorized-withdrawer path, which governance controls.
pub fn network_treasury_address() -> Address {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(TREASURY_DOMAIN);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    Address::new(out)
}

/// Upper bound on the per-app developer margin (basis points, 100 = 1%)
///
/// Applications registered in the on-chain app registry declare a `margin_bps`
/// that is added on top of the network cost when their end users are settled
/// through `tenzro_settleAuthorized`. Developers control their own fiat pricing,
/// so this cap is abuse and fat-finger protection — not consumer protection.
///
/// Default cap: 2000 bps (20%).
pub const MAX_DEVELOPER_MARGIN_BPS: u32 = 2000;

/// Applies a developer margin to a network cost.
///
/// Returns `user_pays = network_cost * (1 + margin_bps / 10000)`, or `None`
/// when `margin_bps` exceeds [`MAX_DEVELOPER_MARGIN_BPS`] or the arithmetic
/// overflows.
pub fn apply_developer_margin(network_cost: u128, margin_bps: u32) -> Option<u128> {
    if margin_bps > MAX_DEVELOPER_MARGIN_BPS {
        return None;
    }
    let margin = network_cost
        .checked_mul(margin_bps as u128)?
        .checked_div(10000)?;
    network_cost.checked_add(margin)
}

/// Network commission on `tenzro_settleAuthorized` executions (basis points).
///
/// When a developer-signed [`crate::SettlementAuthorization`] moves TNZO from
/// an app wallet to a payer, this fraction of the authorized amount routes to
/// the network treasury instead. The payer receives `amount_tnzo` minus this
/// commission; the app wallet is debited exactly `amount_tnzo`.
///
/// This is its own rate and **not** part of the `EconomicPolicy` settlement
/// split — an app paying out to its own user is not a service payment being
/// divided between operator, treasury and validator, so the split does not
/// apply and neither charge stacks on the other. It is also not the settlement
/// engine's former `network_fee_bps`, which is now 0; a comment here once
/// claimed parity with that rate, which stopped being true when the double
/// charge it described was removed.
pub const SETTLEMENT_AUTHORIZATION_COMMISSION_BPS: u32 = 50;

/// Splits an authorized settlement amount into (payer_net, commission).
///
/// `commission = amount * SETTLEMENT_AUTHORIZATION_COMMISSION_BPS / 10000`
/// (integer floor), `payer_net = amount - commission`. Cannot overflow for
/// any `u128` input because the multiply is decomposed.
pub fn split_settlement_authorization(amount: u128) -> (u128, u128) {
    let bps = SETTLEMENT_AUTHORIZATION_COMMISSION_BPS as u128;
    // Quotient/remainder decomposition avoids u128 overflow on amount * bps.
    let commission = (amount / 10000) * bps + (amount % 10000) * bps / 10000;
    (amount - commission, commission)
}

/// Service fees for Tenzro Ledger operations, all denominated in TNZO
///
/// These fees are charged for ledger-level operations like identity registration,
/// verification, and model registration. All amounts are in the smallest TNZO unit
/// (18 decimal places, like Ethereum's wei).
///
/// # Examples
///
/// ```
/// use tenzro_types::ServiceFeeSchedule;
///
/// let fees = ServiceFeeSchedule::default();
/// assert_eq!(fees.human_identity_registration, 10_000_000_000_000_000_000); // 10 TNZO
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceFeeSchedule {
    /// Human identity registration fee (in smallest TNZO unit)
    ///
    /// Default: 10 TNZO (10 * 10^18)
    #[serde(with = "crate::primitives::u128_serde")]
    pub human_identity_registration: u128,

    /// Machine identity registration fee
    ///
    /// Default: 5 TNZO (5 * 10^18)
    #[serde(with = "crate::primitives::u128_serde")]
    pub machine_identity_registration: u128,

    /// Agent identity registration fee
    ///
    /// Default: 5 TNZO (5 * 10^18)
    #[serde(with = "crate::primitives::u128_serde")]
    pub agent_registration: u128,

    /// Credential issuance fee
    ///
    /// Default: 2 TNZO (2 * 10^18)
    #[serde(with = "crate::primitives::u128_serde")]
    pub credential_issuance: u128,

    /// Identity verification fee
    ///
    /// Default: 1 TNZO (1 * 10^18)
    #[serde(with = "crate::primitives::u128_serde")]
    pub identity_verification: u128,

    /// Model registration fee
    ///
    /// Default: 50 TNZO (50 * 10^18)
    #[serde(with = "crate::primitives::u128_serde")]
    pub model_registration: u128,

    /// Bridge transfer base fee
    ///
    /// Default: 1 TNZO (1 * 10^18)
    #[serde(with = "crate::primitives::u128_serde")]
    pub bridge_transfer_base: u128,
}

impl Default for ServiceFeeSchedule {
    fn default() -> Self {
        const TNZO_DECIMALS: u32 = 18;
        const ONE_TNZO: u128 = 10u128.pow(TNZO_DECIMALS);

        Self {
            human_identity_registration: 10 * ONE_TNZO,  // 10 TNZO
            machine_identity_registration: 5 * ONE_TNZO, // 5 TNZO
            agent_registration: 5 * ONE_TNZO,            // 5 TNZO
            credential_issuance: 2 * ONE_TNZO,           // 2 TNZO
            identity_verification: ONE_TNZO,             // 1 TNZO
            model_registration: 50 * ONE_TNZO,           // 50 TNZO
            bridge_transfer_base: ONE_TNZO,              // 1 TNZO
        }
    }
}

impl ServiceFeeSchedule {
    /// Creates a new fee schedule with custom values
    pub fn new(
        human_identity_registration: u128,
        machine_identity_registration: u128,
        agent_registration: u128,
        credential_issuance: u128,
        identity_verification: u128,
        model_registration: u128,
        bridge_transfer_base: u128,
    ) -> Self {
        Self {
            human_identity_registration,
            machine_identity_registration,
            agent_registration,
            credential_issuance,
            identity_verification,
            model_registration,
            bridge_transfer_base,
        }
    }

    /// Returns the total fees collected across all categories
    ///
    /// Note: This requires keeping track of how many operations of each type have occurred.
    /// The counts are passed as parameters.
    pub fn calculate_total_collected(
        &self,
        human_identity_count: u128,
        machine_identity_count: u128,
        agent_count: u128,
        credential_count: u128,
        verification_count: u128,
        model_count: u128,
        bridge_count: u128,
    ) -> Option<u128> {
        let total = self
            .human_identity_registration
            .checked_mul(human_identity_count)?
            .checked_add(
                self.machine_identity_registration
                    .checked_mul(machine_identity_count)?,
            )?
            .checked_add(self.agent_registration.checked_mul(agent_count)?)?
            .checked_add(self.credential_issuance.checked_mul(credential_count)?)?
            .checked_add(self.identity_verification.checked_mul(verification_count)?)?
            .checked_add(self.model_registration.checked_mul(model_count)?)?
            .checked_add(self.bridge_transfer_base.checked_mul(bridge_count)?)?;
        Some(total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_service_fee_schedule_defaults() {
        let fees = ServiceFeeSchedule::default();
        const ONE_TNZO: u128 = 1_000_000_000_000_000_000; // 10^18

        assert_eq!(fees.human_identity_registration, 10 * ONE_TNZO);
        assert_eq!(fees.machine_identity_registration, 5 * ONE_TNZO);
        assert_eq!(fees.agent_registration, 5 * ONE_TNZO);
        assert_eq!(fees.credential_issuance, 2 * ONE_TNZO);
        assert_eq!(fees.identity_verification, ONE_TNZO);
        assert_eq!(fees.model_registration, 50 * ONE_TNZO);
        assert_eq!(fees.bridge_transfer_base, ONE_TNZO);
    }

    #[test]
    fn test_service_fee_schedule_total_collected() {
        let fees = ServiceFeeSchedule::default();
        const ONE_TNZO: u128 = 1_000_000_000_000_000_000;

        // 1 of each operation
        let total = fees.calculate_total_collected(1, 1, 1, 1, 1, 1, 1).unwrap();
        let expected = 10 + 5 + 5 + 2 + 1 + 50 + 1; // 74 TNZO
        assert_eq!(total, expected * ONE_TNZO);
    }

    #[test]
    fn test_apply_developer_margin() {
        const ONE_HUNDRED_TNZO: u128 = 100_000_000_000_000_000_000;

        // 10% margin on 100 TNZO -> 110 TNZO
        let user_pays = apply_developer_margin(ONE_HUNDRED_TNZO, 1000).unwrap();
        assert_eq!(user_pays, 110_000_000_000_000_000_000);

        // Zero margin is identity
        assert_eq!(
            apply_developer_margin(ONE_HUNDRED_TNZO, 0),
            Some(ONE_HUNDRED_TNZO)
        );

        // Cap itself is accepted
        let at_cap = apply_developer_margin(ONE_HUNDRED_TNZO, MAX_DEVELOPER_MARGIN_BPS).unwrap();
        assert_eq!(at_cap, 120_000_000_000_000_000_000);

        // Above the cap is rejected
        assert!(apply_developer_margin(ONE_HUNDRED_TNZO, MAX_DEVELOPER_MARGIN_BPS + 1).is_none());

        // Overflow returns None instead of panicking
        assert!(apply_developer_margin(u128::MAX, 1).is_none());
    }
}
