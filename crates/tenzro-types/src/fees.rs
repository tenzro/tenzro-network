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
/// an enacted governance proposal.
pub fn network_treasury_address() -> Address {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(TREASURY_DOMAIN);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    Address::new(out)
}

/// Share of an HTTP-402 payment settled off chain (delivery-versus-payment
/// and fiat rails) paid to the network treasury, in basis points of the
/// amount left after the developer margin.
///
/// The same rate as the treasury leg of a public validating node's revenue
/// split (`EconomicPolicy::validating.treasury_bps`). A payment settled on
/// chain pays the governed settlement fee instead
/// ([`DEFAULT_SETTLEMENT_FEE_BPS`] at genesis).
pub const HTTP_402_NETWORK_SHARE_BPS: u32 = 1_000;

/// Genesis value of the governed settlement fee `fees.settlement_fee_bps`:
/// the share of every on-chain settlement's value (escrow voucher, stream and
/// hash-lock claims, x402) divided between burn and treasury by the governed
/// settlement fee split. Chain state holds the live value.
pub const DEFAULT_SETTLEMENT_FEE_BPS: u32 = 10;

/// Upper bound on the per-app developer margin at genesis (basis points, 100 = 1%)
///
/// Applications registered in the on-chain app registry declare a `margin_bps`
/// that is carved out of a settlement attributed to the app and credited to
/// the app wallet. This cap is abuse and fat-finger protection, not consumer
/// protection.
///
/// Genesis value of the governed cap `fees.max_developer_margin_bps`: 2000
/// bps (20%).
pub const DEFAULT_MAX_DEVELOPER_MARGIN_BPS: u32 = 2000;

/// Applies a developer margin to a network cost.
///
/// Returns `user_pays = network_cost * (1 + margin_bps / 10000)`, or `None`
/// when `margin_bps` exceeds the governed cap `max_margin_bps` or the
/// arithmetic overflows.
pub fn apply_developer_margin(
    network_cost: u128,
    margin_bps: u32,
    max_margin_bps: u32,
) -> Option<u128> {
    if margin_bps > max_margin_bps {
        return None;
    }
    let margin = network_cost
        .checked_mul(margin_bps as u128)?
        .checked_div(10000)?;
    network_cost.checked_add(margin)
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
        model_registration: u128,
        bridge_transfer_base: u128,
    ) -> Self {
        Self {
            human_identity_registration,
            machine_identity_registration,
            agent_registration,
            model_registration,
            bridge_transfer_base,
        }
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
        assert_eq!(fees.model_registration, 50 * ONE_TNZO);
        assert_eq!(fees.bridge_transfer_base, ONE_TNZO);
    }

    #[test]
    fn test_apply_developer_margin() {
        const ONE_HUNDRED_TNZO: u128 = 100_000_000_000_000_000_000;

        // 10% margin on 100 TNZO -> 110 TNZO
        let user_pays =
            apply_developer_margin(ONE_HUNDRED_TNZO, 1000, DEFAULT_MAX_DEVELOPER_MARGIN_BPS)
                .unwrap();
        assert_eq!(user_pays, 110_000_000_000_000_000_000);

        // Zero margin is identity
        assert_eq!(
            apply_developer_margin(ONE_HUNDRED_TNZO, 0, DEFAULT_MAX_DEVELOPER_MARGIN_BPS),
            Some(ONE_HUNDRED_TNZO)
        );

        // Cap itself is accepted
        let at_cap = apply_developer_margin(
            ONE_HUNDRED_TNZO,
            DEFAULT_MAX_DEVELOPER_MARGIN_BPS,
            DEFAULT_MAX_DEVELOPER_MARGIN_BPS,
        )
        .unwrap();
        assert_eq!(at_cap, 120_000_000_000_000_000_000);

        // Above the cap is rejected
        assert!(
            apply_developer_margin(
                ONE_HUNDRED_TNZO,
                DEFAULT_MAX_DEVELOPER_MARGIN_BPS + 1,
                DEFAULT_MAX_DEVELOPER_MARGIN_BPS
            )
            .is_none()
        );

        // Overflow returns None instead of panicking
        assert!(apply_developer_margin(u128::MAX, 1, DEFAULT_MAX_DEVELOPER_MARGIN_BPS).is_none());
    }
}
