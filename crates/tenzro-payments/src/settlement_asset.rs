//! Multi-chain stablecoin settlement routing.
//!
//! A payment can arrive as a stablecoin on any chain Tenzro bridges — USDC on
//! Base, USDT on Solana, EURC on Ethereum. The payee decides what they want to
//! *hold*: the stablecoin as it arrived, or TNZO.
//!
//! # Why the swap is optional
//!
//! Forcing every inbound stablecoin through a swap to TNZO would be the
//! simpler router, and it would be wrong for the case that matters most on
//! testnet: a model provider earning USDC wants spendable USDC. Making them
//! hold a token whose liquidity is still forming, in order to pay costs
//! denominated in dollars, converts a working payment into an FX position they
//! did not ask for.
//!
//! So [`SettlementAsset::KeepInbound`] is the default, and a swap happens only
//! when the payee has asked for one. A route that cannot be built is a refusal,
//! never a silent fallback to the other asset — a payee who asked for TNZO and
//! received USDC (or the reverse) has been given something they did not choose.
//!
//! # Chain-agnostic asset identity
//!
//! Inbound assets are named by [`Caip19`] rather than a bare symbol. "USDC" is
//! not an identifier: there are USDC deployments on a dozen chains, several
//! bridged variants per chain, and at least one well-known impostor per chain.
//! `eip155:8453/erc20:0x833589f...` is unambiguous, and it is what the payee's
//! preference is keyed on.
//!
//! This module decides *what asset settles*. Who receives it is
//! [`crate::revenue_split`].

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::error::{PaymentError, Result};

/// A CAIP-19 asset identifier: `<chain_namespace>:<chain_reference>/<asset_namespace>:<asset_reference>`.
///
/// Examples:
/// - `eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913` — USDC on Base
/// - `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp/token:EPjFWdd5...` — USDC on Solana
/// - `eip155:1/slip44:60` — native ETH
///
/// Parsed rather than held as a string so a malformed identifier is rejected at
/// the boundary instead of failing somewhere downstream, and so equality is
/// structural rather than textual.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Caip19 {
    /// Chain namespace: `eip155`, `solana`, `cosmos`, …
    pub chain_namespace: String,
    /// Chain reference: the EVM chain id, the Solana genesis hash prefix, …
    pub chain_reference: String,
    /// Asset namespace: `erc20`, `token`, `slip44`, …
    pub asset_namespace: String,
    /// Asset reference: the contract address, mint address, or coin type.
    pub asset_reference: String,
}

impl Caip19 {
    /// Parse a CAIP-19 identifier.
    ///
    /// Case is normalised to lowercase: EVM addresses are commonly written in
    /// EIP-55 mixed case, and two spellings of one asset must not key to two
    /// different payee preferences. Solana addresses are base58 and *are*
    /// case-sensitive, so they are left as written — see
    /// [`Self::asset_reference`].
    pub fn parse(s: &str) -> Result<Self> {
        let malformed =
            |why: &str| PaymentError::ConfigError(format!("invalid CAIP-19 asset id {s:?}: {why}"));

        let (chain, asset) = s
            .split_once('/')
            .ok_or_else(|| malformed("expected <chain>/<asset>"))?;
        let (chain_namespace, chain_reference) = chain
            .split_once(':')
            .ok_or_else(|| malformed("chain part expected <namespace>:<reference>"))?;
        let (asset_namespace, asset_reference) = asset
            .split_once(':')
            .ok_or_else(|| malformed("asset part expected <namespace>:<reference>"))?;

        for (label, value) in [
            ("chain namespace", chain_namespace),
            ("chain reference", chain_reference),
            ("asset namespace", asset_namespace),
            ("asset reference", asset_reference),
        ] {
            if value.is_empty() {
                return Err(malformed(&format!("{label} is empty")));
            }
        }

        // Namespaces and the chain reference are case-insensitive; the asset
        // reference is not, because base58 mint addresses carry case.
        let case_insensitive = chain_namespace.eq_ignore_ascii_case("eip155");
        Ok(Self {
            chain_namespace: chain_namespace.to_ascii_lowercase(),
            chain_reference: chain_reference.to_ascii_lowercase(),
            asset_namespace: asset_namespace.to_ascii_lowercase(),
            asset_reference: if case_insensitive {
                asset_reference.to_ascii_lowercase()
            } else {
                asset_reference.to_string()
            },
        })
    }

    /// Whether this asset lives on an EVM chain.
    pub fn is_evm(&self) -> bool {
        self.chain_namespace == "eip155"
    }

    /// Whether this asset lives on Solana.
    pub fn is_svm(&self) -> bool {
        self.chain_namespace == "solana"
    }

    /// Canonical string form.
    pub fn to_id(&self) -> String {
        format!(
            "{}:{}/{}:{}",
            self.chain_namespace, self.chain_reference, self.asset_namespace, self.asset_reference
        )
    }
}

impl std::fmt::Display for Caip19 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_id())
    }
}

/// What a payee wants to hold once a payment settles.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SettlementAsset {
    /// Keep the stablecoin exactly as it arrived. **The default.**
    ///
    /// A provider earning USDC generally wants spendable USDC — their costs are
    /// denominated in dollars, and converting to TNZO would hand them an FX
    /// position they did not ask for.
    #[default]
    KeepInbound,
    /// Swap the inbound asset to TNZO before crediting the payee.
    ///
    /// Opt-in. Chosen by payees who want network-token exposure, or who are
    /// staking their earnings.
    Tnzo,
}

impl SettlementAsset {
    /// Stable wire form.
    pub fn as_str(self) -> &'static str {
        match self {
            SettlementAsset::KeepInbound => "keep_inbound",
            SettlementAsset::Tnzo => "tnzo",
        }
    }
}

/// What the router decided to do with one inbound payment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettlementRoute {
    /// Credit the payee the inbound asset unchanged. No swap, no slippage, no
    /// route risk.
    Direct {
        /// The asset being credited — the same one that arrived.
        asset: Caip19,
        /// Amount in the asset's smallest unit.
        amount: u128,
    },
    /// Swap the inbound asset to TNZO, then credit the payee.
    Swap {
        /// The asset that arrived.
        from: Caip19,
        /// Amount in of the inbound asset, smallest unit.
        amount_in: u128,
        /// Minimum TNZO the payee will accept, after slippage.
        ///
        /// Carried on the route rather than left to the executor so the
        /// acceptable loss is a decision made here, where the payee's
        /// preference is known, and is auditable on the receipt.
        min_amount_out: u128,
    },
}

/// Per-payee settlement preferences.
///
/// Keyed by payee DID. A payee with no recorded preference gets
/// [`SettlementAsset::KeepInbound`], which is the conservative answer: it
/// credits exactly what was paid and involves no route.
#[derive(Debug, Clone, Default)]
pub struct SettlementPreferences {
    by_payee: HashMap<String, SettlementAsset>,
}

impl SettlementPreferences {
    /// Empty set — every payee gets the default.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a payee's preference.
    pub fn set(&mut self, payee_did: impl Into<String>, asset: SettlementAsset) {
        self.by_payee.insert(payee_did.into(), asset);
    }

    /// The payee's preference, or the default when none is recorded.
    pub fn get(&self, payee_did: &str) -> SettlementAsset {
        self.by_payee
            .get(payee_did)
            .copied()
            .unwrap_or(SettlementAsset::KeepInbound)
    }

    /// Drop a payee's preference, returning them to the default.
    pub fn clear(&mut self, payee_did: &str) -> Option<SettlementAsset> {
        self.by_payee.remove(payee_did)
    }

    /// Number of recorded preferences (payees on the default are not counted).
    pub fn len(&self) -> usize {
        self.by_payee.len()
    }

    /// Whether any preference is recorded.
    pub fn is_empty(&self) -> bool {
        self.by_payee.is_empty()
    }
}

/// Quotes a swap from an inbound asset to TNZO.
///
/// A trait so the router does not care whether the venue is an on-chain DEX, a
/// bridge's built-in swap, or an internal market-maker — and so a node with no
/// venue configured is a *representable* state rather than a panic.
pub trait SwapQuoter: Send + Sync {
    /// Minimum TNZO out for `amount_in` of `from`, after slippage.
    ///
    /// `Ok(None)` means "no route for this asset" — a normal answer, not a
    /// failure. `Err` is reserved for a venue that should have answered and
    /// could not.
    fn quote_to_tnzo(&self, from: &Caip19, amount_in: u128) -> Result<Option<u128>>;
}

/// Decide how one inbound payment settles.
///
/// Returns the route, or an error when the payee asked for something that
/// cannot be delivered.
///
/// # Errors
///
/// Fails when the payee asked for TNZO and no swap route exists. This is
/// deliberately **not** a fallback to `Direct`: quietly crediting a stablecoin
/// to a payee who asked for TNZO gives them an asset they did not choose, and
/// the failure is silent precisely where it matters. Refusing surfaces it while
/// the payment can still be retried or the preference changed.
pub fn route_settlement(
    payee_did: &str,
    inbound_asset: &Caip19,
    amount: u128,
    prefs: &SettlementPreferences,
    quoter: Option<&dyn SwapQuoter>,
) -> Result<SettlementRoute> {
    match prefs.get(payee_did) {
        SettlementAsset::KeepInbound => Ok(SettlementRoute::Direct {
            asset: inbound_asset.clone(),
            amount,
        }),
        SettlementAsset::Tnzo => {
            let quoter = quoter.ok_or_else(|| {
                PaymentError::SettlementError(format!(
                    "payee {payee_did} settles in TNZO but no swap venue is configured on this \
                     node; the payment is refused rather than settled in {inbound_asset}, which \
                     is not the asset they chose"
                ))
            })?;

            let min_amount_out = quoter
                .quote_to_tnzo(inbound_asset, amount)?
                .ok_or_else(|| {
                    PaymentError::SettlementError(format!(
                        "payee {payee_did} settles in TNZO but no route exists from {inbound_asset}"
                    ))
                })?;

            if min_amount_out == 0 {
                return Err(PaymentError::SettlementError(format!(
                    "swap route from {inbound_asset} quoted zero TNZO out for {amount} in"
                )));
            }

            Ok(SettlementRoute::Swap {
                from: inbound_asset.clone(),
                amount_in: amount,
                min_amount_out,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn usdc_base() -> Caip19 {
        Caip19::parse("eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913").unwrap()
    }

    fn usdc_solana() -> Caip19 {
        Caip19::parse("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp/token:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v")
            .unwrap()
    }

    struct FixedQuoter(Option<u128>);
    impl SwapQuoter for FixedQuoter {
        fn quote_to_tnzo(&self, _from: &Caip19, _amount_in: u128) -> Result<Option<u128>> {
            Ok(self.0)
        }
    }

    // ---- CAIP-19 parsing -------------------------------------------------

    #[test]
    fn parses_an_evm_asset() {
        let a = usdc_base();
        assert_eq!(a.chain_namespace, "eip155");
        assert_eq!(a.chain_reference, "8453");
        assert_eq!(a.asset_namespace, "erc20");
        assert!(a.is_evm());
        assert!(!a.is_svm());
    }

    #[test]
    fn parses_an_svm_asset() {
        let a = usdc_solana();
        assert_eq!(a.chain_namespace, "solana");
        assert_eq!(a.asset_namespace, "token");
        assert!(a.is_svm());
        assert!(!a.is_evm());
    }

    /// EIP-55 mixed case and lowercase name the same token. Two spellings must
    /// not key to two different payee preferences.
    #[test]
    fn evm_addresses_compare_case_insensitively() {
        let lower =
            Caip19::parse("eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913").unwrap();
        let mixed =
            Caip19::parse("eip155:8453/erc20:0x833589fCd6eDb6E08f4c7C32D4f71b54bdA02913").unwrap();
        assert_eq!(lower, mixed);
    }

    /// Solana mint addresses are base58 and case-carrying, so they must NOT be
    /// folded — two different mints can differ only by case.
    #[test]
    fn solana_mints_keep_their_case() {
        let a = usdc_solana();
        assert!(
            a.asset_reference.chars().any(|c| c.is_ascii_uppercase()),
            "base58 case must survive parsing"
        );
    }

    #[test]
    fn round_trips_through_its_canonical_form() {
        let a = usdc_base();
        assert_eq!(Caip19::parse(&a.to_id()).unwrap(), a);
    }

    #[test]
    fn rejects_malformed_identifiers() {
        for bad in [
            "eip155:8453",        // no asset part
            "eip155/erc20:0xabc", // chain missing reference
            "eip155:8453/erc20",  // asset missing reference
            "eip155:8453/erc20:", // empty asset reference
            ":8453/erc20:0xabc",  // empty chain namespace
            "usdc",               // a bare symbol is not an id
        ] {
            assert!(
                Caip19::parse(bad).is_err(),
                "{bad:?} should not parse as CAIP-19"
            );
        }
    }

    // ---- preferences -----------------------------------------------------

    /// The default matters: a provider earning USDC wants spendable USDC.
    #[test]
    fn an_unrecorded_payee_keeps_the_inbound_asset() {
        let prefs = SettlementPreferences::new();
        assert_eq!(
            prefs.get("did:tenzro:human:nobody"),
            SettlementAsset::KeepInbound
        );
        assert_eq!(SettlementAsset::default(), SettlementAsset::KeepInbound);
    }

    #[test]
    fn preferences_are_per_payee() {
        let mut prefs = SettlementPreferences::new();
        prefs.set("did:a", SettlementAsset::Tnzo);
        assert_eq!(prefs.get("did:a"), SettlementAsset::Tnzo);
        assert_eq!(prefs.get("did:b"), SettlementAsset::KeepInbound);

        prefs.clear("did:a");
        assert_eq!(prefs.get("did:a"), SettlementAsset::KeepInbound);
    }

    // ---- routing ---------------------------------------------------------

    #[test]
    fn default_preference_routes_direct_with_no_quoter() {
        let prefs = SettlementPreferences::new();
        let route = route_settlement("did:a", &usdc_base(), 1_000_000, &prefs, None).unwrap();
        assert_eq!(
            route,
            SettlementRoute::Direct {
                asset: usdc_base(),
                amount: 1_000_000
            }
        );
    }

    #[test]
    fn tnzo_preference_routes_a_swap_when_a_route_exists() {
        let mut prefs = SettlementPreferences::new();
        prefs.set("did:a", SettlementAsset::Tnzo);
        let quoter = FixedQuoter(Some(42));

        let route =
            route_settlement("did:a", &usdc_base(), 1_000_000, &prefs, Some(&quoter)).unwrap();
        assert_eq!(
            route,
            SettlementRoute::Swap {
                from: usdc_base(),
                amount_in: 1_000_000,
                min_amount_out: 42
            }
        );
    }

    /// The rule worth pinning: a payee who asked for TNZO is never quietly
    /// credited the stablecoin instead. Silently delivering the other asset is
    /// the failure mode this refusal exists to prevent.
    #[test]
    fn tnzo_preference_refuses_rather_than_falling_back_to_direct() {
        let mut prefs = SettlementPreferences::new();
        prefs.set("did:a", SettlementAsset::Tnzo);

        // No venue configured at all.
        let err = route_settlement("did:a", &usdc_base(), 1_000_000, &prefs, None)
            .expect_err("no venue must refuse, not settle in the wrong asset");
        assert!(
            format!("{err}").contains("not the asset they chose"),
            "got {err}"
        );

        // A venue that has no route for this asset.
        let quoter = FixedQuoter(None);
        assert!(
            route_settlement("did:a", &usdc_base(), 1_000_000, &prefs, Some(&quoter)).is_err(),
            "no route must refuse"
        );
    }

    #[test]
    fn a_zero_quote_is_refused() {
        let mut prefs = SettlementPreferences::new();
        prefs.set("did:a", SettlementAsset::Tnzo);
        let quoter = FixedQuoter(Some(0));
        assert!(
            route_settlement("did:a", &usdc_base(), 1_000_000, &prefs, Some(&quoter)).is_err(),
            "a route that yields nothing is not a route"
        );
    }

    /// Both inbound chain families route identically — the router is
    /// chain-agnostic by construction, which is the point of keying on CAIP-19.
    #[test]
    fn evm_and_svm_inbound_route_the_same_way() {
        let prefs = SettlementPreferences::new();
        for asset in [usdc_base(), usdc_solana()] {
            let route = route_settlement("did:a", &asset, 500, &prefs, None).unwrap();
            assert_eq!(
                route,
                SettlementRoute::Direct {
                    asset: asset.clone(),
                    amount: 500
                }
            );
        }
    }
}
