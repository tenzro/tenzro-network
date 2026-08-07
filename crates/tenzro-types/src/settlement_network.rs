//! The networks a payment can settle on, and what it costs to settle there.
//!
//! Tenzro settles on its own ledger and treats every other chain as a
//! **secondary** settlement layer. This module is the single place those
//! secondary layers are enumerated: their CAIP-2 identifiers, the asset family
//! they belong to, the stablecoins they carry canonically, and — the part that
//! actually drives behaviour — roughly what a transfer costs on each.
//!
//! # Why cost belongs in the registry
//!
//! A micropayment is only a payment if the fee is small relative to it.
//! Charging a tenth of a cent for one inference token is arithmetic on most
//! chains and a *loss* on Ethereum L1, where the fee exceeds the payment by
//! three orders of magnitude. An agentic economy metered per token therefore
//! cannot pick a rail by preference alone; it has to pick one where the
//! payment survives its own settlement.
//!
//! So [`SettlementNetwork::fee_floor_micro_usd`] is carried here and
//! [`cheapest_rail_for`] uses it. Without it every caller re-invents the same
//! comparison from a hardcoded guess, which is how a network ends up quoting
//! sub-cent prices on a rail that cannot carry them.
//!
//! # These figures are ordering hints, not quotes
//!
//! Fee floors are **indicative** and denominated in micro-USD (1 = $0.000001).
//! They exist to rank rails against each other, and they are deliberately not
//! used to quote a price to a payer — a real quote comes from the rail at
//! payment time, because gas markets move and these constants do not. Treat a
//! change in relative order as meaningful and a change in absolute value as
//! noise. Governance can override the whole table; see `docs/ECONOMICS.md`.

use serde::{Deserialize, Serialize};

/// One micro-USD is $0.000001. Fee floors and payment sizes share this unit so
/// they can be compared without a scaling step that someone eventually forgets.
pub const MICRO_USD: u64 = 1;

/// How a network is addressed and signed for, which decides which adapter
/// carries a payment to it.
///
/// This is deliberately about *mechanism*, not marketing: two EVM chains differ
/// in chain id and fee level but not in how a transfer is constructed, so they
/// share a family. Stellar and XRPL each get their own because their
/// authorization model genuinely differs — Soroban auth entries and XRPL
/// transaction signing are not EVM calldata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkFamily {
    /// The Tenzro Ledger itself — the primary settlement layer.
    Tenzro,
    /// EVM-compatible chains, addressed `eip155:<chain-id>`.
    Evm,
    /// Solana and SVM-compatible chains.
    Svm,
    /// Stellar, where payment authorization is a signed Soroban auth entry.
    Stellar,
    /// XRP Ledger, including its classic `r...` address form.
    Xrpl,
    /// Canton, where the cash leg is a tokenized deposit rather than a
    /// crypto-native token and settlement is atomic DvP.
    Canton,
}

impl NetworkFamily {
    /// Whether the family settles through the EVM bridge adapters.
    pub fn is_evm(self) -> bool {
        matches!(self, NetworkFamily::Evm)
    }

    /// Human-facing label.
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkFamily::Tenzro => "tenzro",
            NetworkFamily::Evm => "evm",
            NetworkFamily::Svm => "svm",
            NetworkFamily::Stellar => "stellar",
            NetworkFamily::Xrpl => "xrpl",
            NetworkFamily::Canton => "canton",
        }
    }
}

/// A network a payment can settle on.
///
/// `Serialize` only, deliberately: this is a compile-time table, so the fields
/// are `&'static`. Making it deserializable would mean accepting a network
/// definition off the wire, and the set of rails Tenzro settles on is not
/// something a caller gets to extend at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SettlementNetwork {
    /// CAIP-2 chain identifier. This is the identifier x402 v2 uses on the
    /// wire, so it is the key everything else joins on.
    pub caip2: &'static str,
    /// Short name for logs and operator-facing output.
    pub name: &'static str,
    /// Which adapter mechanism carries a payment here.
    pub family: NetworkFamily,
    /// Ticker of the gas/native asset.
    pub native_asset: &'static str,
    /// Stablecoins this network carries natively — issued on it rather than
    /// bridged to it. A bridged wrapper is a different asset with a different
    /// risk profile, so it does not belong in this list.
    pub native_stablecoins: &'static [&'static str],
    /// Whether an x402 payment can settle here today.
    pub x402: bool,
    /// Indicative cost of one transfer, in micro-USD. See the module docs:
    /// this ranks rails, it does not quote them.
    pub fee_floor_micro_usd: u64,
}

impl SettlementNetwork {
    /// Whether a payment of `amount_micro_usd` is worth settling here.
    ///
    /// The test is that the fee must not eat a material share of the payment.
    /// `min_ratio` is how many times the fee the payment must be worth — 100
    /// means "the fee may cost at most 1% of the payment".
    ///
    /// A rail whose fee *equals* the payment is not a marginal choice, it is a
    /// transfer of the entire amount to validators, so this is a real gate
    /// rather than a preference.
    pub fn carries(&self, amount_micro_usd: u64, min_ratio: u64) -> bool {
        if self.fee_floor_micro_usd == 0 {
            return true;
        }
        amount_micro_usd >= self.fee_floor_micro_usd.saturating_mul(min_ratio)
    }

    /// Whether this network natively carries `symbol`, compared case-insensitively.
    pub fn carries_asset(&self, symbol: &str) -> bool {
        self.native_stablecoins
            .iter()
            .any(|s| s.eq_ignore_ascii_case(symbol))
            || self.native_asset.eq_ignore_ascii_case(symbol)
    }
}

/// The default ratio for [`SettlementNetwork::carries`]: a payment must be
/// worth at least 100× the fee, i.e. settlement may cost at most 1% of it.
///
/// Chosen against the split itself — the treasury leg of a public validating
/// node is 10%, so a settlement cost above that order would dominate the
/// economics the split describes.
pub const DEFAULT_FEE_RATIO: u64 = 100;

/// Every network Tenzro can settle on.
///
/// Ordered cheapest-first so `iter().find(...)` yields the cheapest viable rail
/// without a sort at every call. A test enforces the ordering.
pub static SETTLEMENT_NETWORKS: &[SettlementNetwork] = &[
    SettlementNetwork {
        caip2: "tenzro:1337",
        name: "Tenzro Ledger",
        family: NetworkFamily::Tenzro,
        native_asset: "TNZO",
        native_stablecoins: &[],
        x402: true,
        // The primary layer. Gas is paid in TNZO under EIP-1559 at a 0.1 Gwei
        // floor; against a metered micropayment this rounds to nothing, and
        // ranking the home chain first is also correct by policy.
        fee_floor_micro_usd: 0,
    },
    SettlementNetwork {
        caip2: "stellar:pubnet",
        name: "Stellar",
        family: NetworkFamily::Stellar,
        native_asset: "XLM",
        // First-class on Stellar rather than bridged.
        native_stablecoins: &["USDC", "PYUSD", "USDY"],
        x402: true,
        // ~$0.00001. The cheapest rail that carries USDC natively, which is
        // why it is the default destination for sub-cent metering.
        fee_floor_micro_usd: 10,
    },
    SettlementNetwork {
        caip2: "xrpl:0",
        name: "XRP Ledger",
        family: NetworkFamily::Xrpl,
        native_asset: "XRP",
        native_stablecoins: &["RLUSD"],
        x402: true,
        // ~10 drops. Transactions confirm or expire rather than sitting
        // pending, which matters more to an agent than the fee does.
        fee_floor_micro_usd: 20,
    },
    SettlementNetwork {
        caip2: "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        name: "Solana",
        family: NetworkFamily::Svm,
        native_asset: "SOL",
        native_stablecoins: &["USDC", "PYUSD", "USDG"],
        x402: true,
        fee_floor_micro_usd: 250,
    },
    SettlementNetwork {
        caip2: "eip155:8453",
        name: "Base",
        family: NetworkFamily::Evm,
        native_asset: "ETH",
        native_stablecoins: &["USDC"],
        x402: true,
        fee_floor_micro_usd: 1_000,
    },
    SettlementNetwork {
        caip2: "eip155:98866",
        name: "Plume",
        family: NetworkFamily::Evm,
        native_asset: "PLUME",
        // pUSD is Plume's own; USDC arrives natively via CCTP v2 rather than
        // as a bridged wrapper.
        native_stablecoins: &["pUSD", "USDC"],
        x402: false,
        fee_floor_micro_usd: 1_000,
    },
    SettlementNetwork {
        caip2: "eip155:42161",
        name: "Arbitrum",
        family: NetworkFamily::Evm,
        native_asset: "ETH",
        native_stablecoins: &["USDC"],
        x402: false,
        fee_floor_micro_usd: 2_000,
    },
    SettlementNetwork {
        caip2: "eip155:137",
        name: "Polygon",
        family: NetworkFamily::Evm,
        native_asset: "POL",
        native_stablecoins: &["USDC"],
        x402: false,
        fee_floor_micro_usd: 3_000,
    },
    SettlementNetwork {
        caip2: "canton:global",
        name: "Canton",
        family: NetworkFamily::Canton,
        native_asset: "CC",
        // Canton has no native crypto stablecoin: tokenized money there is
        // issued by regulated institutions and represents real deposits.
        // USDC reaches it through Circle's privacy-preserving deployment.
        native_stablecoins: &["USDC"],
        x402: false,
        // Institutional DvP, not a micropayment rail. Ranked last so the
        // cheapest-first scan never lands here for metering; it is chosen
        // explicitly, for atomic delivery-versus-payment.
        fee_floor_micro_usd: 50_000,
    },
    SettlementNetwork {
        caip2: "eip155:1",
        name: "Ethereum",
        family: NetworkFamily::Evm,
        native_asset: "ETH",
        native_stablecoins: &["USDC", "USDT", "PYUSD", "USDP"],
        x402: false,
        // L1 settlement is for size, not frequency. At this fee a per-token
        // micropayment costs orders of magnitude more than it moves.
        fee_floor_micro_usd: 500_000,
    },
];

/// Look up a network by CAIP-2 identifier.
pub fn network_by_caip2(caip2: &str) -> Option<&'static SettlementNetwork> {
    SETTLEMENT_NETWORKS.iter().find(|n| n.caip2 == caip2)
}

/// The cheapest rail that can carry `amount_micro_usd` of `symbol`.
///
/// Returns `None` when no rail can — which is a real answer, not a failure:
/// a payment too small for every rail must be accumulated rather than settled,
/// and that is what the micro-settlement floor in `EconomicPolicy` is for.
/// Silently settling it anyway would spend more on the transfer than the
/// transfer moves.
pub fn cheapest_rail_for(
    symbol: &str,
    amount_micro_usd: u64,
    min_ratio: u64,
) -> Option<&'static SettlementNetwork> {
    SETTLEMENT_NETWORKS
        .iter()
        .find(|n| n.carries_asset(symbol) && n.carries(amount_micro_usd, min_ratio))
}

/// Every network that can settle an x402 payment.
pub fn x402_networks() -> impl Iterator<Item = &'static SettlementNetwork> {
    SETTLEMENT_NETWORKS.iter().filter(|n| n.x402)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_ordered_cheapest_first() {
        // `cheapest_rail_for` is a linear scan that returns the first match, so
        // the ordering *is* the algorithm. An out-of-order entry silently
        // routes payments to a more expensive rail.
        let fees: Vec<u64> = SETTLEMENT_NETWORKS
            .iter()
            .map(|n| n.fee_floor_micro_usd)
            .collect();
        let mut sorted = fees.clone();
        sorted.sort_unstable();
        assert_eq!(fees, sorted, "SETTLEMENT_NETWORKS must be cheapest-first");
    }

    #[test]
    fn caip2_identifiers_are_unique_and_well_formed() {
        let mut seen = std::collections::HashSet::new();
        for n in SETTLEMENT_NETWORKS {
            assert!(seen.insert(n.caip2), "duplicate CAIP-2: {}", n.caip2);
            let (ns, reference) = n
                .caip2
                .split_once(':')
                .expect("CAIP-2 is namespace:reference");
            assert!(
                !ns.is_empty() && !reference.is_empty(),
                "malformed: {}",
                n.caip2
            );
        }
    }

    #[test]
    fn tenzro_ledger_is_the_primary_layer() {
        // Tenzro settles on its own ledger and treats others as secondary, so
        // the home chain must rank first for any asset it carries.
        assert_eq!(SETTLEMENT_NETWORKS[0].caip2, "tenzro:1337");
        assert_eq!(
            cheapest_rail_for("TNZO", 1, 100).unwrap().name,
            "Tenzro Ledger"
        );
    }

    #[test]
    fn a_sub_cent_payment_routes_to_stellar_not_ethereum() {
        // The whole point of the registry. One tenth of a cent (1_000
        // micro-USD) in USDC is viable on Stellar and a loss on Ethereum.
        let rail = cheapest_rail_for("USDC", 1_000, DEFAULT_FEE_RATIO).unwrap();
        assert_eq!(rail.name, "Stellar");
    }

    #[test]
    fn a_payment_too_small_for_every_rail_returns_none() {
        // Must accumulate against the micro-settlement floor instead of
        // settling at a loss. `None` is the correct answer, not an error.
        assert!(cheapest_rail_for("USDC", 1, DEFAULT_FEE_RATIO).is_none());
    }

    #[test]
    fn a_large_payment_can_reach_every_rail_carrying_its_asset() {
        // $100 = 100_000_000 micro-USD clears even Ethereum's floor.
        let rail = cheapest_rail_for("USDT", 100_000_000, DEFAULT_FEE_RATIO).unwrap();
        assert_eq!(
            rail.name, "Ethereum",
            "USDT is only native on Ethereum here"
        );
    }

    #[test]
    fn carries_gates_on_the_ratio_not_merely_on_exceeding_the_fee() {
        let stellar = network_by_caip2("stellar:pubnet").unwrap();
        // Equal to the fee: the entire payment would be consumed settling it.
        assert!(!stellar.carries(10, DEFAULT_FEE_RATIO));
        // 100x the fee: settlement costs 1%.
        assert!(stellar.carries(1_000, DEFAULT_FEE_RATIO));
    }

    #[test]
    fn a_zero_fee_rail_carries_any_amount() {
        let tenzro = network_by_caip2("tenzro:1337").unwrap();
        assert!(tenzro.carries(1, DEFAULT_FEE_RATIO));
    }

    #[test]
    fn rlusd_is_reachable_and_lives_on_xrpl() {
        let rail = cheapest_rail_for("RLUSD", 100_000, DEFAULT_FEE_RATIO).unwrap();
        assert_eq!(rail.name, "XRP Ledger");
    }

    #[test]
    fn pusd_is_reachable_and_lives_on_plume() {
        let rail = cheapest_rail_for("pUSD", 1_000_000, DEFAULT_FEE_RATIO).unwrap();
        assert_eq!(rail.name, "Plume");
    }

    #[test]
    fn asset_lookup_is_case_insensitive() {
        // Tickers arrive from wire formats that disagree about case; routing
        // must not depend on which one a caller happened to use.
        assert!(cheapest_rail_for("usdc", 1_000, DEFAULT_FEE_RATIO).is_some());
        assert!(cheapest_rail_for("rlUSD", 100_000, DEFAULT_FEE_RATIO).is_some());
    }

    #[test]
    fn canton_never_wins_a_micropayment_race() {
        // Canton is institutional DvP. It must be chosen deliberately, never
        // by a cheapest-rail scan for metered traffic.
        let rail = cheapest_rail_for("USDC", 10_000, DEFAULT_FEE_RATIO).unwrap();
        assert_ne!(rail.family, NetworkFamily::Canton);
    }

    #[test]
    fn x402_support_does_not_imply_sub_cent_capability() {
        // These are different properties and conflating them is the mistake
        // this registry exists to prevent. Base speaks x402 fluently and still
        // cannot carry a one-cent payment at 1% overhead — its fee is ~10% of
        // the payment at that size. An agent that picks a rail by "does it
        // support x402" will lose money on every metered call.
        let base = network_by_caip2("eip155:8453").unwrap();
        assert!(base.x402);
        assert!(!base.carries(10_000, DEFAULT_FEE_RATIO));

        let stellar = network_by_caip2("stellar:pubnet").unwrap();
        assert!(stellar.x402);
        assert!(stellar.carries(10_000, DEFAULT_FEE_RATIO));
    }

    #[test]
    fn a_sub_cent_tier_exists_and_is_reachable_by_x402() {
        // The metering tier: rails that can carry a tenth of a cent. If this
        // set ever empties, per-token metering has no rail to settle on and
        // the token meter is arithmetic with nowhere to go.
        let tier: Vec<_> = x402_networks()
            .filter(|n| n.carries(1_000, DEFAULT_FEE_RATIO))
            .map(|n| n.name)
            .collect();
        assert!(
            tier.contains(&"Stellar"),
            "expected Stellar in the sub-cent tier, got {tier:?}"
        );
        assert!(
            tier.len() >= 2,
            "sub-cent metering needs more than one rail"
        );
    }

    #[test]
    fn every_x402_network_beats_l1_settlement_cost() {
        // The weaker claim that *is* true of all of them: an x402 rail is
        // always materially cheaper than Ethereum L1, which is the rail x402
        // exists to avoid for machine-scale traffic.
        let l1 = network_by_caip2("eip155:1").unwrap();
        for n in x402_networks() {
            assert!(
                n.fee_floor_micro_usd < l1.fee_floor_micro_usd,
                "{} advertises x402 but is not cheaper than L1",
                n.name
            );
        }
    }

    #[test]
    fn no_network_lists_a_stablecoin_twice() {
        for n in SETTLEMENT_NETWORKS {
            let mut seen = std::collections::HashSet::new();
            for s in n.native_stablecoins {
                assert!(
                    seen.insert(s.to_ascii_uppercase()),
                    "{} lists {s} twice",
                    n.name
                );
            }
        }
    }
}
