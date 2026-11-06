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

use std::borrow::Cow;

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
    /// wire, so it is the key everything else joins on. The Tenzro Ledger's
    /// is `tenzro:<chain-id>`, built from the chain id of the network a node
    /// runs; every other network's is fixed.
    pub caip2: Cow<'static, str>,
    /// Short name for logs and operator-facing output.
    pub name: &'static str,
    /// Which adapter mechanism carries a payment here.
    pub family: NetworkFamily,
    /// Ticker of the gas/native asset.
    pub native_asset: &'static str,
    /// Decimals of the native asset's smallest unit (wei 18, lamports 9).
    pub native_decimals: u8,
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

/// The CAIP-2 namespace of the Tenzro Ledger.
pub const TENZRO_NAMESPACE: &str = "tenzro";

/// The CAIP-2 identifier of the Tenzro Ledger with chain id `chain_id`:
/// `tenzro:133801` on the preview network.
///
/// The identifier names the network a payment settles on, so it is built from
/// the chain id the network's genesis sets, never from a constant: a fixed
/// identifier would name a different network on every chain but one.
pub fn tenzro_caip2(chain_id: u64) -> String {
    format!("{TENZRO_NAMESPACE}:{chain_id}")
}

/// The chain id a `tenzro:<chain-id>` identifier names, or `None` for any
/// other identifier.
pub fn tenzro_chain_id_of(caip2: &str) -> Option<u64> {
    let reference = caip2.strip_prefix(TENZRO_NAMESPACE)?.strip_prefix(':')?;
    if reference.is_empty() || !reference.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    reference.parse().ok()
}

/// The Tenzro Ledger, the primary settlement layer, on chain `chain_id`.
pub fn tenzro_ledger(chain_id: u64) -> SettlementNetwork {
    SettlementNetwork {
        caip2: Cow::Owned(tenzro_caip2(chain_id)),
        name: "Tenzro Ledger",
        family: NetworkFamily::Tenzro,
        native_asset: "TNZO",
        native_decimals: 18,
        native_stablecoins: &[],
        x402: true,
        // The primary layer. Gas is paid in TNZO under EIP-1559 at a 0.1 Gwei
        // floor; against a metered micropayment this rounds to nothing, and
        // ranking the home chain first is also correct by policy.
        fee_floor_micro_usd: 0,
    }
}

/// Every network Tenzro can settle on, for a node on chain `chain_id`: the
/// Tenzro Ledger first, then [`SECONDARY_NETWORKS`].
pub fn settlement_networks(chain_id: u64) -> Vec<SettlementNetwork> {
    std::iter::once(tenzro_ledger(chain_id))
        .chain(SECONDARY_NETWORKS.iter().cloned())
        .collect()
}

/// Every network other than the Tenzro Ledger that Tenzro can settle on.
///
/// # Where these identifiers come from
///
/// Each was verified against its authoritative registry rather than inferred,
/// because a wrong chain id routes real money to the wrong place and looks
/// perfectly healthy while doing it:
///
/// - `xrpl:0` — CASA `xrpl` namespace: `xrpl:{network_id}`, livenet is 0
///   (testnet 1, devnet 2). Some libraries use `xrpl:mainnet` instead; that
///   form is *not* the registered one.
/// - `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` — CASA `solana` namespace: the
///   44-character genesis hash truncated to its first 32 characters.
/// - `stellar:pubnet` — Stellar's own x402 documentation.
/// - `eip155:98866` — Plume mainnet per ChainList and Plume's docs. Note 98865
///   is *Plume Legacy* and 98867 is testnet; neither belongs here.
///
/// Ordered cheapest-first so `iter().find(...)` yields the cheapest viable rail
/// without a sort at every call. A test enforces the ordering.
pub static SECONDARY_NETWORKS: &[SettlementNetwork] = &[
    SettlementNetwork {
        caip2: Cow::Borrowed("stellar:pubnet"),
        name: "Stellar",
        family: NetworkFamily::Stellar,
        native_asset: "XLM",
        native_decimals: 7,
        // First-class on Stellar rather than bridged.
        native_stablecoins: &["USDC", "PYUSD", "USDY"],
        x402: true,
        // ~$0.00001. The cheapest rail that carries USDC natively, which is
        // why it is the default destination for sub-cent metering.
        fee_floor_micro_usd: 10,
    },
    SettlementNetwork {
        caip2: Cow::Borrowed("xrpl:0"),
        name: "XRP Ledger",
        family: NetworkFamily::Xrpl,
        native_asset: "XRP",
        native_decimals: 6,
        native_stablecoins: &["RLUSD"],
        x402: true,
        // ~10 drops. Transactions confirm or expire rather than sitting
        // pending, which matters more to an agent than the fee does.
        fee_floor_micro_usd: 20,
    },
    SettlementNetwork {
        caip2: Cow::Borrowed("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"),
        name: "Solana",
        family: NetworkFamily::Svm,
        native_asset: "SOL",
        native_decimals: 9,
        native_stablecoins: &["USDC", "PYUSD", "USDG"],
        x402: true,
        fee_floor_micro_usd: 250,
    },
    SettlementNetwork {
        caip2: Cow::Borrowed("eip155:8453"),
        name: "Base",
        family: NetworkFamily::Evm,
        native_asset: "ETH",
        native_decimals: 18,
        native_stablecoins: &["USDC"],
        x402: true,
        fee_floor_micro_usd: 1_000,
    },
    SettlementNetwork {
        caip2: Cow::Borrowed("eip155:98866"),
        name: "Plume",
        family: NetworkFamily::Evm,
        native_asset: "PLUME",
        native_decimals: 18,
        // pUSD is Plume's own; USDC arrives natively via CCTP v2 rather than
        // as a bridged wrapper.
        native_stablecoins: &["pUSD", "USDC"],
        x402: false,
        fee_floor_micro_usd: 1_000,
    },
    SettlementNetwork {
        caip2: Cow::Borrowed("eip155:42161"),
        name: "Arbitrum",
        family: NetworkFamily::Evm,
        native_asset: "ETH",
        native_decimals: 18,
        native_stablecoins: &["USDC"],
        x402: false,
        fee_floor_micro_usd: 2_000,
    },
    SettlementNetwork {
        caip2: Cow::Borrowed("eip155:137"),
        name: "Polygon",
        family: NetworkFamily::Evm,
        native_asset: "POL",
        native_decimals: 18,
        native_stablecoins: &["USDC"],
        x402: false,
        fee_floor_micro_usd: 3_000,
    },
    SettlementNetwork {
        caip2: Cow::Borrowed("eip155:1"),
        name: "Ethereum",
        family: NetworkFamily::Evm,
        native_asset: "ETH",
        native_decimals: 18,
        native_stablecoins: &["USDC", "USDT", "PYUSD", "USDP"],
        x402: false,
        // L1 settlement is for size, not frequency. At this fee a per-token
        // micropayment costs orders of magnitude more than it moves.
        fee_floor_micro_usd: 500_000,
    },
];

/// Canonical CAIP-2 identifier for a bridge adapter's chain name.
///
/// # Why this exists
///
/// Tenzro carries two identifier schemes for the same chains. The bridge
/// adapters name them (`ChainInfo::chain_id` is `"ethereum"`, `"arbitrum"`),
/// because that is what the underlying protocols use in their own routing
/// tables. Settlement uses CAIP-2 (`eip155:1`), because that is what x402 v2
/// puts on the wire. Both are correct in their own layer, and a settlement
/// mirror has to span them.
///
/// This is the one place they meet. Without it, every caller that needs to
/// cross the boundary invents its own table, and those tables drift.
///
/// # Every value here was read from a registry, not recalled
///
/// EVM ids come from the canonical EIP-155 registry at `chainid.network`.
/// That check was not ceremonial: a naive lookup by short name resolves
/// `plume` to **98865, which is Plume *Legacy***, and `story` to a *testnet*.
/// Both would have silently pointed settlements at the wrong chain.
///
/// # `None` means "no verified mapping", not "unreachable"
///
/// Several chains the adapters reach have no entry: Cosmos-family chains
/// (Osmosis, Juno, Neutron, Injective, Evmos, Kava, Kujira, Crescent),
/// Move-family chains (Aptos, Sui), and chains whose mainnet is absent from
/// the EIP-155 registry (Hyperliquid and Story list only testnets there).
///
/// Returning `None` for those is deliberate. They remain fully reachable
/// through their adapters and fully mirrorable — `MirrorPlan` accepts a plain
/// chain name exactly so a chain without a verified CAIP-2 is not shut out.
/// Inventing an identifier to fill the gap is the one option that could route
/// real value to the wrong chain, so it is the one option not taken.
///
/// `tenzro` maps to the Tenzro Ledger of chain `chain_id`, the chain the
/// caller runs on.
pub fn caip2_for_chain_name(name: &str, chain_id: u64) -> Option<Cow<'static, str>> {
    if name.eq_ignore_ascii_case(TENZRO_NAMESPACE) {
        return Some(Cow::Owned(tenzro_caip2(chain_id)));
    }
    secondary_caip2_for_chain_name(name).map(Cow::Borrowed)
}

/// [`caip2_for_chain_name`] for every chain but the Tenzro Ledger, whose
/// identifier depends on the chain id.
fn secondary_caip2_for_chain_name(name: &str) -> Option<&'static str> {
    Some(match name.to_ascii_lowercase().as_str() {
        // EVM, per the EIP-155 registry.
        "ethereum" => "eip155:1",
        "optimism" => "eip155:10",
        "bsc" | "binance" => "eip155:56",
        "gnosis" => "eip155:100",
        "polygon" => "eip155:137",
        "monad" => "eip155:143",
        "sonic" => "eip155:146",
        "manta" => "eip155:169",
        "blast" => "eip155:238",
        "fantom" => "eip155:250",
        "fraxtal" => "eip155:252",
        "filecoin" => "eip155:314",
        "zksync" => "eip155:324",
        "moonbeam" => "eip155:1284",
        "sei" => "eip155:1329",
        "megaeth" => "eip155:4326",
        "mantle" => "eip155:5000",
        "base" => "eip155:8453",
        "mode" => "eip155:34443",
        "arbitrum" => "eip155:42161",
        "celo" => "eip155:42220",
        "avalanche" => "eip155:43114",
        "linea" => "eip155:59144",
        "berachain" => "eip155:80094",
        // 98866 is Plume *Mainnet*. 98865 is Legacy and 98867 is testnet;
        // a short-name lookup returns the Legacy chain, which is why this
        // entry is pinned explicitly.
        "plume" => "eip155:98866",
        "aurora" => "eip155:1313161554",
        "scroll" => "eip155:534352",

        // Non-EVM, per their CASA namespaces.
        "solana" => "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp",
        "stellar" => "stellar:pubnet",
        "xrpl" => "xrpl:0",

        // Reachable, but with no verified CAIP-2. See the note above: these
        // mirror by name rather than being excluded.
        _ => return None,
    })
}

/// The chain name a CAIP-2 identifier corresponds to, where one is mapped.
///
/// The reverse of [`caip2_for_chain_name`], for resolving a settlement target
/// back to the adapter that can carry it. Any `tenzro:<chain-id>` resolves to
/// `tenzro`: routes are keyed by name, and the name does not carry the chain.
pub fn chain_name_for_caip2(caip2: &str) -> Option<&'static str> {
    if tenzro_chain_id_of(caip2).is_some() {
        return Some(TENZRO_NAMESPACE);
    }
    const NAMES: &[&str] = &[
        "ethereum",
        "optimism",
        "bsc",
        "gnosis",
        "polygon",
        "monad",
        "sonic",
        "manta",
        "blast",
        "fantom",
        "fraxtal",
        "filecoin",
        "zksync",
        "moonbeam",
        "sei",
        "megaeth",
        "mantle",
        "base",
        "mode",
        "arbitrum",
        "celo",
        "avalanche",
        "linea",
        "berachain",
        "plume",
        "aurora",
        "scroll",
        "solana",
        "stellar",
        "xrpl",
    ];
    NAMES
        .iter()
        .find(|n| secondary_caip2_for_chain_name(n) == Some(caip2))
        .copied()
}

/// Look up a network by CAIP-2 identifier, for a node on chain `chain_id`.
///
/// The Tenzro Ledger is found only under the identifier of that chain: a
/// `tenzro:` identifier naming another chain is another network, which this
/// node does not settle on.
pub fn network_by_caip2(caip2: &str, chain_id: u64) -> Option<SettlementNetwork> {
    if tenzro_chain_id_of(caip2).is_some() {
        return (tenzro_chain_id_of(caip2) == Some(chain_id)).then(|| tenzro_ledger(chain_id));
    }
    secondary_network_by_caip2(caip2).cloned()
}

/// Look up a network other than the Tenzro Ledger by CAIP-2 identifier.
pub fn secondary_network_by_caip2(caip2: &str) -> Option<&'static SettlementNetwork> {
    SECONDARY_NETWORKS.iter().find(|n| n.caip2 == caip2)
}

/// The family of the network `caip2` names, if it is a settlement network.
/// Every `tenzro:<chain-id>` is of the Tenzro family, whichever chain it names.
pub fn family_of_caip2(caip2: &str) -> Option<NetworkFamily> {
    if tenzro_chain_id_of(caip2).is_some() {
        return Some(NetworkFamily::Tenzro);
    }
    secondary_network_by_caip2(caip2).map(|n| n.family)
}

/// The cheapest rail that can carry `amount_micro_usd` of `symbol`, for a node
/// on chain `chain_id`.
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
    chain_id: u64,
) -> Option<SettlementNetwork> {
    let home = tenzro_ledger(chain_id);
    if home.carries_asset(symbol) && home.carries(amount_micro_usd, min_ratio) {
        return Some(home);
    }
    cheapest_secondary_rail_for(symbol, amount_micro_usd, min_ratio).cloned()
}

/// [`cheapest_rail_for`] among the networks other than the Tenzro Ledger.
pub fn cheapest_secondary_rail_for(
    symbol: &str,
    amount_micro_usd: u64,
    min_ratio: u64,
) -> Option<&'static SettlementNetwork> {
    SECONDARY_NETWORKS
        .iter()
        .find(|n| n.carries_asset(symbol) && n.carries(amount_micro_usd, min_ratio))
}

/// Every network that can settle an x402 payment, for a node on chain
/// `chain_id`.
pub fn x402_networks(chain_id: u64) -> impl Iterator<Item = SettlementNetwork> {
    settlement_networks(chain_id).into_iter().filter(|n| n.x402)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The preview network's chain id.
    const PREVIEW: u64 = 133801;

    #[test]
    fn registry_is_ordered_cheapest_first() {
        // `cheapest_rail_for` is a linear scan that returns the first match, so
        // the ordering *is* the algorithm. An out-of-order entry silently
        // routes payments to a more expensive rail.
        let fees: Vec<u64> = settlement_networks(PREVIEW)
            .iter()
            .map(|n| n.fee_floor_micro_usd)
            .collect();
        let mut sorted = fees.clone();
        sorted.sort_unstable();
        assert_eq!(fees, sorted, "the registry must be cheapest-first");
    }

    #[test]
    fn caip2_identifiers_are_unique_and_well_formed() {
        let mut seen = std::collections::HashSet::new();
        for n in settlement_networks(PREVIEW) {
            assert!(
                seen.insert(n.caip2.clone()),
                "duplicate CAIP-2: {}",
                n.caip2
            );
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
        assert_eq!(settlement_networks(PREVIEW)[0].caip2, "tenzro:133801");
        assert_eq!(
            cheapest_rail_for("TNZO", 1, 100, PREVIEW).unwrap().name,
            "Tenzro Ledger"
        );
    }

    #[test]
    fn the_tenzro_identifier_is_the_chain_the_node_runs() {
        // The identifier names a network. Built from a constant it would
        // name the developer chain on every network, and a payment quoted
        // for `tenzro:1337` on the preview network names the wrong chain.
        assert_eq!(tenzro_caip2(PREVIEW), "tenzro:133801");
        assert_eq!(tenzro_ledger(PREVIEW).caip2, "tenzro:133801");
        assert_eq!(tenzro_ledger(1337).caip2, "tenzro:1337");
        assert_eq!(
            caip2_for_chain_name("tenzro", PREVIEW).as_deref(),
            Some("tenzro:133801")
        );
        assert_eq!(
            cheapest_rail_for("TNZO", 1, DEFAULT_FEE_RATIO, PREVIEW)
                .unwrap()
                .caip2,
            "tenzro:133801"
        );
        assert!(x402_networks(PREVIEW).any(|n| n.caip2 == "tenzro:133801"));
    }

    #[test]
    fn a_node_finds_only_its_own_tenzro_chain() {
        assert_eq!(
            network_by_caip2("tenzro:133801", PREVIEW).unwrap().name,
            "Tenzro Ledger"
        );
        // Another Tenzro chain is another network.
        assert!(network_by_caip2("tenzro:1337", PREVIEW).is_none());
        assert!(network_by_caip2("tenzro:13380", PREVIEW).is_none());
        // Its family and route name do not depend on which chain it is.
        assert_eq!(family_of_caip2("tenzro:1337"), Some(NetworkFamily::Tenzro));
        assert_eq!(chain_name_for_caip2("tenzro:133801"), Some("tenzro"));
    }

    #[test]
    fn only_a_numeric_chain_id_is_a_tenzro_identifier() {
        assert_eq!(tenzro_chain_id_of("tenzro:133801"), Some(PREVIEW));
        for not_one in [
            "tenzro:",
            "tenzro",
            "tenzro:0x20a89",
            "tenzro:+1",
            "tenzro:bd7db8168a4fb615",
            "tenzrox:1",
            "eip155:133801",
        ] {
            assert_eq!(tenzro_chain_id_of(not_one), None, "{not_one}");
        }
    }

    #[test]
    fn a_sub_cent_payment_routes_to_stellar_not_ethereum() {
        // The whole point of the registry. One tenth of a cent (1_000
        // micro-USD) in USDC is viable on Stellar and a loss on Ethereum.
        let rail = cheapest_rail_for("USDC", 1_000, DEFAULT_FEE_RATIO, PREVIEW).unwrap();
        assert_eq!(rail.name, "Stellar");
    }

    #[test]
    fn a_payment_too_small_for_every_rail_returns_none() {
        // Must accumulate against the micro-settlement floor instead of
        // settling at a loss. `None` is the correct answer, not an error.
        assert!(cheapest_rail_for("USDC", 1, DEFAULT_FEE_RATIO, PREVIEW).is_none());
    }

    #[test]
    fn a_large_payment_can_reach_every_rail_carrying_its_asset() {
        // $100 = 100_000_000 micro-USD clears even Ethereum's floor.
        let rail = cheapest_rail_for("USDT", 100_000_000, DEFAULT_FEE_RATIO, PREVIEW).unwrap();
        assert_eq!(
            rail.name, "Ethereum",
            "USDT is only native on Ethereum here"
        );
    }

    #[test]
    fn carries_gates_on_the_ratio_not_merely_on_exceeding_the_fee() {
        let stellar = network_by_caip2("stellar:pubnet", PREVIEW).unwrap();
        // Equal to the fee: the entire payment would be consumed settling it.
        assert!(!stellar.carries(10, DEFAULT_FEE_RATIO));
        // 100x the fee: settlement costs 1%.
        assert!(stellar.carries(1_000, DEFAULT_FEE_RATIO));
    }

    #[test]
    fn a_zero_fee_rail_carries_any_amount() {
        let tenzro = network_by_caip2("tenzro:133801", PREVIEW).unwrap();
        assert!(tenzro.carries(1, DEFAULT_FEE_RATIO));
    }

    #[test]
    fn rlusd_is_reachable_and_lives_on_xrpl() {
        let rail = cheapest_rail_for("RLUSD", 100_000, DEFAULT_FEE_RATIO, PREVIEW).unwrap();
        assert_eq!(rail.name, "XRP Ledger");
    }

    #[test]
    fn pusd_is_reachable_and_lives_on_plume() {
        let rail = cheapest_rail_for("pUSD", 1_000_000, DEFAULT_FEE_RATIO, PREVIEW).unwrap();
        assert_eq!(rail.name, "Plume");
    }

    #[test]
    fn asset_lookup_is_case_insensitive() {
        // Tickers arrive from wire formats that disagree about case; routing
        // must not depend on which one a caller happened to use.
        assert!(cheapest_rail_for("usdc", 1_000, DEFAULT_FEE_RATIO, PREVIEW).is_some());
        assert!(cheapest_rail_for("rlUSD", 100_000, DEFAULT_FEE_RATIO, PREVIEW).is_some());
    }

    #[test]
    fn x402_support_does_not_imply_sub_cent_capability() {
        // These are different properties and conflating them is the mistake
        // this registry exists to prevent. Base speaks x402 fluently and still
        // cannot carry a one-cent payment at 1% overhead — its fee is ~10% of
        // the payment at that size. An agent that picks a rail by "does it
        // support x402" will lose money on every metered call.
        let base = network_by_caip2("eip155:8453", PREVIEW).unwrap();
        assert!(base.x402);
        assert!(!base.carries(10_000, DEFAULT_FEE_RATIO));

        let stellar = network_by_caip2("stellar:pubnet", PREVIEW).unwrap();
        assert!(stellar.x402);
        assert!(stellar.carries(10_000, DEFAULT_FEE_RATIO));
    }

    #[test]
    fn a_sub_cent_tier_exists_and_is_reachable_by_x402() {
        // The metering tier: rails that can carry a tenth of a cent. If this
        // set ever empties, per-token metering has no rail to settle on and
        // the token meter is arithmetic with nowhere to go.
        let tier: Vec<_> = x402_networks(PREVIEW)
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
        let l1 = network_by_caip2("eip155:1", PREVIEW).unwrap();
        for n in x402_networks(PREVIEW) {
            assert!(
                n.fee_floor_micro_usd < l1.fee_floor_micro_usd,
                "{} advertises x402 but is not cheaper than L1",
                n.name
            );
        }
    }

    #[test]
    fn no_network_lists_a_stablecoin_twice() {
        for n in settlement_networks(PREVIEW) {
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

    // ---- the two identifier schemes meeting -----------------------------

    #[test]
    fn every_native_settlement_network_resolves_from_its_chain_name() {
        // The registry and the name mapping must agree, or a mirror resolves
        // to a chain the settlement layer does not recognise.
        for (name, caip2) in [
            ("tenzro", "tenzro:133801"),
            ("stellar", "stellar:pubnet"),
            ("xrpl", "xrpl:0"),
            ("solana", "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"),
            ("base", "eip155:8453"),
            ("plume", "eip155:98866"),
            ("arbitrum", "eip155:42161"),
            ("polygon", "eip155:137"),
            ("ethereum", "eip155:1"),
        ] {
            assert_eq!(
                caip2_for_chain_name(name, PREVIEW).as_deref(),
                Some(caip2),
                "{name}"
            );
            assert!(
                network_by_caip2(caip2, PREVIEW).is_some(),
                "{caip2} maps from a name but is not a settlement network"
            );
        }
    }

    #[test]
    fn plume_resolves_to_mainnet_not_the_legacy_chain() {
        // A short-name lookup against the EIP-155 registry returns 98865,
        // which is Plume *Legacy*. Settling there would be silently wrong.
        assert_eq!(
            caip2_for_chain_name("plume", PREVIEW).as_deref(),
            Some("eip155:98866")
        );
        assert_ne!(
            caip2_for_chain_name("plume", PREVIEW).as_deref(),
            Some("eip155:98865")
        );
    }

    #[test]
    fn name_lookup_is_case_insensitive() {
        for spelling in ["Base", "BASE", "base"] {
            assert_eq!(
                caip2_for_chain_name(spelling, PREVIEW).as_deref(),
                Some("eip155:8453")
            );
        }
    }

    #[test]
    fn an_unmapped_chain_returns_none_rather_than_a_guess() {
        // Cosmos and Move family chains, and chains whose mainnet is absent
        // from the EIP-155 registry, have no verified CAIP-2. They stay
        // reachable by name; inventing an id is the one thing that could
        // route value to the wrong chain.
        for unmapped in [
            "osmosis",
            "juno",
            "aptos",
            "sui",
            "hyperliquid",
            "story",
            "injective",
        ] {
            assert_eq!(caip2_for_chain_name(unmapped, PREVIEW), None, "{unmapped}");
        }
    }

    #[test]
    fn the_mapping_round_trips() {
        for name in [
            "ethereum", "base", "plume", "solana", "stellar", "xrpl", "arbitrum",
        ] {
            let caip2 = caip2_for_chain_name(name, PREVIEW).unwrap();
            assert_eq!(chain_name_for_caip2(&caip2), Some(name), "{name}");
        }
        assert_eq!(chain_name_for_caip2("bitcoin:mainnet"), None);
    }

    #[test]
    fn no_two_chain_names_share_a_caip2_except_declared_aliases() {
        // `bsc` and `binance` are deliberately the same chain. Any other
        // collision means two different chains were given one identifier.
        let names = [
            "ethereum",
            "optimism",
            "gnosis",
            "polygon",
            "monad",
            "sonic",
            "manta",
            "blast",
            "fantom",
            "fraxtal",
            "filecoin",
            "zksync",
            "moonbeam",
            "sei",
            "megaeth",
            "mantle",
            "base",
            "mode",
            "arbitrum",
            "celo",
            "avalanche",
            "linea",
            "berachain",
            "plume",
            "aurora",
            "scroll",
            "solana",
            "stellar",
            "xrpl",
            "tenzro",
        ];
        let mut seen = std::collections::HashMap::new();
        for n in names {
            let id = caip2_for_chain_name(n, PREVIEW).unwrap();
            if let Some(prev) = seen.insert(id.clone(), n) {
                panic!("{id} claimed by both {prev} and {n}");
            }
        }
        assert_eq!(
            caip2_for_chain_name("bsc", PREVIEW),
            caip2_for_chain_name("binance", PREVIEW)
        );
    }
}
