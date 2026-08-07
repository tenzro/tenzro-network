//! Provenance for every resource and network interaction.
//!
//! An identity and its wallet are the two coordinates that make an interaction
//! attributable: the DID says *who or what*, the wallet says *where the value
//! moved*. This module is the record that binds them to the rest of the answer —
//! **what** was used, **when**, **how** it was reached, and **how much** was
//! paid.
//!
//! # Why one record rather than per-surface logs
//!
//! Inference, rental, storage and subscription each used to account for
//! themselves, in their own shape, on their own path. Asking "what did this
//! agent consume across this node last month, and what did it pay" meant
//! joining four different records that shared no key and disagreed on units.
//!
//! [`InteractionProvenance`] is the shape all four now emit. It is emitted on
//! **every** metered interaction, including the ones that move no money on that
//! call — a subscriber's request and a renter's session are attributable
//! whether or not they are chargeable, and an operator who cannot see what a
//! prepaid tenant consumed cannot price the next term.
//!
//! # It records what happened, not what was intended
//!
//! [`InteractionProvenance::amount_charged`] is what actually moved, and
//! [`InteractionProvenance::payees`] is where it actually went — not the rate
//! card that was quoted. A receipt that echoes intent rather than outcome is how
//! a split that silently double-charged went unnoticed: the numbers reported
//! were the ones the config predicted, not the ones the ledger recorded.
//!
//! # Anchored on the Tenzro Ledger
//!
//! [`InteractionProvenance::settlement_tx`] names the Tenzro Ledger transaction
//! that settled the charge. Tenzro is the primary settlement layer; when value
//! arrived over another chain, [`InteractionProvenance::inbound_rail`] records
//! which one it came in on, and the Tenzro transaction is still the anchor. A
//! secondary chain is where a payment *originated*, never where it is finally
//! accounted.

use serde::{Deserialize, Serialize};

use crate::access_tier::{AccessTier, PayerKind};
use crate::economics::{NodeEconomicMode, PayeeRole};
use crate::model::BillableUnits;
use crate::primitives::{Address, Hash, Timestamp};

/// What was consumed in an interaction.
///
/// Coarser than the resource's own identifier, which travels alongside in
/// [`InteractionProvenance::resource_id`]. This is the axis an operator's
/// reporting groups by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InteractionKind {
    /// A model was run — text, vision, audio, video, embeddings, timeseries,
    /// segmentation, detection or generative media. One kind, because every one
    /// of them meters into the same [`BillableUnits`].
    Inference,
    /// Leased capacity was held or used for a billing period.
    Rental,
    /// Bytes were stored or served.
    Storage,
    /// A database was queried or administered.
    Database,
    /// A hosted site or function served a request.
    Hosting,
    /// A confidential-compute session or key-custody operation ran.
    Security,
    /// A marketplace entry was invoked — an agent template, skill or tool.
    Marketplace,
    /// An external network was brokered on the caller's behalf.
    RpcBrokerage,
}

impl InteractionKind {
    /// Every kind, in a stable order.
    pub const ALL: [InteractionKind; 8] = [
        InteractionKind::Inference,
        InteractionKind::Rental,
        InteractionKind::Storage,
        InteractionKind::Database,
        InteractionKind::Hosting,
        InteractionKind::Security,
        InteractionKind::Marketplace,
        InteractionKind::RpcBrokerage,
    ];

    /// Stable wire form.
    pub fn as_str(&self) -> &'static str {
        match self {
            InteractionKind::Inference => "inference",
            InteractionKind::Rental => "rental",
            InteractionKind::Storage => "storage",
            InteractionKind::Database => "database",
            InteractionKind::Hosting => "hosting",
            InteractionKind::Security => "security",
            InteractionKind::Marketplace => "marketplace",
            InteractionKind::RpcBrokerage => "rpc_brokerage",
        }
    }

    /// Parse the wire form; unknown values are refused rather than defaulted.
    pub fn parse(s: &str) -> Option<Self> {
        InteractionKind::ALL
            .into_iter()
            .find(|k| k.as_str().eq_ignore_ascii_case(s))
    }
}

impl std::fmt::Display for InteractionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Which rail the value arrived on.
///
/// Tenzro Ledger is the settlement layer; everything else is where a payment
/// *started*. Recorded so a treasury reconciliation can tell native volume from
/// bridged volume without inferring it from the asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "rail", rename_all = "snake_case")]
pub enum InboundRail {
    /// Paid natively in TNZO on the Tenzro Ledger.
    Tenzro,
    /// Arrived over HTTP 402 under an x402 scheme.
    X402 {
        /// The scheme that carried it — `tenzro-hybrid`, `upto`,
        /// `batch-settlement`, and so on.
        scheme: String,
        /// CAIP-2 identifier of the chain the payment was authorized against.
        chain: String,
    },
    /// Arrived over a secondary chain through a bridge.
    Bridged {
        /// CAIP-2 identifier of the originating chain.
        chain: String,
        /// CAIP-19 identifier of the asset as it arrived.
        asset: String,
    },
    /// Drawn against a mandate an agent held — the payer committed under a
    /// standing authorization rather than paying interactively.
    Mandate {
        /// The protocol the mandate was written in — `ap2-payment`, `x402`,
        /// and so on.
        protocol: String,
        /// Hash of the mandate that authorized the charge.
        mandate_hash: String,
    },
}

impl InboundRail {
    /// Whether the value originated on the Tenzro Ledger rather than a
    /// secondary chain.
    pub fn is_native(&self) -> bool {
        matches!(self, InboundRail::Tenzro)
    }
}

/// One party's share of a charge, as it actually settled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PayeeRecord {
    /// Which role this party was paid in.
    pub role: PayeeRole,
    /// The account the value landed in.
    pub address: Address,
    /// How much landed, in the settled asset's smallest unit.
    #[serde(with = "crate::primitives::u128_serde")]
    pub amount: u128,
    /// The share in basis points, carried so a receipt can be audited without
    /// re-deriving it from a policy that may since have changed.
    pub bps: u32,
}

/// A ledger other than Tenzro that this charge was additionally recorded on.
///
/// Tenzro Ledger is where a charge settles. A secondary layer is where the
/// settlement is *mirrored* because a counterparty's system is the system of
/// record for their side — a Canton participant holding an enterprise
/// obligation, an EVM or SVM chain holding a token leg. Recording it here keeps
/// the mirror auditable without letting it be mistaken for the settlement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecondarySettlement {
    /// Which layer — `canton`, `evm`, `svm`, or a bridge adapter's name.
    pub layer: String,
    /// CAIP-2 identifier of the chain, where the layer has one. Empty for
    /// Canton, which is identified by its synchronizer rather than a CAIP-2 id.
    pub chain: String,
    /// The identifier that layer assigned — a transaction hash, a Canton
    /// contract id, a bridge message id.
    pub reference: String,
}

/// The full attributable record of one interaction.
///
/// Emitted on every metered interaction, chargeable or not.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractionProvenance {
    /// Stable identifier for this interaction. Shared with the usage record and
    /// the settlement receipt so the three join without a heuristic.
    pub interaction_id: String,

    // ---- who ------------------------------------------------------------
    /// DID of the party that consumed the resource.
    pub payer_did: String,
    /// Whether that party is a human, a machine or an agent. Each holds its own
    /// identity and wallet, so each is attributable on its own terms.
    pub payer_kind: PayerKind,
    /// The wallet the charge was drawn from. Together with `payer_did` this is
    /// the provenance pair — identity says who, wallet says where value moved.
    pub payer_wallet: Address,
    /// When the payer acts under delegation, the DID it acts for. `None` for a
    /// principal acting on its own behalf.
    pub on_behalf_of: Option<String>,

    // ---- what -----------------------------------------------------------
    /// What class of resource was consumed.
    pub kind: InteractionKind,
    /// The resource's own identifier — a model id, a lease id, a database id, a
    /// skill id. Empty when the kind alone identifies it.
    pub resource_id: String,
    /// Work performed, across every modality. Zero on interactions that consume
    /// no metered units, such as opening a lease.
    pub units: BillableUnits,

    // ---- when -----------------------------------------------------------
    /// When the interaction was recorded.
    pub occurred_at: Timestamp,

    // ---- how ------------------------------------------------------------
    /// The relationship under which the resource was reached.
    pub tier: AccessTier,
    /// Digest of the credential presented, never the credential. `None` for an
    /// on-demand user, who presents payment rather than a key.
    pub credential_digest: Option<String>,
    /// The economic mode the serving node was in, so a receipt explains its own
    /// split without a lookup against a policy that may since have changed.
    pub mode: NodeEconomicMode,
    /// Which rail the value arrived on.
    pub inbound_rail: InboundRail,

    // ---- how much -------------------------------------------------------
    /// What actually moved, in the settled asset's smallest unit. Zero on a
    /// metered-but-not-charged interaction — a subscriber's request, or a
    /// renter's use of capacity already paid for.
    #[serde(with = "crate::primitives::u128_serde")]
    pub amount_charged: u128,
    /// CAIP-19 identifier of the asset that settled.
    pub settled_asset: String,
    /// Where the value actually went. Empty when nothing was charged.
    pub payees: Vec<PayeeRecord>,
    /// The Tenzro Ledger transaction that settled the charge. `None` when
    /// nothing was charged, or when the charge accrued into a channel rather
    /// than settling on its own.
    pub settlement_tx: Option<Hash>,
    /// Secondary settlement layers this charge was additionally mirrored to.
    ///
    /// Every charge settles on the Tenzro Ledger. Some are *also* recorded on a
    /// ledger a counterparty requires — a Canton participant for an enterprise
    /// obligation, an EVM or SVM chain for a token leg, a bridge for a
    /// cross-chain transfer. Those are mirrors of a settlement that already
    /// happened, never the settlement itself, which is why this is a list and
    /// `settlement_tx` is not.
    #[serde(default)]
    pub secondary_settlements: Vec<SecondarySettlement>,
}

impl InteractionProvenance {
    /// Whether this interaction moved value.
    ///
    /// A metered interaction that charged nothing is still recorded — an
    /// operator who cannot see what a prepaid tenant consumed cannot price the
    /// next term.
    pub fn is_chargeable(&self) -> bool {
        self.amount_charged > 0
    }

    /// Total across the payee legs.
    pub fn paid_out(&self) -> u128 {
        self.payees.iter().map(|p| p.amount).sum()
    }

    /// Whether the payee legs account for exactly what was charged.
    ///
    /// The invariant that catches both leaks and double-charges: value that
    /// neither arrives nor is accounted for shows up months later as a balance
    /// nobody can reconcile, and legs that sum *above* the charge mean some
    /// party was paid out of another's share.
    pub fn is_conserved(&self) -> bool {
        self.paid_out() == self.amount_charged
    }

    /// The amount that reached `role`, or zero if that role was not paid.
    pub fn amount_for(&self, role: PayeeRole) -> u128 {
        self.payees
            .iter()
            .filter(|p| p.role == role)
            .map(|p| p.amount)
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provenance(amount: u128, payees: Vec<PayeeRecord>) -> InteractionProvenance {
        InteractionProvenance {
            interaction_id: "int_1".into(),
            payer_did: "did:tenzro:machine:agent".into(),
            payer_kind: PayerKind::Agent,
            payer_wallet: Address::default(),
            on_behalf_of: Some("did:tenzro:human:alice".into()),
            kind: InteractionKind::Inference,
            resource_id: "qwen3-27b".into(),
            units: BillableUnits::tokens(1_000, 250),
            occurred_at: Timestamp::new(1_700_000_000_000),
            tier: AccessTier::User,
            credential_digest: None,
            mode: NodeEconomicMode::PublicDelegated,
            inbound_rail: InboundRail::Tenzro,
            amount_charged: amount,
            settled_asset: "tenzro:1337/native:tnzo".into(),
            payees,
            settlement_tx: None,
            secondary_settlements: Vec::new(),
        }
    }

    fn payee(role: PayeeRole, amount: u128, bps: u32) -> PayeeRecord {
        PayeeRecord {
            role,
            address: Address::default(),
            amount,
            bps,
        }
    }

    /// The invariant that catches leaks in one direction and double-charges in
    /// the other.
    #[test]
    fn conservation_holds_only_when_the_legs_equal_the_charge() {
        let exact = provenance(
            1_000,
            vec![
                payee(PayeeRole::Operator, 800, 8_000),
                payee(PayeeRole::RpcProvider, 100, 1_000),
                payee(PayeeRole::Treasury, 100, 1_000),
            ],
        );
        assert!(exact.is_conserved());
        assert_eq!(exact.paid_out(), 1_000);

        // Legs sum low — value stranded with no owner.
        let leak = provenance(
            1_000,
            vec![
                payee(PayeeRole::Operator, 800, 8_000),
                payee(PayeeRole::Treasury, 100, 1_000),
            ],
        );
        assert!(!leak.is_conserved());

        // Legs sum high — someone was paid out of another party's share.
        let overpay = provenance(
            1_000,
            vec![
                payee(PayeeRole::Operator, 900, 8_000),
                payee(PayeeRole::RpcProvider, 100, 1_000),
                payee(PayeeRole::Treasury, 100, 1_000),
            ],
        );
        assert!(!overpay.is_conserved());
    }

    /// A subscriber's call moves no money and is still attributable — an
    /// operator who cannot see prepaid consumption cannot price the next term.
    #[test]
    fn a_metered_but_uncharged_interaction_is_still_recorded() {
        let mut p = provenance(0, vec![]);
        p.tier = AccessTier::Subscriber;
        p.credential_digest = Some("sha256:abcd".into());
        assert!(!p.is_chargeable());
        // Conservation is trivially true, and the units are still recorded.
        assert!(p.is_conserved());
        assert_eq!(p.units.total_tokens(), 1_250);
    }

    #[test]
    fn a_role_that_was_not_paid_reads_as_zero() {
        let p = provenance(
            1_000,
            vec![
                payee(PayeeRole::Operator, 900, 9_000),
                payee(PayeeRole::Treasury, 100, 1_000),
            ],
        );
        assert_eq!(p.amount_for(PayeeRole::Operator), 900);
        assert_eq!(p.amount_for(PayeeRole::RpcProvider), 0);
    }

    /// Tenzro is the settlement layer; another chain is only where a payment
    /// started.
    #[test]
    fn a_secondary_chain_is_recorded_as_an_origin_not_a_settlement() {
        assert!(InboundRail::Tenzro.is_native());
        let bridged = InboundRail::Bridged {
            chain: "eip155:8453".into(),
            asset: "eip155:8453/erc20:0x833589f".into(),
        };
        assert!(!bridged.is_native());
        let x402 = InboundRail::X402 {
            scheme: "upto".into(),
            chain: "eip155:8453".into(),
        };
        assert!(!x402.is_native());
    }

    /// A charge settles once, on Tenzro. A Canton contract or an EVM hash
    /// alongside it is a mirror of that settlement, not a second one — so it
    /// must not change what was charged or what the legs total.
    #[test]
    fn secondary_layers_mirror_a_settlement_they_do_not_add_one() {
        let mut p = provenance(1_000, vec![payee(PayeeRole::Operator, 1_000, 10_000)]);
        p.settlement_tx = Some(Hash::default());
        p.secondary_settlements = vec![
            SecondarySettlement {
                layer: "canton".into(),
                chain: String::new(),
                reference: "00a1b2c3".into(),
            },
            SecondarySettlement {
                layer: "evm".into(),
                chain: "eip155:8453".into(),
                reference: "0xdeadbeef".into(),
            },
        ];
        assert!(p.is_conserved(), "a mirror must not alter the accounting");
        assert_eq!(p.amount_charged, 1_000);
        assert_eq!(p.paid_out(), 1_000);
        assert!(p.settlement_tx.is_some(), "Tenzro is still the anchor");
    }

    #[test]
    fn the_record_survives_serialization() {
        let p = provenance(1_000, vec![payee(PayeeRole::Operator, 1_000, 10_000)]);
        let json = serde_json::to_string(&p).expect("serializes");
        let back: InteractionProvenance = serde_json::from_str(&json).expect("parses");
        assert_eq!(back, p);
    }

    #[test]
    fn wire_forms_round_trip() {
        for kind in InteractionKind::ALL {
            assert_eq!(InteractionKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(InteractionKind::parse("llm"), None);
    }
}
