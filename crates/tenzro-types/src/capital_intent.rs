//! Capital Intent standard — agentic capital allocation over tokenized assets.
//!
//! See `docs/architecture/capital-intent.md`. This is a **new standard Tenzro
//! introduces** that the market does not have: commerce intents (AP2 Intent
//! Mandate), swap intents (CoW), cross-chain transfer intents (ERC-7683), and
//! general wallet intents (ERC-7521) all exist — but none expresses a
//! *regulated capital-allocation objective* over tokenized securities/assets.
//!
//! A [`CapitalIntent`] is the regulated-capital-markets analog of an AP2 Intent
//! Mandate: it declares a financial **objective** (Acquire/Exit/Rebalance/
//! Hedge/Yield) plus **risk + compliance constraints**, signed by the principal
//! with the shared DID envelope. Solver agents compete to fulfil it; fulfilment
//! runs as a saga (Execute → Verify → Compensate) using ERC-7683/CCIP for
//! settlement legs, AP2 cart/payment mandates for authorization, `erc3643` for
//! compliance gating, Proof-of-Reserve for backing, and ERC-8004 for solver
//! scoring. Tenzro defines and enforces the standard + invariants; the solver
//! agents, venue adapters, and UX are ecosystem.

use serde::{Deserialize, Serialize};

use crate::identity::KycTier;

/// Regulatory regime an intent must be executed under. Gates which investors
/// (by `IdentityClaim`) and venues are eligible at the `erc3643` transfer layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegRegime {
    /// Regulation S — offers made outside the US (most tokenized-equity venues).
    RegS,
    /// Regulation D — US accredited-investor private placements.
    RegD,
    /// EU MiFID II.
    MiFidII,
    /// No regulatory restriction (e.g. a permissionless utility asset).
    Unrestricted,
}

/// Side of a capital leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    Buy,
    Sell,
}

/// A target weight in a rebalance objective.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetWeight {
    /// Tokenized-asset id (matches the `erc3643` / Proof-of-Reserve asset id).
    pub asset_id: String,
    /// Target portfolio weight in basis points (sum across targets should be 10_000).
    pub weight_bps: u16,
}

/// The financial objective an intent expresses. Amounts are in the smallest unit
/// of the quote asset (notional) or the asset itself (quantity).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum Objective {
    /// Acquire up to `target_notional` of `asset_id`, paying at most `max_unit_price`.
    Acquire {
        asset_id: String,
        target_notional: u128,
        max_unit_price: u128,
    },
    /// Sell `quantity` of `asset_id`, accepting at least `min_unit_price`.
    Exit {
        asset_id: String,
        quantity: u128,
        min_unit_price: u128,
    },
    /// Rebalance the principal's holdings toward the given target weights.
    Rebalance { targets: Vec<AssetWeight> },
    /// Open a hedge of `notional` against `asset_id` using `instrument`.
    Hedge {
        asset_id: String,
        notional: u128,
        instrument: String,
    },
    /// Deploy `amount` of `asset_id` into a yield venue at >= `min_apy_bps`.
    Yield {
        asset_id: String,
        amount: u128,
        min_apy_bps: u32,
    },
}

/// Risk / routing constraints the solver must respect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Constraints {
    /// Maximum tolerated slippage in basis points.
    pub max_slippage_bps: u16,
    /// Unix-seconds deadline; the intent expires after this.
    pub deadline_unix: i64,
    /// Allowed execution venues (empty = any). Matched against solver plans.
    #[serde(default)]
    pub allowed_venues: Vec<String>,
    /// Allowed settlement chains (CAIP-2-ish ids, empty = any).
    #[serde(default)]
    pub allowed_chains: Vec<String>,
}

/// Compliance requirements enforced at the `erc3643` transfer layer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceReq {
    /// Regulatory regime the execution must satisfy.
    pub reg_regime: RegRegime,
    /// Minimum KYC tier the principal (and counterparties) must hold.
    pub min_kyc_tier: KycTier,
    /// Whether participation is restricted to accredited investors.
    #[serde(default)]
    pub accredited_only: bool,
}

/// Authorization envelope — the hard capital ceilings. References AP2 mandates
/// and a delegation scope by id (kept decoupled so this crate does not depend on
/// the AP2 / payments types); the node verifies the references at open time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Authorization {
    /// AP2 cart/payment mandate id authorizing spend for the settlement legs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ap2_mandate_ref: Option<String>,
    /// TDIP delegation-scope id bounding the executing agent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation_scope_ref: Option<String>,
    /// Absolute ceiling on total notional this intent may spend (smallest unit).
    pub max_total_notional: u128,
}

/// Settlement requirements for fulfilment proofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReq {
    /// Proof tag the solver must satisfy per leg (e.g. "tee", "zk", "oracle").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    /// Optional preferred settlement route (e.g. a bridge / CCIP lane).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_route: Option<String>,
}

/// A signed capital intent — the regulated-capital-markets analog of an AP2
/// Intent Mandate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapitalIntent {
    /// Caller-chosen unique id (e.g. "ci_abc123").
    pub intent_id: String,
    /// DID of the principal authorizing the intent.
    pub principal_did: String,
    /// The financial objective.
    pub objective: Objective,
    /// Risk / routing constraints.
    pub constraints: Constraints,
    /// Compliance requirements.
    pub compliance: ComplianceReq,
    /// Capital authorization ceilings.
    pub authorization: Authorization,
    /// Settlement / proof requirements.
    pub settlement: SettlementReq,
    /// Principal's DID-envelope signature over [`CapitalIntent::signing_payload`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signature: Vec<u8>,
}

impl CapitalIntent {
    /// Deterministic bytes the principal signs (everything except the signature),
    /// so RPC, MCP, and A2A all verify an identical preimage. Layout is
    /// length-prefixed and field-ordered for cross-language reproducibility.
    pub fn signing_payload(&self) -> Vec<u8> {
        fn push_str(buf: &mut Vec<u8>, s: &str) {
            buf.extend_from_slice(&(s.len() as u32).to_be_bytes());
            buf.extend_from_slice(s.as_bytes());
        }
        let mut buf = Vec::new();
        buf.extend_from_slice(b"tenzro-capital-intent:v1");
        push_str(&mut buf, &self.intent_id);
        push_str(&mut buf, &self.principal_did);
        // Objective discriminant + a stable rendering of its fields.
        push_str(&mut buf, &serde_objective_tag(&self.objective));
        buf.extend_from_slice(&self.authorization.max_total_notional.to_be_bytes());
        buf.extend_from_slice(&self.constraints.deadline_unix.to_be_bytes());
        buf.extend_from_slice(&(self.constraints.max_slippage_bps).to_be_bytes());
        push_str(&mut buf, self.compliance.reg_regime.as_str());
        push_str(&mut buf, self.compliance.min_kyc_tier.as_str());
        buf.push(self.compliance.accredited_only as u8);
        buf
    }
}

impl RegRegime {
    pub fn as_str(&self) -> &'static str {
        match self {
            RegRegime::RegS => "reg_s",
            RegRegime::RegD => "reg_d",
            RegRegime::MiFidII => "mifid_ii",
            RegRegime::Unrestricted => "unrestricted",
        }
    }
}

/// Render an objective's identity (kind + primary asset/amount) into a stable
/// string for the signing payload.
fn serde_objective_tag(o: &Objective) -> String {
    match o {
        Objective::Acquire {
            asset_id,
            target_notional,
            max_unit_price,
        } => {
            format!("acquire:{asset_id}:{target_notional}:{max_unit_price}")
        }
        Objective::Exit {
            asset_id,
            quantity,
            min_unit_price,
        } => {
            format!("exit:{asset_id}:{quantity}:{min_unit_price}")
        }
        Objective::Rebalance { targets } => {
            let mut s = String::from("rebalance");
            for t in targets {
                s.push_str(&format!(":{}={}", t.asset_id, t.weight_bps));
            }
            s
        }
        Objective::Hedge {
            asset_id,
            notional,
            instrument,
        } => {
            format!("hedge:{asset_id}:{notional}:{instrument}")
        }
        Objective::Yield {
            asset_id,
            amount,
            min_apy_bps,
        } => {
            format!("yield:{asset_id}:{amount}:{min_apy_bps}")
        }
    }
}

/// A solver's bid to fulfil an intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapitalQuote {
    pub intent_id: String,
    /// DID of the bidding solver agent (KYA-verified, ERC-8004-ranked).
    pub solver_did: String,
    /// Human/opaque description of the execution plan.
    pub plan: String,
    /// Quoted all-in price (smallest unit) to fulfil the objective.
    pub price: u128,
    /// Estimated time to completion, seconds.
    pub eta_secs: u64,
    pub quoted_at: i64,
}

/// Lifecycle status of a capital intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapitalIntentStatus {
    /// Opened, awaiting solver quotes.
    Open,
    /// At least one quote received.
    Quoting,
    /// A solver was assigned; principal escrow locked.
    Assigned,
    /// Saga execution in flight.
    Executing,
    /// Legs executed; proofs being verified.
    Verifying,
    /// Completed — escrow released, receipt written.
    Settled,
    /// A leg failed; compensation in progress.
    Compensating,
    /// Terminally failed (after compensation).
    Failed,
    /// Deadline passed before fulfilment.
    Expired,
}

impl CapitalIntentStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            CapitalIntentStatus::Settled
                | CapitalIntentStatus::Failed
                | CapitalIntentStatus::Expired
        )
    }
}

/// Status of one settlement leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegStatus {
    Planned,
    Settled,
    Compensated,
    Failed,
}

/// A price quote from a venue, recorded on a leg to prove best execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VenueQuote {
    pub venue: String,
    pub unit_price: u128,
}

/// True if `chosen` is the best price among `quotes` for the side (lowest for a
/// buy, highest for a sell). Empty quotes → unprovable → false.
pub fn best_execution_ok(side: Side, chosen: u128, quotes: &[VenueQuote]) -> bool {
    if quotes.is_empty() {
        return false;
    }
    match side {
        Side::Buy => chosen <= quotes.iter().map(|q| q.unit_price).min().unwrap_or(chosen),
        Side::Sell => chosen >= quotes.iter().map(|q| q.unit_price).max().unwrap_or(chosen),
    }
}

/// One settlement leg executed while fulfilling an intent (a single venue trade
/// + its ERC-7683 settlement + compliance check + backing proof).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapitalLeg {
    pub venue: String,
    pub asset_id: String,
    pub side: Side,
    pub quantity: u128,
    pub unit_price: u128,
    /// ERC-7683 order / settlement reference for this leg, once settled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_ref: Option<String>,
    /// Opaque fulfilment-proof reference (TEE/zk/oracle per `SettlementReq`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proof: Option<String>,
    /// Venue quotes the solver observed at execution (best-execution proof set).
    #[serde(default)]
    pub venue_quotes: Vec<VenueQuote>,
    /// True if `unit_price` is best among `venue_quotes` for `side`.
    #[serde(default)]
    pub best_execution_verified: bool,
    pub status: LegStatus,
    pub updated_at: i64,
}

/// The persisted, on-chain-anchored state machine for a capital intent.
/// Persisted under `CF_SETTLEMENTS` with the `capital_intent:` prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapitalIntentRecord {
    pub intent: CapitalIntent,
    pub status: CapitalIntentStatus,
    /// Assigned solver DID, once chosen.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub solver_did: Option<String>,
    /// Solver bids received.
    #[serde(default)]
    pub quotes: Vec<CapitalQuote>,
    /// Settlement legs executed during fulfilment.
    #[serde(default)]
    pub legs: Vec<CapitalLeg>,
    /// Principal escrow id locked at assignment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub escrow_id: Option<String>,
    /// Notional filled so far (smallest unit).
    #[serde(default)]
    pub filled_notional: u128,
    /// Final receipt hash (hex) once settled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

impl CapitalIntentRecord {
    /// True when every executed leg has settled (and at least one exists).
    pub fn all_legs_settled(&self) -> bool {
        !self.legs.is_empty() && self.legs.iter().all(|l| l.status == LegStatus::Settled)
    }

    /// True when the intent has reached a terminal status.
    pub fn is_terminal(&self) -> bool {
        self.status.is_terminal()
    }
}
