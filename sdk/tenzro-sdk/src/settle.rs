//! Settlement plans: several value legs, one Commit-or-Abort decision, the
//! division fixed by the quote.
//!
//! [`preview_split`] is the network's split engine, computed locally: the
//! protocol fee once on the gross (burn, treasury, insurance), payee-borne
//! network fees, then the split rule's lines by largest remainder. It is
//! checked against the shared vectors in `sdk/fixtures/split`, so a payer
//! sees exactly the division the chain will make. [`PlanBuilder`] assembles
//! the `open` operation a payer signs; [`SettleClient`] builds the
//! transaction types and reads plans, decisions and leg receipts.

use crate::error::{SdkError, SdkResult};
use crate::rpc::RpcClient;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// Rule encoding version.
pub const SPLIT_RULE_VERSION: u16 = 1;
const BPS: u128 = 10_000;

mod dec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum N {
            S(String),
            U(u64),
        }
        match N::deserialize(d)? {
            N::S(s) => s.parse().map_err(serde::de::Error::custom),
            N::U(u) => Ok(u128::from(u)),
        }
    }

    pub mod opt {
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S: Serializer>(v: &Option<u128>, s: S) -> Result<S::Ok, S::Error> {
            match v {
                Some(v) => s.serialize_some(&v.to_string()),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u128>, D::Error> {
            #[derive(Deserialize)]
            struct W(#[serde(with = "super")] u128);
            Ok(Option::<W>::deserialize(d)?.map(|w| w.0))
        }
    }

    pub mod vec {
        use serde::{Deserialize, Deserializer, Serializer, ser::SerializeSeq};

        pub fn serialize<S: Serializer>(v: &[u128], s: S) -> Result<S::Ok, S::Error> {
            let mut seq = s.serialize_seq(Some(v.len()))?;
            for x in v {
                seq.serialize_element(&x.to_string())?;
            }
            seq.end()
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u128>, D::Error> {
            Vec::<String>::deserialize(d)?
                .into_iter()
                .map(|s| s.parse().map_err(serde::de::Error::custom))
                .collect()
        }
    }
}

/// What a split line is paid for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitRole {
    Payee,
    Publisher,
    Licensor,
    Referrer,
    Facilitator,
    Relayer,
    Solver,
    Prover,
    Refund,
}

/// Who a split line pays.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitRecipient {
    /// A 32-byte account, hex.
    Address(String),
    /// The account a registered DID's root key derived.
    DidDerived(String),
    /// Whoever sent the transaction that decided the plan.
    LegSubmitter,
}

/// How much a split line takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitBasis {
    /// Basis points of what the fixed lines leave.
    Bps(u16),
    /// A fixed amount, capped by what remains.
    Fixed(#[serde(with = "dec")] u128),
    /// Everything else; exactly one line per rule.
    Remainder,
}

/// One line of a split rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitLine {
    pub role: SplitRole,
    pub recipient: SplitRecipient,
    pub basis: SplitBasis,
    #[serde(default, with = "dec::opt")]
    pub cap: Option<u128>,
}

/// A split rule, fixed by the quote before value moves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitRule {
    pub version: u16,
    pub lines: Vec<SplitLine>,
}

/// The governed fee parameters the split engine reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeParams {
    pub fee_bps: u16,
    #[serde(with = "dec")]
    pub min_fee: u128,
    pub burn_bps: u16,
    pub insurance_bps: u16,
}

/// How the protocol fee divides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeAllocation {
    #[serde(with = "dec")]
    pub fee: u128,
    #[serde(with = "dec")]
    pub burn: u128,
    #[serde(with = "dec")]
    pub treasury: u128,
    #[serde(with = "dec")]
    pub insurance: u128,
}

/// The full division of one gross amount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allocation {
    #[serde(with = "dec")]
    pub gross: u128,
    pub fee: FeeAllocation,
    #[serde(with = "dec")]
    pub network_fees: u128,
    #[serde(with = "dec")]
    pub net: u128,
    #[serde(with = "dec::vec")]
    pub credits: Vec<u128>,
}

fn bps_of(value: u128, bps: u128) -> u128 {
    value / BPS * bps + value % BPS * bps / BPS
}

fn bad(msg: impl Into<String>) -> SdkError {
    SdkError::InvalidParameter(msg.into())
}

impl SplitRule {
    /// A rule paying everything to one account.
    pub fn sole(role: SplitRole, address_hex: &str) -> Self {
        Self {
            version: SPLIT_RULE_VERSION,
            lines: vec![SplitLine {
                role,
                recipient: SplitRecipient::Address(
                    address_hex.trim_start_matches("0x").to_lowercase(),
                ),
                basis: SplitBasis::Remainder,
                cap: None,
            }],
        }
    }

    /// The checks the chain applies to a rule.
    pub fn validate(&self) -> SdkResult<()> {
        if self.version != SPLIT_RULE_VERSION {
            return Err(bad("unknown split rule version"));
        }
        if self.lines.is_empty() || self.lines.len() > 16 {
            return Err(bad("a split rule has 1 to 16 lines"));
        }
        let mut remainders = 0;
        let mut bps = 0u128;
        for l in &self.lines {
            match l.basis {
                SplitBasis::Remainder if l.cap.is_some() => {
                    return Err(bad("the remainder line has no cap"));
                }
                SplitBasis::Remainder => remainders += 1,
                SplitBasis::Bps(0) => return Err(bad("a basis-point line takes a positive share")),
                SplitBasis::Bps(b) => bps += u128::from(b),
                SplitBasis::Fixed(0) => return Err(bad("a fixed line takes a positive amount")),
                SplitBasis::Fixed(_) => {}
            }
            match &l.recipient {
                SplitRecipient::DidDerived(d) if d.is_empty() || d.len() > 256 => {
                    return Err(bad("a DID recipient is 1 to 256 bytes"));
                }
                SplitRecipient::Address(a)
                    if hex::decode(a.trim_start_matches("0x")).map_or(true, |b| b.len() != 32) =>
                {
                    return Err(bad("an address is 32 bytes of hex"));
                }
                _ => {}
            }
        }
        if remainders != 1 {
            return Err(bad("a split rule has exactly one remainder line"));
        }
        if bps > BPS {
            return Err(bad("basis-point lines sum to at most 10000"));
        }
        Ok(())
    }

    /// The hash a quote signs and a plan binds.
    pub fn hash(&self) -> SdkResult<[u8; 32]> {
        let mut out = b"tenzro/split-rule/v1".to_vec();
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.lines.len().min(255) as u8);
        for l in &self.lines {
            out.push(l.role as u8);
            match &l.recipient {
                SplitRecipient::Address(a) => {
                    out.push(0);
                    out.extend(
                        hex::decode(a.trim_start_matches("0x"))
                            .map_err(|_| bad("address is not hex"))?,
                    );
                }
                SplitRecipient::DidDerived(d) => {
                    out.push(1);
                    out.extend_from_slice(&(d.len() as u16).to_be_bytes());
                    out.extend_from_slice(d.as_bytes());
                }
                SplitRecipient::LegSubmitter => out.push(2),
            }
            match l.basis {
                SplitBasis::Bps(b) => {
                    out.push(0);
                    out.extend_from_slice(&b.to_be_bytes());
                }
                SplitBasis::Fixed(v) => {
                    out.push(1);
                    out.extend_from_slice(&v.to_be_bytes());
                }
                SplitBasis::Remainder => out.push(2),
            }
            match l.cap {
                Some(c) => {
                    out.push(1);
                    out.extend_from_slice(&c.to_be_bytes());
                }
                None => out.push(0),
            }
        }
        Ok(Sha256::digest(&out).into())
    }
}

/// The protocol fee on `gross` and its parts.
pub fn fee_allocation(gross: u128, p: &FeeParams) -> FeeAllocation {
    let fee = bps_of(gross, u128::from(p.fee_bps.min(10_000)))
        .max(p.min_fee)
        .min(gross);
    let burn = bps_of(fee, u128::from(p.burn_bps.min(10_000)));
    let insurance = bps_of(fee - burn, u128::from(p.insurance_bps.min(10_000)));
    FeeAllocation {
        fee,
        burn,
        treasury: fee - burn - insurance,
        insurance,
    }
}

/// The division the chain makes of `gross` under `rule`.
pub fn preview_split(
    gross: u128,
    rule: &SplitRule,
    params: &FeeParams,
    network_fees: u128,
) -> SdkResult<Allocation> {
    rule.validate()?;
    let fee = fee_allocation(gross, params);
    let fees = fee
        .fee
        .checked_add(network_fees)
        .filter(|f| *f <= gross)
        .ok_or_else(|| bad("fees exceed the gross"))?;
    let net = gross - fees;
    let mut credits = vec![0u128; rule.lines.len()];
    let mut left = net;
    for (i, l) in rule.lines.iter().enumerate() {
        if let SplitBasis::Fixed(v) = l.basis {
            let take = v.min(l.cap.unwrap_or(u128::MAX)).min(left);
            credits[i] = take;
            left -= take;
        }
    }
    let pool = left;
    let mut sum_bps = 0u128;
    let mut floors = 0u128;
    let mut fractions = Vec::new();
    for (i, l) in rule.lines.iter().enumerate() {
        if let SplitBasis::Bps(b) = l.basis {
            let b = u128::from(b);
            sum_bps += b;
            credits[i] = bps_of(pool, b);
            floors += credits[i];
            fractions.push((pool % BPS * b % BPS, i));
        }
    }
    fractions.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let mut extra = bps_of(pool, sum_bps) - floors;
    for (_, i) in fractions {
        if extra == 0 {
            break;
        }
        credits[i] += 1;
        extra -= 1;
    }
    for (i, l) in rule.lines.iter().enumerate() {
        if let (SplitBasis::Bps(_), Some(cap)) = (l.basis, l.cap) {
            credits[i] = credits[i].min(cap);
        }
    }
    let paid: u128 = credits.iter().sum();
    let r = rule
        .lines
        .iter()
        .position(|l| l.basis == SplitBasis::Remainder)
        .unwrap_or(0);
    credits[r] = net - paid;
    Ok(Allocation {
        gross,
        fee,
        network_fees,
        net,
        credits,
    })
}

/// The evidence class a leg requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LegClass {
    Native,
    Proven,
    Attested,
}

/// Builds the `open` operation of a settlement plan.
#[derive(Debug, Clone)]
pub struct PlanBuilder {
    nonce: u64,
    quote_digest: [u8; 32],
    split: SplitRule,
    legs: Vec<Value>,
    decide_deadline_ms: u64,
}

impl PlanBuilder {
    /// A plan settling the quote `quote_digest` divided by `split`, decided by
    /// `decide_deadline_ms` (block time, ms).
    pub fn new(
        nonce: u64,
        quote_digest: [u8; 32],
        split: SplitRule,
        decide_deadline_ms: u64,
    ) -> Self {
        Self {
            nonce,
            quote_digest,
            split,
            legs: Vec::new(),
            decide_deadline_ms,
        }
    }

    /// A Tenzro leg paid from the payer's balance, or from its funded escrow.
    pub fn native(mut self, amount: u128, escrow_id: Option<[u8; 32]>) -> Self {
        self.legs.push(json!({
            "kind": { "native_transfer": { "amount": amount.to_string(), "escrow_id": escrow_id.map(hex::encode) } },
            "class_required": LegClass::Native,
        }));
        self
    }

    /// The `open` operation's fields, as `SettleClient::open_plan` and the
    /// CLI's `--plan` file take them.
    pub fn build(&self) -> SdkResult<Value> {
        self.split.validate()?;
        if self.legs.is_empty() || self.legs.len() > 16 {
            return Err(bad("a plan has 1 to 16 legs"));
        }
        Ok(json!({
            "nonce": self.nonce,
            "quote_digest": hex::encode(self.quote_digest),
            "split_hash": hex::encode(self.split.hash()?),
            "split": self.split,
            "legs": self.legs,
            "decide_deadline_ms": self.decide_deadline_ms,
        }))
    }
}

/// Settlement plan client: reads, the live preview, and the transaction
/// types a caller signs with its own key.
#[derive(Clone)]
pub struct SettleClient {
    rpc: Arc<RpcClient>,
}

impl SettleClient {
    pub(crate) fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// The division under the node's live fee parameters.
    pub async fn preview_split(
        &self,
        gross: u128,
        split: &SplitRule,
        network_fees: u128,
    ) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_previewSplit",
                json!({ "gross": gross.to_string(), "split": split, "network_fees": network_fees.to_string() }),
            )
            .await
    }

    /// The `SettlementPlan` transaction type that opens `plan`
    /// ([`PlanBuilder::build`]'s output), for the payer's own signer.
    pub fn open_plan_tx(plan: Value) -> Value {
        json!({ "SettlementPlan": { "op": { "open": plan } } })
    }

    /// The `SettlementPlan` transaction type recording that leg `index`
    /// reached its evidence class, for any signer. `evidence` is a lock leg's
    /// `Locked` event proof, a hash-locked leg's funding proof or, once
    /// funded, its preimage; empty for legs Tenzro reads from its own state.
    /// `network_fee` is the wei the sender paid on the leg's network to carry
    /// the proof; the commit repays it up to the leg's `max_network_fee`.
    pub fn prove_leg_tx(plan_id: &str, index: u8, evidence: &[u8], network_fee: u128) -> Value {
        let mut prove = json!({
            "plan_id": plan_id.trim_start_matches("0x"),
            "index": index,
            "network_fee": network_fee.to_string(),
        });
        if !evidence.is_empty() {
            prove["evidence"] = json!(hex::encode(evidence));
        }
        json!({ "SettlementPlan": { "op": { "prove_leg": prove } } })
    }

    /// The `SettlementPlan` transaction type a rail leg's payee sends to
    /// dispute the leg its attestor confirmed, inside the compensation
    /// window: the payee is paid the leg's reserve and the attestor's bond is
    /// slashed. `evidence` is the payee's proof that the payment did not
    /// arrive.
    pub fn dispute_rail_tx(plan_id: &str, index: u8, evidence: &[u8]) -> Value {
        let dispute = json!({
            "plan_id": plan_id.trim_start_matches("0x"),
            "index": index,
            "evidence": hex::encode(evidence),
        });
        json!({ "SettlementPlan": { "op": { "dispute_rail": dispute } } })
    }

    /// The transaction type that posts (`post`) or withdraws collateral for
    /// netted plans; a withdrawal keeps what the asset's open batch's net
    /// debit needs. `asset` is the token id, 32-byte hex. `agent` is a
    /// delegated agent's signed action (`{ action, signature }`) when the
    /// collateral is the agent's: a post names the asset (`0x` token id,
    /// absent for TNZO), states the amount and, off TNZO, its USD value, and
    /// counts against the asset's limits and the wei limits in its terms; a
    /// withdrawal states none and returns to its wallet.
    pub fn collateral_tx(asset: &str, amount: u128, post: bool, agent: Option<Value>) -> Value {
        let mut body =
            json!({ "asset": asset.trim_start_matches("0x"), "amount": amount.to_string() });
        if let Some(agent) = agent {
            body["agent"] = agent;
        }
        let op = if post {
            json!({ "post_collateral": body })
        } else {
            json!({ "withdraw_collateral": body })
        };
        json!({ "SettlementPlan": { "op": op } })
    }

    /// Check a reconciliation of the settlement lock of route
    /// `(adapter, chain)` against the route's stored one. `entries` are what
    /// the lock recorded since the last reconciliation, in order
    /// (`[{plan_id, leg_id, kind, amount}]`); `checkpoint` is the route's
    /// proof of the lock's checkpoint. Returns `tx_type`, the
    /// `SettlementPlan` transaction to sign and send, with the `count` and
    /// running hash `acc` the checkpoint must prove.
    pub async fn submit_reconciliation(
        &self,
        adapter: &str,
        chain: &str,
        entries: Value,
        checkpoint: &[u8],
    ) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_submitReconciliation",
                json!({ "adapter": adapter, "chain": chain, "entries": entries, "checkpoint": hex::encode(checkpoint) }),
            )
            .await
    }

    /// How far the settlement lock of route `(adapter, chain)` is reconciled,
    /// with its state-proof key.
    pub async fn get_reconciliation(&self, adapter: &str, chain: &str) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_getReconciliation",
                json!({ "adapter": adapter, "chain": chain }),
            )
            .await
    }

    /// The reconciliation mismatches stored for the settlement lock of route
    /// `(adapter, chain)`, each with the account it cost, the loss an
    /// insurance claim can pay and its state-proof key.
    pub async fn list_mismatches(&self, adapter: &str, chain: &str) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_listMismatches",
                json!({ "adapter": adapter, "chain": chain }),
            )
            .await
    }

    /// An asset's netting batch (the latest when `seq` is `None`) with its
    /// state-proof key; with a participant, its collateral, defaults and,
    /// once settled, its gross-to-net statement.
    pub async fn get_netting_batch(
        &self,
        asset: &str,
        seq: Option<u64>,
        participant: Option<&str>,
    ) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_getNettingBatch",
                json!({ "asset": asset, "seq": seq, "participant": participant }),
            )
            .await
    }

    /// A plan, with its state-proof key.
    pub async fn get_plan(&self, plan_id: &str) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_getPlan", json!({ "plan_id": plan_id }))
            .await
    }

    /// A plan's decision, with its state-proof key.
    pub async fn get_decision(&self, plan_id: &str) -> SdkResult<Value> {
        self.rpc
            .call("tenzro_getPlanDecision", json!({ "plan_id": plan_id }))
            .await
    }

    /// One leg's receipt and its recorded evidence (class, evidence digest, a
    /// hash-locked leg's funding txid and, once the plan commits, the
    /// preimage its recipient claims with), each with its state-proof key.
    pub async fn get_leg_receipt(&self, plan_id: &str, index: u8) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_getLegReceipt",
                json!({ "plan_id": plan_id, "index": index }),
            )
            .await
    }

    /// Plans, optionally by payer and status (`open`, `committed`, `aborted`).
    pub async fn list_plans(
        &self,
        payer: Option<&str>,
        status: Option<&str>,
        limit: Option<u64>,
    ) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_listPlans",
                json!({ "payer": payer, "status": status, "limit": limit }),
            )
            .await
    }
}
