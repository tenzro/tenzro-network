//! Settlement plans: several value legs, one Commit-or-Abort decision.
//!
//! A plan is opened by its payer. Its Tenzro legs are paid into the plan's
//! vault when it opens (from the payer's balance or from an escrow it
//! funded); a leg on another network is evidence the plan waits for. The
//! transaction that brings the last leg to its required class commits the
//! plan: the protocol fee is charged once on the plan's Tenzro value and the
//! rest is divided by the split rule the quote fixed, both by the one pure
//! function in `tenzro_types::split`. A plan whose legs are all on Tenzro
//! commits in the transaction that opens it. A plan still open at its
//! deadline aborts in block execution and its vault returns to the payer.
//! A hash-locked leg's payer also escrows a TNZO premium: an abort that
//! finds that leg funded and every other leg in, the preimage withheld,
//! pays it by the split rule; every other outcome returns it.
//! The decision is kept in the plan, its fixed-size commitment (what remote
//! locks prove) is written at `decision:<plan_id>`, and every leg's outcome
//! at `plr:<leg_id>`.

use sha2::{Digest, Sha256};
use tenzro_bridge::route::ibc_core::{PacketOutcome, PacketState, packet_outcome};
use tenzro_settlement::escrow::EscrowStatus;
use tenzro_types::bridge_route::BridgeRouteAdapter;
use tenzro_types::network::NetworkRole;
use tenzro_types::primitives::Address;
use tenzro_types::settlement::{
    AtomicityTier, LegClass, LegKind, LegReceipt, LegRelay, PlanDecision, PlanOp, PlanStatus,
    ReleaseConditions, SettlementPlan, decision_commitment, leg_id, plan_id,
};
use tenzro_types::split::{Allocation, FeeParams, SplitRecipient, SplitRule};

use super::super::funding::{move_balance, read_json, refuse, write_json};
use super::super::{
    NativeExecutor, SYSTEM_ADDRESS, derive_vault_address, deterministic_now_ms, economy,
    escrow_storage_key, network_param, role_bonded, write_escrow_record,
};
use crate::error::{Result, VmError};
use crate::gas::GasMeter;
use crate::traits::VmState;
use crate::types::{ExecutionResult, Log, StateChange, VmTransaction};

/// Selector of `SettlementPlan`.
pub const SELECTOR_SETTLEMENT_PLAN: [u8; 4] = [0x01, 0x00, 0x00, 0x86];

/// Base gas of a plan operation.
pub const GAS_SETTLEMENT_PLAN: u64 = 60_000;

/// Gas per leg a plan operation evaluates.
pub const GAS_PER_PLAN_LEG: u64 = 15_000;

/// Topic of every plan log; the second topic names the event.
pub const SETTLEMENT_PLAN_TOPIC: &[u8] = b"SettlementPlan";

/// Governed: the longest a plan may stay undecided, ms.
pub const ESCAPE_HORIZON_PARAM: &str = "settlement.escape_horizon_ms";

/// Genesis escape horizon: 14 days.
pub const DEFAULT_ESCAPE_HORIZON_MS: u64 = 14 * 24 * 60 * 60 * 1000;

/// Governed: the least griefing premium a hash-locked leg escrows, basis
/// points of the plan's Tenzro value.
pub const GRIEFING_PREMIUM_PARAM: &str = "settlement.griefing_premium_bps";

/// Genesis griefing premium: 1%.
pub const DEFAULT_GRIEFING_PREMIUM_BPS: u64 = 100;

/// Most overdue plans block execution aborts per block; the rest wait for
/// the next block.
pub const MAX_ABORTS_PER_BLOCK: usize = 64;

const PLAN_VAULT_DOMAIN: &[u8] = b"tenzro/plan/vault/v1";
const DUE_CURSOR_KEY: &str = "plan_due_cursor";
const MINUTE_MS: u64 = 60_000;

/// Most deadline minutes block execution walks per block when catching up.
const MAX_DUE_MINUTES_PER_BLOCK: u64 = 1_440;

/// Gas of `op`.
pub fn settlement_plan_gas(op: &PlanOp) -> u64 {
    let legs = match op {
        PlanOp::Open { legs, .. } => legs.len() as u64,
        PlanOp::ProveLeg { .. } | PlanOp::DisputeRail { .. } => 1,
        PlanOp::PostCollateral { .. } | PlanOp::WithdrawCollateral { .. } => 0,
        PlanOp::Reconcile { entries, .. } => entries.len() as u64,
    };
    let evidence = match op {
        PlanOp::ProveLeg { evidence, .. }
        | PlanOp::DisputeRail { evidence, .. }
        | PlanOp::Reconcile {
            checkpoint: evidence,
            ..
        } => GAS_PER_EVIDENCE_BYTE * evidence.len() as u64,
        PlanOp::Open { .. } | PlanOp::PostCollateral { .. } | PlanOp::WithdrawCollateral { .. } => {
            0
        }
    };
    GAS_SETTLEMENT_PLAN + GAS_PER_PLAN_LEG * legs + evidence
}

/// Gas per byte of leg evidence a proof verification reads.
pub const GAS_PER_EVIDENCE_BYTE: u64 = 16;

fn plan_key(plan_id: &[u8; 32]) -> String {
    format!("plan:{}", hex::encode(plan_id))
}

fn decision_key(plan_id: &[u8; 32]) -> String {
    format!("decision:{}", hex::encode(plan_id))
}

fn receipt_key(leg_id: &[u8; 32]) -> String {
    format!("plr:{}", hex::encode(leg_id))
}

fn evidence_key(leg_id: &[u8; 32]) -> String {
    format!("ple:{}", hex::encode(leg_id))
}

/// What proved a lock or hash-locked leg, at `ple:<leg_id>`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct LegEvidence {
    /// The class the evidence reached.
    pub class: LegClass,
    /// SHA-256 of the evidence (the lock-event proof or the funding proof).
    #[serde(with = "tenzro_types::agent_audit::hex32")]
    pub digest: [u8; 32],
    /// A hash-locked leg's funding transaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub funding_txid: Option<String>,
    /// A hash-locked leg's preimage, written by the transaction that commits
    /// the plan; the recipient reads it here to claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preimage: Option<String>,
}

/// The evidence recorded for a leg.
pub fn read_leg_evidence(state: &dyn VmState, leg_id: &[u8; 32]) -> Option<LegEvidence> {
    read_json(state, &evidence_key(leg_id))
}

/// Governed: how long after a plan's deadline a remote lock must still hold
/// its leg, ms, so a proven decision can be relayed before the payer may
/// reclaim.
pub const RELEASE_MARGIN_PARAM: &str = "settlement.release_margin_ms";
/// Genesis release margin: 24 hours.
pub const DEFAULT_RELEASE_MARGIN_MS: u64 = 24 * 60 * 60 * 1000;

/// Governed: how long after a plan commits its rail legs may be confirmed
/// or disputed, ms.
pub const COMPENSATION_WINDOW_PARAM: &str = "settlement.compensation_window_ms";
/// Genesis compensation window: 72 hours, which covers a credit transfer's
/// return cycle.
pub const DEFAULT_COMPENSATION_WINDOW_MS: u64 = 72 * 60 * 60 * 1000;
/// Governed: share of an attestor's bond a compensated rail leg slashes, bps.
pub const ATTESTOR_SLASH_PARAM: &str = "settlement.attestor_slash_bps";
/// Genesis attestor slash: 10%.
pub const DEFAULT_ATTESTOR_SLASH_BPS: u64 = 1_000;

fn rail_key(leg_id: &[u8; 32]) -> String {
    format!("plrail:{}", hex::encode(leg_id))
}

/// How a rail leg ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum RailOutcome {
    /// Confirmed and undisputed: the reserve went back to the payer.
    Settled,
    /// Unconfirmed when the window closed, or disputed: the reserve paid the
    /// payee and the attestor was slashed.
    Compensated,
}

/// A committed plan's rail leg, at `plrail:<leg_id>`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct RailWindow {
    /// Block time the window closes, ms.
    closes_at_ms: u64,
    /// SHA-256 of the confirmation, once confirmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confirmed: Option<String>,
    /// SHA-256 of the payee's dispute evidence, if it disputed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    disputed: Option<String>,
    /// How it ended, once it has.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    outcome: Option<RailOutcome>,
}

fn read_rail(state: &dyn VmState, leg_id: &[u8; 32]) -> Option<RailWindow> {
    read_json(state, &rail_key(leg_id))
}

/// The rail legs of `plan`: index, payee, attestor and reserve.
fn rail_legs(plan: &SettlementPlan) -> Vec<(usize, Address, Option<Address>, u128)> {
    plan.legs
        .iter()
        .enumerate()
        .filter_map(|(i, l)| match &l.kind {
            LegKind::RailInstruction {
                payee,
                attestor,
                reserve,
                ..
            } => Some((i, *payee, *attestor, *reserve)),
            _ => None,
        })
        .collect()
}

fn is_rail(plan: &SettlementPlan, index: usize) -> bool {
    matches!(plan.legs[index].kind, LegKind::RailInstruction { .. })
}

/// Verify `evidence` for leg `index` of `plan` and record it. A lock leg
/// takes its `Locked` event proof. A hash-locked leg first takes the SPV
/// proof of its funding, then its preimage, which is accepted only by the
/// transaction that commits the plan (the caller refuses otherwise).
/// Returns whether this evidence is the preimage.
fn record_evidence(
    state: &mut dyn VmState,
    ctx: Ctx,
    plan: &SettlementPlan,
    index: u8,
    evidence: &[u8],
    changes: &mut Vec<StateChange>,
) -> Result<bool> {
    let id = leg_id(&plan.plan_id, index);
    let margin = network_param(state, RELEASE_MARGIN_PARAM);
    let hold_until = plan.decide_deadline_ms.saturating_add(margin);
    let epoch = economy::read_current_epoch(state);
    match &plan.legs[usize::from(index)].kind {
        LegKind::RemoteLock {
            adapter,
            chain,
            asset,
            amount,
            recipient,
        } => {
            let mut view =
                super::super::bridge::VmRouteState::new(state, ctx.chain_id, ctx.now_ms, epoch);
            let (record, proven, digest) = super::super::bridge::route_framework()
                .prove_lock(&mut view, *adapter, &chain.to_ascii_lowercase(), evidence)
                .map_err(|e| refuse(format!("lock proof refused by the route: {e}")))?;
            let tenzro_bridge::route::receipt_proof::LockRecord::Locked(event) = record else {
                return Err(refuse(
                    "a leg is proven by its lock's Locked event, not a checkpoint",
                ));
            };
            changes.extend(view.into_changes());
            if event.plan_id != plan.plan_id || event.leg_id != id || event.index != index {
                return Err(refuse("the lock is for another plan or leg"));
            }
            if event.asset != *asset || event.amount != *amount || event.recipient != *recipient {
                return Err(refuse(
                    "the lock does not hold the leg's asset, amount and recipient",
                ));
            }
            if event.escape_at_ms < hold_until {
                return Err(refuse(format!(
                    "the lock lets its payer reclaim before {hold_until} ms, the plan's deadline plus the release margin"
                )));
            }
            let class = if proven {
                LegClass::Proven
            } else {
                LegClass::Attested
            };
            let rec = LegEvidence {
                class,
                digest,
                funding_txid: None,
                preimage: None,
            };
            write_json(state, &evidence_key(&id), &rec, changes)?;
            Ok(false)
        }
        LegKind::HashLocked {
            chain,
            hash,
            recipient_key,
            refund_key,
            refund_after_secs,
            amount_sats,
            ..
        } => {
            if let Some(mut rec) = read_leg_evidence(state, &id) {
                if rec.preimage.is_some() {
                    return Err(refuse("the preimage is already revealed"));
                }
                if evidence.len() != 32 || <[u8; 32]>::from(Sha256::digest(evidence)) != *hash {
                    return Err(refuse("the preimage does not hash to the leg's hash"));
                }
                rec.preimage = Some(hex::encode(evidence));
                write_json(state, &evidence_key(&id), &rec, changes)?;
                return Ok(true);
            }
            if u64::from(*refund_after_secs).saturating_mul(1000) < hold_until {
                return Err(refuse(format!(
                    "the script's refund opens before {hold_until} ms, the plan's deadline plus the release margin"
                )));
            }
            let script = tenzro_types::settlement::htlc_output_script(
                &tenzro_types::settlement::htlc_witness_script(
                    hash,
                    recipient_key,
                    refund_key,
                    *refund_after_secs,
                ),
            );
            let view =
                super::super::bridge::VmRouteState::new(state, ctx.chain_id, ctx.now_ms, epoch);
            let paid = super::super::bridge::route_framework()
                .prove_bitcoin_payment(
                    &view,
                    BridgeRouteAdapter::Deposit,
                    &chain.to_ascii_lowercase(),
                    evidence,
                )
                .map_err(|e| refuse(format!("funding proof refused by the route: {e}")))?;
            if !paid
                .tx
                .outputs
                .iter()
                .any(|o| o.script == script && o.value == *amount_sats)
            {
                return Err(refuse(
                    "the transaction pays no output of the leg's amount to the leg's script",
                ));
            }
            let txid = hex::encode(paid.txid);
            // One funding output backs one leg.
            let used = format!("ple_fund:{txid}");
            if state
                .get_storage(&SYSTEM_ADDRESS, used.as_bytes())
                .is_some()
            {
                return Err(refuse("the funding transaction already backs a leg"));
            }
            write_json(state, &used, &hex::encode(id), changes)?;
            let rec = LegEvidence {
                class: LegClass::Proven,
                digest: Sha256::digest(evidence).into(),
                funding_txid: Some(txid),
                preimage: None,
            };
            write_json(state, &evidence_key(&id), &rec, changes)?;
            Ok(false)
        }
        _ => Err(refuse(
            "this leg takes no evidence; it is read from Tenzro's state",
        )),
    }
}

/// The account a plan's Tenzro value waits in until its decision.
pub fn plan_vault_address(plan_id: &[u8; 32]) -> Address {
    let mut h = Sha256::new();
    h.update(PLAN_VAULT_DOMAIN);
    h.update(plan_id);
    Address::new(h.finalize().into())
}

/// The plan at `plan:<plan_id>`.
pub fn read_plan(state: &dyn VmState, plan_id: &[u8; 32]) -> Option<SettlementPlan> {
    read_json(state, &plan_key(plan_id))
}

/// The plan's decision, once taken.
pub fn read_decision(state: &dyn VmState, plan_id: &[u8; 32]) -> Option<PlanDecision> {
    read_plan(state, plan_id).and_then(|p| p.decision)
}

/// The decision commitment at `decision:<plan_id>`.
pub fn read_decision_commitment(state: &dyn VmState, plan_id: &[u8; 32]) -> Option<Vec<u8>> {
    state
        .get_storage(&SYSTEM_ADDRESS, decision_key(plan_id).as_bytes())
        .filter(|b| !b.is_empty())
}

/// The receipt at `plr:<leg_id>`.
pub fn read_leg_receipt(state: &dyn VmState, leg_id: &[u8; 32]) -> Option<LegReceipt> {
    read_leg_receipt_commitment(state, leg_id).and_then(|b| LegReceipt::decode(&b))
}

/// The fixed-size record at `plr:<leg_id>` ([`LegReceipt::encode`]), what a
/// contract on another chain proves.
pub fn read_leg_receipt_commitment(state: &dyn VmState, leg_id: &[u8; 32]) -> Option<Vec<u8>> {
    state
        .get_storage(&SYSTEM_ADDRESS, receipt_key(leg_id).as_bytes())
        .filter(|b| !b.is_empty())
}

fn write_leg_receipt(
    state: &mut dyn VmState,
    receipt: &LegReceipt,
    changes: &mut Vec<StateChange>,
) {
    let key = receipt_key(&receipt.leg_id);
    let bytes = receipt.encode().to_vec();
    let prior = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), bytes.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        prior,
        Some(bytes),
    ));
}

/// What a commit repays each leg's relayer: the fee it stated, capped at the
/// leg's `max_network_fee`, by leg index.
fn repaid_network_fees(plan: &SettlementPlan) -> Vec<Option<(Address, u128)>> {
    (0..plan.legs.len())
        .map(|i| {
            let relay = plan.relays.get(i).copied().flatten()?;
            Some((
                relay.relayer,
                relay.realised.min(plan.legs[i].max_network_fee),
            ))
        })
        .collect()
}

/// What one leg's evidence shows right now.
enum LegState {
    /// It reached this class.
    Reached(LegClass),
    /// Not yet.
    Pending,
    /// It can no longer reach its class.
    Failed(String),
}

/// What block a plan is evaluated in.
#[derive(Clone, Copy)]
struct Ctx {
    chain_id: u64,
    now_ms: i64,
}

fn evaluate(state: &mut dyn VmState, ctx: Ctx, plan: &SettlementPlan, index: usize) -> LegState {
    let leg = &plan.legs[index];
    match &leg.kind {
        LegKind::IbcTransfer { chain, sequence } => {
            match ibc_packet(state, ctx, chain, *sequence) {
                Err(e) => LegState::Failed(e),
                Ok(p) if p.sender != plan.opened_by.0 => {
                    LegState::Failed("the packet was not sent by the plan's payer".into())
                }
                Ok(p) => match p.state {
                    PacketState::Delivered => LegState::Reached(LegClass::Proven),
                    PacketState::Refunded => {
                        LegState::Failed("the packet timed out or was refused".into())
                    }
                    PacketState::Pending => LegState::Pending,
                },
            }
        }
        LegKind::NativeTransfer { .. } | LegKind::Netted { .. } => {
            LegState::Reached(LegClass::Native)
        }
        // Instructed once the plan commits, so confirmed only after it.
        LegKind::RailInstruction { .. } => LegState::Pending,
        // Reached once its lock is proven.
        LegKind::RemoteLock { .. } => {
            match read_leg_evidence(state, &leg_id(&plan.plan_id, index as u8)) {
                Some(e) => LegState::Reached(e.class),
                None => LegState::Pending,
            }
        }
        // Reached once funded and its preimage revealed.
        LegKind::HashLocked { .. } => {
            match read_leg_evidence(state, &leg_id(&plan.plan_id, index as u8)) {
                Some(e) if e.preimage.is_some() => LegState::Reached(e.class),
                _ => LegState::Pending,
            }
        }
    }
}

/// Outbound packet `sequence` on the governed IBC route to `chain`.
fn ibc_packet(
    state: &mut dyn VmState,
    ctx: Ctx,
    chain: &str,
    sequence: u64,
) -> std::result::Result<PacketOutcome, String> {
    let chain = chain.to_ascii_lowercase();
    let route = super::super::read_bridge_route(state, BridgeRouteAdapter::Ibc, &chain)
        .ok_or_else(|| format!("no IBC route to {chain}"))?;
    let epoch = economy::read_current_epoch(state);
    let view = super::super::bridge::VmRouteState::new(state, ctx.chain_id, ctx.now_ms, epoch);
    packet_outcome(&view, &route, sequence).map_err(|e| e.to_string())
}

/// Hold an agent's plan to its terms before anything moves: the action
/// states the plan's whole value, wei, every leg counted (a Tenzro leg at
/// its amount, any other at its USD price at the rate in force) plus the
/// TNZO the plan escrows beside them (a griefing premium, rail reserves),
/// and the USD value of the legs off Tenzro, naming no asset; a netted
/// plan's action names its one asset (none for TNZO) and states its gross in
/// it (and, off TNZO, that gross's USD value), so the asset's own limits in
/// the terms count it beside the wei limits. Every
/// chain a leg settles on and every party the plan pays is within the
/// terms' scope.
fn check_agent_plan(
    state: &dyn VmState,
    auth: &tenzro_types::agent_terms::AgentAuthorization,
    split: &SplitRule,
    legs: &[tenzro_types::settlement::Leg],
    paid: &[Address],
    payer: &Address,
    now_ms: u64,
) -> Result<super::super::remote_grant::RemoteUse> {
    let action = &auth.action;
    let overflow = || refuse("the legs overflow");
    let netted: Vec<([u8; 32], u128)> = legs
        .iter()
        .filter_map(|l| match &l.kind {
            LegKind::Netted { asset, amount } => Some((*asset, *amount)),
            _ => None,
        })
        .collect();
    if let Some((asset, _)) = netted.first() {
        // The action names the asset and states the gross in it; a carried
        // asset also states the positive USD value its legs give it, which
        // the wei limits count while the asset's own limits count the gross.
        let gross = netted
            .iter()
            .try_fold(0u128, |t, (_, a)| t.checked_add(*a))
            .ok_or_else(overflow)?;
        let (named, usd) = if *asset == crate::token_ledger::tnzo_id() {
            (None, 0)
        } else {
            if legs.iter().any(|l| l.usd_e6 == 0) {
                return Err(refuse(
                    "an agent's netted leg in a carried asset states its USD value",
                ));
            }
            let usd = legs
                .iter()
                .try_fold(0u64, |t, l| t.checked_add(l.usd_e6))
                .ok_or_else(overflow)?;
            (Some(format!("0x{}", hex::encode(asset))), usd)
        };
        if action.asset != named || action.amount != gross || action.usd_e6 != usd {
            return Err(refuse(format!(
                "the agent's action names the netted plan's asset {} and states its gross: {gross}, {usd} USD micro-units",
                named.as_deref().unwrap_or("TNZO")
            )));
        }
        check_split_fee(state, &action.agent_did, split, gross)?;
        return check_agent_scope(state, action, legs, paid, payer, now_ms);
    }
    let mut tnzo = 0u128;
    let mut off_tenzro_usd = 0u64;
    for leg in legs {
        match &leg.kind {
            LegKind::NativeTransfer { amount, .. } => {
                tnzo = tnzo.checked_add(*amount).ok_or_else(overflow)?
            }
            other => {
                off_tenzro_usd = off_tenzro_usd
                    .checked_add(leg.usd_e6)
                    .ok_or_else(overflow)?;
                let escrowed = match other {
                    LegKind::HashLocked { premium, .. } => *premium,
                    LegKind::RailInstruction { reserve, .. } => *reserve,
                    _ => 0,
                };
                tnzo = tnzo.checked_add(escrowed).ok_or_else(overflow)?;
            }
        }
    }
    let total = tnzo
        .checked_add(super::usd_e6_to_wei(state, off_tenzro_usd))
        .ok_or_else(overflow)?;
    if action.asset.is_some() || action.amount != total || action.usd_e6 != off_tenzro_usd {
        return Err(refuse(format!(
            "the agent's action names no asset (the plan moves TNZO on Tenzro) and states the plan's whole value: {total} wei, {off_tenzro_usd} USD micro-units off Tenzro"
        )));
    }
    // The rule divides the TNZO the plan's Tenzro legs fund.
    let funded = legs
        .iter()
        .filter_map(|l| match &l.kind {
            LegKind::NativeTransfer { amount, .. } => Some(*amount),
            _ => None,
        })
        .try_fold(0u128, |t, a| t.checked_add(a))
        .ok_or_else(overflow)?;
    check_split_fee(state, &action.agent_did, split, funded)?;
    check_agent_scope(state, action, legs, paid, payer, now_ms)
}

/// Hold the facilitator and relayer lines of the rule an agent's plan opens
/// with to the share of `divided` its Terms allow.
fn check_split_fee(
    state: &dyn VmState,
    agent_did: &str,
    split: &SplitRule,
    divided: u128,
) -> Result<()> {
    let Some(max_bps) = super::super::agent_terms::read_agent_terms(state, agent_did)
        .and_then(|s| s.terms.delegation_scope.max_split_fee_bps)
    else {
        return Ok(());
    };
    split
        .check_intermediary_share(divided, max_bps)
        .map_err(|e| refuse(e.to_string()))
}

/// Hold an agent's collateral move to its terms and return its wallet, the
/// collateral's owner. A post names its asset (none for TNZO) and states its
/// amount (and a carried asset's USD value), so the most the agent's net
/// debit can reach counts against the asset's limits and the wei limits; a
/// withdrawal returns to the same wallet and states no value.
#[allow(clippy::too_many_arguments)]
fn collateral_agent(
    state: &mut dyn VmState,
    chain_id: u64,
    auth: &tenzro_types::agent_terms::AgentAuthorization,
    asset: &[u8; 32],
    value: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<Address> {
    let action = &auth.action;
    // A post names a carried asset and states its amount and positive USD
    // value, so the asset's limits and the wei limits both count it; TNZO is
    // named by no asset and counts at its amount. A withdrawal states none.
    let tnzo = value == 0 || *asset == crate::token_ledger::tnzo_id();
    let named = (!tnzo).then(|| format!("0x{}", hex::encode(asset)));
    if action.asset != named || action.amount != value || (action.usd_e6 == 0) != tnzo {
        return Err(refuse(if value == 0 {
            "the agent's withdrawal action states no value".to_string()
        } else {
            format!(
                "the agent's action names the collateral's asset {} and states its amount {value}, with its USD value off TNZO",
                named.as_deref().unwrap_or("TNZO")
            )
        }));
    }
    let (c, l) =
        super::super::agent_terms::act_for_plan(state, chain_id, action, &auth.signature, now_ms)?;
    changes.extend(c);
    logs.extend(l);
    Ok(Address::new(tenzro_types::agent_terms::agent_wallet(
        &action.agent_did,
    )))
}

/// Every chain a leg settles on and every party the plan pays is within the
/// agent's terms, and so is every asset a leg locks on another chain: each
/// is named by the CAIP-19 id its route gives it and held to that asset's
/// daily limit in the terms. Returns what the legs move per asset, for the
/// caller to count once the action is admitted.
fn check_agent_scope(
    state: &dyn VmState,
    action: &tenzro_types::agent_terms::AgentAction,
    legs: &[tenzro_types::settlement::Leg],
    paid: &[Address],
    payer: &Address,
    now_ms: u64,
) -> Result<super::super::remote_grant::RemoteUse> {
    let stored =
        super::super::agent_terms::read_agent_terms(state, &action.agent_did).ok_or_else(|| {
            refuse(format!(
                "{} has no approved terms on chain",
                action.agent_did
            ))
        })?;
    let scope = |chain: &str, counterparty: String| {
        let mut view = action.clone();
        view.chain = chain.to_string();
        view.counterparty = counterparty;
        tenzro_types::agent_terms::check_scope(&stored.terms, &view, now_ms)
            .map_err(|d| refuse(format!("outside the agent's approved terms: {d}")))
    };
    for leg in legs {
        match &leg.kind {
            LegKind::IbcTransfer { chain, .. } | LegKind::HashLocked { chain, .. } => {
                scope(chain, String::new())?
            }
            LegKind::RemoteLock {
                chain, recipient, ..
            } => scope(chain, hex::encode(recipient))?,
            LegKind::RailInstruction { payee, .. } => {
                scope(&action.chain, hex::encode(payee.as_bytes()))?
            }
            LegKind::NativeTransfer { .. } | LegKind::Netted { .. } => {}
        }
    }
    for to in paid.iter().filter(|a| *a != payer) {
        scope(&action.chain, hex::encode(to.as_bytes()))?;
    }
    let mut uses = Vec::new();
    for leg in legs {
        if let Some((caip19, amount)) = leg_remote_asset(state, &leg.kind)? {
            super::super::remote_grant::add_remote_use(&mut uses, &caip19, amount)
                .map_err(refuse)?;
        }
    }
    super::super::remote_grant::check_remote_use(state, &stored, &action.agent_did, &uses, now_ms)
        .map_err(refuse)?;
    Ok(uses)
}

/// The CAIP-19 id and amount of what a leg locks on another chain, by its
/// route's asset ids: a remote lock's asset, a hash-locked leg's coin. None
/// for a leg that locks nothing there (TNZO and carried assets move on
/// Tenzro, an IBC packet locks on Tenzro, a rail is no
/// chain). A locked asset the route names no id for is refused.
fn leg_remote_asset(state: &dyn VmState, kind: &LegKind) -> Result<Option<(String, u128)>> {
    let (adapter, chain, asset, amount) = match kind {
        LegKind::RemoteLock {
            adapter,
            chain,
            asset,
            amount,
            ..
        } => (*adapter, chain, *asset, *amount),
        LegKind::HashLocked {
            chain, amount_sats, ..
        } => (
            BridgeRouteAdapter::Deposit,
            chain,
            [0u8; 32],
            u128::from(*amount_sats),
        ),
        _ => return Ok(None),
    };
    let chain = chain.to_ascii_lowercase();
    let route = super::super::read_bridge_route(state, adapter, &chain)
        .ok_or_else(|| refuse(format!("no {} route to {chain}", adapter.as_str())))?;
    let caip19 = route.caip19_of(&asset).ok_or_else(|| {
        refuse(format!(
            "the {chain} route names no CAIP-19 id for the asset 0x{}",
            hex::encode(asset)
        ))
    })?;
    Ok(Some((caip19.to_string(), amount)))
}

/// Resolve each split line's recipient. `submitter` is the account whose
/// transaction takes the decision.
pub(super) fn recipients(
    state: &dyn VmState,
    rule: &SplitRule,
    submitter: &Address,
) -> Result<Vec<Address>> {
    rule.lines
        .iter()
        .map(|line| match &line.recipient {
            SplitRecipient::Address(a) => Ok(*a),
            SplitRecipient::LegSubmitter => Ok(*submitter),
            SplitRecipient::DidDerived(did) => resolve_did(state, did),
        })
        .collect()
}

/// The account a DID's root key derived, from its consensus identity
/// record; a revoked identity is paid nothing.
fn resolve_did(state: &dyn VmState, did: &str) -> Result<Address> {
    if state
        .get_storage(&SYSTEM_ADDRESS, &super::super::identity_revocation_key(did))
        .is_some_and(|b| !b.is_empty())
    {
        return Err(refuse(format!("split recipient {did} is revoked")));
    }
    let record: tenzro_types::identity::RegisterIdentityPayload = state
        .get_storage(&SYSTEM_ADDRESS, &super::super::identity_storage_key(did))
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .ok_or_else(|| refuse(format!("split recipient {did} is not registered")))?;
    Ok(record.wallet_address)
}

/// A committed plan seen by one of its parties through a leg's receipt at
/// `plr:<leg_id>`: the plan id and what the commit credited `account`. The
/// payer is a party credited nothing. `None` when the leg's plan did not
/// commit or `account` took no part in it.
pub(in crate::native) fn settled_party(
    state: &dyn VmState,
    leg_id: &[u8; 32],
    account: &Address,
) -> Option<([u8; 32], u128)> {
    let receipt = read_leg_receipt(state, leg_id).filter(|r| r.committed)?;
    let plan = read_plan(state, &receipt.plan_id)?;
    let decision = plan.decision.as_ref()?;
    let credited = match &decision.allocation {
        Some(a) => decision
            .recipients
            .iter()
            .zip(&a.credits)
            .filter(|(r, _)| *r == account)
            .fold(0u128, |t, (_, c)| t.saturating_add(*c)),
        None => 0,
    };
    (plan.opened_by == *account || credited > 0).then_some((receipt.plan_id, credited))
}

/// Block time, ms, at which plan `plan_id` was decided; `None` while it is
/// unknown or undecided.
pub(in crate::native) fn decided_at_ms(state: &dyn VmState, plan_id: &[u8; 32]) -> Option<u64> {
    read_plan(state, plan_id)?
        .decision
        .as_ref()
        .map(|d| d.decided_at_ms)
}

/// What a committed plan cost outside the trade: its payer, the agent that
/// opened it from its wallet if one did, and the TNZO protocol fee its
/// commit took (burned, and paid to the treasury and the insurance pool). A
/// plan netted in another asset paid no TNZO fee. `None` when the plan is
/// unknown or undecided.
pub(in crate::native) fn settled_outsider_cost(
    state: &dyn VmState,
    plan_id: &[u8; 32],
) -> Option<(Address, Option<String>, u128)> {
    let plan = read_plan(state, plan_id)?;
    let decision = plan.decision.as_ref()?;
    let fee = match super::netting::netted_value(&plan) {
        Some((asset, _)) if asset != crate::token_ledger::tnzo_id() => 0,
        _ => decision.allocation.as_ref().map_or(0, |a| a.fee.fee),
    };
    Some((plan.opened_by, plan.agent_did.clone(), fee))
}

/// The most undecided plans one agent holds at a time, so withdrawing its
/// authority aborts them all in one transaction.
pub const MAX_OPEN_PLANS_PER_AGENT: usize = 32;

fn agent_plans_key(did: &str) -> String {
    format!("agent_plans:{did}")
}

fn read_agent_plans(state: &dyn VmState, did: &str) -> Vec<String> {
    read_json(state, &agent_plans_key(did)).unwrap_or_default()
}

fn write_agent_plans(
    state: &mut dyn VmState,
    did: &str,
    open: &[String],
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    write_json(state, &agent_plans_key(did), &open, changes).map(|_| ())
}

/// Abort every undecided plan `did` opened, refunding its wallet: the agent
/// was revoked, paused or quarantined, so nothing it started may still
/// commit. A counterparty's funded hash lock is still paid its premium.
pub(in crate::native) fn abort_agent_plans(
    state: &mut dyn VmState,
    did: &str,
    now_ms: u64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let ctx = Ctx {
        chain_id: 0,
        now_ms: now_ms as i64,
    };
    let decider = Address::new([0u8; 32]);
    for hex_id in read_agent_plans(state, did) {
        let plan = hex::decode(&hex_id)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .and_then(|id| read_plan(state, &id));
        if let Some(mut plan) = plan.filter(|p| p.status == PlanStatus::Open) {
            abort(
                state,
                ctx,
                &mut plan,
                &decider,
                "the agent's authority was withdrawn".into(),
                now_ms,
                changes,
                logs,
            )?;
        }
    }
    Ok(())
}

fn due_key(minute: u64) -> String {
    format!("plan_due:{minute:016x}")
}

fn read_due(state: &dyn VmState, minute: u64) -> Vec<String> {
    read_json(state, &due_key(minute)).unwrap_or_default()
}

fn write_due(
    state: &mut dyn VmState,
    minute: u64,
    due: &[String],
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    write_json(state, &due_key(minute), &due, changes).map(|_| ())
}

fn plan_log(event: &str, data: &serde_json::Value) -> Result<Log> {
    let bytes =
        serde_json::to_vec(data).map_err(|e| VmError::Internal(format!("encode plan log: {e}")))?;
    Ok(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![SETTLEMENT_PLAN_TOPIC.to_vec(), event.as_bytes().to_vec()],
        bytes,
    ))
}

/// Draw `amount` from the payer's funded escrow into the plan vault.
fn draw_escrow(
    state: &mut dyn VmState,
    payer: &Address,
    escrow_id: &[u8; 32],
    amount: u128,
    to: &[u8],
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let key = escrow_storage_key(&hex::encode(escrow_id));
    let old = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    let mut escrow = super::read_escrow(state, escrow_id)
        .ok_or_else(|| refuse(format!("escrow {} does not exist", hex::encode(escrow_id))))?;
    if escrow.payer != *payer {
        return Err(refuse("only the escrow's payer pays a plan from it"));
    }
    if escrow.status != EscrowStatus::Funded {
        return Err(refuse("the escrow is not funded"));
    }
    if now_ms > escrow.expires_at.0 {
        return Err(refuse(
            "the escrow has expired; its remainder belongs to the payer",
        ));
    }
    if matches!(escrow.release_conditions, ReleaseConditions::Stream { .. }) {
        return Err(refuse("a streaming escrow pays its payee by the stream"));
    }
    let remaining = escrow.amount - escrow.claimed;
    if amount > remaining {
        return Err(refuse(format!(
            "the leg draws {amount}, the escrow holds {remaining}"
        )));
    }
    let vault = derive_vault_address(escrow_id);
    move_balance(state, vault.as_bytes(), to, amount, changes)?;
    escrow.claimed += amount;
    if escrow.claimed == escrow.amount {
        escrow.status = EscrowStatus::Released;
    }
    changes.push(write_escrow_record(state, &key, old, &escrow)?);
    Ok(())
}

/// Commit `plan`: divide its vault by the split rule after the protocol fee,
/// write the decision and the leg receipts. Returns the burned fee part.
fn commit(
    state: &mut dyn VmState,
    ctx: Ctx,
    plan: &mut SettlementPlan,
    decided_by: &Address,
    now_ms: u64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<u128> {
    let vault = plan_vault_address(&plan.plan_id);
    let paid_to = recipients(state, &plan.split, decided_by)?;
    let repaid = repaid_network_fees(plan);
    let network_fees = repaid
        .iter()
        .flatten()
        .try_fold(0u128, |t, (_, f)| t.checked_add(*f));
    let network_fees = network_fees.ok_or_else(|| refuse("the network fees overflow"))?;
    let mut netted_burn = 0u128;
    let allocation = if super::netting::netted_value(plan).is_some() {
        let (alloc, burned) = super::netting::commit(state, plan, &paid_to, now_ms, changes)?;
        netted_burn = burned;
        Some(alloc)
    } else if plan.funded == 0 {
        None
    } else {
        let params = economy::fee_params(state);
        let alloc = tenzro_types::split::apply(plan.funded, &plan.split, &params, network_fees)
            .map_err(|e| refuse(e.to_string()))?;
        if !alloc.conserves() {
            return Err(VmError::Internal(
                "plan division does not conserve its value".into(),
            ));
        }
        let held = state.get_balance(vault.as_bytes());
        if held < plan.funded {
            return Err(VmError::Internal(format!(
                "plan vault holds {held}, the plan funded {}",
                plan.funded
            )));
        }
        // The vault pays every line; the fee's treasury and insurance parts
        // are credited by the fee step and its burn part leaves supply.
        for (to, amount) in paid_to.iter().zip(&alloc.credits) {
            if *amount > 0 {
                move_balance(state, vault.as_bytes(), to.as_bytes(), *amount, changes)?;
            }
        }
        // Each relayer is repaid the network fee it carried a proof for.
        for (relayer, fee) in repaid.iter().flatten() {
            if *fee > 0 {
                move_balance(state, vault.as_bytes(), relayer.as_bytes(), *fee, changes)?;
            }
        }
        let rest = state.get_balance(vault.as_bytes());
        state.set_balance(vault.as_bytes(), rest - alloc.fee.fee);
        changes.push(StateChange::new(
            vault.as_bytes().to_vec(),
            b"balance".to_vec(),
            Some(rest.to_le_bytes().to_vec()),
            Some((rest - alloc.fee.fee).to_le_bytes().to_vec()),
        ));
        // One settlement, recorded against the line that takes the remainder
        // (the primary payee).
        let primary = plan
            .split
            .lines
            .iter()
            .position(|l| l.basis == tenzro_types::split::SplitBasis::Remainder)
            .map(|i| paid_to[i])
            .unwrap_or(plan.opened_by);
        // The plan's payees report their provider work; the creators the
        // payer attributed it to earn here.
        economy::record_fee(
            state,
            plan.opened_by.as_bytes(),
            primary.as_bytes(),
            plan.funded,
            &alloc.fee,
            0,
            &economy::Earning {
                provider: None,
                payer_agent: plan.agent_did.clone(),
                attribution: plan.attribution.clone(),
                network_share_paid: false,
            },
            changes,
        )?;
        economy::count_settlement(state, 1, changes)?;
        Some(alloc)
    };
    let burned = if super::netting::netted_value(plan).is_some() {
        netted_burn
    } else {
        allocation.as_ref().map_or(0, |a| a.fee.burn)
    };
    plan.status = PlanStatus::Committed;
    let decision = PlanDecision {
        plan_id: plan.plan_id,
        commit: true,
        decided_at_ms: now_ms,
        decided_by: *decided_by,
        reason: None,
        allocation,
        recipients: paid_to,
        premium_paid: None,
    };
    // The preimage landed with this commit: the premium goes back.
    if let Some((_, premium)) = plan.griefing_premium() {
        move_balance(
            state,
            vault.as_bytes(),
            plan.opened_by.as_bytes(),
            premium,
            changes,
        )?;
    }
    finish(state, ctx, plan, &decision, changes, logs)?;
    // Each rail leg is instructed now; its window opens with the commit and
    // the plan is due again when it closes. Its reserve stays in the vault.
    let rails = rail_legs(plan);
    if !rails.is_empty() {
        let window = network_param(state, COMPENSATION_WINDOW_PARAM);
        let closes_at_ms = now_ms.saturating_add(window);
        for (i, ..) in rails {
            let w = RailWindow {
                closes_at_ms,
                confirmed: None,
                disputed: None,
                outcome: None,
            };
            write_json(
                state,
                &rail_key(&leg_id(&plan.plan_id, i as u8)),
                &w,
                changes,
            )?;
        }
        let minute = closes_at_ms / MINUTE_MS;
        let mut due = read_due(state, minute);
        due.push(hex::encode(plan.plan_id));
        write_due(state, minute, &due, changes)?;
    }
    Ok(burned)
}

/// The premium's division and its recipients, if an abort of `plan` pays
/// it: its hash-locked leg was funded, every other leg reached its class,
/// and the preimage was never revealed. No proof completed anything, so a
/// line paid to the submitter goes to the transaction's sender, or in block
/// execution to the first line that names an account.
fn forfeited_premium(
    state: &dyn VmState,
    plan: &SettlementPlan,
    decided_by: &Address,
) -> Result<Option<(Allocation, Vec<Address>)>> {
    let Some((h, premium)) = plan.griefing_premium() else {
        return Ok(None);
    };
    let funded = read_leg_evidence(state, &leg_id(&plan.plan_id, h as u8))
        .is_some_and(|e| e.funding_txid.is_some() && e.preimage.is_none());
    // Rail legs are instructed only after a commit, so none is ever in.
    let others_in = plan
        .achieved
        .iter()
        .enumerate()
        .all(|(i, a)| i == h || a.is_some() || is_rail(plan, i));
    if !funded || !others_in {
        return Ok(None);
    }
    let mut to = recipients(state, &plan.split, decided_by)?;
    if *decided_by == Address::new([0u8; 32]) {
        let Some(named) = plan
            .split
            .lines
            .iter()
            .position(|l| l.recipient != SplitRecipient::LegSubmitter)
        else {
            return Ok(None);
        };
        let named = to[named];
        for (i, l) in plan.split.lines.iter().enumerate() {
            if l.recipient == SplitRecipient::LegSubmitter {
                to[i] = named;
            }
        }
    }
    // Compensation, not a settlement: the plan's one fee is its commit's.
    let no_fee = FeeParams {
        fee_bps: 0,
        min_fee: 0,
        burn_bps: 0,
        insurance_bps: 0,
    };
    let alloc = tenzro_types::split::apply(premium, &plan.split, &no_fee, 0)
        .map_err(|e| refuse(e.to_string()))?;
    if !alloc.conserves() || alloc.fee.fee != 0 {
        return Err(VmError::Internal(
            "premium division does not conserve its value".into(),
        ));
    }
    Ok(Some((alloc, to)))
}

/// Abort `plan`: its vault returns to the payer in full, except a griefing
/// premium the abort pays (see [`forfeited_premium`]).
fn abort(
    state: &mut dyn VmState,
    ctx: Ctx,
    plan: &mut SettlementPlan,
    decided_by: &Address,
    reason: String,
    now_ms: u64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    if plan.funded > 0 {
        let vault = plan_vault_address(&plan.plan_id);
        move_balance(
            state,
            vault.as_bytes(),
            plan.opened_by.as_bytes(),
            plan.funded,
            changes,
        )?;
    }
    let mut premium_paid = None;
    let mut paid_to = Vec::new();
    if let Some((_, premium)) = plan.griefing_premium() {
        let vault = plan_vault_address(&plan.plan_id);
        match forfeited_premium(state, plan, decided_by)? {
            Some((alloc, to)) => {
                for (a, amount) in to.iter().zip(&alloc.credits) {
                    if *amount > 0 {
                        move_balance(state, vault.as_bytes(), a.as_bytes(), *amount, changes)?;
                    }
                }
                premium_paid = Some(alloc);
                paid_to = to;
            }
            None => move_balance(
                state,
                vault.as_bytes(),
                plan.opened_by.as_bytes(),
                premium,
                changes,
            )?,
        }
    }
    // No rail leg is instructed for an aborted plan: its reserve goes back.
    for (_, _, _, reserve) in rail_legs(plan) {
        let vault = plan_vault_address(&plan.plan_id);
        move_balance(
            state,
            vault.as_bytes(),
            plan.opened_by.as_bytes(),
            reserve,
            changes,
        )?;
    }
    plan.status = PlanStatus::Aborted;
    let decision = PlanDecision {
        plan_id: plan.plan_id,
        commit: false,
        decided_at_ms: now_ms,
        decided_by: *decided_by,
        reason: Some(reason),
        allocation: None,
        recipients: paid_to,
        premium_paid,
    };
    finish(state, ctx, plan, &decision, changes, logs)
}

/// Write the decision, the plan and every leg's receipt; drop the plan from
/// the due list.
fn finish(
    state: &mut dyn VmState,
    ctx: Ctx,
    plan: &SettlementPlan,
    decision: &PlanDecision,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let key = decision_key(&plan.plan_id);
    let commitment =
        decision_commitment(&plan.plan_id, decision.commit, decision.decided_at_ms).to_vec();
    let prior = state.get_storage(&SYSTEM_ADDRESS, key.as_bytes());
    state.set_storage(&SYSTEM_ADDRESS, key.as_bytes(), commitment.clone());
    changes.push(StateChange::new(
        SYSTEM_ADDRESS.to_vec(),
        key.into_bytes(),
        prior,
        Some(commitment),
    ));
    let mut plan = plan.clone();
    plan.decision = Some(decision.clone());
    write_json(state, &plan_key(&plan.plan_id), &plan, changes)?;
    let repaid = repaid_network_fees(&plan);
    for (i, leg) in plan.legs.iter().enumerate() {
        let id = leg_id(&plan.plan_id, i as u8);
        let (class_achieved, proof_digest) = match plan.achieved.get(i).copied().flatten() {
            Some(c) => (Some(c), proof_digest_of(state, ctx, &leg.kind, &id)),
            None => (None, None),
        };
        let receipt = LegReceipt {
            plan_id: plan.plan_id,
            leg_id: id,
            index: i as u8,
            committed: decision.commit,
            class_achieved,
            amount: leg_value(state, ctx, &leg.kind),
            proof_digest,
            decided_at_ms: decision.decided_at_ms,
            compensation: None,
            network_fee: if decision.commit {
                repaid[i].map_or(0, |(_, f)| f)
            } else {
                0
            },
            relayer: plan.relays.get(i).copied().flatten().map(|r| r.relayer),
        };
        write_leg_receipt(state, &receipt, changes);
    }
    let hex_id = hex::encode(plan.plan_id);
    let minute = plan.decide_deadline_ms / MINUTE_MS;
    let mut due = read_due(state, minute);
    if let Some(at) = due.iter().position(|id| *id == hex_id) {
        due.remove(at);
        write_due(state, minute, &due, changes)?;
    }
    if let Some(did) = &plan.agent_did {
        let mut open = read_agent_plans(state, did);
        if let Some(at) = open.iter().position(|id| *id == hex_id) {
            open.remove(at);
            write_agent_plans(state, did, &open, changes)?;
        }
    }
    logs.push(plan_log(
        if decision.commit {
            "committed"
        } else {
            "aborted"
        },
        &serde_json::json!({
            "plan_id": hex_id,
            "commit": decision.commit,
            "reason": decision.reason,
        }),
    )?);
    Ok(())
}

fn proof_digest_of(
    state: &mut dyn VmState,
    ctx: Ctx,
    kind: &LegKind,
    id: &[u8; 32],
) -> Option<[u8; 32]> {
    match kind {
        LegKind::NativeTransfer { .. } | LegKind::Netted { .. } => None,
        LegKind::RemoteLock { .. } | LegKind::HashLocked { .. } => {
            read_leg_evidence(state, id).map(|e| e.digest)
        }
        LegKind::RailInstruction { .. } => read_rail(state, id)
            .and_then(|r| r.confirmed)
            .and_then(|d| tenzro_types::agent_audit::parse_digest(&d).ok()),
        LegKind::IbcTransfer { chain, sequence } => ibc_packet(state, ctx, chain, *sequence)
            .ok()
            .map(|p| p.commitment),
    }
}

fn leg_value(state: &mut dyn VmState, ctx: Ctx, kind: &LegKind) -> u128 {
    match kind {
        LegKind::NativeTransfer { amount, .. } | LegKind::Netted { amount, .. } => *amount,
        LegKind::RemoteLock { amount, .. } => *amount,
        LegKind::HashLocked { amount_sats, .. } => u128::from(*amount_sats),
        LegKind::RailInstruction { amount_minor, .. } => *amount_minor,
        LegKind::IbcTransfer { chain, sequence } => {
            ibc_packet(state, ctx, chain, *sequence).map_or(0, |p| p.amount)
        }
    }
}

/// End rail leg `index` of committed `plan`. `Settled` returns its reserve
/// to the payer; `Compensated` pays it to the payee and slashes the
/// attestor, if the leg names one, into the insurance pool through the one
/// slash path. Rewrites the leg's receipt.
fn end_rail(
    state: &mut dyn VmState,
    plan: &SettlementPlan,
    index: usize,
    outcome: RailOutcome,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let LegKind::RailInstruction {
        payee,
        attestor,
        reserve,
        ..
    } = &plan.legs[index].kind
    else {
        return Err(VmError::Internal(
            "only a rail leg ends by its window".into(),
        ));
    };
    let id = leg_id(&plan.plan_id, index as u8);
    let mut window = read_rail(state, &id)
        .ok_or_else(|| VmError::Internal("a committed rail leg has no window".into()))?;
    let vault = plan_vault_address(&plan.plan_id);
    let to = match outcome {
        RailOutcome::Settled => plan.opened_by,
        RailOutcome::Compensated => *payee,
    };
    move_balance(state, vault.as_bytes(), to.as_bytes(), *reserve, changes)?;
    let mut slashed = 0u128;
    if let (RailOutcome::Compensated, Some(a)) = (outcome, attestor) {
        let bps = network_param(state, ATTESTOR_SLASH_PARAM).min(10_000) as u16;
        slashed = super::super::staking::slash_to_insurance(
            state,
            a.as_bytes(),
            super::super::staking::SlashedStake::Role(NetworkRole::Attestor),
            bps,
            changes,
        )?;
    }
    window.outcome = Some(outcome);
    write_json(state, &rail_key(&id), &window, changes)?;
    if let Some(mut receipt) = read_leg_receipt(state, &id) {
        let settled = outcome == RailOutcome::Settled;
        receipt.class_achieved = settled.then_some(LegClass::Attested);
        receipt.proof_digest = window
            .confirmed
            .as_deref()
            .and_then(|d| tenzro_types::agent_audit::parse_digest(d).ok());
        receipt.compensation = (!settled).then_some(*reserve);
        write_leg_receipt(state, &receipt, changes);
    }
    logs.push(plan_log(
        match outcome {
            RailOutcome::Settled => "rail_settled",
            RailOutcome::Compensated => "rail_compensated",
        },
        &serde_json::json!({
            "plan_id": hex::encode(plan.plan_id),
            "index": index,
            "slashed": slashed.to_string(),
        }),
    )?);
    Ok(())
}

/// Record the confirmation of rail leg `index` of committed `plan`, sent by
/// its attestor or, when it names none, its payee. A payee's own
/// confirmation ends the leg at once; an attestor's stands until the window
/// closes, open to the payee's dispute.
fn confirm_rail(
    state: &mut dyn VmState,
    plan: &mut SettlementPlan,
    index: usize,
    sender: &Address,
    evidence: &[u8],
    now_ms: u64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    if plan.status != PlanStatus::Committed {
        return Err(refuse("a rail leg is confirmed once its plan commits"));
    }
    let LegKind::RailInstruction {
        payee, attestor, ..
    } = plan.legs[index].kind.clone()
    else {
        return Err(VmError::Internal(
            "only a rail leg is confirmed after the commit".into(),
        ));
    };
    if *sender != attestor.unwrap_or(payee) {
        return Err(refuse(
            "only the leg's attestor, or its payee when it names none, confirms it",
        ));
    }
    if attestor.is_some() && !role_bonded(state, sender.as_bytes(), NetworkRole::Attestor) {
        return Err(refuse(
            "the attestor's bond is below the attestor role's stake",
        ));
    }
    if evidence.is_empty() {
        return Err(refuse(
            "a confirmation carries the rail's settlement confirmation",
        ));
    }
    let id = leg_id(&plan.plan_id, index as u8);
    let mut window = read_rail(state, &id)
        .ok_or_else(|| VmError::Internal("a committed rail leg has no window".into()))?;
    if window.confirmed.is_some() || window.outcome.is_some() {
        return Err(refuse("the rail leg is already confirmed"));
    }
    if now_ms > window.closes_at_ms {
        return Err(refuse("the rail leg's compensation window has closed"));
    }
    window.confirmed = Some(hex::encode(Sha256::digest(evidence)));
    write_json(state, &rail_key(&id), &window, changes)?;
    plan.achieved[index] = Some(LegClass::Attested);
    write_json(state, &plan_key(&plan.plan_id), plan, changes)?;
    logs.push(plan_log(
        "rail_confirmed",
        &serde_json::json!({ "plan_id": hex::encode(plan.plan_id), "index": index, "by": hex::encode(sender.as_bytes()) }),
    )?);
    if attestor.is_none() {
        end_rail(state, plan, index, RailOutcome::Settled, changes, logs)?;
    }
    Ok(())
}

/// The payee's dispute of rail leg `index` that its attestor confirmed,
/// inside the window: the payee is compensated and the attestor slashed.
fn dispute_rail(
    state: &mut dyn VmState,
    plan: &SettlementPlan,
    index: usize,
    sender: &Address,
    evidence: &[u8],
    now_ms: u64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let LegKind::RailInstruction {
        payee, attestor, ..
    } = &plan.legs[index].kind
    else {
        return Err(refuse("only a rail leg is disputed"));
    };
    if plan.status != PlanStatus::Committed {
        return Err(refuse("a rail leg is disputed once its plan commits"));
    }
    if sender != payee {
        return Err(refuse("only the leg's payee disputes it"));
    }
    if attestor.is_none() {
        return Err(refuse(
            "a leg its payee confirms has no attestor to dispute",
        ));
    }
    let id = leg_id(&plan.plan_id, index as u8);
    let mut window = read_rail(state, &id)
        .ok_or_else(|| VmError::Internal("a committed rail leg has no window".into()))?;
    if window.outcome.is_some() {
        return Err(refuse("the rail leg has already ended"));
    }
    if window.confirmed.is_none() {
        return Err(refuse(
            "the attestor has not confirmed the leg; it is compensated when its window closes",
        ));
    }
    if now_ms > window.closes_at_ms {
        return Err(refuse("the rail leg's compensation window has closed"));
    }
    window.disputed = Some(hex::encode(Sha256::digest(evidence)));
    write_json(state, &rail_key(&id), &window, changes)?;
    end_rail(state, plan, index, RailOutcome::Compensated, changes, logs)
}

/// End every rail leg of committed `plan` whose window closed by `now_ms`:
/// confirmed legs settle, unconfirmed legs are compensated. Returns how many
/// it ended.
fn close_rails(
    state: &mut dyn VmState,
    plan: &SettlementPlan,
    now_ms: u64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<usize> {
    let mut ended = 0;
    for (i, ..) in rail_legs(plan) {
        let Some(window) = read_rail(state, &leg_id(&plan.plan_id, i as u8)) else {
            continue;
        };
        if window.outcome.is_some() || window.closes_at_ms > now_ms {
            continue;
        }
        let outcome = if window.confirmed.is_some() {
            RailOutcome::Settled
        } else {
            RailOutcome::Compensated
        };
        end_rail(state, plan, i, outcome, changes, logs)?;
        ended += 1;
    }
    Ok(ended)
}

/// Evaluate every leg not yet reached; commit when all have, abort when one
/// failed. Returns the burned fee part on commit.
fn advance(
    state: &mut dyn VmState,
    ctx: Ctx,
    plan: &mut SettlementPlan,
    sender: &Address,
    now_ms: u64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<u128> {
    for i in 0..plan.legs.len() {
        if plan.achieved[i].is_some() {
            continue;
        }
        match evaluate(state, ctx, plan, i) {
            LegState::Reached(class) if class.satisfies(plan.legs[i].class_required) => {
                plan.achieved[i] = Some(class);
            }
            LegState::Reached(class) => {
                let reason = format!(
                    "leg {i} reached {class:?}, below the {:?} it requires",
                    plan.legs[i].class_required
                );
                abort(state, ctx, plan, sender, reason, now_ms, changes, logs)?;
                return Ok(0);
            }
            LegState::Failed(reason) => {
                abort(
                    state,
                    ctx,
                    plan,
                    sender,
                    format!("leg {i}: {reason}"),
                    now_ms,
                    changes,
                    logs,
                )?;
                return Ok(0);
            }
            LegState::Pending => {}
        }
    }
    // Rail legs are confirmed after the commit, inside their window.
    if (0..plan.legs.len()).all(|i| plan.achieved[i].is_some() || is_rail(plan, i)) {
        commit(state, ctx, plan, sender, now_ms, changes, logs)
    } else {
        write_json(state, &plan_key(&plan.plan_id), plan, changes)?;
        Ok(0)
    }
}

impl NativeExecutor {
    pub(in crate::native) fn execute_settlement_plan(
        &self,
        tx: &VmTransaction,
        state: &mut dyn VmState,
        gas_meter: &mut GasMeter,
    ) -> Result<ExecutionResult> {
        let op: PlanOp = serde_json::from_slice(&tx.data[4..])
            .map_err(|e| refuse(format!("Invalid SettlementPlan payload: {e}")))?;
        op.validate().map_err(refuse)?;
        let gas = settlement_plan_gas(&op);
        gas_meter.consume(gas)?;
        let cost = tx.gas_price.saturating_mul(u128::from(gas));
        let balance = state.get_balance(&tx.from);
        if balance < cost {
            return Err(VmError::InsufficientBalance {
                required: cost,
                available: balance,
            });
        }
        state.set_balance(&tx.from, balance - cost);
        let mut changes = vec![StateChange::new(
            tx.from.clone(),
            b"balance".to_vec(),
            Some(balance.to_le_bytes().to_vec()),
            Some((balance - cost).to_le_bytes().to_vec()),
        )];
        let mut logs = Vec::new();
        let now = deterministic_now_ms(tx);
        let now_ms = now.max(0) as u64;
        let sender = Address::from_bytes(&tx.from)
            .ok_or_else(|| refuse("a plan is sent from a 32-byte account"))?;
        let ctx = Ctx {
            chain_id: tx.chain_id,
            now_ms: now,
        };

        let (plan_id, burned) = match &op {
            PlanOp::Open {
                nonce,
                quote_digest,
                split,
                legs,
                decide_deadline_ms,
                agent,
                attribution,
                ..
            } => {
                if let Some(a) = attribution {
                    super::check_attribution(state, a)?;
                }
                // An agent's plan is opened from its wallet; anyone else's
                // from the sender's account.
                let payer = match agent {
                    Some(a) => {
                        Address::new(tenzro_types::agent_terms::agent_wallet(&a.action.agent_did))
                    }
                    None => sender,
                };
                let horizon = network_param(state, ESCAPE_HORIZON_PARAM);
                if *decide_deadline_ms <= now_ms || *decide_deadline_ms - now_ms > horizon {
                    return Err(refuse(format!(
                        "a plan's deadline is after this block and within {horizon} ms of it"
                    )));
                }
                let id = plan_id(tx.chain_id, &payer, quote_digest, *nonce);
                if read_plan(state, &id).is_some() {
                    return Err(refuse("a plan with this id already exists"));
                }
                // Every DID the rule pays must resolve now, so a commit
                // cannot fail on an unknown recipient later.
                let paid = recipients(state, split, &payer)?;
                if let Some(auth) = agent {
                    let uses = check_agent_plan(state, auth, split, legs, &paid, &payer, now_ms)?;
                    let (c, l) = super::super::agent_terms::act_for_plan(
                        state,
                        tx.chain_id,
                        &auth.action,
                        &auth.signature,
                        now,
                    )?;
                    changes.extend(c);
                    logs.extend(l);
                    super::super::remote_grant::record_remote_use(
                        state,
                        &auth.action.agent_did,
                        &uses,
                        now_ms,
                        &mut changes,
                    )?;
                }
                let vault = plan_vault_address(&id);
                let mut funded = 0u128;
                for leg in legs {
                    if let LegKind::NativeTransfer { amount, escrow_id } = &leg.kind {
                        match escrow_id {
                            Some(e) => draw_escrow(
                                state,
                                &payer,
                                e,
                                *amount,
                                vault.as_bytes(),
                                now,
                                &mut changes,
                            )?,
                            None => move_balance(
                                state,
                                payer.as_bytes(),
                                vault.as_bytes(),
                                *amount,
                                &mut changes,
                            )?,
                        }
                        funded = funded
                            .checked_add(*amount)
                            .ok_or_else(|| refuse("the legs overflow"))?;
                    }
                }
                // The Tenzro value repays every leg's network fee at its cap.
                let caps = legs
                    .iter()
                    .try_fold(0u128, |t, l| t.checked_add(l.max_network_fee))
                    .ok_or_else(|| refuse("the network fee caps overflow"))?;
                if caps > 0 {
                    tenzro_types::split::apply(funded, split, &economy::fee_params(state), caps).map_err(|_| {
                        refuse("the plan's Tenzro value cannot repay its legs' network fee caps after the protocol fee")
                    })?;
                }
                if let Some(premium) = legs.iter().find_map(|l| match l.kind {
                    LegKind::HashLocked { premium, .. } => Some(premium),
                    _ => None,
                }) {
                    let bps = network_param(state, GRIEFING_PREMIUM_PARAM);
                    let floor = funded
                        .checked_mul(u128::from(bps))
                        .map(|v| v.div_ceil(10_000))
                        .ok_or_else(|| refuse("the legs overflow"))?;
                    if premium < floor {
                        return Err(refuse(format!(
                            "a hash-locked leg escrows at least {floor} wei, {bps} bps of the plan's Tenzro value"
                        )));
                    }
                    move_balance(
                        state,
                        payer.as_bytes(),
                        vault.as_bytes(),
                        premium,
                        &mut changes,
                    )?;
                }
                for leg in legs {
                    if let LegKind::RailInstruction {
                        attestor, reserve, ..
                    } = &leg.kind
                    {
                        if network_param(state, super::ATTESTED_ENABLED_PARAM) == 0 {
                            return Err(refuse("attested rail payments are disabled"));
                        }
                        let cap = network_param(state, super::ATTESTED_CAP_PARAM);
                        if leg.usd_e6 > cap {
                            return Err(refuse(format!(
                                "a rail leg is worth at most {cap} USD micro-units"
                            )));
                        }
                        if let Some(a) = attestor
                            && !role_bonded(state, a.as_bytes(), NetworkRole::Attestor)
                        {
                            return Err(refuse("the rail leg's attestor holds no attestor bond"));
                        }
                        move_balance(
                            state,
                            payer.as_bytes(),
                            vault.as_bytes(),
                            *reserve,
                            &mut changes,
                        )?;
                    }
                }
                let tier = legs
                    .iter()
                    .map(|l| l.kind.tier())
                    .max()
                    .unwrap_or(AtomicityTier::Native);
                let mut plan = SettlementPlan {
                    plan_id: id,
                    opened_by: payer,
                    agent_did: agent.as_ref().map(|a| a.action.agent_did.clone()),
                    quote_digest: *quote_digest,
                    split: split.clone(),
                    legs: legs.clone(),
                    tier,
                    funded,
                    opened_at_ms: now_ms,
                    decide_deadline_ms: *decide_deadline_ms,
                    status: PlanStatus::Open,
                    achieved: vec![None; legs.len()],
                    relays: vec![None; legs.len()],
                    decision: None,
                    attribution: attribution.clone(),
                };
                logs.push(plan_log(
                    "opened",
                    &serde_json::json!({
                        "plan_id": hex::encode(id),
                        "payer": hex::encode(payer.as_bytes()),
                        "funded": funded.to_string(),
                        "tier": tier,
                        "split_hash": hex::encode(split.hash()),
                    }),
                )?);
                let burned = advance(
                    state,
                    ctx,
                    &mut plan,
                    &payer,
                    now_ms,
                    &mut changes,
                    &mut logs,
                )?;
                if plan.status == PlanStatus::Aborted {
                    // A leg that cannot complete is refused before anything
                    // is recorded.
                    let reason = read_decision(state, &id)
                        .and_then(|d| d.reason)
                        .unwrap_or_default();
                    return Err(refuse(format!("the plan cannot settle: {reason}")));
                }
                if plan.status == PlanStatus::Open {
                    // Still waiting for a leg: index its deadline.
                    let minute = *decide_deadline_ms / MINUTE_MS;
                    let mut due = read_due(state, minute);
                    due.push(hex::encode(id));
                    write_due(state, minute, &due, &mut changes)?;
                    if let Some(did) = &plan.agent_did {
                        let mut open = read_agent_plans(state, did);
                        if open.len() >= MAX_OPEN_PLANS_PER_AGENT {
                            return Err(refuse(format!(
                                "an agent has at most {MAX_OPEN_PLANS_PER_AGENT} undecided plans"
                            )));
                        }
                        open.push(hex::encode(id));
                        write_agent_plans(state, did, &open, &mut changes)?;
                    }
                }
                (id, burned)
            }
            PlanOp::ProveLeg {
                plan_id,
                index,
                evidence,
                network_fee,
            } => {
                let mut plan = read_plan(state, plan_id).ok_or_else(|| {
                    refuse(format!("plan {} does not exist", hex::encode(plan_id)))
                })?;
                if plan.status != PlanStatus::Open
                    && !plan
                        .legs
                        .get(usize::from(*index))
                        .is_some_and(|l| matches!(l.kind, LegKind::RailInstruction { .. }))
                {
                    return Err(refuse("the plan is already decided"));
                }
                if usize::from(*index) >= plan.legs.len() {
                    return Err(refuse("the plan has no such leg"));
                }
                if plan.achieved[usize::from(*index)].is_some() {
                    return Err(refuse("the leg already reached its class"));
                }
                if is_rail(&plan, usize::from(*index)) {
                    if *network_fee > 0 {
                        return Err(refuse("a rail leg repays no network fee"));
                    }
                    confirm_rail(
                        state,
                        &mut plan,
                        usize::from(*index),
                        &sender,
                        evidence,
                        now_ms,
                        &mut changes,
                        &mut logs,
                    )?;
                    (*plan_id, 0)
                } else if now_ms > plan.decide_deadline_ms {
                    let mut aborted = plan;
                    abort(
                        state,
                        ctx,
                        &mut aborted,
                        &sender,
                        "the deadline passed".into(),
                        now_ms,
                        &mut changes,
                        &mut logs,
                    )?;
                    (*plan_id, 0)
                } else {
                    if let Some(slot) = plan.relays.get_mut(usize::from(*index)) {
                        *slot = Some(LegRelay {
                            relayer: sender,
                            realised: *network_fee,
                        });
                    }
                    let revealed = if evidence.is_empty() {
                        false
                    } else {
                        record_evidence(state, ctx, &plan, *index, evidence, &mut changes)?
                    };
                    let before = plan.achieved.clone();
                    let burned = advance(
                        state,
                        ctx,
                        &mut plan,
                        &sender,
                        now_ms,
                        &mut changes,
                        &mut logs,
                    )?;
                    if revealed && plan.status != PlanStatus::Committed {
                        // The preimage is public once it lands, and it pays
                        // the remote recipient, so it lands only with the commit.
                        return Err(refuse(
                            "a preimage is accepted only by the transaction that commits the plan",
                        ));
                    }
                    let funded = !evidence.is_empty() && !revealed;
                    if plan.status == PlanStatus::Open && plan.achieved == before && !funded {
                        return Err(refuse("the leg has no new evidence"));
                    }
                    (*plan_id, burned)
                }
            }
            PlanOp::DisputeRail {
                plan_id,
                index,
                evidence,
            } => {
                let plan = read_plan(state, plan_id).ok_or_else(|| {
                    refuse(format!("plan {} does not exist", hex::encode(plan_id)))
                })?;
                if usize::from(*index) >= plan.legs.len() {
                    return Err(refuse("the plan has no such leg"));
                }
                dispute_rail(
                    state,
                    &plan,
                    usize::from(*index),
                    &sender,
                    evidence,
                    now_ms,
                    &mut changes,
                    &mut logs,
                )?;
                (*plan_id, 0)
            }
            PlanOp::PostCollateral {
                asset,
                amount,
                agent,
            } => {
                let owner = match agent {
                    Some(auth) => collateral_agent(
                        state,
                        tx.chain_id,
                        auth,
                        asset,
                        *amount,
                        now,
                        &mut changes,
                        &mut logs,
                    )?,
                    None => sender,
                };
                super::netting::post(state, &owner, asset, *amount, now, &mut changes, &mut logs)?;
                ([0u8; 32], 0)
            }
            PlanOp::WithdrawCollateral {
                asset,
                amount,
                agent,
            } => {
                let owner = match agent {
                    Some(auth) => collateral_agent(
                        state,
                        tx.chain_id,
                        auth,
                        asset,
                        0,
                        now,
                        &mut changes,
                        &mut logs,
                    )?,
                    None => sender,
                };
                super::netting::withdraw(
                    state,
                    &owner,
                    asset,
                    *amount,
                    now,
                    &mut changes,
                    &mut logs,
                )?;
                ([0u8; 32], 0)
            }
            PlanOp::Reconcile {
                adapter,
                chain,
                entries,
                checkpoint,
            } => {
                super::recon::reconcile(
                    state,
                    tx.chain_id,
                    *adapter,
                    chain,
                    entries,
                    checkpoint,
                    &sender,
                    now,
                    &mut changes,
                    &mut logs,
                )?;
                ([0u8; 32], 0)
            }
        };
        let out = serde_json::json!({ "plan_id": hex::encode(plan_id) });
        let data = serde_json::to_vec(&out)
            .map_err(|e| VmError::Internal(format!("encode plan output: {e}")))?;
        Ok(ExecutionResult::success(gas, data, logs, changes).with_burn(burned))
    }
}

/// Settle the netting batches whose epoch ended, then abort the open plans
/// whose deadline minute has passed, at most
/// [`MAX_ABORTS_PER_BLOCK`], in block execution before the block's
/// transactions. Every node derives the same aborts. Returns how many
/// plans it aborted.
pub fn begin_block(state: &mut dyn VmState, now_ms: i64) -> Result<usize> {
    // Netting batches whose epoch ended settle first, from collateral.
    super::netting::begin_block(state, now_ms)?;
    // Each epoch's reconciliation duties open in its first block.
    super::recon::begin_block(state, now_ms)?;
    let now_minute = now_ms.max(0) as u64 / MINUTE_MS;
    let mut changes = Vec::new();
    let mut logs = Vec::new();
    let Some(mut cursor) = read_json::<u64>(state, DUE_CURSOR_KEY) else {
        // No plan was ever opened before this block: start the walk here.
        write_json(state, DUE_CURSOR_KEY, &now_minute, &mut changes)?;
        return Ok(0);
    };
    let decider = Address::new([0u8; 32]);
    // Block execution has no transaction: the chain id only labels the route
    // view, which an abort reads for receipts.
    let ctx = Ctx {
        chain_id: 0,
        now_ms,
    };
    let mut aborted = 0usize;
    let stop = now_minute.min(cursor.saturating_add(MAX_DUE_MINUTES_PER_BLOCK));
    while cursor < stop {
        let mut due = read_due(state, cursor);
        while let Some(hex_id) = due.first().cloned() {
            if aborted == MAX_ABORTS_PER_BLOCK {
                write_due(state, cursor, &due, &mut changes)?;
                write_json(state, DUE_CURSOR_KEY, &cursor, &mut changes)?;
                return Ok(aborted);
            }
            due.remove(0);
            let plan = hex::decode(&hex_id)
                .ok()
                .and_then(|b| <[u8; 32]>::try_from(b).ok())
                .and_then(|id| read_plan(state, &id));
            match plan {
                Some(mut plan) if plan.status == PlanStatus::Open => {
                    // `finish` rewrites this minute's list without the plan.
                    write_due(state, cursor, &due, &mut changes)?;
                    abort(
                        state,
                        ctx,
                        &mut plan,
                        &decider,
                        "the deadline passed".into(),
                        now_ms.max(0) as u64,
                        &mut changes,
                        &mut logs,
                    )?;
                    aborted += 1;
                    due = read_due(state, cursor);
                }
                // Due again when its rail legs' window closes.
                Some(plan) if plan.status == PlanStatus::Committed => {
                    write_due(state, cursor, &due, &mut changes)?;
                    aborted +=
                        close_rails(state, &plan, now_ms.max(0) as u64, &mut changes, &mut logs)?
                            .min(1);
                }
                _ => {}
            }
        }
        cursor += 1;
    }
    write_json(state, DUE_CURSOR_KEY, &cursor, &mut changes)?;
    Ok(aborted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VmConfig;
    use crate::VmType;
    use crate::state_adapter::StateAdapter;
    use crate::traits::VmExecutor;
    use tenzro_types::bridge_route::BridgeRouteAdapter;
    use tenzro_types::settlement::Leg;
    use tenzro_types::split::{SPLIT_RULE_VERSION, SplitBasis, SplitLine, SplitRole};

    const CHAIN: u64 = 1337;
    const T0: i64 = 1_800_000_000_000;
    const TNZO: u128 = 1_000_000_000_000_000_000;
    const PAYER: [u8; 32] = [7; 32];

    struct Book {
        ex: NativeExecutor,
        state: StateAdapter,
        nonce: u64,
    }

    impl Book {
        fn new() -> Self {
            let mut state = StateAdapter::new();
            state.set_balance(&PAYER, 1_000 * TNZO);
            Self {
                ex: NativeExecutor::new(VmConfig::default()).unwrap(),
                state,
                nonce: 0,
            }
        }

        async fn run(
            &mut self,
            from: &[u8],
            selector: [u8; 4],
            body: Vec<u8>,
            at: i64,
        ) -> std::result::Result<serde_json::Value, String> {
            let mut data = selector.to_vec();
            data.extend(body);
            let mut t = VmTransaction::new(
                from.to_vec(),
                None,
                0,
                data,
                5_000_000,
                0,
                self.nonce,
                VmType::Tenzro,
                CHAIN,
            );
            t.block_timestamp_ms = Some(at);
            self.nonce += 1;
            // A refused transaction leaves no state, as in a block.
            self.state.begin_transaction();
            let out = match self.ex.execute_transaction(&t, &mut self.state).await {
                Ok(r) if r.success => Ok(serde_json::from_slice(&r.output).unwrap_or_default()),
                Ok(r) => Err(format!("{:?}", r.revert_reason)),
                Err(e) => Err(e.to_string()),
            };
            if out.is_ok() {
                self.state.commit_transaction();
            } else {
                self.state.revert_transaction();
            }
            out
        }

        async fn send(
            &mut self,
            from: &[u8],
            op: PlanOp,
            at: i64,
        ) -> std::result::Result<[u8; 32], String> {
            let out = self
                .run(
                    from,
                    SELECTOR_SETTLEMENT_PLAN,
                    serde_json::to_vec(&op).unwrap(),
                    at,
                )
                .await?;
            let id = hex::decode(out["plan_id"].as_str().unwrap()).unwrap();
            Ok(id.try_into().unwrap())
        }

        fn balance(&self, a: &Address) -> u128 {
            self.state.get_balance(a.as_bytes())
        }
    }

    fn rule() -> SplitRule {
        SplitRule {
            version: SPLIT_RULE_VERSION,
            lines: vec![
                SplitLine {
                    role: SplitRole::Publisher,
                    recipient: SplitRecipient::Address(Address::new([2; 32])),
                    basis: SplitBasis::Bps(3_000),
                    cap: None,
                },
                SplitLine {
                    role: SplitRole::Payee,
                    recipient: SplitRecipient::Address(Address::new([1; 32])),
                    basis: SplitBasis::Remainder,
                    cap: None,
                },
            ],
        }
    }

    fn native(amount: u128) -> Leg {
        Leg {
            kind: LegKind::NativeTransfer {
                amount,
                escrow_id: None,
            },
            class_required: LegClass::Native,
            usd_e6: 0,
            max_network_fee: 0,
        }
    }

    fn open(nonce: u64, legs: Vec<Leg>, deadline: i64) -> PlanOp {
        let split = rule();
        PlanOp::Open {
            nonce,
            quote_digest: [9; 32],
            split_hash: split.hash(),
            split,
            legs,
            decide_deadline_ms: deadline as u64,
            agent: None,
            attribution: None,
        }
    }

    /// One rule, one engine: a direct payment, an escrow release and a plan
    /// leg of the same gross divide it identically.
    #[tokio::test]
    async fn a_direct_payment_an_escrow_release_and_a_plan_leg_split_alike() {
        let gross = 10 * TNZO;
        let (publisher, payee) = (Address::new([2; 32]), Address::new([1; 32]));
        let split = |state: &StateAdapter| {
            (
                state.get_balance(publisher.as_bytes()),
                state.get_balance(payee.as_bytes()),
            )
        };
        let standing = |state: &mut StateAdapter| {
            let op = tenzro_types::settlement::PaymentOp::SetSplit { rule: Some(rule()) };
            super::super::apply_payment_op(
                state,
                CHAIN,
                T0,
                payee.as_bytes(),
                &op,
                &mut Vec::new(),
            )
            .unwrap();
        };

        let mut b = Book::new();
        let id = b
            .send(&PAYER, open(1, vec![native(gross)], T0 + 60_000), T0)
            .await
            .unwrap();
        let alloc = read_decision(&b.state, &id).unwrap().allocation.unwrap();
        let by_plan = split(&b.state);
        assert_eq!(by_plan, (alloc.credits[0], alloc.credits[1]));

        let mut direct = StateAdapter::new();
        direct.set_balance(&PAYER, 1_000 * TNZO);
        standing(&mut direct);
        let tnzo = crate::token_ledger::tnzo_id();
        super::super::settle_asset(
            &mut direct,
            &tnzo,
            &PAYER,
            &PAYER,
            payee.as_bytes(),
            gross,
            0,
            T0,
            &Default::default(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(split(&direct), by_plan);

        let mut escrowed = StateAdapter::new();
        standing(&mut escrowed);
        let escrow_id = [5u8; 32];
        escrowed.set_balance(
            super::super::derive_vault_address(&escrow_id).as_bytes(),
            gross,
        );
        let escrow = tenzro_settlement::escrow::EscrowAccount::new(
            Address::new(PAYER),
            payee,
            gross,
            tenzro_types::asset::AssetId::tnzo(),
            tenzro_types::primitives::Timestamp(T0 + 60_000),
            tenzro_types::settlement::ReleaseConditions::Timeout,
        );
        super::super::pay_from_vault(
            &mut escrowed,
            &escrow_id,
            &escrow,
            payee.as_bytes(),
            gross,
            T0,
            &Default::default(),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(split(&escrowed), by_plan);
    }

    #[tokio::test]
    async fn a_tenzro_only_plan_commits_in_the_transaction_that_opens_it() {
        let mut b = Book::new();
        let id = b
            .send(&PAYER, open(1, vec![native(10 * TNZO)], T0 + 60_000), T0)
            .await
            .unwrap();
        let plan = read_plan(&b.state, &id).unwrap();
        assert_eq!(plan.status, PlanStatus::Committed);
        assert_eq!(plan.tier, AtomicityTier::Native);
        let decision = read_decision(&b.state, &id).unwrap();
        assert!(decision.commit);
        let alloc = decision.allocation.unwrap();
        assert!(alloc.conserves());
        assert!(alloc.fee.fee > 0);
        assert_eq!(b.balance(&Address::new([2; 32])), alloc.credits[0]);
        assert_eq!(b.balance(&Address::new([1; 32])), alloc.credits[1]);
        assert_eq!(b.balance(&Address::new(PAYER)), 990 * TNZO);
        assert_eq!(b.balance(&plan_vault_address(&id)), 0);
        let commitment = read_decision_commitment(&b.state, &id).unwrap();
        assert_eq!(
            commitment,
            decision_commitment(&id, true, T0 as u64).to_vec()
        );
        let receipt = read_leg_receipt(&b.state, &leg_id(&id, 0)).unwrap();
        assert!(receipt.committed);
        assert_eq!(receipt.class_achieved, Some(LegClass::Native));
        // The plan id is taken.
        assert!(
            b.send(&PAYER, open(1, vec![native(TNZO)], T0 + 60_000), T0)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn the_fee_is_charged_once_however_the_value_is_split_into_legs() {
        let mut one = Book::new();
        let id = one
            .send(
                &PAYER,
                open(1, vec![native(16 * (TNZO + 999))], T0 + 60_000),
                T0,
            )
            .await
            .unwrap();
        let mut many = Book::new();
        let id16 = many
            .send(
                &PAYER,
                open(
                    1,
                    (0..16).map(|_| native(TNZO + 999)).collect(),
                    T0 + 60_000,
                ),
                T0,
            )
            .await
            .unwrap();
        let fee = |b: &Book, id| {
            read_decision(&b.state, &id)
                .unwrap()
                .allocation
                .unwrap()
                .fee
        };
        assert_eq!(fee(&one, id), fee(&many, id16));
    }

    fn pay_to(to: Address) -> SplitRule {
        SplitRule {
            version: SPLIT_RULE_VERSION,
            lines: vec![SplitLine {
                role: SplitRole::Payee,
                recipient: SplitRecipient::Address(to),
                basis: SplitBasis::Remainder,
                cap: None,
            }],
        }
    }

    /// One actor pays a plan into an account it also holds (a second account,
    /// or the paying account itself) and reports it as served work. The
    /// provider reward the epoch then issues it must stay below what the
    /// settlement paid outside the trade, or paying oneself would mint.
    #[tokio::test]
    async fn a_self_paid_settlement_never_earns_more_provider_reward_than_its_fee() {
        use crate::native::rewards;
        let validator = Address::new([0x55; 32]);
        for provider in [Address::new([1; 32]), Address::new(PAYER)] {
            let mut b = Book::new();
            b.state.set_storage(
                &SYSTEM_ADDRESS,
                rewards::REWARD_SCHEDULE_KEY.as_bytes(),
                rewards::genesis_reward_schedule(86_400_000).unwrap(),
            );
            rewards::begin_block(&mut b.state, 0, &validator, T0).unwrap();
            let split = pay_to(provider);
            let op = PlanOp::Open {
                nonce: 1,
                quote_digest: [9; 32],
                split_hash: split.hash(),
                split,
                legs: vec![native(100 * TNZO)],
                decide_deadline_ms: (T0 + 60_000) as u64,
                agent: None,
                attribution: None,
            };
            let id = b.send(&PAYER, op, T0).await.unwrap();
            let fee = read_decision(&b.state, &id)
                .unwrap()
                .allocation
                .unwrap()
                .fee
                .fee;
            assert!(fee > 0);
            let report = crate::funding::FundingOp::ReportSettledWork {
                legs: vec![tenzro_types::settlement::leg_id(&id, 0)],
            };
            // The report itself may be refused once self-payment no longer
            // counts; either way the epoch must not pay above the fee.
            let _ = b
                .run(
                    provider.as_bytes(),
                    super::super::super::funding::SELECTOR_FUNDING,
                    serde_json::to_vec(&report).unwrap(),
                    T0 + 1,
                )
                .await;
            rewards::begin_block(&mut b.state, 1, &validator, T0 + 86_400_000).unwrap();
            let minted: u128 = rewards::read_coupons(&b.state, &provider)
                .unwrap()
                .iter()
                .filter(|c| c.bucket == tenzro_token::rewards::RoleBucket::Provider)
                .map(|c| c.amount)
                .sum();
            assert!(
                minted < fee,
                "provider {provider:?} paid a fee of {fee} wei and was issued {minted} wei of provider reward"
            );
        }
    }

    /// Pay 100 TNZO from `PAYER` to `provider` through a plan, with each
    /// (account, DID) of `bind` registered, report it as `provider`'s work
    /// and close the epoch: (the fee paid, the provider reward issued).
    async fn reward_for_one_plan(bind: &[(Address, &str)], provider: Address) -> (u128, u128) {
        use crate::native::rewards;
        let validator = Address::new([0x55; 32]);
        let mut b = Book::new();
        for (addr, did) in bind {
            b.state.set_storage(
                &SYSTEM_ADDRESS,
                crate::native::identity_wallet_index_key(addr.as_bytes()).as_bytes(),
                did.as_bytes().to_vec(),
            );
        }
        b.state.set_storage(
            &SYSTEM_ADDRESS,
            rewards::REWARD_SCHEDULE_KEY.as_bytes(),
            rewards::genesis_reward_schedule(86_400_000).unwrap(),
        );
        rewards::begin_block(&mut b.state, 0, &validator, T0).unwrap();
        let split = pay_to(provider);
        let op = PlanOp::Open {
            nonce: 1,
            quote_digest: [9; 32],
            split_hash: split.hash(),
            split,
            legs: vec![native(100 * TNZO)],
            decide_deadline_ms: (T0 + 60_000) as u64,
            agent: None,
            attribution: None,
        };
        let id = b.send(&PAYER, op, T0).await.unwrap();
        let fee = read_decision(&b.state, &id)
            .unwrap()
            .allocation
            .unwrap()
            .fee
            .fee;
        let report = crate::funding::FundingOp::ReportSettledWork {
            legs: vec![tenzro_types::settlement::leg_id(&id, 0)],
        };
        let _ = b
            .run(
                provider.as_bytes(),
                super::super::super::funding::SELECTOR_FUNDING,
                serde_json::to_vec(&report).unwrap(),
                T0 + 1,
            )
            .await;
        rewards::begin_block(&mut b.state, 1, &validator, T0 + 86_400_000).unwrap();
        let minted = rewards::read_coupons(&b.state, &provider)
            .unwrap()
            .iter()
            .filter(|c| c.bucket == tenzro_token::rewards::RoleBucket::Provider)
            .map(|c| c.amount)
            .sum();
        (fee, minted)
    }

    /// A plan names the app it was bought through: the app must be a
    /// registered identity, and at commit it earns the activity share of the
    /// fee while the payee earns none.
    #[tokio::test]
    async fn an_attributed_plan_credits_its_app_and_not_its_payee() {
        let provider = Address::new([1; 32]);
        let maker = Address::new([3; 32]);
        let mut b = Book::new();
        for (addr, did) in [
            (Address::new(PAYER), "did:tenzro:human:bob"),
            (provider, "did:tenzro:human:carol"),
        ] {
            b.state.set_storage(
                &SYSTEM_ADDRESS,
                crate::native::identity_wallet_index_key(addr.as_bytes()).as_bytes(),
                did.as_bytes().to_vec(),
            );
        }
        let attributed = |nonce| {
            let split = pay_to(provider);
            PlanOp::Open {
                nonce,
                quote_digest: [9; 32],
                split_hash: split.hash(),
                split,
                legs: vec![native(100 * TNZO)],
                decide_deadline_ms: (T0 + 60_000) as u64,
                agent: None,
                attribution: Some(tenzro_types::settlement::CallAttribution {
                    app_did: Some("did:tenzro:human:dana".into()),
                    ..Default::default()
                }),
            }
        };
        // Not yet registered: refused before any value moves.
        assert!(b.send(&PAYER, attributed(1), T0).await.is_err());
        b.state.set_storage(
            &SYSTEM_ADDRESS,
            crate::native::identity_wallet_index_key(maker.as_bytes()).as_bytes(),
            b"did:tenzro:human:dana".to_vec(),
        );
        let record = tenzro_types::identity::RegisterIdentityPayload {
            did: "did:tenzro:human:dana".into(),
            identity_type: "human".into(),
            display_name: String::new(),
            controller_pubkey: Vec::new(),
            key_type: "p256".into(),
            wallet_id: String::new(),
            wallet_address: maker,
            pq_verifying_key: Vec::new(),
            metadata: Default::default(),
            proof: tenzro_types::identity::RegistrationProof::Hardware {
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            },
        };
        b.state.set_storage(
            &SYSTEM_ADDRESS,
            &crate::native::identity_storage_key("did:tenzro:human:dana"),
            serde_json::to_vec(&record).unwrap(),
        );
        let id = b.send(&PAYER, attributed(2), T0).await.unwrap();
        let plan = read_plan(&b.state, &id).unwrap();
        assert!(plan.attribution.is_some());
        let fee = plan.decision.unwrap().allocation.unwrap().fee.fee;
        let rows = crate::native::rewards::pending_work(&b.state, 0);
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].address, maker);
        assert_eq!(rows[0].class, tenzro_token::rewards::WorkClass::AppUsage);
        assert_eq!(
            rows[0].weight,
            tenzro_types::split::bps_of(
                fee,
                u128::from(crate::native::economy::DEFAULT_ACTIVITY_REWARD_FEE_BPS)
            )
        );
    }

    /// A counted plan's record is deleted with its epoch past the claim
    /// window, and the plan can no longer be cited: it is not counted twice.
    #[tokio::test]
    async fn a_counted_plan_past_the_claim_window_is_deleted_and_not_counted_again() {
        use crate::native::rewards;
        let validator = Address::new([0x55; 32]);
        let provider = Address::new([1; 32]);
        let mut b = Book::new();
        for (addr, did) in [
            (Address::new(PAYER), "did:tenzro:human:bob"),
            (provider, "did:tenzro:human:carol"),
        ] {
            b.state.set_storage(
                &SYSTEM_ADDRESS,
                crate::native::identity_wallet_index_key(addr.as_bytes()).as_bytes(),
                did.as_bytes().to_vec(),
            );
        }
        b.state.set_storage(
            &SYSTEM_ADDRESS,
            rewards::REWARD_SCHEDULE_KEY.as_bytes(),
            rewards::genesis_reward_schedule(86_400_000).unwrap(),
        );
        rewards::begin_block(&mut b.state, 0, &validator, T0).unwrap();
        let split = pay_to(provider);
        let op = PlanOp::Open {
            nonce: 1,
            quote_digest: [9; 32],
            split_hash: split.hash(),
            split,
            legs: vec![native(100 * TNZO)],
            decide_deadline_ms: (T0 + 60_000) as u64,
            agent: None,
            attribution: None,
        };
        let id = b.send(&PAYER, op, T0).await.unwrap();
        let report = serde_json::to_vec(&crate::funding::FundingOp::ReportSettledWork {
            legs: vec![tenzro_types::settlement::leg_id(&id, 0)],
        })
        .unwrap();
        let selector = super::super::super::funding::SELECTOR_FUNDING;
        b.run(provider.as_bytes(), selector, report.clone(), T0 + 1)
            .await
            .unwrap();
        let receipt = format!("reward_receipt:{}", hex::encode(id));
        assert!(
            b.state
                .get_storage(&SYSTEM_ADDRESS, receipt.as_bytes())
                .is_some()
        );

        let past = tenzro_token::rewards::DEFAULT_CLAIM_WINDOW_EPOCHS + 2;
        for epoch in 1..=past {
            let at = T0 + epoch as i64 * 86_400_000;
            rewards::begin_block(&mut b.state, epoch, &validator, at).unwrap();
        }
        assert_eq!(
            b.state.get_storage(&SYSTEM_ADDRESS, receipt.as_bytes()),
            None
        );
        let at = T0 + (past as i64 + 1) * 86_400_000;
        assert!(
            b.run(provider.as_bytes(), selector, report, at)
                .await
                .is_err()
        );
    }

    /// Two agents one human delegated are one party: paying each other earns
    /// no provider reward. The same holds for a device and the agent it
    /// delegated. Agents of different roots are distinct parties.
    #[tokio::test]
    async fn agents_under_one_root_paying_each_other_earn_nothing() {
        let provider = Address::new([1; 32]);
        let payer = Address::new(PAYER);
        for (payer_did, provider_did) in [
            (
                "did:tenzro:machine:alice:agent-a",
                "did:tenzro:machine:alice:agent-b",
            ),
            ("did:tenzro:human:alice", "did:tenzro:machine:alice:agent-b"),
            (
                "did:tenzro:machine:device1",
                "did:tenzro:machine:device1:agent-a",
            ),
        ] {
            let (_, minted) =
                reward_for_one_plan(&[(payer, payer_did), (provider, provider_did)], provider)
                    .await;
            assert_eq!(
                minted, 0,
                "{payer_did} paying {provider_did} minted {minted}"
            );
        }
        let (fee, minted) = reward_for_one_plan(
            &[
                (payer, "did:tenzro:machine:bob:agent-a"),
                (provider, "did:tenzro:machine:alice:agent-b"),
            ],
            provider,
        )
        .await;
        assert_eq!(
            minted,
            fee * u128::from(crate::native::rewards::DEFAULT_PROVIDER_REWARD_COST_BPS) / 10_000
        );
    }

    /// A provider paid by another party earns provider reward weight of the
    /// governed share of the fee the settlement paid outside the trade.
    #[tokio::test]
    async fn a_settlement_paid_by_another_party_earns_its_share_of_the_fee() {
        use crate::native::rewards;
        let validator = Address::new([0x55; 32]);
        let provider = Address::new([1; 32]);
        let mut b = Book::new();
        b.state.set_storage(
            &SYSTEM_ADDRESS,
            crate::native::identity_wallet_index_key(provider.as_bytes()).as_bytes(),
            b"did:tenzro:machine:alice:agent-b".to_vec(),
        );
        b.state.set_storage(
            &SYSTEM_ADDRESS,
            rewards::REWARD_SCHEDULE_KEY.as_bytes(),
            rewards::genesis_reward_schedule(86_400_000).unwrap(),
        );
        rewards::begin_block(&mut b.state, 0, &validator, T0).unwrap();
        let split = pay_to(provider);
        let op = PlanOp::Open {
            nonce: 1,
            quote_digest: [9; 32],
            split_hash: split.hash(),
            split,
            legs: vec![native(100 * TNZO)],
            decide_deadline_ms: (T0 + 60_000) as u64,
            agent: None,
            attribution: None,
        };
        let id = b.send(&PAYER, op, T0).await.unwrap();
        let fee = read_decision(&b.state, &id)
            .unwrap()
            .allocation
            .unwrap()
            .fee
            .fee;
        let report = crate::funding::FundingOp::ReportSettledWork {
            legs: vec![tenzro_types::settlement::leg_id(&id, 0)],
        };
        let body = serde_json::to_vec(&report).unwrap();
        b.run(
            provider.as_bytes(),
            super::super::super::funding::SELECTOR_FUNDING,
            body.clone(),
            T0 + 1,
        )
        .await
        .unwrap();
        // Counted once.
        assert!(
            b.run(
                provider.as_bytes(),
                super::super::super::funding::SELECTOR_FUNDING,
                body,
                T0 + 2
            )
            .await
            .is_err()
        );
        rewards::begin_block(&mut b.state, 1, &validator, T0 + 86_400_000).unwrap();
        let coupons = rewards::read_coupons(&b.state, &provider).unwrap();
        assert_eq!(coupons.len(), 1);
        assert_eq!(
            coupons[0].bucket,
            tenzro_token::rewards::RoleBucket::Provider
        );
        assert_eq!(
            coupons[0].amount,
            fee * u128::from(rewards::DEFAULT_PROVIDER_REWARD_COST_BPS) / 10_000
        );
    }

    #[tokio::test]
    async fn a_split_rule_other_than_the_one_the_quote_signed_is_refused() {
        let mut b = Book::new();
        let PlanOp::Open { split, legs, .. } = open(1, vec![native(TNZO)], T0 + 60_000) else {
            unreachable!()
        };
        let mut other = split.clone();
        other.lines[0].basis = SplitBasis::Bps(9_000);
        let op = PlanOp::Open {
            nonce: 1,
            quote_digest: [9; 32],
            split_hash: split.hash(),
            split: other,
            legs,
            decide_deadline_ms: (T0 + 60_000) as u64,
            agent: None,
            attribution: None,
        };
        assert!(op.validate().is_err());
        assert!(b.send(&PAYER, op, T0).await.is_err());
        assert_eq!(b.balance(&Address::new(PAYER)), 1_000 * TNZO);
    }

    #[tokio::test]
    async fn a_deadline_beyond_the_escape_horizon_is_refused() {
        let mut b = Book::new();
        let far = T0 + DEFAULT_ESCAPE_HORIZON_MS as i64 + 1;
        assert!(
            b.send(&PAYER, open(1, vec![native(TNZO)], far), T0)
                .await
                .is_err()
        );
        assert!(
            b.send(&PAYER, open(1, vec![native(TNZO)], T0), T0)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn an_undecided_plan_aborts_in_block_execution_after_its_deadline() {
        let mut b = Book::new();
        begin_block(&mut b.state, T0).unwrap();
        let before = b.balance(&Address::new(PAYER));
        let deadline = T0 + 120_000;
        let id = b
            .send(
                &PAYER,
                open(1, vec![native(TNZO), remote_lock(700)], deadline),
                T0,
            )
            .await
            .unwrap();
        assert_eq!(
            begin_block(&mut b.state, deadline).unwrap(),
            0,
            "not before the deadline's minute ends"
        );
        assert_eq!(read_plan(&b.state, &id).unwrap().status, PlanStatus::Open);
        assert_eq!(begin_block(&mut b.state, deadline + 60_000).unwrap(), 1);
        assert_eq!(
            read_plan(&b.state, &id).unwrap().status,
            PlanStatus::Aborted
        );
        assert_eq!(b.balance(&Address::new(PAYER)), before);
        assert_eq!(b.balance(&plan_vault_address(&id)), 0);
        assert_eq!(begin_block(&mut b.state, deadline + 120_000).unwrap(), 0);
    }

    #[tokio::test]
    async fn a_plan_draws_from_the_payers_funded_escrow() {
        let mut b = Book::new();
        let create = serde_json::json!({
            "payee": Address::new([1; 32]),
            "amount": (4 * TNZO) as u64,
            "asset_id": tenzro_types::asset::AssetId::new("TNZO"),
            "expires_at": (T0 + 3_600_000) as u64,
            "release_conditions": ReleaseConditions::ProviderSignature,
        });
        b.run(
            &PAYER,
            super::super::super::SELECTOR_ESCROW_CREATE,
            serde_json::to_vec(&create).unwrap(),
            T0,
        )
        .await
        .unwrap();
        let escrow_id = super::super::super::derive_escrow_id(&Address::new(PAYER), 0);
        let leg = |amount| Leg {
            kind: LegKind::NativeTransfer {
                amount,
                escrow_id: Some(escrow_id),
            },
            class_required: LegClass::Native,
            usd_e6: 0,
            max_network_fee: 0,
        };
        assert!(
            b.send(&[5; 32], open(1, vec![leg(TNZO)], T0 + 60_000), T0)
                .await
                .is_err(),
            "only the payer"
        );
        assert!(
            b.send(&PAYER, open(2, vec![leg(5 * TNZO)], T0 + 60_000), T0)
                .await
                .is_err(),
            "no more than it holds"
        );
        b.send(&PAYER, open(3, vec![leg(TNZO)], T0 + 60_000), T0)
            .await
            .unwrap();
        let escrow = super::super::read_escrow(&b.state, &escrow_id).unwrap();
        assert_eq!(escrow.claimed, TNZO);
        assert_eq!(escrow.status, EscrowStatus::Funded);
        b.send(&PAYER, open(4, vec![leg(3 * TNZO)], T0 + 60_000), T0)
            .await
            .unwrap();
        let escrow = super::super::read_escrow(&b.state, &escrow_id).unwrap();
        assert_eq!(escrow.status, EscrowStatus::Released);
    }

    /// A v2 IBC route to `cosmoshub` with one packet of `amount` the payer
    /// sent, written as the route framework writes it; returns its sequence.
    fn ibc_packet_sent(
        b: &mut Book,
        amount: u128,
    ) -> (tenzro_types::bridge_route::BridgeRoute, Vec<u8>) {
        use tenzro_bridge::route::ibc::outbound_packet;
        use tenzro_types::bridge_route::{
            ChainFamily, IbcRoute, IbcVersion, MintRateLimit, VerifierQuorum,
        };
        let ibc = IbcRoute {
            version: IbcVersion::V2,
            counterparty_client_id: "07-tendermint-0".into(),
            counterparty_connection_id: None,
            counterparty_channel_id: None,
            packet_timeout_secs: 600,
        };
        let route = tenzro_types::bridge_route::BridgeRoute {
            adapter: BridgeRouteAdapter::Ibc,
            family: ChainFamily::Cosmos,
            source_chain: "cosmoshub".into(),
            source_chain_id: 118,
            local_selector: 7_777,
            peer: IbcRoute::end_hash(ibc.counterparty_packet_id()),
            ramp: [1; 32],
            local_endpoint: IbcRoute::end_hash(&ibc.tenzro_packet_id("cosmoshub")),
            remote_token: sha2::Sha256::digest(ibc.tnzo_trace().as_bytes()).into(),
            verifiers: VerifierQuorum {
                set_index: 0,
                size: 0,
                members: Vec::new(),
                threshold: 0,
            },
            blessing: None,
            light_client: None,
            mint_limit: MintRateLimit {
                per_mint: u128::MAX,
                per_epoch: u128::MAX,
            },
            outflow: tenzro_types::bridge_route::LaneRateLimit {
                capacity: u128::MAX,
                rate: u128::MAX / 2,
            },
            lane_limits: None,
            ibc: Some(ibc),
            settlement_lock: None,
            native_asset: None,
            assets: Vec::new(),
        };
        let key = tenzro_types::bridge_route::bridge_route_storage_key(
            BridgeRouteAdapter::Ibc,
            "cosmoshub",
        );
        b.state.set_storage(
            &SYSTEM_ADDRESS,
            key.as_bytes(),
            serde_json::to_vec(&route).unwrap(),
        );
        let message = tenzro_bridge::route::RouteMessage {
            message_id: [0; 32],
            source_selector: route.local_selector,
            dest_selector: route.source_chain_id,
            sequence: 1,
            sender: PAYER.to_vec(),
            receiver: b"cosmos1receiver".to_vec(),
            token_pool: route.local_endpoint,
            token: route.remote_token,
            amount,
        };
        let packet = outbound_packet(&route, &message, (T0 / 1000) as u64 + 600).unwrap();
        let out_key = tenzro_bridge::route::state::outbound_key(&route, 1);
        b.state
            .set_storage(&SYSTEM_ADDRESS, out_key.as_bytes(), packet.encode());
        let path = packet.commitment_key();
        let commit_key = tenzro_bridge::route::ibc_core::store_key(&path);
        b.state.set_storage(
            &SYSTEM_ADDRESS,
            commit_key.as_bytes(),
            packet.commitment().to_vec(),
        );
        (route, commit_key.into_bytes())
    }

    fn ibc_leg() -> Leg {
        Leg {
            kind: LegKind::IbcTransfer {
                chain: "cosmoshub".into(),
                sequence: 1,
            },
            class_required: LegClass::Proven,
            usd_e6: 1_000_000,
            max_network_fee: 0,
        }
    }

    fn remote_lock(amount: u128) -> Leg {
        Leg {
            kind: LegKind::RemoteLock {
                adapter: BridgeRouteAdapter::Ccip,
                chain: "ethereum".into(),
                asset: [0; 32],
                amount,
                recipient: [4; 32],
            },
            class_required: LegClass::Attested,
            usd_e6: 1_000_000,
            max_network_fee: 0,
        }
    }

    const SECRET: [u8; 32] = [0x5e; 32];

    fn hash_locked(refund_after_secs: u32) -> Leg {
        let mut recipient_key = [2u8; 33];
        recipient_key[1] = 1;
        let mut refund_key = [3u8; 33];
        refund_key[1] = 2;
        Leg {
            kind: LegKind::HashLocked {
                chain: "bitcoin".into(),
                hash: Sha256::digest(SECRET).into(),
                recipient_key,
                refund_key,
                refund_after_secs,
                amount_sats: 50_000,
                premium: PREMIUM,
            },
            class_required: LegClass::Proven,
            usd_e6: 30_000_000,
            max_network_fee: 0,
        }
    }

    /// Record a leg's evidence as a verified proof would.
    fn seed_evidence(b: &mut Book, plan: &[u8; 32], index: u8, class: LegClass) {
        let rec = LegEvidence {
            class,
            digest: [1; 32],
            funding_txid: Some("ab".into()),
            preimage: None,
        };
        b.state.set_storage(
            &SYSTEM_ADDRESS,
            evidence_key(&leg_id(plan, index)).as_bytes(),
            serde_json::to_vec(&rec).unwrap(),
        );
    }

    /// 2% of a one-TNZO plan, above the genesis 1% floor.
    const PREMIUM: u128 = TNZO / 50;

    const LATE: u32 = ((T0 as u64 + 600_000 + DEFAULT_RELEASE_MARGIN_MS) / 1000) as u32;

    #[tokio::test]
    async fn an_attested_lock_reaches_its_class_and_commits() {
        let mut b = Book::new();
        let id = b
            .send(
                &PAYER,
                open(1, vec![native(TNZO), remote_lock(700)], T0 + 600_000),
                T0,
            )
            .await
            .unwrap();
        assert_eq!(
            read_plan(&b.state, &id).unwrap().tier,
            AtomicityTier::DecisionLocked
        );
        let prove = PlanOp::ProveLeg {
            plan_id: id,
            index: 1,
            evidence: Vec::new(),
            network_fee: 0,
        };
        assert!(
            b.send(&[5; 32], prove.clone(), T0 + 1_000).await.is_err(),
            "no lock yet"
        );
        let bogus = PlanOp::ProveLeg {
            plan_id: id,
            index: 1,
            evidence: vec![1; 40],
            network_fee: 0,
        };
        assert!(
            b.send(&[5; 32], bogus, T0 + 1_000).await.is_err(),
            "no route carries the proof"
        );
        seed_evidence(&mut b, &id, 1, LegClass::Attested);
        b.send(&[5; 32], prove, T0 + 2_000).await.unwrap();
        assert!(read_decision(&b.state, &id).unwrap().commit);
        let receipt = read_leg_receipt(&b.state, &leg_id(&id, 1)).unwrap();
        assert_eq!(receipt.class_achieved, Some(LegClass::Attested));
        assert_eq!(receipt.amount, 700);
    }

    /// A commit repays the relayer the network fee it stated, up to the leg's
    /// cap: the relayer bears what it paid above it.
    #[tokio::test]
    async fn a_network_fee_above_the_legs_cap_is_borne_by_the_relayer() {
        let mut b = Book::new();
        let cap = TNZO / 100;
        let mut leg = remote_lock(700);
        leg.max_network_fee = cap;
        let id = b
            .send(&PAYER, open(1, vec![native(TNZO), leg], T0 + 600_000), T0)
            .await
            .unwrap();
        seed_evidence(&mut b, &id, 1, LegClass::Attested);
        let relayer = Address::new([5; 32]);
        let before = b.balance(&relayer);
        let prove = PlanOp::ProveLeg {
            plan_id: id,
            index: 1,
            evidence: Vec::new(),
            network_fee: 2 * cap,
        };
        b.send(&[5; 32], prove, T0 + 1_000).await.unwrap();
        let decision = read_decision(&b.state, &id).unwrap();
        assert!(decision.commit);
        let alloc = decision.allocation.unwrap();
        assert_eq!(alloc.network_fees, cap);
        assert!(alloc.conserves());
        assert_eq!(
            b.balance(&relayer) - before,
            cap,
            "repaid the cap, not the fee it stated"
        );
        let receipt = read_leg_receipt(&b.state, &leg_id(&id, 1)).unwrap();
        assert_eq!((receipt.network_fee, receipt.relayer), (cap, Some(relayer)));
        // The stored record is the fixed-size encoding a remote chain proves.
        let stored = read_leg_receipt_commitment(&b.state, &leg_id(&id, 1)).unwrap();
        assert_eq!(stored, receipt.encode().to_vec());
        assert_eq!(LegReceipt::decode(&stored), Some(receipt));
        // The Tenzro leg's receipt names no relayer and repays nothing.
        let native_leg = read_leg_receipt(&b.state, &leg_id(&id, 0)).unwrap();
        assert_eq!((native_leg.network_fee, native_leg.relayer), (0, None));
    }

    #[tokio::test]
    async fn caps_the_tenzro_value_cannot_repay_are_refused_at_open() {
        let mut b = Book::new();
        let mut leg = remote_lock(700);
        leg.max_network_fee = TNZO;
        let err = b
            .send(&PAYER, open(1, vec![native(TNZO), leg], T0 + 600_000), T0)
            .await
            .unwrap_err();
        assert!(err.contains("network fee caps"), "{err}");
    }

    #[tokio::test]
    async fn a_hash_locked_leg_refuses_an_early_refund_and_a_reveal_that_does_not_commit() {
        let mut b = Book::new();
        // A refund that opens before the deadline plus the margin.
        let early = b
            .send(
                &PAYER,
                open(1, vec![native(TNZO), hash_locked(LATE - 1)], T0 + 600_000),
                T0,
            )
            .await
            .unwrap();
        let fund = PlanOp::ProveLeg {
            plan_id: early,
            index: 1,
            evidence: vec![0; 80],
            network_fee: 0,
        };
        let err = b.send(&[5; 32], fund, T0 + 1_000).await.unwrap_err();
        assert!(err.contains("refund opens before"), "{err}");

        // Funded, but another leg is still pending: the reveal would not commit.
        let id = b
            .send(
                &PAYER,
                open(
                    2,
                    vec![native(TNZO), hash_locked(LATE), remote_lock(5)],
                    T0 + 600_000,
                ),
                T0,
            )
            .await
            .unwrap();
        assert_eq!(
            read_plan(&b.state, &id).unwrap().tier,
            AtomicityTier::HashLocked
        );
        seed_evidence(&mut b, &id, 1, LegClass::Proven);
        let reveal = PlanOp::ProveLeg {
            plan_id: id,
            index: 1,
            evidence: SECRET.to_vec(),
            network_fee: 0,
        };
        let err = b
            .send(&[5; 32], reveal.clone(), T0 + 1_000)
            .await
            .unwrap_err();
        assert!(
            err.contains("only by the transaction that commits"),
            "{err}"
        );
        assert!(
            read_leg_evidence(&b.state, &leg_id(&id, 1))
                .unwrap()
                .preimage
                .is_none()
        );
        let wrong = PlanOp::ProveLeg {
            plan_id: id,
            index: 1,
            evidence: [0x5f; 32].to_vec(),
            network_fee: 0,
        };
        assert!(
            b.send(&[5; 32], wrong, T0 + 1_000)
                .await
                .unwrap_err()
                .contains("does not hash")
        );

        // Once the other leg is in, the reveal is the commit.
        seed_evidence(&mut b, &id, 2, LegClass::Attested);
        b.send(&[5; 32], reveal.clone(), T0 + 2_000).await.unwrap();
        assert!(read_decision(&b.state, &id).unwrap().commit);
        let ev = read_leg_evidence(&b.state, &leg_id(&id, 1)).unwrap();
        assert_eq!(ev.preimage.as_deref(), Some(hex::encode(SECRET).as_str()));
        assert!(
            b.send(&[5; 32], reveal, T0 + 3_000).await.is_err(),
            "decided"
        );
    }

    #[tokio::test]
    async fn an_acknowledged_ibc_transfer_commits_and_a_timed_out_one_aborts() {
        use tenzro_bridge::route::ibc_core::{DELIVERED, REFUNDED};
        for (marker, commits) in [(DELIVERED, true), (REFUNDED, false)] {
            let mut b = Book::new();
            let (_, commit_key) = ibc_packet_sent(&mut b, 3 * TNZO);
            let before = b.balance(&Address::new(PAYER));
            let id = b
                .send(
                    &PAYER,
                    open(1, vec![native(TNZO), ibc_leg()], T0 + 600_000),
                    T0,
                )
                .await
                .unwrap();
            assert_eq!(
                read_plan(&b.state, &id).unwrap().tier,
                AtomicityTier::IbcTransfer
            );
            let prove = PlanOp::ProveLeg {
                plan_id: id,
                index: 1,
                evidence: Vec::new(),
                network_fee: 0,
            };
            assert!(
                b.send(&[5; 32], prove.clone(), T0 + 1_000).await.is_err(),
                "the packet is in flight"
            );
            b.state
                .set_storage(&SYSTEM_ADDRESS, &commit_key, marker.to_vec());
            b.send(&[5; 32], prove, T0 + 2_000).await.unwrap();
            let decision = read_decision(&b.state, &id).unwrap();
            assert_eq!(decision.commit, commits);
            if commits {
                let receipt = read_leg_receipt(&b.state, &leg_id(&id, 1)).unwrap();
                assert_eq!(receipt.amount, 3 * TNZO);
                assert_eq!(receipt.class_achieved, Some(LegClass::Proven));
                assert!(b.balance(&Address::new([1; 32])) > 0);
            } else {
                assert_eq!(b.balance(&Address::new(PAYER)), before);
            }
        }
    }

    #[tokio::test]
    async fn another_accounts_packet_cannot_be_a_plans_leg() {
        let mut b = Book::new();
        ibc_packet_sent(&mut b, TNZO);
        const OTHER: [u8; 32] = [8; 32];
        b.state.set_balance(&OTHER, 10 * TNZO);
        let refused = b
            .send(
                &OTHER,
                open(1, vec![native(TNZO), ibc_leg()], T0 + 600_000),
                T0,
            )
            .await;
        assert!(
            refused
                .unwrap_err()
                .contains("not sent by the plan's payer")
        );
        assert_eq!(b.balance(&Address::new(OTHER)), 10 * TNZO);
    }
    #[tokio::test]
    async fn a_hash_locked_leg_escrows_its_premium_and_a_commit_returns_it() {
        let mut b = Book::new();
        let start = b.balance(&Address::new(PAYER));
        let mut cheap = hash_locked(LATE);
        if let LegKind::HashLocked { premium, .. } = &mut cheap.kind {
            *premium = TNZO / 200;
        }
        let err = b
            .send(&PAYER, open(1, vec![native(TNZO), cheap], T0 + 600_000), T0)
            .await
            .unwrap_err();
        assert!(
            err.contains("escrows at least 10000000000000000 wei"),
            "{err}"
        );

        let id = b
            .send(
                &PAYER,
                open(
                    2,
                    vec![native(TNZO), hash_locked(LATE), remote_lock(5)],
                    T0 + 600_000,
                ),
                T0,
            )
            .await
            .unwrap();
        assert_eq!(b.balance(&plan_vault_address(&id)), TNZO + PREMIUM);
        assert_eq!(b.balance(&Address::new(PAYER)), start - TNZO - PREMIUM);
        seed_evidence(&mut b, &id, 1, LegClass::Proven);
        seed_evidence(&mut b, &id, 2, LegClass::Attested);
        let reveal = PlanOp::ProveLeg {
            plan_id: id,
            index: 1,
            evidence: SECRET.to_vec(),
            network_fee: 0,
        };
        b.send(&[5; 32], reveal, T0 + 1_000).await.unwrap();
        let decision = read_decision(&b.state, &id).unwrap();
        assert!(decision.commit && decision.premium_paid.is_none());
        assert_eq!(b.balance(&Address::new(PAYER)), start - TNZO);
        assert_eq!(b.balance(&plan_vault_address(&id)), 0);
    }

    #[tokio::test]
    async fn a_funded_htlc_whose_preimage_is_withheld_pays_the_premium_by_the_split() {
        let mut b = Book::new();
        let start = b.balance(&Address::new(PAYER));
        let id = b
            .send(
                &PAYER,
                open(
                    1,
                    vec![native(TNZO), hash_locked(LATE), remote_lock(5)],
                    T0 + 600_000,
                ),
                T0,
            )
            .await
            .unwrap();
        seed_evidence(&mut b, &id, 1, LegClass::Proven);
        seed_evidence(&mut b, &id, 2, LegClass::Attested);
        let prove = PlanOp::ProveLeg {
            plan_id: id,
            index: 2,
            evidence: Vec::new(),
            network_fee: 0,
        };
        b.send(&[5; 32], prove, T0 + 1_000).await.unwrap();
        assert_eq!(
            read_plan(&b.state, &id).unwrap().status,
            PlanStatus::Open,
            "the preimage is still out"
        );

        let late = PlanOp::ProveLeg {
            plan_id: id,
            index: 1,
            evidence: Vec::new(),
            network_fee: 0,
        };
        b.send(&[5; 32], late, T0 + 700_000).await.unwrap();
        let decision = read_decision(&b.state, &id).unwrap();
        assert!(!decision.commit);
        let paid = decision.premium_paid.expect("the premium is paid");
        assert_eq!(paid.fee.fee, 0, "no second fee");
        assert_eq!(
            decision.recipients,
            vec![Address::new([2; 32]), Address::new([1; 32])]
        );
        assert_eq!(b.balance(&Address::new([2; 32])), PREMIUM * 3 / 10);
        assert_eq!(b.balance(&Address::new([1; 32])), PREMIUM * 7 / 10);
        assert_eq!(
            b.balance(&Address::new(PAYER)),
            start - PREMIUM,
            "the Tenzro value returns, the premium does not"
        );
        assert_eq!(b.balance(&plan_vault_address(&id)), 0);
    }

    #[tokio::test]
    async fn the_premium_returns_unless_the_withheld_preimage_was_all_that_was_missing() {
        // (HTLC funded, the other lock in): funded with a lock missing, and
        // every other leg in with the HTLC never funded.
        for (funded, other_in) in [(true, false), (false, true)] {
            let mut b = Book::new();
            begin_block(&mut b.state, T0).unwrap();
            let start = b.balance(&Address::new(PAYER));
            let deadline = T0 + 600_000;
            let id = b
                .send(
                    &PAYER,
                    open(
                        1,
                        vec![native(TNZO), hash_locked(LATE), remote_lock(5)],
                        deadline,
                    ),
                    T0,
                )
                .await
                .unwrap();
            if funded {
                seed_evidence(&mut b, &id, 1, LegClass::Proven);
            }
            if other_in {
                seed_evidence(&mut b, &id, 2, LegClass::Attested);
                let prove = PlanOp::ProveLeg {
                    plan_id: id,
                    index: 2,
                    evidence: Vec::new(),
                    network_fee: 0,
                };
                b.send(&[5; 32], prove, T0 + 1_000).await.unwrap();
            }
            assert_eq!(begin_block(&mut b.state, deadline + 60_000).unwrap(), 1);
            let decision = read_decision(&b.state, &id).unwrap();
            assert!(
                !decision.commit && decision.premium_paid.is_none(),
                "funded={funded} other_in={other_in}"
            );
            assert_eq!(b.balance(&Address::new(PAYER)), start);
            assert_eq!(b.balance(&Address::new([1; 32])), 0);
        }
    }

    #[tokio::test]
    async fn an_abort_in_block_execution_pays_a_submitter_line_to_a_named_one() {
        let mut b = Book::new();
        begin_block(&mut b.state, T0).unwrap();
        let mut split = rule();
        split.lines[0].recipient = SplitRecipient::LegSubmitter;
        let deadline = T0 + 600_000;
        let op = PlanOp::Open {
            nonce: 1,
            quote_digest: [9; 32],
            split_hash: split.hash(),
            split,
            legs: vec![native(TNZO), hash_locked(LATE), remote_lock(5)],
            decide_deadline_ms: deadline as u64,
            agent: None,
            attribution: None,
        };
        let id = b.send(&PAYER, op, T0).await.unwrap();
        seed_evidence(&mut b, &id, 1, LegClass::Proven);
        seed_evidence(&mut b, &id, 2, LegClass::Attested);
        b.send(
            &[5; 32],
            PlanOp::ProveLeg {
                plan_id: id,
                index: 2,
                evidence: Vec::new(),
                network_fee: 0,
            },
            T0 + 1_000,
        )
        .await
        .unwrap();
        assert_eq!(begin_block(&mut b.state, deadline + 60_000).unwrap(), 1);
        assert!(read_decision(&b.state, &id).unwrap().premium_paid.is_some());
        assert_eq!(b.balance(&Address::new([1; 32])), PREMIUM);
        assert_eq!(b.balance(&Address::new([0; 32])), 0);
    }

    const MACHINE: &str = "did:tenzro:machine:serving";

    /// A delegated agent whose terms allow plans up to `cap` wei a
    /// transaction, served by one node, with 10 TNZO in its wallet.
    fn plan_agent(b: &mut Book, cap: u128) -> (String, p256::ecdsa::SigningKey) {
        plan_agent_with(b, cap, Vec::new())
    }

    /// Ether on the test lock route.
    const ETH: &str = "eip155:1/slip44:60";

    /// The CCIP route to `ethereum` the remote-lock legs name, its native
    /// coin named `native`.
    fn lock_route(b: &mut Book, native: Option<&str>) {
        use tenzro_types::bridge_route::{ChainFamily, MintRateLimit, VerifierQuorum};
        let route = tenzro_types::bridge_route::BridgeRoute {
            adapter: BridgeRouteAdapter::Ccip,
            family: ChainFamily::Evm,
            source_chain: "ethereum".into(),
            source_chain_id: 1,
            local_selector: 7_777,
            peer: [1; 32],
            ramp: [2; 32],
            local_endpoint: [3; 32],
            remote_token: [4; 32],
            verifiers: VerifierQuorum {
                set_index: 0,
                size: 0,
                members: Vec::new(),
                threshold: 0,
            },
            blessing: None,
            light_client: None,
            mint_limit: MintRateLimit {
                per_mint: u128::MAX,
                per_epoch: u128::MAX,
            },
            outflow: tenzro_types::bridge_route::LaneRateLimit {
                capacity: u128::MAX,
                rate: u128::MAX / 2,
            },
            lane_limits: None,
            ibc: None,
            settlement_lock: Some([5; 32]),
            native_asset: native.map(str::to_string),
            assets: Vec::new(),
        };
        let key = tenzro_types::bridge_route::bridge_route_storage_key(
            BridgeRouteAdapter::Ccip,
            "ethereum",
        );
        b.state.set_storage(
            &SYSTEM_ADDRESS,
            key.as_bytes(),
            serde_json::to_vec(&route).unwrap(),
        );
    }

    fn plan_agent_with(
        b: &mut Book,
        cap: u128,
        asset_limits: Vec<tenzro_types::agent_terms::AssetLimit>,
    ) -> (String, p256::ecdsa::SigningKey) {
        lock_route(b, Some(ETH));
        let remote = vec![tenzro_types::agent_terms::RemoteLimit {
            caip19: ETH.into(),
            max_per_day: "1000000".into(),
        }];
        plan_agent_scoped(b, cap, asset_limits, remote)
    }

    fn plan_agent_scoped(
        b: &mut Book,
        cap: u128,
        asset_limits: Vec<tenzro_types::agent_terms::AssetLimit>,
        remote_limits: Vec<tenzro_types::agent_terms::RemoteLimit>,
    ) -> (String, p256::ecdsa::SigningKey) {
        use tenzro_types::agent_terms::{AgentTerms, ServingNode, TermsScope};
        crate::native::economy::count_wei_as_units_for_tests(&mut b.state);
        let key = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let point = key.verifying_key().to_sec1_point(false);
        let terms = AgentTerms {
            controller_did: "did:tenzro:human:ctl".into(),
            agent_name: "settler".into(),
            delegation_scope: TermsScope {
                allowed_operations: vec![tenzro_types::agent_terms::OP_SETTLEMENT_PLAN.into()],
                max_transaction_value: Some(cap.to_string()),
                asset_limits,
                remote_limits,
                ..Default::default()
            },
            capabilities: vec![],
            serving_nodes: vec![ServingNode {
                machine_did: MACHINE.into(),
                operator_did: "did:tenzro:human:op".into(),
                dpop_public_key: hex::encode(&point.as_bytes()[1..]),
                ..Default::default()
            }],
            min_distinct_operators: 1,
            expires_at_ms: None,
            trifecta_exception: false,
            auto_approve: None,
            credentials: Vec::new(),
        };
        let did =
            tenzro_types::agent_terms::agent_did(&terms.controller_did, &terms.agent_name).unwrap();
        let record = super::super::super::agent_terms::StoredAgentTerms {
            terms,
            root: tenzro_types::agent_terms::RootKind::Passkey,
            version: 1,
            approval_digest: String::new(),
            updated_at_ms: 0,
            renewed_at_ms: Some(T0),
        };
        write_json(
            &mut b.state,
            &super::super::super::agent_terms::terms_key(&did),
            &record,
            &mut Vec::new(),
        )
        .unwrap();
        b.state.set_balance(
            super::super::super::derive_bond_vault_address(&did).as_bytes(),
            1_000_000 * TNZO,
        );
        b.state
            .set_balance(&tenzro_types::agent_terms::agent_wallet(&did), 10 * TNZO);
        (did, key)
    }

    fn plan_action(
        b: &Book,
        did: &str,
        key: &p256::ecdsa::SigningKey,
        amount: u128,
        usd_e6: u64,
    ) -> tenzro_types::agent_terms::AgentAuthorization {
        plan_action_in(b, did, key, None, amount, usd_e6)
    }

    fn plan_action_in(
        b: &Book,
        did: &str,
        key: &p256::ecdsa::SigningKey,
        asset: Option<String>,
        amount: u128,
        usd_e6: u64,
    ) -> tenzro_types::agent_terms::AgentAuthorization {
        use p256::ecdsa::signature::hazmat::PrehashSigner;
        let action = tenzro_types::agent_terms::AgentAction {
            agent_did: did.into(),
            machine_did: MACHINE.into(),
            operation: tenzro_types::agent_terms::OP_SETTLEMENT_PLAN.into(),
            counterparty: String::new(),
            amount,
            asset,
            usd_e6,
            payment: None,
            chain: String::new(),
            payment_protocol: None,
            model: None,
            calls: Vec::new(),
            escrow: None,
            remote_grant: None,
            ballot: None,
            veto_signal: None,
            nonce: super::super::super::agent_terms::read_agent_act_nonce(&b.state, did),
            tainted: false,
            step_up: None,
        };
        let sig: p256::ecdsa::Signature = key.sign_prehash(&action.digest()).unwrap();
        tenzro_types::agent_terms::AgentAuthorization {
            action,
            signature: sig.to_bytes().to_vec(),
        }
    }

    fn agent_open(
        nonce: u64,
        legs: Vec<Leg>,
        auth: tenzro_types::agent_terms::AgentAuthorization,
    ) -> PlanOp {
        let PlanOp::Open {
            split,
            split_hash,
            quote_digest,
            decide_deadline_ms,
            ..
        } = open(nonce, Vec::new(), T0 + 600_000)
        else {
            unreachable!()
        };
        PlanOp::Open {
            nonce,
            quote_digest,
            split_hash,
            split,
            legs,
            decide_deadline_ms,
            agent: Some(auth),
            attribution: None,
        }
    }

    #[tokio::test]
    async fn an_agent_plan_counts_every_leg_against_the_terms() {
        let mut b = Book::new();
        crate::native::economy::count_wei_as_units_for_tests(&mut b.state);
        let legs = || vec![native(TNZO), remote_lock(5)];
        let off_usd = remote_lock(5).usd_e6;
        let total = TNZO + super::super::usd_e6_to_wei(&b.state, off_usd);
        assert!(total > TNZO, "the leg off Tenzro carries value");

        // The Tenzro leg alone fits the cap; the plan's whole value does not.
        let (did, key) = plan_agent(&mut b, total - 1);
        let auth = plan_action(&b, &did, &key, total, off_usd);
        let err = b
            .send(&PAYER, agent_open(1, legs(), auth), T0)
            .await
            .unwrap_err();
        assert!(err.contains("outside the agent's approved terms"), "{err}");
        // Understating the value to the Tenzro leg alone is refused too.
        let auth = plan_action(&b, &did, &key, TNZO, 0);
        let err = b
            .send(&PAYER, agent_open(2, legs(), auth), T0)
            .await
            .unwrap_err();
        assert!(err.contains("whole value"), "{err}");
        // A plan action never rides an ordinary agent action.
        let auth = plan_action(&b, &did, &key, total, off_usd);
        assert!(
            super::super::super::agent_terms::act(
                &mut b.state,
                1,
                &auth.action,
                &auth.signature,
                T0
            )
            .is_err()
        );

        // Within the cap the plan opens from the agent's wallet and the
        // whole value is spent from the day's budget.
        let mut b = Book::new();
        let (did, key) = plan_agent(&mut b, total);
        let wallet = Address::new(tenzro_types::agent_terms::agent_wallet(&did));
        let auth = plan_action(&b, &did, &key, total, off_usd);
        let id = b
            .send(&PAYER, agent_open(1, legs(), auth), T0)
            .await
            .unwrap();
        assert_eq!(read_plan(&b.state, &id).unwrap().opened_by, wallet);
        assert_eq!(b.balance(&wallet), 9 * TNZO);
        assert_eq!(
            super::super::super::agent_terms::read_agent_spent(&b.state, &did, T0 as u64),
            total
        );
    }

    #[tokio::test]
    async fn an_agent_plan_holds_facilitator_and_relayer_lines_to_the_terms() {
        let mut b = Book::new();
        let (did, key) = plan_agent(&mut b, 10 * TNZO);
        let key_slot = super::super::super::agent_terms::terms_key(&did);
        let mut stored =
            super::super::super::agent_terms::read_agent_terms(&b.state, &did).unwrap();
        stored.terms.delegation_scope.max_split_fee_bps = Some(150);
        write_json(&mut b.state, &key_slot, &stored, &mut Vec::new()).unwrap();
        let with_fees = |facilitator: u16| {
            let mut split = rule();
            split.lines.push(SplitLine {
                role: SplitRole::Facilitator,
                recipient: SplitRecipient::Address(Address::new([5; 32])),
                basis: SplitBasis::Bps(facilitator),
                cap: None,
            });
            split.lines.push(SplitLine {
                role: SplitRole::Relayer,
                recipient: SplitRecipient::Address(Address::new([6; 32])),
                basis: SplitBasis::Bps(50),
                cap: None,
            });
            split
        };
        let open_with = |nonce: u64, split: SplitRule, auth| PlanOp::Open {
            nonce,
            quote_digest: [9; 32],
            split_hash: split.hash(),
            split,
            legs: vec![native(TNZO)],
            decide_deadline_ms: (T0 + 600_000) as u64,
            agent: Some(auth),
            attribution: None,
        };

        // 101 + 50 bps is above the Terms' 150: refused, nothing spent.
        let auth = plan_action(&b, &did, &key, TNZO, 0);
        let err = b
            .send(&PAYER, open_with(1, with_fees(101), auth), T0)
            .await
            .unwrap_err();
        assert!(
            err.contains("facilitator and relayer lines can take more than 150 bps"),
            "{err}"
        );
        assert_eq!(
            super::super::super::agent_terms::read_agent_spent(&b.state, &did, T0 as u64),
            0
        );
        // 100 + 50 bps is within them.
        let auth = plan_action(&b, &did, &key, TNZO, 0);
        b.send(&PAYER, open_with(2, with_fees(100), auth), T0)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn an_agent_plan_holds_external_legs_to_the_terms_asset_limits() {
        use tenzro_types::agent_terms::RemoteLimit;
        let off_usd = remote_lock(5).usd_e6;
        let book = || {
            let mut b = Book::new();
            lock_route(&mut b, Some(ETH));
            b
        };
        let open_with =
            |b: &Book, did: &str, key: &p256::ecdsa::SigningKey, nonce: u64, leg: Leg| {
                let total = TNZO + super::super::usd_e6_to_wei(&b.state, off_usd);
                agent_open(
                    nonce,
                    vec![native(TNZO), leg],
                    plan_action(b, did, key, total, off_usd),
                )
            };
        let limit = |per_day: &str| {
            vec![RemoteLimit {
                caip19: ETH.into(),
                max_per_day: per_day.into(),
            }]
        };

        // The lock's coin is named by the route's CAIP-19 id and counted
        // against its daily limit in the terms, beside the wei limits.
        let mut b = book();
        let (did, key) = plan_agent_scoped(&mut b, 100 * TNZO, Vec::new(), limit("7"));
        let op = open_with(&b, &did, &key, 1, remote_lock(5));
        b.send(&PAYER, op, T0).await.unwrap();
        assert_eq!(
            super::super::super::remote_grant::read_remote_spent(&b.state, &did, ETH, T0 as u64),
            5
        );
        let op = open_with(&b, &did, &key, 2, remote_lock(3));
        let err = b.send(&PAYER, op, T0).await.unwrap_err();
        assert!(
            err.contains("the daily limit on eip155:1/slip44:60"),
            "{err}"
        );
        let op = open_with(&b, &did, &key, 3, remote_lock(2));
        b.send(&PAYER, op, T0).await.unwrap();
        assert_eq!(
            super::super::super::remote_grant::read_remote_spent(&b.state, &did, ETH, T0 as u64),
            7
        );

        // An asset the terms do not list is refused.
        let mut b = book();
        let (did, key) = plan_agent_scoped(&mut b, 100 * TNZO, Vec::new(), Vec::new());
        let op = open_with(&b, &did, &key, 1, remote_lock(5));
        let err = b.send(&PAYER, op, T0).await.unwrap_err();
        assert!(
            err.contains("outside the agent's approved terms: asset eip155:1/slip44:60"),
            "{err}"
        );

        // A token the route names no CAIP-19 id for cannot be held to the
        // terms, so an agent's leg in it is refused.
        let mut b = book();
        let (did, key) = plan_agent_scoped(&mut b, 100 * TNZO, Vec::new(), limit("7"));
        let mut leg = remote_lock(5);
        if let LegKind::RemoteLock { asset, .. } = &mut leg.kind {
            *asset = [9; 32];
        }
        let op = open_with(&b, &did, &key, 1, leg);
        let err = b.send(&PAYER, op, T0).await.unwrap_err();
        assert!(err.contains("names no CAIP-19 id"), "{err}");
        let mut b = Book::new();
        lock_route(&mut b, None);
        let (did, key) = plan_agent_scoped(&mut b, 100 * TNZO, Vec::new(), limit("7"));
        let op = open_with(&b, &did, &key, 1, remote_lock(5));
        let err = b.send(&PAYER, op, T0).await.unwrap_err();
        assert!(err.contains("names no CAIP-19 id"), "{err}");

        // A plan opened by anyone else is not an agent's and takes no count.
        let mut b = Book::new();
        b.send(
            &PAYER,
            open(1, vec![native(TNZO), remote_lock(5)], T0 + 600_000),
            T0,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_quarantined_agents_open_plan_aborts_and_refunds_its_wallet() {
        let mut b = Book::new();
        crate::native::economy::count_wei_as_units_for_tests(&mut b.state);
        begin_block(&mut b.state, T0).unwrap();
        let legs = vec![native(TNZO), remote_lock(5)];
        let off_usd = remote_lock(5).usd_e6;
        let total = TNZO + super::super::usd_e6_to_wei(&b.state, off_usd);
        let (did, key) = plan_agent(&mut b, total);
        let wallet = Address::new(tenzro_types::agent_terms::agent_wallet(&did));
        let auth = plan_action(&b, &did, &key, total, off_usd);
        let id = b.send(&PAYER, agent_open(1, legs, auth), T0).await.unwrap();
        let plan = read_plan(&b.state, &id).unwrap();
        assert_eq!(plan.status, PlanStatus::Open);
        assert_eq!(plan.agent_did.as_deref(), Some(did.as_str()));
        assert_eq!(b.balance(&wallet), 9 * TNZO);

        let quarantine = super::super::super::agent_audit::AgentQuarantine {
            controller_did: "did:tenzro:human:ctl".into(),
            by: String::new(),
            reason_code: 1,
            evidence_hash: None,
            at_ms: T0 + 1_000,
            revoked: false,
        };
        super::super::super::agent_audit::impose(
            &mut b.state,
            &did,
            &quarantine,
            &mut Vec::new(),
            &mut Vec::new(),
        )
        .unwrap();
        let plan = read_plan(&b.state, &id).unwrap();
        assert_eq!(plan.status, PlanStatus::Aborted);
        assert_eq!(
            plan.decision.unwrap().reason.as_deref(),
            Some("the agent's authority was withdrawn")
        );
        assert_eq!(b.balance(&wallet), 10 * TNZO);
        assert_eq!(b.state.get_balance(plan_vault_address(&id).as_bytes()), 0);
        assert!(read_agent_plans(&b.state, &did).is_empty());
        // The deadline sweep later finds nothing left to abort.
        sweep(&mut b, T0 + 700_000);
        assert_eq!(b.balance(&wallet), 10 * TNZO);
    }

    const RESERVE: u128 = 5 * TNZO;
    const RAIL_PAYEE: [u8; 32] = [0x51; 32];
    const ATTESTOR: [u8; 32] = [0x52; 32];
    const WINDOW: i64 = DEFAULT_COMPENSATION_WINDOW_MS as i64;

    fn rail(attestor: Option<[u8; 32]>) -> Leg {
        Leg {
            kind: LegKind::RailInstruction {
                rail: tenzro_types::settlement::RailKind::Iso20022,
                instruction_digest: [0x33; 32],
                currency: "EUR".into(),
                amount_minor: 125_000,
                payee: Address::new(RAIL_PAYEE),
                attestor: attestor.map(Address::new),
                reserve: RESERVE,
            },
            class_required: LegClass::Attested,
            usd_e6: 1_350_000_000,
            max_network_fee: 0,
        }
    }

    /// A plan with a Tenzro leg and a rail leg, committed at `T0`.
    async fn committed_rail_plan(b: &mut Book, attestor: Option<[u8; 32]>) -> [u8; 32] {
        begin_block(&mut b.state, T0).unwrap();
        if attestor.is_some() {
            crate::native::role_stake::bond_role_for_test(
                &mut b.state,
                &ATTESTOR,
                NetworkRole::Attestor,
                tenzro_types::constants::MIN_ATTESTOR_STAKE,
            );
        }
        let id = b
            .send(
                &PAYER,
                open(1, vec![native(10 * TNZO), rail(attestor)], T0 + 60_000),
                T0,
            )
            .await
            .unwrap();
        assert_eq!(
            read_plan(&b.state, &id).unwrap().status,
            PlanStatus::Committed
        );
        assert_eq!(
            read_plan(&b.state, &id).unwrap().tier,
            AtomicityTier::Compensated
        );
        assert_eq!(
            b.state.get_balance(plan_vault_address(&id).as_bytes()),
            RESERVE
        );
        id
    }

    fn prove(plan_id: [u8; 32], index: u8, evidence: &[u8]) -> PlanOp {
        PlanOp::ProveLeg {
            plan_id,
            index,
            evidence: evidence.to_vec(),
            network_fee: 0,
        }
    }

    /// Block execution at `at`, enough blocks for the due walk to catch up.
    fn sweep(b: &mut Book, at: i64) {
        for _ in 0..=(WINDOW as u64 / MINUTE_MS / MAX_DUE_MINUTES_PER_BLOCK) {
            begin_block(&mut b.state, at).unwrap();
        }
    }

    fn attestor_bond(b: &Book) -> u128 {
        crate::native::role_stake::read_role_stake(&b.state, &ATTESTOR, NetworkRole::Attestor)
            .unwrap()
            .bonded
    }

    #[tokio::test]
    async fn an_unconfirmed_rail_leg_compensates_its_payee_and_slashes_its_attestor() {
        let mut b = Book::new();
        let id = committed_rail_plan(&mut b, Some(ATTESTOR)).await;
        let pool = super::super::super::derive_insurance_pool_address();
        let pool_before = b.balance(&pool);
        // Nothing ends before the window closes.
        sweep(&mut b, T0 + WINDOW - MINUTE_MS as i64);
        assert_eq!(b.balance(&Address::new(RAIL_PAYEE)), 0);
        sweep(&mut b, T0 + WINDOW + 2 * MINUTE_MS as i64);
        assert_eq!(b.balance(&Address::new(RAIL_PAYEE)), RESERVE);
        let bond = tenzro_types::constants::MIN_ATTESTOR_STAKE;
        let slashed = bond / 10;
        assert_eq!(attestor_bond(&b), bond - slashed);
        assert_eq!(b.balance(&pool) - pool_before, slashed);
        let receipt = read_leg_receipt(&b.state, &leg_id(&id, 1)).unwrap();
        assert_eq!(receipt.compensation, Some(RESERVE));
        assert_eq!(receipt.class_achieved, None);
        // A confirmation after the window is refused.
        assert!(
            b.send(
                &ATTESTOR,
                prove(id, 1, b"camt.054"),
                T0 + WINDOW + 3 * MINUTE_MS as i64
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn a_rail_leg_confirmed_after_the_commit_returns_the_reserve_when_its_window_closes() {
        let mut b = Book::new();
        let id = committed_rail_plan(&mut b, Some(ATTESTOR)).await;
        let payer_before = b.balance(&Address::new(PAYER));
        // Only the attestor confirms.
        assert!(
            b.send(&RAIL_PAYEE, prove(id, 1, b"camt.054"), T0 + 1_000)
                .await
                .is_err()
        );
        b.send(&ATTESTOR, prove(id, 1, b"camt.054"), T0 + WINDOW / 2)
            .await
            .unwrap();
        assert!(
            b.send(&ATTESTOR, prove(id, 1, b"camt.054 again"), T0 + WINDOW / 2)
                .await
                .is_err()
        );
        // Held for the payee's dispute until the window closes.
        assert_eq!(
            b.state.get_balance(plan_vault_address(&id).as_bytes()),
            RESERVE
        );
        sweep(&mut b, T0 + WINDOW + 2 * MINUTE_MS as i64);
        assert_eq!(b.balance(&Address::new(PAYER)) - payer_before, RESERVE);
        assert_eq!(
            attestor_bond(&b),
            tenzro_types::constants::MIN_ATTESTOR_STAKE
        );
        let receipt = read_leg_receipt(&b.state, &leg_id(&id, 1)).unwrap();
        assert_eq!(receipt.class_achieved, Some(LegClass::Attested));
        assert_eq!(
            receipt.proof_digest,
            Some(Sha256::digest(b"camt.054").into())
        );
        assert_eq!(receipt.compensation, None);
    }

    #[tokio::test]
    async fn a_payee_dispute_inside_the_window_compensates_it_and_slashes_the_attestor() {
        let mut b = Book::new();
        let id = committed_rail_plan(&mut b, Some(ATTESTOR)).await;
        let dispute = || PlanOp::DisputeRail {
            plan_id: id,
            index: 1,
            evidence: b"return notice".to_vec(),
        };
        // Nothing to dispute before the attestor confirms.
        assert!(b.send(&RAIL_PAYEE, dispute(), T0 + 1_000).await.is_err());
        b.send(&ATTESTOR, prove(id, 1, b"camt.054"), T0 + 2_000)
            .await
            .unwrap();
        assert!(b.send(&PAYER, dispute(), T0 + 3_000).await.is_err());
        b.send(&RAIL_PAYEE, dispute(), T0 + 3_000).await.unwrap();
        assert_eq!(b.balance(&Address::new(RAIL_PAYEE)), RESERVE);
        let bond = tenzro_types::constants::MIN_ATTESTOR_STAKE;
        assert_eq!(attestor_bond(&b), bond - bond / 10);
        assert!(b.send(&RAIL_PAYEE, dispute(), T0 + 4_000).await.is_err());
        // The window's close finds the leg ended.
        sweep(&mut b, T0 + WINDOW + 2 * MINUTE_MS as i64);
        assert_eq!(attestor_bond(&b), bond - bond / 10);
        assert_eq!(b.state.get_balance(plan_vault_address(&id).as_bytes()), 0);
    }

    #[tokio::test]
    async fn a_payee_confirmation_ends_its_rail_leg_at_once() {
        let mut b = Book::new();
        let id = committed_rail_plan(&mut b, None).await;
        let payer_before = b.balance(&Address::new(PAYER));
        assert!(
            b.send(&PAYER, prove(id, 1, b"receipt"), T0 + 1_000)
                .await
                .is_err()
        );
        b.send(&RAIL_PAYEE, prove(id, 1, b"receipt"), T0 + 1_000)
            .await
            .unwrap();
        assert_eq!(b.balance(&Address::new(PAYER)) - payer_before, RESERVE);
        assert!(
            b.send(
                &RAIL_PAYEE,
                PlanOp::DisputeRail {
                    plan_id: id,
                    index: 1,
                    evidence: b"x".to_vec()
                },
                T0 + 2_000
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn a_rail_leg_needs_a_bonded_attestor_and_stays_under_the_attested_cap() {
        let mut b = Book::new();
        assert!(
            b.send(
                &PAYER,
                open(1, vec![native(TNZO), rail(Some(ATTESTOR))], T0 + 60_000),
                T0
            )
            .await
            .is_err()
        );
        let mut big = rail(None);
        big.usd_e6 = super::super::DEFAULT_ATTESTED_CAP_USD_E6 + 1;
        assert!(
            b.send(&PAYER, open(2, vec![native(TNZO), big], T0 + 60_000), T0)
                .await
                .is_err()
        );
        let mut proven = rail(None);
        proven.class_required = LegClass::Proven;
        assert!(
            b.send(&PAYER, open(3, vec![native(TNZO), proven], T0 + 60_000), T0)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn an_aborted_plan_returns_its_rail_reserve() {
        let mut b = Book::new();
        begin_block(&mut b.state, T0).unwrap();
        let before = b.balance(&Address::new(PAYER));
        let id = b
            .send(
                &PAYER,
                open(
                    1,
                    vec![native(TNZO), remote_lock(1_000), rail(None)],
                    T0 + 60_000,
                ),
                T0,
            )
            .await
            .unwrap();
        assert_eq!(read_plan(&b.state, &id).unwrap().status, PlanStatus::Open);
        begin_block(&mut b.state, T0 + 3 * MINUTE_MS as i64).unwrap();
        assert_eq!(
            read_plan(&b.state, &id).unwrap().status,
            PlanStatus::Aborted
        );
        assert_eq!(b.balance(&Address::new(PAYER)), before);
        assert!(read_rail(&b.state, &leg_id(&id, 2)).is_none());
    }

    fn netted(amount: u128) -> Leg {
        Leg {
            kind: LegKind::Netted {
                asset: crate::token_ledger::tnzo_id(),
                amount,
            },
            class_required: LegClass::Native,
            usd_e6: 0,
            max_network_fee: 0,
        }
    }

    fn netted_open(nonce: u64, split: SplitRule, amount: u128) -> PlanOp {
        PlanOp::Open {
            nonce,
            quote_digest: [9; 32],
            split_hash: split.hash(),
            split,
            legs: vec![netted(amount)],
            decide_deadline_ms: (T0 + 60_000) as u64,
            agent: None,
            attribution: None,
        }
    }

    fn post(amount: u128) -> PlanOp {
        PlanOp::PostCollateral {
            asset: crate::token_ledger::tnzo_id(),
            amount,
            agent: None,
        }
    }

    /// An agent nets from its own wallet under its terms: the collateral it
    /// posts (the most its net debit can reach) and each netted plan's gross
    /// count against its caps, refused over them and admitted within.
    #[tokio::test]
    async fn an_agent_nets_within_its_terms() {
        use super::super::netting::{collateral_vault, latest_seq, read_batch};
        let tnzo = crate::token_ledger::tnzo_id();
        let mut b = Book::new();
        let (did, key) = plan_agent(&mut b, 5 * TNZO);
        let wallet = Address::new(tenzro_types::agent_terms::agent_wallet(&did));
        let posting = |auth, amount| PlanOp::PostCollateral {
            asset: tnzo,
            amount,
            agent: Some(auth),
        };

        // Collateral over the cap is refused; within it, it leaves the
        // agent's wallet for the agent's vault and is spent from its budget.
        let auth = plan_action(&b, &did, &key, 6 * TNZO, 0);
        let err = b
            .send(&PAYER, posting(auth, 6 * TNZO), T0)
            .await
            .unwrap_err();
        assert!(err.contains("outside the agent's approved terms"), "{err}");
        let auth = plan_action(&b, &did, &key, 3 * TNZO, 0);
        let err = b
            .send(&PAYER, posting(auth, 4 * TNZO), T0)
            .await
            .unwrap_err();
        assert!(err.contains("collateral's asset"), "{err}");
        let auth = plan_action(&b, &did, &key, 4 * TNZO, 0);
        b.send(&PAYER, posting(auth, 4 * TNZO), T0).await.unwrap();
        assert_eq!(b.balance(&collateral_vault(&wallet, &tnzo)), 4 * TNZO);
        assert_eq!(b.balance(&wallet), 6 * TNZO);
        assert_eq!(
            super::super::super::agent_terms::read_agent_spent(&b.state, &did, T0 as u64),
            4 * TNZO
        );

        let to = Address::new([3; 32]);
        let netted_agent = |nonce, amount, auth| {
            let PlanOp::Open {
                split,
                split_hash,
                quote_digest,
                decide_deadline_ms,
                legs,
                ..
            } = netted_open(nonce, SplitRule::sole(SplitRole::Payee, to), amount)
            else {
                unreachable!()
            };
            PlanOp::Open {
                nonce,
                quote_digest,
                split_hash,
                split,
                legs,
                decide_deadline_ms,
                agent: Some(auth),
                attribution: None,
            }
        };
        // A plan's gross over the cap is refused, and so is an understated one.
        let auth = plan_action(&b, &did, &key, 6 * TNZO, 0);
        let err = b
            .send(&PAYER, netted_agent(1, 6 * TNZO, auth), T0)
            .await
            .unwrap_err();
        assert!(err.contains("outside the agent's approved terms"), "{err}");
        let auth = plan_action(&b, &did, &key, TNZO, 0);
        let err = b
            .send(&PAYER, netted_agent(1, 2 * TNZO, auth), T0)
            .await
            .unwrap_err();
        assert!(err.contains("states its gross"), "{err}");
        // Within the cap the agent's wallet owes the payee in the batch.
        let auth = plan_action(&b, &did, &key, 2 * TNZO, 0);
        let id = b
            .send(&PAYER, netted_agent(1, 2 * TNZO, auth), T0)
            .await
            .unwrap();
        assert_eq!(read_plan(&b.state, &id).unwrap().opened_by, wallet);
        let batch = read_batch(&b.state, &tnzo, latest_seq(&b.state, &tnzo).unwrap()).unwrap();
        assert!(
            batch
                .obligations
                .iter()
                .all(|o| o.debtor == wallet && o.creditor == to)
        );
        assert_eq!(
            super::super::super::agent_terms::read_agent_spent(&b.state, &did, T0 as u64),
            6 * TNZO
        );

        // A withdrawal returns to the agent's wallet and states no value.
        let auth = plan_action(&b, &did, &key, 0, 0);
        let fee = read_decision(&b.state, &id)
            .unwrap()
            .allocation
            .unwrap()
            .fee
            .fee;
        let free = 4 * TNZO - fee - batch.obligations.iter().map(|o| o.amount).sum::<u128>();
        let op = PlanOp::WithdrawCollateral {
            asset: tnzo,
            amount: free,
            agent: Some(auth),
        };
        b.send(&PAYER, op, T0).await.unwrap();
        assert_eq!(b.balance(&wallet), 6 * TNZO + free);
    }

    /// An agent nets in a carried asset: every collateral post and netted
    /// plan names the asset, and the asset's own per-payment and daily limits
    /// in the terms count them beside the wei limits.
    #[tokio::test]
    async fn an_agent_nets_a_carried_asset_within_its_asset_limits() {
        use tenzro_types::agent_terms::AssetLimit;
        let mut b = Book::new();
        let issuer = super::super::super::bridge::deposit_issuer();
        let spec = crate::token_ledger::TokenRecord {
            name: "Dollar".into(),
            symbol: "USDX".into(),
            decimals: 6,
            total_supply: 0,
            creator: Vec::new(),
            max_supply: None,
            powers: tenzro_types::token_policy::PowerManifest::NONE,
            policy: tenzro_types::token_policy::TokenPolicy::default(),
            council: None,
            reserve_backing: None,
            pending: None,
        };
        let usdx =
            crate::token_ledger::create(&mut b.state, &issuer, &spec, &mut Vec::new()).unwrap();
        let named = Some(format!("0x{}", hex::encode(usdx)));
        let mut entry = tenzro_types::settlement_asset::SettlementAsset::new(
            named.as_deref().unwrap(),
            "USDX",
            "USD",
            6,
        );
        crate::native::settlement_asset::install_for_test(&mut b.state, &entry);
        crate::native::economy::write_symbol_rate_for_tests(&mut b.state, "USDX", 0, 1_000_000_000);
        let limit = AssetLimit {
            min_counterparty_kyc_tier: 0,
            asset: named.clone().unwrap(),
            max_per_tx: Some("3000".into()),
            max_per_day: "5000".into(),
        };
        let (did, key) = plan_agent_with(&mut b, 1_000 * TNZO, vec![limit]);
        let wallet = Address::new(tenzro_types::agent_terms::agent_wallet(&did));
        crate::token_ledger::mint(
            &mut b.state,
            &usdx,
            wallet.as_bytes(),
            10_000,
            0,
            &mut Vec::new(),
        )
        .unwrap();
        let posting = |auth, amount| PlanOp::PostCollateral {
            asset: usdx,
            amount,
            agent: Some(auth),
        };

        // A post that names no asset, or another one, is refused; one over
        // the asset's per-payment limit is outside the terms.
        let auth = plan_action_in(&b, &did, &key, None, 3000, 3000);
        let err = b.send(&PAYER, posting(auth, 3000), T0).await.unwrap_err();
        assert!(err.contains("collateral's asset"), "{err}");
        let auth = plan_action_in(
            &b,
            &did,
            &key,
            Some(format!("0x{}", hex::encode([5u8; 32]))),
            3000,
            3000,
        );
        let err = b.send(&PAYER, posting(auth, 3000), T0).await.unwrap_err();
        assert!(err.contains("collateral's asset"), "{err}");
        let auth = plan_action_in(&b, &did, &key, named.clone(), 4000, 4000);
        let err = b.send(&PAYER, posting(auth, 4000), T0).await.unwrap_err();
        assert!(err.contains("asset per-transaction limit"), "{err}");
        let auth = plan_action_in(&b, &did, &key, named.clone(), 3000, 3000);
        b.send(&PAYER, posting(auth, 3000), T0).await.unwrap();

        let to = Address::new([3; 32]);
        let netted_agent = |nonce, amount: u128, auth| {
            let split = SplitRule::sole(SplitRole::Payee, to);
            let leg = Leg {
                kind: LegKind::Netted {
                    asset: usdx,
                    amount,
                },
                class_required: LegClass::Native,
                usd_e6: amount as u64,
                max_network_fee: 0,
            };
            PlanOp::Open {
                nonce,
                quote_digest: [9; 32],
                split_hash: split.hash(),
                split,
                legs: vec![leg],
                decide_deadline_ms: (T0 + 60_000) as u64,
                agent: Some(auth),
                attribution: None,
            }
        };
        // A netted plan that names no asset is refused; the day's asset
        // total (3000 posted) leaves 2000: 2500 is outside the terms.
        let auth = plan_action_in(&b, &did, &key, None, 2000, 2000);
        let err = b
            .send(&PAYER, netted_agent(1, 2000, auth), T0)
            .await
            .unwrap_err();
        assert!(err.contains("names the netted plan's asset"), "{err}");
        let auth = plan_action_in(&b, &did, &key, named.clone(), 2500, 2500);
        let err = b
            .send(&PAYER, netted_agent(1, 2500, auth), T0)
            .await
            .unwrap_err();
        assert!(err.contains("asset daily limit"), "{err}");
        // A carried asset that may not settle is refused by name.
        entry.enabled = false;
        crate::native::settlement_asset::install_for_test(&mut b.state, &entry);
        let auth = plan_action_in(&b, &did, &key, named.clone(), 2000, 2000);
        let err = b
            .send(&PAYER, netted_agent(1, 2000, auth), T0)
            .await
            .unwrap_err();
        assert!(err.contains("disabled"), "{err}");
        entry.enabled = true;
        crate::native::settlement_asset::install_for_test(&mut b.state, &entry);
        let treasury = super::super::super::derive_treasury_address();
        let auth = plan_action_in(&b, &did, &key, named.clone(), 2000, 2000);
        b.send(&PAYER, netted_agent(1, 2000, auth), T0)
            .await
            .unwrap();
        // The fee was taken in the asset, and its burn share booked as
        // burn-equivalent for the epoch, as a settlement in kind books it.
        let fee = tenzro_types::split::fee_allocation(
            2000,
            &tenzro_types::split::FeeParams {
                min_fee: 1,
                ..crate::native::economy::fee_params(&b.state)
            },
        );
        assert!(fee.burn > 0);
        assert_eq!(
            crate::token_ledger::balance(&b.state, &usdx, treasury.as_bytes()),
            fee.treasury + fee.burn
        );
        let epoch = crate::native::economy::read_current_epoch(&b.state);
        let booked = crate::native::economy::read_epoch_activity(&b.state, epoch).burn_eq;
        assert!(booked > 0, "the burn share is booked as burn-equivalent");
        assert_eq!(
            booked,
            crate::native::settlement_asset::tnzo_eq(
                fee.burn,
                1_000_000_000,
                6,
                crate::native::economy::read_fee_rate(&b.state).rate_nano_usd,
                true
            )
        );
        let auth = plan_action_in(&b, &did, &key, named, 1, 1);
        let err = b
            .send(&PAYER, netted_agent(2, 1, auth), T0)
            .await
            .unwrap_err();
        assert!(err.contains("asset daily limit"), "{err}");
    }

    /// Two participants owe each other across a batch: the fee is taken on
    /// each plan's gross at commit, the batch settles only the net from
    /// collateral when its epoch ends, value is conserved, and each
    /// participant's gross-to-net statement verifies against the root.
    #[tokio::test]
    async fn a_netting_batch_settles_the_net_from_collateral() {
        use super::super::netting::{collateral_vault, latest_seq, read_batch};
        let tnzo = crate::token_ledger::tnzo_id();
        let (a, b_, c) = (
            Address::new(PAYER),
            Address::new([1; 32]),
            Address::new([2; 32]),
        );
        let mut b = Book::new();
        b.state.set_balance(b_.as_bytes(), 100 * TNZO);
        b.send(&PAYER, post(20 * TNZO), T0).await.unwrap();
        b.send(b_.as_bytes(), post(20 * TNZO), T0).await.unwrap();
        // A owes C 30% and B the rest of 10; B owes A all of 8.
        let p1 = b
            .send(&PAYER, netted_open(1, rule(), 10 * TNZO), T0)
            .await
            .unwrap();
        let p2 = b
            .send(
                b_.as_bytes(),
                netted_open(1, SplitRule::sole(SplitRole::Payee, a), 8 * TNZO),
                T0,
            )
            .await
            .unwrap();
        let fee1 = read_decision(&b.state, &p1)
            .unwrap()
            .allocation
            .unwrap()
            .fee
            .fee;
        let fee2 = read_decision(&b.state, &p2)
            .unwrap()
            .allocation
            .unwrap()
            .fee
            .fee;
        assert!(fee1 > 0 && fee2 > 0, "the fee is charged on gross");
        assert_eq!(b.balance(&collateral_vault(&a, &tnzo)), 20 * TNZO - fee1);
        // Nothing moved to the creditors yet.
        assert_eq!(b.balance(&c), 0);
        // A cannot withdraw what its net debit needs.
        let too_much = PlanOp::WithdrawCollateral {
            asset: tnzo,
            amount: 20 * TNZO - fee1,
            agent: None,
        };
        assert!(b.send(&PAYER, too_much, T0).await.is_err());

        let seq = latest_seq(&b.state, &tnzo).unwrap();
        let batch = read_batch(&b.state, &tnzo, seq).unwrap();
        let gross: u128 = batch.obligations.iter().map(|o| o.amount).sum();
        let before: u128 = [a, b_, c]
            .iter()
            .map(|x| b.balance(x) + b.balance(&collateral_vault(x, &tnzo)))
            .sum();
        sweep(&mut b, batch.closes_at_ms as i64);
        let after: u128 = [a, b_, c]
            .iter()
            .map(|x| b.balance(x) + b.balance(&collateral_vault(x, &tnzo)))
            .sum();
        assert_eq!(before, after, "settlement conserves the asset");

        let batch = read_batch(&b.state, &tnzo, seq).unwrap();
        let st = batch.settlement.clone().unwrap();
        assert_eq!(st.gross_total, gross);
        assert!(st.net_total < st.gross_total);
        assert!(st.defaults.is_empty());
        assert_eq!(
            st.paid,
            st.instructions.iter().map(|i| i.amount).collect::<Vec<_>>()
        );
        assert_eq!(
            b.balance(&c),
            batch
                .obligations
                .iter()
                .filter(|o| o.creditor == c)
                .map(|o| o.amount)
                .sum::<u128>()
        );
        let full = tenzro_settlement::netting::compute_batch(batch.obligations.clone()).unwrap();
        for who in [a, b_, c] {
            let stmt = tenzro_settlement::netting::statement(&full, &who);
            tenzro_settlement::netting::verify_statement(&st.obligations_root, &stmt).unwrap();
        }
        // Once settled, all the rest is free.
        let rest = b.balance(&collateral_vault(&a, &tnzo));
        b.send(
            &PAYER,
            PlanOp::WithdrawCollateral {
                asset: tnzo,
                amount: rest,
                agent: None,
            },
            batch.closes_at_ms as i64,
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn a_netted_plan_beyond_collateral_is_refused() {
        let mut b = Book::new();
        b.send(&PAYER, post(TNZO), T0).await.unwrap();
        let err = b
            .send(&PAYER, netted_open(1, rule(), 10 * TNZO), T0)
            .await
            .unwrap_err();
        assert!(err.contains("does not cover"), "{err}");
        let mixed = open(2, vec![netted(TNZO), native(TNZO)], T0 + 60_000);
        assert!(b.send(&PAYER, mixed, T0).await.is_err());
    }

    /// A debtor whose collateral was taken after admission defaults: what is
    /// left is shared pro rata over its instructions, the default is
    /// recorded, and it opens no netted plan again.
    #[tokio::test]
    async fn a_short_debtor_defaults_and_its_collateral_is_shared() {
        use super::super::netting::{collateral_vault, latest_seq, read_batch, read_defaults};
        let tnzo = crate::token_ledger::tnzo_id();
        let a = Address::new(PAYER);
        let mut b = Book::new();
        b.send(&PAYER, post(20 * TNZO), T0).await.unwrap();
        b.send(&PAYER, netted_open(1, rule(), 10 * TNZO), T0)
            .await
            .unwrap();
        let vault = collateral_vault(&a, &tnzo);
        b.state.set_balance(vault.as_bytes(), 5 * TNZO);
        let seq = latest_seq(&b.state, &tnzo).unwrap();
        let closes = read_batch(&b.state, &tnzo, seq).unwrap().closes_at_ms as i64;
        sweep(&mut b, closes);
        let st = read_batch(&b.state, &tnzo, seq)
            .unwrap()
            .settlement
            .unwrap();
        assert_eq!(st.defaults.len(), 1);
        assert_eq!(st.defaults[0].participant, a);
        assert_eq!(st.defaults[0].paid, 5 * TNZO);
        assert_eq!(st.paid.iter().sum::<u128>(), 5 * TNZO);
        assert_eq!(b.balance(&vault), 0);
        assert_eq!(read_defaults(&b.state, &a).len(), 1);
        b.send(&PAYER, post(20 * TNZO), closes).await.unwrap();
        let mut again = netted_open(2, rule(), TNZO);
        if let PlanOp::Open {
            decide_deadline_ms, ..
        } = &mut again
        {
            *decide_deadline_ms = (closes + 60_000) as u64;
        }
        let err = b.send(&PAYER, again, closes).await.unwrap_err();
        assert!(err.contains("defaulted"), "{err}");
    }

    // Reconciliation of the ccip/ethereum lock against these plans.

    use super::super::recon::{
        Proven, apply as recon_apply, list_mismatches, read_recon_jobs, read_reconciliation,
    };
    use crate::native::SELECTOR_PAY_INSURANCE_CLAIM;
    use tenzro_bridge::route::receipt_proof::LockCheckpoint;
    use tenzro_types::settlement::{ReconEntry, ReconKind, ReconState};

    fn lock_entry(plan: &[u8; 32], kind: ReconKind, amount: u128) -> ReconEntry {
        ReconEntry {
            plan_id: *plan,
            leg_id: leg_id(plan, 1),
            kind,
            amount,
        }
    }

    fn checkpoint_after(prior: &ReconState, entries: &[ReconEntry]) -> LockCheckpoint {
        let acc = entries.iter().fold(prior.acc, |a, e| e.fold(&a));
        LockCheckpoint {
            count: prior.count + entries.len() as u64,
            acc,
        }
    }

    fn reconcile(b: &mut Book, entries: &[ReconEntry], proven: LockCheckpoint) -> Result<Vec<Log>> {
        reconcile_as(b, entries, proven, false)
    }

    fn reconcile_as(
        b: &mut Book,
        entries: &[ReconEntry],
        proven: LockCheckpoint,
        attested: bool,
    ) -> Result<Vec<Log>> {
        let (mut changes, mut logs) = (Vec::new(), Vec::new());
        let proof = Proven {
            checkpoint: proven,
            digest: [9; 32],
            attested,
        };
        recon_apply(
            &mut b.state,
            BridgeRouteAdapter::Ccip,
            "ethereum",
            proof,
            entries,
            &Address::new([5; 32]),
            T0,
            3,
            &mut changes,
            &mut logs,
        )?;
        Ok(logs)
    }

    /// A plan with a 700 lock leg at index 1: committed, aborted, or open.
    async fn lock_plan(b: &mut Book, nonce: u64, commit: Option<bool>) -> [u8; 32] {
        let deadline = T0 + 120_000;
        let id = b
            .send(
                &PAYER,
                open(nonce, vec![native(TNZO), remote_lock(700)], deadline),
                T0,
            )
            .await
            .unwrap();
        match commit {
            Some(true) => {
                seed_evidence(b, &id, 1, LegClass::Attested);
                b.send(
                    &[5; 32],
                    PlanOp::ProveLeg {
                        plan_id: id,
                        index: 1,
                        evidence: Vec::new(),
                        network_fee: 0,
                    },
                    T0 + 1_000,
                )
                .await
                .unwrap();
            }
            Some(false) => {
                begin_block(&mut b.state, deadline + 60_000).unwrap();
            }
            None => {}
        }
        id
    }

    fn route_stop(b: &Book) -> Option<super::super::super::bridge_circuit::BridgeCircuitTrip> {
        super::super::super::bridge_circuit::read_bridge_circuit(
            &b.state,
            BridgeRouteAdapter::Ccip,
            "ethereum",
        )
    }

    #[tokio::test]
    async fn a_lock_that_matches_the_books_reconciles_from_its_stored_hash() {
        let mut b = Book::new();
        begin_block(&mut b.state, T0).unwrap();
        let committed = lock_plan(&mut b, 1, Some(true)).await;
        let aborted = lock_plan(&mut b, 2, Some(false)).await;
        assert!(read_decision(&b.state, &committed).unwrap().commit);
        assert!(!read_decision(&b.state, &aborted).unwrap().commit);
        let first = [
            lock_entry(&committed, ReconKind::Locked, 700),
            lock_entry(&aborted, ReconKind::Locked, 700),
        ];
        let cp = checkpoint_after(&ReconState::default(), &first);
        reconcile(&mut b, &first, cp).unwrap();
        let rec = read_reconciliation(&b.state, BridgeRouteAdapter::Ccip, "ethereum").unwrap();
        assert_eq!((rec.count, rec.acc, rec.mismatches.len()), (2, cp.acc, 0));
        let next = [
            lock_entry(&committed, ReconKind::Released, 700),
            lock_entry(&aborted, ReconKind::Refunded, 700),
        ];
        // Entries that do not fold to the proven hash, or a count that does
        // not continue the stored one, are refused.
        assert!(reconcile(&mut b, &first, checkpoint_after(&rec, &next)).is_err());
        let mut short = checkpoint_after(&rec, &next);
        short.count -= 1;
        assert!(reconcile(&mut b, &next, short).is_err());
        reconcile(&mut b, &next, checkpoint_after(&rec, &next)).unwrap();
        assert_eq!(
            read_reconciliation(&b.state, BridgeRouteAdapter::Ccip, "ethereum")
                .unwrap()
                .count,
            4
        );
        assert!(route_stop(&b).is_none());
    }

    #[tokio::test]
    async fn a_lock_that_disagrees_with_the_books_is_a_provable_mismatch_and_disables_the_route() {
        let mut b = Book::new();
        begin_block(&mut b.state, T0).unwrap();
        let committed = lock_plan(&mut b, 1, Some(true)).await;
        let aborted = lock_plan(&mut b, 2, Some(false)).await;
        let entries = [
            lock_entry(&aborted, ReconKind::Locked, 700),
            // Paid out although Tenzro aborted the plan.
            lock_entry(&aborted, ReconKind::Released, 700),
            // Refunded although Tenzro committed it.
            lock_entry(&committed, ReconKind::Refunded, 700),
            // Locked another amount than the leg's.
            lock_entry(&committed, ReconKind::Locked, 701),
            // A lock no plan names.
            ReconEntry {
                plan_id: [7; 32],
                leg_id: [8; 32],
                kind: ReconKind::Locked,
                amount: 1,
            },
        ];
        let cp = checkpoint_after(&ReconState::default(), &entries);
        let logs = reconcile(&mut b, &entries, cp).unwrap();
        let found = list_mismatches(&b.state, BridgeRouteAdapter::Ccip, "ethereum");
        assert_eq!(
            found.iter().map(|m| m.position).collect::<Vec<_>>(),
            vec![2, 3, 4, 5]
        );
        assert_eq!(found[0].reason, "released without the plan's commit");
        assert_eq!(found[1].reason, "refunded although the plan committed");
        assert_eq!(found[3].reason, "no such plan");
        // Provable: the hash before the entry, the entry and the ones after
        // it fold to the proven checkpoint.
        let m = &found[0];
        let end = entries[2..]
            .iter()
            .fold(m.entry.fold(&m.acc_before), |a, e| e.fold(&a));
        assert_eq!((end, m.checkpoint_digest), (cp.acc, [9; 32]));
        let stop = route_stop(&b).unwrap();
        assert_eq!(
            stop.mode,
            tenzro_types::bridge_route::BridgeRouteMode::Disabled
        );
        assert_eq!(
            stop.by,
            super::super::super::bridge_circuit::BridgeCircuitAuthority::Reconciliation
        );
        assert_eq!(
            logs.iter()
                .filter(|l| l.topics[0] == super::super::recon::RECON_MISMATCH_TOPIC)
                .count(),
            4
        );
        // Proven by light client: nobody is slashed and nothing is claimable.
        assert!(!found[0].attested);
        assert_eq!(found[0].harmed, Some(Address::new(PAYER)));
        assert_eq!(found[1].harmed, Some(Address::new([1; 32])));
        assert_eq!(found[3].harmed, None);
        let claim = serde_json::to_vec(&recon_claim(2)).unwrap();
        assert!(
            b.run(&PAYER, SELECTOR_PAY_INSURANCE_CLAIM, claim, T0)
                .await
                .is_err()
        );
    }

    fn recon_claim(position: u64) -> tenzro_types::insurance::InsuranceEvidence {
        tenzro_types::insurance::InsuranceEvidence::ReconMismatch {
            adapter: BridgeRouteAdapter::Ccip,
            chain: "ethereum".into(),
            position,
        }
    }

    #[tokio::test]
    async fn a_mismatch_on_an_attested_route_slashes_its_committee_and_its_loss_is_claimable() {
        use super::super::super::role_stake::{bond_role_for_test, read_role_stake};
        const MEMBER: [u8; 20] = [0x61; 20];
        let mut member_account = [0u8; 32];
        member_account[..20].copy_from_slice(&MEMBER);
        let mut b = Book::new();
        begin_block(&mut b.state, T0).unwrap();
        lock_route(&mut b, None);
        let key = tenzro_types::bridge_route::bridge_route_storage_key(
            BridgeRouteAdapter::Ccip,
            "ethereum",
        );
        let mut route: tenzro_types::bridge_route::BridgeRoute = serde_json::from_slice(
            &b.state
                .get_storage(&SYSTEM_ADDRESS, key.as_bytes())
                .unwrap(),
        )
        .unwrap();
        route.verifiers.members = vec![tenzro_types::bridge_route::VerifierMember {
            address: MEMBER,
            pq_public_key: vec![0u8; 1952],
            operator: "a".into(),
            rpc_provider: "a".into(),
        }];
        route.verifiers.threshold = 1;
        b.state.set_storage(
            &SYSTEM_ADDRESS,
            key.as_bytes(),
            serde_json::to_vec(&route).unwrap(),
        );
        let stake = tenzro_types::constants::MIN_ATTESTOR_STAKE;
        bond_role_for_test(&mut b.state, &member_account, NetworkRole::Attestor, stake);

        let committed = lock_plan(&mut b, 1, Some(true)).await;
        let aborted = lock_plan(&mut b, 2, Some(false)).await;
        let entries = [
            lock_entry(&aborted, ReconKind::Locked, 700),
            lock_entry(&aborted, ReconKind::Released, 700),
            lock_entry(&committed, ReconKind::Locked, 700),
            lock_entry(&committed, ReconKind::Refunded, 700),
        ];
        let pool = super::super::super::derive_insurance_pool_address();
        let pool_before = b.balance(&pool);
        reconcile_as(
            &mut b,
            &entries,
            checkpoint_after(&ReconState::default(), &entries),
            true,
        )
        .unwrap();
        let slashed = stake / 10;
        assert_eq!(
            read_role_stake(&b.state, &member_account, NetworkRole::Attestor)
                .unwrap()
                .bonded,
            stake - slashed
        );
        assert_eq!(b.balance(&pool) - pool_before, slashed);

        let found = list_mismatches(&b.state, BridgeRouteAdapter::Ccip, "ethereum");
        assert!(found.iter().all(|m| m.attested && m.loss > 0));
        // Only the account the entry cost may claim, once.
        let released = serde_json::to_vec(&recon_claim(2)).unwrap();
        assert!(
            b.run(&[1; 32], SELECTOR_PAY_INSURANCE_CLAIM, released.clone(), T0)
                .await
                .is_err()
        );
        let payer_before = b.balance(&Address::new(PAYER));
        b.run(&PAYER, SELECTOR_PAY_INSURANCE_CLAIM, released.clone(), T0)
            .await
            .unwrap();
        let paid = b.balance(&Address::new(PAYER)) - payer_before;
        assert!(paid > 0 && paid <= found[0].loss, "paid {paid}");
        assert!(
            b.run(&PAYER, SELECTOR_PAY_INSURANCE_CLAIM, released, T0)
                .await
                .is_err()
        );
        // The payee a refund after the commit cost claims its own.
        let refunded = serde_json::to_vec(&recon_claim(4)).unwrap();
        let payee_before = b.balance(&Address::new([1; 32]));
        b.run(&[1; 32], SELECTOR_PAY_INSURANCE_CLAIM, refunded, T0)
            .await
            .unwrap();
        assert!(b.balance(&Address::new([1; 32])) > payee_before);
        // A position with no mismatch proves nothing.
        let none = serde_json::to_vec(&recon_claim(1)).unwrap();
        assert!(
            b.run(&PAYER, SELECTOR_PAY_INSURANCE_CLAIM, none, T0)
                .await
                .is_err()
        );
    }

    fn set_epoch(b: &mut Book, epoch: u64) {
        use super::super::super::rewards::{REWARD_STATE_KEY, read_reward_state};
        let mut rs = read_reward_state(&b.state).unwrap();
        rs.current_epoch = epoch;
        write_json(&mut b.state, REWARD_STATE_KEY, &rs, &mut Vec::new()).unwrap();
    }

    /// Reconcile at the current epoch as `[5; 32]`.
    fn reconcile_now(b: &mut Book, entries: &[ReconEntry]) -> Result<()> {
        let prior =
            read_reconciliation(&b.state, BridgeRouteAdapter::Ccip, "ethereum").unwrap_or_default();
        let proof = Proven {
            checkpoint: checkpoint_after(&prior, entries),
            digest: [9; 32],
            attested: false,
        };
        let epoch = super::super::super::economy::read_current_epoch(&b.state);
        recon_apply(
            &mut b.state,
            BridgeRouteAdapter::Ccip,
            "ethereum",
            proof,
            entries,
            &Address::new([5; 32]),
            T0,
            epoch,
            &mut Vec::new(),
            &mut Vec::new(),
        )
    }

    #[tokio::test]
    async fn each_epoch_opens_a_reconciliation_duty_per_locked_route_paid_once_to_the_first_reconciliation()
     {
        use tenzro_types::duty::DutyState;
        let state_of = |b: &Book, id: &str| {
            let id: [u8; 32] = hex::decode(id).unwrap().try_into().unwrap();
            super::super::super::duty::read_duty(&b.state, &id)
                .unwrap()
                .state
        };
        let mut b = Book::new();
        lock_route(&mut b, None);
        super::super::recon::note_route(
            &mut b.state,
            BridgeRouteAdapter::Ccip,
            "ethereum",
            true,
            &mut Vec::new(),
        )
        .unwrap();
        let treasury = super::super::super::derive_treasury_address();
        b.state.set_balance(treasury.as_bytes(), 10 * TNZO);
        // The reward is small against the 3% outflow period of a treasury
        // this size; the cap itself is tested below.
        super::super::super::set_governed_param_for_test(
            &mut b.state,
            crate::governance::MAX_PERIOD_OUTFLOW_PARAM,
            10_000,
        );
        begin_block(&mut b.state, T0).unwrap();
        let jobs = read_recon_jobs(&b.state).unwrap();
        assert_eq!((jobs.epoch, jobs.duties.len()), (0, 1));
        // The reward is reserved from the treasury when the duty opens.
        assert_eq!(b.balance(&treasury), 9 * TNZO);
        assert_eq!(state_of(&b, &jobs.duties[0]), DutyState::Open);

        let one = lock_plan(&mut b, 1, Some(true)).await;
        let reconciler = Address::new([5; 32]);
        let before = b.balance(&reconciler);
        reconcile_now(
            &mut b,
            &[
                lock_entry(&one, ReconKind::Locked, 700),
                lock_entry(&one, ReconKind::Released, 700),
            ],
        )
        .unwrap();
        assert_eq!(b.balance(&reconciler) - before, TNZO);
        assert_eq!(state_of(&b, &jobs.duties[0]), DutyState::Paid);
        // A second reconciliation in the same epoch is recorded, not paid.
        let two = lock_plan(&mut b, 2, Some(true)).await;
        let before = b.balance(&reconciler);
        reconcile_now(&mut b, &[lock_entry(&two, ReconKind::Locked, 700)]).unwrap();
        assert_eq!(b.balance(&reconciler), before);
        assert_eq!(
            read_reconciliation(&b.state, BridgeRouteAdapter::Ccip, "ethereum")
                .unwrap()
                .count,
            3
        );

        // The next epoch opens a fresh duty; one left unpaid is closed when
        // its epoch ends and its reward goes back to the treasury.
        set_epoch(&mut b, 1);
        begin_block(&mut b.state, T0 + 1).unwrap();
        let next = read_recon_jobs(&b.state).unwrap();
        assert_eq!((next.epoch, next.duties.len()), (1, 1));
        assert_ne!(next.duties[0], jobs.duties[0]);
        assert_eq!(state_of(&b, &jobs.duties[0]), DutyState::Paid);
        let held = b.balance(&treasury);
        set_epoch(&mut b, 2);
        begin_block(&mut b.state, T0 + 2).unwrap();
        assert_eq!(state_of(&b, &next.duties[0]), DutyState::Expired);
        assert_eq!(b.balance(&treasury), held);

        // A route whose lock is removed gets no duty.
        super::super::recon::note_route(
            &mut b.state,
            BridgeRouteAdapter::Ccip,
            "ethereum",
            false,
            &mut Vec::new(),
        )
        .unwrap();
        set_epoch(&mut b, 3);
        begin_block(&mut b.state, T0 + 3).unwrap();
        assert!(read_recon_jobs(&b.state).unwrap().duties.is_empty());
    }

    /// The duty reward is opened with no proposal, so the treasury outflow
    /// period caps it: a duty the period cannot cover is left unfunded and
    /// the treasury keeps its TNZO.
    #[tokio::test]
    async fn a_reconciliation_duty_the_outflow_period_cannot_cover_is_left_unfunded() {
        let mut b = Book::new();
        lock_route(&mut b, None);
        super::super::recon::note_route(
            &mut b.state,
            BridgeRouteAdapter::Ccip,
            "ethereum",
            true,
            &mut Vec::new(),
        )
        .unwrap();
        let treasury = super::super::super::derive_treasury_address();
        // 3% of 10 TNZO is under the 1 TNZO reward.
        b.state.set_balance(treasury.as_bytes(), 10 * TNZO);
        begin_block(&mut b.state, T0).unwrap();
        let jobs = read_recon_jobs(&b.state).unwrap();
        assert!(jobs.duties.is_empty(), "no duty was funded");
        assert_eq!(jobs.unfunded.len(), 1, "the route is listed unfunded");
        assert_eq!(b.balance(&treasury), 10 * TNZO);
    }
}
