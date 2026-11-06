//! Netted obligations, settled per epoch from collateral held on Tenzro.
//!
//! A participant posts collateral in an asset (TNZO, or a carried asset a
//! governed route lists) into its own collateral vault. A plan whose legs are
//! netted commits when it opens: the protocol fee is taken on its gross value
//! from the opener's collateral, and the split rule's credits become the
//! opener's obligations to the recipients in the asset's open batch. An
//! obligation is admitted only while the opener's net debit in the batch
//! stays within its collateral.
//!
//! When a batch's epoch ends, block execution nets it with
//! `tenzro_settlement::netting::compute_batch` and pays each instruction from
//! the debtor's collateral vault. A debtor whose usable collateral no longer
//! covers its net debit (an issuer froze or took it) defaults: what it has is
//! divided among its instructions by `tenzro_types::split::pro_rata`, the
//! default is recorded, and it may not open netted plans again. The batch
//! record keeps the obligations, their Merkle root, the instructions and the
//! defaults, so every participant's gross-to-net position is provable.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_settlement::netting::{
    Obligation, SettlementInstruction, compute_batch, obligations_root,
};
use tenzro_types::primitives::Address;
use tenzro_types::settlement::{LegKind, SettlementPlan};
use tenzro_types::split::Allocation;

use super::super::funding::{move_balance, read_json, refuse, write_json};
use super::super::{SYSTEM_ADDRESS, economy, network_param};
use crate::error::{Result, VmError};
use crate::token_ledger;
use crate::traits::VmState;
use crate::types::{Log, StateChange};

/// Governed length of a netting epoch, ms.
pub const NETTING_EPOCH_PARAM: &str = "settlement.netting_epoch_ms";
/// Default netting epoch: one hour.
pub const DEFAULT_NETTING_EPOCH_MS: u64 = 60 * 60 * 1000;
/// Most obligations one batch holds; a plan that would pass it is refused.
pub const MAX_OBLIGATIONS_PER_BATCH: usize = 1024;
/// Most batches block execution settles in one block.
pub const MAX_BATCHES_PER_BLOCK: usize = 16;

const COLLATERAL_DOMAIN: &[u8] = b"tenzro/settlement/collateral/v1";
const OPEN_BATCHES_KEY: &str = "net_open";

/// A participant that did not cover its net debit when a batch closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetDefault {
    /// The debtor.
    pub participant: Address,
    /// Its net debit, the asset's smallest unit.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub owed: u128,
    /// What its collateral paid towards it.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub paid: u128,
}

/// A closed batch's settlement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetSettlement {
    /// `compute_batch`'s id over the canonical obligations.
    pub batch_id: String,
    /// Merkle root over the canonical obligations.
    #[serde(with = "tenzro_types::agent_audit::hex32")]
    pub obligations_root: [u8; 32],
    /// The net instructions.
    pub instructions: Vec<SettlementInstruction>,
    /// What each instruction actually paid (less than its amount only for a
    /// defaulted debtor), by instruction index.
    #[serde(with = "u128_list")]
    pub paid: Vec<u128>,
    /// Sum of the obligations.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub gross_total: u128,
    /// Sum of the instructions.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub net_total: u128,
    /// Block time it settled, ms.
    pub settled_at_ms: u64,
    /// Debtors that defaulted.
    pub defaults: Vec<NetDefault>,
}

/// One asset's batch of netted obligations for an epoch, at
/// `nbat:<asset>:<seq>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetBatch {
    /// Token id.
    #[serde(with = "tenzro_types::agent_audit::hex32")]
    pub asset: [u8; 32],
    /// The asset's batch number.
    pub seq: u64,
    /// Block time from which it settles, ms.
    pub closes_at_ms: u64,
    /// Obligations in the order they were admitted.
    pub obligations: Vec<Obligation>,
    /// Set once it settled.
    pub settlement: Option<NetSettlement>,
}

mod u128_list {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &[u128], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().map(|x| x.to_string()))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u128>, D::Error> {
        Vec::<String>::deserialize(d)?
            .into_iter()
            .map(|x| x.parse().map_err(serde::de::Error::custom))
            .collect()
    }
}

fn batch_key(asset: &[u8; 32], seq: u64) -> String {
    format!("nbat:{}:{seq}", hex::encode(asset))
}

fn seq_key(asset: &[u8; 32]) -> String {
    format!("nseq:{}", hex::encode(asset))
}

fn default_key(participant: &Address) -> String {
    format!("ndef:{}", hex::encode(participant.as_bytes()))
}

/// The asset's batch `seq`.
pub fn read_batch(state: &dyn VmState, asset: &[u8; 32], seq: u64) -> Option<NetBatch> {
    read_json(state, &batch_key(asset, seq))
}

/// The asset's latest batch number, if it ever had one.
pub fn latest_seq(state: &dyn VmState, asset: &[u8; 32]) -> Option<u64> {
    read_json(state, &seq_key(asset))
}

/// The batches `participant` defaulted in, as `(asset, seq)`.
pub fn read_defaults(state: &dyn VmState, participant: &Address) -> Vec<(String, u64)> {
    read_json(state, &default_key(participant)).unwrap_or_default()
}

/// The vault holding `participant`'s collateral in `asset`.
pub fn collateral_vault(participant: &Address, asset: &[u8; 32]) -> Address {
    let mut h = Sha256::new();
    h.update(COLLATERAL_DOMAIN);
    h.update(participant.as_bytes());
    h.update(asset);
    Address::new(h.finalize().into())
}

/// Collateral the vault can pay out: its balance less what an issuer froze.
pub fn usable_collateral(state: &dyn VmState, participant: &Address, asset: &[u8; 32]) -> u128 {
    let vault = collateral_vault(participant, asset);
    let held = token_ledger::balance(state, asset, vault.as_bytes());
    if *asset == token_ledger::tnzo_id() {
        return held;
    }
    held.saturating_sub(token_ledger::frozen(state, asset, vault.as_bytes()))
}

/// TNZO, or a token only the bridge issues (a carried asset a governed route
/// lists).
fn listed(state: &dyn VmState, asset: &[u8; 32]) -> bool {
    *asset == token_ledger::tnzo_id()
        || token_ledger::read_token(state, asset)
            .is_some_and(|t| t.creator == super::super::bridge::deposit_issuer())
}

fn move_asset(
    state: &mut dyn VmState,
    asset: &[u8; 32],
    from: &Address,
    to: &Address,
    amount: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    if *asset == token_ledger::tnzo_id() {
        return move_balance(state, from.as_bytes(), to.as_bytes(), amount, changes);
    }
    match token_ledger::transfer(state, asset, from.as_bytes(), to.as_bytes(), amount, now_ms)? {
        Some(c) => {
            changes.extend(c);
            Ok(())
        }
        None => Err(refuse("the collateral does not cover the move")),
    }
}

fn net_debit(obligations: &[Obligation], participant: &Address) -> u128 {
    let (mut debit, mut credit) = (0u128, 0u128);
    for o in obligations {
        if o.debtor == *participant {
            debit = debit.saturating_add(o.amount);
        }
        if o.creditor == *participant {
            credit = credit.saturating_add(o.amount);
        }
    }
    debit.saturating_sub(credit)
}

fn open_batch(state: &dyn VmState, asset: &[u8; 32]) -> Option<NetBatch> {
    latest_seq(state, asset)
        .and_then(|seq| read_batch(state, asset, seq))
        .filter(|b| b.settlement.is_none())
}

fn net_log(event: &str, data: &serde_json::Value) -> Result<Log> {
    let data = serde_json::to_vec(data)
        .map_err(|e| VmError::Internal(format!("encode netting log: {e}")))?;
    Ok(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![
            super::plan::SETTLEMENT_PLAN_TOPIC.to_vec(),
            event.as_bytes().to_vec(),
        ],
        data,
    ))
}

/// Post `amount` of `asset` from `sender` into its collateral vault.
pub(super) fn post(
    state: &mut dyn VmState,
    sender: &Address,
    asset: &[u8; 32],
    amount: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    if amount == 0 {
        return Err(refuse("collateral is a positive amount"));
    }
    if !listed(state, asset) {
        return Err(refuse(
            "collateral is TNZO or a carried asset a route lists",
        ));
    }
    move_asset(
        state,
        asset,
        sender,
        &collateral_vault(sender, asset),
        amount,
        now_ms,
        changes,
    )?;
    logs.push(net_log(
        "collateral_posted",
        &serde_json::json!({
            "participant": hex::encode(sender.as_bytes()),
            "asset": hex::encode(asset),
            "amount": amount.to_string(),
        }),
    )?);
    Ok(())
}

/// Withdraw `amount` of `sender`'s collateral, keeping what its net debit in
/// the asset's open batch needs.
pub(super) fn withdraw(
    state: &mut dyn VmState,
    sender: &Address,
    asset: &[u8; 32],
    amount: u128,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let needed = open_batch(state, asset).map_or(0, |b| net_debit(&b.obligations, sender));
    let usable = usable_collateral(state, sender, asset);
    if amount == 0 || usable.saturating_sub(needed) < amount {
        return Err(refuse(format!(
            "at most {} can be withdrawn: the open batch's net debit needs {needed}",
            usable.saturating_sub(needed)
        )));
    }
    move_asset(
        state,
        asset,
        &collateral_vault(sender, asset),
        sender,
        amount,
        now_ms,
        changes,
    )?;
    logs.push(net_log(
        "collateral_withdrawn",
        &serde_json::json!({
            "participant": hex::encode(sender.as_bytes()),
            "asset": hex::encode(asset),
            "amount": amount.to_string(),
        }),
    )?);
    Ok(())
}

/// The asset and gross value of a plan whose legs are netted.
pub(super) fn netted_value(plan: &SettlementPlan) -> Option<([u8; 32], u128)> {
    let mut out: Option<([u8; 32], u128)> = None;
    for leg in &plan.legs {
        let LegKind::Netted { asset, amount } = &leg.kind else {
            return None;
        };
        let total = out.map_or(0, |(_, t)| t).saturating_add(*amount);
        out = Some((*asset, total));
    }
    out
}

/// Commit a netted plan: take the protocol fee on the gross from the
/// opener's collateral and admit the split's credits as the opener's
/// obligations in the asset's open batch. Returns the division and the TNZO
/// the fee burned.
pub(super) fn commit(
    state: &mut dyn VmState,
    plan: &SettlementPlan,
    paid_to: &[Address],
    now_ms: u64,
    changes: &mut Vec<StateChange>,
) -> Result<(Allocation, u128)> {
    let (asset, gross) =
        netted_value(plan).ok_or_else(|| VmError::Internal("not a netted plan".into()))?;
    let debtor = plan.opened_by;
    if !listed(state, &asset) {
        return Err(refuse(
            "a netted leg's asset is TNZO or a carried asset a route lists",
        ));
    }
    if !read_defaults(state, &debtor).is_empty() {
        return Err(refuse(
            "a participant that defaulted on a netting batch opens no netted plans",
        ));
    }
    // A carried asset settles only as a permitted settlement asset on its
    // peg, and its fee is collected in kind.
    let permitted = if asset == token_ledger::tnzo_id() {
        None
    } else {
        Some(super::super::settlement_asset::permitted(state, &asset)?)
    };
    let params = match &permitted {
        None => economy::fee_params(state),
        Some(p) => super::in_kind_fee_params(state, p),
    };
    let split = &plan.split;
    let alloc =
        tenzro_types::split::apply(gross, split, &params, 0).map_err(|e| refuse(e.to_string()))?;
    if !alloc.conserves() {
        return Err(VmError::Internal(
            "netted division does not conserve its value".into(),
        ));
    }
    let asset_hex = hex::encode(asset);
    let mut batch = match open_batch(state, &asset) {
        Some(b) => b,
        None => {
            let epoch = network_param(state, NETTING_EPOCH_PARAM).max(1);
            let seq = latest_seq(state, &asset).map_or(0, |s| s + 1);
            write_json(state, &seq_key(&asset), &seq, changes)?;
            let mut open: Vec<String> = read_json(state, OPEN_BATCHES_KEY).unwrap_or_default();
            open.push(asset_hex.clone());
            write_json(state, OPEN_BATCHES_KEY, &open, changes)?;
            NetBatch {
                asset,
                seq,
                closes_at_ms: (now_ms / epoch + 1) * epoch,
                obligations: Vec::new(),
                settlement: None,
            }
        }
    };
    for (to, amount) in paid_to.iter().zip(&alloc.credits) {
        if *amount > 0 && *to != debtor {
            batch.obligations.push(Obligation {
                debtor,
                creditor: *to,
                asset: asset_hex.clone(),
                amount: *amount,
            });
        }
    }
    if batch.obligations.len() > MAX_OBLIGATIONS_PER_BATCH {
        return Err(refuse(format!(
            "the batch holds at most {MAX_OBLIGATIONS_PER_BATCH} obligations"
        )));
    }
    // The fee leaves the collateral now; the net debit must fit in the rest.
    let fee = alloc.fee.fee;
    let usable = usable_collateral(state, &debtor, &asset);
    let debit = net_debit(&batch.obligations, &debtor);
    if usable < fee || usable - fee < debit {
        return Err(refuse(format!(
            "collateral {usable} does not cover the fee {fee} and the net debit {debit}"
        )));
    }
    let vault = collateral_vault(&debtor, &asset);
    let primary = split
        .lines
        .iter()
        .position(|l| l.basis == tenzro_types::split::SplitBasis::Remainder)
        .map(|i| paid_to[i])
        .unwrap_or(debtor);
    let burned = if asset == token_ledger::tnzo_id() {
        // The fee's treasury and insurance parts are credited by the fee
        // step and its burn part leaves supply.
        let held = state.get_balance(vault.as_bytes());
        state.set_balance(vault.as_bytes(), held - fee);
        changes.push(StateChange::new(
            vault.as_bytes().to_vec(),
            b"balance".to_vec(),
            Some(held.to_le_bytes().to_vec()),
            Some((held - fee).to_le_bytes().to_vec()),
        ));
        economy::record_fee(
            state,
            debtor.as_bytes(),
            primary.as_bytes(),
            gross,
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
        alloc.fee.burn
    } else {
        // A token the protocol does not issue cannot be burned: the fee is
        // collected in kind and its burn share booked as burn-equivalent,
        // netted against the epoch's issuance.
        let permitted = permitted.as_ref().ok_or_else(|| {
            VmError::Internal("a carried asset is checked when the plan commits".into())
        })?;
        let worth = super::super::settlement_asset::value_e6(
            gross,
            permitted.rate_nano_usd,
            permitted.asset.decimals,
        );
        super::super::settlement_asset::admit_inflow(state, &asset, permitted, worth, changes)?;
        super::collect_in_kind(
            state,
            &asset,
            permitted,
            vault.as_bytes(),
            debtor.as_bytes(),
            primary.as_bytes(),
            gross,
            &alloc.fee,
            0,
            &economy::Earning {
                provider: None,
                payer_agent: plan.agent_did.clone(),
                attribution: plan.attribution.clone(),
                network_share_paid: false,
            },
            now_ms as i64,
            changes,
        )?;
        0
    };
    economy::count_settlement(state, 1, changes)?;
    write_json(state, &batch_key(&asset, batch.seq), &batch, changes)?;
    Ok((alloc, burned))
}

/// Settle every batch whose epoch ended by `now_ms`, up to
/// [`MAX_BATCHES_PER_BLOCK`]. Returns how many settled.
pub fn begin_block(state: &mut dyn VmState, now_ms: i64) -> Result<usize> {
    let open: Vec<String> = read_json(state, OPEN_BATCHES_KEY).unwrap_or_default();
    if open.is_empty() {
        return Ok(0);
    }
    let now = now_ms.max(0) as u64;
    let mut changes = Vec::new();
    let mut still_open = Vec::with_capacity(open.len());
    let mut settled = 0usize;
    for asset_hex in open {
        let asset = hex::decode(&asset_hex)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .ok_or_else(|| VmError::Internal(format!("bad open batch asset {asset_hex}")))?;
        match open_batch(state, &asset) {
            Some(batch) if batch.closes_at_ms <= now && settled < MAX_BATCHES_PER_BLOCK => {
                settle(state, batch, now, &mut changes)?;
                settled += 1;
            }
            Some(_) => still_open.push(asset_hex),
            None => {}
        }
    }
    write_json(state, OPEN_BATCHES_KEY, &still_open, &mut changes)?;
    Ok(settled)
}

fn settle(
    state: &mut dyn VmState,
    mut batch: NetBatch,
    now: u64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let netted = compute_batch(batch.obligations.clone())
        .map_err(|e| VmError::Internal(format!("netting: {e}")))?;
    let mut paid = vec![0u128; netted.instructions.len()];
    let mut defaults = Vec::new();
    // Instructions grouped by debtor, in canonical order.
    let mut debtors: Vec<Address> = netted.instructions.iter().map(|i| i.from).collect();
    debtors.dedup();
    debtors.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    debtors.dedup();
    for debtor in debtors {
        let idx: Vec<usize> = (0..netted.instructions.len())
            .filter(|&i| netted.instructions[i].from == debtor)
            .collect();
        let owed: u128 = idx.iter().map(|&i| netted.instructions[i].amount).sum();
        let usable = usable_collateral(state, &debtor, &batch.asset);
        let shares: Vec<u128> = if usable >= owed {
            idx.iter().map(|&i| netted.instructions[i].amount).collect()
        } else {
            let claims: Vec<u128> = idx.iter().map(|&i| netted.instructions[i].amount).collect();
            tenzro_types::split::pro_rata(usable, &claims)
        };
        let vault = collateral_vault(&debtor, &batch.asset);
        let mut total = 0u128;
        for (&i, share) in idx.iter().zip(&shares) {
            let to = netted.instructions[i].to;
            // A move the asset's rules refuse leaves that share unpaid.
            let mut scratch = Vec::new();
            if move_asset(
                state,
                &batch.asset,
                &vault,
                &to,
                *share,
                now as i64,
                &mut scratch,
            )
            .is_ok()
            {
                changes.extend(scratch);
                paid[i] = *share;
                total += *share;
            }
        }
        // Only a debtor short of collateral defaults; a share the asset's
        // rules refused to deliver stays unpaid in `paid` without one.
        if usable < owed {
            defaults.push(NetDefault {
                participant: debtor,
                owed,
                paid: total,
            });
            let mut recorded = read_defaults(state, &debtor);
            recorded.push((hex::encode(batch.asset), batch.seq));
            write_json(state, &default_key(&debtor), &recorded, changes)?;
        }
    }
    batch.settlement = Some(NetSettlement {
        batch_id: netted.batch_id,
        obligations_root: obligations_root(&netted.obligations),
        instructions: netted.instructions,
        paid,
        gross_total: netted.gross_total,
        net_total: netted.net_total,
        settled_at_ms: now,
        defaults,
    });
    // The record keeps the canonical order the root commits.
    batch.obligations = netted.obligations;
    write_json(state, &batch_key(&batch.asset, batch.seq), &batch, changes)?;
    Ok(())
}
