//! Reconciliation of a route's settlement lock against Tenzro's books.
//!
//! Every settlement lock keeps a running hash over what it records (each
//! lock, release and refund, in order) and its count, and its checkpoint is
//! proven through the route like a lock event. A reconciliation submits the
//! entries the lock recorded since the last one with a proof of the lock's
//! checkpoint: folded from the stored hash, they must give the proven count
//! and hash, so they are exactly what the lock did. Each is then checked
//! against Tenzro's plan and decision. An entry that disagrees is stored as a
//! mismatch, provable from the stored hash before it and the checkpoint, and
//! disables the route.

use tenzro_bridge::route::receipt_proof::LockCheckpoint;
use tenzro_types::bridge_route::{BridgeRouteAdapter, BridgeRouteMode, bridge_route_storage_key};
use tenzro_types::primitives::Address;
use tenzro_types::settlement::{
    LegKind, MAX_RECON_ENTRIES, ReconEntry, ReconKind, ReconMismatch, ReconState, leg_id,
};

use tenzro_types::network::NetworkRole;
use tenzro_types::split::{SplitRecipient, SplitRole};

use super::super::bridge_circuit::{BridgeCircuitAuthority, BridgeCircuitTrip, trip};
use super::super::duty;
use super::super::funding::{move_balance, read_json, refuse, write_json};
use super::super::{SYSTEM_ADDRESS, economy, network_param};
use super::plan::{ATTESTOR_SLASH_PARAM, read_decision, read_plan, recipients};
use crate::error::Result;
use crate::traits::VmState;
use crate::types::{Log, StateChange};
use tenzro_types::duty::{Duty, DutyKind};

/// Topic of the log a reconciliation emits for each mismatch.
pub const RECON_MISMATCH_TOPIC: &[u8] = b"ReconciliationMismatch";

/// Governed reward, wei, of the reconciliation duty the chain opens for
/// each route with a settlement lock each epoch, funded by the treasury.
pub const RECON_REWARD_PARAM: &str = "settlement.reconciliation_reward";
/// Genesis value of [`RECON_REWARD_PARAM`]: 1 TNZO.
pub const DEFAULT_RECON_REWARD: u64 = 1_000_000_000_000_000_000;

/// The routes with a settlement lock, as `(adapter, chain)`, in install
/// order.
pub const RECON_ROUTES_KEY: &str = "recon_routes";
const RECON_JOBS_KEY: &str = "recon_jobs";

/// This epoch's reconciliation duties.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ReconJobs {
    /// The epoch they were opened for.
    pub epoch: u64,
    /// Their duty ids, hex.
    pub duties: Vec<String>,
    /// Routes whose duty the treasury could not fund, by storage key.
    pub unfunded: Vec<String>,
}

/// The routes with a settlement lock.
pub fn recon_routes(state: &dyn VmState) -> Vec<(BridgeRouteAdapter, String)> {
    read_json(state, RECON_ROUTES_KEY).unwrap_or_default()
}

/// This epoch's reconciliation duties, once the first block of the epoch
/// opened them.
pub fn read_recon_jobs(state: &dyn VmState) -> Option<ReconJobs> {
    read_json(state, RECON_JOBS_KEY)
}

/// Keep route `(adapter, chain)` in the reconciliation index exactly when it
/// is installed with a settlement lock.
pub fn note_route(
    state: &mut dyn VmState,
    adapter: BridgeRouteAdapter,
    chain: &str,
    has_lock: bool,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let mut routes = recon_routes(state);
    let at = routes.iter().position(|(a, c)| *a == adapter && c == chain);
    match (has_lock, at) {
        (true, None) => routes.push((adapter, chain.to_string())),
        (false, Some(i)) => {
            routes.remove(i);
        }
        _ => return Ok(()),
    }
    write_json(state, RECON_ROUTES_KEY, &routes, changes)?;
    Ok(())
}

fn duty_kind(adapter: BridgeRouteAdapter, chain: &str, epoch: u64) -> DutyKind {
    DutyKind::Reconciliation {
        route: bridge_route_storage_key(adapter, chain),
        epoch,
    }
}

/// This epoch's reconciliation duty of route `(adapter, chain)`, if the
/// chain opened one.
pub fn read_recon_duty(
    state: &dyn VmState,
    adapter: BridgeRouteAdapter,
    chain: &str,
) -> Option<Duty> {
    let jobs = read_recon_jobs(state)?;
    duty::read_duty(
        state,
        &duty_kind(adapter, &chain.to_ascii_lowercase(), jobs.epoch).id(),
    )
}

/// In the first block of each epoch: close last epoch's unpaid
/// reconciliation duties, returning their rewards to the treasury, and open
/// one for every route with a settlement lock at the governed reward.
pub(super) fn begin_block(state: &mut dyn VmState, now_ms: i64) -> Result<()> {
    let epoch = economy::read_current_epoch(state);
    let last = read_recon_jobs(state);
    if last.as_ref().is_some_and(|j| j.epoch == epoch) {
        return Ok(());
    }
    let mut changes = Vec::new();
    for id in last.map(|j| j.duties).unwrap_or_default() {
        if let Some(id) = hex::decode(&id)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        {
            duty::close(state, &id, &mut changes)?;
        }
    }
    let reward = u128::from(network_param(state, RECON_REWARD_PARAM));
    let mut jobs = ReconJobs {
        epoch,
        ..ReconJobs::default()
    };
    if reward > 0 {
        let treasury: [u8; 32] = super::super::derive_treasury_address()
            .as_bytes()
            .try_into()
            .unwrap_or_default();
        for (adapter, chain) in recon_routes(state) {
            let kind = duty_kind(adapter, &chain, epoch);
            if duty::read_duty(state, &kind.id()).is_some() {
                jobs.duties.push(hex::encode(kind.id()));
                continue;
            }
            // The reward is opened with no proposal, so it counts against
            // the treasury's outflow period; a duty the cap cannot cover is
            // left unfunded, like one the balance cannot cover.
            if state.get_balance(&treasury) < reward
                || super::super::funding::record_outflow(state, reward, now_ms, &mut changes)
                    .is_err()
            {
                jobs.unfunded
                    .push(bridge_route_storage_key(adapter, &chain));
                continue;
            }
            let vault = duty::duty_vault(&kind.id());
            move_balance(state, &treasury, &vault, reward, &mut changes)?;
            let id = duty::open(
                state,
                kind,
                vault,
                treasury,
                reward,
                now_ms,
                None,
                &mut changes,
            )?;
            jobs.duties.push(hex::encode(id));
        }
    }
    write_json(state, RECON_JOBS_KEY, &jobs, &mut changes)?;
    Ok(())
}

/// Pay this epoch's reconciliation duty of `(adapter, chain)` to `sender`,
/// if it is still open: only the first verified reconciliation of the
/// route in the epoch is paid.
fn pay_job(
    state: &mut dyn VmState,
    adapter: BridgeRouteAdapter,
    chain: &str,
    epoch: u64,
    sender: &Address,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let payee: [u8; 32] = sender
        .as_bytes()
        .try_into()
        .map_err(|_| refuse("a reconciler is a 32-byte account"))?;
    duty::pay(
        state,
        &duty_kind(adapter, chain, epoch).id(),
        &payee,
        changes,
    )?;
    Ok(())
}

fn recon_key(adapter: BridgeRouteAdapter, chain: &str) -> String {
    format!("recon:{}", bridge_route_storage_key(adapter, chain))
}

fn mismatch_key(adapter: BridgeRouteAdapter, chain: &str, position: u64) -> String {
    format!(
        "recon_mismatch:{}:{position}",
        bridge_route_storage_key(adapter, chain)
    )
}

/// How far the route's lock has been reconciled; nothing before the first
/// reconciliation.
pub fn read_reconciliation(
    state: &dyn VmState,
    adapter: BridgeRouteAdapter,
    chain: &str,
) -> Option<ReconState> {
    read_json(state, &recon_key(adapter, &chain.to_ascii_lowercase()))
}

/// The mismatch at `position` of the route's lock, if that entry disagreed.
pub fn read_mismatch(
    state: &dyn VmState,
    adapter: BridgeRouteAdapter,
    chain: &str,
    position: u64,
) -> Option<ReconMismatch> {
    read_json(
        state,
        &mismatch_key(adapter, &chain.to_ascii_lowercase(), position),
    )
}

/// Every mismatch of the route's lock, in order.
pub fn list_mismatches(
    state: &dyn VmState,
    adapter: BridgeRouteAdapter,
    chain: &str,
) -> Vec<ReconMismatch> {
    read_reconciliation(state, adapter, chain)
        .map(|r| {
            r.mismatches
                .iter()
                .filter_map(|p| read_mismatch(state, adapter, chain, *p))
                .collect()
        })
        .unwrap_or_default()
}

/// Why `entry`, recorded by the lock of route `(adapter, chain)`, disagrees
/// with Tenzro's books, if it does: a lock or payout must belong to a lock leg
/// of a plan on this route, of the leg's amount; a release needs the plan's
/// commit and a refund must not follow one. With the reason, the account on
/// Tenzro the entry cost the leg's value and that value in USD micro-units:
/// the payer when the lock released without a commit, the plan's payee when
/// it refunded after one.
fn disagreement(
    state: &dyn VmState,
    adapter: BridgeRouteAdapter,
    chain: &str,
    entry: &ReconEntry,
) -> Option<(String, Option<(Address, u64)>)> {
    let Some(plan) = read_plan(state, &entry.plan_id) else {
        return Some(("no such plan".into(), None));
    };
    let Some(index) =
        (0..plan.legs.len()).find(|i| leg_id(&plan.plan_id, *i as u8) == entry.leg_id)
    else {
        return Some(("the plan has no such leg".into(), None));
    };
    let LegKind::RemoteLock {
        adapter: a,
        chain: c,
        amount,
        ..
    } = &plan.legs[index].kind
    else {
        return Some(("the leg is not a lock leg".into(), None));
    };
    if *a != adapter || c.to_ascii_lowercase() != chain {
        return Some(("the leg is on another route".into(), None));
    }
    if *amount != entry.amount {
        return Some((
            format!("the leg is of {amount}, the lock recorded {}", entry.amount),
            None,
        ));
    }
    let usd_e6 = plan.legs[index].usd_e6;
    let committed = read_decision(state, &entry.plan_id).map(|d| d.commit);
    match (entry.kind, committed) {
        (ReconKind::Locked, _) => None,
        (ReconKind::Released, Some(true)) => None,
        (ReconKind::Released, _) => Some((
            "released without the plan's commit".into(),
            Some((plan.opened_by, usd_e6)),
        )),
        (ReconKind::Refunded, Some(true)) => Some((
            "refunded although the plan committed".into(),
            plan_payee(state, &plan).map(|p| (p, usd_e6)),
        )),
        (ReconKind::Refunded, _) => None,
    }
}

/// The account the plan's first payee line pays, when it names one.
fn plan_payee(
    state: &dyn VmState,
    plan: &tenzro_types::settlement::SettlementPlan,
) -> Option<Address> {
    let index = plan
        .split
        .lines
        .iter()
        .position(|l| l.role == SplitRole::Payee)?;
    if plan.split.lines[index].recipient == SplitRecipient::LegSubmitter {
        return None;
    }
    recipients(state, &plan.split, &plan.opened_by)
        .ok()
        .map(|r| r[index])
}

/// Slash `bps` of the attestor stake of every member of the route's
/// committees, the accounts their signing keys name, into the insurance
/// pool.
fn slash_committee(
    state: &mut dyn VmState,
    adapter: BridgeRouteAdapter,
    chain: &str,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let Some(route) = super::super::read_bridge_route(state, adapter, chain) else {
        return Ok(());
    };
    let mut members: Vec<[u8; 20]> = route.verifiers.addresses();
    members.extend(route.blessing.iter().flat_map(|q| q.addresses()));
    members.sort_unstable();
    members.dedup();
    let bps = network_param(state, ATTESTOR_SLASH_PARAM).min(10_000) as u16;
    for m in members {
        let mut account = [0u8; 32];
        account[..20].copy_from_slice(&m);
        super::super::staking::slash_to_insurance(
            state,
            &account,
            super::super::staking::SlashedStake::Role(NetworkRole::Attestor),
            bps,
            changes,
        )?;
    }
    Ok(())
}

/// Reconcile the lock of route `(adapter, chain)` (see the module docs).
#[allow(clippy::too_many_arguments)]
pub(super) fn reconcile(
    state: &mut dyn VmState,
    chain_id: u64,
    adapter: BridgeRouteAdapter,
    chain: &str,
    entries: &[ReconEntry],
    checkpoint: &[u8],
    sender: &Address,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    if entries.is_empty() || entries.len() > MAX_RECON_ENTRIES {
        return Err(refuse(format!(
            "a reconciliation submits 1 to {MAX_RECON_ENTRIES} entries"
        )));
    }
    let chain = chain.to_ascii_lowercase();
    let epoch = economy::read_current_epoch(state);
    let mut view = super::super::bridge::VmRouteState::new(state, chain_id, now_ms, epoch);
    let (record, light_client, digest) = super::super::bridge::route_framework()
        .prove_lock(&mut view, adapter, &chain, checkpoint)
        .map_err(|e| refuse(format!("checkpoint proof refused by the route: {e}")))?;
    let tenzro_bridge::route::receipt_proof::LockRecord::Checkpoint(proven) = record else {
        return Err(refuse(
            "a reconciliation is proven by the lock's checkpoint, not a Locked event",
        ));
    };
    changes.extend(view.into_changes());
    let proof = Proven {
        checkpoint: proven,
        digest,
        attested: !light_client,
    };
    apply(
        state, adapter, &chain, proof, entries, sender, now_ms, epoch, changes, logs,
    )
}

/// A lock checkpoint the route proved: the checkpoint, the SHA-256 of its
/// evidence and whether the route admitted it on its committee's
/// attestation alone.
#[derive(Debug, Clone, Copy)]
pub(super) struct Proven {
    pub(super) checkpoint: LockCheckpoint,
    pub(super) digest: [u8; 32],
    pub(super) attested: bool,
}

/// Check `entries` against the proven lock checkpoint and record the result.
/// Mismatches disable the route and, on an attested route, slash its
/// committees' attestor stake into the insurance pool. The first
/// reconciliation of the route in `epoch` is paid its reconciliation duty.
#[allow(clippy::too_many_arguments)]
pub(super) fn apply(
    state: &mut dyn VmState,
    adapter: BridgeRouteAdapter,
    chain: &str,
    proof: Proven,
    entries: &[ReconEntry],
    sender: &Address,
    now_ms: i64,
    epoch: u64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let Proven {
        checkpoint: proven,
        digest,
        attested,
    } = proof;
    let chain = chain.to_string();
    let mut rec = read_reconciliation(state, adapter, &chain).unwrap_or_default();
    if proven.count != rec.count + entries.len() as u64 {
        return Err(refuse(format!(
            "the checkpoint holds {} entries; {} are reconciled and {} submitted",
            proven.count,
            rec.count,
            entries.len()
        )));
    }
    let mut acc = rec.acc;
    let mut befores = Vec::with_capacity(entries.len());
    for e in entries {
        befores.push(acc);
        acc = e.fold(&acc);
    }
    if acc != proven.acc {
        return Err(refuse("the entries do not fold to the checkpoint's hash"));
    }

    let at_ms = u64::try_from(now_ms).unwrap_or_default();
    let mut found = 0usize;
    for (i, (e, before)) in entries.iter().zip(befores).enumerate() {
        let Some((reason, cost)) = disagreement(state, adapter, &chain, e) else {
            continue;
        };
        let position = rec.count + i as u64 + 1;
        let (harmed, loss) = match cost {
            Some((account, usd_e6)) => (Some(account), super::usd_e6_to_wei(state, usd_e6)),
            None => (None, 0),
        };
        let m = ReconMismatch {
            adapter,
            chain: chain.clone(),
            position,
            acc_before: before,
            entry: e.clone(),
            reason,
            checkpoint_digest: digest,
            submitted_by: *sender,
            at_ms,
            attested,
            harmed,
            loss,
        };
        write_json(state, &mismatch_key(adapter, &chain, position), &m, changes)?;
        logs.push(Log::new(
            SYSTEM_ADDRESS.to_vec(),
            vec![RECON_MISMATCH_TOPIC.to_vec()],
            serde_json::to_vec(&m)
                .map_err(|e| crate::error::VmError::Internal(format!("encode mismatch: {e}")))?,
        ));
        rec.mismatches.push(position);
        found += 1;
    }
    rec.count = proven.count;
    rec.acc = acc;
    rec.checkpoint_digest = digest;
    rec.at_ms = at_ms;
    write_json(state, &recon_key(adapter, &chain), &rec, changes)?;

    if found > 0 {
        let stop = BridgeCircuitTrip {
            adapter,
            source_chain: chain.clone(),
            mode: BridgeRouteMode::Disabled,
            by: BridgeCircuitAuthority::Reconciliation,
            reason: format!("{found} reconciliation mismatch(es) of the settlement lock"),
            evidence_hash: Some(hex::encode(digest)),
            epoch,
            at_ms: now_ms,
        };
        trip(state, &stop, changes, logs)?;
        if attested {
            slash_committee(state, adapter, &chain, changes)?;
        }
    }
    pay_job(state, adapter, &chain, epoch, sender, changes)
}
