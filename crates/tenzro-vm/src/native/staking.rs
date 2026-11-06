//! Validator bond accounting in consensus state.
//!
//! A validator's bond is TNZO held by the staking vault account and recorded
//! per validator under `staking_bond:<addr>`. Leaving is two steps: the bond
//! first moves to `staking_unbonding:<addr>`, where it no longer counts as
//! stake but is still held by the vault and can still be slashed, and only
//! after the governed unbonding period ([`UNBONDING_PARAM`]) can it be paid
//! out.
//!
//! Two totals are kept alongside the per-validator records, so nothing has to
//! trust the vault's balance to mean anything: `total_bonded` and
//! `total_unbonding`. Whatever the vault holds beyond their sum was sent to it
//! by someone else and is not stake.
//!
//! Part of a bond may be sponsored: existing treasury TNZO an enacted
//! proposal bonded on the validator's behalf ([`super::sponsored_bond`]). It
//! sits inside the bond and the unbonding records, counts toward the bond and
//! is slashed with it, pro rata, but it is tracked as a lien
//! (`staking_sponsored:<addr>`, `staking_sponsored_unbonding:<addr>`) so that
//! it never votes and, when it leaves the vault, goes back to the treasury
//! rather than to the validator. Governance quorum divides by the bonded total
//! less the sponsored total ([`governance_total_bonded`]).

use serde::{Deserialize, Serialize};

use super::{STAKING_VAULT_ADDRESS, SYSTEM_ADDRESS, derive_insurance_pool_address, network_param};
use crate::error::{Result, VmError};
use crate::traits::VmState;
use crate::types::StateChange;

/// Governed key: how long an exiting validator's bond stays slashable in the
/// vault before it can be withdrawn, ms.
pub const UNBONDING_PARAM: &str = "staking.validator_unbonding_ms";
/// Genesis value of [`UNBONDING_PARAM`]: seven days.
pub const DEFAULT_VALIDATOR_UNBONDING_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// Governed key: the signature schemes a consensus key may be registered
/// under, one bit per scheme id.
pub const SIGNATURE_SCHEMES_PARAM: &str = "staking.validator_signature_schemes";
/// Genesis value of [`SIGNATURE_SCHEMES_PARAM`]: the default scheme only.
pub const DEFAULT_SIGNATURE_SCHEMES: u64 = 1;

/// Whether governance admits consensus keys of `scheme`.
pub fn scheme_admitted(
    state: &dyn VmState,
    scheme: tenzro_types::signature_scheme::SignatureScheme,
) -> bool {
    network_param(state, SIGNATURE_SCHEMES_PARAM) & (1u64 << scheme.id()) != 0
}

/// Governed key: share of the active set's self-stake that may finish
/// exiting in one epoch, bps. The node hands it to the validator registry at
/// every epoch boundary; at least one exit always completes.
pub const EXIT_CHURN_PARAM: &str = "staking.exit_churn_bps";

/// Governed key: consecutive epochs without a certified signature after
/// which a validator is moved to exit, so a validator that is gone cannot
/// hold the quorum above what the live set reaches. 0 turns ejection off.
pub const INACTIVITY_LIMIT_PARAM: &str = "staking.inactivity_limit_epochs";

/// Governed key: ejection never leaves fewer than this many validators in
/// the active set.
pub const ACTIVE_FLOOR_PARAM: &str = "staking.active_set_floor";

/// Governed key: the first epoch whose validators' participation is
/// counted toward inactivity ejection. A running chain sets it to an epoch
/// every node has reached the build that keeps the count; a new chain
/// starts it at 0.
pub const INACTIVITY_ACTIVATION_PARAM: &str = "staking.inactivity_activation_epoch";

/// Governed key: epochs a validator slashed for misbehaviour stays jailed
/// before it returns as a candidate. A longer term asks more of the
/// validator, so raising it waits out the tightening grace window.
pub const JAIL_TERM_PARAM: &str = "slashing.jail_term_epochs";

/// Storage key, under the system account, of the epoch in which a
/// reinstatement of the validator at `addr` was enacted.
pub fn reinstatement_key(addr: &[u8]) -> String {
    format!("validator_reinstated:{}", hex::encode(addr))
}

/// The epoch in which governance last enacted a reinstatement of `addr`, if
/// it ever did. The node releases a jailed validator whose jailing is not
/// newer than this.
pub fn reinstated_at_epoch(state: &dyn VmState, addr: &[u8]) -> Option<u64> {
    state
        .get_storage(&SYSTEM_ADDRESS, reinstatement_key(addr).as_bytes())
        .filter(|b| b.len() == 8)
        .map(|b| u64::from_le_bytes(b[..8].try_into().expect("eight bytes")))
}

/// Governed key: offences within this many checkpoints of each other are
/// correlated, so each offender's penalty is scaled by the stake of every
/// offender in the window.
pub const CORRELATION_WINDOW_PARAM: &str = "slashing.correlation_window_checkpoints";
/// Genesis value of [`CORRELATION_WINDOW_PARAM`].
pub const DEFAULT_CORRELATION_WINDOW_CHECKPOINTS: u64 = 16;

/// Governed key: the least an equivocation costs, bps of the offender's
/// stake. An isolated equivocation is far more often a misconfigured
/// failover or a restored snapshot than an attack, and a rate high enough to
/// be ruinous for an honest mistake discourages small operators.
pub const EQUIVOCATION_MIN_SLASH_PARAM: &str = "slashing.equivocation_min_bps";
/// Genesis value of [`EQUIVOCATION_MIN_SLASH_PARAM`]: 5%.
pub const DEFAULT_EQUIVOCATION_MIN_SLASH_BPS: u64 = 500;

/// Governed key: how steeply an equivocation's penalty grows with the stake
/// that equivocated with it, and the multiple of the floor a repeat offender
/// pays. At 3, one third of the stake equivocating together (what an attack
/// on finality needs) costs each of them their whole stake.
pub const CORRELATION_MULTIPLIER_PARAM: &str = "slashing.correlation_multiplier";
/// Genesis value of [`CORRELATION_MULTIPLIER_PARAM`].
pub const DEFAULT_CORRELATION_MULTIPLIER: u64 = 3;

const RECENT_OFFENCES_KEY: &[u8] = b"staking_recent_offences";

fn offended_key(addr: &[u8]) -> String {
    format!("staking_offended:{}", hex::encode(addr))
}

fn consensus_key_index(fingerprint: &[u8; 32]) -> String {
    format!("validator_key:{}", hex::encode(fingerprint))
}

/// Records that `addr` registered the consensus key whose fingerprint is
/// `fingerprint`, so evidence against the key reaches the bond.
pub fn index_consensus_key(state: &mut dyn VmState, fingerprint: &[u8; 32], addr: &[u8]) {
    state.set_storage(
        &SYSTEM_ADDRESS,
        consensus_key_index(fingerprint).as_bytes(),
        addr.to_vec(),
    );
}

fn vrf_key_index(addr: &[u8]) -> String {
    format!("validator_vrf_key:{}", hex::encode(addr))
}

/// Records `addr`'s VRF key: the hardware-derived key, separate from its
/// node key, that its registration proved and its beacon contributions are
/// checked against.
pub fn index_vrf_key(state: &mut dyn VmState, addr: &[u8], vrf_key: &[u8; 32]) {
    state.set_storage(
        &SYSTEM_ADDRESS,
        vrf_key_index(addr).as_bytes(),
        vrf_key.to_vec(),
    );
}

/// The VRF key `addr` registered, if it registered one.
pub fn vrf_key_of(state: &dyn VmState, addr: &[u8]) -> Option<[u8; 32]> {
    state
        .get_storage(&SYSTEM_ADDRESS, vrf_key_index(addr).as_bytes())?
        .try_into()
        .ok()
}

/// The account that registered the consensus key whose fingerprint is
/// `fingerprint`, if one did.
pub fn account_of_consensus_key(state: &dyn VmState, fingerprint: &[u8; 32]) -> Option<Vec<u8>> {
    state
        .get_storage(&SYSTEM_ADDRESS, consensus_key_index(fingerprint).as_bytes())
        .filter(|a| !a.is_empty())
}

const TOTAL_BONDED_KEY: &[u8] = b"staking_total_bonded";
const TOTAL_UNBONDING_KEY: &[u8] = b"staking_total_unbonding";
const TOTAL_SPONSORED_KEY: &[u8] = b"staking_total_sponsored";
const TOTAL_SPONSORED_UNBONDING_KEY: &[u8] = b"staking_total_sponsored_unbonding";

fn sponsored_key(addr: &[u8]) -> String {
    format!("staking_sponsored:{}", hex::encode(addr))
}

fn sponsored_unbonding_key(addr: &[u8]) -> String {
    format!("staking_sponsored_unbonding:{}", hex::encode(addr))
}

fn bond_key(addr: &[u8]) -> String {
    format!("staking_bond:{}", hex::encode(addr))
}

fn unbonding_key(addr: &[u8]) -> String {
    format!("staking_unbonding:{}", hex::encode(addr))
}

fn read_u128(state: &dyn VmState, key: &[u8]) -> u128 {
    state
        .get_storage(&SYSTEM_ADDRESS, key)
        .filter(|b| b.len() == 16)
        .map(|b| {
            let mut a = [0u8; 16];
            a.copy_from_slice(&b);
            u128::from_le_bytes(a)
        })
        .unwrap_or(0)
}

fn write_u128(state: &mut dyn VmState, key: &[u8], value: u128) {
    let bytes = if value == 0 {
        Vec::new()
    } else {
        value.to_le_bytes().to_vec()
    };
    state.set_storage(&SYSTEM_ADDRESS, key, bytes);
}

/// A bond on its way out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unbonding {
    /// Amount still held by the vault for this validator.
    pub amount: u128,
    /// Block time (ms) from which it can be withdrawn.
    pub release_at_ms: i64,
}

fn read_unbonding(state: &dyn VmState, addr: &[u8]) -> Option<Unbonding> {
    let bytes = state.get_storage(&SYSTEM_ADDRESS, unbonding_key(addr).as_bytes())?;
    if bytes.len() != 24 {
        return None;
    }
    let mut amount = [0u8; 16];
    amount.copy_from_slice(&bytes[..16]);
    let mut release = [0u8; 8];
    release.copy_from_slice(&bytes[16..]);
    Some(Unbonding {
        amount: u128::from_le_bytes(amount),
        release_at_ms: i64::from_le_bytes(release),
    })
}

fn write_unbonding(state: &mut dyn VmState, addr: &[u8], unbonding: Option<Unbonding>) {
    let bytes = match unbonding {
        Some(u) if u.amount > 0 => {
            let mut b = u.amount.to_le_bytes().to_vec();
            b.extend_from_slice(&u.release_at_ms.to_le_bytes());
            b
        }
        _ => Vec::new(),
    };
    state.set_storage(&SYSTEM_ADDRESS, unbonding_key(addr).as_bytes(), bytes);
}

/// Stake currently bonded by `addr`. Counts for voting and consensus weight.
pub fn bonded_stake_of(state: &dyn VmState, addr: &[u8]) -> u128 {
    read_u128(state, bond_key(addr).as_bytes())
}

/// Stake bonded network-wide, the denominator governance quorum divides by.
pub fn total_bonded(state: &dyn VmState) -> u128 {
    read_u128(state, TOTAL_BONDED_KEY)
}

/// What the vault owes validators: bonded plus unbonding.
pub fn vault_liabilities(state: &dyn VmState) -> u128 {
    total_bonded(state).saturating_add(read_u128(state, TOTAL_UNBONDING_KEY))
}

/// The sponsored part of `addr`'s bond: treasury TNZO bonded on its behalf.
pub fn sponsored_bond_of(state: &dyn VmState, addr: &[u8]) -> u128 {
    read_u128(state, sponsored_key(addr).as_bytes())
}

/// The sponsored part of what `addr` has unbonding: recalled or exiting
/// sponsored stake, still slashable, owed to the treasury.
pub fn sponsored_unbonding_of(state: &dyn VmState, addr: &[u8]) -> u128 {
    read_u128(state, sponsored_unbonding_key(addr).as_bytes())
}

/// Sponsored stake bonded network-wide.
pub fn total_sponsored_bonded(state: &dyn VmState) -> u128 {
    read_u128(state, TOTAL_SPONSORED_KEY)
}

/// Sponsored stake still in the vault network-wide, bonded or unbonding: what
/// the treasury has out.
pub fn total_sponsored_outstanding(state: &dyn VmState) -> u128 {
    total_sponsored_bonded(state).saturating_add(read_u128(state, TOTAL_SPONSORED_UNBONDING_KEY))
}

/// The part of `addr`'s bond it put up itself.
pub fn own_bonded_stake_of(state: &dyn VmState, addr: &[u8]) -> u128 {
    bonded_stake_of(state, addr).saturating_sub(sponsored_bond_of(state, addr))
}

/// Bonded stake that votes: the bonded total less sponsored stake, which
/// never votes. What governance quorum and the proposal threshold divide by.
pub fn governance_total_bonded(state: &dyn VmState) -> u128 {
    total_bonded(state).saturating_sub(total_sponsored_bonded(state))
}

fn set_sponsored(state: &mut dyn VmState, addr: &[u8], bonded: u128) {
    let before = sponsored_bond_of(state, addr);
    let total = total_sponsored_bonded(state)
        .saturating_sub(before)
        .saturating_add(bonded);
    write_u128(state, sponsored_key(addr).as_bytes(), bonded);
    write_u128(state, TOTAL_SPONSORED_KEY, total);
}

fn set_sponsored_unbonding(state: &mut dyn VmState, addr: &[u8], unbonding: u128) {
    let before = sponsored_unbonding_of(state, addr);
    let total = read_u128(state, TOTAL_SPONSORED_UNBONDING_KEY)
        .saturating_sub(before)
        .saturating_add(unbonding);
    write_u128(state, sponsored_unbonding_key(addr).as_bytes(), unbonding);
    write_u128(state, TOTAL_SPONSORED_UNBONDING_KEY, total);
}

/// `part` of `whole` scaled to `remaining` of it, rounded down.
fn scale(part: u128, remaining: u128, whole: u128) -> u128 {
    if whole == 0 {
        return 0;
    }
    use revm::primitives::U256;
    u128::try_from(U256::from(part) * U256::from(remaining) / U256::from(whole))
        .unwrap_or(remaining)
        .min(remaining)
}

/// Records `amount` of treasury TNZO the caller has already moved into the
/// staking vault as sponsored bond of `addr`: it is added to the bond like
/// any stake increase and to the sponsored lien.
pub(super) fn add_sponsored_bond(
    state: &mut dyn VmState,
    addr: &[u8],
    amount: u128,
    now_ms: i64,
) -> Result<()> {
    add_bond(state, addr, amount, now_ms)?;
    let sponsored = sponsored_bond_of(state, addr)
        .checked_add(amount)
        .ok_or_else(|| VmError::Internal("sponsored bond overflow".to_string()))?;
    set_sponsored(state, addr, sponsored);
    Ok(())
}

/// Moves `amount` of the sponsored part of `addr`'s bond into unbonding: it
/// stops counting as bond at once and stays slashable in the vault for the
/// governed unbonding period, after which it returns to the treasury
/// ([`release_recalled`]). An unbonding already running for `addr` keeps the
/// later of its release time and the recall's.
pub(super) fn recall_sponsored_bond(
    state: &mut dyn VmState,
    addr: &[u8],
    amount: u128,
    now_ms: i64,
) -> Result<Unbonding> {
    crate::invariant_monitor::require_unfrozen(
        state,
        crate::invariant_monitor::GuardedModule::Staking,
    )?;
    let sponsored = sponsored_bond_of(state, addr);
    if amount == 0 || amount > sponsored {
        return Err(VmError::InvalidTransaction(format!(
            "{} has {sponsored} sponsored bond; {amount} cannot be recalled",
            hex::encode(addr)
        )));
    }
    let bond = bonded_stake_of(state, addr);
    let prior = read_unbonding(state, addr);
    let release = now_ms.saturating_add(network_param(state, UNBONDING_PARAM) as i64);
    let unbonding = Unbonding {
        amount: prior
            .map_or(0, |u| u.amount)
            .checked_add(amount)
            .ok_or_else(|| VmError::Internal("unbonding overflow".to_string()))?,
        release_at_ms: prior.map_or(release, |u| u.release_at_ms.max(release)),
    };
    let rest = bond
        .checked_sub(amount)
        .ok_or_else(|| VmError::Internal("sponsored bond exceeds the bond".to_string()))?;
    write_u128(state, bond_key(addr).as_bytes(), rest);
    let bonded_total = total_bonded(state).saturating_sub(amount);
    let unbonding_total = read_u128(state, TOTAL_UNBONDING_KEY).saturating_add(amount);
    write_u128(state, TOTAL_BONDED_KEY, bonded_total);
    write_u128(state, TOTAL_UNBONDING_KEY, unbonding_total);
    write_unbonding(state, addr, Some(unbonding));
    set_sponsored(state, addr, sponsored - amount);
    let lien = sponsored_unbonding_of(state, addr).saturating_add(amount);
    set_sponsored_unbonding(state, addr, lien);
    Ok(unbonding)
}

/// Returns the matured sponsored part of `addr`'s unbonding to the treasury,
/// leaving the rest for the validator. Anyone may cause it. Refuses while the
/// period is running and when nothing sponsored is unbonding. Returns the
/// amount returned.
pub fn release_recalled(state: &mut dyn VmState, addr: &[u8], now_ms: i64) -> Result<u128> {
    crate::invariant_monitor::require_unfrozen(
        state,
        crate::invariant_monitor::GuardedModule::Staking,
    )?;
    let lien = sponsored_unbonding_of(state, addr);
    let unbonding = read_unbonding(state, addr)
        .filter(|_| lien > 0)
        .ok_or_else(|| {
            VmError::InvalidTransaction(format!(
                "{} has no sponsored stake unbonding",
                hex::encode(addr)
            ))
        })?;
    if now_ms < unbonding.release_at_ms {
        return Err(VmError::InvalidTransaction(format!(
            "sponsored stake is unbonding until {} ms, block time is {} ms",
            unbonding.release_at_ms, now_ms
        )));
    }
    let returned = lien.min(unbonding.amount);
    let treasury = super::derive_treasury_address();
    pay_from_vault(state, treasury.as_bytes(), returned)?;
    let unbonding_total = read_u128(state, TOTAL_UNBONDING_KEY).saturating_sub(returned);
    write_u128(state, TOTAL_UNBONDING_KEY, unbonding_total);
    write_unbonding(
        state,
        addr,
        Some(Unbonding {
            amount: unbonding.amount - returned,
            release_at_ms: unbonding.release_at_ms,
        }),
    );
    set_sponsored_unbonding(state, addr, 0);
    Ok(returned)
}

/// Pays `amount` out of the staking vault to `to`.
fn pay_from_vault(state: &mut dyn VmState, to: &[u8], amount: u128) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let vault = state.get_balance(&STAKING_VAULT_ADDRESS);
    let new_vault = vault
        .checked_sub(amount)
        .ok_or(VmError::InsufficientBalance {
            required: amount,
            available: vault,
        })?;
    state.set_balance(&STAKING_VAULT_ADDRESS, new_vault);
    let balance = state.get_balance(to);
    state.set_balance(
        to,
        balance
            .checked_add(amount)
            .ok_or_else(|| VmError::Internal("stake refund overflow".to_string()))?,
    );
    Ok(())
}

/// Records `amount` the caller has already moved into the staking vault as
/// bond of `addr` at block time `now_ms`. The increase is remembered for the
/// longest governance voting window plus the longest minimum bond age, so a
/// vote weighs the bond that had aged when the proposal opened
/// ([`vote_weight`]).
pub fn add_bond(state: &mut dyn VmState, addr: &[u8], amount: u128, now_ms: i64) -> Result<()> {
    crate::invariant_monitor::require_unfrozen(
        state,
        crate::invariant_monitor::GuardedModule::Staking,
    )?;
    let before = bonded_stake_of(state, addr);
    let bond = before
        .checked_add(amount)
        .ok_or_else(|| VmError::Internal("bond overflow".to_string()))?;
    let total = total_bonded(state)
        .checked_add(amount)
        .ok_or_else(|| VmError::Internal("total bond overflow".to_string()))?;
    write_u128(state, bond_key(addr).as_bytes(), bond);
    write_u128(state, TOTAL_BONDED_KEY, total);
    let horizon = now_ms
        .saturating_sub(crate::governance::ProposalTrack::longest_voting_period_ms())
        .saturating_sub(crate::governance::MAX_MIN_BOND_AGE_MS);
    let mut increases: Vec<BondIncrease> = read_increases(state, addr)
        .into_iter()
        .filter(|i| i.at_ms >= horizon)
        .collect();
    increases.push(BondIncrease {
        at_ms: now_ms,
        before,
    });
    let blob = serde_json::to_vec(&increases)
        .map_err(|e| VmError::Internal(format!("bond history: {e}")))?;
    state.set_storage(&SYSTEM_ADDRESS, increases_key(addr).as_bytes(), blob);
    Ok(())
}

/// One bond increase: when, and the bond just before it.
#[derive(serde::Serialize, serde::Deserialize)]
struct BondIncrease {
    at_ms: i64,
    before: u128,
}

fn increases_key(addr: &[u8]) -> String {
    format!("bond_increases:{}", hex::encode(addr))
}

fn read_increases(state: &dyn VmState, addr: &[u8]) -> Vec<BondIncrease> {
    state
        .get_storage(&SYSTEM_ADDRESS, increases_key(addr).as_bytes())
        .filter(|b| !b.is_empty())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Weight of `addr` on `proposal`: the bond it already held the proposal's
/// minimum bond age before the proposal opened, or the bond it put up itself
/// now if that is lower (exit and slashing reduce it, and sponsored stake
/// never votes).
pub fn vote_weight(
    state: &dyn VmState,
    addr: &[u8],
    proposal: &crate::governance::Proposal,
) -> u128 {
    let aged_at = proposal
        .created_ms
        .saturating_sub(proposal.rules.min_bond_age_ms.max(0));
    bond_at(state, addr, aged_at).min(own_bonded_stake_of(state, addr))
}

/// Bond `addr` held at block time `at_ms`, for any `at_ms` within the
/// longest governance voting window plus the longest minimum bond age: the bond before the first increase
/// after `at_ms`, or the current bond when there was none. Decreases (exit,
/// slashing) are not tracked here; a caller takes the minimum with the
/// current bond.
pub fn bond_at(state: &dyn VmState, addr: &[u8], at_ms: i64) -> u128 {
    read_increases(state, addr)
        .into_iter()
        .find(|i| i.at_ms > at_ms)
        .map(|i| i.before)
        .unwrap_or_else(|| bonded_stake_of(state, addr))
}

/// First exit step: moves the whole bond of `addr` into unbonding, releasable
/// after the governed unbonding period. Returns `None` when `addr` has no
/// bond, which is when the second step applies instead.
pub fn begin_unbonding(
    state: &mut dyn VmState,
    addr: &[u8],
    now_ms: i64,
) -> Result<Option<Unbonding>> {
    crate::invariant_monitor::require_unfrozen(
        state,
        crate::invariant_monitor::GuardedModule::Staking,
    )?;
    let bond = bonded_stake_of(state, addr);
    if bond == 0 {
        return Ok(None);
    }
    let prior = read_unbonding(state, addr).map(|u| u.amount).unwrap_or(0);
    let unbonding = Unbonding {
        amount: prior
            .checked_add(bond)
            .ok_or_else(|| VmError::Internal("unbonding overflow".to_string()))?,
        release_at_ms: now_ms.saturating_add(network_param(state, UNBONDING_PARAM) as i64),
    };
    let bonded_total = total_bonded(state).saturating_sub(bond);
    let unbonding_total = read_u128(state, TOTAL_UNBONDING_KEY).saturating_add(bond);
    write_u128(state, bond_key(addr).as_bytes(), 0);
    write_u128(state, TOTAL_BONDED_KEY, bonded_total);
    write_u128(state, TOTAL_UNBONDING_KEY, unbonding_total);
    write_unbonding(state, addr, Some(unbonding));
    // The sponsored part leaves with the bond and stays owed to the treasury.
    let sponsored = sponsored_bond_of(state, addr);
    if sponsored > 0 {
        set_sponsored(state, addr, 0);
        let lien = sponsored_unbonding_of(state, addr).saturating_add(sponsored);
        set_sponsored_unbonding(state, addr, lien);
    }
    Ok(Some(unbonding))
}

/// Second exit step: pays a matured unbonding out of the vault to `addr`.
///
/// Refuses while the period is running, when there is nothing unbonding, and
/// when the vault does not hold the amount (it never pays out what it does
/// not have).
pub fn withdraw_unbonded(state: &mut dyn VmState, addr: &[u8], now_ms: i64) -> Result<u128> {
    withdraw_unbonded_to(state, addr, addr, now_ms)
}

/// [`withdraw_unbonded`] of `addr`'s matured unbonding, paid to `payee`.
/// Returns what `payee` was paid; a sponsored part goes to the treasury
/// ([`withdraw_unbonded_split`]).
pub fn withdraw_unbonded_to(
    state: &mut dyn VmState,
    addr: &[u8],
    payee: &[u8],
    now_ms: i64,
) -> Result<u128> {
    withdraw_unbonded_split(state, addr, payee, now_ms).map(|(paid, _)| paid)
}

/// Pays `addr`'s matured unbonding out of the vault: its sponsored part to
/// the treasury, the rest to `payee`. Returns `(paid to payee, returned to
/// the treasury)`.
pub fn withdraw_unbonded_split(
    state: &mut dyn VmState,
    addr: &[u8],
    payee: &[u8],
    now_ms: i64,
) -> Result<(u128, u128)> {
    crate::invariant_monitor::require_unfrozen(
        state,
        crate::invariant_monitor::GuardedModule::Staking,
    )?;
    let unbonding = read_unbonding(state, addr)
        .ok_or_else(|| VmError::InvalidTransaction("no bond and nothing unbonding".to_string()))?;
    if now_ms < unbonding.release_at_ms {
        return Err(VmError::InvalidTransaction(format!(
            "bond is unbonding until {} ms, block time is {} ms",
            unbonding.release_at_ms, now_ms
        )));
    }
    let vault = state.get_balance(&STAKING_VAULT_ADDRESS);
    if vault < unbonding.amount {
        return Err(VmError::InsufficientBalance {
            required: unbonding.amount,
            available: vault,
        });
    }
    let returned = sponsored_unbonding_of(state, addr).min(unbonding.amount);
    let paid = unbonding.amount - returned;
    let treasury = super::derive_treasury_address();
    pay_from_vault(state, treasury.as_bytes(), returned)?;
    pay_from_vault(state, payee, paid)?;
    let unbonding_total = read_u128(state, TOTAL_UNBONDING_KEY).saturating_sub(unbonding.amount);
    write_u128(state, TOTAL_UNBONDING_KEY, unbonding_total);
    write_unbonding(state, addr, None);
    set_sponsored_unbonding(state, addr, 0);
    Ok((paid, returned))
}

/// Storage entries that bond each genesis validator's stake: its bond, the
/// bonded total, the index from its consensus key to its account, so
/// evidence against a genesis key reaches its bond exactly as it reaches a
/// key registered later, and its VRF key. Each entry is `(account, consensus
/// key fingerprint, VRF key, stake)`. The caller credits the returned total
/// to the staking vault's balance.
pub fn genesis_validator_bonds(
    bonds: &[([u8; 32], [u8; 32], [u8; 32], u128)],
) -> Result<(Vec<(Vec<u8>, Vec<u8>)>, u128)> {
    let mut entries = Vec::with_capacity(bonds.len() * 3 + 1);
    let mut total: u128 = 0;
    for (addr, fingerprint, vrf_key, amount) in bonds {
        if *amount == 0 {
            continue;
        }
        total = total
            .checked_add(*amount)
            .ok_or_else(|| VmError::Internal("genesis bond overflow".to_string()))?;
        entries.push((bond_key(addr).into_bytes(), amount.to_le_bytes().to_vec()));
        entries.push((consensus_key_index(fingerprint).into_bytes(), addr.to_vec()));
        entries.push((vrf_key_index(addr).into_bytes(), vrf_key.to_vec()));
    }
    if total > 0 {
        entries.push((TOTAL_BONDED_KEY.to_vec(), total.to_le_bytes().to_vec()));
    }
    Ok((entries, total))
}

/// The staking vault's account.
pub fn staking_vault_address() -> [u8; 20] {
    STAKING_VAULT_ADDRESS
}

/// An equivocation inside the correlation window, as it was slashed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowOffence {
    /// Checkpoint index of the latest offence.
    pub index: u64,
    /// The offending account.
    pub addr: Vec<u8>,
    /// Its bonded stake when it first offended in the window.
    pub bonded: u128,
    /// Its bonded and unbonding stake when it first offended in the window.
    pub at_stake: u128,
    /// The rate it has paid so far, basis points of `at_stake`.
    pub applied_bps: u16,
    /// What has been taken from it for the window's offences.
    pub taken: u128,
    /// The part of `taken` that came out of bonded stake.
    pub taken_bonded: u128,
}

/// The equivocations inside the current correlation window.
pub fn window_offences(state: &dyn VmState) -> Result<Vec<WindowOffence>> {
    state
        .get_storage(&SYSTEM_ADDRESS, RECENT_OFFENCES_KEY)
        .filter(|b| !b.is_empty())
        .map(|b| {
            bincode::deserialize(&b)
                .map_err(|e| VmError::Internal(format!("recent offences decode: {e}")))
        })
        .transpose()
        .map(Option::unwrap_or_default)
}

/// The equivocation rate, basis points, when offenders holding
/// `correlated_bonded` of `total_bonded` equivocated within one window:
/// `multiplier` times their share of bonded stake, at least `floor_bps`, at
/// most everything.
pub fn correlated_slash_bps(
    correlated_bonded: u128,
    total_bonded: u128,
    floor_bps: u32,
    multiplier: u32,
) -> u16 {
    if total_bonded == 0 {
        return 10_000;
    }
    let scaled = correlated_bonded
        .saturating_mul(u128::from(multiplier))
        .min(total_bonded);
    let bps = scaled
        .checked_mul(10_000)
        .map_or_else(|| scaled / (total_bonded / 10_000), |x| x / total_bonded);
    bps.max(u128::from(floor_bps)).min(10_000) as u16
}

/// Slashes `addr` for signing two different checkpoints with checkpoint
/// index `index`, into the insurance pool.
///
/// The rate is proportional to the stake that equivocated together: every
/// offender within the governed correlation window of another pays
/// [`correlated_slash_bps`] of its stake, at least
/// the governed equivocation floor (the correlation multiple of it for a validator that has
/// offended before). When a later offence raises the window's rate, the
/// earlier offenders are topped up to it, so the outcome does not depend on
/// the order evidence lands in. Returns the total amount taken, from the
/// offender and from any topped-up co-offenders.
pub fn slash_for_equivocation(
    state: &mut dyn VmState,
    addr: &[u8],
    index: u64,
    changes: &mut Vec<StateChange>,
) -> Result<u128> {
    let window_checkpoints = network_param(state, CORRELATION_WINDOW_PARAM);
    let floor_bps = network_param(state, EQUIVOCATION_MIN_SLASH_PARAM).min(10_000) as u32;
    let multiplier = network_param(state, CORRELATION_MULTIPLIER_PARAM).min(100) as u32;
    let mut window = window_offences(state)?;
    window.retain(|o| o.index.abs_diff(index) <= window_checkpoints);
    let repeat = state
        .get_storage(&SYSTEM_ADDRESS, offended_key(addr).as_bytes())
        .is_some_and(|m| !m.is_empty());
    state.set_storage(&SYSTEM_ADDRESS, offended_key(addr).as_bytes(), vec![1]);
    match window.iter_mut().find(|o| o.addr.as_slice() == addr) {
        Some(own) => own.index = own.index.max(index),
        None => window.push(WindowOffence {
            index,
            addr: addr.to_vec(),
            bonded: bonded_stake_of(state, addr),
            at_stake: bonded_stake_of(state, addr)
                .saturating_add(read_unbonding(state, addr).map_or(0, |u| u.amount)),
            applied_bps: 0,
            taken: 0,
            taken_bonded: 0,
        }),
    }

    // An offender's stake counts whether it was still bonded or already
    // unbonding when the evidence landed: starting to exit does not shrink
    // the share of stake that equivocated together. Its unbonding left the
    // bonded total, so it is added back to the denominator as well.
    // Stake is bounded by supply, so these sums saturate rather than fail: a
    // slash must never be refused for the size of the stake it takes.
    let correlated = window
        .iter()
        .fold(0u128, |t, o| t.saturating_add(o.at_stake));
    let bonded_before = window.iter().fold(total_bonded(state), |t, o| {
        t.saturating_add(
            o.taken_bonded
                .saturating_add(o.at_stake.saturating_sub(o.bonded)),
        )
    });
    let window_rate = correlated_slash_bps(correlated, bonded_before, floor_bps, multiplier);
    let own_floor = if repeat {
        floor_bps * multiplier
    } else {
        floor_bps
    };

    let mut taken_total = 0u128;
    for o in window.iter_mut() {
        let rate = if o.addr.as_slice() == addr {
            window_rate.max(own_floor.min(10_000) as u16)
        } else {
            window_rate
        };
        if rate <= o.applied_bps {
            continue;
        }
        let owed = bps_share(o.at_stake, u128::from(rate)).saturating_sub(o.taken);
        let (from_bond, from_unbonding) = take(state, &o.addr, owed)?;
        o.applied_bps = rate;
        o.taken = o
            .taken
            .saturating_add(from_bond.saturating_add(from_unbonding));
        o.taken_bonded += from_bond;
        taken_total = taken_total.saturating_add(from_bond.saturating_add(from_unbonding));
    }

    let encoded = bincode::serialize(&window)
        .map_err(|e| VmError::Internal(format!("recent offences encode: {e}")))?;
    state.set_storage(&SYSTEM_ADDRESS, RECENT_OFFENCES_KEY, encoded);
    credit_pool(state, taken_total, changes)?;
    Ok(taken_total)
}

/// Which of an account's stakes a slash takes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlashedStake {
    /// Its validator bond.
    Validator,
    /// Its bond for a role it serves.
    Role(tenzro_types::network::NetworkRole),
}

/// Slashes `bps` basis points of `stake` of `addr`, bonded and unbonding,
/// into the insurance pool, recording the credit. The one route by which a
/// protocol offence takes stake. Returns the amount taken.
pub fn slash_to_insurance(
    state: &mut dyn VmState,
    addr: &[u8],
    stake: SlashedStake,
    bps: u16,
    changes: &mut Vec<StateChange>,
) -> Result<u128> {
    let taken = match stake {
        SlashedStake::Validator => slash(state, addr, bps)?,
        SlashedStake::Role(role) => {
            super::role_stake::take_role_stake(state, addr, role, bps, changes)?
        }
    };
    credit_pool(state, taken, changes)?;
    Ok(taken)
}

/// Credit `taken`, already removed from a stake, to the insurance pool and
/// record it as slash revenue.
fn credit_pool(state: &mut dyn VmState, taken: u128, changes: &mut Vec<StateChange>) -> Result<()> {
    if taken == 0 {
        return Ok(());
    }
    let pool = derive_insurance_pool_address().as_bytes().to_vec();
    let before = state.get_balance(&pool);
    let after = before
        .checked_add(taken)
        .ok_or_else(|| VmError::Internal("insurance pool balance overflow".to_string()))?;
    state.set_balance(&pool, after);
    changes.push(StateChange::new(
        pool,
        b"balance".to_vec(),
        Some(before.to_le_bytes().to_vec()),
        Some(after.to_le_bytes().to_vec()),
    ));
    super::insurance::note_credit(state, taken, super::insurance::PoolSource::Slash, changes)?;
    Ok(())
}

/// `bps` basis points of `amount`, rounded down, without overflowing for any
/// `amount`. `bps` above 10 000 counts as 10 000.
pub(crate) fn bps_share(amount: u128, bps: u128) -> u128 {
    let bps = bps.min(10_000);
    share_of_lots(amount / 10_000, bps) + share_of_rest(amount % 10_000, bps)
}

/// `bps` basis points of `lots` whole lots of 10 000.
#[cfg_attr(kani, kani::requires(lots <= u128::MAX / 10_000 && bps <= 10_000))]
#[cfg_attr(kani, kani::ensures(|share: &u128| *share <= lots * 10_000
    && (bps != 10_000 || *share == lots * 10_000)
    && (bps != 0 || *share == 0)))]
pub(crate) fn share_of_lots(lots: u128, bps: u128) -> u128 {
    lots * bps
}

/// `bps` basis points of `rest`, less than one lot of 10 000, rounded down.
#[cfg_attr(kani, kani::requires(rest < 10_000 && bps <= 10_000))]
#[cfg_attr(kani, kani::ensures(|share: &u128| *share <= rest
    && (bps != 10_000 || *share == rest)
    && (bps != 0 || *share == 0)))]
pub(crate) fn share_of_rest(rest: u128, bps: u128) -> u128 {
    rest * bps / 10_000
}

/// What a slash of `bps` takes from a bond and an unbonding amount, and
/// their sum; `None` if the sum overflows.
pub(crate) fn slash_split(bond: u128, unbonding: u128, bps: u16) -> Option<(u128, u128, u128)> {
    let from_bond = bps_share(bond, u128::from(bps));
    let from_unbonding = bps_share(unbonding, u128::from(bps));
    Some((
        from_bond,
        from_unbonding,
        from_bond.checked_add(from_unbonding)?,
    ))
}

/// Slashes `bps` basis points of everything `addr` has at stake, bonded and
/// unbonding, taking it out of the vault. Returns the amount taken, which
/// the caller credits to its destination.
fn slash(state: &mut dyn VmState, addr: &[u8], bps: u16) -> Result<u128> {
    let bond = bonded_stake_of(state, addr);
    let unbonding = read_unbonding(state, addr);
    let (from_bond, from_unbonding, total) =
        slash_split(bond, unbonding.as_ref().map_or(0, |u| u.amount), bps)
            .ok_or_else(|| VmError::Internal("slashed stake overflows".to_string()))?;
    if total == 0 {
        return Ok(0);
    }

    remove(state, addr, bond, unbonding, from_bond, from_unbonding)?;
    Ok(total)
}

/// Takes up to `amount` from what `addr` has at stake, bonded first, then
/// unbonding, out of the vault. Returns what came from each.
fn take(state: &mut dyn VmState, addr: &[u8], amount: u128) -> Result<(u128, u128)> {
    let bond = bonded_stake_of(state, addr);
    let unbonding = read_unbonding(state, addr);
    let from_bond = amount.min(bond);
    let from_unbonding = (amount - from_bond).min(unbonding.as_ref().map_or(0, |u| u.amount));
    remove(state, addr, bond, unbonding, from_bond, from_unbonding)?;
    Ok((from_bond, from_unbonding))
}

/// Removes `from_bond` of `bond` and `from_unbonding` of `unbonding` held for
/// `addr` from the vault and the totals.
fn remove(
    state: &mut dyn VmState,
    addr: &[u8],
    bond: u128,
    unbonding: Option<Unbonding>,
    from_bond: u128,
    from_unbonding: u128,
) -> Result<()> {
    let total = from_bond + from_unbonding;
    if total == 0 {
        return Ok(());
    }
    let vault = state.get_balance(&STAKING_VAULT_ADDRESS);
    let new_vault = vault
        .checked_sub(total)
        .ok_or(VmError::InsufficientBalance {
            required: total,
            available: vault,
        })?;
    state.set_balance(&STAKING_VAULT_ADDRESS, new_vault);

    // A slash takes the sponsored part of a stake in proportion, exactly as
    // it takes the rest: what is left of the lien is what is left of the
    // stake scaled by the share that was sponsored.
    if from_bond > 0 {
        let sponsored = sponsored_bond_of(state, addr);
        if sponsored > 0 {
            set_sponsored(state, addr, scale(sponsored, bond - from_bond, bond));
        }
    }
    if let Some(u) = unbonding
        && from_unbonding > 0
    {
        let lien = sponsored_unbonding_of(state, addr);
        if lien > 0 {
            set_sponsored_unbonding(
                state,
                addr,
                scale(lien, u.amount - from_unbonding, u.amount),
            );
        }
    }

    if from_bond > 0 {
        let bonded_total = total_bonded(state).saturating_sub(from_bond);
        write_u128(state, bond_key(addr).as_bytes(), bond - from_bond);
        write_u128(state, TOTAL_BONDED_KEY, bonded_total);
    }
    if let Some(u) = unbonding
        && from_unbonding > 0
    {
        let unbonding_total = read_u128(state, TOTAL_UNBONDING_KEY).saturating_sub(from_unbonding);
        write_unbonding(
            state,
            addr,
            Some(Unbonding {
                amount: u.amount - from_unbonding,
                release_at_ms: u.release_at_ms,
            }),
        );
        write_u128(state, TOTAL_UNBONDING_KEY, unbonding_total);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;

    /// Twenty years of monthly top-ups: the bond history a vote reads keeps
    /// only what the longest voting period and the longest minimum bond age
    /// can reach, and a top-up made inside the minimum bond age before a
    /// proposal opens adds nothing to its weight.
    #[test]
    fn twenty_years_of_top_ups_keep_the_bond_history_bounded_and_late_stake_weightless() {
        const MONTH: i64 = 30 * 24 * 60 * 60 * 1000;
        let mut state = StateAdapter::new();
        let who = [0x42u8; 32];
        let t0: i64 = 1_800_000_000_000;
        for m in 0..240 {
            add_bond(&mut state, &who, 1_000, t0 + m * MONTH).unwrap();
        }
        let horizon = crate::governance::ProposalTrack::longest_voting_period_ms()
            + crate::governance::MAX_MIN_BOND_AGE_MS;
        let kept = read_increases(&state, &who).len() as i64;
        assert!(
            kept <= horizon / MONTH + 2,
            "{kept} increases kept after 240"
        );
        let opens = t0 + 240 * MONTH;
        let aged = bonded_stake_of(&state, &who);
        add_bond(&mut state, &who, 1_000_000, opens - 1).unwrap();
        assert_eq!(
            bond_at(&state, &who, opens - crate::governance::MIN_BOND_AGE_MS),
            aged
        );
    }

    const STAKE: u128 = 1_000_000;

    fn bonded(state: &mut StateAdapter, who: [u8; 32], key: [u8; 32]) {
        let (entries, total) = genesis_validator_bonds(&[(who, key, [7; 32], STAKE)]).unwrap();
        for (k, v) in entries {
            if k.as_slice() == TOTAL_BONDED_KEY {
                let prior = total_bonded(state);
                write_u128(state, TOTAL_BONDED_KEY, prior + total);
            } else {
                state.set_storage(&SYSTEM_ADDRESS, &k, v);
            }
        }
        let vault = state.get_balance(&STAKING_VAULT_ADDRESS);
        state.set_balance(&STAKING_VAULT_ADDRESS, vault + total);
    }

    fn validators(state: &mut StateAdapter, n: u8) -> Vec<[u8; 32]> {
        (1..=n)
            .map(|i| {
                let who = [i; 32];
                let mut key = [0u8; 32];
                key[0] = i;
                key[1] = 0xc0;
                bonded(state, who, key);
                who
            })
            .collect()
    }

    fn rate(bps: u32) -> u128 {
        STAKE * u128::from(bps) / 10_000
    }

    #[test]
    fn a_slash_of_stake_at_the_top_of_the_range_takes_what_there_is_without_overflow() {
        // A bond and an unbonding that together pass u128::MAX: the stake at
        // risk and the window sums saturate instead of overflowing, and the
        // slash still goes through.
        let mut state = StateAdapter::new();
        let who = [9u8; 20];
        add_bond(&mut state, &who, u128::MAX / 2 + 1, 0).unwrap();
        begin_unbonding(&mut state, &who, 0).unwrap();
        add_bond(&mut state, &who, u128::MAX / 2 + 1, 0).unwrap();
        state.set_balance(&STAKING_VAULT_ADDRESS, u128::MAX);
        let mut changes = Vec::new();
        let taken = slash_for_equivocation(&mut state, &who, 1, &mut changes).unwrap();
        assert!(taken > 0);
    }

    #[test]
    fn an_isolated_offence_pays_the_floor_into_the_pool() {
        let mut state = StateAdapter::new();
        let v = validators(&mut state, 100);
        let mut key = [0u8; 32];
        key[0] = 1;
        key[1] = 0xc0;
        assert_eq!(
            account_of_consensus_key(&state, &key).as_deref(),
            Some(v[0].as_slice())
        );
        let pool = derive_insurance_pool_address().as_bytes().to_vec();
        let mut changes = Vec::new();
        let taken = slash_for_equivocation(&mut state, &v[0], 100, &mut changes).unwrap();
        // One percent of stake times three is under the floor.
        assert_eq!(taken, rate(DEFAULT_EQUIVOCATION_MIN_SLASH_BPS as u32));
        assert_eq!(state.get_balance(&pool), taken);
        assert_eq!(
            state.get_balance(&STAKING_VAULT_ADDRESS),
            100 * STAKE - taken
        );
        assert_eq!(total_bonded(&state), 100 * STAKE - taken);
    }

    #[test]
    fn correlated_offences_scale_the_penalty_and_top_up_earlier_offenders() {
        let mut state = StateAdapter::new();
        let v = validators(&mut state, 100);
        let pool = derive_insurance_pool_address().as_bytes().to_vec();
        let mut changes = Vec::new();
        slash_for_equivocation(&mut state, &v[0], 100, &mut changes).unwrap();
        // Three offenders holding 3% of stake: each pays 9%.
        slash_for_equivocation(&mut state, &v[1], 104, &mut changes).unwrap();
        slash_for_equivocation(&mut state, &v[2], 110, &mut changes).unwrap();
        for who in &v[..3] {
            assert_eq!(bonded_stake_of(&state, who), STAKE - rate(900));
        }
        assert_eq!(bonded_stake_of(&state, &v[3]), STAKE);
        assert_eq!(state.get_balance(&pool), 3 * rate(900));
        assert_eq!(total_bonded(&state), 100 * STAKE - 3 * rate(900));
    }

    #[test]
    fn the_outcome_does_not_depend_on_the_order_evidence_lands_in() {
        let run = |order: [usize; 3]| {
            let mut state = StateAdapter::new();
            let v = validators(&mut state, 100);
            let mut changes = Vec::new();
            for i in order {
                slash_for_equivocation(&mut state, &v[i], 200 + i as u64, &mut changes).unwrap();
            }
            v[..3]
                .iter()
                .map(|w| bonded_stake_of(&state, w))
                .collect::<Vec<_>>()
        };
        assert_eq!(run([0, 1, 2]), run([2, 0, 1]));
    }

    #[test]
    fn a_third_of_stake_equivocating_together_loses_everything() {
        let mut state = StateAdapter::new();
        let v = validators(&mut state, 100);
        let pool = derive_insurance_pool_address().as_bytes().to_vec();
        let mut changes = Vec::new();
        for (i, who) in v[..34].iter().enumerate() {
            slash_for_equivocation(&mut state, who, 300 + (i as u64 % 8), &mut changes).unwrap();
        }
        for who in &v[..34] {
            assert_eq!(bonded_stake_of(&state, who), 0);
        }
        assert_eq!(state.get_balance(&pool), 34 * STAKE);
        assert_eq!(correlated_slash_bps(34, 100, 500, 3), 10_000);
        assert_eq!(correlated_slash_bps(1, 100, 500, 3), 500);
        assert_eq!(correlated_slash_bps(2, 100, 500, 3), 600);
    }

    #[test]
    fn a_cartel_that_starts_unbonding_before_the_evidence_lands_still_loses_everything() {
        let mut state = StateAdapter::new();
        let v = validators(&mut state, 100);
        let mut changes = Vec::new();
        // A third of stake equivocates together, then every offender starts
        // unbonding before any evidence is recorded.
        for who in &v[..34] {
            begin_unbonding(&mut state, who, 0).unwrap();
        }
        for (i, who) in v[..34].iter().enumerate() {
            slash_for_equivocation(&mut state, who, 300 + (i as u64 % 8), &mut changes).unwrap();
        }
        for who in &v[..34] {
            assert_eq!(bonded_stake_of(&state, who), 0);
            assert_eq!(read_unbonding(&state, who).map_or(0, |u| u.amount), 0);
        }
        let pool = derive_insurance_pool_address().as_bytes().to_vec();
        assert_eq!(state.get_balance(&pool), 34 * STAKE);
    }

    #[test]
    fn offences_outside_the_window_are_isolated_and_a_repeat_pays_three_times_the_floor() {
        let mut state = StateAdapter::new();
        let v = validators(&mut state, 100);
        let mut changes = Vec::new();
        slash_for_equivocation(&mut state, &v[0], 100, &mut changes).unwrap();
        let later = slash_for_equivocation(
            &mut state,
            &v[1],
            100 + DEFAULT_CORRELATION_WINDOW_CHECKPOINTS + 1,
            &mut changes,
        )
        .unwrap();
        assert_eq!(later, rate(DEFAULT_EQUIVOCATION_MIN_SLASH_BPS as u32));
        let at_stake = STAKE - rate(DEFAULT_EQUIVOCATION_MIN_SLASH_BPS as u32);
        let again = slash_for_equivocation(&mut state, &v[0], 500, &mut changes).unwrap();
        assert_eq!(
            again,
            at_stake
                * u128::from(
                    (DEFAULT_EQUIVOCATION_MIN_SLASH_BPS * DEFAULT_CORRELATION_MULTIPLIER) as u32
                )
                / 10_000
        );
    }
}
