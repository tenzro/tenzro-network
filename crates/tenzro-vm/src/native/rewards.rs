//! Network rewards in consensus state.
//!
//! Every finalized block runs [`begin_block`] before its transactions: it
//! pays the vote work of the checkpoint signers recorded since the last
//! block, closes each epoch older than the block's own (issuing that epoch's
//! coupons and expiring coupons past their claim window) and credits the
//! block's proposer with a block-proposal unit.
//!
//! A certified checkpoint's signers are recorded by a transaction carrying
//! its certificate ([`record_checkpoint_signers`]). Each signer earns one
//! vote unit per consensus round the checkpoint certified, in the
//! checkpoint's epoch, or in the block's own epoch once that one has closed.
//! The same tally gives each validator's share of its epoch's certified
//! rounds ([`EpochVotes::participation_bps`]). Provider work a plan paid,
//! claims and vesting releases are `Funding` operations; the provider work
//! of vouchers, streams, claim hours and direct payments, and the activity
//! of the creators a settlement is attributed to, are recorded as that
//! settlement executes. So the coupons, the pool and every vesting schedule
//! are the same on every node that executed the same chain. The rules are in
//! [`tenzro_token::rewards`].
//!
//! Records, all under `SYSTEM_ADDRESS`:
//! - `reward_state` — the [`RewardEngineState`] aggregate.
//! - `reward_pending:<epoch 16-hex>` — work recorded in an open epoch.
//! - `reward_epoch:<epoch 16-hex>` — a closed epoch's summary.
//! - `reward_coupon:<epoch 16-hex>:<bucket>:<addr hex>` — a coupon.
//! - `reward_coupons_of:<addr hex>` — the keys of an address's coupons.
//! - `reward_epoch_coupons:<epoch 16-hex>` — the keys of an epoch's coupons.
//! - `reward_receipt:<receipt id>` — a settled plan already counted.
//! - `reward_epoch_receipts:<epoch 16-hex>` — how many plans the epoch
//!   counted; `reward_epoch_receipt:<epoch 16-hex>:<seq 16-hex>` — each one,
//!   with the block time it was decided at.
//! - `reward_receipts_decided_through_ms` — the latest decision time of a
//!   counted plan whose record was deleted: a plan decided no later can no
//!   longer be cited.
//! - `reward_votes:<epoch 16-hex>` — an epoch's [`EpochVotes`].
//! - `reward_votes_pending` — vote work recorded and not yet paid.
//! - `vesting:<addr hex>` — an address's vesting schedules.
//! - `reward_pruned_below` — the first epoch whose records are still kept.
//!
//! An epoch's coupons, summary, vote tally and activity are deleted once its
//! claim window has passed: a coupon can no longer be claimed, and a
//! checkpoint of that epoch can no longer be recorded, so nothing reads
//! them again.

use super::funding::{delete_record, move_balance, refuse, write_json};
use super::*;
use tenzro_token::rewards::{
    ClaimOutcome, CouponStatus, EpochRewardSummary, MintPolicy, MintingSchedule, RewardCoupon,
    RewardEngineState, WorkClass, WorkRecord, add_work, coupon_expired, next_mint_mult,
    rewards_pool_address,
};
use tenzro_token::vesting::{VestingKind, VestingSchedule, vesting_escrow_address, vesting_key};

/// Key of the reward aggregate.
pub const REWARD_STATE_KEY: &str = "reward_state";

/// Key of the payout schedule genesis writes, derived from its epoch length.
pub const REWARD_SCHEDULE_KEY: &str = "reward_schedule";

/// Log topic of a reward claim; data is the JSON [`ClaimOutcome`].
pub const REWARDS_CLAIMED_TOPIC: &[u8] = b"RewardsClaimed";

/// Log topic of a vesting release; data is the released amount, LE u128.
pub const VESTING_RELEASED_TOPIC: &[u8] = b"VestingReleased";

fn pending_key(epoch: u64) -> String {
    format!("reward_pending:{epoch:016x}")
}

/// The work recorded so far in open epoch `epoch`.
#[cfg(test)]
pub(crate) fn pending_work(state: &dyn VmState, epoch: u64) -> Vec<WorkRecord> {
    read_record(state, &pending_key(epoch))
        .unwrap()
        .unwrap_or_default()
}

fn summary_key(epoch: u64) -> String {
    format!("reward_epoch:{epoch:016x}")
}

fn coupons_of_key(address: &Address) -> String {
    format!("reward_coupons_of:{}", hex::encode(address.as_bytes()))
}

fn epoch_coupons_key(epoch: u64) -> String {
    format!("reward_epoch_coupons:{epoch:016x}")
}

fn receipt_key(receipt_id: &str) -> String {
    format!("reward_receipt:{receipt_id}")
}

fn epoch_receipts_key(epoch: u64) -> String {
    format!("reward_epoch_receipts:{epoch:016x}")
}

fn epoch_receipt_key(epoch: u64, seq: u64) -> String {
    format!("reward_epoch_receipt:{epoch:016x}:{seq:016x}")
}

/// Key of the latest decision time, ms, of a counted plan whose record was
/// deleted.
const RECEIPTS_DECIDED_THROUGH_KEY: &str = "reward_receipts_decided_through_ms";

fn vesting_list_key(address: &Address) -> String {
    String::from_utf8_lossy(&vesting_key(address)).into_owned()
}

fn votes_key(epoch: u64) -> String {
    format!("reward_votes:{epoch:016x}")
}

/// Key of the first epoch whose records are still kept.
const PRUNED_BELOW_KEY: &str = "reward_pruned_below";

/// Most epochs one block deletes the records of, so a chain that starts
/// deleting late catches up over several blocks at a bounded cost each.
const MAX_PRUNED_EPOCHS_PER_BLOCK: u64 = 64;

/// Key of the vote work recorded and not yet paid.
const VOTES_PENDING_KEY: &str = "reward_votes_pending";

/// Most signers one recorded checkpoint may name.
pub const MAX_CHECKPOINT_SIGNERS: usize = 4_096;

/// The signers of one certified checkpoint, by account.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CheckpointSigners {
    /// The checkpoint's epoch.
    pub epoch: u64,
    /// The checkpoint's index.
    pub index: u64,
    /// Round of the anchor that closed the checkpoint.
    pub anchor_round: u64,
    /// The signers' accounts, distinct.
    pub signers: Vec<Address>,
}

/// One epoch's recorded checkpoints: the consensus rounds they certified and
/// how many of those each validator signed.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EpochVotes {
    /// The first round no recorded checkpoint of the epoch certified.
    pub next_round: u64,
    /// The highest checkpoint index recorded in the epoch.
    pub last_index: Option<u64>,
    /// Rounds the recorded checkpoints certified.
    pub certified_rounds: u64,
    /// Per validator account, the certified rounds of the checkpoints it
    /// signed, in account order.
    pub signed: Vec<(Address, u64)>,
}

impl EpochVotes {
    /// The share of the epoch's certified rounds `validator` signed, in
    /// basis points; `None` before any checkpoint of the epoch is recorded.
    pub fn participation_bps(&self, validator: &Address) -> Option<u64> {
        if self.certified_rounds == 0 {
            return None;
        }
        let signed = self
            .signed
            .iter()
            .find(|(a, _)| a == validator)
            .map_or(0, |(_, r)| *r);
        Some((signed as u128 * 10_000 / self.certified_rounds as u128) as u64)
    }
}

/// One unpaid vote: `(epoch, signer, rounds)`.
type PendingVote = (u64, Address, u64);

/// An epoch's recorded checkpoints.
pub fn read_epoch_votes(state: &dyn VmState, epoch: u64) -> Result<EpochVotes> {
    Ok(read_record(state, &votes_key(epoch))?.unwrap_or_default())
}

/// Records a certified checkpoint's signers: each signed the rounds from
/// the first one no earlier recorded checkpoint of the epoch certified
/// through the checkpoint's anchor round. Adds them to the epoch's tally and
/// queues the vote work the next block pays. A checkpoint at or below one
/// already recorded in its epoch is refused, so each round is counted once.
pub fn record_checkpoint_signers(
    state: &mut dyn VmState,
    record: &CheckpointSigners,
) -> Result<Vec<StateChange>> {
    if record.signers.is_empty() || record.signers.len() > MAX_CHECKPOINT_SIGNERS {
        return Err(refuse("a recorded checkpoint names 1 to 4096 signers"));
    }
    let mut distinct: Vec<[u8; 32]> = record.signers.iter().map(|a| a.0).collect();
    distinct.sort_unstable();
    distinct.dedup();
    if distinct.len() != record.signers.len() {
        return Err(refuse("a recorded checkpoint names a signer twice"));
    }
    // An epoch past its claim window has had its tally deleted; a late
    // checkpoint of it would count its rounds again.
    let current = read_reward_state(state)?.current_epoch;
    if record.epoch < pruned_below(state)?
        || coupon_expired(
            record.epoch,
            current,
            super::network_param(state, CLAIM_WINDOW_PARAM),
        )
    {
        return Err(refuse(format!(
            "checkpoint {} of epoch {} is past the epoch's claim window",
            record.index, record.epoch
        )));
    }
    let mut votes = read_epoch_votes(state, record.epoch)?;
    if votes.last_index.is_some_and(|l| record.index <= l) || record.anchor_round < votes.next_round
    {
        return Err(refuse(format!(
            "checkpoint {} of epoch {} is at or below one already recorded",
            record.index, record.epoch
        )));
    }
    let next_round = record
        .anchor_round
        .checked_add(1)
        .ok_or_else(|| refuse("a recorded checkpoint's anchor round is past the last round"))?;
    let rounds = next_round - votes.next_round;
    votes.next_round = next_round;
    votes.last_index = Some(record.index);
    votes.certified_rounds = votes.certified_rounds.saturating_add(rounds);
    for signer in &record.signers {
        match votes.signed.binary_search_by(|(a, _)| a.0.cmp(&signer.0)) {
            Ok(i) => votes.signed[i].1 = votes.signed[i].1.saturating_add(rounds),
            Err(i) => votes.signed.insert(i, (*signer, rounds)),
        }
    }
    let mut changes = Vec::new();
    write_json(state, &votes_key(record.epoch), &votes, &mut changes)?;
    let mut pending: Vec<PendingVote> = read_record(state, VOTES_PENDING_KEY)?.unwrap_or_default();
    pending.extend(record.signers.iter().map(|s| (record.epoch, *s, rounds)));
    write_json(state, VOTES_PENDING_KEY, &pending, &mut changes)?;
    Ok(changes)
}

/// A stored record, or `None` when absent. A record that is present but
/// does not decode is an error: consensus state is never read as a default.
fn read_record<T: serde::de::DeserializeOwned>(
    state: &dyn VmState,
    key: &str,
) -> Result<Option<T>> {
    match state.get_storage(&SYSTEM_ADDRESS, key.as_bytes()) {
        Some(b) if !b.is_empty() => serde_json::from_slice(&b)
            .map(Some)
            .map_err(|e| VmError::Internal(format!("reward record {key} does not decode: {e}"))),
        _ => Ok(None),
    }
}

/// The reward aggregate.
pub fn read_reward_state(state: &dyn VmState) -> Result<RewardEngineState> {
    Ok(read_record(state, REWARD_STATE_KEY)?.unwrap_or_default())
}

/// The schedule record genesis writes under [`REWARD_SCHEDULE_KEY`] for a
/// chain whose epochs last `epoch_ms` of block time.
pub fn genesis_reward_schedule(epoch_ms: u64) -> Result<Vec<u8>> {
    let schedule = MintingSchedule::for_epoch_ms(epoch_ms).map_err(VmError::Internal)?;
    serde_json::to_vec(&schedule)
        .map_err(|e| VmError::Internal(format!("encode {REWARD_SCHEDULE_KEY}: {e}")))
}

/// The payout schedule genesis fixed. A chain without one cannot close an
/// epoch.
pub fn read_reward_schedule(state: &dyn VmState) -> Result<MintingSchedule> {
    read_record(state, REWARD_SCHEDULE_KEY)?
        .ok_or_else(|| VmError::Internal(format!("{REWARD_SCHEDULE_KEY} missing from genesis")))
}

/// Key of the compressed calendar genesis writes when its calendar runs
/// faster than block time.
pub const CALENDAR_KEY: &str = "calendar";

/// A calendar running `scale` times faster than block time from
/// `anchor_ms`, the genesis time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Calendar {
    pub anchor_ms: i64,
    pub scale: u64,
}

/// The calendar record genesis writes under [`CALENDAR_KEY`].
pub fn genesis_calendar(anchor_ms: i64, scale: u64) -> Result<Vec<u8>> {
    if scale < 2 || anchor_ms <= 0 {
        return Err(VmError::Internal(
            "a compressed calendar needs a scale above 1 and a genesis timestamp".into(),
        ));
    }
    serde_json::to_vec(&Calendar { anchor_ms, scale })
        .map_err(|e| VmError::Internal(format!("encode {CALENDAR_KEY}: {e}")))
}

/// Block time at calendar time `calendar_ms`: the inverse of
/// [`calendar_ms`], calendar time itself unless genesis compressed the
/// calendar.
pub fn block_ms_at(state: &dyn VmState, calendar_ms: i64) -> Result<i64> {
    Ok(match read_record::<Calendar>(state, CALENDAR_KEY)? {
        Some(c) if c.scale > 1 => c
            .anchor_ms
            .saturating_add(calendar_ms.saturating_sub(c.anchor_ms) / c.scale as i64),
        _ => calendar_ms,
    })
}

/// Calendar time at block time `block_ms`: block time itself unless genesis
/// compressed the calendar.
pub fn calendar_ms(state: &dyn VmState, block_ms: i64) -> Result<i64> {
    Ok(match read_record::<Calendar>(state, CALENDAR_KEY)? {
        Some(c) => c.anchor_ms.saturating_add(
            block_ms
                .saturating_sub(c.anchor_ms)
                .saturating_mul(c.scale as i64),
        ),
        None => block_ms,
    })
}

/// A closed epoch's summary.
pub fn read_epoch_summary(state: &dyn VmState, epoch: u64) -> Result<Option<EpochRewardSummary>> {
    read_record(state, &summary_key(epoch))
}

/// Every coupon issued to `address`, newest epoch first.
pub fn read_coupons(state: &dyn VmState, address: &Address) -> Result<Vec<RewardCoupon>> {
    let keys: Vec<String> = read_record(state, &coupons_of_key(address))?.unwrap_or_default();
    let mut out = Vec::with_capacity(keys.len());
    for key in keys {
        if let Some(c) = read_record::<RewardCoupon>(state, &key)? {
            out.push(c);
        }
    }
    out.sort_by_key(|c| std::cmp::Reverse(c.epoch));
    Ok(out)
}

/// Every vesting schedule of `address`.
pub fn read_vesting(state: &dyn VmState, address: &Address) -> Result<Vec<VestingSchedule>> {
    Ok(read_record(state, &vesting_list_key(address))?.unwrap_or_default())
}

/// Moves `amount` from `source` into vesting escrow and opens a schedule
/// for `beneficiary` starting at `now_ms`. Reward claims and treasury grants
/// both vest this way; `ReleaseVesting` pays every schedule out.
#[allow(clippy::too_many_arguments)]
pub(super) fn open_vesting(
    state: &mut dyn VmState,
    source: &[u8],
    beneficiary: Address,
    kind: VestingKind,
    amount: u128,
    now_ms: i64,
    cliff_ms: i64,
    duration_ms: i64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    move_balance(
        state,
        source,
        vesting_escrow_address().as_bytes(),
        amount,
        changes,
    )?;
    let key = vesting_list_key(&beneficiary);
    let mut list: Vec<VestingSchedule> = read_record(state, &key)?.unwrap_or_default();
    drop_released(&mut list);
    list.push(VestingSchedule {
        seq: list.last().map_or(0, |s| s.seq + 1),
        address: beneficiary,
        kind,
        total: amount,
        released: 0,
        start_ms: now_ms,
        cliff_ms,
        duration_ms,
        created_at: Timestamp::new(now_ms),
    });
    write_json(state, &key, &list, changes)?;
    Ok(())
}

/// Drops every schedule paid out in full but the newest, so an address's
/// list holds its open schedules and nothing more, and the next schedule's
/// sequence number still follows the last one handed out.
fn drop_released(list: &mut Vec<VestingSchedule>) {
    let newest = list.len().saturating_sub(1);
    let mut at = 0;
    list.retain(|s| {
        let keep = at == newest || s.released < s.total;
        at += 1;
        keep
    });
}

/// Governed key: epochs an issued reward coupon stays claimable.
pub const CLAIM_WINDOW_PARAM: &str = "rewards.claim_window_epochs";
/// Governed key: share of a reward claim paid liquid, bps; the rest vests.
pub const CLAIM_LIQUID_PARAM: &str = "rewards.claim_liquid_bps";
/// Governed key: share of the running-cost base in a claim paid liquid, bps;
/// the base is the operator's and is split before the rest of the claim.
pub const BASE_LIQUID_PARAM: &str = "rewards.base_liquid_bps";
/// Governed key: ms the vesting part of a reward claim vests over.
pub const CLAIM_VESTING_PARAM: &str = "rewards.claim_vesting_ms";

// The `mint.` keys and `MINT_` names are kept for consensus state and
// governance proposals; they govern releases from the genesis-funded
// network-rewards pool. No TNZO is minted.

/// Governed key: pool release in schedule year 0, whole TNZO.
pub const MINT_BASE_PARAM: &str = "mint.base_tnzo_per_year";
/// Governed key: share of a year's pool release dropped the next year, bps.
pub const MINT_DECAY_PARAM: &str = "mint.decay_bps_per_year";
/// Governed key: least yearly pool release, whole TNZO.
pub const MINT_FLOOR_PARAM: &str = "mint.floor_tnzo_per_year";
/// Governed key: most the controller moves the multiplier per year, bps of 1x.
pub const MINT_ADJ_PARAM: &str = "mint.adj_bps_per_year";
/// Governed key: least controller multiplier, bps of 1x.
pub const MINT_MIN_MULT_PARAM: &str = "mint.min_mult_bps";
/// Governed key: greatest controller multiplier, bps of 1x.
pub const MINT_MAX_MULT_PARAM: &str = "mint.max_mult_bps";
/// Governed key: validators' share of each epoch's pool release, bps.
pub const MINT_VALIDATOR_SHARE_PARAM: &str = "mint.validator_share_bps";
/// Governed key: providers' share, bps.
pub const MINT_PROVIDER_SHARE_PARAM: &str = "mint.provider_share_bps";
/// Governed key: apps' share, paid by measured usage, bps.
pub const MINT_ECOSYSTEM_SHARE_PARAM: &str = "mint.ecosystem_share_bps";
/// Governed key: cap on provider and app payouts, bps of the work weight
/// their settlements recorded.
pub const MINT_REVENUE_PEG_PARAM: &str = "mint.revenue_peg_bps";
/// Governed key: most provider work weight one settlement earns, bps of the
/// protocol fee it paid outside the trade. With the activity reward it stays
/// within [`tenzro_token::rewards::MAX_SETTLEMENT_REWARD_BPS`] of that fee.
pub const PROVIDER_REWARD_COST_PARAM: &str = "mint.provider_reward_cost_bps";
/// Genesis value of [`PROVIDER_REWARD_COST_PARAM`]: four tenths of the fee,
/// beside the activity reward's half.
pub const DEFAULT_PROVIDER_REWARD_COST_BPS: u64 = 4_000;

/// The provider reward share and the activity reward share of a
/// settlement's fee in force, bps: the first two of
/// [`settlement_reward_shares`].
pub fn settlement_reward_bps(state: &dyn VmState) -> (u64, u64) {
    let (provider, activity, _) = settlement_reward_shares(state);
    (provider, activity)
}

/// The provider reward, activity reward and creator royalty shares of a
/// settlement's fee in force, bps. The activity share is read as set (at
/// most the ceiling); the provider share and then the royalty take what is
/// left under [`tenzro_token::rewards::MAX_SETTLEMENT_REWARD_BPS`], so the
/// three together never reach the fee. Governance refuses values that would
/// need the clamp.
pub fn settlement_reward_shares(state: &dyn VmState) -> (u64, u64, u64) {
    use tenzro_token::rewards::MAX_SETTLEMENT_REWARD_BPS;
    let activity = network_param(state, super::economy::ACTIVITY_REWARD_FEE_PARAM)
        .min(MAX_SETTLEMENT_REWARD_BPS);
    let provider =
        network_param(state, PROVIDER_REWARD_COST_PARAM).min(MAX_SETTLEMENT_REWARD_BPS - activity);
    let royalty = network_param(state, super::economy::CREATOR_ROYALTY_FEE_PARAM)
        .min(MAX_SETTLEMENT_REWARD_BPS - activity - provider);
    (provider, activity, royalty)
}

/// The provider work a payment to `payee` is, from the bond or stake that
/// account holds: a stream paid to the account that posted a compute bond
/// is a compute lease; any other payment is a TEE session for a bonded TEE
/// provider, RPC traffic for a bonded RPC operator, and inference for the
/// account that posted a compute bond. `None` when it holds none of them.
pub(super) fn provider_class(state: &dyn VmState, payee: &[u8], stream: bool) -> Option<WorkClass> {
    use tenzro_types::network::NetworkRole;
    let bonded = || {
        identity_did_of(state, payee)
            .and_then(|did| super::economy::compute_bond(state, &did))
            .is_some_and(|b| {
                b.is_eligible() && b.provider_address.trim_start_matches("0x") == hex::encode(payee)
            })
    };
    if stream {
        return bonded().then_some(WorkClass::ComputeLease);
    }
    if super::role_stake::role_bonded(state, payee, NetworkRole::TeeProvider) {
        Some(WorkClass::TeeSession)
    } else if super::role_stake::role_bonded(state, payee, NetworkRole::Rpc) {
        Some(WorkClass::RpcTraffic)
    } else if bonded() {
        Some(WorkClass::InferenceServed)
    } else {
        None
    }
}

/// The root identity behind `did`: its controller as its agent terms on
/// chain record it, followed to an identity that controls itself, then the
/// root id a delegated DID is derived under (`{root}` of
/// `did:tenzro:machine:{root}:{id}`) or the root's own id. Every agent and
/// machine one human passkey or one autonomous device delegated maps to that
/// root's id, and so does the root itself.
pub fn root_identity(state: &dyn VmState, did: &str) -> String {
    let mut did = did.to_string();
    for _ in 0..8 {
        match super::agent_terms::read_agent_terms(state, &did) {
            Some(t) if !t.terms.controller_did.is_empty() && t.terms.controller_did != did => {
                did = t.terms.controller_did;
            }
            _ => break,
        }
    }
    match tenzro_types::identity::delegated_root_id(&did) {
        Some(root) => root.to_string(),
        None => did.rsplit(':').next().unwrap_or(&did).to_string(),
    }
}

/// Whether the payer of a plan (`payer`, and the agent that opened it from
/// its wallet, if one did) and the account `provider` are one party: the
/// same account, or identities that share a root, however many agents
/// stand between each and its root.
fn same_party(
    state: &dyn VmState,
    payer: &Address,
    payer_agent: Option<&str>,
    provider: &Address,
) -> bool {
    if payer == provider {
        return true;
    }
    let payer_did = payer_agent
        .map(str::to_string)
        .or_else(|| identity_did_of(state, payer.as_bytes()));
    let provider_did = identity_did_of(state, provider.as_bytes());
    matches!((payer_did, provider_did), (Some(a), Some(b))
        if root_identity(state, &a) == root_identity(state, &b))
}

/// Governed key: share of an epoch's burn that funds validators' base
/// rewards, bps.
pub const VALIDATOR_BURN_SHARE_PARAM: &str = "fees.validator_burn_share_bps";
/// Governed key: running cost a validator's base reward covers, USD a month.
pub const VALIDATOR_BASE_COST_PARAM: &str = "validator.base_cost_usd_month";
/// Governed key: most base reward one validator earns, whole TNZO a month.
pub const VALIDATOR_BASE_CAP_PARAM: &str = "validator.base_cap_tnzo_month";

/// Base rights for `active` validators in one epoch of `epochs_per_year`:
/// each validator's monthly cost at the rate in force, at most the monthly
/// cap, and in all at most the governed share of the epoch's burn and
/// burn-equivalent.
pub fn validator_base_rights(
    state: &dyn VmState,
    epoch: u64,
    active: u64,
    epochs_per_year: u64,
) -> u128 {
    let months = u128::from(epochs_per_year.max(1)) * 1_000 / 12;
    let cost_atto_usd = u128::from(network_param(state, VALIDATOR_BASE_COST_PARAM))
        .saturating_mul(1_000_000_000_000_000_000);
    let cost = super::economy::usd_to_wei(state, cost_atto_usd);
    let cap = u128::from(network_param(state, VALIDATOR_BASE_CAP_PARAM))
        .saturating_mul(tenzro_token::rewards::ONE_TNZO);
    let (left, of) =
        super::validator_cover::uncovered(&super::validator_cover::read_cover(state, epoch));
    let each = cost.min(cap).saturating_mul(1_000) / months.max(1) * left / of.max(1);
    let activity = super::economy::read_epoch_activity(state, epoch);
    let burned = activity.burned.saturating_add(activity.burn_eq);
    let funded = burned.saturating_mul(u128::from(
        network_param(state, VALIDATOR_BURN_SHARE_PARAM).min(10_000),
    )) / 10_000;
    each.saturating_mul(u128::from(active)).min(funded)
}

/// The issuance policy in force: the governed parameters and the
/// controller's multiplier.
pub fn mint_policy(state: &dyn VmState, rs: &RewardEngineState) -> MintPolicy {
    MintPolicy {
        base_tnzo_per_year: network_param(state, MINT_BASE_PARAM),
        decay_bps_per_year: network_param(state, MINT_DECAY_PARAM),
        floor_tnzo_per_year: network_param(state, MINT_FLOOR_PARAM),
        mult_ppm: rs.mint_mult_ppm,
        validator_bps: network_param(state, MINT_VALIDATOR_SHARE_PARAM),
        provider_bps: network_param(state, MINT_PROVIDER_SHARE_PARAM),
        ecosystem_bps: network_param(state, MINT_ECOSYSTEM_SHARE_PARAM),
        revenue_peg_bps: network_param(state, MINT_REVENUE_PEG_PARAM),
        validator_base_rights: 0,
        withheld_rights: 0,
    }
}

/// Reward accounting for one finalized block, run before its
/// transactions: pays the vote work recorded since the last block, closes
/// every open epoch older than `epoch`, then credits `proposer` with one
/// block-proposal unit in `epoch`. Returns the logs the epochs it closed
/// emitted.
pub fn begin_block(
    state: &mut dyn VmState,
    epoch: u64,
    proposer: &Address,
    now_ms: i64,
) -> Result<Vec<Log>> {
    let mut changes = Vec::new();
    let mut logs = Vec::new();
    let mut rs = read_reward_state(state)?;
    let pending: Vec<PendingVote> = read_record(state, VOTES_PENDING_KEY)?.unwrap_or_default();
    if !pending.is_empty() {
        // Votes of an epoch already closed are paid in the current one.
        let current = rs.current_epoch.max(epoch);
        for (vote_epoch, signer, rounds) in pending {
            let into = if rs.last_closed_epoch.is_some_and(|l| vote_epoch <= l) {
                current
            } else {
                vote_epoch
            };
            record_work(
                state,
                &mut rs,
                into,
                signer,
                WorkClass::ConsensusVote,
                rounds as u128,
                &mut changes,
            )?;
        }
        write_json(
            state,
            VOTES_PENDING_KEY,
            &Vec::<PendingVote>::new(),
            &mut changes,
        )?;
    }
    let closing: Vec<u64> = rs
        .open_epochs
        .iter()
        .copied()
        .filter(|e| *e < epoch)
        .collect();
    for e in closing {
        close_epoch(state, &mut rs, e, now_ms, &mut changes, &mut logs)?;
        super::payout_swap::fill_epoch(state, e, now_ms, &mut changes, &mut logs)?;
        super::insurance::publish_coverage(state, e, &mut changes, &mut logs)?;
    }
    rs.current_epoch = rs.current_epoch.max(epoch);
    let current = rs.current_epoch;
    super::hardware_level::note_epoch_start(state, current, now_ms, &mut changes)?;
    sweep_expired(state, &mut rs, current, &mut changes)?;
    prune_epochs(state, current, &mut changes)?;
    super::agent_audit::prune(state, current, &mut changes)?;
    record_work(
        state,
        &mut rs,
        epoch,
        *proposer,
        WorkClass::BlockProposal,
        1,
        &mut changes,
    )?;
    write_json(state, REWARD_STATE_KEY, &rs, &mut changes)?;
    Ok(logs)
}

/// Adds work to an open epoch. Work for a closed epoch is refused.
fn record_work(
    state: &mut dyn VmState,
    rs: &mut RewardEngineState,
    epoch: u64,
    address: Address,
    class: WorkClass,
    weight: u128,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    if weight == 0 {
        return Ok(());
    }
    if rs.last_closed_epoch.is_some_and(|last| epoch <= last) {
        return Err(refuse(format!("reward epoch {epoch} is already closed")));
    }
    let key = pending_key(epoch);
    let mut rows: Vec<WorkRecord> = read_record(state, &key)?.unwrap_or_default();
    add_work(&mut rows, address, class, weight);
    write_json(state, &key, &rows, changes)?;
    if let Err(at) = rs.open_epochs.binary_search(&epoch) {
        rs.open_epochs.insert(at, epoch);
    }
    Ok(())
}

/// Credits `address` with `weight` of `class` work, the most one settlement
/// may earn it, in the current epoch.
pub(super) fn record_settled_work(
    state: &mut dyn VmState,
    address: Address,
    class: WorkClass,
    weight: u128,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    if weight == 0 {
        return Ok(());
    }
    let mut rs = read_reward_state(state)?;
    let epoch = rs.current_epoch;
    record_work(state, &mut rs, epoch, address, class, weight, changes)?;
    write_json(state, REWARD_STATE_KEY, &rs, changes)?;
    Ok(())
}

/// Closes `epoch`: settles its work into coupons, then expires coupons
/// whose claim window has passed.
fn close_epoch(
    state: &mut dyn VmState,
    rs: &mut RewardEngineState,
    epoch: u64,
    now_ms: i64,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let pending = pending_key(epoch);
    let work: Vec<WorkRecord> = read_record(state, &pending)?.unwrap_or_default();
    let schedule = read_reward_schedule(state)?;
    let mut policy = mint_policy(state, rs);
    let validators: Vec<Address> = work
        .iter()
        .filter(|w| w.class.bucket() == tenzro_token::rewards::RoleBucket::Validator)
        .map(|w| w.address.0)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .map(Address::new)
        .collect();
    let active = validators.len() as u64;
    // Running cost is paid first in the stable fees paid usage settled; the
    // base reward pays only what that left uncovered.
    super::validator_cover::cover_epoch(
        state,
        epoch,
        &validators,
        schedule.epochs_per_year,
        now_ms,
        changes,
        logs,
    )?;
    policy.validator_base_rights =
        validator_base_rights(state, epoch, active, schedule.epochs_per_year);
    // Fees collected in other assets burn by withholding issuance.
    let (scheduled, base) = schedule.epoch_rights(&policy, epoch, rs.cumulative_rights_issued);
    let per_epoch = policy.annual_rights(schedule.year_for_epoch(epoch))
        / u128::from(schedule.epochs_per_year.max(1));
    policy.withheld_rights = super::burn_netting::net_epoch(
        state,
        epoch,
        scheduled.saturating_add(base),
        per_epoch,
        changes,
        logs,
    )?;
    // Every provider earner's hardware level, derived again at this close.
    let providers = work
        .iter()
        .filter(|w| w.class.bucket() == tenzro_token::rewards::RoleBucket::Provider)
        .map(|w| w.address.0)
        .collect::<std::collections::BTreeSet<_>>();
    let levels = super::hardware_level::record_epoch(state, epoch, &providers, now_ms, changes)?;
    let (summary, coupons) = tenzro_token::rewards::settle_epoch_with_levels(
        &schedule,
        &policy,
        rs.cumulative_rights_issued,
        epoch,
        &work,
        &levels,
        Timestamp::new(now_ms),
    );

    let mut issued = Vec::with_capacity(coupons.len());
    for coupon in &coupons {
        let key = RewardCoupon::storage_key(coupon.epoch, coupon.bucket, &coupon.address);
        write_json(state, &key, coupon, changes)?;
        let index = coupons_of_key(&coupon.address);
        let mut of: Vec<String> = read_record(state, &index)?.unwrap_or_default();
        of.push(key.clone());
        write_json(state, &index, &of, changes)?;
        issued.push(key);
    }
    if !issued.is_empty() {
        write_json(state, &epoch_coupons_key(epoch), &issued, changes)?;
        rs.issued_epochs.push(epoch);
    }
    write_json(state, &summary_key(epoch), &summary, changes)?;
    state.set_storage(&SYSTEM_ADDRESS, pending.as_bytes(), Vec::new());

    rs.open_epochs.retain(|e| *e != epoch);
    rs.last_closed_epoch = Some(rs.last_closed_epoch.map_or(epoch, |l| l.max(epoch)));
    // Withheld rights were burned from the pool: they count as drawn.
    rs.cumulative_rights_issued = rs
        .cumulative_rights_issued
        .saturating_add(summary.rights_issued)
        .saturating_add(summary.withheld);
    rs.cumulative_matched = rs.cumulative_matched.saturating_add(summary.matched);
    rs.cumulative_expired = rs
        .cumulative_expired
        .saturating_add(summary.expired_unmatched);
    // Issuance follows economic security: it rises (to at most the base
    // schedule) while slashable stake covers less than k times what one
    // attack can take out over the bridges, and falls once it covers more.
    // An unknown ratio counts as below k.
    rs.mint_mult_ppm = next_mint_mult(
        rs.mint_mult_ppm,
        super::security::ratio_bps(state).unwrap_or(0),
        network_param(state, super::security::MIN_RATIO_PARAM),
        network_param(state, MINT_ADJ_PARAM),
        schedule.epochs_per_year,
        network_param(state, MINT_MIN_MULT_PARAM),
        network_param(state, MINT_MAX_MULT_PARAM),
    );
    Ok(())
}

/// Expires the unclaimed coupons of every epoch whose claim window has
/// passed at `current_epoch`; their amounts stay in the pool. The epoch's
/// coupons, claimed or not, are deleted with their index entries.
fn sweep_expired(
    state: &mut dyn VmState,
    rs: &mut RewardEngineState,
    current_epoch: u64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let window = super::network_param(state, CLAIM_WINDOW_PARAM);
    let mut swept: u128 = 0;
    let (stale, live): (Vec<u64>, Vec<u64>) = rs
        .issued_epochs
        .iter()
        .copied()
        .partition(|e| coupon_expired(*e, current_epoch, window));
    let mut dropped: std::collections::BTreeMap<[u8; 32], Vec<String>> = Default::default();
    for e in stale {
        let keys: Vec<String> = read_record(state, &epoch_coupons_key(e))?.unwrap_or_default();
        for key in keys {
            if let Some(c) = read_record::<RewardCoupon>(state, &key)? {
                if c.status == CouponStatus::Issued {
                    swept = swept.saturating_add(c.amount);
                }
                dropped.entry(c.address.0).or_default().push(key.clone());
            }
            delete_record(state, &key, changes);
        }
        delete_record(state, &epoch_coupons_key(e), changes);
    }
    for (address, keys) in dropped {
        let index = coupons_of_key(&Address::new(address));
        let mut of: Vec<String> = read_record(state, &index)?.unwrap_or_default();
        of.retain(|k| !keys.contains(k));
        if of.is_empty() {
            delete_record(state, &index, changes);
        } else {
            write_json(state, &index, &of, changes)?;
        }
    }
    rs.issued_epochs = live;
    rs.cumulative_expired = rs.cumulative_expired.saturating_add(swept);
    Ok(())
}

/// The first epoch whose records are still kept.
fn pruned_below(state: &dyn VmState) -> Result<u64> {
    Ok(read_record(state, PRUNED_BELOW_KEY)?.unwrap_or(0))
}

/// The oldest reward epoch whose summary, votes and activity are still
/// kept; every older epoch's are pruned.
pub fn first_kept_epoch(state: &dyn VmState) -> Result<u64> {
    pruned_below(state)
}

/// Deletes the summary, vote tally and activity of every epoch whose claim
/// window has passed at `current_epoch`, at most
/// [`MAX_PRUNED_EPOCHS_PER_BLOCK`] epochs a block. Every open epoch older
/// than the current one closed before this runs, so no record deleted here
/// is read again: a closed epoch takes no work, its coupons expired with
/// the window, and [`record_checkpoint_signers`] refuses its checkpoints.
fn prune_epochs(
    state: &mut dyn VmState,
    current_epoch: u64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let window = super::network_param(state, CLAIM_WINDOW_PARAM);
    let from = pruned_below(state)?;
    let to = current_epoch
        .saturating_sub(window)
        .min(from.saturating_add(MAX_PRUNED_EPOCHS_PER_BLOCK));
    if to <= from {
        return Ok(());
    }
    for e in from..to {
        debug_assert!(coupon_expired(e, current_epoch, window));
        delete_record(state, &summary_key(e), changes);
        delete_record(state, &votes_key(e), changes);
        delete_record(state, &pending_key(e), changes);
        super::economy::prune_epoch(state, e, changes);
        prune_receipts(state, e, changes)?;
    }
    write_json(state, PRUNED_BELOW_KEY, &to, changes)?;
    Ok(())
}

/// Deletes the plans epoch `epoch` counted, and moves the decision time no
/// later than which a plan can no longer be cited up to the latest of
/// theirs: a plan whose record is gone can then never be counted twice,
/// and every plan decided after that time still has its record.
fn prune_receipts(
    state: &mut dyn VmState,
    epoch: u64,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let n: u64 = read_record(state, &epoch_receipts_key(epoch))?.unwrap_or(0);
    let prior: u64 = read_record(state, RECEIPTS_DECIDED_THROUGH_KEY)?.unwrap_or(0);
    let mut through = prior;
    for seq in 0..n {
        let entry = epoch_receipt_key(epoch, seq);
        if let Some((plan, decided_at)) = read_record::<(String, u64)>(state, &entry)? {
            delete_record(state, &receipt_key(&plan), changes);
            through = through.max(decided_at);
        }
        delete_record(state, &entry, changes);
    }
    delete_record(state, &epoch_receipts_key(epoch), changes);
    if through != prior {
        write_json(state, RECEIPTS_DECIDED_THROUGH_KEY, &through, changes)?;
    }
    Ok(())
}

/// `ReportSettledWork`: credits, as provider work of the sender in the
/// current epoch (a TEE session or RPC traffic when the sender holds that
/// bonded stake, else inference), each cited leg's committed plan at
/// [`tenzro_token::rewards::provider_work_weight`]: what the plan credited
/// the sender, at most the governed share of the TNZO protocol fee the plan
/// paid outside the trade. A plan the sender paid itself, or one whose payer
/// (or the agent that opened it) shares the sender's root identity, counts
/// nothing: two agents of one human pay each other for no reward. Each plan
/// counts once, and only while it is recent: a plan decided no later than
/// the latest plan whose record was deleted past the claim window counts
/// nothing.
pub(super) fn report_settled_work(
    tx: &VmTransaction,
    state: &mut dyn VmState,
    legs: &[[u8; 32]],
    changes: &mut Vec<StateChange>,
) -> Result<Vec<u8>> {
    let from = account_address(&tx.from)?;
    let mut rs = read_reward_state(state)?;
    let epoch = rs.current_epoch;
    let (reward_cost_bps, _) = settlement_reward_bps(state);
    let class = provider_class(state, from.as_bytes(), false).unwrap_or(WorkClass::InferenceServed);
    let mut counted = 0u64;
    let mut credited: u128 = 0;
    let through: Option<u64> = read_record(state, RECEIPTS_DECIDED_THROUGH_KEY)?;
    for leg in legs {
        let Some((plan_id, paid)) =
            super::payment_settlement::plan::settled_party(state, leg, &from)
        else {
            continue;
        };
        let Some(decided_at) = super::payment_settlement::plan::decided_at_ms(state, &plan_id)
        else {
            continue;
        };
        if through.is_some_and(|t| decided_at <= t) {
            continue;
        }
        let Some((payer, payer_agent, outsider_cost)) =
            super::payment_settlement::plan::settled_outsider_cost(state, &plan_id)
        else {
            continue;
        };
        if same_party(state, &payer, payer_agent.as_deref(), &from) {
            continue;
        }
        let amount =
            tenzro_token::rewards::provider_work_weight(paid, outsider_cost, reward_cost_bps);
        if amount == 0 {
            continue;
        }
        let key = receipt_key(&hex::encode(plan_id));
        if state
            .get_storage(&SYSTEM_ADDRESS, key.as_bytes())
            .is_some_and(|b| !b.is_empty())
        {
            continue;
        }
        write_json(state, &key, &epoch, changes)?;
        let n: u64 = read_record(state, &epoch_receipts_key(epoch))?.unwrap_or(0);
        write_json(
            state,
            &epoch_receipt_key(epoch, n),
            &(hex::encode(plan_id), decided_at),
            changes,
        )?;
        write_json(state, &epoch_receipts_key(epoch), &(n + 1), changes)?;
        record_work(state, &mut rs, epoch, from, class, amount, changes)?;
        counted += 1;
        credited = credited.saturating_add(amount);
    }
    if counted == 0 {
        return Err(refuse(
            "no leg counts: each must cite a committed plan that credited this account, \
             was paid by another party and was not counted before",
        ));
    }
    write_json(state, REWARD_STATE_KEY, &rs, changes)?;
    Ok(serde_json::to_vec(&serde_json::json!({
        "epoch": epoch,
        "receipts": counted,
        "credited": credited.to_string(),
    }))
    .unwrap_or_default())
}

/// `ClaimRewards`: pays the sender's claimable coupons out of the rewards
/// pool: the liquid share to the sender, the rest into vesting escrow under
/// a new schedule that vests linearly over the governed claim vesting period.
/// Coupons past the window expire instead.
pub(super) fn claim_rewards(
    tx: &VmTransaction,
    state: &mut dyn VmState,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<Vec<u8>> {
    let from = account_address(&tx.from)?;
    let now_ms = deterministic_now_ms(tx);
    let mut rs = read_reward_state(state)?;
    let keys: Vec<String> = read_record(state, &coupons_of_key(&from))?.unwrap_or_default();
    let mut total: u128 = 0;
    let mut base: u128 = 0;
    let mut expired: u128 = 0;
    let mut epochs = Vec::new();
    for key in keys {
        let Some(mut c) = read_record::<RewardCoupon>(state, &key)? else {
            continue;
        };
        if c.status != CouponStatus::Issued {
            continue;
        }
        if coupon_expired(
            c.epoch,
            rs.current_epoch,
            super::network_param(state, CLAIM_WINDOW_PARAM),
        ) {
            c.status = CouponStatus::Expired;
            expired = expired.saturating_add(c.amount);
        } else {
            c.status = CouponStatus::Claimed;
            c.claimed_at = Some(Timestamp::new(now_ms));
            total = total.saturating_add(c.amount);
            base = base.saturating_add(c.base.min(c.amount));
            epochs.push(c.epoch);
        }
        write_json(state, &key, &c, changes)?;
    }
    if total == 0 {
        return Err(refuse("no claimable reward coupons"));
    }
    rs.cumulative_claimed = rs.cumulative_claimed.saturating_add(total);
    rs.cumulative_expired = rs.cumulative_expired.saturating_add(expired);
    write_json(state, REWARD_STATE_KEY, &rs, changes)?;

    let (liquid, vesting) = tenzro_token::rewards::claim_parts(
        total,
        base,
        super::network_param(state, CLAIM_LIQUID_PARAM).min(10_000) as u32,
        super::network_param(state, BASE_LIQUID_PARAM).min(10_000) as u32,
    );
    let vesting_ms = super::network_param(state, CLAIM_VESTING_PARAM) as i64;
    let pool = rewards_pool_address();
    if liquid > 0 {
        move_balance(state, pool.as_bytes(), &tx.from, liquid, changes)?;
    }
    if vesting > 0 {
        open_vesting(
            state,
            pool.as_bytes(),
            from,
            VestingKind::Reward,
            vesting,
            now_ms,
            0,
            vesting_ms,
            changes,
        )?;
    }
    epochs.sort_unstable();
    epochs.dedup();
    let outcome = ClaimOutcome {
        total,
        liquid,
        vesting,
        epochs,
    };
    let blob = serde_json::to_vec(&outcome)
        .map_err(|e| VmError::Internal(format!("encode claim outcome: {e}")))?;
    logs.push(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![REWARDS_CLAIMED_TOPIC.to_vec(), tx.from.clone()],
        blob.clone(),
    ));
    Ok(blob)
}

/// `ReleaseVesting`: pays the sender everything its schedules have accrued
/// and not yet released, out of vesting escrow.
pub(super) fn release_vesting(
    tx: &VmTransaction,
    state: &mut dyn VmState,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<Vec<u8>> {
    let from = account_address(&tx.from)?;
    let now_ms = deterministic_now_ms(tx);
    let key = vesting_list_key(&from);
    let mut list: Vec<VestingSchedule> = read_record(state, &key)?.unwrap_or_default();
    let mut released: u128 = 0;
    for s in list.iter_mut() {
        let amount = s.releasable_at(now_ms);
        s.released = s.released.saturating_add(amount);
        released = released.saturating_add(amount);
    }
    if released == 0 {
        return Err(refuse("nothing has vested since the last release"));
    }
    drop_released(&mut list);
    write_json(state, &key, &list, changes)?;
    move_balance(
        state,
        vesting_escrow_address().as_bytes(),
        &tx.from,
        released,
        changes,
    )?;
    logs.push(Log::new(
        SYSTEM_ADDRESS.to_vec(),
        vec![VESTING_RELEASED_TOPIC.to_vec(), tx.from.clone()],
        released.to_le_bytes().to_vec(),
    ));
    Ok(released.to_le_bytes().to_vec())
}

fn account_address(raw: &[u8]) -> Result<Address> {
    let bytes: [u8; 32] = raw
        .try_into()
        .map_err(|_| refuse(format!("a reward account is 32 bytes, not {}", raw.len())))?;
    Ok(Address::new(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StateAdapter;

    fn addr(b: u8) -> Address {
        Address::new([b; 32])
    }

    /// A paid settlement's work in the current epoch: a provider served
    /// `weight` of reward ceiling. Without it, nothing is released.
    fn paid_work(state: &mut StateAdapter, weight: u128) {
        record_settled_work(
            state,
            addr(99),
            WorkClass::InferenceServed,
            weight,
            &mut Vec::new(),
        )
        .unwrap();
    }

    /// Chain state holding the schedule genesis writes, for one-day epochs.
    fn genesis_state() -> StateAdapter {
        let mut state = StateAdapter::new();
        let schedule = genesis_reward_schedule(86_400_000).unwrap();
        state.set_storage(&SYSTEM_ADDRESS, REWARD_SCHEDULE_KEY.as_bytes(), schedule);
        state
    }

    /// Epoch accounting is a pure function of the blocks: coupons appear
    /// when a later epoch's first block runs, in proportion to proposals, and
    /// a coupon nobody claims lapses once its window has passed.
    #[test]
    fn blocks_close_epochs_into_coupons_and_stale_coupons_lapse() {
        let mut state = genesis_state();
        begin_block(&mut state, 0, &addr(1), 1_000).unwrap();
        begin_block(&mut state, 0, &addr(1), 2_000).unwrap();
        begin_block(&mut state, 0, &addr(2), 3_000).unwrap();
        paid_work(&mut state, 1_000_000_000_000_000_000_000);
        assert!(read_coupons(&state, &addr(1)).unwrap().is_empty());

        begin_block(&mut state, 1, &addr(2), 4_000).unwrap();
        let summary = read_epoch_summary(&state, 0).unwrap().unwrap();
        let one = read_coupons(&state, &addr(1)).unwrap();
        let two = read_coupons(&state, &addr(2)).unwrap();
        assert_eq!(one[0].work_weight, 2);
        assert_eq!(two[0].work_weight, 1);
        let provider = read_coupons(&state, &addr(99)).unwrap();
        assert_eq!(
            one[0].amount + two[0].amount + provider[0].amount,
            summary.matched
        );
        let rs = read_reward_state(&state).unwrap();
        assert_eq!(rs.last_closed_epoch, Some(0));
        assert_eq!(rs.open_epochs, vec![1]);
        assert_eq!(rs.issued_epochs, vec![0]);

        // Work for a closed epoch is refused.
        let mut rs = read_reward_state(&state).unwrap();
        let mut changes = Vec::new();
        assert!(
            record_work(
                &mut state,
                &mut rs,
                0,
                addr(3),
                WorkClass::BlockProposal,
                1,
                &mut changes
            )
            .is_err()
        );

        // Past the claim window the epoch-0 coupons lapse into the pool.
        let far = tenzro_token::rewards::DEFAULT_CLAIM_WINDOW_EPOCHS + 2;
        begin_block(&mut state, far, &addr(2), 5_000).unwrap();
        assert!(read_coupons(&state, &addr(1)).unwrap().is_empty());
        let rs = read_reward_state(&state).unwrap();
        assert!(rs.issued_epochs.iter().all(|e| *e != 0));
        assert!(rs.cumulative_expired >= one[0].amount + two[0].amount);
    }

    /// A schedule paid out in full leaves the list once a release or a new
    /// claim writes it: after many claims, each released in full, the list
    /// holds the newest schedule only, and sequence numbers keep counting.
    #[test]
    fn released_vesting_schedules_leave_the_list() {
        let mut state = genesis_state();
        let who = addr(9);
        let source = addr(8);
        state.set_balance(source.as_bytes(), 1_000_000);
        let tx = |at: i64| {
            let mut tx = VmTransaction::new(
                who.as_bytes().to_vec(),
                None,
                0,
                Vec::new(),
                0,
                0,
                0,
                VmType::Evm,
                1337,
            );
            tx.block_timestamp_ms = Some(at);
            tx
        };
        let mut now = 1_000;
        for n in 0..20u64 {
            let mut changes = Vec::new();
            open_vesting(
                &mut state,
                source.as_bytes(),
                who,
                VestingKind::Reward,
                100,
                now,
                0,
                10,
                &mut changes,
            )
            .unwrap();
            now += 50;
            let mut logs = Vec::new();
            release_vesting(&tx(now), &mut state, &mut changes, &mut logs).unwrap();
            let list = read_vesting(&state, &who).unwrap();
            assert_eq!(list.len(), 1, "after claim {n}: {list:?}");
            assert_eq!(list[0].seq, n);
        }
        assert_eq!(state.get_balance(who.as_bytes()), 2_000);

        // An open schedule stays until it is paid out in full.
        let mut changes = Vec::new();
        open_vesting(
            &mut state,
            source.as_bytes(),
            who,
            VestingKind::Reward,
            100,
            now,
            0,
            1_000,
            &mut changes,
        )
        .unwrap();
        release_vesting(&tx(now + 500), &mut state, &mut changes, &mut Vec::new()).unwrap();
        let list = read_vesting(&state, &who).unwrap();
        assert_eq!(list.iter().map(|s| s.seq).collect::<Vec<_>>(), vec![20]);
        assert_eq!(list[0].released, 50);
    }

    /// Once an epoch's claim window has passed, its coupons, summary, vote
    /// tally and activity are deleted and a late checkpoint of it is
    /// refused; the epochs still inside the window keep theirs. Two chains
    /// running the same blocks, one of them restarted from its store on the
    /// way, end at the same state root.
    #[test]
    fn records_of_an_epoch_past_its_claim_window_are_deleted() {
        use tenzro_storage::state_trie::{StateTrie, capture};
        let window = tenzro_token::rewards::DEFAULT_CLAIM_WINDOW_EPOCHS;
        let last = window + 5;
        let run = |restart_at: Option<u64>| {
            let store: std::sync::Arc<dyn tenzro_storage::KvStore> =
                std::sync::Arc::new(tenzro_storage::MemoryStore::new());
            let trie = StateTrie::new(store.clone());
            let fresh = |store: &std::sync::Arc<dyn tenzro_storage::KvStore>| {
                StateAdapter::with_storage(store.clone())
            };
            let mut state = fresh(&store);
            let schedule = genesis_reward_schedule(86_400_000).unwrap();
            state.set_storage(&SYSTEM_ADDRESS, REWARD_SCHEDULE_KEY.as_bytes(), schedule);
            let mut root = None;
            for epoch in 0..=last {
                if restart_at == Some(epoch) {
                    state = fresh(&store);
                }
                let at = epoch as i64 * 1_000 + 1;
                begin_block(&mut state, epoch, &addr(1 + (epoch % 2) as u8), at).unwrap();
                paid_work(&mut state, 1_000_000_000_000_000_000_000);
                let record = CheckpointSigners {
                    epoch,
                    index: 0,
                    anchor_round: 3,
                    signers: vec![addr(1), addr(2)],
                };
                record_checkpoint_signers(&mut state, &record).unwrap();
                super::super::economy::record_burn(&mut state, 5).unwrap();
                let writes = capture::WriteSet::new();
                capture::in_thread(writes.clone(), || state.commit()).unwrap();
                root = Some(trie.commit(epoch + 1, &writes.take()).unwrap());
            }
            (state, store, root)
        };
        let (state, store, root) = run(None);

        let kept_from = last - window;
        for e in 0..kept_from {
            assert!(
                read_epoch_summary(&state, e).unwrap().is_none(),
                "summary {e}"
            );
            assert_eq!(read_epoch_votes(&state, e).unwrap(), EpochVotes::default());
            assert_eq!(
                super::super::economy::read_epoch_activity(&state, e).burned,
                0
            );
            for key in [summary_key(e), votes_key(e), epoch_coupons_key(e)] {
                let db = format!(
                    "storage:{}:{}",
                    hex::encode(SYSTEM_ADDRESS),
                    hex::encode(key.as_bytes())
                );
                assert_eq!(
                    store.get(tenzro_storage::CF_STATE, db.as_bytes()).unwrap(),
                    None
                );
            }
        }
        for e in kept_from..last {
            assert!(
                read_epoch_summary(&state, e).unwrap().is_some(),
                "summary {e}"
            );
            assert!(read_epoch_votes(&state, e).unwrap().certified_rounds > 0);
        }
        for a in [addr(1), addr(2)] {
            let coupons = read_coupons(&state, &a).unwrap();
            assert!(!coupons.is_empty());
            assert!(coupons.iter().all(|c| c.epoch >= kept_from), "{coupons:?}");
        }

        let late = CheckpointSigners {
            epoch: kept_from - 1,
            index: 1,
            anchor_round: 9,
            signers: vec![addr(1)],
        };
        let mut st = state;
        assert!(record_checkpoint_signers(&mut st, &late).is_err());

        let (_, _, restarted) = run(Some(window / 2));
        assert_eq!(root, restarted);
    }

    /// A record whose anchor round is the last representable round is
    /// refused rather than overflowing the next round.
    #[test]
    fn a_checkpoint_at_the_last_round_is_refused_without_overflow() {
        let mut state = genesis_state();
        let record = CheckpointSigners {
            epoch: 0,
            index: 0,
            anchor_round: u64::MAX,
            signers: vec![addr(1)],
        };
        assert!(record_checkpoint_signers(&mut state, &record).is_err());
        assert_eq!(read_epoch_votes(&state, 0).unwrap().certified_rounds, 0);
    }

    /// Each signer of a recorded checkpoint earns one vote unit per round it
    /// certified, paid by the next block into the checkpoint's epoch; a
    /// checkpoint is counted once, and the tally gives each validator's
    /// share of the epoch's certified rounds.
    #[test]
    fn checkpoint_signers_earn_votes_per_certified_round() {
        let mut state = genesis_state();
        let cp = |index, anchor_round, signers: Vec<Address>| CheckpointSigners {
            epoch: 0,
            index,
            anchor_round,
            signers,
        };
        record_checkpoint_signers(&mut state, &cp(0, 3, vec![addr(1), addr(2)])).unwrap();
        record_checkpoint_signers(&mut state, &cp(1, 7, vec![addr(1)])).unwrap();
        assert!(
            record_checkpoint_signers(&mut state, &cp(1, 9, vec![addr(2)])).is_err(),
            "index recorded"
        );
        assert!(
            record_checkpoint_signers(&mut state, &cp(2, 5, vec![addr(2)])).is_err(),
            "rounds recorded"
        );
        assert!(
            record_checkpoint_signers(&mut state, &cp(3, 9, vec![addr(2), addr(2)])).is_err(),
            "signer twice"
        );

        let votes = read_epoch_votes(&state, 0).unwrap();
        assert_eq!(votes.certified_rounds, 8);
        assert_eq!(votes.participation_bps(&addr(1)), Some(10_000));
        assert_eq!(votes.participation_bps(&addr(2)), Some(5_000));
        assert_eq!(votes.participation_bps(&addr(3)), Some(0));

        begin_block(&mut state, 0, &addr(3), 1_000).unwrap();
        paid_work(&mut state, 1_000_000_000_000_000_000_000);
        begin_block(&mut state, 1, &addr(3), 2_000).unwrap();
        let weight = |a| read_coupons(&state, &addr(a)).unwrap()[0].work_weight;
        assert_eq!((weight(1), weight(2), weight(3)), (8, 4, 1));
    }

    /// A record for a checkpoint at or below the epoch's last recorded index
    /// is refused and leaves the epoch's tally exactly as it was, whoever
    /// proposed the block that carries it.
    #[test]
    fn a_record_at_or_below_the_recorded_index_changes_nothing() {
        let mut state = genesis_state();
        let cp = |index, anchor_round, signer| CheckpointSigners {
            epoch: 0,
            index,
            anchor_round,
            signers: vec![addr(signer)],
        };
        record_checkpoint_signers(&mut state, &cp(4, 9, 1)).unwrap();
        let held = read_epoch_votes(&state, 0).unwrap();
        for copy in [cp(4, 9, 2), cp(4, 12, 2), cp(3, 20, 2)] {
            assert!(record_checkpoint_signers(&mut state, &copy).is_err());
            assert_eq!(read_epoch_votes(&state, 0).unwrap(), held);
        }
    }

    /// A claim moves exactly the coupon total out of the pool: the liquid
    /// share to the claimant, the rest into escrow under a schedule that
    /// releases in full after the vesting period.
    #[test]
    fn claim_and_release_move_the_pool_balance() {
        let mut state = genesis_state();
        let pool = rewards_pool_address();
        state.set_balance(pool.as_bytes(), tenzro_token::rewards::NETWORK_REWARDS_POOL);
        super::super::economy::write_rate_for_tests(&mut state, 1, 100_000_000, 100_000_000);
        begin_block(&mut state, 0, &addr(7), 0).unwrap();
        paid_work(&mut state, 1_000_000_000_000_000_000_000);
        super::super::economy::record_burn(&mut state, 1_000_000_000_000_000_000_000).unwrap();
        begin_block(&mut state, 1, &addr(8), 10).unwrap();
        let issued = read_coupons(&state, &addr(7)).unwrap()[0].clone();
        let coupon = issued.amount;
        // The burn's share pays the base; it is claimed liquid, the rest at
        // the claim liquid share.
        assert!(issued.base > 0 && issued.base <= coupon);

        let mut tx = VmTransaction::new(
            addr(7).as_bytes().to_vec(),
            None,
            0,
            Vec::new(),
            0,
            0,
            0,
            crate::traits::VmType::Tenzro,
            1,
        )
        .with_block_timestamp_ms(100);
        let (mut changes, mut logs) = (Vec::new(), Vec::new());
        let out = claim_rewards(&tx, &mut state, &mut changes, &mut logs).unwrap();
        let outcome: ClaimOutcome = serde_json::from_slice(&out).unwrap();
        let (liquid, vesting) = tenzro_token::rewards::claim_parts(
            coupon,
            issued.base,
            tenzro_token::rewards::DEFAULT_LIQUID_BPS,
            10_000,
        );
        assert_eq!(
            (outcome.total, outcome.liquid, outcome.vesting),
            (coupon, liquid, vesting)
        );
        assert_eq!(outcome.epochs, vec![0]);
        assert_eq!(state.get_balance(addr(7).as_bytes()), liquid);
        assert_eq!(
            state.get_balance(vesting_escrow_address().as_bytes()),
            vesting
        );
        assert_eq!(
            state.get_balance(pool.as_bytes()),
            tenzro_token::rewards::NETWORK_REWARDS_POOL - coupon
        );
        assert_eq!(
            read_coupons(&state, &addr(7)).unwrap()[0].status,
            CouponStatus::Claimed
        );
        assert!(logs.iter().any(|l| l.topics[0] == REWARDS_CLAIMED_TOPIC));
        assert!(claim_rewards(&tx, &mut state, &mut changes, &mut logs).is_err());

        tx = tx.with_block_timestamp_ms(100 + tenzro_token::vesting::REWARD_VESTING_MS);
        release_vesting(&tx, &mut state, &mut changes, &mut logs).unwrap();
        assert_eq!(state.get_balance(addr(7).as_bytes()), coupon);
        assert_eq!(state.get_balance(vesting_escrow_address().as_bytes()), 0);
        assert!(release_vesting(&tx, &mut state, &mut changes, &mut logs).is_err());
    }

    /// Rewards are released from the genesis-funded pool, never minted:
    /// across epoch closes, a claim and its vesting release, the balances
    /// change only by what the block records, and the record only ever
    /// lowers supply.
    #[test]
    fn epoch_closes_claims_and_releases_add_no_supply() {
        let mut state = genesis_state();
        let pool = rewards_pool_address();
        let funded = tenzro_token::rewards::NETWORK_REWARDS_POOL;
        state.set_balance(pool.as_bytes(), funded);
        super::super::economy::write_rate_for_tests(&mut state, 1, 100_000_000, 100_000_000);
        begin_block(&mut state, 0, &addr(7), 0).unwrap();
        paid_work(&mut state, 1_000_000_000_000_000_000_000);
        super::super::economy::record_burn(&mut state, 1_000_000_000_000_000_000_000).unwrap();
        begin_block(&mut state, 1, &addr(8), 10).unwrap();
        let coupon = read_coupons(&state, &addr(7)).unwrap()[0].amount;
        assert!(coupon > 0);

        let mut tx = VmTransaction::new(
            addr(7).as_bytes().to_vec(),
            None,
            0,
            Vec::new(),
            0,
            0,
            0,
            crate::traits::VmType::Tenzro,
            1,
        )
        .with_block_timestamp_ms(100);
        let (mut changes, mut logs) = (Vec::new(), Vec::new());
        claim_rewards(&tx, &mut state, &mut changes, &mut logs).unwrap();
        tx = tx.with_block_timestamp_ms(100 + tenzro_token::vesting::REWARD_VESTING_MS);
        release_vesting(&tx, &mut state, &mut changes, &mut logs).unwrap();
        assert_eq!(state.get_balance(addr(7).as_bytes()), coupon);

        // The pool funding is the only unrecorded write; everything after it
        // moved value or burned it.
        let (balances, supply) = state.pending_block_delta();
        assert_eq!(balances - funded as i128, supply);
        assert!(supply <= 0, "supply rose by {supply}");
    }
}
