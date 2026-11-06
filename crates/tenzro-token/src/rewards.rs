//! Work-gated reward distribution.
//!
//! Rewards leave the network-rewards pool only against verified work.
//! The pool is a genesis-funded account ([`rewards_pool_address`], 400M
//! TNZO); nothing mints rewards, so total supply stays fixed. Every epoch
//! the network issues a bounded amount of payout rights (a declining
//! schedule over the pool), splits those rights across three role buckets
//! (validators / providers / ecosystem), caps the provider and ecosystem
//! buckets at a peg to the verified revenue they settled, and matches the
//! rights pro-rata to the verified work recorded during that epoch.
//! Matched rights become [`RewardCoupon`]s the earner claims within
//! the governed claim window; a claim is a transfer out of the pool.
//! Unmatched rights and unclaimed coupons lapse and stay in the pool.
//!
//! This module holds the rules: the schedule, the epoch settlement
//! ([`settle_epoch`]) and the claim split ([`split_claim`]). The accounting
//! they drive lives in consensus state, written as finalized blocks execute,
//! so every node derives the same coupons and balances from the same chain.
//!
//! Work evidence is never self-reported:
//!
//! - Validator work comes from finalized block headers, the proposer
//!   address ([`WorkClass::BlockProposal`]), and from checkpoint
//!   certificates recorded on chain, one unit per certified round to each
//!   signer ([`WorkClass::ConsensusVote`]).
//! - Provider work ([`WorkClass::InferenceServed`], [`WorkClass::TeeSession`],
//!   [`WorkClass::RpcTraffic`], [`WorkClass::ComputeLease`] and
//!   [`WorkClass::StorageServed`]) is weighted per settlement by
//!   [`provider_work_weight`]: what the provider was paid, at most a governed
//!   share of the protocol fee that settlement paid outside the trade, each
//!   settlement counted once. A settlement therefore never earns its parties
//!   more than it cost them, so paying oneself never pays.
//! - Ecosystem work ([`WorkClass::AppUsage`]) is credited only to the apps,
//!   agents and tools a payer attributed a settlement to, never to its payee,
//!   at most a governed share of the same fee.
//!
//! All TNZO amounts are 18-decimal base units.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tenzro_types::primitives::{Address, Timestamp};

/// Genesis value of the governed `rewards.claim_window_epochs`: epochs an
/// issued coupon stays claimable before it expires unclaimed, its amount
/// staying in the pool.
pub const DEFAULT_CLAIM_WINDOW_EPOCHS: u64 = 30;

/// Length of a schedule year in block time (365.25 days, in milliseconds).
/// Epochs per year follow from it and the genesis epoch length.
pub const SCHEDULE_YEAR_MS: u64 = 31_557_600_000;

/// One TNZO in base units.
pub const ONE_TNZO: u128 = 1_000_000_000_000_000_000;

/// Total network-rewards pool: 400M TNZO (40% of supply).
pub const NETWORK_REWARDS_POOL: u128 = 400_000_000 * ONE_TNZO;

/// Default liquid share of a claim, in basis points. The remainder
/// vests (12-month linear per the economic model).
pub const DEFAULT_LIQUID_BPS: u32 = 2500;

/// Role bucket a work class settles into for the epoch split.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleBucket {
    /// Consensus participation: block proposals.
    Validator,
    /// Verified served work: inference, TEE sessions, RPC, compute leases
    /// and storage.
    Provider,
    /// Registered apps / agents / tools earning from settled usage.
    Ecosystem,
}

impl RoleBucket {
    /// Stable key fragment used in storage keys.
    pub fn as_key(&self) -> &'static str {
        match self {
            RoleBucket::Validator => "validator",
            RoleBucket::Provider => "provider",
            RoleBucket::Ecosystem => "ecosystem",
        }
    }
}

/// A verifiable class of work. The weight semantics differ per bucket:
/// validator classes count events (1 per proposal, 1 per certified round
/// signed); provider and ecosystem classes weigh settled fees in TNZO base
/// units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkClass {
    /// Signature on a certified checkpoint, per round it certified
    /// (chain-verified).
    ConsensusVote,
    /// Proposer of a finalized block (chain-verified).
    BlockProposal,
    /// Settled inference fees.
    InferenceServed,
    /// Settled attested-TEE-session fees.
    TeeSession,
    /// Settled RPC traffic fees.
    RpcTraffic,
    /// Settled usage fees attributed to a registered app / agent / tool.
    AppUsage,
    /// Settled compute rental: stream claims and claim hours paid to the
    /// account that posted the compute bond delivering them.
    ComputeLease,
    /// Settled storage: claim hours a bond or storage stake delivered while
    /// validators found the stored object retrievable.
    StorageServed,
}

impl WorkClass {
    /// The role bucket this class draws minting rights from.
    pub fn bucket(&self) -> RoleBucket {
        match self {
            WorkClass::ConsensusVote | WorkClass::BlockProposal => RoleBucket::Validator,
            WorkClass::InferenceServed
            | WorkClass::TeeSession
            | WorkClass::RpcTraffic
            | WorkClass::ComputeLease
            | WorkClass::StorageServed => RoleBucket::Provider,
            WorkClass::AppUsage => RoleBucket::Ecosystem,
        }
    }

    /// Stable key fragment.
    pub fn as_key(&self) -> &'static str {
        match self {
            WorkClass::ConsensusVote => "consensus_vote",
            WorkClass::BlockProposal => "block_proposal",
            WorkClass::InferenceServed => "inference_served",
            WorkClass::TeeSession => "tee_session",
            WorkClass::RpcTraffic => "rpc_traffic",
            WorkClass::AppUsage => "app_usage",
            WorkClass::ComputeLease => "compute_lease",
            WorkClass::StorageServed => "storage_served",
        }
    }
}

/// Default revenue peg for the provider and ecosystem buckets, in basis
/// points of the work weight they recorded in the epoch. At 10_000 an epoch
/// pays out at most each settlement's own reward ceiling.
pub const DEFAULT_REVENUE_PEG_BPS: u64 = 10_000;

/// Most the rewards one settlement earns may add up to, in basis points of
/// the protocol fee it paid outside the trade: the provider reward, the
/// activity reward and the creator royalty together. Below the whole fee, so
/// a buyer, provider and app acting together always pay more than they earn.
pub const MAX_SETTLEMENT_REWARD_BPS: u64 = 9_000;

/// Provider work weight one settlement earns: what the provider was
/// `credited`, at most `reward_cost_bps` (itself at most
/// [`MAX_SETTLEMENT_REWARD_BPS`]) of the protocol fee `outsider_cost` the
/// settlement paid to parties outside the trade.
pub fn provider_work_weight(credited: u128, outsider_cost: u128, reward_cost_bps: u64) -> u128 {
    let bps = u128::from(reward_cost_bps.min(MAX_SETTLEMENT_REWARD_BPS));
    let ceiling = outsider_cost / 10_000 * bps + outsider_cost % 10_000 * bps / 10_000;
    credited.min(ceiling)
}

/// Domain for the rewards pool account address.
const REWARDS_POOL_DOMAIN: &[u8] = b"tenzro/rewards-pool/v1";

/// The account holding the network-rewards pool.
///
/// Funded once at genesis with [`NETWORK_REWARDS_POOL`]; every reward claim
/// and vesting release is a transfer out of it. Nothing mints rewards, so
/// total supply stays at the genesis figure and rights that lapse simply
/// stay in the pool.
pub fn rewards_pool_address() -> Address {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(REWARDS_POOL_DOMAIN);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    Address::new(out)
}

/// The network-rewards pool and the epoch length its payouts are paced by.
/// How much each epoch pays, and to whom, is the governed [`MintPolicy`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintingSchedule {
    /// Consensus epochs per schedule year.
    pub epochs_per_year: u64,
    /// Total pool the schedule draws from.
    pub pool: u128,
}

impl MintingSchedule {
    /// The schedule for a chain whose epochs last `epoch_ms` of block time,
    /// so each schedule year pays its annual rights over one year of block
    /// time whatever the epoch length.
    pub fn for_epoch_ms(epoch_ms: u64) -> Result<Self, String> {
        if epoch_ms == 0 || epoch_ms > SCHEDULE_YEAR_MS {
            return Err(format!(
                "epoch length {epoch_ms} ms must be positive and at most one year"
            ));
        }
        Ok(Self {
            epochs_per_year: SCHEDULE_YEAR_MS / epoch_ms,
            pool: NETWORK_REWARDS_POOL,
        })
    }

    /// Schedule year for a given epoch number.
    pub fn year_for_epoch(&self, epoch: u64) -> u64 {
        epoch / self.epochs_per_year.max(1)
    }

    /// The scheduled and validator base rights of one epoch under `policy`,
    /// before any are withheld, each capped by the remaining pool.
    pub fn epoch_rights(
        &self,
        policy: &MintPolicy,
        epoch: u64,
        cumulative_issued: u128,
    ) -> (u128, u128) {
        let scheduled = self.per_epoch_rights(policy, epoch, cumulative_issued);
        let base = policy.validator_base_rights.min(
            self.pool
                .saturating_sub(cumulative_issued)
                .saturating_sub(scheduled),
        );
        (scheduled, base)
    }

    /// Rights issued for one epoch under `policy`, capped by the remaining
    /// pool.
    pub fn per_epoch_rights(
        &self,
        policy: &MintPolicy,
        epoch: u64,
        cumulative_issued: u128,
    ) -> u128 {
        let annual = policy.annual_rights(self.year_for_epoch(epoch));
        let per_epoch = annual / self.epochs_per_year.max(1) as u128;
        per_epoch.min(self.pool.saturating_sub(cumulative_issued))
    }
}

/// Multiplier of 1x, in parts per million.
pub const MINT_MULT_ONE_PPM: u64 = 1_000_000;

/// The governed issuance an epoch pays from the pool. Issuance is set in
/// TNZO and never reads a fiat rate. It decays each schedule year down to a
/// floor and is scaled by the issuance controller's multiplier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintPolicy {
    /// Issuance in schedule year 0, whole TNZO.
    pub base_tnzo_per_year: u64,
    /// Share of the previous year's issuance dropped each year, bps.
    pub decay_bps_per_year: u64,
    /// Least yearly issuance, whole TNZO.
    pub floor_tnzo_per_year: u64,
    /// Controller multiplier in force, parts per million.
    pub mult_ppm: u64,
    /// Role split, bps; normalised to 10_000 when read.
    pub validator_bps: u64,
    /// Provider share, bps.
    pub provider_bps: u64,
    /// Ecosystem (app) share, bps.
    pub ecosystem_bps: u64,
    /// Cap on the provider and ecosystem buckets, bps of the work weight
    /// they recorded in the epoch (each settlement's own reward ceiling), at
    /// most 10_000. Rights above the cap stay in the pool, so service payouts
    /// track service paid for, not the calendar.
    pub revenue_peg_bps: u64,
    /// Validator base rights this epoch on top of the validator share: each
    /// active validator's cost floor, funded from a share of the epoch's
    /// burn, drawn from the pool.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub validator_base_rights: u128,
    /// Rights withheld from the epoch and burned from the pool instead, to
    /// net the burn that fees collected in other assets stand for: taken
    /// from the scheduled rights first, then from the base rights.
    #[serde(default, with = "tenzro_types::primitives::u128_serde")]
    pub withheld_rights: u128,
}

impl MintPolicy {
    /// Annual rights for a schedule year: the decayed base, at least the
    /// floor, times the controller multiplier.
    pub fn annual_rights(&self, year: u64) -> u128 {
        let keep = 10_000u128 - u128::from(self.decay_bps_per_year.min(10_000));
        let mut a = u128::from(self.base_tnzo_per_year).saturating_mul(ONE_TNZO);
        for _ in 0..year.min(200) {
            a = a / 10_000 * keep + a % 10_000 * keep / 10_000;
        }
        let a = a.max(u128::from(self.floor_tnzo_per_year).saturating_mul(ONE_TNZO));
        let m = u128::from(self.mult_ppm);
        let one = u128::from(MINT_MULT_ONE_PPM);
        a / one * m + a % one * m / one
    }

    /// Role split (validator, provider, ecosystem), normalised to sum to
    /// 10_000; all to validators when every share is zero.
    pub fn role_split(&self) -> (u32, u32, u32) {
        let (v, p, e) = (self.validator_bps, self.provider_bps, self.ecosystem_bps);
        let total = v + p + e;
        if total == 0 {
            return (10_000, 0, 0);
        }
        let p = (p * 10_000 / total) as u32;
        let e = (e * 10_000 / total) as u32;
        (10_000 - p - e, p, e)
    }

    /// Rights a bucket may pay out in an epoch: its share, capped for the
    /// settlement-weighted buckets at `revenue_peg_bps` (at most 10_000) of
    /// the work weight (`total_weight`) they recorded.
    pub fn bucket_rights(&self, bucket: RoleBucket, share: u128, total_weight: u128) -> u128 {
        match bucket {
            RoleBucket::Validator => share,
            // Each settlement's weight is already its reward ceiling, so
            // neither bucket pays above it.
            RoleBucket::Provider | RoleBucket::Ecosystem => self.paid_peg(share, total_weight),
        }
    }

    /// `share`, at most `revenue_peg_bps` (at most 10_000) of `paid_weight`:
    /// the reward ceilings of the paid settlements an epoch recorded.
    pub fn paid_peg(&self, share: u128, paid_weight: u128) -> u128 {
        let peg_bps = self.revenue_peg_bps.min(10_000) as u128;
        let peg = paid_weight / 10_000 * peg_bps + paid_weight % 10_000 * peg_bps / 10_000;
        share.min(peg)
    }
}

/// One epoch's step of the issuance controller: the multiplier rises while
/// the measured quantity (the security ratio, bps) is below `goal_bps` and
/// falls above it, by up to `adj_bps_per_year` of 1x per year, and stays
/// within `[min_bps, max_bps]`. The gap is clamped to one goal either way,
/// so a ratio far above the goal moves at full speed, never faster.
pub fn next_mint_mult(
    mult_ppm: u64,
    measured_bps: u64,
    goal_bps: u64,
    adj_bps_per_year: u64,
    epochs_per_year: u64,
    min_bps: u64,
    max_bps: u64,
) -> u64 {
    let goal = goal_bps.max(1) as i128;
    let gap = ((goal - measured_bps as i128) * 10_000 / goal).clamp(-10_000, 10_000);
    let step = (adj_bps_per_year as i128) * 100 * gap / 10_000 / epochs_per_year.max(1) as i128;
    let lo = min_bps as i128 * 100;
    let hi = (max_bps as i128 * 100).max(lo);
    u64::try_from((mult_ppm as i128 + step).clamp(lo, hi)).unwrap_or(u64::MAX)
}

/// Lifecycle of a coupon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    /// Issued at epoch close, claimable within the window.
    Issued,
    /// Claimed by the earner; paid out of the pool (liquid + vesting split).
    Claimed,
    /// Claim window elapsed; the amount stays in the pool.
    Expired,
}

/// A per-epoch payout right matched to verified work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardCoupon {
    /// Epoch the work was performed in.
    pub epoch: u64,
    /// Earner address.
    pub address: Address,
    /// Role bucket the rights were drawn from.
    pub bucket: RoleBucket,
    /// Verified work weight that backed this coupon.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub work_weight: u128,
    /// TNZO base units payable on claim.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub amount: u128,
    /// When the coupon was issued (the block that closed its epoch).
    pub issued_at: Timestamp,
    /// Current lifecycle status.
    pub status: CouponStatus,
    /// When the coupon was claimed, if it was.
    pub claimed_at: Option<Timestamp>,
    /// Part of `amount` that is the earner's hardware-level bonus, paid on
    /// top of its base share (see [`LevelBonus`]).
    #[serde(default, with = "tenzro_types::primitives::u128_serde")]
    pub level_bonus: u128,
    /// Part of `amount` that is the validator's running-cost base (see
    /// `MintPolicy::validator_base_rights`): the operator's, paid at its own
    /// liquid share before the rest of the claim is split.
    #[serde(default, with = "tenzro_types::primitives::u128_serde")]
    pub base: u128,
}

impl RewardCoupon {
    /// Key: `reward_coupon:<epoch 16-hex>:<bucket>:<addr hex>`.
    pub fn storage_key(epoch: u64, bucket: RoleBucket, address: &Address) -> String {
        format!(
            "reward_coupon:{:016x}:{}:{}",
            epoch,
            bucket.as_key(),
            hex::encode(address.as_bytes())
        )
    }
}

/// Result of closing one epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochRewardSummary {
    /// Epoch that was closed.
    pub epoch: u64,
    /// Total rights issued for the epoch.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub rights_issued: u128,
    /// Rights withheld from the epoch and burned from the pool.
    #[serde(default, with = "tenzro_types::primitives::u128_serde")]
    pub withheld: u128,
    /// Rights matched into coupons.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub matched: u128,
    /// Rights that lapsed unmatched at issuance (zero-weight buckets,
    /// revenue-peg caps and pro-rata rounding dust).
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub expired_unmatched: u128,
    /// Total validator-bucket work weight.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub validator_weight: u128,
    /// Total provider-bucket work weight.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub provider_weight: u128,
    /// Total ecosystem-bucket work weight.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub ecosystem_weight: u128,
    /// Coupons issued.
    pub coupon_count: u64,
    /// When the epoch was closed.
    pub closed_at: Timestamp,
    /// Hardware-level bonus paid on top of the provider bucket's base
    /// shares; included in `matched`.
    #[serde(default, with = "tenzro_types::primitives::u128_serde")]
    pub level_bonus: u128,
}

/// The hardware-level bonus of one epoch's provider bucket.
///
/// An earner's bonus is its base provider share times the bps of its level,
/// at most `cap_bps`. It is paid on top of the base share, never out of it:
/// first from the provider share's rights that would otherwise lapse, then
/// from the pool beyond the schedule, so no earner's base share changes
/// whatever the levels of the others. When neither covers every bonus, the
/// bonuses shrink pro rata.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LevelBonus {
    /// Level of each provider earner above level 0, by address bytes. An
    /// address absent here is level 0.
    pub levels: BTreeMap<[u8; 32], u8>,
    /// Bonus per level, bps; index 0 is level 0, which earns none.
    pub level_bps: [u64; 4],
    /// Most bonus any level earns, bps; 0 turns the bonus off.
    pub cap_bps: u64,
}

impl LevelBonus {
    /// Bonus bps `level` earns: its governed bps, at most the cap.
    pub fn effective_bps(&self, level: u8) -> u64 {
        if level == 0 {
            return 0;
        }
        self.level_bps
            .get(usize::from(level))
            .copied()
            .unwrap_or(0)
            .min(self.cap_bps)
            .min(10_000)
    }
}

/// `amount * bps / 10_000`, rounded down, without overflow.
fn mul_bps(amount: u128, bps: u64) -> u128 {
    let b = u128::from(bps);
    amount / 10_000 * b + amount % 10_000 * b / 10_000
}

/// Split of a successful claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimOutcome {
    /// Total coupon amount claimed.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub total: u128,
    /// Immediately liquid portion.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub liquid: u128,
    /// Portion routed to a vesting schedule.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub vesting: u128,
    /// Epochs the claimed coupons came from.
    pub epochs: Vec<u64>,
}

/// Aggregate reward accounting, one record in consensus state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardEngineState {
    /// Epoch of the latest finalized block.
    pub current_epoch: u64,
    /// Epochs holding recorded work that have not been closed, ascending.
    pub open_epochs: Vec<u64>,
    /// Closed epochs whose coupons have not yet been swept for expiry,
    /// ascending.
    pub issued_epochs: Vec<u64>,
    /// Highest epoch that has been closed, if any.
    pub last_closed_epoch: Option<u64>,
    /// Total rights issued across all closed epochs.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub cumulative_rights_issued: u128,
    /// Total rights matched into coupons.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub cumulative_matched: u128,
    /// Total coupon amounts claimed.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub cumulative_claimed: u128,
    /// Total rights that stayed in the pool: unmatched at issuance plus
    /// coupons expired past the claim window.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub cumulative_expired: u128,
    /// The issuance controller's mint multiplier, parts per million.
    #[serde(default = "one_mult_ppm")]
    pub mint_mult_ppm: u64,
}

fn one_mult_ppm() -> u64 {
    MINT_MULT_ONE_PPM
}

impl Default for RewardEngineState {
    fn default() -> Self {
        Self {
            current_epoch: 0,
            open_epochs: Vec::new(),
            issued_epochs: Vec::new(),
            last_closed_epoch: None,
            cumulative_rights_issued: 0,
            cumulative_matched: 0,
            cumulative_claimed: 0,
            cumulative_expired: 0,
            mint_mult_ppm: MINT_MULT_ONE_PPM,
        }
    }
}

/// Verified work recorded for an open epoch: one row per
/// (address, class).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkRecord {
    pub address: Address,
    pub class: WorkClass,
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub weight: u128,
}

/// Adds `weight` of `class` work by `address` to an epoch's rows.
pub fn add_work(rows: &mut Vec<WorkRecord>, address: Address, class: WorkClass, weight: u128) {
    if weight == 0 {
        return;
    }
    match rows
        .iter_mut()
        .find(|r| r.address == address && r.class == class)
    {
        Some(row) => row.weight = row.weight.saturating_add(weight),
        None => rows.push(WorkRecord {
            address,
            class,
            weight,
        }),
    }
}

/// Settles one epoch: issues its rights, splits them across the role
/// buckets for the schedule year, and matches each bucket pro-rata to the
/// recorded work. Returns the summary and the coupons, in a fixed order
/// (bucket, then address bytes), so every node produces the same ones.
pub fn settle_epoch(
    schedule: &MintingSchedule,
    policy: &MintPolicy,
    cumulative_rights_issued: u128,
    epoch: u64,
    work: &[WorkRecord],
    closed_at: Timestamp,
) -> (EpochRewardSummary, Vec<RewardCoupon>) {
    settle_epoch_with_levels(
        schedule,
        policy,
        cumulative_rights_issued,
        epoch,
        work,
        &LevelBonus::default(),
        closed_at,
    )
}

/// [`settle_epoch`], then the provider bucket's hardware-level bonus on top
/// of the base shares (see [`LevelBonus`]).
pub fn settle_epoch_with_levels(
    schedule: &MintingSchedule,
    policy: &MintPolicy,
    cumulative_rights_issued: u128,
    epoch: u64,
    work: &[WorkRecord],
    bonus: &LevelBonus,
    closed_at: Timestamp,
) -> (EpochRewardSummary, Vec<RewardCoupon>) {
    let buckets = [
        RoleBucket::Validator,
        RoleBucket::Provider,
        RoleBucket::Ecosystem,
    ];
    let mut bucket_work: [BTreeMap<[u8; 32], u128>; 3] = Default::default();
    let mut bucket_totals = [0u128; 3];
    for row in work {
        let i = buckets
            .iter()
            .position(|b| *b == row.class.bucket())
            .unwrap_or(0);
        bucket_totals[i] = bucket_totals[i].saturating_add(row.weight);
        let entry = bucket_work[i].entry(row.address.0).or_insert(0);
        *entry = entry.saturating_add(row.weight);
    }

    let (scheduled, base) = schedule.epoch_rights(policy, epoch, cumulative_rights_issued);
    let from_scheduled = policy.withheld_rights.min(scheduled);
    let from_base = (policy.withheld_rights - from_scheduled).min(base);
    let (scheduled, base) = (scheduled - from_scheduled, base - from_base);
    let withheld = from_scheduled + from_base;
    let mut rights = scheduled.saturating_add(base);
    let (validator_bps, provider_bps, ecosystem_bps) = policy.role_split();
    let shares_bps = [validator_bps, provider_bps, ecosystem_bps];

    let mut coupons = Vec::new();
    let mut matched: u128 = 0;
    let mut level_bonus: u128 = 0;
    for (i, bucket) in buckets.iter().enumerate() {
        let share_bps = shares_bps[i] as u128;
        let mut share = scheduled / 10_000 * share_bps + scheduled % 10_000 * share_bps / 10_000;
        if *bucket == RoleBucket::Validator {
            // Validators' scheduled share is pegged to the paid work the
            // epoch settled, as the other buckets are: consensus over an
            // epoch with no paid settlement earns no pool release. The base is
            // the governed share of the burn those settlements paid.
            let paid = bucket_totals[1].saturating_add(bucket_totals[2]);
            share = policy.paid_peg(share, paid).saturating_add(base);
        }
        let total_weight = bucket_totals[i];
        let bucket_rights = policy.bucket_rights(*bucket, share, total_weight);
        if bucket_rights == 0 || total_weight == 0 {
            continue; // Unmatched share lapses.
        }
        let first = coupons.len();
        let mut bucket_matched: u128 = 0;
        for (address, weight) in &bucket_work[i] {
            let amount = pro_rata(bucket_rights, *weight, total_weight);
            if amount == 0 {
                continue;
            }
            bucket_matched = bucket_matched.saturating_add(amount);
            coupons.push(RewardCoupon {
                epoch,
                address: Address::new(*address),
                bucket: *bucket,
                work_weight: *weight,
                amount,
                issued_at: closed_at,
                status: CouponStatus::Issued,
                claimed_at: None,
                level_bonus: 0,
                base: if *bucket == RoleBucket::Validator {
                    pro_rata(base, *weight, total_weight).min(amount)
                } else {
                    0
                },
            });
        }
        matched = matched.saturating_add(bucket_matched);
        if *bucket != RoleBucket::Provider || bonus.cap_bps == 0 {
            continue;
        }
        // The bonus comes from the share's unmatched rights, then from the
        // pool beyond what this epoch already issues; base shares are final.
        let wanted: Vec<u128> = coupons[first..]
            .iter()
            .map(|c| {
                let level = bonus.levels.get(&c.address.0).copied().unwrap_or(0);
                mul_bps(c.amount, bonus.effective_bps(level))
            })
            .collect();
        let total_wanted = wanted.iter().fold(0u128, |a, w| a.saturating_add(*w));
        if total_wanted == 0 {
            continue;
        }
        let headroom = share.saturating_sub(bucket_matched);
        // Withheld rights are burned from the pool, so no bonus is paid from them.
        let pool_room = schedule
            .pool
            .saturating_sub(cumulative_rights_issued)
            .saturating_sub(rights)
            .saturating_sub(withheld);
        let available = headroom.saturating_add(pool_room);
        let mut paid: u128 = 0;
        for (coupon, want) in coupons[first..].iter_mut().zip(&wanted) {
            let b = if total_wanted <= available {
                *want
            } else {
                pro_rata(available, *want, total_wanted)
            };
            coupon.amount = coupon.amount.saturating_add(b);
            coupon.level_bonus = b;
            paid = paid.saturating_add(b);
        }
        rights = rights.saturating_add(paid.saturating_sub(headroom));
        matched = matched.saturating_add(paid);
        level_bonus = paid;
    }

    let summary = EpochRewardSummary {
        epoch,
        rights_issued: rights,
        withheld,
        matched,
        expired_unmatched: rights.saturating_sub(matched),
        validator_weight: bucket_totals[0],
        provider_weight: bucket_totals[1],
        ecosystem_weight: bucket_totals[2],
        coupon_count: coupons.len() as u64,
        closed_at,
        level_bonus,
    };
    (summary, coupons)
}

/// Whether a coupon issued in `coupon_epoch` has passed its claim window at
/// `current_epoch`.
pub fn coupon_expired(coupon_epoch: u64, current_epoch: u64, window_epochs: u64) -> bool {
    coupon_epoch.saturating_add(window_epochs) < current_epoch
}

/// Splits a claim into its liquid and vesting parts at `liquid_bps`.
pub fn split_claim(total: u128, liquid_bps: u32) -> (u128, u128) {
    let bps = liquid_bps.min(10_000) as u128;
    let liquid = total / 10_000 * bps + total % 10_000 * bps / 10_000;
    (liquid, total - liquid)
}

/// Splits a claim of `total`, `base` of it a validator's running-cost base,
/// into liquid and vesting parts: the base at `base_liquid_bps`, the rest at
/// `liquid_bps`.
pub fn claim_parts(total: u128, base: u128, liquid_bps: u32, base_liquid_bps: u32) -> (u128, u128) {
    let base = base.min(total);
    let (bl, bv) = split_claim(base, base_liquid_bps);
    let (rl, rv) = split_claim(total - base, liquid_bps);
    (bl + rl, bv + rv)
}

/// Pro-rata share of `rights` for `weight` out of `total_weight`.
/// Normalizes the denominator into u64 range, then uses
/// quotient/remainder decomposition to stay within u128.
/// `rights * weight / total_weight`, rounded down, without overflow.
pub fn pro_rata(rights: u128, weight: u128, total_weight: u128) -> u128 {
    if total_weight == 0 || weight == 0 {
        return 0;
    }
    let mut w = weight;
    let mut tw = total_weight;
    while tw > u64::MAX as u128 {
        w >>= 1;
        tw >>= 1;
    }
    if tw == 0 || w == 0 {
        return 0;
    }
    (rights / tw) * w + (rights % tw) * w / tw
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::new([byte; 32])
    }

    const DAY_MS: u64 = 86_400_000;

    /// A schedule with one epoch per day.
    fn daily() -> MintingSchedule {
        MintingSchedule::for_epoch_ms(DAY_MS).unwrap()
    }

    fn policy() -> MintPolicy {
        MintPolicy {
            base_tnzo_per_year: 60_000_000,
            decay_bps_per_year: 1_500,
            floor_tnzo_per_year: 10_000_000,
            mult_ppm: MINT_MULT_ONE_PPM,
            validator_bps: 4_500,
            provider_bps: 4_000,
            ecosystem_bps: 1_500,
            revenue_peg_bps: 10_000,
            validator_base_rights: 0,
            withheld_rights: 0,
        }
    }

    #[test]
    fn withheld_rights_come_from_the_schedule_first_then_the_base() {
        let schedule = daily();
        let work = [WorkRecord {
            address: Address::new([1; 32]),
            class: WorkClass::BlockProposal,
            weight: 1,
        }];
        let mut p = policy();
        p.validator_base_rights = 1_000;
        let (scheduled, base) = schedule.epoch_rights(&p, 0, 0);
        assert_eq!(base, 1_000);
        let full = settle_epoch(&schedule, &p, 0, 0, &work, Timestamp::new(0)).0;
        assert_eq!(full.rights_issued, scheduled + base);
        assert_eq!(full.withheld, 0);

        p.withheld_rights = 7;
        let some = settle_epoch(&schedule, &p, 0, 0, &work, Timestamp::new(0)).0;
        assert_eq!(some.withheld, 7);
        assert_eq!(some.rights_issued, scheduled + base - 7);

        p.withheld_rights = scheduled + 400;
        let most = settle_epoch(&schedule, &p, 0, 0, &work, Timestamp::new(0)).0;
        assert_eq!(
            most.rights_issued, 600,
            "the base keeps what the schedule could not cover"
        );
        assert_eq!(most.withheld, scheduled + 400);

        p.withheld_rights = u128::MAX;
        let all = settle_epoch(&schedule, &p, 0, 0, &work, Timestamp::new(0)).0;
        assert_eq!(all.rights_issued, 0);
        assert_eq!(all.withheld, scheduled + base);
        assert_eq!(all.matched, 0);
    }

    fn settle(work: &[WorkRecord]) -> (EpochRewardSummary, Vec<RewardCoupon>) {
        settle_epoch(&daily(), &policy(), 0, 0, work, Timestamp::new(0))
    }

    /// The first schedule year pays its annual rights over one year of block
    /// time, for production hour-long epochs and compressed minute-long ones.
    #[test]
    fn year_one_emission_matches_annual_rights_for_any_epoch_length() {
        let p = policy();
        for (epoch_ms, epochs) in [(3_600_000, 8_766), (60_000, 525_960)] {
            let s = MintingSchedule::for_epoch_ms(epoch_ms).unwrap();
            assert_eq!(s.epochs_per_year, epochs);
            let mut issued = 0u128;
            for epoch in 0..s.epochs_per_year {
                issued += s.per_epoch_rights(&p, epoch, issued);
            }
            let annual = p.annual_rights(0);
            assert!(issued <= annual && annual - issued < s.epochs_per_year as u128);
            assert_eq!(s.year_for_epoch(s.epochs_per_year), 1);
        }
        assert!(MintingSchedule::for_epoch_ms(0).is_err());
        assert!(MintingSchedule::for_epoch_ms(SCHEDULE_YEAR_MS + 1).is_err());
    }

    #[test]
    fn issuance_decays_to_its_floor_and_follows_the_multiplier() {
        let mut p = policy();
        assert_eq!(p.annual_rights(0), 60_000_000 * ONE_TNZO);
        assert_eq!(p.annual_rights(1), 51_000_000 * ONE_TNZO);
        assert_eq!(p.annual_rights(2), 43_350_000 * ONE_TNZO);
        assert_eq!(p.annual_rights(40), 10_000_000 * ONE_TNZO);
        p.mult_ppm = MINT_MULT_ONE_PPM * 3 / 2;
        assert_eq!(p.annual_rights(0), 90_000_000 * ONE_TNZO);
    }

    #[test]
    fn per_epoch_rights_capped_by_pool() {
        let s = daily();
        let p = policy();
        let per_epoch = 60_000_000 * ONE_TNZO / s.epochs_per_year as u128;
        assert_eq!(s.per_epoch_rights(&p, 0, 0), per_epoch);
        assert_eq!(s.per_epoch_rights(&p, 0, NETWORK_REWARDS_POOL - 5), 5);
        assert_eq!(s.per_epoch_rights(&p, 0, NETWORK_REWARDS_POOL), 0);
    }

    #[test]
    fn role_splits_sum_to_ten_thousand() {
        let mut p = policy();
        for (v, pr, e) in [
            (4_500, 4_000, 1_500),
            (1, 1, 1),
            (0, 0, 0),
            (7_000, 7_000, 7_000),
        ] {
            p.validator_bps = v;
            p.provider_bps = pr;
            p.ecosystem_bps = e;
            let (a, b, c) = p.role_split();
            assert_eq!(a + b + c, 10_000, "{v} {pr} {e}");
        }
    }

    #[test]
    fn a_validator_coupon_records_its_running_cost_base() {
        let mut work = Vec::new();
        add_work(&mut work, addr(1), WorkClass::BlockProposal, 3);
        add_work(&mut work, addr(2), WorkClass::BlockProposal, 1);
        let mut p = policy();
        p.validator_base_rights = 8 * ONE_TNZO;
        let (_, c) = settle_epoch(&daily(), &p, 0, 0, &work, Timestamp::new(0));
        let base: Vec<u128> = c.iter().map(|c| c.base).collect();
        assert_eq!(base, vec![6 * ONE_TNZO, 2 * ONE_TNZO]);
        assert!(c.iter().all(|c| c.base <= c.amount));
        assert_eq!(
            claim_parts(10 * ONE_TNZO, 4 * ONE_TNZO, 2_500, 10_000),
            (5_500_000_000_000_000_000, 4_500_000_000_000_000_000)
        );
        assert_eq!(
            claim_parts(10 * ONE_TNZO, 0, 2_500, 10_000),
            split_claim(10 * ONE_TNZO, 2_500)
        );
        assert_eq!(
            claim_parts(10 * ONE_TNZO, 4 * ONE_TNZO, 2_500, 2_500),
            split_claim(10 * ONE_TNZO, 2_500)
        );
    }

    #[test]
    fn validator_base_rights_add_to_the_validator_share_only() {
        let mut work = Vec::new();
        add_work(&mut work, addr(1), WorkClass::BlockProposal, 1);
        // No paid settlement in the epoch: the validator share releases
        // nothing, and only the base, the burn's share, is paid.
        let (plain, c0) = settle(&work);
        assert!(c0.is_empty(), "{c0:?}");
        let mut p = policy();
        p.validator_base_rights = 7 * ONE_TNZO;
        let (with, c1) = settle_epoch(&daily(), &p, 0, 0, &work, Timestamp::new(0));
        assert_eq!(with.rights_issued, plain.rights_issued + 7 * ONE_TNZO);
        assert_eq!(c1[0].amount, 7 * ONE_TNZO);
        // With paid work the validator share is released too, at most the
        // paid weight, on top of the base.
        add_work(&mut work, addr(9), WorkClass::InferenceServed, ONE_TNZO);
        let (_, c2) = settle_epoch(&daily(), &p, 0, 0, &work, Timestamp::new(0));
        let v = c2.iter().find(|c| c.address == addr(1)).unwrap();
        assert!(v.amount > 7 * ONE_TNZO && v.amount <= 8 * ONE_TNZO, "{v:?}");
        // Never past the pool.
        let (capped, _) = settle_epoch(
            &daily(),
            &p,
            NETWORK_REWARDS_POOL,
            0,
            &work,
            Timestamp::new(0),
        );
        assert_eq!(capped.rights_issued, 0);
    }

    #[test]
    fn the_controller_raises_mint_below_the_security_ratio_within_bounds() {
        let one = MINT_MULT_ONE_PPM;
        let k = 15_000;
        // Far below the ratio: rises by the yearly rate spread over the
        // epochs, but never above 1x.
        let half = next_mint_mult(one / 2, 0, k, 2_500, 365, 5_000, 10_000);
        assert_eq!(half - one / 2, 2_500 * 100 / 365);
        assert_eq!(next_mint_mult(one, 0, k, 2_500, 365, 5_000, 10_000), one);
        // Above it: falls, at full speed however far above.
        let down = next_mint_mult(one, u64::MAX, k, 2_500, 365, 5_000, 10_000);
        assert_eq!(one - down, 2_500 * 100 / 365);
        assert_eq!(
            next_mint_mult(one, 2 * k, k, 2_500, 365, 5_000, 10_000),
            down
        );
        // At it: holds.
        assert_eq!(next_mint_mult(one, k, k, 2_500, 365, 5_000, 10_000), one);
        // Bounded below.
        assert_eq!(
            next_mint_mult(one / 2, u64::MAX, k, 2_500, 1, 5_000, 10_000),
            one / 2
        );
    }

    #[test]
    fn settlement_issues_pro_rata_coupons_in_a_fixed_order() {
        let mut work = Vec::new();
        add_work(&mut work, addr(2), WorkClass::BlockProposal, 1);
        add_work(&mut work, addr(1), WorkClass::BlockProposal, 2);
        add_work(&mut work, addr(1), WorkClass::BlockProposal, 1);
        assert_eq!(work.len(), 2);
        // The paid settlement the epoch's releases are pegged to.
        add_work(
            &mut work,
            addr(9),
            WorkClass::InferenceServed,
            1_000_000 * ONE_TNZO,
        );
        let (summary, coupons) = settle(&work);
        assert_eq!(coupons.len(), 3);
        assert_eq!(coupons[0].address, addr(1));
        assert_eq!(coupons[0].work_weight, 3);
        assert!(coupons[0].amount > coupons[1].amount);
        // The ecosystem bucket had no work: its share lapses.
        assert_eq!(
            summary.matched,
            coupons.iter().map(|c| c.amount).sum::<u128>()
        );
        assert_eq!(
            summary.expired_unmatched,
            summary.rights_issued - summary.matched
        );
    }

    /// Provider payouts are capped by the revenue they settled.
    #[test]
    fn provider_payouts_are_pegged_to_verified_revenue() {
        let mut work = Vec::new();
        add_work(&mut work, addr(1), WorkClass::InferenceServed, 3 * ONE_TNZO);
        add_work(&mut work, addr(2), WorkClass::InferenceServed, ONE_TNZO);
        let (summary, coupons) = settle(&work);
        assert_eq!(coupons[0].amount, 3 * ONE_TNZO);
        assert_eq!(coupons[1].amount, ONE_TNZO);
        assert_eq!(summary.matched, 4 * ONE_TNZO);
    }

    /// Compute leases and storage are provider work: they draw on the
    /// provider bucket beside inference, pro rata to the weight each
    /// settlement earned, and nothing reaches the ecosystem bucket.
    #[test]
    fn compute_leases_and_storage_share_the_provider_bucket() {
        assert_eq!(WorkClass::ComputeLease.bucket(), RoleBucket::Provider);
        assert_eq!(WorkClass::StorageServed.bucket(), RoleBucket::Provider);
        assert_eq!(WorkClass::ComputeLease.as_key(), "compute_lease");
        assert_eq!(WorkClass::StorageServed.as_key(), "storage_served");
        let mut work = Vec::new();
        add_work(&mut work, addr(1), WorkClass::InferenceServed, ONE_TNZO);
        add_work(&mut work, addr(2), WorkClass::ComputeLease, 2 * ONE_TNZO);
        add_work(&mut work, addr(3), WorkClass::StorageServed, 3 * ONE_TNZO);
        let (summary, coupons) = settle(&work);
        assert_eq!(summary.provider_weight, 6 * ONE_TNZO);
        assert_eq!(summary.ecosystem_weight, 0);
        let paid: Vec<u128> = coupons.iter().map(|c| c.amount).collect();
        assert_eq!(paid, vec![ONE_TNZO, 2 * ONE_TNZO, 3 * ONE_TNZO]);
        assert!(coupons.iter().all(|c| c.bucket == RoleBucket::Provider));
    }

    /// A settlement's provider weight is what the provider was paid, at most
    /// the governed share of the fee paid outside the trade, and that share
    /// never reaches the whole fee whatever is asked for.
    #[test]
    fn provider_weight_never_reaches_the_fee_paid_outside_the_trade() {
        let fee = 10 * ONE_TNZO;
        assert_eq!(provider_work_weight(ONE_TNZO, fee, 4_000), ONE_TNZO);
        assert_eq!(
            provider_work_weight(10_000 * ONE_TNZO, fee, 4_000),
            4 * ONE_TNZO
        );
        assert_eq!(
            provider_work_weight(10_000 * ONE_TNZO, fee, 10_000),
            9 * ONE_TNZO
        );
        assert_eq!(
            provider_work_weight(10_000 * ONE_TNZO, fee, u64::MAX),
            9 * ONE_TNZO
        );
        assert_eq!(
            provider_work_weight(u128::MAX, u128::MAX, u64::MAX),
            u128::MAX / 10_000 * 9_000 + u128::MAX % 10_000 * 9_000 / 10_000
        );
        assert_eq!(provider_work_weight(5, 0, 9_000), 0);
        for fee in [1u128, 9, 10_001, 3 * ONE_TNZO + 7, u128::MAX] {
            for bps in [0u64, 1, 4_000, 9_000, 9_001, u64::MAX] {
                assert!(provider_work_weight(u128::MAX, fee, bps) < fee);
            }
        }
    }

    /// Neither settlement-weighted bucket pays above the weight it recorded,
    /// whatever peg is set.
    #[test]
    fn a_peg_above_one_never_pays_above_the_recorded_weight() {
        let mut p = policy();
        p.revenue_peg_bps = 100_000;
        for bucket in [RoleBucket::Provider, RoleBucket::Ecosystem] {
            assert_eq!(
                p.bucket_rights(bucket, 50 * ONE_TNZO, 3 * ONE_TNZO),
                3 * ONE_TNZO
            );
        }
        assert_eq!(
            p.bucket_rights(RoleBucket::Validator, 50 * ONE_TNZO, 0),
            50 * ONE_TNZO
        );
    }

    #[test]
    fn zero_work_epoch_lapses_all_rights() {
        let (summary, coupons) = settle(&[]);
        assert!(coupons.is_empty());
        assert_eq!(summary.expired_unmatched, summary.rights_issued);
    }

    #[test]
    fn claim_split_and_expiry() {
        let (liquid, vesting) = split_claim(1_000_001, DEFAULT_LIQUID_BPS);
        assert_eq!(liquid + vesting, 1_000_001);
        assert_eq!(liquid, 250_000);
        assert!(!coupon_expired(
            0,
            DEFAULT_CLAIM_WINDOW_EPOCHS,
            DEFAULT_CLAIM_WINDOW_EPOCHS
        ));
        assert!(coupon_expired(
            0,
            DEFAULT_CLAIM_WINDOW_EPOCHS + 1,
            DEFAULT_CLAIM_WINDOW_EPOCHS
        ));
    }

    #[test]
    fn pro_rata_handles_large_weights() {
        let rights = 60_000_000 * ONE_TNZO / 365;
        let big = u128::from(u64::MAX) * 16;
        let share = pro_rata(rights, big / 2, big);
        assert!(share > 0 && share <= rights);
        assert!((rights / 2).abs_diff(share) < rights / 1_000);
    }

    /// The genesis band: 1%, 2% and 3% for levels 1 to 3, capped at 3%.
    fn band(levels: &[(u8, u8)]) -> LevelBonus {
        LevelBonus {
            levels: levels.iter().map(|(a, l)| ([*a; 32], *l)).collect(),
            level_bps: [0, 100, 200, 300],
            cap_bps: 300,
        }
    }

    fn settle_levels(
        work: &[WorkRecord],
        cumulative: u128,
        bonus: &LevelBonus,
    ) -> (EpochRewardSummary, Vec<RewardCoupon>) {
        settle_epoch_with_levels(
            &daily(),
            &policy(),
            cumulative,
            0,
            work,
            bonus,
            Timestamp::new(0),
        )
    }

    fn paid(coupons: &[RewardCoupon], a: u8, bucket: RoleBucket) -> u128 {
        coupons
            .iter()
            .find(|c| c.address == addr(a) && c.bucket == bucket)
            .map_or(0, |c| c.amount)
    }

    /// Two providers with the same work, one at level 0 and one at level 1,
    /// earn in the governed ratio, whether the bonus fits in the provider
    /// share's headroom or is drawn from the pool beyond it.
    #[test]
    fn identical_providers_but_for_level_earn_in_the_governed_ratio() {
        for weight in [ONE_TNZO, 1_000_000_000 * ONE_TNZO] {
            let mut work = Vec::new();
            add_work(&mut work, addr(1), WorkClass::InferenceServed, weight);
            add_work(&mut work, addr(2), WorkClass::InferenceServed, weight);
            let (summary, coupons) = settle_levels(&work, 0, &band(&[(2, 1)]));
            let (l0, l1) = (
                paid(&coupons, 1, RoleBucket::Provider),
                paid(&coupons, 2, RoleBucket::Provider),
            );
            assert!(l0 > 0);
            assert_eq!(l1, l0 + l0 / 10_000 * 100 + l0 % 10_000 * 100 / 10_000);
            assert_eq!(summary.level_bonus, l1 - l0);
            assert_eq!(
                summary.matched,
                coupons.iter().map(|c| c.amount).sum::<u128>()
            );
            assert!(summary.matched <= summary.rights_issued);
        }
    }

    /// A level whose governed bonus is above the cap earns the cap, no more.
    #[test]
    fn a_level_above_the_cap_earns_only_the_cap() {
        let mut work = Vec::new();
        add_work(&mut work, addr(1), WorkClass::InferenceServed, ONE_TNZO);
        add_work(&mut work, addr(3), WorkClass::InferenceServed, ONE_TNZO);
        let mut b = band(&[(3, 3)]);
        b.level_bps[3] = 900;
        let (_, coupons) = settle_levels(&work, 0, &b);
        let (l0, l3) = (
            paid(&coupons, 1, RoleBucket::Provider),
            paid(&coupons, 3, RoleBucket::Provider),
        );
        assert_eq!(l3 - l0, l0 / 10_000 * 300 + l0 % 10_000 * 300 / 10_000);
        // A level the band does not know earns nothing, and a cap of 0 turns
        // every bonus off.
        assert_eq!(b.effective_bps(9), 0);
        b.cap_bps = 0;
        let (summary, coupons) = settle_levels(&work, 0, &b);
        assert_eq!(summary.level_bonus, 0);
        assert_eq!(
            paid(&coupons, 3, RoleBucket::Provider),
            paid(&coupons, 1, RoleBucket::Provider)
        );
    }

    /// A level-0 participant earns at least what it earns with levels off,
    /// in every bucket, however many others hold a level, including when
    /// the pool can no longer cover every bonus.
    #[test]
    fn level_zero_earns_at_least_its_reward_with_levels_off() {
        let mut work = Vec::new();
        add_work(&mut work, addr(1), WorkClass::BlockProposal, 5);
        add_work(
            &mut work,
            addr(1),
            WorkClass::InferenceServed,
            1_000_000_000 * ONE_TNZO,
        );
        add_work(&mut work, addr(1), WorkClass::AppUsage, ONE_TNZO);
        for a in 2..40u8 {
            add_work(
                &mut work,
                addr(a),
                WorkClass::InferenceServed,
                1_000_000_000 * ONE_TNZO,
            );
        }
        let levels: Vec<(u8, u8)> = (2..40u8).map(|a| (a, 1 + a % 3)).collect();
        let scheduled = daily().per_epoch_rights(&policy(), 0, 0);
        for cumulative in [0, daily().pool - scheduled - 1_000] {
            let (off_summary, off) = settle_levels(&work, cumulative, &LevelBonus::default());
            let (on_summary, on) = settle_levels(&work, cumulative, &band(&levels));
            for bucket in [
                RoleBucket::Validator,
                RoleBucket::Provider,
                RoleBucket::Ecosystem,
            ] {
                assert!(paid(&on, 1, bucket) >= paid(&off, 1, bucket));
                assert_eq!(paid(&on, 1, bucket), paid(&off, 1, bucket));
            }
            // Every base share is the same; the bonus is on top.
            for (a, b) in off.iter().zip(&on) {
                assert_eq!(b.amount - b.level_bonus, a.amount);
            }
            assert!(on_summary.level_bonus > 0);
            assert!(on_summary.rights_issued >= off_summary.rights_issued);
            assert!(cumulative + on_summary.rights_issued <= daily().pool);
        }
    }

    #[test]
    fn pro_rata_dust_never_exceeds_rights() {
        let rights = 1_000_003;
        let total = pro_rata(rights, 3, 7) + pro_rata(rights, 2, 7) + pro_rata(rights, 2, 7);
        assert!(total <= rights);
    }
}
