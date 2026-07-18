//! Work-gated reward distribution.
//!
//! TNZO enters circulation only against verified work. Every epoch the
//! network issues a bounded amount of minting rights (a declining
//! schedule drawn from the 400M network-rewards pool), splits those
//! rights across three role buckets (validators / providers /
//! ecosystem), and matches them pro-rata to the verified work recorded
//! during that epoch. Matched rights become [`RewardCoupon`]s the
//! earner claims within [`CLAIM_WINDOW_EPOCHS`]; unmatched rights and
//! unclaimed coupons expire permanently unminted.
//!
//! Work evidence is never self-reported:
//!
//! - Validator work ([`WorkClass::BlockProposal`] /
//!   [`WorkClass::ConsensusVote`]) comes from finalized block headers —
//!   the proposer address and the commit-QC validator signatures.
//! - Provider work ([`WorkClass::InferenceServed`] and the other
//!   settlement-bound classes) is weighted by settled fees, ingested as
//!   deltas of cumulative revenue meters, not by request counts.
//!
//! Storage layout (`CF_TOKENS`):
//! - `reward_engine:state` → JSON-encoded [`RewardEngineState`].
//! - `reward_epoch:<epoch 16-hex>` → JSON-encoded [`EpochRewardSummary`].
//! - `reward_coupon:<epoch 16-hex>:<bucket>:<addr hex>` → JSON-encoded
//!   [`RewardCoupon`].
//! - `reward_pending:<epoch 16-hex>` → JSON-encoded pending-work rows
//!   (work recorded for a not-yet-closed epoch).
//! - `reward_meter:<class>:<addr hex>` → JSON-encoded `u128` last-seen
//!   cumulative meter reading.
//!
//! All TNZO amounts are 18-decimal base units.

use crate::error::{Result, TokenError};
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;
use std::collections::HashMap;
use std::sync::Arc;
use tenzro_storage::{KvStore, WriteOp, CF_TOKENS};
use tenzro_types::primitives::{Address, Timestamp};
use tracing::{debug, info, warn};

/// Epochs an issued coupon stays claimable before it expires unminted.
pub const CLAIM_WINDOW_EPOCHS: u64 = 30;

/// Default epochs per schedule year (one consensus epoch per day).
pub const DEFAULT_EPOCHS_PER_YEAR: u64 = 365;

/// One TNZO in base units.
pub const ONE_TNZO: u128 = 1_000_000_000_000_000_000;

/// Total network-rewards pool: 400M TNZO (40% of supply).
pub const NETWORK_REWARDS_POOL: u128 = 400_000_000 * ONE_TNZO;

/// Default liquid share of a claim, in basis points. The remainder
/// vests (12-month linear per the economic model).
pub const DEFAULT_LIQUID_BPS: u32 = 2500;

/// Storage key for the singleton [`RewardEngineState`].
pub const REWARD_STATE_KEY: &[u8] = b"reward_engine:state";
/// Prefix for per-epoch summaries: `reward_epoch:<epoch 16-hex>`.
pub const REWARD_EPOCH_PREFIX: &[u8] = b"reward_epoch:";
/// Prefix for coupons: `reward_coupon:<epoch 16-hex>:<bucket>:<addr hex>`.
pub const REWARD_COUPON_PREFIX: &[u8] = b"reward_coupon:";
/// Prefix for pending (open-epoch) work: `reward_pending:<epoch 16-hex>`.
pub const REWARD_PENDING_PREFIX: &[u8] = b"reward_pending:";
/// Prefix for cumulative meters: `reward_meter:<class>:<addr hex>`.
pub const REWARD_METER_PREFIX: &[u8] = b"reward_meter:";

/// Role bucket a work class settles into for the epoch split.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleBucket {
    /// Consensus participation: proposals + commit votes.
    Validator,
    /// Verified served work: inference, TEE sessions, training, RPC.
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
/// validator classes count events (1 per proposal / vote); provider and
/// ecosystem classes weigh settled fees in TNZO base units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkClass {
    /// Commit-QC signature on a finalized block (chain-verified).
    ConsensusVote,
    /// Proposer of a finalized block (chain-verified).
    BlockProposal,
    /// Settled inference fees (from the usage tracker's revenue meter).
    InferenceServed,
    /// Settled attested-TEE-session fees.
    TeeSession,
    /// Finalized training-round fees.
    TrainingRound,
    /// Settled RPC traffic fees (T3).
    RpcTraffic,
    /// Settled usage fees attributed to a registered app / agent / tool.
    AppUsage,
}

impl WorkClass {
    /// The role bucket this class draws minting rights from.
    pub fn bucket(&self) -> RoleBucket {
        match self {
            WorkClass::ConsensusVote | WorkClass::BlockProposal => RoleBucket::Validator,
            WorkClass::InferenceServed
            | WorkClass::TeeSession
            | WorkClass::TrainingRound
            | WorkClass::RpcTraffic => RoleBucket::Provider,
            WorkClass::AppUsage => RoleBucket::Ecosystem,
        }
    }

    /// Stable key fragment used in meter storage keys.
    pub fn as_key(&self) -> &'static str {
        match self {
            WorkClass::ConsensusVote => "consensus_vote",
            WorkClass::BlockProposal => "block_proposal",
            WorkClass::InferenceServed => "inference_served",
            WorkClass::TeeSession => "tee_session",
            WorkClass::TrainingRound => "training_round",
            WorkClass::RpcTraffic => "rpc_traffic",
            WorkClass::AppUsage => "app_usage",
        }
    }
}

/// Declining minting-rights schedule over the network-rewards pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintingSchedule {
    /// Consensus epochs per schedule year.
    pub epochs_per_year: u64,
    /// Total pool the schedule draws from.
    pub pool: u128,
}

impl Default for MintingSchedule {
    fn default() -> Self {
        Self {
            epochs_per_year: DEFAULT_EPOCHS_PER_YEAR,
            pool: NETWORK_REWARDS_POOL,
        }
    }
}

impl MintingSchedule {
    /// Schedule year for a given epoch number.
    pub fn year_for_epoch(&self, epoch: u64) -> u64 {
        epoch / self.epochs_per_year.max(1)
    }

    /// Annual minting rights for a schedule year.
    pub fn annual_rights_for_year(&self, year: u64) -> u128 {
        match year {
            0 => 60_000_000 * ONE_TNZO,
            1..=2 => 45_000_000 * ONE_TNZO,
            3..=5 => 30_000_000 * ONE_TNZO,
            6..=9 => 20_000_000 * ONE_TNZO,
            _ => 10_000_000 * ONE_TNZO,
        }
    }

    /// Rights issued for one epoch, capped by the remaining pool.
    pub fn per_epoch_rights(&self, epoch: u64, cumulative_issued: u128) -> u128 {
        let annual = self.annual_rights_for_year(self.year_for_epoch(epoch));
        let per_epoch = annual / self.epochs_per_year.max(1) as u128;
        per_epoch.min(self.pool.saturating_sub(cumulative_issued))
    }

    /// Role split for a schedule year, in basis points:
    /// (validator, provider, ecosystem). Always sums to 10_000.
    pub fn role_split_for_year(&self, year: u64) -> (u32, u32, u32) {
        match year {
            0 => (4500, 4000, 1500),
            1..=2 => (3000, 4000, 3000),
            3..=5 => (2000, 3500, 4500),
            _ => (1500, 2500, 6000),
        }
    }
}

/// Lifecycle of a coupon.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponStatus {
    /// Issued at epoch close, claimable within the window.
    Issued,
    /// Claimed by the earner; TNZO minted (liquid + vesting split).
    Claimed,
    /// Claim window elapsed; permanently unminted.
    Expired,
}

/// A per-epoch minting right matched to verified work.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardCoupon {
    /// Epoch the work was performed in.
    pub epoch: u64,
    /// Earner address.
    pub address: Address,
    /// Role bucket the rights were drawn from.
    pub bucket: RoleBucket,
    /// Verified work weight that backed this coupon.
    pub work_weight: u128,
    /// TNZO base units mintable on claim.
    pub amount: u128,
    /// When the coupon was issued (epoch close).
    pub issued_at: Timestamp,
    /// Current lifecycle status.
    pub status: CouponStatus,
    /// When the coupon was claimed, if it was.
    pub claimed_at: Option<Timestamp>,
}

impl RewardCoupon {
    /// Storage key: `reward_coupon:<epoch 16-hex>:<bucket>:<addr hex>`.
    pub fn storage_key(epoch: u64, bucket: RoleBucket, address: &Address) -> Vec<u8> {
        format!(
            "reward_coupon:{:016x}:{}:{}",
            epoch,
            bucket.as_key(),
            hex::encode(address.as_bytes())
        )
        .into_bytes()
    }
}

/// Result of closing one epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochRewardSummary {
    /// Epoch that was closed.
    pub epoch: u64,
    /// Total rights issued for the epoch.
    pub rights_issued: u128,
    /// Rights matched into coupons.
    pub matched: u128,
    /// Rights that lapsed unmatched at issuance (zero-weight buckets +
    /// pro-rata rounding dust). Permanently unminted.
    pub expired_unmatched: u128,
    /// Total validator-bucket work weight.
    pub validator_weight: u128,
    /// Total provider-bucket work weight.
    pub provider_weight: u128,
    /// Total ecosystem-bucket work weight.
    pub ecosystem_weight: u128,
    /// Coupons issued.
    pub coupon_count: u64,
    /// When the epoch was closed.
    pub closed_at: Timestamp,
}

/// Split of a successful claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimOutcome {
    /// Total coupon amount claimed.
    pub total: u128,
    /// Immediately liquid portion.
    pub liquid: u128,
    /// Portion routed to a vesting schedule.
    pub vesting: u128,
    /// Epochs the claimed coupons came from.
    pub epochs: Vec<u64>,
}

/// Persistent aggregate counters for the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardEngineState {
    /// Highest epoch that has been closed, if any.
    pub last_closed_epoch: Option<u64>,
    /// Total rights issued across all closed epochs.
    pub cumulative_rights_issued: u128,
    /// Total rights matched into coupons.
    pub cumulative_matched: u128,
    /// Total coupon amounts claimed (minted).
    pub cumulative_claimed: u128,
    /// Total rights permanently unminted: unmatched at issuance plus
    /// coupons expired past the claim window.
    pub cumulative_expired: u128,
    /// Liquid share of a claim in basis points; remainder vests.
    pub liquid_bps: u32,
}

impl Default for RewardEngineState {
    fn default() -> Self {
        Self {
            last_closed_epoch: None,
            cumulative_rights_issued: 0,
            cumulative_matched: 0,
            cumulative_claimed: 0,
            cumulative_expired: 0,
            liquid_bps: DEFAULT_LIQUID_BPS,
        }
    }
}

/// Serialization shape for pending work rows (tuple-keyed maps do not
/// encode to JSON objects).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingEntry {
    address: Address,
    class: WorkClass,
    weight: u128,
}

/// Work-gated reward engine: records verified work per open epoch,
/// issues coupons at epoch close, and settles claims into a
/// liquid/vesting split.
pub struct RewardEngine {
    /// Verified work for not-yet-closed epochs:
    /// epoch → (address, class) → weight.
    pending: RwLock<HashMap<u64, HashMap<(Address, WorkClass), u128>>>,
    /// Issued/claimed/expired coupons, keyed by storage key string.
    coupons: DashMap<String, RewardCoupon>,
    /// Last-seen cumulative revenue meters per (address, class).
    meters: DashMap<(Address, WorkClass), u128>,
    /// Closed-epoch summaries.
    epoch_summaries: DashMap<u64, EpochRewardSummary>,
    /// Aggregate counters.
    state: RwLock<RewardEngineState>,
    /// Minting-rights schedule.
    schedule: MintingSchedule,
    /// Optional write-through persistence.
    storage: Option<Arc<dyn KvStore>>,
}

impl RewardEngine {
    /// In-memory engine with the default schedule.
    pub fn new() -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
            coupons: DashMap::new(),
            meters: DashMap::new(),
            epoch_summaries: DashMap::new(),
            state: RwLock::new(RewardEngineState::default()),
            schedule: MintingSchedule::default(),
            storage: None,
        }
    }

    /// Engine with RocksDB write-through; hydrates state, coupons,
    /// meters, and pending work from `CF_TOKENS` on construction.
    /// Unreadable records are dropped and deleted (pre-launch flag-day).
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self> {
        let engine = Self {
            storage: Some(storage),
            ..Self::new()
        };
        engine.hydrate()?;
        Ok(engine)
    }

    /// The active minting schedule.
    pub fn schedule(&self) -> &MintingSchedule {
        &self.schedule
    }

    /// Snapshot of the aggregate counters.
    pub fn state_snapshot(&self) -> RewardEngineState {
        self.state.read().clone()
    }

    /// Highest closed epoch, if any.
    pub fn last_closed_epoch(&self) -> Option<u64> {
        self.state.read().last_closed_epoch
    }

    /// Summary of a closed epoch.
    pub fn epoch_summary(&self, epoch: u64) -> Option<EpochRewardSummary> {
        self.epoch_summaries.get(&epoch).map(|s| s.clone())
    }

    /// All coupons for an address, newest epoch first.
    pub fn coupons_for(&self, address: &Address) -> Vec<RewardCoupon> {
        let mut out: Vec<RewardCoupon> = self
            .coupons
            .iter()
            .filter(|e| &e.value().address == address)
            .map(|e| e.value().clone())
            .collect();
        out.sort_by_key(|c| Reverse(c.epoch));
        out
    }

    /// Records verified work for an open epoch. Weight semantics are
    /// per [`WorkClass`]: counts for validator classes, settled fees in
    /// base units for provider/ecosystem classes. Zero weights are
    /// ignored. Work for an already-closed epoch is rejected.
    pub fn record_work(
        &self,
        epoch: u64,
        address: Address,
        class: WorkClass,
        weight: u128,
    ) -> Result<()> {
        if weight == 0 {
            return Ok(());
        }
        self.check_epoch_open(epoch)?;
        {
            let mut pending = self.pending.write();
            let entry = pending
                .entry(epoch)
                .or_default()
                .entry((address, class))
                .or_insert(0);
            *entry = entry.saturating_add(weight);
        }
        self.persist_pending_epoch(epoch)
    }

    /// Records one finalized block's consensus participation: the
    /// proposer earns a [`WorkClass::BlockProposal`] unit and each
    /// commit-QC signer earns a [`WorkClass::ConsensusVote`] unit.
    /// Single persist per block (hot path).
    pub fn record_block_participation(
        &self,
        epoch: u64,
        proposer: &Address,
        voters: &[Address],
    ) -> Result<()> {
        self.check_epoch_open(epoch)?;
        {
            let mut pending = self.pending.write();
            let epoch_map = pending.entry(epoch).or_default();
            let p = epoch_map
                .entry((*proposer, WorkClass::BlockProposal))
                .or_insert(0);
            *p = p.saturating_add(1);
            for voter in voters {
                let v = epoch_map
                    .entry((*voter, WorkClass::ConsensusVote))
                    .or_insert(0);
                *v = v.saturating_add(1);
            }
        }
        self.persist_pending_epoch(epoch)
    }

    /// Ingests a cumulative revenue meter reading (e.g. the usage
    /// tracker's `total_revenue`) and records the delta since the last
    /// reading as work for the open epoch. Returns the delta. A reading
    /// below the stored meter resets the meter without crediting work
    /// (pre-launch flag-day for wiped counters).
    pub fn ingest_cumulative(
        &self,
        epoch: u64,
        address: Address,
        class: WorkClass,
        cumulative: u128,
    ) -> Result<u128> {
        let key = (address, class);
        let last = self.meters.get(&key).map(|m| *m.value()).unwrap_or(0);
        let delta = if cumulative >= last {
            cumulative - last
        } else {
            warn!(
                address = %hex::encode(address.as_bytes()),
                class = class.as_key(),
                last,
                cumulative,
                "reward meter went backwards; resetting without credit (pre-launch flag-day)"
            );
            0
        };
        self.meters.insert(key, cumulative);
        self.persist_meter(&address, class, cumulative)?;
        if delta > 0 {
            self.record_work(epoch, address, class, delta)?;
        }
        Ok(delta)
    }

    /// Closes an epoch: issues that epoch's minting rights, splits them
    /// across role buckets per the schedule year, matches them pro-rata
    /// to recorded work, and sweeps expired coupons. Idempotent — a
    /// second close of the same epoch returns the stored summary.
    pub fn close_epoch(&self, epoch: u64) -> Result<EpochRewardSummary> {
        if let Some(summary) = self.epoch_summaries.get(&epoch) {
            return Ok(summary.clone());
        }
        {
            let state = self.state.read();
            if let Some(last) = state.last_closed_epoch
                && epoch <= last
            {
                return Err(TokenError::InvalidParameter(format!(
                    "epoch {epoch} already closed (last closed {last})"
                )));
            }
        }

        let now = Timestamp::now();
        let work = self.pending.write().remove(&epoch).unwrap_or_default();

        // Aggregate per-address weight within each bucket.
        let mut bucket_totals: HashMap<RoleBucket, u128> = HashMap::new();
        let mut bucket_work: HashMap<RoleBucket, HashMap<Address, u128>> = HashMap::new();
        for ((address, class), weight) in work {
            let bucket = class.bucket();
            let total = bucket_totals.entry(bucket).or_insert(0);
            *total = total.saturating_add(weight);
            let entry = bucket_work
                .entry(bucket)
                .or_default()
                .entry(address)
                .or_insert(0);
            *entry = entry.saturating_add(weight);
        }

        let rights = {
            let state = self.state.read();
            self.schedule
                .per_epoch_rights(epoch, state.cumulative_rights_issued)
        };
        let year = self.schedule.year_for_epoch(epoch);
        let (validator_bps, provider_bps, ecosystem_bps) = self.schedule.role_split_for_year(year);

        let mut ops: Vec<WriteOp> = Vec::new();
        let mut matched: u128 = 0;
        let mut coupon_count: u64 = 0;

        for (bucket, share_bps) in [
            (RoleBucket::Validator, validator_bps),
            (RoleBucket::Provider, provider_bps),
            (RoleBucket::Ecosystem, ecosystem_bps),
        ] {
            let bucket_rights = rights / 10_000 * share_bps as u128
                + rights % 10_000 * share_bps as u128 / 10_000;
            let total_weight = bucket_totals.get(&bucket).copied().unwrap_or(0);
            if bucket_rights == 0 || total_weight == 0 {
                continue; // Unmatched share lapses.
            }
            for (address, weight) in bucket_work.remove(&bucket).unwrap_or_default() {
                let amount = pro_rata(bucket_rights, weight, total_weight);
                if amount == 0 {
                    continue;
                }
                let coupon = RewardCoupon {
                    epoch,
                    address,
                    bucket,
                    work_weight: weight,
                    amount,
                    issued_at: now,
                    status: CouponStatus::Issued,
                    claimed_at: None,
                };
                matched = matched.saturating_add(amount);
                coupon_count += 1;
                let key = RewardCoupon::storage_key(epoch, bucket, &address);
                if self.storage.is_some() {
                    ops.push(WriteOp::Put {
                        cf: CF_TOKENS.to_string(),
                        key: key.clone(),
                        value: serde_json::to_vec(&coupon)
                            .map_err(|e| TokenError::StorageError(format!("encode coupon: {e}")))?,
                    });
                }
                self.coupons
                    .insert(String::from_utf8_lossy(&key).into_owned(), coupon);
            }
        }

        let expired_unmatched = rights.saturating_sub(matched);

        // Sweep coupons whose claim window elapsed at this close.
        let mut swept_expired: u128 = 0;
        for mut entry in self.coupons.iter_mut() {
            let coupon = entry.value_mut();
            if coupon.status == CouponStatus::Issued
                && coupon.epoch.saturating_add(CLAIM_WINDOW_EPOCHS) < epoch
            {
                coupon.status = CouponStatus::Expired;
                swept_expired = swept_expired.saturating_add(coupon.amount);
                if self.storage.is_some() {
                    ops.push(WriteOp::Put {
                        cf: CF_TOKENS.to_string(),
                        key: RewardCoupon::storage_key(coupon.epoch, coupon.bucket, &coupon.address),
                        value: serde_json::to_vec(&*coupon)
                            .map_err(|e| TokenError::StorageError(format!("encode coupon: {e}")))?,
                    });
                }
            }
        }

        let summary = EpochRewardSummary {
            epoch,
            rights_issued: rights,
            matched,
            expired_unmatched,
            validator_weight: bucket_totals
                .get(&RoleBucket::Validator)
                .copied()
                .unwrap_or(0),
            provider_weight: bucket_totals
                .get(&RoleBucket::Provider)
                .copied()
                .unwrap_or(0),
            ecosystem_weight: bucket_totals
                .get(&RoleBucket::Ecosystem)
                .copied()
                .unwrap_or(0),
            coupon_count,
            closed_at: now,
        };

        {
            let mut state = self.state.write();
            state.last_closed_epoch = Some(epoch);
            state.cumulative_rights_issued = state.cumulative_rights_issued.saturating_add(rights);
            state.cumulative_matched = state.cumulative_matched.saturating_add(matched);
            state.cumulative_expired = state
                .cumulative_expired
                .saturating_add(expired_unmatched)
                .saturating_add(swept_expired);
            if let Some(storage) = &self.storage {
                ops.push(WriteOp::Put {
                    cf: CF_TOKENS.to_string(),
                    key: REWARD_STATE_KEY.to_vec(),
                    value: serde_json::to_vec(&*state)
                        .map_err(|e| TokenError::StorageError(format!("encode state: {e}")))?,
                });
                ops.push(WriteOp::Put {
                    cf: CF_TOKENS.to_string(),
                    key: epoch_summary_key(epoch),
                    value: serde_json::to_vec(&summary)
                        .map_err(|e| TokenError::StorageError(format!("encode summary: {e}")))?,
                });
                ops.push(WriteOp::Delete {
                    cf: CF_TOKENS.to_string(),
                    key: pending_key(epoch),
                });
                storage.write_batch_sync(ops)?;
            }
        }

        self.epoch_summaries.insert(epoch, summary.clone());
        info!(
            epoch,
            rights = %rights,
            matched = %matched,
            expired_unmatched = %expired_unmatched,
            coupons = coupon_count,
            "reward epoch closed"
        );
        Ok(summary)
    }

    /// Claims every claimable coupon for an address. Coupons past the
    /// claim window are marked expired instead. Returns the
    /// liquid/vesting split per the configured `liquid_bps`; the caller
    /// (node RPC layer) performs the actual mint and vesting-schedule
    /// creation. Errors with [`TokenError::NotFound`] when nothing is
    /// claimable.
    pub fn claim(&self, address: &Address, current_epoch: u64) -> Result<ClaimOutcome> {
        let now = Timestamp::now();
        let mut total: u128 = 0;
        let mut expired: u128 = 0;
        let mut epochs: Vec<u64> = Vec::new();
        let mut ops: Vec<WriteOp> = Vec::new();

        for mut entry in self.coupons.iter_mut() {
            let coupon = entry.value_mut();
            if &coupon.address != address || coupon.status != CouponStatus::Issued {
                continue;
            }
            if coupon.epoch.saturating_add(CLAIM_WINDOW_EPOCHS) < current_epoch {
                coupon.status = CouponStatus::Expired;
                expired = expired.saturating_add(coupon.amount);
            } else {
                coupon.status = CouponStatus::Claimed;
                coupon.claimed_at = Some(now);
                total = total.saturating_add(coupon.amount);
                epochs.push(coupon.epoch);
            }
            if self.storage.is_some() {
                ops.push(WriteOp::Put {
                    cf: CF_TOKENS.to_string(),
                    key: RewardCoupon::storage_key(coupon.epoch, coupon.bucket, &coupon.address),
                    value: serde_json::to_vec(&*coupon)
                        .map_err(|e| TokenError::StorageError(format!("encode coupon: {e}")))?,
                });
            }
        }

        let liquid_bps = {
            let mut state = self.state.write();
            state.cumulative_claimed = state.cumulative_claimed.saturating_add(total);
            state.cumulative_expired = state.cumulative_expired.saturating_add(expired);
            if self.storage.is_some() && (total > 0 || expired > 0) {
                ops.push(WriteOp::Put {
                    cf: CF_TOKENS.to_string(),
                    key: REWARD_STATE_KEY.to_vec(),
                    value: serde_json::to_vec(&*state)
                        .map_err(|e| TokenError::StorageError(format!("encode state: {e}")))?,
                });
            }
            state.liquid_bps
        };
        if let Some(storage) = &self.storage
            && !ops.is_empty()
        {
            storage.write_batch_sync(ops)?;
        }

        if total == 0 {
            return Err(TokenError::NotFound(format!(
                "no claimable reward coupons for {}",
                hex::encode(address.as_bytes())
            )));
        }

        let liquid =
            total / 10_000 * liquid_bps as u128 + total % 10_000 * liquid_bps as u128 / 10_000;
        let vesting = total - liquid;
        epochs.sort_unstable();
        epochs.dedup();
        info!(
            address = %hex::encode(address.as_bytes()),
            total = %total,
            liquid = %liquid,
            vesting = %vesting,
            "reward coupons claimed"
        );
        Ok(ClaimOutcome {
            total,
            liquid,
            vesting,
            epochs,
        })
    }

    fn check_epoch_open(&self, epoch: u64) -> Result<()> {
        if let Some(last) = self.state.read().last_closed_epoch
            && epoch <= last
        {
            return Err(TokenError::InvalidParameter(format!(
                "epoch {epoch} is closed (last closed {last})"
            )));
        }
        Ok(())
    }

    fn persist_pending_epoch(&self, epoch: u64) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        let entries: Vec<PendingEntry> = {
            let pending = self.pending.read();
            pending
                .get(&epoch)
                .map(|m| {
                    m.iter()
                        .map(|((address, class), weight)| PendingEntry {
                            address: *address,
                            class: *class,
                            weight: *weight,
                        })
                        .collect()
                })
                .unwrap_or_default()
        };
        let value = serde_json::to_vec(&entries)
            .map_err(|e| TokenError::StorageError(format!("encode pending: {e}")))?;
        storage.write_batch_sync(vec![WriteOp::Put {
            cf: CF_TOKENS.to_string(),
            key: pending_key(epoch),
            value,
        }])?;
        Ok(())
    }

    fn persist_meter(&self, address: &Address, class: WorkClass, cumulative: u128) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        let value = serde_json::to_vec(&cumulative)
            .map_err(|e| TokenError::StorageError(format!("encode meter: {e}")))?;
        storage.write_batch_sync(vec![WriteOp::Put {
            cf: CF_TOKENS.to_string(),
            key: meter_key(address, class),
            value,
        }])?;
        Ok(())
    }

    fn hydrate(&self) -> Result<()> {
        let Some(storage) = &self.storage else {
            return Ok(());
        };
        let mut drops: Vec<WriteOp> = Vec::new();

        if let Some(bytes) = storage.get(CF_TOKENS, REWARD_STATE_KEY)? {
            match serde_json::from_slice::<RewardEngineState>(&bytes) {
                Ok(state) => *self.state.write() = state,
                Err(e) => {
                    warn!(error = %e, "dropping unreadable reward state (pre-launch flag-day)");
                    drops.push(WriteOp::Delete {
                        cf: CF_TOKENS.to_string(),
                        key: REWARD_STATE_KEY.to_vec(),
                    });
                }
            }
        }

        let mut coupon_count = 0usize;
        for key in storage.get_keys_with_prefix(CF_TOKENS, REWARD_COUPON_PREFIX)? {
            let Some(bytes) = storage.get(CF_TOKENS, &key)? else {
                continue;
            };
            match serde_json::from_slice::<RewardCoupon>(&bytes) {
                Ok(coupon) => {
                    self.coupons
                        .insert(String::from_utf8_lossy(&key).into_owned(), coupon);
                    coupon_count += 1;
                }
                Err(e) => {
                    warn!(error = %e, "dropping unreadable reward coupon (pre-launch flag-day)");
                    drops.push(WriteOp::Delete {
                        cf: CF_TOKENS.to_string(),
                        key,
                    });
                }
            }
        }

        let mut summary_count = 0usize;
        for key in storage.get_keys_with_prefix(CF_TOKENS, REWARD_EPOCH_PREFIX)? {
            let Some(bytes) = storage.get(CF_TOKENS, &key)? else {
                continue;
            };
            match serde_json::from_slice::<EpochRewardSummary>(&bytes) {
                Ok(summary) => {
                    self.epoch_summaries.insert(summary.epoch, summary);
                    summary_count += 1;
                }
                Err(e) => {
                    warn!(error = %e, "dropping unreadable epoch summary (pre-launch flag-day)");
                    drops.push(WriteOp::Delete {
                        cf: CF_TOKENS.to_string(),
                        key,
                    });
                }
            }
        }

        let mut pending_count = 0usize;
        for key in storage.get_keys_with_prefix(CF_TOKENS, REWARD_PENDING_PREFIX)? {
            let Some(bytes) = storage.get(CF_TOKENS, &key)? else {
                continue;
            };
            let Some(epoch) = parse_epoch_suffix(&key, REWARD_PENDING_PREFIX) else {
                warn!("dropping malformed pending-work key (pre-launch flag-day)");
                drops.push(WriteOp::Delete {
                    cf: CF_TOKENS.to_string(),
                    key,
                });
                continue;
            };
            match serde_json::from_slice::<Vec<PendingEntry>>(&bytes) {
                Ok(entries) => {
                    let mut pending = self.pending.write();
                    let epoch_map = pending.entry(epoch).or_default();
                    for entry in entries {
                        epoch_map.insert((entry.address, entry.class), entry.weight);
                        pending_count += 1;
                    }
                }
                Err(e) => {
                    warn!(error = %e, "dropping unreadable pending work (pre-launch flag-day)");
                    drops.push(WriteOp::Delete {
                        cf: CF_TOKENS.to_string(),
                        key,
                    });
                }
            }
        }

        let mut meter_count = 0usize;
        for key in storage.get_keys_with_prefix(CF_TOKENS, REWARD_METER_PREFIX)? {
            let Some(bytes) = storage.get(CF_TOKENS, &key)? else {
                continue;
            };
            match (
                parse_meter_key(&key),
                serde_json::from_slice::<u128>(&bytes),
            ) {
                (Some((address, class)), Ok(cumulative)) => {
                    self.meters.insert((address, class), cumulative);
                    meter_count += 1;
                }
                _ => {
                    warn!("dropping unreadable reward meter (pre-launch flag-day)");
                    drops.push(WriteOp::Delete {
                        cf: CF_TOKENS.to_string(),
                        key,
                    });
                }
            }
        }

        if !drops.is_empty() {
            storage.write_batch_sync(drops)?;
        }
        debug!(
            coupons = coupon_count,
            summaries = summary_count,
            pending = pending_count,
            meters = meter_count,
            "reward engine hydrated"
        );
        Ok(())
    }
}

impl Default for RewardEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Pro-rata share of `rights` for `weight` out of `total_weight`.
/// Normalizes the denominator into u64 range, then uses
/// quotient/remainder decomposition to stay within u128.
fn pro_rata(rights: u128, weight: u128, total_weight: u128) -> u128 {
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

fn epoch_summary_key(epoch: u64) -> Vec<u8> {
    format!("reward_epoch:{epoch:016x}").into_bytes()
}

fn pending_key(epoch: u64) -> Vec<u8> {
    format!("reward_pending:{epoch:016x}").into_bytes()
}

fn meter_key(address: &Address, class: WorkClass) -> Vec<u8> {
    format!(
        "reward_meter:{}:{}",
        class.as_key(),
        hex::encode(address.as_bytes())
    )
    .into_bytes()
}

/// Parses the 16-hex epoch immediately after `prefix` in a storage key.
fn parse_epoch_suffix(key: &[u8], prefix: &[u8]) -> Option<u64> {
    let rest = key.strip_prefix(prefix)?;
    let hex_part = rest.get(..16)?;
    u64::from_str_radix(std::str::from_utf8(hex_part).ok()?, 16).ok()
}

/// Parses `reward_meter:<class>:<addr hex>` back into its components.
fn parse_meter_key(key: &[u8]) -> Option<(Address, WorkClass)> {
    let rest = key.strip_prefix(REWARD_METER_PREFIX)?;
    let rest = std::str::from_utf8(rest).ok()?;
    let (class_key, addr_hex) = rest.split_once(':')?;
    let class = match class_key {
        "consensus_vote" => WorkClass::ConsensusVote,
        "block_proposal" => WorkClass::BlockProposal,
        "inference_served" => WorkClass::InferenceServed,
        "tee_session" => WorkClass::TeeSession,
        "training_round" => WorkClass::TrainingRound,
        "rpc_traffic" => WorkClass::RpcTraffic,
        "app_usage" => WorkClass::AppUsage,
        _ => return None,
    };
    let bytes: [u8; 32] = hex::decode(addr_hex).ok()?.try_into().ok()?;
    Some((Address::new(bytes), class))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::new([byte; 32])
    }

    #[test]
    fn schedule_declines_by_year() {
        let s = MintingSchedule::default();
        assert_eq!(s.annual_rights_for_year(0), 60_000_000 * ONE_TNZO);
        assert_eq!(s.annual_rights_for_year(1), 45_000_000 * ONE_TNZO);
        assert_eq!(s.annual_rights_for_year(2), 45_000_000 * ONE_TNZO);
        assert_eq!(s.annual_rights_for_year(3), 30_000_000 * ONE_TNZO);
        assert_eq!(s.annual_rights_for_year(5), 30_000_000 * ONE_TNZO);
        assert_eq!(s.annual_rights_for_year(6), 20_000_000 * ONE_TNZO);
        assert_eq!(s.annual_rights_for_year(9), 20_000_000 * ONE_TNZO);
        assert_eq!(s.annual_rights_for_year(10), 10_000_000 * ONE_TNZO);
        assert_eq!(s.annual_rights_for_year(25), 10_000_000 * ONE_TNZO);
    }

    #[test]
    fn per_epoch_rights_capped_by_pool() {
        let s = MintingSchedule::default();
        let per_epoch = s.per_epoch_rights(0, 0);
        assert_eq!(per_epoch, 60_000_000 * ONE_TNZO / 365);
        // Nearly exhausted pool caps issuance.
        let nearly_all = NETWORK_REWARDS_POOL - 5;
        assert_eq!(s.per_epoch_rights(0, nearly_all), 5);
        assert_eq!(s.per_epoch_rights(0, NETWORK_REWARDS_POOL), 0);
    }

    #[test]
    fn role_splits_sum_to_ten_thousand() {
        let s = MintingSchedule::default();
        for year in [0, 1, 2, 3, 5, 6, 9, 10, 30] {
            let (v, p, e) = s.role_split_for_year(year);
            assert_eq!(v + p + e, 10_000, "year {year}");
        }
    }

    #[test]
    fn work_class_bucket_mapping() {
        assert_eq!(WorkClass::ConsensusVote.bucket(), RoleBucket::Validator);
        assert_eq!(WorkClass::BlockProposal.bucket(), RoleBucket::Validator);
        assert_eq!(WorkClass::InferenceServed.bucket(), RoleBucket::Provider);
        assert_eq!(WorkClass::TeeSession.bucket(), RoleBucket::Provider);
        assert_eq!(WorkClass::TrainingRound.bucket(), RoleBucket::Provider);
        assert_eq!(WorkClass::RpcTraffic.bucket(), RoleBucket::Provider);
        assert_eq!(WorkClass::AppUsage.bucket(), RoleBucket::Ecosystem);
    }

    #[test]
    fn close_epoch_issues_pro_rata_coupons() {
        let engine = RewardEngine::new();
        let v1 = addr(1);
        let v2 = addr(2);
        // Two blocks: v1 proposes both; votes split 3 (v1) : 1 (v2).
        engine
            .record_block_participation(0, &v1, &[v1, v2])
            .unwrap();
        engine.record_block_participation(0, &v1, &[v1]).unwrap();
        let summary = engine.close_epoch(0).unwrap();
        let rights = MintingSchedule::default().per_epoch_rights(0, 0);
        assert_eq!(summary.rights_issued, rights);
        // Provider + ecosystem buckets had no work → their shares lapse.
        let validator_share = rights / 10_000 * 4500;
        assert!(summary.expired_unmatched >= rights - validator_share - 4500);
        let c1 = engine.coupons_for(&v1);
        let c2 = engine.coupons_for(&v2);
        assert_eq!(c1.len(), 1);
        assert_eq!(c2.len(), 1);
        // v1 weight: 2 proposals + 2 votes = 4; v2 weight: 1 vote.
        assert_eq!(c1[0].work_weight, 4);
        assert_eq!(c2[0].work_weight, 1);
        assert!(c1[0].amount > c2[0].amount);
        // Total matched never exceeds the validator bucket share.
        assert!(summary.matched <= validator_share + 4500);
    }

    #[test]
    fn close_epoch_is_idempotent() {
        let engine = RewardEngine::new();
        engine
            .record_work(0, addr(1), WorkClass::InferenceServed, 100)
            .unwrap();
        let first = engine.close_epoch(0).unwrap();
        let second = engine.close_epoch(0).unwrap();
        assert_eq!(first.rights_issued, second.rights_issued);
        assert_eq!(first.coupon_count, second.coupon_count);
    }

    #[test]
    fn work_for_closed_epoch_rejected() {
        let engine = RewardEngine::new();
        engine.close_epoch(0).unwrap();
        let err = engine
            .record_work(0, addr(1), WorkClass::ConsensusVote, 1)
            .unwrap_err();
        assert!(matches!(err, TokenError::InvalidParameter(_)));
    }

    #[test]
    fn zero_work_epoch_lapses_all_rights() {
        let engine = RewardEngine::new();
        let summary = engine.close_epoch(0).unwrap();
        assert_eq!(summary.matched, 0);
        assert_eq!(summary.expired_unmatched, summary.rights_issued);
        assert_eq!(summary.coupon_count, 0);
    }

    #[test]
    fn claim_splits_liquid_and_vesting() {
        let engine = RewardEngine::new();
        let provider = addr(9);
        engine
            .record_work(0, provider, WorkClass::InferenceServed, 1_000)
            .unwrap();
        engine.close_epoch(0).unwrap();
        let outcome = engine.claim(&provider, 1).unwrap();
        assert!(outcome.total > 0);
        assert_eq!(outcome.liquid + outcome.vesting, outcome.total);
        // 25% liquid default.
        let expected_liquid =
            outcome.total / 10_000 * 2500 + outcome.total % 10_000 * 2500 / 10_000;
        assert_eq!(outcome.liquid, expected_liquid);
        assert_eq!(outcome.epochs, vec![0]);
        // Second claim: nothing left.
        assert!(matches!(
            engine.claim(&provider, 1),
            Err(TokenError::NotFound(_))
        ));
        let state = engine.state_snapshot();
        assert_eq!(state.cumulative_claimed, outcome.total);
    }

    #[test]
    fn coupons_expire_past_claim_window() {
        let engine = RewardEngine::new();
        let provider = addr(7);
        engine
            .record_work(0, provider, WorkClass::RpcTraffic, 500)
            .unwrap();
        engine.close_epoch(0).unwrap();
        let issued = engine.coupons_for(&provider)[0].amount;
        // Claim attempted far past the window → coupon expires.
        let err = engine.claim(&provider, CLAIM_WINDOW_EPOCHS + 2).unwrap_err();
        assert!(matches!(err, TokenError::NotFound(_)));
        let coupons = engine.coupons_for(&provider);
        assert_eq!(coupons[0].status, CouponStatus::Expired);
        let state = engine.state_snapshot();
        assert!(state.cumulative_expired >= issued);
    }

    #[test]
    fn expiry_sweep_at_epoch_close() {
        let engine = RewardEngine::new();
        let provider = addr(5);
        engine
            .record_work(0, provider, WorkClass::InferenceServed, 10)
            .unwrap();
        engine.close_epoch(0).unwrap();
        let issued_amount = engine.coupons_for(&provider)[0].amount;
        // Closing an epoch past the window sweeps the stale coupon.
        let far = CLAIM_WINDOW_EPOCHS + 5;
        engine.close_epoch(far).unwrap();
        let coupons = engine.coupons_for(&provider);
        assert_eq!(
            coupons.iter().find(|c| c.epoch == 0).unwrap().status,
            CouponStatus::Expired
        );
        let state = engine.state_snapshot();
        assert!(state.cumulative_expired >= issued_amount);
    }

    #[test]
    fn cumulative_meter_deltas() {
        let engine = RewardEngine::new();
        let provider = addr(3);
        let d1 = engine
            .ingest_cumulative(0, provider, WorkClass::InferenceServed, 1_000)
            .unwrap();
        assert_eq!(d1, 1_000);
        let d2 = engine
            .ingest_cumulative(0, provider, WorkClass::InferenceServed, 1_500)
            .unwrap();
        assert_eq!(d2, 500);
        // Backwards meter: no credit, meter resets.
        let d3 = engine
            .ingest_cumulative(0, provider, WorkClass::InferenceServed, 200)
            .unwrap();
        assert_eq!(d3, 0);
        let d4 = engine
            .ingest_cumulative(0, provider, WorkClass::InferenceServed, 300)
            .unwrap();
        assert_eq!(d4, 100);
    }

    #[test]
    fn pro_rata_handles_large_weights() {
        // Weights beyond u64 range still divide without overflow.
        let rights = 60_000_000 * ONE_TNZO / 365;
        let big = u128::from(u64::MAX) * 16;
        let share = pro_rata(rights, big / 2, big);
        assert!(share > 0);
        assert!(share <= rights);
        // Half the weight yields about half the rights.
        let expected = rights / 2;
        let diff = expected.abs_diff(share);
        assert!(diff < rights / 1_000);
    }

    #[test]
    fn pro_rata_dust_never_exceeds_rights() {
        let rights = 1_000_003;
        let total = pro_rata(rights, 3, 7) + pro_rata(rights, 2, 7) + pro_rata(rights, 2, 7);
        assert!(total <= rights);
    }

    #[test]
    fn meter_key_roundtrip() {
        let a = addr(0xAB);
        let key = meter_key(&a, WorkClass::RpcTraffic);
        let (parsed_addr, parsed_class) = parse_meter_key(&key).unwrap();
        assert_eq!(parsed_addr, a);
        assert_eq!(parsed_class, WorkClass::RpcTraffic);
    }

    #[test]
    fn epoch_suffix_roundtrip() {
        let key = pending_key(42);
        assert_eq!(parse_epoch_suffix(&key, REWARD_PENDING_PREFIX), Some(42));
    }
}
