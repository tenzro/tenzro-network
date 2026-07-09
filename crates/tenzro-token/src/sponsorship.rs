//! Foundation sponsorship program (tokenomics economic model §6).
//!
//! Qualifying hardware operators join as T2 validators / AI providers
//! (10,000 TNZO) or T3 RPC providers (100,000 TNZO) without buying TNZO:
//! the foundation delegates the tier minimum from a 100M revolving pool.
//! The delegation is foundation-owned and revocable — never the
//! operator's property. The operator posts a junior bond (5% of the tier
//! minimum) which is slashed first, before vesting balances and before
//! any owned stake; foundation stake is senior and is revoked, not
//! slashed, on operator fault.
//!
//! Graduation: 100% of the operator's earned rewards convert to
//! self-owned stake (no liquid portion while sponsored). When self-owned
//! stake reaches the tier minimum the slot graduates and the delegation
//! returns to the pool. Slots expire at 24 months if not graduated;
//! expiry withdraws the delegation and the operator keeps all self-owned
//! stake.
//!
//! Concentration limits are percentage-based and adaptive — never fixed
//! region lists (the network is permissionless and topology-free):
//! - ≤ 5% of active sponsored slots per controller DID (min 1),
//! - ≤ 15% of active sponsored slots per ASN/datacenter (min 1),
//! - sponsored stake in aggregate ≤ 33% of total network stake.
//!
//! Application review (hardware attestation, jurisdiction, DID history)
//! happens off-chain at the foundation; this module owns the on-chain
//! accounting from delegation onward. The [`SeedAgentEarmarkManager`]
//! (crate::seed_agent) is the structural template.
//!
//! Storage layout (`CF_TOKENS`):
//! - `sponsor_pool:singleton` → JSON-encoded [`SponsorshipPool`].
//! - `sponsor_slot:<operator_did>` → JSON-encoded [`SponsorshipSlot`].
//!
//! All TNZO amounts are 18-decimal base units.

use crate::error::{Result, TokenError};
use crate::rewards::ONE_TNZO;
use crate::vesting::DAY_MILLIS;
use dashmap::DashMap;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_storage::{KvStore, WriteOp, CF_TOKENS};
use tenzro_types::primitives::{Address, Timestamp};
use tracing::{info, warn};

/// Storage key for the singleton [`SponsorshipPool`] under `CF_TOKENS`.
pub const SPONSOR_POOL_KEY: &[u8] = b"sponsor_pool:singleton";
/// Prefix for per-operator slots: `sponsor_slot:<operator_did>`.
pub const SPONSOR_SLOT_PREFIX: &[u8] = b"sponsor_slot:";

/// Revolving sponsorship pool: 100M TNZO (10% of supply).
pub const SPONSORSHIP_POOL: u128 = 100_000_000 * ONE_TNZO;
/// T2 (validator / AI provider) delegation — the tier minimum.
pub const T2_DELEGATION: u128 = 10_000 * ONE_TNZO;
/// T3 (RPC provider) delegation — the tier minimum.
pub const T3_DELEGATION: u128 = 100_000 * ONE_TNZO;
/// T2 junior bond: 5% of the tier minimum.
pub const T2_JUNIOR_BOND: u128 = 500 * ONE_TNZO;
/// T3 junior bond: 5% of the tier minimum.
pub const T3_JUNIOR_BOND: u128 = 5_000 * ONE_TNZO;

/// Max share of active sponsored slots per controller DID (bps).
pub const MAX_CONTROLLER_SLOT_BPS: u32 = 500;
/// Max share of active sponsored slots per ASN/datacenter (bps).
pub const MAX_ASN_SLOT_BPS: u32 = 1500;
/// Max sponsored stake as a share of total network stake (bps).
pub const MAX_SPONSORED_STAKE_BPS: u32 = 3300;

/// Slot lifetime: 24 months (730 days).
pub const SLOT_EXPIRY_MS: i64 = 730 * DAY_MILLIS;
/// Re-application bar after revocation: 12 months.
pub const REAPPLICATION_BAR_MS: i64 = 365 * DAY_MILLIS;

/// Which program track a slot belongs to. Validator and AI/TEE provider
/// share the T2 economics; RPC providers are T3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SponsorshipTrack {
    /// T2 consensus validator.
    Validator,
    /// T2 AI / TEE provider.
    AiProvider,
    /// T3 RPC provider.
    RpcProvider,
}

impl SponsorshipTrack {
    pub fn as_key(&self) -> &'static str {
        match self {
            SponsorshipTrack::Validator => "validator",
            SponsorshipTrack::AiProvider => "ai_provider",
            SponsorshipTrack::RpcProvider => "rpc_provider",
        }
    }

    /// Foundation delegation = the tier minimum for the track.
    pub fn delegation_amount(&self) -> u128 {
        match self {
            SponsorshipTrack::Validator | SponsorshipTrack::AiProvider => T2_DELEGATION,
            SponsorshipTrack::RpcProvider => T3_DELEGATION,
        }
    }

    /// Required junior bond (5% of the tier minimum).
    pub fn junior_bond(&self) -> u128 {
        match self {
            SponsorshipTrack::Validator | SponsorshipTrack::AiProvider => T2_JUNIOR_BOND,
            SponsorshipTrack::RpcProvider => T3_JUNIOR_BOND,
        }
    }
}

/// Slot lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SponsorshipStatus {
    /// Delegation live, operator earning; rewards convert to stake.
    Active,
    /// Self-owned stake reached the tier minimum; delegation returned.
    Graduated,
    /// 24-month lifetime elapsed without graduation; delegation returned.
    Expired,
    /// Foundation withdrew the delegation on operator fault.
    Revoked,
}

/// Why a slot was revoked (economic model §6.2 / campaign brief §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RevocationReason {
    /// Consensus equivocation.
    Equivocation,
    /// Transaction censorship (T3).
    Censorship,
    /// No verified work units for 30 consecutive epochs.
    NonParticipation,
    /// Hardware attestation failed on re-check.
    AttestationFailure,
    /// Concentration-cap breach discovered post-admission.
    ConcentrationBreach,
}

impl RevocationReason {
    pub fn as_key(&self) -> &'static str {
        match self {
            RevocationReason::Equivocation => "equivocation",
            RevocationReason::Censorship => "censorship",
            RevocationReason::NonParticipation => "non_participation",
            RevocationReason::AttestationFailure => "attestation_failure",
            RevocationReason::ConcentrationBreach => "concentration_breach",
        }
    }
}

/// The revolving pool singleton. Delegations return on graduation,
/// expiry, and revocation — the pool is not an expense line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SponsorshipPool {
    /// Pool size (100M TNZO).
    pub total: u128,
    /// Currently delegated to active slots.
    pub delegated_outstanding: u128,
    /// Lifetime delegated (monotone).
    pub cumulative_delegated: u128,
    /// Lifetime returned via graduation/expiry/revocation (monotone).
    pub cumulative_returned: u128,
    /// Master switch — governance can pause new delegations.
    pub enabled: bool,
}

impl Default for SponsorshipPool {
    fn default() -> Self {
        Self {
            total: SPONSORSHIP_POOL,
            delegated_outstanding: 0,
            cumulative_delegated: 0,
            cumulative_returned: 0,
            enabled: true,
        }
    }
}

impl SponsorshipPool {
    /// Undelegated pool capacity.
    pub fn remaining(&self) -> u128 {
        self.total.saturating_sub(self.delegated_outstanding)
    }
}

/// Per-operator sponsorship record. One record per operator DID; a new
/// delegation for a DID whose prior slot has terminated replaces the
/// record (pre-launch flag-day policy — no history table).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SponsorshipSlot {
    /// Operator's TDIP DID (storage key).
    pub operator_did: String,
    /// Controller DID for the concentration cap (may equal the
    /// operator DID for self-controlled operators).
    pub controller_did: String,
    /// Reward/stake address of the operator's node.
    pub operator_address: Address,
    pub track: SponsorshipTrack,
    /// Foundation delegation satisfying the tier minimum.
    pub delegation_amount: u128,
    /// Junior bond posted at admission.
    pub junior_bond_posted: u128,
    /// Bond remaining after slashing (slashed first, before vesting and
    /// owned stake).
    pub junior_bond_remaining: u128,
    /// Self-owned stake accrued from converted rewards. Graduation at
    /// `>= delegation_amount`.
    pub self_owned_stake: u128,
    /// ASN / datacenter identifier from the application, when known.
    pub asn: Option<String>,
    pub status: SponsorshipStatus,
    pub started_at: Timestamp,
    /// `started_at + 24 months`.
    pub expires_at: Timestamp,
    /// Set on graduation / expiry / revocation.
    pub terminated_at: Option<Timestamp>,
    /// Set on revocation; drives the 12-month re-application bar.
    pub revocation_reason: Option<RevocationReason>,
}

/// Outcome of a reward-to-stake conversion.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversionOutcome {
    /// Amount converted in this call.
    pub converted: u128,
    /// Operator's self-owned stake after conversion.
    pub self_owned_stake: u128,
    /// True when this conversion crossed the tier minimum and the slot
    /// graduated (delegation returned to the pool).
    pub graduated: bool,
}

/// Owns the pool singleton + per-operator slots with optional RocksDB
/// write-through.
pub struct SponsorshipManager {
    pool: RwLock<SponsorshipPool>,
    slots: DashMap<String, SponsorshipSlot>,
    storage: Option<Arc<dyn KvStore>>,
}

impl SponsorshipManager {
    /// In-memory manager (tests, storage-less nodes).
    pub fn new() -> Self {
        Self {
            pool: RwLock::new(SponsorshipPool::default()),
            slots: DashMap::new(),
            storage: None,
        }
    }

    /// Manager with RocksDB write-through. Hydrates the pool singleton
    /// and all slots from `CF_TOKENS`; unreadable records are dropped
    /// and deleted (pre-launch flag-day policy).
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self> {
        let pool = storage
            .get(CF_TOKENS, SPONSOR_POOL_KEY)?
            .and_then(|bytes| serde_json::from_slice::<SponsorshipPool>(&bytes).ok())
            .unwrap_or_default();

        let slots: DashMap<String, SponsorshipSlot> = DashMap::new();
        let mut drops: Vec<WriteOp> = Vec::new();
        for key in storage.get_keys_with_prefix(CF_TOKENS, SPONSOR_SLOT_PREFIX)? {
            let parsed = storage
                .get(CF_TOKENS, &key)?
                .and_then(|bytes| serde_json::from_slice::<SponsorshipSlot>(&bytes).ok());
            match parsed {
                Some(slot) => {
                    slots.insert(slot.operator_did.clone(), slot);
                }
                None => {
                    warn!(
                        key = %String::from_utf8_lossy(&key),
                        "dropping unreadable sponsorship slot"
                    );
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
        info!(slots = slots.len(), "sponsorship manager hydrated");

        Ok(Self {
            pool: RwLock::new(pool),
            slots,
            storage: Some(storage),
        })
    }

    /// Delegate the tier minimum to an approved operator. Called after
    /// off-chain foundation review; enforces every on-chain admission
    /// invariant: pool enabled + capacity, bond sufficiency, one active
    /// slot per operator DID, the 12-month re-application bar, and the
    /// three adaptive concentration caps. `total_network_stake` is the
    /// current total network stake *excluding* this new delegation.
    #[allow(clippy::too_many_arguments)]
    pub fn delegate(
        &self,
        operator_did: &str,
        controller_did: &str,
        operator_address: Address,
        track: SponsorshipTrack,
        junior_bond: u128,
        asn: Option<String>,
        total_network_stake: u128,
        now: Timestamp,
    ) -> Result<SponsorshipSlot> {
        if operator_did.is_empty() || controller_did.is_empty() {
            return Err(TokenError::InvalidParameter(
                "operator and controller DIDs are required".to_string(),
            ));
        }
        let required_bond = track.junior_bond();
        if junior_bond < required_bond {
            return Err(TokenError::InvalidAmount(format!(
                "junior bond {} below required {} for track {}",
                junior_bond,
                required_bond,
                track.as_key()
            )));
        }

        // Prior-slot checks: never two live delegations per DID; revoked
        // operators wait 12 months.
        if let Some(existing) = self.slots.get(operator_did) {
            match existing.status {
                SponsorshipStatus::Active => {
                    return Err(TokenError::InvalidParameter(format!(
                        "operator {operator_did} already holds an active sponsored slot"
                    )));
                }
                SponsorshipStatus::Revoked => {
                    let barred_until = existing
                        .terminated_at
                        .map(|t| t.as_millis().saturating_add(REAPPLICATION_BAR_MS))
                        .unwrap_or(i64::MAX);
                    if now.as_millis() < barred_until {
                        return Err(TokenError::Unauthorized {
                            reason: format!(
                                "operator {operator_did} was revoked; re-application barred until {barred_until}"
                            ),
                        });
                    }
                }
                SponsorshipStatus::Graduated | SponsorshipStatus::Expired => {}
            }
        }

        let amount = track.delegation_amount();
        let active: Vec<SponsorshipSlot> = self
            .slots
            .iter()
            .filter(|e| e.value().status == SponsorshipStatus::Active)
            .map(|e| e.value().clone())
            .collect();
        let total_after = active.len() as u64 + 1;

        // Controller cap: ≤ 5% of active sponsored slots, min 1.
        let controller_after = active
            .iter()
            .filter(|s| s.controller_did == controller_did)
            .count() as u64
            + 1;
        let controller_allowed =
            1u64.max(total_after * MAX_CONTROLLER_SLOT_BPS as u64 / 10_000);
        if controller_after > controller_allowed {
            return Err(TokenError::Unauthorized {
                reason: format!(
                    "controller {controller_did} would hold {controller_after} of {total_after} sponsored slots (cap {controller_allowed})"
                ),
            });
        }

        // ASN cap: ≤ 15% of active sponsored slots, min 1 (when known).
        if let Some(asn_id) = asn.as_deref() {
            let asn_after = active
                .iter()
                .filter(|s| s.asn.as_deref() == Some(asn_id))
                .count() as u64
                + 1;
            let asn_allowed = 1u64.max(total_after * MAX_ASN_SLOT_BPS as u64 / 10_000);
            if asn_after > asn_allowed {
                return Err(TokenError::Unauthorized {
                    reason: format!(
                        "ASN {asn_id} would host {asn_after} of {total_after} sponsored slots (cap {asn_allowed})"
                    ),
                });
            }
        }

        {
            let mut pool = self.pool.write();
            if !pool.enabled {
                return Err(TokenError::Unauthorized {
                    reason: "sponsorship pool is disabled".to_string(),
                });
            }
            if pool.remaining() < amount {
                return Err(TokenError::InvalidAmount(format!(
                    "sponsorship pool exhausted: {} remaining, {} required",
                    pool.remaining(),
                    amount
                )));
            }

            // Aggregate cap: sponsored stake ≤ 33% of post-delegation
            // total network stake. bps decomposition avoids overflow.
            let sponsored_after = pool.delegated_outstanding.saturating_add(amount);
            let network_after = total_network_stake.saturating_add(amount);
            let cap = network_after / 10_000 * MAX_SPONSORED_STAKE_BPS as u128
                + network_after % 10_000 * MAX_SPONSORED_STAKE_BPS as u128 / 10_000;
            if sponsored_after > cap {
                return Err(TokenError::InvalidAmount(format!(
                    "aggregate sponsored stake {sponsored_after} would exceed 33% of total network stake"
                )));
            }

            pool.delegated_outstanding = sponsored_after;
            pool.cumulative_delegated = pool.cumulative_delegated.saturating_add(amount);
        }

        let slot = SponsorshipSlot {
            operator_did: operator_did.to_string(),
            controller_did: controller_did.to_string(),
            operator_address,
            track,
            delegation_amount: amount,
            junior_bond_posted: junior_bond,
            junior_bond_remaining: junior_bond,
            self_owned_stake: 0,
            asn,
            status: SponsorshipStatus::Active,
            started_at: now,
            expires_at: Timestamp::new(now.as_millis().saturating_add(SLOT_EXPIRY_MS)),
            terminated_at: None,
            revocation_reason: None,
        };
        self.slots.insert(operator_did.to_string(), slot.clone());
        self.persist_pool()?;
        self.persist_slot(&slot)?;

        info!(
            operator = operator_did,
            track = track.as_key(),
            amount,
            "sponsorship delegation issued"
        );
        Ok(slot)
    }

    /// Convert an operator's claimed reward into self-owned stake (100%
    /// of rewards while sponsored — no liquid portion). Graduates the
    /// slot and returns the delegation to the pool once self-owned stake
    /// reaches the tier minimum.
    pub fn convert_reward_to_stake(
        &self,
        operator_did: &str,
        amount: u128,
    ) -> Result<ConversionOutcome> {
        if amount == 0 {
            return Err(TokenError::InvalidAmount(
                "conversion amount must be non-zero".to_string(),
            ));
        }
        let mut slot = self.active_slot_mut(operator_did)?;
        slot.self_owned_stake = slot.self_owned_stake.saturating_add(amount);

        let graduated = slot.self_owned_stake >= slot.delegation_amount;
        if graduated {
            slot.status = SponsorshipStatus::Graduated;
            slot.terminated_at = Some(Timestamp::now());
        }
        let snapshot = slot.clone();
        drop(slot);

        if graduated {
            self.return_delegation(snapshot.delegation_amount)?;
            info!(
                operator = operator_did,
                self_stake = snapshot.self_owned_stake,
                "sponsored slot graduated; delegation returned to pool"
            );
        }
        self.persist_slot(&snapshot)?;
        Ok(ConversionOutcome {
            converted: amount,
            self_owned_stake: snapshot.self_owned_stake,
            graduated,
        })
    }

    /// Consume up to `amount` from the operator's junior bond — the
    /// first stop in the slashing order (bond → vesting → owned stake).
    /// Returns the amount actually consumed.
    pub fn slash_bond(&self, operator_did: &str, amount: u128) -> Result<u128> {
        if amount == 0 {
            return Ok(0);
        }
        let mut slot = self.active_slot_mut(operator_did)?;
        let consumed = slot.junior_bond_remaining.min(amount);
        slot.junior_bond_remaining -= consumed;
        let snapshot = slot.clone();
        drop(slot);

        if consumed > 0 {
            self.persist_slot(&snapshot)?;
            warn!(operator = operator_did, consumed, "junior bond slashed");
        }
        Ok(consumed)
    }

    /// Revoke a slot on operator fault. The delegation is withdrawn to
    /// the pool (revoked, not slashed — foundation stake is senior); the
    /// operator keeps self-owned stake and is barred from re-application
    /// for 12 months.
    pub fn revoke(
        &self,
        operator_did: &str,
        reason: RevocationReason,
        now: Timestamp,
    ) -> Result<SponsorshipSlot> {
        let mut slot = self.active_slot_mut(operator_did)?;
        slot.status = SponsorshipStatus::Revoked;
        slot.terminated_at = Some(now);
        slot.revocation_reason = Some(reason);
        let snapshot = slot.clone();
        drop(slot);

        self.return_delegation(snapshot.delegation_amount)?;
        self.persist_slot(&snapshot)?;
        warn!(
            operator = operator_did,
            reason = reason.as_key(),
            "sponsorship revoked; delegation returned to pool"
        );
        Ok(snapshot)
    }

    /// Sweep slots whose 24-month lifetime elapsed without graduation:
    /// mark Expired and return the delegations. Returns the expired
    /// slots so the caller can withdraw the registry-side stake.
    pub fn expire_due(&self, now: Timestamp) -> Result<Vec<SponsorshipSlot>> {
        let due: Vec<String> = self
            .slots
            .iter()
            .filter(|e| {
                e.value().status == SponsorshipStatus::Active
                    && now.as_millis() >= e.value().expires_at.as_millis()
            })
            .map(|e| e.key().clone())
            .collect();

        let mut expired = Vec::with_capacity(due.len());
        for did in due {
            let Some(mut slot) = self.slots.get_mut(&did) else {
                continue;
            };
            slot.status = SponsorshipStatus::Expired;
            slot.terminated_at = Some(now);
            let snapshot = slot.clone();
            drop(slot);

            self.return_delegation(snapshot.delegation_amount)?;
            self.persist_slot(&snapshot)?;
            info!(
                operator = %snapshot.operator_did,
                "sponsored slot expired; delegation returned to pool"
            );
            expired.push(snapshot);
        }
        Ok(expired)
    }

    /// Pool snapshot.
    pub fn pool_snapshot(&self) -> SponsorshipPool {
        self.pool.read().clone()
    }

    /// Enable or disable new delegations (governance switch). Existing
    /// slots are unaffected.
    pub fn set_enabled(&self, enabled: bool) -> Result<()> {
        self.pool.write().enabled = enabled;
        self.persist_pool()?;
        info!(enabled, "sponsorship pool switch updated");
        Ok(())
    }

    /// Slot by operator DID.
    pub fn get_slot(&self, operator_did: &str) -> Option<SponsorshipSlot> {
        self.slots.get(operator_did).map(|e| e.value().clone())
    }

    /// All slots (every status).
    pub fn list_slots(&self) -> Vec<SponsorshipSlot> {
        self.slots.iter().map(|e| e.value().clone()).collect()
    }

    /// Active slot for a reward address, if any — the reward-claim path
    /// uses this to route 100% of a sponsored operator's claim into
    /// [`Self::convert_reward_to_stake`] instead of mint + vesting.
    pub fn active_slot_for_address(&self, address: &Address) -> Option<SponsorshipSlot> {
        self.slots
            .iter()
            .find(|e| {
                e.value().status == SponsorshipStatus::Active
                    && e.value().operator_address == *address
            })
            .map(|e| e.value().clone())
    }

    fn active_slot_mut(
        &self,
        operator_did: &str,
    ) -> Result<dashmap::mapref::one::RefMut<'_, String, SponsorshipSlot>> {
        let slot = self.slots.get_mut(operator_did).ok_or_else(|| {
            TokenError::NotFound(format!("no sponsorship slot for {operator_did}"))
        })?;
        if slot.status != SponsorshipStatus::Active {
            return Err(TokenError::InvalidParameter(format!(
                "sponsorship slot for {operator_did} is not active"
            )));
        }
        Ok(slot)
    }

    fn return_delegation(&self, amount: u128) -> Result<()> {
        {
            let mut pool = self.pool.write();
            pool.delegated_outstanding = pool.delegated_outstanding.saturating_sub(amount);
            pool.cumulative_returned = pool.cumulative_returned.saturating_add(amount);
        }
        self.persist_pool()
    }

    fn persist_pool(&self) -> Result<()> {
        if let Some(storage) = &self.storage {
            let pool = self.pool.read().clone();
            storage.write_batch_sync(vec![WriteOp::Put {
                cf: CF_TOKENS.to_string(),
                key: SPONSOR_POOL_KEY.to_vec(),
                value: serde_json::to_vec(&pool)
                    .map_err(|e| TokenError::StorageError(e.to_string()))?,
            }])?;
        }
        Ok(())
    }

    fn persist_slot(&self, slot: &SponsorshipSlot) -> Result<()> {
        if let Some(storage) = &self.storage {
            let mut key = SPONSOR_SLOT_PREFIX.to_vec();
            key.extend_from_slice(slot.operator_did.as_bytes());
            storage.write_batch_sync(vec![WriteOp::Put {
                cf: CF_TOKENS.to_string(),
                key,
                value: serde_json::to_vec(slot)
                    .map_err(|e| TokenError::StorageError(e.to_string()))?,
            }])?;
        }
        Ok(())
    }
}

impl Default for SponsorshipManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(byte: u8) -> Address {
        Address::new([byte; 32])
    }

    /// Large enough network stake that the 33% aggregate cap never
    /// interferes with unrelated test scenarios.
    const BIG_STAKE: u128 = 1_000_000_000 * ONE_TNZO;

    fn delegate_ok(m: &SponsorshipManager, i: u8, track: SponsorshipTrack) -> SponsorshipSlot {
        m.delegate(
            &format!("did:tenzro:machine:op-{i}"),
            &format!("did:tenzro:human:ctl-{i}"),
            addr(i),
            track,
            track.junior_bond(),
            None,
            BIG_STAKE,
            Timestamp::new(0),
        )
        .expect("delegate")
    }

    #[test]
    fn delegate_happy_path_updates_pool() {
        let m = SponsorshipManager::new();
        let slot = delegate_ok(&m, 1, SponsorshipTrack::Validator);
        assert_eq!(slot.delegation_amount, T2_DELEGATION);
        assert_eq!(slot.junior_bond_remaining, T2_JUNIOR_BOND);
        assert_eq!(slot.status, SponsorshipStatus::Active);
        assert_eq!(slot.expires_at.as_millis(), SLOT_EXPIRY_MS);

        let pool = m.pool_snapshot();
        assert_eq!(pool.delegated_outstanding, T2_DELEGATION);
        assert_eq!(pool.cumulative_delegated, T2_DELEGATION);
        assert_eq!(pool.remaining(), SPONSORSHIP_POOL - T2_DELEGATION);
    }

    #[test]
    fn t3_track_amounts() {
        let m = SponsorshipManager::new();
        let slot = delegate_ok(&m, 2, SponsorshipTrack::RpcProvider);
        assert_eq!(slot.delegation_amount, T3_DELEGATION);
        assert_eq!(slot.junior_bond_posted, T3_JUNIOR_BOND);
    }

    #[test]
    fn insufficient_bond_rejected() {
        let m = SponsorshipManager::new();
        let err = m.delegate(
            "did:tenzro:machine:op",
            "did:tenzro:human:ctl",
            addr(3),
            SponsorshipTrack::Validator,
            T2_JUNIOR_BOND - 1,
            None,
            BIG_STAKE,
            Timestamp::new(0),
        );
        assert!(matches!(err, Err(TokenError::InvalidAmount(_))));
    }

    #[test]
    fn duplicate_active_slot_rejected() {
        let m = SponsorshipManager::new();
        delegate_ok(&m, 4, SponsorshipTrack::Validator);
        let err = m.delegate(
            "did:tenzro:machine:op-4",
            "did:tenzro:human:other",
            addr(40),
            SponsorshipTrack::Validator,
            T2_JUNIOR_BOND,
            None,
            BIG_STAKE,
            Timestamp::new(0),
        );
        assert!(matches!(err, Err(TokenError::InvalidParameter(_))));
    }

    #[test]
    fn controller_cap_adaptive() {
        let m = SponsorshipManager::new();
        // Seed 20 active slots under distinct controllers.
        for i in 1..=20u8 {
            delegate_ok(&m, i, SponsorshipTrack::Validator);
        }
        // Controller ctl-1 already holds 1 of 20; a second slot would be
        // 2 of 21 against an allowance of max(1, 21*5%) = 1.
        let err = m.delegate(
            "did:tenzro:machine:op-21",
            "did:tenzro:human:ctl-1",
            addr(21),
            SponsorshipTrack::Validator,
            T2_JUNIOR_BOND,
            None,
            BIG_STAKE,
            Timestamp::new(0),
        );
        assert!(matches!(err, Err(TokenError::Unauthorized { .. })));
    }

    #[test]
    fn asn_cap_adaptive() {
        let m = SponsorshipManager::new();
        // 10 slots, 2 already in AS64500 (2 of 10 ≤ ... we seed so the
        // next AS64500 slot breaches: allowance at 11 slots is
        // max(1, 11*15%) = 1, so a second AS64500 slot must reject.
        for i in 1..=10u8 {
            let asn = if i == 1 { Some("AS64500".to_string()) } else { None };
            m.delegate(
                &format!("did:tenzro:machine:op-{i}"),
                &format!("did:tenzro:human:ctl-{i}"),
                addr(i),
                SponsorshipTrack::Validator,
                T2_JUNIOR_BOND,
                asn,
                BIG_STAKE,
                Timestamp::new(0),
            )
            .expect("seed");
        }
        let err = m.delegate(
            "did:tenzro:machine:op-11",
            "did:tenzro:human:ctl-11",
            addr(11),
            SponsorshipTrack::Validator,
            T2_JUNIOR_BOND,
            Some("AS64500".to_string()),
            BIG_STAKE,
            Timestamp::new(0),
        );
        assert!(matches!(err, Err(TokenError::Unauthorized { .. })));
    }

    #[test]
    fn aggregate_stake_cap() {
        let m = SponsorshipManager::new();
        // Network stake so small that even one T2 delegation exceeds
        // 33% of the post-delegation total.
        let err = m.delegate(
            "did:tenzro:machine:op",
            "did:tenzro:human:ctl",
            addr(5),
            SponsorshipTrack::Validator,
            T2_JUNIOR_BOND,
            None,
            T2_DELEGATION, // total: 20k after; 10k > 33% of 20k
            Timestamp::new(0),
        );
        assert!(matches!(err, Err(TokenError::InvalidAmount(_))));

        // With enough surrounding stake the same delegation admits.
        m.delegate(
            "did:tenzro:machine:op",
            "did:tenzro:human:ctl",
            addr(5),
            SponsorshipTrack::Validator,
            T2_JUNIOR_BOND,
            None,
            T2_DELEGATION * 10,
            Timestamp::new(0),
        )
        .expect("admits with stake context");
    }

    #[test]
    fn disabled_pool_rejects() {
        let m = SponsorshipManager::new();
        m.set_enabled(false).expect("disable");
        let err = m.delegate(
            "did:tenzro:machine:op",
            "did:tenzro:human:ctl",
            addr(6),
            SponsorshipTrack::Validator,
            T2_JUNIOR_BOND,
            None,
            BIG_STAKE,
            Timestamp::new(0),
        );
        assert!(matches!(err, Err(TokenError::Unauthorized { .. })));
    }

    #[test]
    fn conversion_accrues_and_graduates() {
        let m = SponsorshipManager::new();
        delegate_ok(&m, 7, SponsorshipTrack::Validator);
        let did = "did:tenzro:machine:op-7";

        let out = m
            .convert_reward_to_stake(did, T2_DELEGATION / 2)
            .expect("half");
        assert!(!out.graduated);
        assert_eq!(out.self_owned_stake, T2_DELEGATION / 2);

        let out = m
            .convert_reward_to_stake(did, T2_DELEGATION / 2)
            .expect("rest");
        assert!(out.graduated);
        assert_eq!(
            m.get_slot(did).expect("slot").status,
            SponsorshipStatus::Graduated
        );
        // Delegation returned to the revolving pool.
        let pool = m.pool_snapshot();
        assert_eq!(pool.delegated_outstanding, 0);
        assert_eq!(pool.cumulative_returned, T2_DELEGATION);

        // Terminated slots reject further conversion.
        assert!(matches!(
            m.convert_reward_to_stake(did, 1),
            Err(TokenError::InvalidParameter(_))
        ));
    }

    #[test]
    fn bond_slash_consumes_bond_first() {
        let m = SponsorshipManager::new();
        delegate_ok(&m, 8, SponsorshipTrack::Validator);
        let did = "did:tenzro:machine:op-8";

        let consumed = m.slash_bond(did, T2_JUNIOR_BOND / 2).expect("half");
        assert_eq!(consumed, T2_JUNIOR_BOND / 2);
        // Over-slash consumes only the remainder; caller continues to
        // vesting, then owned stake.
        let consumed = m.slash_bond(did, T2_JUNIOR_BOND).expect("over");
        assert_eq!(consumed, T2_JUNIOR_BOND / 2);
        assert_eq!(
            m.get_slot(did).expect("slot").junior_bond_remaining,
            0
        );
        assert_eq!(m.slash_bond(did, 100).expect("empty"), 0);
    }

    #[test]
    fn revoke_returns_delegation_and_bars_reapplication() {
        let m = SponsorshipManager::new();
        delegate_ok(&m, 9, SponsorshipTrack::Validator);
        let did = "did:tenzro:machine:op-9";

        let slot = m
            .revoke(did, RevocationReason::Equivocation, Timestamp::new(1_000))
            .expect("revoke");
        assert_eq!(slot.status, SponsorshipStatus::Revoked);
        assert_eq!(m.pool_snapshot().delegated_outstanding, 0);

        // Within the 12-month bar: rejected.
        let err = m.delegate(
            did,
            "did:tenzro:human:ctl-9",
            addr(9),
            SponsorshipTrack::Validator,
            T2_JUNIOR_BOND,
            None,
            BIG_STAKE,
            Timestamp::new(1_000 + REAPPLICATION_BAR_MS - 1),
        );
        assert!(matches!(err, Err(TokenError::Unauthorized { .. })));

        // After the bar: admitted again.
        m.delegate(
            did,
            "did:tenzro:human:ctl-9",
            addr(9),
            SponsorshipTrack::Validator,
            T2_JUNIOR_BOND,
            None,
            BIG_STAKE,
            Timestamp::new(1_000 + REAPPLICATION_BAR_MS),
        )
        .expect("re-admitted after bar");
    }

    #[test]
    fn expiry_sweep() {
        let m = SponsorshipManager::new();
        delegate_ok(&m, 10, SponsorshipTrack::Validator);
        delegate_ok(&m, 11, SponsorshipTrack::RpcProvider);

        // Nothing due before the lifetime elapses.
        assert!(m
            .expire_due(Timestamp::new(SLOT_EXPIRY_MS - 1))
            .expect("early")
            .is_empty());

        let expired = m
            .expire_due(Timestamp::new(SLOT_EXPIRY_MS))
            .expect("sweep");
        assert_eq!(expired.len(), 2);
        assert!(expired
            .iter()
            .all(|s| s.status == SponsorshipStatus::Expired));
        assert_eq!(m.pool_snapshot().delegated_outstanding, 0);
        assert_eq!(
            m.pool_snapshot().cumulative_returned,
            T2_DELEGATION + T3_DELEGATION
        );
    }

    #[test]
    fn active_slot_lookup_by_address() {
        let m = SponsorshipManager::new();
        delegate_ok(&m, 12, SponsorshipTrack::AiProvider);
        let found = m.active_slot_for_address(&addr(12)).expect("found");
        assert_eq!(found.operator_did, "did:tenzro:machine:op-12");
        assert!(m.active_slot_for_address(&addr(99)).is_none());
    }
}
