//! Per-byte storage metering and per-epoch payment (D4).
//!
//! Storage is billed like a rental (TOKENOMICS §9): a renter pre-funds a
//! deposit, the price of one storage epoch is `size_bytes × rate_per_byte_epoch`,
//! and that slice streams to the provider each epoch **only when the provider
//! passes a retrievability challenge** for the object. A failed challenge is a
//! *miss*: the renter is not charged for that epoch. Repeated misses are the
//! signal the consensus/settlement layer uses to slash the provider's stake and
//! re-replicate the object elsewhere.
//!
//! This module owns the pricing and the per-epoch charge loop. It deliberately
//! does **not** own slashing — that stays with the staking subsystem, reached
//! through the same `StakeLedger`-style indirection used by
//! `tenzro_settlement::rental`. Here we only move renter→provider value out of
//! the shared deposit balances when service is proven.

use crate::error::{Result, StorageProviderError};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_settlement::obligations::{ObligationSource, ProviderObligations};
use tenzro_settlement::rental::StakeLedger;
use tenzro_storage::{CF_SETTLEMENTS, KvStore};
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::{Address, Timestamp};
use tenzro_types::settlement::ServiceType;
use tracing::{debug, info, warn};

/// RocksDB key prefix for persisted storage deals (`CF_SETTLEMENTS`).
const STORAGE_DEAL_PREFIX: &[u8] = b"storage_deal:";

/// Pricing for stored bytes, in smallest TNZO units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoragePricing {
    /// Price to store one byte for one settlement epoch.
    pub rate_per_byte_epoch: u128,
}

impl StoragePricing {
    /// Creates a pricing schedule.
    pub fn new(rate_per_byte_epoch: u128) -> Self {
        Self {
            rate_per_byte_epoch,
        }
    }

    /// Price of one storage epoch for an object of `size_bytes`.
    pub fn epoch_price(&self, size_bytes: u64) -> u128 {
        self.rate_per_byte_epoch.saturating_mul(size_bytes as u128)
    }

    /// Builds the canonical `ServiceType::Storage` settlement descriptor for an
    /// object of `size_bytes` held for `duration_secs`.
    pub fn service_type(&self, size_bytes: u64, duration_secs: u64) -> ServiceType {
        ServiceType::Storage {
            data_size: size_bytes,
            duration: duration_secs,
        }
    }
}

/// Lifecycle of a metered storage agreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageDealStatus {
    /// Streaming: epochs charge to the provider as challenges pass.
    Active,
    /// All paid epochs delivered; deposit may have any unused remainder returned.
    Completed,
    /// Ended early — renter underfunded or object dropped after repeated misses.
    Terminated,
}

/// A metered storage agreement between a renter and a provider for one object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageDeal {
    /// Unique deal identifier.
    pub deal_id: String,
    /// Object being stored.
    pub object_id: String,
    /// Renter (payer) address.
    pub renter: Address,
    /// Provider (payee) address.
    pub provider: Address,
    /// Settlement asset (TNZO).
    pub asset_id: AssetId,
    /// Object size in bytes (the metered quantity).
    pub size_bytes: u64,
    /// Price of one storage epoch (`size_bytes × rate`), fixed at deal time.
    pub price_per_epoch: u128,
    /// Total epochs the renter pre-funded.
    pub total_epochs: u64,
    /// Epochs charged so far.
    pub epochs_charged: u64,
    /// Consecutive failed challenges since the last pass.
    pub consecutive_misses: u32,
    /// Creation time.
    pub created_at: Timestamp,
    /// Current status.
    pub status: StorageDealStatus,
}

impl StorageDeal {
    /// Value still locked for undelivered epochs.
    pub fn locked_remaining(&self) -> u128 {
        let remaining = self.total_epochs.saturating_sub(self.epochs_charged);
        self.price_per_epoch.saturating_mul(remaining as u128)
    }

    /// True once every funded epoch has been charged.
    pub fn is_complete(&self) -> bool {
        self.epochs_charged >= self.total_epochs
    }
}

/// Outcome of charging one storage epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChargeOutcome {
    /// Challenge passed: `slice` streamed renter → provider.
    Charged {
        /// Amount paid to the provider this epoch.
        slice: u128,
    },
    /// Challenge failed: no charge this epoch.
    Missed,
    /// Deal closed this tick.
    Closed {
        /// Whether the closure was a clean completion.
        completed: bool,
    },
}

/// Streaming per-epoch storage meter over a shared deposit balance map.
pub struct StorageMeter {
    /// Pricing schedule.
    pricing: StoragePricing,
    /// Deals by id.
    deals: DashMap<String, StorageDeal>,
    /// Per-provider index of deal ids (for exposure recomputation).
    deals_by_provider: DashMap<Address, Vec<String>>,
    /// Shared prepaid deposit balances (same convention as settlement escrow).
    balances: Arc<DashMap<(Address, AssetId), u128>>,
    /// Consecutive failed-challenge count that terminates a deal.
    miss_threshold: u32,
    /// Optional provider stake source. When set together with `obligations`,
    /// `open_deal` enforces that the provider's stake covers this storage
    /// exposure on top of everything already registered across services. When
    /// unset, deals are admitted on deposit alone (legacy behavior).
    stake_ledger: Option<Arc<dyn StakeLedger>>,
    /// Optional shared cross-service coverage tracker. When set, the meter
    /// publishes each provider's *storage* per-epoch exposure so a multi-role
    /// node's rentals admit against stake net of storage (and vice versa).
    obligations: Option<Arc<ProviderObligations>>,
    /// Optional durable backing store. When set, every deal open / charge /
    /// termination writes through to `CF_SETTLEMENTS` under `storage_deal:<id>`
    /// and the deal set is hydrated on construction via `with_storage`.
    storage: Option<Arc<dyn KvStore>>,
}

impl std::fmt::Debug for StorageMeter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageMeter")
            .field("pricing", &self.pricing)
            .field("deals", &self.deals.len())
            .field("miss_threshold", &self.miss_threshold)
            .field("coverage_enforced", &self.stake_ledger.is_some())
            .finish()
    }
}

impl StorageMeter {
    /// Creates a meter with the given pricing and miss threshold. No stake
    /// coverage enforcement — deals admit on deposit alone.
    pub fn new(
        pricing: StoragePricing,
        balances: Arc<DashMap<(Address, AssetId), u128>>,
        miss_threshold: u32,
    ) -> Self {
        Self {
            pricing,
            deals: DashMap::new(),
            deals_by_provider: DashMap::new(),
            balances,
            miss_threshold,
            stake_ledger: None,
            obligations: None,
            storage: None,
        }
    }

    /// Attaches a durable backing store and hydrates any persisted deals. Every
    /// subsequent open / charge / termination writes through to
    /// `CF_SETTLEMENTS` under `storage_deal:<id>`, so a provider survives a
    /// restart mid-deal without losing its billing state.
    pub fn with_storage(mut self, storage: Arc<dyn KvStore>) -> Self {
        let keys = storage
            .get_keys_with_prefix(CF_SETTLEMENTS, STORAGE_DEAL_PREFIX)
            .unwrap_or_default();
        let mut hydrated = 0usize;
        for key in keys {
            if let Ok(Some(bytes)) = storage.get(CF_SETTLEMENTS, &key)
                && let Ok(deal) = serde_json::from_slice::<StorageDeal>(&bytes)
            {
                self.deals_by_provider
                    .entry(deal.provider)
                    .or_default()
                    .push(deal.deal_id.clone());
                self.deals.insert(deal.deal_id.clone(), deal);
                hydrated += 1;
            }
        }
        if hydrated > 0 {
            info!("Hydrated {} storage deal(s) from persistence", hydrated);
        }
        self.storage = Some(storage);
        self
    }

    /// Writes a deal through to the backing store, if attached. Best-effort:
    /// a persistence failure is logged, never fatal to the in-memory charge.
    fn persist_deal(&self, deal: &StorageDeal) {
        if let Some(store) = &self.storage {
            let mut key = STORAGE_DEAL_PREFIX.to_vec();
            key.extend_from_slice(deal.deal_id.as_bytes());
            match serde_json::to_vec(deal) {
                Ok(bytes) => {
                    if let Err(e) = store.put(CF_SETTLEMENTS, &key, &bytes) {
                        warn!(deal_id = %deal.deal_id, error = %e, "Failed to persist storage deal");
                    }
                }
                Err(e) => {
                    warn!(deal_id = %deal.deal_id, error = %e, "Failed to serialize storage deal")
                }
            }
        }
    }

    /// Deal ids of every currently-active deal on this meter. The billing
    /// daemon walks these each epoch to run the retrievability charge.
    pub fn active_deal_ids(&self) -> Vec<String> {
        self.deals
            .iter()
            .filter(|d| d.value().status == StorageDealStatus::Active)
            .map(|d| d.key().clone())
            .collect()
    }

    /// Enables cross-service stake-coverage enforcement. After this, `open_deal`
    /// rejects a deal whose per-epoch exposure would push the provider's total
    /// obligations (storage + rentals) past its available stake, and the meter
    /// publishes storage exposure into the shared tracker.
    pub fn with_coverage(
        mut self,
        stake_ledger: Arc<dyn StakeLedger>,
        obligations: Arc<ProviderObligations>,
    ) -> Self {
        self.stake_ledger = Some(stake_ledger);
        self.obligations = Some(obligations);
        self
    }

    /// Sum of per-epoch exposure across a provider's currently-active deals.
    pub fn active_exposure(&self, provider: &Address) -> u128 {
        let ids = match self.deals_by_provider.get(provider) {
            Some(v) => v.value().clone(),
            None => return 0,
        };
        ids.iter()
            .filter_map(|id| self.deals.get(id))
            .filter(|d| d.value().status == StorageDealStatus::Active)
            .map(|d| d.value().price_per_epoch)
            .fold(0u128, |acc, e| acc.saturating_add(e))
    }

    /// Publishes the provider's current storage exposure into the shared
    /// tracker, if one is attached.
    fn publish_exposure(&self, provider: &Address) {
        if let Some(obs) = &self.obligations {
            obs.set(
                provider,
                ObligationSource::Storage,
                self.active_exposure(provider),
            );
        }
    }

    /// Opens a storage deal, locking the full pre-funded term from the renter's
    /// deposit. The per-epoch price is `size_bytes × rate`, fixed here.
    pub fn open_deal(
        &self,
        object_id: impl Into<String>,
        renter: Address,
        provider: Address,
        asset_id: AssetId,
        size_bytes: u64,
        total_epochs: u64,
    ) -> Result<StorageDeal> {
        if size_bytes == 0 || total_epochs == 0 {
            return Err(StorageProviderError::InvalidRequest(
                "size_bytes and total_epochs must be greater than zero".to_string(),
            ));
        }
        let price_per_epoch = self.pricing.epoch_price(size_bytes);
        if price_per_epoch == 0 {
            return Err(StorageProviderError::InvalidRequest(
                "computed epoch price is zero; rate too low for object size".to_string(),
            ));
        }
        let total_value = price_per_epoch.saturating_mul(total_epochs as u128);

        // Coverage admission (only when a stake ledger + tracker are attached):
        // the provider's stake must cover this new storage exposure on top of
        // everything already registered across services (rentals + storage).
        if let (Some(ledger), Some(obs)) = (&self.stake_ledger, &self.obligations) {
            let new_storage_total = self
                .active_exposure(&provider)
                .saturating_add(price_per_epoch);
            let stake = ledger.available_stake(&provider);
            if !obs.can_admit(
                &provider,
                ObligationSource::Storage,
                new_storage_total,
                stake,
            ) {
                let other = obs.exposure_excluding(&provider, ObligationSource::Storage);
                return Err(StorageProviderError::Settlement(format!(
                    "insufficient provider stake to cover storage: need {} (storage {} + other {}), stake {}",
                    new_storage_total.saturating_add(other),
                    new_storage_total,
                    other,
                    stake
                )));
            }
        }

        let key = (renter, asset_id.clone());
        let balance = self.balances.get(&key).map(|e| *e.value()).unwrap_or(0);
        if balance < total_value {
            return Err(StorageProviderError::Settlement(format!(
                "insufficient deposit: need {}, have {}",
                total_value, balance
            )));
        }
        {
            let mut entry = self.balances.entry(key).or_insert(0);
            *entry = entry.saturating_sub(total_value);
        }

        let deal = StorageDeal {
            deal_id: uuid::Uuid::new_v4().to_string(),
            object_id: object_id.into(),
            renter,
            provider,
            asset_id,
            size_bytes,
            price_per_epoch,
            total_epochs,
            epochs_charged: 0,
            consecutive_misses: 0,
            created_at: Timestamp::now(),
            status: StorageDealStatus::Active,
        };
        self.deals.insert(deal.deal_id.clone(), deal.clone());
        self.deals_by_provider
            .entry(provider)
            .or_default()
            .push(deal.deal_id.clone());
        self.persist_deal(&deal);
        self.publish_exposure(&provider);
        info!(
            "Opened storage deal {} object={} {} bytes @ {}/epoch x{}",
            deal.deal_id, deal.object_id, size_bytes, price_per_epoch, total_epochs
        );
        Ok(deal)
    }

    /// Charges one storage epoch, gated on the retrievability-challenge verdict
    /// for this epoch (`challenge_passed`).
    ///
    /// Passed → the epoch's slice streams from the renter's locked deposit to
    /// the provider. Failed → a miss: no charge, and the renter's slice for
    /// that epoch returns to their withdrawable deposit (they do not pay for
    /// storage that was not proven). Repeated misses past the threshold
    /// terminate the deal and return the unearned remainder.
    pub fn charge_epoch(&self, deal_id: &str, challenge_passed: bool) -> Result<ChargeOutcome> {
        let (outcome, provider, closed, snapshot) = {
            let mut entry = self
                .deals
                .get_mut(deal_id)
                .ok_or_else(|| StorageProviderError::ObjectNotFound(deal_id.to_string()))?;
            let deal = entry.value_mut();

            if deal.status != StorageDealStatus::Active {
                return Err(StorageProviderError::InvalidRequest(format!(
                    "deal {} is not active",
                    deal_id
                )));
            }

            let slice = deal.price_per_epoch;
            let provider = deal.provider;

            let outcome = if challenge_passed {
                let key = (deal.provider, deal.asset_id.clone());
                {
                    let mut bal = self.balances.entry(key).or_insert(0);
                    *bal = bal.saturating_add(slice);
                }
                deal.epochs_charged = deal.epochs_charged.saturating_add(1);
                deal.consecutive_misses = 0;

                if deal.is_complete() {
                    deal.status = StorageDealStatus::Completed;
                    debug!("Storage deal {} completed", deal_id);
                }
                debug!("Storage deal {} charged {} to provider", deal_id, slice);
                ChargeOutcome::Charged { slice }
            } else {
                // Miss: return the renter's locked slice for this (unproven) epoch.
                let key = (deal.renter, deal.asset_id.clone());
                {
                    let mut bal = self.balances.entry(key).or_insert(0);
                    *bal = bal.saturating_add(slice);
                }
                deal.epochs_charged = deal.epochs_charged.saturating_add(1);
                deal.consecutive_misses = deal.consecutive_misses.saturating_add(1);
                warn!(
                    "Storage deal {} epoch missed (challenge failed); {} returned to renter",
                    deal_id, slice
                );

                if deal.consecutive_misses >= self.miss_threshold {
                    let unearned = deal.locked_remaining();
                    if unearned > 0 {
                        let rkey = (deal.renter, deal.asset_id.clone());
                        let mut bal = self.balances.entry(rkey).or_insert(0);
                        *bal = bal.saturating_add(unearned);
                    }
                    deal.status = StorageDealStatus::Terminated;
                    info!(
                        "Storage deal {} terminated after {} misses",
                        deal_id, deal.consecutive_misses
                    );
                } else if deal.is_complete() {
                    deal.status = StorageDealStatus::Completed;
                }
                ChargeOutcome::Missed
            };
            let closed = deal.status != StorageDealStatus::Active;
            (outcome, provider, closed, deal.clone())
        };

        // Persist the post-charge deal state so a restart does not re-charge
        // an already-billed epoch or resurrect a terminated deal.
        self.persist_deal(&snapshot);

        // A closed deal no longer contributes per-epoch exposure; refresh the
        // shared tracker so the freed stake is available to other obligations.
        if closed {
            self.publish_exposure(&provider);
        }

        Ok(outcome)
    }

    /// Looks up a deal.
    pub fn deal(&self, deal_id: &str) -> Result<StorageDeal> {
        self.deals
            .get(deal_id)
            .map(|e| e.value().clone())
            .ok_or_else(|| StorageProviderError::ObjectNotFound(deal_id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(
        deposit: u128,
    ) -> (
        Arc<DashMap<(Address, AssetId), u128>>,
        StorageMeter,
        Address,
        Address,
    ) {
        let renter = Address::new([1u8; 32]);
        let provider = Address::new([2u8; 32]);
        let balances = Arc::new(DashMap::new());
        balances.insert((renter, AssetId::tnzo()), deposit);
        let meter = StorageMeter::new(StoragePricing::new(2), balances.clone(), 3);
        (balances, meter, renter, provider)
    }

    #[test]
    fn epoch_price_is_per_byte() {
        let p = StoragePricing::new(5);
        assert_eq!(p.epoch_price(100), 500);
        assert!(matches!(
            p.service_type(100, 3600),
            ServiceType::Storage {
                data_size: 100,
                duration: 3600
            }
        ));
    }

    #[test]
    fn passing_challenge_streams_to_provider() {
        // rate 2/byte, 100 bytes -> 200/epoch. 5 epochs -> lock 1000.
        let (balances, meter, renter, provider) = setup(1_000);
        let deal = meter
            .open_deal("obj", renter, provider, AssetId::tnzo(), 100, 5)
            .unwrap();
        assert_eq!(deal.price_per_epoch, 200);
        assert_eq!(*balances.get(&(renter, AssetId::tnzo())).unwrap(), 0);

        let out = meter.charge_epoch(&deal.deal_id, true).unwrap();
        assert_eq!(out, ChargeOutcome::Charged { slice: 200 });
        assert_eq!(*balances.get(&(provider, AssetId::tnzo())).unwrap(), 200);
    }

    #[test]
    fn failed_challenge_refunds_epoch_to_renter() {
        let (balances, meter, renter, provider) = setup(1_000);
        let deal = meter
            .open_deal("obj", renter, provider, AssetId::tnzo(), 100, 5)
            .unwrap();
        let out = meter.charge_epoch(&deal.deal_id, false).unwrap();
        assert_eq!(out, ChargeOutcome::Missed);
        // Renter got the unproven epoch's slice back; provider earned nothing.
        assert_eq!(*balances.get(&(renter, AssetId::tnzo())).unwrap(), 200);
        assert!(balances.get(&(provider, AssetId::tnzo())).is_none());
    }

    #[test]
    fn repeated_misses_terminate_and_refund_remainder() {
        let (balances, meter, renter, provider) = setup(2_000); // 200/epoch x 10
        let deal = meter
            .open_deal("obj", renter, provider, AssetId::tnzo(), 100, 10)
            .unwrap();
        meter.charge_epoch(&deal.deal_id, false).unwrap();
        meter.charge_epoch(&deal.deal_id, false).unwrap();
        meter.charge_epoch(&deal.deal_id, false).unwrap(); // 3rd miss -> terminate

        let d = meter.deal(&deal.deal_id).unwrap();
        assert_eq!(d.status, StorageDealStatus::Terminated);
        // 3 missed epochs each returned 200 (600), plus 7 unearned epochs (1400)
        // returned on termination = 2000 back to renter. Provider earned 0.
        assert_eq!(*balances.get(&(renter, AssetId::tnzo())).unwrap(), 2_000);
    }

    #[test]
    fn full_term_completes() {
        let (balances, meter, renter, provider) = setup(600); // 200 x 3
        let deal = meter
            .open_deal("obj", renter, provider, AssetId::tnzo(), 100, 3)
            .unwrap();
        for _ in 0..3 {
            meter.charge_epoch(&deal.deal_id, true).unwrap();
        }
        let d = meter.deal(&deal.deal_id).unwrap();
        assert_eq!(d.status, StorageDealStatus::Completed);
        assert_eq!(*balances.get(&(provider, AssetId::tnzo())).unwrap(), 600);
    }

    #[test]
    fn open_deal_rejects_insufficient_deposit() {
        let (_b, meter, renter, provider) = setup(100);
        let err = meter
            .open_deal("obj", renter, provider, AssetId::tnzo(), 100, 5)
            .unwrap_err();
        assert!(matches!(err, StorageProviderError::Settlement(_)));
    }

    #[test]
    fn charge_after_close_is_rejected() {
        let (_b, meter, renter, provider) = setup(200);
        let deal = meter
            .open_deal("obj", renter, provider, AssetId::tnzo(), 100, 1)
            .unwrap();
        meter.charge_epoch(&deal.deal_id, true).unwrap(); // completes
        let err = meter.charge_epoch(&deal.deal_id, true).unwrap_err();
        assert!(matches!(err, StorageProviderError::InvalidRequest(_)));
    }

    /// Fixed per-provider stake map for coverage tests.
    #[derive(Default)]
    struct TestStakeLedger {
        stakes: DashMap<Address, u128>,
    }
    impl StakeLedger for TestStakeLedger {
        fn available_stake(&self, provider: &Address) -> u128 {
            self.stakes.get(provider).map(|e| *e.value()).unwrap_or(0)
        }
        fn slash_to_make_whole(&self, provider: &Address, _renter: &Address, amount: u128) -> u128 {
            let mut e = self.stakes.entry(*provider).or_insert(0);
            let d = amount.min(*e);
            *e -= d;
            d
        }
    }

    #[test]
    fn coverage_admission_accounts_for_rental_exposure() {
        // rate 2/byte. Provider stake 1500, with 1000 of rental exposure
        // already registered on the shared tracker. A 100-byte object is
        // 200/epoch -> 1000 + 200 = 1200 <= 1500: admitted. A 300-byte object
        // is 600/epoch -> 1000 + 600 = 1600 > 1500: rejected.
        let renter = Address::new([1u8; 32]);
        let provider = Address::new([2u8; 32]);
        let balances = Arc::new(DashMap::new());
        balances.insert((renter, AssetId::tnzo()), 1_000_000);

        let ledger = Arc::new(TestStakeLedger::default());
        ledger.stakes.insert(provider, 1_500);
        let obligations = Arc::new(ProviderObligations::new());
        obligations.set(&provider, ObligationSource::Rental, 1_000);

        let meter = StorageMeter::new(StoragePricing::new(2), balances, 3)
            .with_coverage(ledger, obligations.clone());

        let big = meter.open_deal("big", renter, provider, AssetId::tnzo(), 300, 5);
        assert!(big.is_err());

        let ok = meter.open_deal("ok", renter, provider, AssetId::tnzo(), 100, 5);
        assert!(ok.is_ok());
        assert_eq!(
            obligations.exposure_for(&provider, ObligationSource::Storage),
            200
        );
        assert_eq!(obligations.total_exposure(&provider), 1_200);
    }

    #[test]
    fn closing_deal_frees_published_storage_exposure() {
        let renter = Address::new([1u8; 32]);
        let provider = Address::new([2u8; 32]);
        let balances = Arc::new(DashMap::new());
        balances.insert((renter, AssetId::tnzo()), 1_000_000);
        let ledger = Arc::new(TestStakeLedger::default());
        ledger.stakes.insert(provider, 100_000);
        let obligations = Arc::new(ProviderObligations::new());
        let meter = StorageMeter::new(StoragePricing::new(2), balances, 3)
            .with_coverage(ledger, obligations.clone());

        let deal = meter
            .open_deal("obj", renter, provider, AssetId::tnzo(), 100, 1)
            .unwrap();
        assert_eq!(
            obligations.exposure_for(&provider, ObligationSource::Storage),
            200
        );
        meter.charge_epoch(&deal.deal_id, true).unwrap(); // completes term
        assert_eq!(
            obligations.exposure_for(&provider, ObligationSource::Storage),
            0
        );
    }
}
