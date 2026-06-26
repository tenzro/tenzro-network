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

use crate::error::{Result, StorageMarketError};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::{Address, Timestamp};
use tenzro_types::settlement::ServiceType;
use tracing::{debug, info, warn};

/// Pricing for stored bytes, in smallest TNZO units.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoragePricing {
    /// Price to store one byte for one settlement epoch.
    pub rate_per_byte_epoch: u128,
}

impl StoragePricing {
    /// Creates a pricing schedule.
    pub fn new(rate_per_byte_epoch: u128) -> Self {
        Self { rate_per_byte_epoch }
    }

    /// Price of one storage epoch for an object of `size_bytes`.
    pub fn epoch_price(&self, size_bytes: u64) -> u128 {
        self.rate_per_byte_epoch
            .saturating_mul(size_bytes as u128)
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
    /// Shared prepaid deposit balances (same convention as settlement escrow).
    balances: Arc<DashMap<(Address, AssetId), u128>>,
    /// Consecutive failed-challenge count that terminates a deal.
    miss_threshold: u32,
}

impl std::fmt::Debug for StorageMeter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageMeter")
            .field("pricing", &self.pricing)
            .field("deals", &self.deals.len())
            .field("miss_threshold", &self.miss_threshold)
            .finish()
    }
}

impl StorageMeter {
    /// Creates a meter with the given pricing and miss threshold.
    pub fn new(
        pricing: StoragePricing,
        balances: Arc<DashMap<(Address, AssetId), u128>>,
        miss_threshold: u32,
    ) -> Self {
        Self {
            pricing,
            deals: DashMap::new(),
            balances,
            miss_threshold,
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
            return Err(StorageMarketError::InvalidRequest(
                "size_bytes and total_epochs must be greater than zero".to_string(),
            ));
        }
        let price_per_epoch = self.pricing.epoch_price(size_bytes);
        if price_per_epoch == 0 {
            return Err(StorageMarketError::InvalidRequest(
                "computed epoch price is zero; rate too low for object size".to_string(),
            ));
        }
        let total_value = price_per_epoch.saturating_mul(total_epochs as u128);

        let key = (renter, asset_id.clone());
        let balance = self.balances.get(&key).map(|e| *e.value()).unwrap_or(0);
        if balance < total_value {
            return Err(StorageMarketError::Settlement(format!(
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
        let mut entry = self
            .deals
            .get_mut(deal_id)
            .ok_or_else(|| StorageMarketError::ObjectNotFound(deal_id.to_string()))?;
        let deal = entry.value_mut();

        if deal.status != StorageDealStatus::Active {
            return Err(StorageMarketError::InvalidRequest(format!(
                "deal {} is not active",
                deal_id
            )));
        }

        let slice = deal.price_per_epoch;

        if challenge_passed {
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
            Ok(ChargeOutcome::Charged { slice })
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
                info!("Storage deal {} terminated after {} misses", deal_id, deal.consecutive_misses);
            } else if deal.is_complete() {
                deal.status = StorageDealStatus::Completed;
            }
            Ok(ChargeOutcome::Missed)
        }
    }

    /// Looks up a deal.
    pub fn deal(&self, deal_id: &str) -> Result<StorageDeal> {
        self.deals
            .get(deal_id)
            .map(|e| e.value().clone())
            .ok_or_else(|| StorageMarketError::ObjectNotFound(deal_id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup(deposit: u128) -> (Arc<DashMap<(Address, AssetId), u128>>, StorageMeter, Address, Address) {
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
            ServiceType::Storage { data_size: 100, duration: 3600 }
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
        assert!(matches!(err, StorageMarketError::Settlement(_)));
    }

    #[test]
    fn charge_after_close_is_rejected() {
        let (_b, meter, renter, provider) = setup(200);
        let deal = meter
            .open_deal("obj", renter, provider, AssetId::tnzo(), 100, 1)
            .unwrap();
        meter.charge_epoch(&deal.deal_id, true).unwrap(); // completes
        let err = meter.charge_epoch(&deal.deal_id, true).unwrap_err();
        assert!(matches!(err, StorageMarketError::InvalidRequest(_)));
    }
}
