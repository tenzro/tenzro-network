//! Time-based capacity rental with streaming per-epoch escrow.
//!
//! Pay-per-use (the existing [`crate::escrow`] / [`crate::micropayments`]
//! primitives) is naturally safe: a provider serves a unit, then earns for
//! that unit, so neither side is ever exposed for more than one unit. Rental
//! breaks that symmetry — the renter pays for *future* capacity. Paying fully
//! upfront would expose the renter if the provider vanishes mid-term; paying
//! at the end would expose the provider if the renter walks. This module
//! resolves that with **escrow + streaming release**, so neither party is ever
//! exposed for more than one settlement epoch (TOKENOMICS §9).
//!
//! # Model
//!
//! - **Renter deposit.** A renter funds a prepaid TNZO balance (the same
//!   `balances` map the escrow manager debits). Booking a rental *locks* the
//!   full term value inside that deposit — it cannot be double-booked — but
//!   never spends it up front.
//! - **Provider stake is the collateral.** A provider is a staked validator
//!   (§7); that one stake collateralizes every serving obligation. There is no
//!   separate per-rental bond. When a provider misses an epoch, the renter is
//!   made whole *immediately from the provider's standing stake*.
//! - **Concurrent-exposure coverage.** A provider's stake must cover the sum
//!   of **one settlement epoch of value across all active rentals** — the total
//!   at-risk window — not the full value of every term. Booking admission:
//!   accept a new rental only if `stake ≥ Σ(active per-epoch exposure)`.
//! - **Streaming settlement.** Each epoch: a valid availability proof unlocks
//!   that epoch's slice from the renter's deposit to the provider; a missing or
//!   invalid proof is a *miss* — the renter is made whole from the provider's
//!   stake and their own locked slice returns to their deposit.
//! - **Clean termination.** If the deposit cannot fund the next epoch, the
//!   rental terminates at the epoch boundary with no debt created. Repeated
//!   misses past a governance threshold auto-terminate and free the slot.
//!
//! # Source of truth
//!
//! Like [`crate::escrow::EscrowManager`], [`RentalManager`] is a denormalized
//! cache + write path over a shared `balances` map and an optional persistent
//! [`KvStore`]. The Native VM remains the on-chain source of truth for funds;
//! provider stake is held by the staking/validator subsystem and surfaced here
//! through the [`StakeLedger`] trait so this module never owns slashing policy,
//! only requests make-whole debits against the provider's bonded stake.

use crate::error::{Result, SettlementError};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_storage::{KvStore, WriteOp, CF_SETTLEMENTS};
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::{Address, Timestamp};
use tracing::{debug, info, warn};

/// Storage key prefix for `RentalAgreement` records in `CF_SETTLEMENTS`.
const RENTAL_KEY_PREFIX: &[u8] = b"rental:";
/// Storage key prefix for the per-renter index of rental IDs.
const RENTAL_RENTER_KEY_PREFIX: &[u8] = b"rental_renter:";
/// Storage key prefix for the per-provider index of rental IDs.
const RENTAL_PROVIDER_KEY_PREFIX: &[u8] = b"rental_provider:";

/// Default consecutive-miss count past which a rental auto-terminates.
/// Governance-set in production (TOKENOMICS §9, *Streaming escrow*); this is
/// the on-chain default until a parameter is pinned.
pub const DEFAULT_MISS_TERMINATION_THRESHOLD: u32 = 3;

/// Read access to a provider's bonded validator stake, and the privileged
/// make-whole debit against it.
///
/// The staking subsystem (validator set / `tenzro-token`) owns stake balances
/// and slashing policy. The rental manager only needs to (a) read available
/// stake at booking time to enforce concurrent-exposure coverage, and (b)
/// request a bounded make-whole debit when a provider misses an epoch. Keeping
/// this behind a trait means rental settlement never duplicates slashing
/// accounting — it asks, the ledger decides how to satisfy the request.
pub trait StakeLedger: Send + Sync {
    /// Currently bonded, un-slashed stake available to collateralize rentals.
    fn available_stake(&self, provider: &Address) -> u128;

    /// Debit `amount` from `provider`'s stake to make `renter` whole for a
    /// missed epoch, crediting the renter's deposit. Returns the amount
    /// actually debited (may be less than requested if stake is exhausted).
    ///
    /// Implementations MUST treat this as a slash: the debited stake leaves the
    /// provider's bond permanently. Callers credit the renter separately, so an
    /// implementation that only adjusts stake (not renter balance) is valid.
    fn slash_to_make_whole(&self, provider: &Address, renter: &Address, amount: u128) -> u128;
}

/// Lifecycle state of a rental agreement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RentalStatus {
    /// Term is running; deposit slices stream to the provider each epoch.
    Active,
    /// Term completed normally; any unearned remainder returned to the renter.
    Completed,
    /// Terminated early — provider misses, renter underfunding, or coverage
    /// shedding. The provider keeps everything earned to the termination
    /// boundary; the renter's unearned slices are returned.
    Terminated,
}

/// Why a rental terminated, recorded for audit and to drive index cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TerminationReason {
    /// Reached the final epoch normally.
    TermComplete,
    /// Consecutive misses crossed the termination threshold.
    MissThreshold,
    /// Renter deposit could not fund the next epoch (clean termination).
    RenterUnderfunded,
    /// Shed (newest-first) so the provider's remaining stake could cover its
    /// other active rentals after a slash.
    CoverageShed,
}

/// A time-based capacity rental: a renter reserves a provider's capacity for a
/// fixed term, paying per epoch out of a locked deposit slice.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RentalAgreement {
    /// Unique rental identifier.
    pub rental_id: String,
    /// Consumer reserving the capacity; deposit is locked from this address.
    pub renter: Address,
    /// Provider serving the capacity; earns one slice per delivered epoch.
    pub provider: Address,
    /// Asset (TNZO) the rental settles in.
    pub asset_id: AssetId,
    /// Price of one settlement epoch — the per-epoch at-risk window.
    pub price_per_epoch: u128,
    /// Total number of epochs in the term.
    pub total_epochs: u64,
    /// Epochs delivered and paid so far (`< total_epochs` while `Active`).
    pub epochs_settled: u64,
    /// Consecutive missed epochs since the last successful settlement; reset to
    /// zero on any valid epoch.
    pub consecutive_misses: u32,
    /// Wall-clock creation time.
    pub created_at: Timestamp,
    /// Current lifecycle state.
    pub status: RentalStatus,
    /// Set when `status != Active`.
    pub termination_reason: Option<TerminationReason>,
}

impl RentalAgreement {
    /// Total term value = `price_per_epoch * total_epochs`.
    pub fn total_value(&self) -> u128 {
        self.price_per_epoch.saturating_mul(self.total_epochs as u128)
    }

    /// Value still locked in the renter's deposit for undelivered epochs.
    pub fn locked_remaining(&self) -> u128 {
        let remaining_epochs = self.total_epochs.saturating_sub(self.epochs_settled);
        self.price_per_epoch.saturating_mul(remaining_epochs as u128)
    }

    /// This rental's contribution to the provider's concurrent-exposure window:
    /// one epoch of value while active, zero once closed.
    pub fn per_epoch_exposure(&self) -> u128 {
        if self.status == RentalStatus::Active {
            self.price_per_epoch
        } else {
            0
        }
    }

    /// True when every epoch has been settled.
    pub fn is_term_complete(&self) -> bool {
        self.epochs_settled >= self.total_epochs
    }
}

/// Outcome of a single epoch tick on one rental.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochOutcome {
    /// Proof valid: `slice` streamed from deposit to provider.
    Settled {
        /// Amount unlocked to the provider this epoch.
        slice: u128,
    },
    /// Proof missing/invalid: renter made whole by `made_whole` from stake.
    Missed {
        /// Amount debited from provider stake to the renter.
        made_whole: u128,
    },
    /// Rental closed this tick (term complete, miss threshold, or underfunded).
    Closed {
        /// Why the rental closed.
        reason: TerminationReason,
    },
}

/// Streaming-escrow manager for time-based capacity rentals.
pub struct RentalManager {
    /// Active + historical agreements by ID.
    rentals: DashMap<String, RentalAgreement>,
    /// Rental IDs indexed by renter.
    rentals_by_renter: DashMap<Address, Vec<String>>,
    /// Rental IDs indexed by provider.
    rentals_by_provider: DashMap<Address, Vec<String>>,
    /// Shared prepaid deposit balances, the same map the escrow manager debits.
    balances: Arc<DashMap<(Address, AssetId), u128>>,
    /// Provider stake source + make-whole sink.
    stake_ledger: Arc<dyn StakeLedger>,
    /// Consecutive-miss count that auto-terminates a rental.
    miss_threshold: u32,
    /// Optional persistent backend; write-through to `CF_SETTLEMENTS`.
    storage: Option<Arc<dyn KvStore>>,
}

impl std::fmt::Debug for RentalManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RentalManager")
            .field("rentals", &self.rentals.len())
            .field("rentals_by_renter", &self.rentals_by_renter.len())
            .field("rentals_by_provider", &self.rentals_by_provider.len())
            .field("miss_threshold", &self.miss_threshold)
            .field("storage", &self.storage.as_ref().map(|_| "Some(Arc<dyn KvStore>)"))
            .finish()
    }
}

impl RentalManager {
    /// Creates an in-memory rental manager (no persistence).
    pub fn new(
        balances: Arc<DashMap<(Address, AssetId), u128>>,
        stake_ledger: Arc<dyn StakeLedger>,
    ) -> Self {
        Self {
            rentals: DashMap::new(),
            rentals_by_renter: DashMap::new(),
            rentals_by_provider: DashMap::new(),
            balances,
            stake_ledger,
            miss_threshold: DEFAULT_MISS_TERMINATION_THRESHOLD,
            storage: None,
        }
    }

    /// Creates a persistent rental manager that rehydrates from
    /// `CF_SETTLEMENTS` on construction and writes through on every mutation.
    pub fn with_storage(
        balances: Arc<DashMap<(Address, AssetId), u128>>,
        stake_ledger: Arc<dyn StakeLedger>,
        storage: Arc<dyn KvStore>,
    ) -> Self {
        let mgr = Self {
            rentals: DashMap::new(),
            rentals_by_renter: DashMap::new(),
            rentals_by_provider: DashMap::new(),
            balances,
            stake_ledger,
            miss_threshold: DEFAULT_MISS_TERMINATION_THRESHOLD,
            storage: Some(storage),
        };
        mgr.hydrate();
        mgr
    }

    /// Overrides the consecutive-miss termination threshold (governance knob).
    pub fn with_miss_threshold(mut self, threshold: u32) -> Self {
        self.miss_threshold = threshold;
        self
    }

    fn rental_storage_key(rental_id: &str) -> Vec<u8> {
        [RENTAL_KEY_PREFIX, rental_id.as_bytes()].concat()
    }

    fn renter_index_key(addr: &Address) -> Vec<u8> {
        [RENTAL_RENTER_KEY_PREFIX, hex::encode(addr.as_bytes()).as_bytes()].concat()
    }

    fn provider_index_key(addr: &Address) -> Vec<u8> {
        [RENTAL_PROVIDER_KEY_PREFIX, hex::encode(addr.as_bytes()).as_bytes()].concat()
    }

    fn hydrate(&self) {
        let storage = match &self.storage {
            Some(s) => s,
            None => return,
        };

        let keys = match storage.get_keys_with_prefix(CF_SETTLEMENTS, RENTAL_KEY_PREFIX) {
            Ok(keys) => keys,
            Err(e) => {
                warn!("Failed to scan CF_SETTLEMENTS for rental hydration: {}", e);
                return;
            }
        };

        let mut hydrated = 0usize;
        for key_bytes in &keys {
            match storage.get(CF_SETTLEMENTS, key_bytes) {
                Ok(Some(data)) => match serde_json::from_slice::<RentalAgreement>(&data) {
                    Ok(rental) => {
                        let id = rental.rental_id.clone();
                        self.rentals_by_renter
                            .entry(rental.renter)
                            .or_default()
                            .push(id.clone());
                        self.rentals_by_provider
                            .entry(rental.provider)
                            .or_default()
                            .push(id.clone());
                        self.rentals.insert(id, rental);
                        hydrated += 1;
                    }
                    Err(e) => {
                        let key_str = std::str::from_utf8(key_bytes).unwrap_or("<binary>");
                        warn!("Failed to deserialize rental at key {}: {}", key_str, e);
                    }
                },
                Ok(None) => {}
                Err(e) => warn!("Storage read failure during RentalManager hydration: {}", e),
            }
        }

        if hydrated > 0 {
            info!("Hydrated {} rental(s) from RocksDB CF_SETTLEMENTS", hydrated);
        }
    }

    /// Atomically persists a rental record and, when indices changed, its
    /// renter/provider index lists.
    fn persist_rental_atomic(&self, rental: &RentalAgreement, indices_changed: bool) -> Result<()> {
        let storage = match &self.storage {
            Some(s) => s,
            None => return Ok(()),
        };

        let rental_data = serde_json::to_vec(rental)
            .map_err(|e| SettlementError::StorageError(format!("serialize rental: {}", e)))?;
        let mut ops = vec![WriteOp::Put {
            cf: CF_SETTLEMENTS.to_string(),
            key: Self::rental_storage_key(&rental.rental_id),
            value: rental_data,
        }];

        if indices_changed {
            let renter_ids: Vec<String> = self
                .rentals_by_renter
                .get(&rental.renter)
                .map(|v| v.value().clone())
                .unwrap_or_default();
            let provider_ids: Vec<String> = self
                .rentals_by_provider
                .get(&rental.provider)
                .map(|v| v.value().clone())
                .unwrap_or_default();

            let renter_data = serde_json::to_vec(&renter_ids).map_err(|e| {
                SettlementError::StorageError(format!("serialize renter index: {}", e))
            })?;
            let provider_data = serde_json::to_vec(&provider_ids).map_err(|e| {
                SettlementError::StorageError(format!("serialize provider index: {}", e))
            })?;

            ops.push(WriteOp::Put {
                cf: CF_SETTLEMENTS.to_string(),
                key: Self::renter_index_key(&rental.renter),
                value: renter_data,
            });
            ops.push(WriteOp::Put {
                cf: CF_SETTLEMENTS.to_string(),
                key: Self::provider_index_key(&rental.provider),
                value: provider_data,
            });
        }

        storage
            .write_batch_sync(ops)
            .map_err(|e| SettlementError::StorageError(e.to_string()))?;
        Ok(())
    }

    /// Sum of one-epoch exposure across a provider's currently-active rentals —
    /// the total at-risk window the provider's stake must cover.
    pub fn active_exposure(&self, provider: &Address) -> u128 {
        let ids = match self.rentals_by_provider.get(provider) {
            Some(v) => v.value().clone(),
            None => return 0,
        };
        ids.iter()
            .filter_map(|id| self.rentals.get(id))
            .map(|r| r.value().per_epoch_exposure())
            .fold(0u128, |acc, e| acc.saturating_add(e))
    }

    /// Books a new rental.
    ///
    /// Locks the full term value from the renter's deposit and admits the
    /// rental only if accepting it keeps the provider's stake covering the
    /// combined per-epoch exposure of all active rentals
    /// (`stake ≥ Σ(active per-epoch exposure)`, TOKENOMICS §9). On any failure,
    /// no deposit is locked and no record is created.
    pub fn book_rental(
        &self,
        renter: Address,
        provider: Address,
        asset_id: AssetId,
        price_per_epoch: u128,
        total_epochs: u64,
    ) -> Result<RentalAgreement> {
        if price_per_epoch == 0 || total_epochs == 0 {
            return Err(SettlementError::InvalidAmount(
                "price_per_epoch and total_epochs must be greater than zero".to_string(),
            ));
        }

        let total_value = price_per_epoch.saturating_mul(total_epochs as u128);

        // Coverage admission: provider stake must cover this new rental's
        // per-epoch slice on top of all existing active exposure.
        let projected_exposure = self
            .active_exposure(&provider)
            .saturating_add(price_per_epoch);
        let stake = self.stake_ledger.available_stake(&provider);
        if stake < projected_exposure {
            return Err(SettlementError::InsufficientFunds {
                required: projected_exposure,
                available: stake,
            });
        }

        // Lock the full term value inside the renter's deposit. It is not spent
        // up front — it streams epoch by epoch — but it cannot be double-booked.
        let key = (renter, asset_id.clone());
        let balance = self.balances.get(&key).map(|e| *e.value()).unwrap_or(0);
        if balance < total_value {
            return Err(SettlementError::InsufficientFunds {
                required: total_value,
                available: balance,
            });
        }
        {
            let mut entry = self.balances.entry(key).or_insert(0);
            *entry = entry
                .checked_sub(total_value)
                .ok_or_else(|| SettlementError::ArithmeticOverflow("Deposit lock overflow".to_string()))?;
        }

        let rental = RentalAgreement {
            rental_id: uuid::Uuid::new_v4().to_string(),
            renter,
            provider,
            asset_id,
            price_per_epoch,
            total_epochs,
            epochs_settled: 0,
            consecutive_misses: 0,
            created_at: Timestamp::now(),
            status: RentalStatus::Active,
            termination_reason: None,
        };
        let rental_id = rental.rental_id.clone();

        self.rentals.insert(rental_id.clone(), rental.clone());
        self.rentals_by_renter
            .entry(renter)
            .or_default()
            .push(rental_id.clone());
        self.rentals_by_provider
            .entry(provider)
            .or_default()
            .push(rental_id.clone());

        self.persist_rental_atomic(&rental, true)?;

        info!(
            "Booked rental {} renter={} provider={} {}x{} (total {})",
            rental.rental_id, renter, provider, price_per_epoch, total_epochs, total_value
        );
        Ok(rental)
    }

    /// Settles one epoch of an active rental.
    ///
    /// `proof_valid` is the verdict on the provider's signed availability proof
    /// for this epoch (heartbeat + capacity attestation, verified by the
    /// caller). Valid → that epoch's slice unlocks from deposit to provider.
    /// Invalid/missing → a *miss*: the renter is made whole from the provider's
    /// stake and the slice returns to their deposit; repeated misses past the
    /// threshold terminate the rental. The final settled epoch completes the
    /// term and returns any unearned remainder (there is none once all epochs
    /// settle).
    pub fn settle_epoch(&self, rental_id: &str, proof_valid: bool) -> Result<EpochOutcome> {
        let (outcome, snapshot, indices_changed) = {
            let mut entry = self
                .rentals
                .get_mut(rental_id)
                .ok_or_else(|| SettlementError::SettlementNotFound(rental_id.to_string()))?;
            let rental = entry.value_mut();

            if rental.status != RentalStatus::Active {
                return Err(SettlementError::EscrowAlreadyReleased(rental_id.to_string()));
            }

            if proof_valid {
                // Unlock this epoch's slice from the locked deposit to the
                // provider's spendable balance.
                let slice = rental.price_per_epoch;
                let key = (rental.provider, rental.asset_id.clone());
                {
                    let mut bal = self.balances.entry(key).or_insert(0);
                    *bal = bal.checked_add(slice).ok_or_else(|| {
                        SettlementError::ArithmeticOverflow("Provider credit overflow".to_string())
                    })?;
                }
                rental.epochs_settled = rental.epochs_settled.saturating_add(1);
                rental.consecutive_misses = 0;

                if rental.is_term_complete() {
                    rental.status = RentalStatus::Completed;
                    rental.termination_reason = Some(TerminationReason::TermComplete);
                    let snap = rental.clone();
                    (EpochOutcome::Settled { slice }, snap, false)
                } else {
                    let snap = rental.clone();
                    (EpochOutcome::Settled { slice }, snap, false)
                }
            } else {
                // Miss: make the renter whole for this epoch from provider
                // stake, and return the renter's own locked slice to their
                // withdrawable deposit. The undelivered epoch is consumed.
                let slice = rental.price_per_epoch;
                let made_whole =
                    self.stake_ledger
                        .slash_to_make_whole(&rental.provider, &rental.renter, slice);

                // Return the renter's locked slice (their own money) plus the
                // make-whole compensation from the provider's stake.
                let renter_key = (rental.renter, rental.asset_id.clone());
                let credit = slice.saturating_add(made_whole);
                {
                    let mut bal = self.balances.entry(renter_key).or_insert(0);
                    *bal = bal.checked_add(credit).ok_or_else(|| {
                        SettlementError::ArithmeticOverflow("Renter make-whole overflow".to_string())
                    })?;
                }

                rental.epochs_settled = rental.epochs_settled.saturating_add(1);
                rental.consecutive_misses = rental.consecutive_misses.saturating_add(1);

                if rental.consecutive_misses >= self.miss_threshold {
                    self.close_in_place(rental, TerminationReason::MissThreshold);
                    let snap = rental.clone();
                    (
                        EpochOutcome::Missed { made_whole },
                        snap,
                        false,
                    )
                } else if rental.is_term_complete() {
                    self.close_in_place(rental, TerminationReason::TermComplete);
                    let snap = rental.clone();
                    (EpochOutcome::Missed { made_whole }, snap, false)
                } else {
                    let snap = rental.clone();
                    (EpochOutcome::Missed { made_whole }, snap, false)
                }
            }
        };

        self.persist_rental_atomic(&snapshot, indices_changed)?;

        match &outcome {
            EpochOutcome::Settled { slice } => debug!(
                "Rental {} epoch settled: {} -> provider {}",
                rental_id, slice, snapshot.provider
            ),
            EpochOutcome::Missed { made_whole } => warn!(
                "Rental {} epoch missed: made renter {} whole by {} from provider {} stake",
                rental_id, snapshot.renter, made_whole, snapshot.provider
            ),
            EpochOutcome::Closed { .. } => {}
        }

        if snapshot.status != RentalStatus::Active {
            info!(
                "Rental {} closed: {:?}",
                rental_id, snapshot.termination_reason
            );
        }

        Ok(outcome)
    }

    /// Marks a rental closed in place and refunds the renter's unearned locked
    /// slices to their deposit. Does not persist — the caller persists the
    /// snapshot after dropping the mutable guard.
    fn close_in_place(&self, rental: &mut RentalAgreement, reason: TerminationReason) {
        let unearned = rental.locked_remaining();
        if unearned > 0 {
            let renter_key = (rental.renter, rental.asset_id.clone());
            let mut bal = self.balances.entry(renter_key).or_insert(0);
            *bal = bal.saturating_add(unearned);
        }
        rental.status = RentalStatus::Terminated;
        rental.termination_reason = Some(reason);
    }

    /// Terminates a rental cleanly at an epoch boundary because the renter's
    /// deposit cannot fund the next epoch. No debt is created: the provider
    /// keeps everything earned to this point and the slot frees
    /// (TOKENOMICS §9, *Underfunded rentals*).
    ///
    /// With the full-term lock model used at booking, an active rental's next
    /// epoch is always pre-funded, so this is used when an external policy
    /// (e.g. partial deposits) decides the renter can no longer pay. Returns
    /// `false` if the rental is not active.
    pub fn terminate_underfunded(&self, rental_id: &str) -> Result<bool> {
        let snapshot = {
            let mut entry = match self.rentals.get_mut(rental_id) {
                Some(e) => e,
                None => return Err(SettlementError::SettlementNotFound(rental_id.to_string())),
            };
            let rental = entry.value_mut();
            if rental.status != RentalStatus::Active {
                return Ok(false);
            }
            self.close_in_place(rental, TerminationReason::RenterUnderfunded);
            rental.clone()
        };
        self.persist_rental_atomic(&snapshot, false)?;
        info!("Rental {} terminated: renter underfunded", rental_id);
        Ok(true)
    }

    /// Re-checks coverage after a provider's stake was reduced (e.g. by a slash
    /// on one rental). If the remaining stake no longer covers the combined
    /// per-epoch exposure of all active rentals, sheds rentals **newest-first**
    /// until coverage holds again — protecting the provider's *other* renters
    /// from a failure on one (TOKENOMICS §9, step 4).
    ///
    /// Returns the rental IDs shed. Each shed rental terminates cleanly with
    /// the renter's unearned slices returned.
    pub fn recheck_coverage(&self, provider: &Address) -> Result<Vec<String>> {
        let stake = self.stake_ledger.available_stake(provider);

        // Active rentals for this provider. The per-provider index preserves
        // booking order (book_rental appends), so a later index position means
        // a more recently booked rental. We carry that position as the primary
        // newest-first key and use created_at only as a secondary signal — this
        // keeps shed order deterministic even when several rentals share the
        // same millisecond timestamp.
        let mut active: Vec<(usize, String, Timestamp, u128)> = {
            let ids = match self.rentals_by_provider.get(provider) {
                Some(v) => v.value().clone(),
                None => return Ok(Vec::new()),
            };
            ids.iter()
                .enumerate()
                .filter_map(|(pos, id)| self.rentals.get(id).map(|r| (pos, r)))
                .filter(|(_, r)| r.value().status == RentalStatus::Active)
                .map(|(pos, r)| {
                    let v = r.value();
                    (pos, v.rental_id.clone(), v.created_at, v.price_per_epoch)
                })
                .collect()
        };

        let mut total: u128 = active
            .iter()
            .fold(0u128, |acc, (_, _, _, e)| acc.saturating_add(*e));
        if total <= stake {
            return Ok(Vec::new());
        }

        // Shed newest-first: by timestamp desc, then by index position desc.
        active.sort_by(|a, b| {
            b.2.as_millis()
                .cmp(&a.2.as_millis())
                .then(b.0.cmp(&a.0))
        });

        let mut shed = Vec::new();
        for (_, id, _, exposure) in active {
            if total <= stake {
                break;
            }
            let snapshot = {
                let mut entry = match self.rentals.get_mut(&id) {
                    Some(e) => e,
                    None => continue,
                };
                let rental = entry.value_mut();
                if rental.status != RentalStatus::Active {
                    continue;
                }
                self.close_in_place(rental, TerminationReason::CoverageShed);
                rental.clone()
            };
            self.persist_rental_atomic(&snapshot, false)?;
            total = total.saturating_sub(exposure);
            shed.push(id);
        }

        if !shed.is_empty() {
            warn!(
                "Coverage shed {} rental(s) for provider {} after stake drop to {}",
                shed.len(),
                provider,
                stake
            );
        }
        Ok(shed)
    }

    /// Gets a rental by ID.
    pub fn get_rental(&self, rental_id: &str) -> Result<RentalAgreement> {
        self.rentals
            .get(rental_id)
            .map(|e| e.value().clone())
            .ok_or_else(|| SettlementError::SettlementNotFound(rental_id.to_string()))
    }

    /// Gets all rentals for a renter.
    pub fn get_rentals_by_renter(&self, renter: &Address) -> Vec<RentalAgreement> {
        self.rentals_by_renter
            .get(renter)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.rentals.get(id).map(|e| e.value().clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Gets all rentals for a provider.
    pub fn get_rentals_by_provider(&self, provider: &Address) -> Vec<RentalAgreement> {
        self.rentals_by_provider
            .get(provider)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.rentals.get(id).map(|e| e.value().clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test stake ledger: a fixed per-provider stake map. `slash_to_make_whole`
    /// debits the provider's stake (capped at available) and returns the amount
    /// debited; it does not touch renter balances (the manager credits those).
    #[derive(Default)]
    struct TestStakeLedger {
        stakes: DashMap<Address, u128>,
    }

    impl TestStakeLedger {
        fn with_stake(provider: Address, amount: u128) -> Arc<Self> {
            let l = Self::default();
            l.stakes.insert(provider, amount);
            Arc::new(l)
        }
        fn set(&self, provider: Address, amount: u128) {
            self.stakes.insert(provider, amount);
        }
    }

    impl StakeLedger for TestStakeLedger {
        fn available_stake(&self, provider: &Address) -> u128 {
            self.stakes.get(provider).map(|e| *e.value()).unwrap_or(0)
        }
        fn slash_to_make_whole(&self, provider: &Address, _renter: &Address, amount: u128) -> u128 {
            let mut entry = self.stakes.entry(*provider).or_insert(0);
            let debited = amount.min(*entry);
            *entry -= debited;
            debited
        }
    }

    fn setup(
        renter_deposit: u128,
        provider_stake: u128,
    ) -> (
        Arc<DashMap<(Address, AssetId), u128>>,
        Arc<TestStakeLedger>,
        RentalManager,
        Address,
        Address,
    ) {
        let renter = Address::new([1u8; 32]);
        let provider = Address::new([2u8; 32]);
        let balances = Arc::new(DashMap::new());
        balances.insert((renter, AssetId::tnzo()), renter_deposit);
        let ledger = TestStakeLedger::with_stake(provider, provider_stake);
        let mgr = RentalManager::new(balances.clone(), ledger.clone());
        (balances, ledger, mgr, renter, provider)
    }

    #[test]
    fn book_locks_full_term_value_from_deposit() {
        let (balances, _ledger, mgr, renter, provider) = setup(10_000, 10_000);
        let rental = mgr
            .book_rental(renter, provider, AssetId::tnzo(), 1_000, 5)
            .unwrap();
        assert_eq!(rental.total_value(), 5_000);
        // Deposit reduced by the full term value.
        assert_eq!(*balances.get(&(renter, AssetId::tnzo())).unwrap(), 5_000);
        assert_eq!(rental.status, RentalStatus::Active);
    }

    #[test]
    fn booking_rejected_when_deposit_too_small() {
        let (_b, _l, mgr, renter, provider) = setup(3_000, 10_000);
        let err = mgr
            .book_rental(renter, provider, AssetId::tnzo(), 1_000, 5)
            .unwrap_err();
        assert!(matches!(err, SettlementError::InsufficientFunds { .. }));
    }

    #[test]
    fn booking_rejected_when_stake_below_per_epoch_exposure() {
        // Provider stake (500) is below a single epoch's exposure (1000).
        let (_b, _l, mgr, renter, provider) = setup(10_000, 500);
        let err = mgr
            .book_rental(renter, provider, AssetId::tnzo(), 1_000, 5)
            .unwrap_err();
        assert!(matches!(err, SettlementError::InsufficientFunds { .. }));
    }

    #[test]
    fn concurrent_exposure_accumulates_against_stake() {
        // Stake 1500 covers one epoch (1000) but not two concurrent (2000).
        let (_b, _l, mgr, renter, provider) = setup(100_000, 1_500);
        mgr.book_rental(renter, provider, AssetId::tnzo(), 1_000, 5)
            .unwrap();
        assert_eq!(mgr.active_exposure(&provider), 1_000);
        let err = mgr
            .book_rental(renter, provider, AssetId::tnzo(), 1_000, 5)
            .unwrap_err();
        assert!(matches!(err, SettlementError::InsufficientFunds { .. }));
    }

    #[test]
    fn valid_epoch_streams_slice_to_provider() {
        let (balances, _l, mgr, renter, provider) = setup(10_000, 10_000);
        let rental = mgr
            .book_rental(renter, provider, AssetId::tnzo(), 1_000, 5)
            .unwrap();

        let out = mgr.settle_epoch(&rental.rental_id, true).unwrap();
        assert_eq!(out, EpochOutcome::Settled { slice: 1_000 });
        // Provider earned one slice.
        assert_eq!(*balances.get(&(provider, AssetId::tnzo())).unwrap(), 1_000);
        let updated = mgr.get_rental(&rental.rental_id).unwrap();
        assert_eq!(updated.epochs_settled, 1);
        assert_eq!(updated.consecutive_misses, 0);
    }

    #[test]
    fn full_term_completes_and_pays_every_epoch() {
        let (balances, _l, mgr, renter, provider) = setup(10_000, 10_000);
        let rental = mgr
            .book_rental(renter, provider, AssetId::tnzo(), 1_000, 3)
            .unwrap();
        for _ in 0..3 {
            mgr.settle_epoch(&rental.rental_id, true).unwrap();
        }
        let done = mgr.get_rental(&rental.rental_id).unwrap();
        assert_eq!(done.status, RentalStatus::Completed);
        assert_eq!(done.termination_reason, Some(TerminationReason::TermComplete));
        // Provider got the full term; nothing left locked; renter spent exactly 3000.
        assert_eq!(*balances.get(&(provider, AssetId::tnzo())).unwrap(), 3_000);
        assert_eq!(*balances.get(&(renter, AssetId::tnzo())).unwrap(), 7_000);
        // Closed rental contributes no exposure.
        assert_eq!(mgr.active_exposure(&provider), 0);
    }

    #[test]
    fn missed_epoch_makes_renter_whole_from_stake() {
        let (balances, ledger, mgr, renter, provider) = setup(10_000, 10_000);
        let rental = mgr
            .book_rental(renter, provider, AssetId::tnzo(), 1_000, 5)
            .unwrap();
        // Deposit now 5000 locked.
        assert_eq!(*balances.get(&(renter, AssetId::tnzo())).unwrap(), 5_000);

        let out = mgr.settle_epoch(&rental.rental_id, false).unwrap();
        assert_eq!(out, EpochOutcome::Missed { made_whole: 1_000 });

        // Renter got back their own locked slice (1000) plus make-whole (1000).
        assert_eq!(*balances.get(&(renter, AssetId::tnzo())).unwrap(), 7_000);
        // Provider stake was slashed by the make-whole amount.
        assert_eq!(ledger.available_stake(&provider), 9_000);
        // Provider earned nothing.
        assert!(balances.get(&(provider, AssetId::tnzo())).is_none());
    }

    #[test]
    fn consecutive_misses_terminate_and_refund_remainder() {
        let (balances, ledger, mgr, renter, provider) = setup(10_000, 10_000);
        let rental = mgr
            .book_rental(renter, provider, AssetId::tnzo(), 1_000, 10)
            .unwrap();
        // Default threshold is 3 consecutive misses.
        mgr.settle_epoch(&rental.rental_id, false).unwrap();
        mgr.settle_epoch(&rental.rental_id, false).unwrap();
        let out = mgr.settle_epoch(&rental.rental_id, false).unwrap();
        assert!(matches!(out, EpochOutcome::Missed { .. }));

        let r = mgr.get_rental(&rental.rental_id).unwrap();
        assert_eq!(r.status, RentalStatus::Terminated);
        assert_eq!(r.termination_reason, Some(TerminationReason::MissThreshold));
        // Booking locked the full 10*1000 = 10000 term, so post-lock the renter
        // balance is 0. Three misses each return the locked slice (3x1000) plus
        // make-whole from stake (3x1000); termination refunds the 7 unearned
        // epochs (7000). Total returned: 3000 + 3000 + 7000 = 13000.
        assert_eq!(*balances.get(&(renter, AssetId::tnzo())).unwrap(), 13_000);
        // Provider stake slashed by 3x1000 make-whole.
        assert_eq!(ledger.available_stake(&provider), 7_000);
        assert_eq!(mgr.active_exposure(&provider), 0);
    }

    #[test]
    fn settle_after_close_is_rejected() {
        let (_b, _l, mgr, renter, provider) = setup(10_000, 10_000);
        let rental = mgr
            .book_rental(renter, provider, AssetId::tnzo(), 1_000, 1)
            .unwrap();
        mgr.settle_epoch(&rental.rental_id, true).unwrap(); // completes term
        let err = mgr.settle_epoch(&rental.rental_id, true).unwrap_err();
        assert!(matches!(err, SettlementError::EscrowAlreadyReleased(_)));
    }

    #[test]
    fn underfunded_termination_returns_remaining_and_frees_slot() {
        let (balances, _l, mgr, renter, provider) = setup(10_000, 10_000);
        let rental = mgr
            .book_rental(renter, provider, AssetId::tnzo(), 1_000, 5)
            .unwrap();
        mgr.settle_epoch(&rental.rental_id, true).unwrap(); // 1 of 5
        assert!(mgr.terminate_underfunded(&rental.rental_id).unwrap());

        let r = mgr.get_rental(&rental.rental_id).unwrap();
        assert_eq!(r.status, RentalStatus::Terminated);
        assert_eq!(r.termination_reason, Some(TerminationReason::RenterUnderfunded));
        // Provider keeps 1 epoch (1000). 4 unearned epochs (4000) returned.
        assert_eq!(*balances.get(&(provider, AssetId::tnzo())).unwrap(), 1_000);
        // Renter: post-lock 5000 + 4000 refund = 9000.
        assert_eq!(*balances.get(&(renter, AssetId::tnzo())).unwrap(), 9_000);
        assert_eq!(mgr.active_exposure(&provider), 0);
    }

    #[test]
    fn coverage_recheck_sheds_newest_first() {
        let renter = Address::new([1u8; 32]);
        let provider = Address::new([2u8; 32]);
        let balances = Arc::new(DashMap::new());
        balances.insert((renter, AssetId::tnzo()), 1_000_000);
        let ledger = TestStakeLedger::with_stake(provider, 3_000);
        let mgr = RentalManager::new(balances, ledger.clone());

        // Three rentals, each 1000/epoch -> total exposure 3000, exactly covered.
        let r1 = mgr
            .book_rental(renter, provider, AssetId::tnzo(), 1_000, 10)
            .unwrap();
        let r2 = mgr
            .book_rental(renter, provider, AssetId::tnzo(), 1_000, 10)
            .unwrap();
        let r3 = mgr
            .book_rental(renter, provider, AssetId::tnzo(), 1_000, 10)
            .unwrap();
        assert_eq!(mgr.active_exposure(&provider), 3_000);

        // Stake drops to 1500: only one epoch of coverage remains, so two
        // newest rentals (r3, r2) must be shed, leaving r1 active.
        ledger.set(provider, 1_500);
        let shed = mgr.recheck_coverage(&provider).unwrap();
        assert_eq!(shed.len(), 2);
        assert!(shed.contains(&r3.rental_id));
        assert!(shed.contains(&r2.rental_id));

        assert_eq!(mgr.get_rental(&r1.rental_id).unwrap().status, RentalStatus::Active);
        assert_eq!(
            mgr.get_rental(&r2.rental_id).unwrap().status,
            RentalStatus::Terminated
        );
        assert_eq!(
            mgr.get_rental(&r3.rental_id).unwrap().status,
            RentalStatus::Terminated
        );
        assert_eq!(mgr.active_exposure(&provider), 1_000);
    }

    #[test]
    fn persistence_round_trips_active_rental() {
        use tenzro_storage::MemoryStore;

        let renter = Address::new([3u8; 32]);
        let provider = Address::new([4u8; 32]);
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let balances = Arc::new(DashMap::new());
        balances.insert((renter, AssetId::tnzo()), 50_000);
        let ledger = TestStakeLedger::with_stake(provider, 50_000);

        let rental_id = {
            let mgr =
                RentalManager::with_storage(balances.clone(), ledger.clone(), storage.clone());
            let r = mgr
                .book_rental(renter, provider, AssetId::tnzo(), 2_000, 4)
                .unwrap();
            mgr.settle_epoch(&r.rental_id, true).unwrap();
            r.rental_id
        };

        let mgr2 = RentalManager::with_storage(balances, ledger, storage);
        let restored = mgr2.get_rental(&rental_id).unwrap();
        assert_eq!(restored.epochs_settled, 1);
        assert_eq!(restored.total_epochs, 4);
        assert_eq!(restored.status, RentalStatus::Active);
        assert_eq!(mgr2.get_rentals_by_renter(&renter).len(), 1);
        assert_eq!(mgr2.get_rentals_by_provider(&provider).len(), 1);
        // Exposure rebuilt from hydrated state.
        assert_eq!(mgr2.active_exposure(&provider), 2_000);
    }
}
