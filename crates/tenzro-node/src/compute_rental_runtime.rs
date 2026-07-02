//! Node-side compute-rental runtime.
//!
//! Spawned when a node's [`RoleSet`] serves AI — a node that offers inference
//! also rents out its CPU/GPU capacity for fixed terms. It owns the two pieces
//! a compute provider needs and wires them together:
//!
//! 1. [`RentalManager`] — books time-based capacity rentals against a locked
//!    renter deposit and streams one epoch's slice to the provider each epoch
//!    *only when an availability proof passes*. Cross-service stake coverage
//!    (compute + storage against one stake) is enforced through the shared
//!    [`ProviderObligations`] tracker.
//! 2. A per-epoch [`PricingPolicy`] — `Fixed`, network-`Dynamic` (EIP-1559
//!    controller, compute gain D=8), or `OrderBook`. The effective per-epoch
//!    rate is read at booking time; a dynamic policy steps once per epoch from
//!    metered utilization.
//!
//! The settle tick is availability-gated: for each active rental the runtime
//! checks the provider can still serve the reserved capacity this epoch, and
//! only then unlocks the epoch's slice. A failed check is a miss (renter made
//! whole from stake); repeated misses terminate the rental — the slash signal
//! the settlement layer consumes.
//!
//! [`RoleSet`]: tenzro_types::RoleSet

use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::RwLock;
use tenzro_settlement::obligations::ProviderObligations;
use tenzro_settlement::rental::{
    EpochOutcome, RentalAgreement, RentalManager, RentalStatus, StakeLedger,
};
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::Address;
use tracing::{debug, info, warn};

use crate::pricing::{DynamicPricing, PricingPolicy, ResourceKind};

/// Owns a node's compute-rental services and the per-epoch settlement loop.
pub struct ComputeRentalRuntime {
    /// The local node's provider address (credited when epochs settle).
    provider: Address,
    /// Streaming-rental booking + settlement + cross-service coverage.
    manager: Arc<RentalManager>,
    /// The per-epoch pricing policy for this provider. Read at booking time;
    /// a dynamic policy advances once per epoch from metered utilization.
    pricing: Arc<RwLock<PricingPolicy>>,
}

impl std::fmt::Debug for ComputeRentalRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ComputeRentalRuntime")
            .field("provider", &self.provider)
            .field("exposure", &self.manager.active_exposure(&self.provider))
            .finish()
    }
}

impl ComputeRentalRuntime {
    /// Builds a runtime over the shared settlement balances. `policy` is the
    /// provider's chosen per-epoch pricing; coverage enforcement is wired
    /// through the shared stake ledger + obligations tracker so compute and
    /// storage exposure share one stake.
    pub fn new(
        provider: Address,
        balances: Arc<DashMap<(Address, AssetId), u128>>,
        stake_ledger: Arc<dyn StakeLedger>,
        obligations: Arc<ProviderObligations>,
        policy: PricingPolicy,
    ) -> Self {
        let manager =
            Arc::new(RentalManager::new(balances, stake_ledger).with_obligations(obligations));
        Self {
            provider,
            manager,
            pricing: Arc::new(RwLock::new(policy)),
        }
    }

    /// Like [`new`], but rehydrates open rentals from `CF_SETTLEMENTS` on
    /// construction and writes through on every mutation, so bookings and
    /// per-epoch settlement survive a restart.
    ///
    /// [`new`]: ComputeRentalRuntime::new
    pub fn with_storage(
        provider: Address,
        balances: Arc<DashMap<(Address, AssetId), u128>>,
        stake_ledger: Arc<dyn StakeLedger>,
        obligations: Arc<ProviderObligations>,
        policy: PricingPolicy,
        storage: Arc<dyn tenzro_storage::KvStore>,
    ) -> Self {
        let manager = Arc::new(
            RentalManager::with_storage(balances, stake_ledger, storage)
                .with_obligations(obligations),
        );
        Self {
            provider,
            manager,
            pricing: Arc::new(RwLock::new(policy)),
        }
    }

    /// Convenience constructor for a flat per-epoch rate.
    pub fn with_fixed_rate(
        provider: Address,
        balances: Arc<DashMap<(Address, AssetId), u128>>,
        stake_ledger: Arc<dyn StakeLedger>,
        obligations: Arc<ProviderObligations>,
        rate_per_epoch: u128,
    ) -> Self {
        Self::new(
            provider,
            balances,
            stake_ledger,
            obligations,
            PricingPolicy::Fixed {
                rate: rate_per_epoch,
            },
        )
    }

    /// The rental manager, for rental lookups / status RPCs.
    pub fn manager(&self) -> &Arc<RentalManager> {
        &self.manager
    }

    /// The current effective per-epoch rate (what a rental booked now pays).
    pub fn effective_rate(&self) -> u128 {
        self.pricing.read().effective_rate()
    }

    /// Books a compute rental on behalf of `renter` for `total_epochs` at the
    /// current effective per-epoch rate, locked from the renter's pre-funded
    /// deposit. Rejected if it would push the provider's total obligations past
    /// its available stake.
    pub fn book_rental(
        &self,
        renter: Address,
        asset_id: AssetId,
        total_epochs: u64,
    ) -> tenzro_settlement::error::Result<RentalAgreement> {
        let price_per_epoch = self.effective_rate();
        self.manager
            .book_rental(renter, self.provider, asset_id, price_per_epoch, total_epochs)
    }

    /// Settles one epoch of an active rental, gated on the provider's
    /// availability proof for this epoch. A valid proof streams that epoch's
    /// slice to the provider; an invalid/missing proof is a miss (renter made
    /// whole from stake). Repeated misses terminate the rental.
    pub fn settle_epoch(
        &self,
        rental_id: &str,
        proof_valid: bool,
    ) -> tenzro_settlement::error::Result<EpochOutcome> {
        self.manager.settle_epoch(rental_id, proof_valid)
    }

    /// Settles one epoch across every active rental this provider owns. The
    /// running epoch tick is itself the availability proof — a provider that is
    /// down does not run this loop, and its rentals miss by the settlement
    /// layer's own timeout accounting. Returns `(settled, missed, closed)`
    /// counts; per-rental errors are logged and skipped.
    pub fn run_billing_epoch(&self) -> (usize, usize, usize) {
        let rentals = self.manager.get_rentals_by_provider(&self.provider);
        let mut settled = 0usize;
        let mut missed = 0usize;
        let mut closed = 0usize;
        for rental in rentals {
            if rental.status != RentalStatus::Active {
                continue;
            }
            match self.manager.settle_epoch(&rental.rental_id, true) {
                Ok(EpochOutcome::Settled { .. }) => settled += 1,
                Ok(EpochOutcome::Missed { .. }) => missed += 1,
                Ok(EpochOutcome::Closed { .. }) => closed += 1,
                Err(e) => warn!(rental = %rental.rental_id, error = %e, "Rental epoch settle failed"),
            }
        }
        if settled + missed + closed > 0 {
            info!(settled, missed, closed, "Compute rental billing epoch complete");
        }
        (settled, missed, closed)
    }

    /// Re-checks coverage after a provider's stake dropped (e.g. a slash on one
    /// rental), shedding rentals newest-first until coverage holds again.
    pub fn recheck_coverage(&self) -> tenzro_settlement::error::Result<Vec<String>> {
        self.manager.recheck_coverage(&self.provider)
    }

    /// Advances a dynamic pricing policy by one epoch from metered utilization
    /// (`used` of `capacity` epoch-slots). No-op for `Fixed`/`OrderBook`. Call
    /// once per settlement epoch before booking new rentals so they price off
    /// fresh network state.
    pub fn step_pricing(&self, used: u128) {
        let mut guard = self.pricing.write();
        if let PricingPolicy::Dynamic(ref mut dynamic) = *guard {
            let new_rate = dynamic.step(used);
            debug!(rate = new_rate, used, "Stepped dynamic compute price");
        }
    }

    /// Switches this provider to network-dynamic per-epoch pricing seeded from
    /// the current rate. Subsequent epochs step it via [`step_pricing`].
    ///
    /// [`step_pricing`]: ComputeRentalRuntime::step_pricing
    pub fn enable_dynamic_pricing(&self, capacity: u128, min_rate: u128, max_rate: u128) {
        let start = self.effective_rate();
        let dynamic = DynamicPricing::new(ResourceKind::Compute, capacity, start, min_rate, max_rate);
        *self.pricing.write() = PricingPolicy::Dynamic(dynamic);
        info!(
            capacity,
            start_rate = start,
            "Compute provider switched to network-dynamic pricing"
        );
    }
}
