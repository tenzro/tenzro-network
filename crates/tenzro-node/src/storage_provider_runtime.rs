//! Node-side storage-provider runtime.
//!
//! Spawned when a node's [`RoleSet`] includes `StorageProvider`. It owns the
//! three pieces a storage provider needs and wires them together:
//!
//! 1. [`StorageProvider`] — erasure-codes objects and publishes/fetches shards
//!    over the node's iroh transport (content-addressed).
//! 2. [`StorageMeter`] — opens per-object streaming deals, holds the renter's
//!    pre-funded deposit, and streams one epoch's slice to the provider each
//!    epoch *only when a retrievability challenge passes*. Cross-service stake
//!    coverage (storage + rentals against one stake) is enforced through the
//!    shared [`ProviderObligations`] tracker.
//! 3. A per-resource [`PricingPolicy`] — `Fixed`, network-`Dynamic`
//!    (EIP-1559 controller), or `OrderBook`. The effective byte-epoch rate is
//!    read at deal-open time; a dynamic policy steps once per epoch from
//!    metered utilization.
//!
//! The charge tick is PoR-gated: for each active deal the runtime draws a fresh
//! challenge over a random shard subset, answers it from local bytes, verifies
//! the answer trustlessly over the transport, and only then charges the epoch.
//! A failed challenge is a miss (renter not charged); repeated misses terminate
//! the deal — the slash signal the settlement layer consumes.
//!
//! [`RoleSet`]: tenzro_types::RoleSet

use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::RwLock;
use tenzro_settlement::obligations::ProviderObligations;
use tenzro_settlement::rental::StakeLedger;
use tenzro_storage_market::{
    answer_challenge, new_challenge, verify_challenge, ChargeOutcome, RedundancyScheme,
    StorageDeal, StorageMeter, StoragePricing, StorageProvider,
};
use tenzro_types::asset::AssetId;
use tenzro_types::primitives::Address;
use tracing::{debug, info, warn};

use crate::pricing::{DynamicPricing, PricingPolicy, ResourceKind};

/// Adapts the node's [`StakingManager`] to the settlement [`StakeLedger`] trait
/// so storage coverage draws on the same bonded stake as everything else. The
/// make-whole path is a genuine slash on the staking ledger.
///
/// [`StakingManager`]: tenzro_token::StakingManager
pub struct StakingStakeLedger {
    staking: Arc<tenzro_token::StakingManager>,
}

impl StakingStakeLedger {
    pub fn new(staking: Arc<tenzro_token::StakingManager>) -> Self {
        Self { staking }
    }
}

impl StakeLedger for StakingStakeLedger {
    fn available_stake(&self, provider: &Address) -> u128 {
        self.staking
            .get_stake(provider)
            .map(|info| info.amount)
            .unwrap_or(0)
    }

    fn slash_to_make_whole(&self, provider: &Address, renter: &Address, amount: u128) -> u128 {
        let available = self.available_stake(provider);
        let debit = amount.min(available);
        if debit == 0 {
            return 0;
        }
        match self.staking.slash(
            provider,
            debit,
            format!("storage make-whole to renter {}", renter),
            Address::default(),
        ) {
            Ok(()) => debit,
            Err(e) => {
                warn!(provider = %provider, error = %e, "Storage make-whole slash failed");
                0
            }
        }
    }
}

/// Number of shards sampled per retrievability challenge each epoch.
const CHALLENGE_SAMPLE_SIZE: usize = 3;

/// Consecutive missed challenges before a deal is terminated and the object is
/// flagged for re-replication.
const DEFAULT_MISS_THRESHOLD: u32 = 3;

/// Owns a node's storage-provider services and the per-epoch billing loop.
pub struct StorageProviderRuntime {
    /// The local node's provider address (credited when epochs charge).
    provider: Address,
    /// Object store over the iroh transport.
    store: Arc<StorageProvider>,
    /// Streaming-deal billing + cross-service coverage.
    meter: Arc<StorageMeter>,
    /// Content-addressed transport, shared with `store`; used to verify
    /// challenges trustlessly (fetch + recompute digests independently).
    resolver: Arc<dyn tenzro_iroh::IrohResolver>,
    /// The byte-epoch pricing policy for this provider. Read at deal-open time;
    /// a dynamic policy advances once per epoch from metered utilization.
    pricing: Arc<RwLock<PricingPolicy>>,
}

impl std::fmt::Debug for StorageProviderRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageProviderRuntime")
            .field("provider", &self.provider)
            .field("deals", &self.meter.active_exposure(&self.provider))
            .finish()
    }
}

impl StorageProviderRuntime {
    /// Builds a runtime over the node's iroh resolver and shared settlement
    /// balances. `policy` is the provider's chosen byte-epoch pricing; coverage
    /// enforcement is wired through the shared stake ledger + obligations
    /// tracker so storage and rental exposure share one stake.
    pub fn new(
        provider: Address,
        resolver: Arc<dyn tenzro_iroh::IrohResolver>,
        balances: Arc<DashMap<(Address, AssetId), u128>>,
        stake_ledger: Arc<dyn StakeLedger>,
        obligations: Arc<ProviderObligations>,
        policy: PricingPolicy,
    ) -> Self {
        let store = Arc::new(StorageProvider::new(resolver.clone()));
        let pricing = StoragePricing::new(policy.effective_rate());
        let meter = Arc::new(
            StorageMeter::new(pricing, balances, DEFAULT_MISS_THRESHOLD)
                .with_coverage(stake_ledger, obligations),
        );
        Self {
            provider,
            store,
            meter,
            resolver,
            pricing: Arc::new(RwLock::new(policy)),
        }
    }

    /// Convenience constructor for a flat byte-epoch rate.
    pub fn with_fixed_rate(
        provider: Address,
        resolver: Arc<dyn tenzro_iroh::IrohResolver>,
        balances: Arc<DashMap<(Address, AssetId), u128>>,
        stake_ledger: Arc<dyn StakeLedger>,
        obligations: Arc<ProviderObligations>,
        rate_per_byte_epoch: u128,
    ) -> Self {
        Self::new(
            provider,
            resolver,
            balances,
            stake_ledger,
            obligations,
            PricingPolicy::Fixed {
                rate: rate_per_byte_epoch,
            },
        )
    }

    /// The object store, for serving retrievals.
    pub fn store(&self) -> &Arc<StorageProvider> {
        &self.store
    }

    /// The billing meter, for deal lookups / status RPCs.
    pub fn meter(&self) -> &Arc<StorageMeter> {
        &self.meter
    }

    /// The current effective byte-epoch rate (what a deal opened now pays).
    pub fn effective_rate(&self) -> u128 {
        self.pricing.read().effective_rate()
    }

    /// Stores an object on behalf of `owner`, erasure-coded under `scheme`, and
    /// returns its content-addressed shard descriptor.
    pub async fn store_object(
        &self,
        object_id: impl Into<String>,
        owner_hex: impl Into<String>,
        data: &[u8],
        scheme: RedundancyScheme,
    ) -> tenzro_storage_market::Result<()> {
        self.store
            .store_object(object_id, owner_hex, data, scheme)
            .await
            .map(|_| ())
    }

    /// Opens a streaming storage deal for an already-stored object. The
    /// per-epoch price is `size_bytes × effective_rate`, locked from the
    /// renter's pre-funded deposit. Rejected if it would push the provider's
    /// total obligations past its available stake.
    pub fn open_deal(
        &self,
        object_id: impl Into<String>,
        renter: Address,
        asset_id: AssetId,
        size_bytes: u64,
        total_epochs: u64,
    ) -> tenzro_storage_market::Result<StorageDeal> {
        self.meter.open_deal(
            object_id,
            renter,
            self.provider,
            asset_id,
            size_bytes,
            total_epochs,
        )
    }

    /// Runs one PoR-gated charge epoch for a single deal.
    ///
    /// Draws a fresh challenge over a random shard subset of the deal's object,
    /// answers it from the local shards, and verifies the answer over the
    /// transport. Charges the epoch only when the challenge passes; a failure
    /// is recorded as a miss (renter unbilled).
    pub async fn charge_epoch(
        &self,
        deal_id: &str,
    ) -> tenzro_storage_market::Result<ChargeOutcome> {
        let deal = self.meter.deal(deal_id)?;
        let passed = self.run_challenge(&deal.object_id).await;
        if !passed {
            warn!(
                deal = %deal_id,
                object = %deal.object_id,
                "Retrievability challenge failed; charging as a miss"
            );
        }
        self.meter.charge_epoch(deal_id, passed)
    }

    /// Draws, answers, and verifies a retrievability challenge for `object_id`.
    /// Returns `true` iff the provider can prove it still holds the sampled
    /// shards. Any error (missing descriptor, unanswerable shard, verification
    /// failure) resolves to `false` — an unprovable object is a miss.
    async fn run_challenge(&self, object_id: &str) -> bool {
        let descriptor = match self.store.descriptor(object_id) {
            Ok(d) => d,
            Err(e) => {
                debug!(object = %object_id, error = %e, "No descriptor to challenge");
                return false;
            }
        };

        let challenge = new_challenge(&descriptor, CHALLENGE_SAMPLE_SIZE);

        // Answer from local shards. The store reconstructs the object and we
        // re-encode to recover individual shard bytes the challenge sampled.
        let object_bytes = match self.store.retrieve_object(object_id).await {
            Ok(b) => b,
            Err(e) => {
                debug!(object = %object_id, error = %e, "Cannot answer challenge: object unretrievable");
                return false;
            }
        };
        let shards = match tenzro_storage_market::encode(&object_bytes, descriptor.scheme) {
            Ok(s) => s,
            Err(e) => {
                debug!(object = %object_id, error = %e, "Cannot re-encode shards to answer challenge");
                return false;
            }
        };

        let response = match answer_challenge(&challenge, |idx| {
            shards
                .iter()
                .find(|s| s.index == idx)
                .map(|s| s.bytes.clone())
                .ok_or_else(|| tenzro_storage_market::StorageMarketError::ShardNotFound {
                    object_id: object_id.to_string(),
                    shard_index: idx,
                })
        }) {
            Ok(r) => r,
            Err(e) => {
                debug!(object = %object_id, error = %e, "Failed to answer own challenge");
                return false;
            }
        };

        match verify_challenge(&descriptor, &challenge, &response, &self.resolver).await {
            Ok(()) => true,
            Err(e) => {
                debug!(object = %object_id, error = %e, "Challenge verification failed");
                false
            }
        }
    }

    /// Advances a dynamic pricing policy by one epoch from metered utilization
    /// (`used` of `capacity` byte-epochs). No-op for `Fixed`/`OrderBook`. Call
    /// this once per settlement epoch before opening new deals so the next
    /// deals price off fresh network state.
    pub fn step_pricing(&self, used: u128) {
        let mut guard = self.pricing.write();
        if let PricingPolicy::Dynamic(ref mut dynamic) = *guard {
            let new_rate = dynamic.step(used);
            debug!(rate = new_rate, used, "Stepped dynamic storage price");
        }
    }

    /// Switches this provider to network-dynamic byte-epoch pricing seeded from
    /// the current rate. Subsequent epochs step it via [`step_pricing`].
    ///
    /// [`step_pricing`]: StorageProviderRuntime::step_pricing
    pub fn enable_dynamic_pricing(&self, capacity: u128, min_rate: u128, max_rate: u128) {
        let start = self.effective_rate();
        let dynamic = DynamicPricing::new(ResourceKind::Storage, capacity, start, min_rate, max_rate);
        *self.pricing.write() = PricingPolicy::Dynamic(dynamic);
        info!(
            capacity,
            start_rate = start,
            "Storage provider switched to network-dynamic pricing"
        );
    }
}
