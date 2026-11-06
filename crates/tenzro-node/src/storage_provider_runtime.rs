//! Node-side storage-provider runtime.
//!
//! Spawned when a node's [`RoleSet`] includes `StorageProvider`. It owns the
//! three pieces a storage provider needs and wires them together:
//!
//! 1. [`StorageProvider`] — erasure-codes objects and publishes/fetches shards
//!    over the node's iroh transport (content-addressed).
//! 2. A fixed byte-epoch [`PricingPolicy`], read at deal-open time. The
//!    rate never follows demand.
//!
//! A renter pays for storage through a compute claim that commits the object's
//! descriptor digest (see [`descriptor_digest`]). Each hour the bond that
//! delivers the claim is found available only while it answers validators'
//! possession probes for that object; the claim settles on those verdicts.
//!
//! [`RoleSet`]: tenzro_types::RoleSet

use std::sync::Arc;

use parking_lot::RwLock;
use tenzro_storage_provider::{ObjectDescriptor, RedundancyScheme, StorageProvider};
use tenzro_types::primitives::Address;
use tracing::{debug, info};

use crate::pricing::PricingPolicy;

/// Owns a node's storage-provider services and the per-epoch billing loop.
pub struct StorageProviderRuntime {
    /// Resolves the local node's provider address — the one credited when
    /// epochs charge and bonded against when deals open.
    ///
    /// A closure rather than a captured `Address` because the address is not
    /// knowable when this runtime is built. `resolve_operator_payee` says so
    /// itself: it is a free function specifically "so background tasks that
    /// outlive a `&self` borrow can re-derive it per tick — an identity
    /// provisioned after startup has to be picked up without a restart".
    ///
    /// Caching it here broke exactly that. The runtime spawns ~1.6s before the
    /// identity registry finishes loading, so the captured value was the
    /// announce-key fallback while every later caller — staking included —
    /// resolved to the identity wallet. A deal would then be bonded against
    /// one address and its stake checked against another, and
    /// `insufficient provider stake ... stake 0` was the only symptom.
    provider: Arc<dyn Fn() -> Option<Address> + Send + Sync>,
    /// Object store over the iroh transport.
    store: Arc<StorageProvider>,
    /// Content-addressed transport, shared with `store`; used to verify
    /// challenges trustlessly (fetch + recompute digests independently).
    resolver: Arc<dyn tenzro_iroh::IrohResolver>,
    /// The byte-epoch pricing policy for this provider, read at deal-open
    /// time.
    pricing: Arc<RwLock<PricingPolicy>>,
}

impl StorageProviderRuntime {
    /// The provider address, resolved now rather than at construction.
    ///
    /// `None` when the node has no resolvable payee yet. Callers must treat
    /// that as "cannot transact", never as the zero address: crediting or
    /// bonding against `Address::default()` silently sends value nowhere.
    fn provider(&self) -> Option<Address> {
        (self.provider)()
    }
}

impl std::fmt::Debug for StorageProviderRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let provider = self.provider();
        f.debug_struct("StorageProviderRuntime")
            .field("provider", &provider)
            .field("objects", &self.store.descriptors().len())
            .finish()
    }
}

impl StorageProviderRuntime {
    /// Builds a runtime over the node's iroh resolver and the chain's stream
    /// escrows. `policy` is the provider's chosen byte-epoch pricing; coverage
    /// enforcement reads the provider's bonded role stake.
    pub fn new(
        provider: Arc<dyn Fn() -> Option<Address> + Send + Sync>,
        resolver: Arc<dyn tenzro_iroh::IrohResolver>,
        policy: PricingPolicy,
    ) -> Self {
        Self::build(provider, resolver, policy, None)
    }

    /// Like [`new`], but persists object descriptors and streaming deals to the
    /// given store (`CF_SETTLEMENTS`) and hydrates both on construction, so a
    /// provider resumes serving held objects and billing open deals after a
    /// restart.
    ///
    /// [`new`]: StorageProviderRuntime::new
    #[allow(clippy::too_many_arguments)]
    pub fn with_storage(
        provider: Arc<dyn Fn() -> Option<Address> + Send + Sync>,
        resolver: Arc<dyn tenzro_iroh::IrohResolver>,
        policy: PricingPolicy,
        storage: Arc<dyn tenzro_storage::KvStore>,
    ) -> Self {
        Self::build(provider, resolver, policy, Some(storage))
    }

    #[allow(clippy::too_many_arguments)]
    fn build(
        provider: Arc<dyn Fn() -> Option<Address> + Send + Sync>,
        resolver: Arc<dyn tenzro_iroh::IrohResolver>,
        policy: PricingPolicy,
        storage: Option<Arc<dyn tenzro_storage::KvStore>>,
    ) -> Self {
        let store = Arc::new(match storage.clone() {
            Some(s) => StorageProvider::with_storage(resolver.clone(), s),
            None => StorageProvider::new(resolver.clone()),
        });
        Self {
            provider,
            store,
            resolver,
            pricing: Arc::new(RwLock::new(policy)),
        }
    }

    /// Convenience constructor for a flat byte-epoch rate.
    pub fn with_fixed_rate(
        provider: Arc<dyn Fn() -> Option<Address> + Send + Sync>,
        resolver: Arc<dyn tenzro_iroh::IrohResolver>,
        rate_per_byte_epoch: u128,
    ) -> Self {
        Self::new(
            provider,
            resolver,
            PricingPolicy::Fixed {
                rate: rate_per_byte_epoch,
            },
        )
    }

    /// The object store, for serving retrievals.
    pub fn store(&self) -> &Arc<StorageProvider> {
        &self.store
    }

    /// The object this provider holds whose descriptor has `digest` (hex
    /// SHA-256 of its bincode encoding), with that encoding.
    pub fn descriptor_by_digest(&self, digest: &str) -> Option<(ObjectDescriptor, Vec<u8>)> {
        self.store.descriptors().into_iter().find_map(|d| {
            let encoded = bincode::serialize(&d).ok()?;
            (descriptor_digest_of(&encoded).eq_ignore_ascii_case(digest)).then_some((d, encoded))
        })
    }

    /// The current effective byte-epoch rate (what a deal opened now pays).
    pub fn effective_rate(&self) -> u128 {
        self.pricing.read().effective_rate()
    }

    /// Stores an object on behalf of `owner`, erasure-coded under `scheme` and
    /// gated by `access_policy`, and returns its content-addressed shard
    /// descriptor. Pass `confidential` to record per-DID wrapped-key envelopes
    /// for a network-tier encrypted object.
    pub async fn store_object(
        &self,
        object_id: impl Into<String>,
        owner_hex: impl Into<String>,
        data: &[u8],
        scheme: RedundancyScheme,
        access_policy: tenzro_types::access_policy::AccessPolicy,
        confidential: Option<tenzro_types::access_policy::ConfidentialSeal>,
    ) -> tenzro_storage_provider::Result<tenzro_storage_provider::ObjectDescriptor> {
        self.store
            .store_object(
                object_id,
                owner_hex,
                data,
                scheme,
                access_policy,
                confidential,
            )
            .await
    }

    /// Answer a possession challenge for `descriptor` from the shards this
    /// node holds: fetch only the shards the nonce selected and prove the
    /// sampled chunks. `None` when a selected shard is not held.
    pub async fn prove_possession(
        &self,
        descriptor: &tenzro_storage_provider::ObjectDescriptor,
        challenge: &tenzro_storage_provider::PdpChallenge,
    ) -> Option<tenzro_storage_provider::PdpProof> {
        let object_id = descriptor.object_id.as_str();

        // The prover side: fetch only the shards the nonce selected, from the
        // blobs this node holds, and prove the sampled chunks of each.
        let positions =
            tenzro_storage_provider::pdp::sample_positions(challenge, &descriptor.shards);
        let mut held = std::collections::HashMap::new();
        for (shard, _) in &positions {
            if held.contains_key(shard) {
                continue;
            }
            let sref = descriptor.shards.iter().find(|s| s.index == *shard)?;
            let Ok(uri) = sref.uri.parse::<tenzro_iroh::TenzroUri>() else {
                return None;
            };
            match self.resolver.fetch_bytes(&uri).await {
                Ok(bytes) => {
                    held.insert(*shard, bytes.to_vec());
                }
                Err(e) => {
                    debug!(object = %object_id, shard, error = %e, "Challenged shard not held");
                    return None;
                }
            }
        }
        match tenzro_storage_provider::prove(challenge, &descriptor.shards, |idx| {
            held.get(&idx).cloned().ok_or(
                tenzro_storage_provider::StorageProviderError::ShardNotFound {
                    object_id: object_id.to_string(),
                    shard_index: idx,
                },
            )
        }) {
            Ok(p) => Some(p),
            Err(e) => {
                debug!(object = %object_id, error = %e, "Failed to answer possession challenge");
                None
            }
        }
    }

    /// Sets this provider's fixed byte-epoch rate, what deals opened from
    /// now on pay.
    pub fn set_fixed_rate(&self, rate: u128) {
        *self.pricing.write() = PricingPolicy::Fixed { rate };
        info!(rate, "Storage provider rate set");
    }
}

/// The digest a storage claim commits for `descriptor`: hex SHA-256 of its
/// bincode encoding.
pub fn descriptor_digest(descriptor: &ObjectDescriptor) -> Option<String> {
    bincode::serialize(descriptor)
        .ok()
        .map(|b| descriptor_digest_of(&b))
}

fn descriptor_digest_of(encoded: &[u8]) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(encoded))
}
