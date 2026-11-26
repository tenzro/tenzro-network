//! The verification levels a gossiped model offer can be routed at.
//!
//! Providers broadcast signed model offers on `tenzro/models` and provider
//! announcements on their own topic; the event loop keeps the unexpired sets in
//! [`crate::node::NetworkModelEntry`] and [`crate::node::NetworkProviderEntry`]
//! records. [`GossipNetworkCatalog::checked_capacity`] joins the two and cuts a
//! provider's announced levels to those this node can check for itself.

use std::sync::Arc;

use dashmap::DashMap;
use tenzro_network::ModelRegistrationMessage;

use crate::node::{NetworkModelEntry, NetworkProviderEntry};

/// The gossip announcement maps, read for an offer's checked capacity.
pub struct GossipNetworkCatalog {
    models: Arc<DashMap<String, NetworkModelEntry>>,
    /// The provider-announcement map, keyed by iroh endpoint id, joined onto each
    /// model offer to recover the serving envelope. `None` leaves every offer
    /// without a capacity.
    providers: Option<Arc<DashMap<String, NetworkProviderEntry>>>,
    /// Chain state, whose compute bonds decide whether a provider's claim to
    /// serve optimistic answers is backed by a bond.
    chain: Option<Arc<dyn tenzro_storage::KvStore>>,
}

impl GossipNetworkCatalog {
    /// Wraps the node's announcement map.
    pub fn new(models: Arc<DashMap<String, NetworkModelEntry>>) -> Self {
        Self {
            models,
            providers: None,
            chain: None,
        }
    }

    /// Checks providers' optimistic-level claims against the compute bonds
    /// in this chain state.
    #[must_use]
    pub fn with_chain(mut self, chain: Option<Arc<dyn tenzro_storage::KvStore>>) -> Self {
        self.chain = chain;
        self
    }

    /// The provider's announced capacity with its verification levels cut to
    /// those this node can check (see
    /// [`crate::verifiable_inference::routable_levels`]).
    pub(crate) fn checked_capacity(
        &self,
        reg: &ModelRegistrationMessage,
    ) -> Option<tenzro_types::AdvertisedCapacity> {
        let mut capacity = self.capacity_for(&reg.iroh_endpoint_id)?;
        let tee_vendor = self
            .providers
            .as_ref()
            .and_then(|p| {
                p.get(&reg.iroh_endpoint_id)
                    .map(|e| e.announcement.trust_profile.tee_vendor.clone())
            })
            .unwrap_or_default();
        let bonded = self.chain.as_ref().is_some_and(|store| {
            crate::verifiable_inference::bonded_machine(
                &tenzro_vm::StateAdapter::with_storage(store.clone()),
                &reg.machine_did,
            )
        });
        let witnesses = self
            .models
            .iter()
            .filter(|e| {
                e.registration.model_id == reg.model_id && e.registration.provider != reg.provider
            })
            .count();
        capacity.verification = crate::verifiable_inference::routable_levels(
            &capacity.verification,
            &tee_vendor,
            bonded,
            witnesses,
        );
        Some(capacity)
    }

    /// Joins provider announcements onto offers. The two live on separate
    /// gossip topics with separate TTLs; a model offer names its
    /// `iroh_endpoint_id`, and the provider announcement is keyed by exactly that.
    #[must_use]
    pub fn with_providers(mut self, providers: Arc<DashMap<String, NetworkProviderEntry>>) -> Self {
        self.providers = Some(providers);
        self
    }

    /// The serving envelope the endpoint `endpoint_id` last announced, if it
    /// is still within its own TTL.
    ///
    /// TTL is rechecked here rather than trusted from the model offer: the two
    /// announcements expire independently.
    fn capacity_for(&self, endpoint_id: &str) -> Option<tenzro_types::AdvertisedCapacity> {
        let providers = self.providers.as_ref()?;
        let entry = providers.get(endpoint_id)?;
        let ttl = std::time::Duration::from_secs(entry.announcement.ttl_secs);
        if std::time::Instant::now().duration_since(entry.last_seen) >= ttl {
            return None;
        }
        Some(entry.announcement.capacity.clone())
    }
}
