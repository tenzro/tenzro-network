//! x402 Bazaar — resource discovery for paid HTTP resources.
//!
//! The Bazaar extension lets a facilitator publish a catalog of paid
//! resources so buyers (and buyer agents) can discover *what* is purchasable
//! before hitting a 402. A seller registers an [`X402ResourceListing`]
//! describing a resource and the x402 [`X402PaymentRequirement`] that gates
//! it; a buyer queries [`ResourceCatalog::discover`] with a [`ResourceQuery`]
//! filter and gets back the matching listings.
//!
//! The catalog is transport-agnostic: this module owns the data model, the
//! query filter, and a pluggable [`ResourceCatalogStore`] persistence seam.
//! The HTTP surface (`GET /discovery/resources`) and the JSON-RPC surface are
//! the node's concern — the node wires a RocksDB-backed store and exposes the
//! query.
//!
//! # Domain separation
//!
//! Listing ids are derived by domain-separated SHA-256 over the canonical
//! `(seller_did, resource)` pair using the tag [`BAZAAR_LISTING_DOMAIN`], so
//! two sellers advertising the same URL get distinct ids and a seller
//! re-registering the same resource is idempotent.

use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{PaymentError, Result};
use crate::x402::payment_required::X402PaymentRequirement;

/// Domain-separation tag for a Bazaar listing id.
pub const BAZAAR_LISTING_DOMAIN: &str = "tenzro/x402/bazaar-listing";

/// A single discoverable paid resource in the Bazaar.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct X402ResourceListing {
    /// Deterministic id derived from `(seller_did, requirement.resource)`.
    pub listing_id: String,
    /// The TDIP DID of the seller publishing this resource.
    pub seller_did: String,
    /// The x402 payment requirement that gates the resource. Carries the
    /// scheme, network, price, asset, pay-to address, and resource URL.
    pub requirement: X402PaymentRequirement,
    /// Freeform tags for filtering (e.g. `["inference", "vision"]`).
    #[serde(default)]
    pub tags: Vec<String>,
    /// Unix-millis timestamp the listing was last registered/updated.
    pub updated_at_ms: u64,
}

impl X402ResourceListing {
    /// Derive the deterministic listing id for `(seller_did, resource)`.
    pub fn derive_id(seller_did: &str, resource: &str) -> String {
        let mut h = Sha256::new();
        h.update(BAZAAR_LISTING_DOMAIN.as_bytes());
        h.update(seller_did.as_bytes());
        h.update(resource.as_bytes());
        hex::encode(h.finalize())
    }

    /// Construct a listing, deriving `listing_id` from the seller + resource.
    pub fn new(
        seller_did: impl Into<String>,
        requirement: X402PaymentRequirement,
        tags: Vec<String>,
        updated_at_ms: u64,
    ) -> Self {
        let seller_did = seller_did.into();
        let listing_id = Self::derive_id(&seller_did, &requirement.resource);
        Self {
            listing_id,
            seller_did,
            requirement,
            tags,
            updated_at_ms,
        }
    }
}

/// Filter for [`ResourceCatalog::discover`]. All set fields are ANDed; unset
/// fields match everything.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceQuery {
    /// Restrict to a specific x402 scheme (e.g. `"upto"`, `"batch-settlement"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scheme: Option<String>,
    /// Restrict to a specific CAIP-2 network (e.g. `"eip155:1337"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,
    /// Restrict to a specific asset (e.g. `"USDC"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset: Option<String>,
    /// Restrict to a specific seller DID.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seller_did: Option<String>,
    /// Require all of these tags to be present on the listing.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    /// Cap the number of listings returned (0 = unbounded).
    #[serde(default)]
    pub limit: usize,
}

impl ResourceQuery {
    /// Whether `listing` satisfies every set field of this query.
    pub fn matches(&self, listing: &X402ResourceListing) -> bool {
        if let Some(s) = &self.scheme
            && &listing.requirement.scheme != s
        {
            return false;
        }
        if let Some(n) = &self.network
            && &listing.requirement.network != n
        {
            return false;
        }
        if let Some(a) = &self.asset
            && &listing.requirement.asset != a
        {
            return false;
        }
        if let Some(d) = &self.seller_did
            && &listing.seller_did != d
        {
            return false;
        }
        for want in &self.tags {
            if !listing.tags.iter().any(|t| t == want) {
                return false;
            }
        }
        true
    }
}

/// Persistence seam for the resource catalog. The default in-memory
/// implementation lives on [`ResourceCatalog`]; the node injects a
/// RocksDB-backed store so listings survive restart.
pub trait ResourceCatalogStore: Send + Sync + std::fmt::Debug {
    /// Persist (insert or replace) a listing keyed by `listing_id`.
    fn put(&self, listing: &X402ResourceListing) -> Result<()>;
    /// Remove a listing by id. Returns whether a listing was removed.
    fn remove(&self, listing_id: &str) -> Result<bool>;
    /// Load every listing (used to hydrate the in-memory index on boot).
    fn load_all(&self) -> Result<Vec<X402ResourceListing>>;
}

/// The Bazaar resource catalog. Holds an in-memory index for fast discovery
/// and optionally a durable [`ResourceCatalogStore`] behind it.
#[derive(Debug)]
pub struct ResourceCatalog {
    /// listing_id → listing.
    index: RwLock<std::collections::HashMap<String, X402ResourceListing>>,
    store: Option<Arc<dyn ResourceCatalogStore>>,
}

impl Default for ResourceCatalog {
    fn default() -> Self {
        Self::new()
    }
}

impl ResourceCatalog {
    /// Create an empty in-memory catalog with no durable backing.
    pub fn new() -> Self {
        Self {
            index: RwLock::new(std::collections::HashMap::new()),
            store: None,
        }
    }

    /// Create a catalog backed by `store`, hydrating the in-memory index from
    /// whatever the store already holds.
    pub fn with_store(store: Arc<dyn ResourceCatalogStore>) -> Result<Self> {
        let existing = store.load_all()?;
        let mut index = std::collections::HashMap::with_capacity(existing.len());
        for l in existing {
            index.insert(l.listing_id.clone(), l);
        }
        Ok(Self {
            index: RwLock::new(index),
            store: Some(store),
        })
    }

    /// Register (or replace) a listing. Writes through to the durable store
    /// when one is configured. Returns the derived listing id.
    pub fn register(&self, listing: X402ResourceListing) -> Result<String> {
        if listing.seller_did.is_empty() {
            return Err(PaymentError::ChallengeError(
                "bazaar listing seller_did must not be empty".to_string(),
            ));
        }
        if listing.requirement.resource.is_empty() {
            return Err(PaymentError::ChallengeError(
                "bazaar listing resource must not be empty".to_string(),
            ));
        }
        // Re-derive the id so a client can't spoof another seller's listing id.
        let expected =
            X402ResourceListing::derive_id(&listing.seller_did, &listing.requirement.resource);
        let listing = X402ResourceListing {
            listing_id: expected.clone(),
            ..listing
        };
        if let Some(store) = &self.store {
            store.put(&listing)?;
        }
        self.index.write().insert(expected.clone(), listing);
        Ok(expected)
    }

    /// Remove a listing by id. A seller may only remove its own listing — the
    /// caller supplies `seller_did` and the removal is refused if it does not
    /// own the listing.
    pub fn deregister(&self, listing_id: &str, seller_did: &str) -> Result<bool> {
        {
            let idx = self.index.read();
            match idx.get(listing_id) {
                None => return Ok(false),
                Some(l) if l.seller_did != seller_did => {
                    return Err(PaymentError::ChallengeError(
                        "bazaar listing can only be removed by its seller".to_string(),
                    ));
                }
                Some(_) => {}
            }
        }
        if let Some(store) = &self.store {
            store.remove(listing_id)?;
        }
        Ok(self.index.write().remove(listing_id).is_some())
    }

    /// Fetch a single listing by id.
    pub fn get(&self, listing_id: &str) -> Option<X402ResourceListing> {
        self.index.read().get(listing_id).cloned()
    }

    /// Discover listings matching `query`. Results are sorted by
    /// `updated_at_ms` descending (freshest first) and truncated to
    /// `query.limit` when non-zero.
    pub fn discover(&self, query: &ResourceQuery) -> Vec<X402ResourceListing> {
        let mut out: Vec<X402ResourceListing> = self
            .index
            .read()
            .values()
            .filter(|l| query.matches(l))
            .cloned()
            .collect();
        out.sort_by(|a, b| b.updated_at_ms.cmp(&a.updated_at_ms));
        if query.limit > 0 && out.len() > query.limit {
            out.truncate(query.limit);
        }
        out
    }

    /// Number of listings currently indexed.
    pub fn len(&self) -> usize {
        self.index.read().len()
    }

    /// Whether the catalog holds no listings.
    pub fn is_empty(&self) -> bool {
        self.index.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requirement(scheme: &str, network: &str, asset: &str, resource: &str) -> X402PaymentRequirement {
        X402PaymentRequirement::new(
            scheme,
            network,
            "1000",
            "0xrecipient",
            asset,
            resource,
            "Test resource",
            "application/json",
            300,
        )
    }

    fn listing(seller: &str, scheme: &str, network: &str, asset: &str, resource: &str, tags: &[&str], ts: u64) -> X402ResourceListing {
        X402ResourceListing::new(
            seller,
            requirement(scheme, network, asset, resource),
            tags.iter().map(|s| s.to_string()).collect(),
            ts,
        )
    }

    #[test]
    fn listing_id_is_deterministic_and_seller_scoped() {
        let a = X402ResourceListing::derive_id("did:tenzro:machine:seller-a", "https://x/r");
        let a2 = X402ResourceListing::derive_id("did:tenzro:machine:seller-a", "https://x/r");
        let b = X402ResourceListing::derive_id("did:tenzro:machine:seller-b", "https://x/r");
        assert_eq!(a, a2);
        assert_ne!(a, b);
    }

    #[test]
    fn register_rederives_id_and_is_idempotent() {
        let cat = ResourceCatalog::new();
        let mut l = listing("did:s", "upto", "eip155:1337", "USDC", "https://x/r", &["ai"], 1);
        // Spoof a bogus id — register must overwrite it with the derived one.
        l.listing_id = "attacker-supplied".to_string();
        let id = cat.register(l).unwrap();
        assert_eq!(id, X402ResourceListing::derive_id("did:s", "https://x/r"));
        assert_eq!(cat.len(), 1);
        // Re-register the same resource → same id, still one entry.
        let id2 = cat
            .register(listing("did:s", "upto", "eip155:1337", "USDC", "https://x/r", &["ai"], 2))
            .unwrap();
        assert_eq!(id, id2);
        assert_eq!(cat.len(), 1);
        assert_eq!(cat.get(&id).unwrap().updated_at_ms, 2);
    }

    #[test]
    fn register_rejects_empty_seller_or_resource() {
        let cat = ResourceCatalog::new();
        let mut l = listing("", "upto", "eip155:1337", "USDC", "https://x/r", &[], 1);
        assert!(matches!(cat.register(l).unwrap_err(), PaymentError::ChallengeError(_)));
        l = listing("did:s", "upto", "eip155:1337", "USDC", "", &[], 1);
        assert!(matches!(cat.register(l).unwrap_err(), PaymentError::ChallengeError(_)));
    }

    #[test]
    fn discover_filters_by_scheme_network_asset_and_tags() {
        let cat = ResourceCatalog::new();
        cat.register(listing("did:s", "upto", "eip155:1337", "USDC", "https://x/a", &["ai", "vision"], 3)).unwrap();
        cat.register(listing("did:s", "batch-settlement", "eip155:1337", "USDC", "https://x/b", &["ai"], 2)).unwrap();
        cat.register(listing("did:s", "upto", "eip155:8453", "EURC", "https://x/c", &["storage"], 1)).unwrap();

        // scheme filter
        let q = ResourceQuery { scheme: Some("upto".into()), ..Default::default() };
        let r = cat.discover(&q);
        assert_eq!(r.len(), 2);

        // scheme + tag filter
        let q = ResourceQuery { scheme: Some("upto".into()), tags: vec!["vision".into()], ..Default::default() };
        let r = cat.discover(&q);
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].requirement.resource, "https://x/a");

        // asset filter
        let q = ResourceQuery { asset: Some("EURC".into()), ..Default::default() };
        assert_eq!(cat.discover(&q).len(), 1);

        // network filter
        let q = ResourceQuery { network: Some("eip155:1337".into()), ..Default::default() };
        assert_eq!(cat.discover(&q).len(), 2);
    }

    #[test]
    fn discover_sorts_fresh_first_and_honors_limit() {
        let cat = ResourceCatalog::new();
        cat.register(listing("did:s", "upto", "n", "USDC", "https://x/old", &[], 1)).unwrap();
        cat.register(listing("did:s", "upto", "n", "USDC", "https://x/new", &[], 9)).unwrap();
        cat.register(listing("did:s", "upto", "n", "USDC", "https://x/mid", &[], 5)).unwrap();

        let all = cat.discover(&ResourceQuery::default());
        assert_eq!(all[0].requirement.resource, "https://x/new");
        assert_eq!(all[2].requirement.resource, "https://x/old");

        let limited = cat.discover(&ResourceQuery { limit: 2, ..Default::default() });
        assert_eq!(limited.len(), 2);
        assert_eq!(limited[0].requirement.resource, "https://x/new");
        assert_eq!(limited[1].requirement.resource, "https://x/mid");
    }

    #[test]
    fn deregister_is_seller_scoped() {
        let cat = ResourceCatalog::new();
        let id = cat
            .register(listing("did:owner", "upto", "n", "USDC", "https://x/r", &[], 1))
            .unwrap();
        // Wrong seller is refused.
        assert!(matches!(
            cat.deregister(&id, "did:intruder").unwrap_err(),
            PaymentError::ChallengeError(_)
        ));
        assert_eq!(cat.len(), 1);
        // Owner succeeds.
        assert!(cat.deregister(&id, "did:owner").unwrap());
        assert!(cat.is_empty());
        // Removing again is a no-op.
        assert!(!cat.deregister(&id, "did:owner").unwrap());
    }

    #[derive(Debug, Default)]
    struct MemStore {
        rows: RwLock<std::collections::HashMap<String, X402ResourceListing>>,
    }
    impl ResourceCatalogStore for MemStore {
        fn put(&self, listing: &X402ResourceListing) -> Result<()> {
            self.rows.write().insert(listing.listing_id.clone(), listing.clone());
            Ok(())
        }
        fn remove(&self, listing_id: &str) -> Result<bool> {
            Ok(self.rows.write().remove(listing_id).is_some())
        }
        fn load_all(&self) -> Result<Vec<X402ResourceListing>> {
            Ok(self.rows.read().values().cloned().collect())
        }
    }

    #[test]
    fn store_backed_catalog_writes_through_and_hydrates() {
        let store = Arc::new(MemStore::default());
        {
            let cat = ResourceCatalog::with_store(store.clone()).unwrap();
            cat.register(listing("did:s", "upto", "n", "USDC", "https://x/r", &[], 1)).unwrap();
            assert_eq!(store.rows.read().len(), 1);
        }
        // A fresh catalog over the same store hydrates the prior listing.
        let cat2 = ResourceCatalog::with_store(store.clone()).unwrap();
        assert_eq!(cat2.len(), 1);
    }
}
