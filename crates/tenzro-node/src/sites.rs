//! Static web hosting: site manifests mapping URL paths to iroh blob hashes,
//! served at `GET /sites/{site_id}/*path` with optional x402 gating.
//!
//! Manifests persist under `CF_METADATA` keyed by `site:<site_id>` with
//! write-through on publish/remove and hydrate-on-boot, matching the other
//! KvStore-prefix registries.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tenzro_crypto::hash::sha256;
use tenzro_storage::{CF_METADATA, KvStore};
use thiserror::Error;
use tracing::{info, warn};

/// Key prefix for site manifests within `CF_METADATA`.
const SITE_PREFIX: &str = "site:";

/// Domain tag for site id derivation.
const SITE_ID_DOMAIN: &[u8] = b"tenzro/sites/id";

const MAX_NAME_LEN: usize = 64;
const MAX_PATH_LEN: usize = 512;
const MAX_CONTENT_TYPE_LEN: usize = 128;

fn site_key(site_id: &str) -> Vec<u8> {
    format!("{}{}", SITE_PREFIX, site_id).into_bytes()
}

/// Derive the deterministic site id from owner DID + site name.
pub fn compute_site_id(owner_did: &str, name: &str) -> String {
    let mut preimage = Vec::with_capacity(SITE_ID_DOMAIN.len() + owner_did.len() + name.len() + 1);
    preimage.extend_from_slice(SITE_ID_DOMAIN);
    preimage.extend_from_slice(owner_did.as_bytes());
    preimage.push(0x00);
    preimage.extend_from_slice(name.as_bytes());
    hex::encode(sha256(&preimage).as_bytes())
}

#[derive(Debug, Error)]
pub enum SiteError {
    #[error("invalid manifest: {0}")]
    InvalidManifest(String),
    #[error("site not found: {0}")]
    NotFound(String),
    #[error("not site owner")]
    NotOwner,
    #[error("storage error: {0}")]
    Storage(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// One published asset within a site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteRoute {
    /// BLAKE3 hex of the blob in the iroh store (64 lowercase hex chars).
    pub blob_hash: String,
    pub content_type: String,
    pub size: u64,
}

/// Published site: routes from URL paths to content-addressed blobs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteManifest {
    pub site_id: String,
    pub name: String,
    pub owner_did: String,
    pub version: u64,
    pub routes: BTreeMap<String, SiteRoute>,
    pub index_path: String,
    pub not_found_path: Option<String>,
    /// TNZO per request; when `Some`, serving is x402-gated.
    pub price_per_request: Option<u128>,
    pub created_at: u64,
    pub updated_at: u64,
}

fn validate_path(path: &str) -> Result<(), SiteError> {
    if !path.starts_with('/') {
        return Err(SiteError::InvalidManifest(format!(
            "route path must start with '/': {path}"
        )));
    }
    if path.len() > MAX_PATH_LEN {
        return Err(SiteError::InvalidManifest("route path too long".into()));
    }
    if path.split('/').any(|seg| seg == "..") {
        return Err(SiteError::InvalidManifest(format!(
            "route path contains '..' segment: {path}"
        )));
    }
    if path.contains(['\r', '\n', '\0']) {
        return Err(SiteError::InvalidManifest(
            "route path contains control characters".into(),
        ));
    }
    Ok(())
}

fn validate_route(path: &str, route: &SiteRoute) -> Result<(), SiteError> {
    validate_path(path)?;
    if route.blob_hash.len() != 64
        || !route
            .blob_hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(SiteError::InvalidManifest(format!(
            "blob_hash must be 64 lowercase hex chars: {path}"
        )));
    }
    let ct = &route.content_type;
    if ct.is_empty()
        || ct.len() > MAX_CONTENT_TYPE_LEN
        || !ct.contains('/')
        || ct.contains(['\r', '\n', '\0'])
    {
        return Err(SiteError::InvalidManifest(format!(
            "invalid content_type for {path}"
        )));
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), SiteError> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(SiteError::InvalidManifest(
            "name must be 1-64 characters".into(),
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return Err(SiteError::InvalidManifest(
            "name may only contain [a-zA-Z0-9._-]".into(),
        ));
    }
    Ok(())
}

/// Configuration for the site subsystem. Standalone struct with defaults —
/// not part of the node TOML config.
#[derive(Debug, Clone)]
pub struct SitesConfig {
    /// Byte cap for the in-memory blob cache.
    pub cache_max_bytes: u64,
    /// Maximum routes per site manifest.
    pub max_routes: usize,
}

impl Default for SitesConfig {
    fn default() -> Self {
        Self {
            cache_max_bytes: 64 * 1024 * 1024,
            max_routes: 4096,
        }
    }
}

impl SitesConfig {
    pub fn with_cache_max_bytes(mut self, bytes: u64) -> Self {
        self.cache_max_bytes = bytes;
        self
    }

    pub fn with_max_routes(mut self, max: usize) -> Self {
        self.max_routes = max;
        self
    }
}

struct CacheEntry {
    bytes: bytes::Bytes,
    last_used: u64,
}

/// LRU byte cache for served blobs, keyed by blob hash.
pub struct SiteBlobCache {
    entries: DashMap<String, CacheEntry>,
    total_bytes: AtomicU64,
    max_bytes: u64,
    tick: AtomicU64,
}

impl SiteBlobCache {
    pub fn new(max_bytes: u64) -> Self {
        Self {
            entries: DashMap::new(),
            total_bytes: AtomicU64::new(0),
            max_bytes,
            tick: AtomicU64::new(0),
        }
    }

    pub fn get(&self, blob_hash: &str) -> Option<bytes::Bytes> {
        let mut entry = self.entries.get_mut(blob_hash)?;
        entry.last_used = self.tick.fetch_add(1, Ordering::Relaxed) + 1;
        Some(entry.bytes.clone())
    }

    pub fn insert(&self, blob_hash: &str, bytes: bytes::Bytes) {
        let len = bytes.len() as u64;
        if len > self.max_bytes {
            return;
        }
        if self.entries.contains_key(blob_hash) {
            return;
        }
        while self.total_bytes.load(Ordering::Relaxed) + len > self.max_bytes {
            if !self.evict_one() {
                break;
            }
        }
        self.entries.insert(
            blob_hash.to_string(),
            CacheEntry {
                bytes,
                last_used: self.tick.fetch_add(1, Ordering::Relaxed) + 1,
            },
        );
        self.total_bytes.fetch_add(len, Ordering::Relaxed);
    }

    fn evict_one(&self) -> bool {
        let mut oldest: Option<(String, u64)> = None;
        for entry in self.entries.iter() {
            match &oldest {
                Some((_, used)) if entry.last_used >= *used => {}
                _ => oldest = Some((entry.key().clone(), entry.last_used)),
            }
        }
        let Some((key, _)) = oldest else {
            return false;
        };
        if let Some((_, removed)) = self.entries.remove(&key) {
            self.total_bytes
                .fetch_sub(removed.bytes.len() as u64, Ordering::Relaxed);
            return true;
        }
        false
    }

    pub fn total_bytes(&self) -> u64 {
        self.total_bytes.load(Ordering::Relaxed)
    }
}

/// Registry of published sites with write-through persistence.
pub struct SiteRegistry {
    sites: DashMap<String, SiteManifest>,
    storage: Option<Arc<dyn KvStore>>,
    config: SitesConfig,
    cache: SiteBlobCache,
}

impl std::fmt::Debug for SiteRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SiteRegistry")
            .field("sites", &self.sites.len())
            .finish()
    }
}

impl SiteRegistry {
    pub fn new() -> Self {
        Self::with_config(SitesConfig::default())
    }

    pub fn with_config(config: SitesConfig) -> Self {
        let cache = SiteBlobCache::new(config.cache_max_bytes);
        Self {
            sites: DashMap::new(),
            storage: None,
            config,
            cache,
        }
    }

    /// Storage-backed registry: hydrates existing manifests from `CF_METADATA`.
    pub fn with_storage(storage: Arc<dyn KvStore>, config: SitesConfig) -> Result<Self, SiteError> {
        let registry = Self {
            sites: DashMap::new(),
            storage: Some(storage.clone()),
            cache: SiteBlobCache::new(config.cache_max_bytes),
            config,
        };
        let keys = storage
            .get_keys_with_prefix(CF_METADATA, SITE_PREFIX.as_bytes())
            .map_err(|e| SiteError::Storage(format!("site scan: {e}")))?;
        let mut restored = 0usize;
        for key in keys {
            match storage.get(CF_METADATA, &key) {
                Ok(Some(bytes)) => match serde_json::from_slice::<SiteManifest>(&bytes) {
                    Ok(manifest) => {
                        registry.sites.insert(manifest.site_id.clone(), manifest);
                        restored += 1;
                    }
                    Err(e) => warn!("skipping undecodable site manifest: {e}"),
                },
                Ok(None) => {}
                Err(e) => return Err(SiteError::Storage(format!("site get: {e}"))),
            }
        }
        if restored > 0 {
            info!("restored {restored} site manifests");
        }
        Ok(registry)
    }

    pub fn blob_cache(&self) -> &SiteBlobCache {
        &self.cache
    }

    fn persist(&self, manifest: &SiteManifest) -> Result<(), SiteError> {
        if let Some(storage) = &self.storage {
            let bytes = serde_json::to_vec(manifest)
                .map_err(|e| SiteError::Serialization(e.to_string()))?;
            storage
                .put(CF_METADATA, &site_key(&manifest.site_id), &bytes)
                .map_err(|e| SiteError::Storage(format!("site put: {e}")))?;
        }
        Ok(())
    }

    /// Publish or republish a site. Republishing the same (owner, name) bumps
    /// `version` and preserves `created_at`; a different owner is rejected.
    pub fn publish_site(
        &self,
        name: &str,
        owner_did: &str,
        routes: BTreeMap<String, SiteRoute>,
        index_path: Option<String>,
        not_found_path: Option<String>,
        price_per_request: Option<u128>,
    ) -> Result<SiteManifest, SiteError> {
        validate_name(name)?;
        if !owner_did.starts_with("did:") {
            return Err(SiteError::InvalidManifest(
                "owner_did must be a DID".into(),
            ));
        }
        if routes.is_empty() {
            return Err(SiteError::InvalidManifest("routes must not be empty".into()));
        }
        if routes.len() > self.config.max_routes {
            return Err(SiteError::InvalidManifest(format!(
                "too many routes (max {})",
                self.config.max_routes
            )));
        }
        for (path, route) in &routes {
            validate_route(path, route)?;
        }
        let index_path = index_path.unwrap_or_else(|| "/index.html".to_string());
        validate_path(&index_path)?;
        if !routes.contains_key(&index_path) {
            return Err(SiteError::InvalidManifest(format!(
                "index_path {index_path} has no route"
            )));
        }
        if let Some(nf) = &not_found_path {
            validate_path(nf)?;
            if !routes.contains_key(nf) {
                return Err(SiteError::InvalidManifest(format!(
                    "not_found_path {nf} has no route"
                )));
            }
        }

        let site_id = compute_site_id(owner_did, name);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let manifest = match self.sites.get(&site_id) {
            Some(existing) => {
                if existing.owner_did != owner_did {
                    return Err(SiteError::NotOwner);
                }
                SiteManifest {
                    site_id: site_id.clone(),
                    name: name.to_string(),
                    owner_did: owner_did.to_string(),
                    version: existing.version + 1,
                    routes,
                    index_path,
                    not_found_path,
                    price_per_request,
                    created_at: existing.created_at,
                    updated_at: now,
                }
            }
            None => SiteManifest {
                site_id: site_id.clone(),
                name: name.to_string(),
                owner_did: owner_did.to_string(),
                version: 1,
                routes,
                index_path,
                not_found_path,
                price_per_request,
                created_at: now,
                updated_at: now,
            },
        };

        self.persist(&manifest)?;
        self.sites.insert(site_id, manifest.clone());
        Ok(manifest)
    }

    pub fn get_site(&self, site_id: &str) -> Option<SiteManifest> {
        self.sites.get(site_id).map(|m| m.clone())
    }

    pub fn list_sites(&self, owner_did: Option<&str>) -> Vec<SiteManifest> {
        self.sites
            .iter()
            .filter(|m| owner_did.is_none_or(|o| m.owner_did == o))
            .map(|m| m.clone())
            .collect()
    }

    /// Remove a site. `owner_did` must match the manifest owner.
    pub fn remove_site(&self, site_id: &str, owner_did: &str) -> Result<SiteManifest, SiteError> {
        {
            let manifest = self
                .sites
                .get(site_id)
                .ok_or_else(|| SiteError::NotFound(site_id.to_string()))?;
            if manifest.owner_did != owner_did {
                return Err(SiteError::NotOwner);
            }
        }
        if let Some(storage) = &self.storage {
            storage
                .delete(CF_METADATA, &site_key(site_id))
                .map_err(|e| SiteError::Storage(format!("site delete: {e}")))?;
        }
        let (_, manifest) = self
            .sites
            .remove(site_id)
            .ok_or_else(|| SiteError::NotFound(site_id.to_string()))?;
        Ok(manifest)
    }
}

impl Default for SiteRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn route(hash_byte: u8) -> SiteRoute {
        SiteRoute {
            blob_hash: hex::encode([hash_byte; 32]),
            content_type: "text/html".to_string(),
            size: 128,
        }
    }

    fn one_page_routes() -> BTreeMap<String, SiteRoute> {
        let mut routes = BTreeMap::new();
        routes.insert("/index.html".to_string(), route(0xaa));
        routes
    }

    #[test]
    fn site_id_is_deterministic_and_owner_scoped() {
        let a = compute_site_id("did:tenzro:human:alice", "blog");
        let b = compute_site_id("did:tenzro:human:alice", "blog");
        let c = compute_site_id("did:tenzro:human:bob", "blog");
        let d = compute_site_id("did:tenzro:human:alice", "docs");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn publish_validates_paths_and_hashes() {
        let registry = SiteRegistry::new();

        let mut bad_path = BTreeMap::new();
        bad_path.insert("index.html".to_string(), route(0x01));
        assert!(
            registry
                .publish_site("s", "did:tenzro:human:a", bad_path, None, None, None)
                .is_err()
        );

        let mut traversal = BTreeMap::new();
        traversal.insert("/../etc/passwd".to_string(), route(0x01));
        assert!(
            registry
                .publish_site("s", "did:tenzro:human:a", traversal, None, None, None)
                .is_err()
        );

        let mut bad_hash = BTreeMap::new();
        bad_hash.insert(
            "/index.html".to_string(),
            SiteRoute {
                blob_hash: "ZZ".to_string(),
                content_type: "text/html".to_string(),
                size: 1,
            },
        );
        assert!(
            registry
                .publish_site("s", "did:tenzro:human:a", bad_hash, None, None, None)
                .is_err()
        );

        let mut bad_ct = BTreeMap::new();
        bad_ct.insert(
            "/index.html".to_string(),
            SiteRoute {
                blob_hash: hex::encode([1u8; 32]),
                content_type: "text/html\r\nX-Injected: 1".to_string(),
                size: 1,
            },
        );
        assert!(
            registry
                .publish_site("s", "did:tenzro:human:a", bad_ct, None, None, None)
                .is_err()
        );

        assert!(
            registry
                .publish_site("bad name!", "did:tenzro:human:a", one_page_routes(), None, None, None)
                .is_err()
        );
        assert!(
            registry
                .publish_site("s", "not-a-did", one_page_routes(), None, None, None)
                .is_err()
        );
    }

    #[test]
    fn index_and_not_found_must_have_routes() {
        let registry = SiteRegistry::new();
        assert!(
            registry
                .publish_site(
                    "s",
                    "did:tenzro:human:a",
                    one_page_routes(),
                    Some("/missing.html".to_string()),
                    None,
                    None,
                )
                .is_err()
        );
        assert!(
            registry
                .publish_site(
                    "s",
                    "did:tenzro:human:a",
                    one_page_routes(),
                    None,
                    Some("/404.html".to_string()),
                    None,
                )
                .is_err()
        );
    }

    #[test]
    fn republish_bumps_version_preserves_created_at() {
        let registry = SiteRegistry::new();
        let v1 = registry
            .publish_site("blog", "did:tenzro:human:a", one_page_routes(), None, None, None)
            .unwrap();
        assert_eq!(v1.version, 1);
        let v2 = registry
            .publish_site("blog", "did:tenzro:human:a", one_page_routes(), None, None, Some(5))
            .unwrap();
        assert_eq!(v2.version, 2);
        assert_eq!(v2.site_id, v1.site_id);
        assert_eq!(v2.created_at, v1.created_at);
        assert_eq!(v2.price_per_request, Some(5));
    }

    #[test]
    fn remove_enforces_owner() {
        let registry = SiteRegistry::new();
        let m = registry
            .publish_site("blog", "did:tenzro:human:a", one_page_routes(), None, None, None)
            .unwrap();
        assert!(matches!(
            registry.remove_site(&m.site_id, "did:tenzro:human:b"),
            Err(SiteError::NotOwner)
        ));
        assert!(registry.remove_site(&m.site_id, "did:tenzro:human:a").is_ok());
        assert!(registry.get_site(&m.site_id).is_none());
    }

    #[test]
    fn list_filters_by_owner() {
        let registry = SiteRegistry::new();
        registry
            .publish_site("a", "did:tenzro:human:a", one_page_routes(), None, None, None)
            .unwrap();
        registry
            .publish_site("b", "did:tenzro:human:b", one_page_routes(), None, None, None)
            .unwrap();
        assert_eq!(registry.list_sites(None).len(), 2);
        assert_eq!(registry.list_sites(Some("did:tenzro:human:a")).len(), 1);
    }

    #[test]
    fn cache_evicts_least_recently_used() {
        let cache = SiteBlobCache::new(100);
        cache.insert("a", bytes::Bytes::from(vec![0u8; 40]));
        cache.insert("b", bytes::Bytes::from(vec![0u8; 40]));
        assert_eq!(cache.total_bytes(), 80);
        // Touch "a" so "b" is oldest.
        assert!(cache.get("a").is_some());
        cache.insert("c", bytes::Bytes::from(vec![0u8; 40]));
        assert!(cache.get("a").is_some());
        assert!(cache.get("b").is_none());
        assert!(cache.get("c").is_some());
        assert_eq!(cache.total_bytes(), 80);
    }

    #[test]
    fn cache_skips_oversized_blobs() {
        let cache = SiteBlobCache::new(10);
        cache.insert("big", bytes::Bytes::from(vec![0u8; 11]));
        assert!(cache.get("big").is_none());
        assert_eq!(cache.total_bytes(), 0);
    }
}
