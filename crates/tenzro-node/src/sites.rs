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
use hickory_resolver::Resolver;
use hickory_resolver::config::ResolverOpts;
use hickory_resolver::proto::rr::RData;
use serde::{Deserialize, Serialize};
use tenzro_crypto::hash::sha256;
use tenzro_storage::{CF_METADATA, KvStore};
use thiserror::Error;
use tracing::{info, warn};

/// Key prefix for site manifests within `CF_METADATA`.
const SITE_PREFIX: &str = "site:";

/// Key prefix for hostname → site-id alias records within `CF_METADATA`.
const ALIAS_PREFIX: &str = "site_alias:";

/// Key prefix for custom-domain ownership records within `CF_METADATA`.
const DOMAIN_PREFIX: &str = "site_domain:";

/// Domain tag for site id derivation.
const SITE_ID_DOMAIN: &[u8] = b"tenzro/sites/id";

/// Domain tag for the ownership-challenge token derivation.
const OWNERSHIP_TOKEN_DOMAIN: &[u8] = b"tenzro/sites/ownership";

/// DNS label prefixed to a custom domain for the ownership TXT record. A caller
/// proves control of `example.com` by publishing the challenge token as a TXT
/// value at `_tenzro-ownership.example.com`.
const OWNERSHIP_TXT_LABEL: &str = "_tenzro-ownership";

const MAX_NAME_LEN: usize = 64;
const MAX_PATH_LEN: usize = 512;
const MAX_CONTENT_TYPE_LEN: usize = 128;
const MAX_HOSTNAME_LEN: usize = 253;

fn site_key(site_id: &str) -> Vec<u8> {
    format!("{}{}", SITE_PREFIX, site_id).into_bytes()
}

fn alias_key(hostname: &str) -> Vec<u8> {
    format!("{}{}", ALIAS_PREFIX, hostname).into_bytes()
}

fn domain_key(hostname: &str) -> Vec<u8> {
    format!("{}{}", DOMAIN_PREFIX, hostname).into_bytes()
}

/// Derive the deterministic ownership-challenge token for a domain. Binding the
/// token to the domain and owner DID means two owners claiming the same domain
/// get distinct tokens, and the token can be recomputed for re-verification
/// without storing a secret. Returns 64 lowercase hex chars.
pub fn compute_ownership_token(hostname: &str, owner_did: &str) -> String {
    let mut preimage =
        Vec::with_capacity(OWNERSHIP_TOKEN_DOMAIN.len() + hostname.len() + owner_did.len() + 1);
    preimage.extend_from_slice(OWNERSHIP_TOKEN_DOMAIN);
    preimage.extend_from_slice(hostname.as_bytes());
    preimage.push(0x00);
    preimage.extend_from_slice(owner_did.as_bytes());
    hex::encode(sha256(&preimage).as_bytes())
}

/// The `_tenzro-ownership.<domain>` name a caller publishes the token at.
pub fn ownership_txt_name(hostname: &str) -> String {
    format!("{OWNERSHIP_TXT_LABEL}.{hostname}")
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
    #[error("dns error: {0}")]
    Dns(String),
    #[error("ownership challenge not found in DNS TXT at {name}")]
    ChallengeNotFound { name: String },
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
    /// Single-page-app fallback. When true, a request that matches no route and
    /// is not an asset request (no file extension in the last path segment)
    /// serves `index_path` with HTTP 200 so client-side routers own the URL
    /// space. Asset misses (a path whose last segment has an extension) still
    /// fall through to `not_found_path` / 404 so a missing bundle chunk is not
    /// masked as the index page.
    #[serde(default)]
    pub spa: bool,
    /// TNZO per request; when `Some`, serving is x402-gated.
    pub price_per_request: Option<u128>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Points a public hostname at a specific site. The alias is the naming layer:
/// `myapp.apps.tenzro.xyz → <site_id>` so the edge resolves an incoming Host
/// header to a manifest without exposing the raw site id. Persisted under
/// `CF_METADATA` keyed `site_alias:<hostname>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteAlias {
    /// Lowercased hostname (the Host header value, no port).
    pub hostname: String,
    pub site_id: String,
    /// DID that owns the target site — must match the manifest owner at set
    /// time so a caller cannot alias a hostname onto another owner's site.
    pub owner_did: String,
    pub created_at: u64,
    pub updated_at: u64,
}

/// A custom domain a caller wants to serve a site under (`myapp.com`), plus its
/// ownership-verification state. Caddy on-demand TLS issues a certificate for a
/// domain only after the ask endpoint confirms a `Verified` record here, so the
/// registry is the anti-flood gate: an unverified or unknown domain never
/// triggers ACME issuance. Persisted under `CF_METADATA` keyed
/// `site_domain:<hostname>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomDomain {
    /// Lowercased apex or subdomain (no port).
    pub hostname: String,
    /// DID that claimed the domain — must match the target site's owner.
    pub owner_did: String,
    /// Site the domain resolves to once verified.
    pub site_id: String,
    /// Challenge token published at `_tenzro-ownership.<hostname>` as a TXT
    /// value. Deterministic from (hostname, owner_did).
    pub ownership_token: String,
    /// Whether the DNS TXT challenge has been confirmed. The ask endpoint gates
    /// TLS issuance on this.
    pub verified: bool,
    /// Millisecond timestamp of the last successful verification, if any.
    pub verified_at: Option<u64>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Normalize a hostname for alias lookup: strip any `:port`, lowercase, trim a
/// single trailing dot. Returns `None` for empty or over-long names.
pub fn normalize_hostname(raw: &str) -> Option<String> {
    let host = raw.split(':').next().unwrap_or(raw).trim();
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > MAX_HOSTNAME_LEN {
        return None;
    }
    if host
        .bytes()
        .any(|b| !(b.is_ascii_alphanumeric() || b == b'-' || b == b'.'))
    {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

/// Whether a request path targets a concrete asset (its final segment carries a
/// file extension) rather than a client-router route. Used by the SPA fallback:
/// asset misses must 404, route misses serve the index.
pub fn is_asset_path(path: &str) -> bool {
    let last = path.rsplit('/').next().unwrap_or("");
    matches!(last.rfind('.'), Some(dot) if dot > 0 && dot < last.len() - 1)
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

/// Configuration for the site subsystem. Defaults for the byte/route caps;
/// the app-edge fields are supplied by the operator (site hosting is
/// operator-served under the operator's own domain, not network-served under
/// any single canonical host).
#[derive(Debug, Clone)]
pub struct SitesConfig {
    /// Byte cap for the in-memory blob cache.
    pub cache_max_bytes: u64,
    /// Maximum routes per site manifest.
    pub max_routes: usize,
    /// The domain this operator's edge serves deployed sites under, e.g.
    /// `apps.<operator>.tld`. `None` = the operator declared none; onboarding
    /// output falls back to a placeholder so nothing hardcodes a canonical
    /// host.
    pub app_domain: Option<String>,
    /// Public IPv4 the edge answers on (apex `A` record). `None` = placeholder.
    pub edge_ipv4: Option<String>,
    /// Public IPv6 the edge answers on (apex `AAAA` record). `None` = placeholder.
    pub edge_ipv6: Option<String>,
}

impl Default for SitesConfig {
    fn default() -> Self {
        Self {
            cache_max_bytes: 64 * 1024 * 1024,
            max_routes: 4096,
            app_domain: None,
            edge_ipv4: None,
            edge_ipv6: None,
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

    pub fn with_app_domain(mut self, domain: Option<String>) -> Self {
        self.app_domain = domain;
        self
    }

    pub fn with_edge_addrs(mut self, ipv4: Option<String>, ipv6: Option<String>) -> Self {
        self.edge_ipv4 = ipv4;
        self.edge_ipv6 = ipv6;
        self
    }
}

/// A single DNS record the domain owner must publish, as reported to the CLI so
/// onboarding output names the operator's actual edge instead of a baked-in
/// host. A `value` of `None` marks a field the operator did not configure — the
/// CLI prints a placeholder the operator fills in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    /// DNS record type: `A`, `AAAA`, `CNAME`, or `TXT`.
    pub record_type: String,
    /// The record name (host).
    pub name: String,
    /// The record value, or `None` when the operator configured no edge address.
    pub value: Option<String>,
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
    /// hostname → alias record (the naming layer).
    aliases: DashMap<String, SiteAlias>,
    /// hostname → custom-domain ownership record (the TLS-ask gate).
    domains: DashMap<String, CustomDomain>,
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
            aliases: DashMap::new(),
            domains: DashMap::new(),
            storage: None,
            config,
            cache,
        }
    }

    /// Storage-backed registry: hydrates existing manifests from `CF_METADATA`.
    pub fn with_storage(storage: Arc<dyn KvStore>, config: SitesConfig) -> Result<Self, SiteError> {
        let registry = Self {
            sites: DashMap::new(),
            aliases: DashMap::new(),
            domains: DashMap::new(),
            storage: Some(storage.clone()),
            cache: SiteBlobCache::new(config.cache_max_bytes),
            config,
        };
        // `site_alias:` is a prefix of `site:`? No — but `SITE_PREFIX` ("site:")
        // is a prefix of `ALIAS_PREFIX` ("site_alias:") is false; still, a raw
        // prefix scan on "site:" would not catch "site_alias:" because the 6th
        // byte differs (':' vs '_'). Scan each keyspace independently.
        let keys = storage
            .get_keys_with_prefix(CF_METADATA, SITE_PREFIX.as_bytes())
            .map_err(|e| SiteError::Storage(format!("site scan: {e}")))?;
        let mut restored = 0usize;
        for key in keys {
            // Guard against the alias and domain keyspaces, whose keys also
            // start with "site" — only decode manifests under the exact "site:"
            // prefix.
            if key.starts_with(ALIAS_PREFIX.as_bytes())
                || key.starts_with(DOMAIN_PREFIX.as_bytes())
            {
                continue;
            }
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
        let alias_keys = storage
            .get_keys_with_prefix(CF_METADATA, ALIAS_PREFIX.as_bytes())
            .map_err(|e| SiteError::Storage(format!("alias scan: {e}")))?;
        let mut restored_aliases = 0usize;
        for key in alias_keys {
            match storage.get(CF_METADATA, &key) {
                Ok(Some(bytes)) => match serde_json::from_slice::<SiteAlias>(&bytes) {
                    Ok(alias) => {
                        registry.aliases.insert(alias.hostname.clone(), alias);
                        restored_aliases += 1;
                    }
                    Err(e) => warn!("skipping undecodable site alias: {e}"),
                },
                Ok(None) => {}
                Err(e) => return Err(SiteError::Storage(format!("alias get: {e}"))),
            }
        }
        let domain_keys = storage
            .get_keys_with_prefix(CF_METADATA, DOMAIN_PREFIX.as_bytes())
            .map_err(|e| SiteError::Storage(format!("domain scan: {e}")))?;
        let mut restored_domains = 0usize;
        for key in domain_keys {
            match storage.get(CF_METADATA, &key) {
                Ok(Some(bytes)) => match serde_json::from_slice::<CustomDomain>(&bytes) {
                    Ok(domain) => {
                        registry.domains.insert(domain.hostname.clone(), domain);
                        restored_domains += 1;
                    }
                    Err(e) => warn!("skipping undecodable custom domain: {e}"),
                },
                Ok(None) => {}
                Err(e) => return Err(SiteError::Storage(format!("domain get: {e}"))),
            }
        }
        if restored > 0 || restored_aliases > 0 || restored_domains > 0 {
            info!(
                "restored {restored} site manifests, {restored_aliases} aliases, \
                 {restored_domains} custom domains"
            );
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
        spa: bool,
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
                    spa,
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
                spa,
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

    fn persist_alias(&self, alias: &SiteAlias) -> Result<(), SiteError> {
        if let Some(storage) = &self.storage {
            let bytes =
                serde_json::to_vec(alias).map_err(|e| SiteError::Serialization(e.to_string()))?;
            storage
                .put(CF_METADATA, &alias_key(&alias.hostname), &bytes)
                .map_err(|e| SiteError::Storage(format!("alias put: {e}")))?;
        }
        Ok(())
    }

    /// Point `hostname` at `site_id`. The caller must own the target site — the
    /// site's manifest owner must equal `owner_did`. Re-pointing an existing
    /// hostname is allowed only by the DID that first claimed it, so one owner
    /// cannot hijack another's hostname.
    pub fn set_alias(
        &self,
        hostname: &str,
        site_id: &str,
        owner_did: &str,
    ) -> Result<SiteAlias, SiteError> {
        let hostname = normalize_hostname(hostname)
            .ok_or_else(|| SiteError::InvalidManifest(format!("invalid hostname: {hostname}")))?;
        let manifest = self
            .sites
            .get(site_id)
            .ok_or_else(|| SiteError::NotFound(site_id.to_string()))?;
        if manifest.owner_did != owner_did {
            return Err(SiteError::NotOwner);
        }
        drop(manifest);
        if let Some(existing) = self.aliases.get(&hostname)
            && existing.owner_did != owner_did
        {
            return Err(SiteError::NotOwner);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let created_at = self
            .aliases
            .get(&hostname)
            .map(|a| a.created_at)
            .unwrap_or(now);
        let alias = SiteAlias {
            hostname: hostname.clone(),
            site_id: site_id.to_string(),
            owner_did: owner_did.to_string(),
            created_at,
            updated_at: now,
        };
        self.persist_alias(&alias)?;
        self.aliases.insert(hostname, alias.clone());
        Ok(alias)
    }

    /// Resolve a hostname to its site id, if aliased.
    pub fn resolve_alias(&self, hostname: &str) -> Option<String> {
        let hostname = normalize_hostname(hostname)?;
        self.aliases.get(&hostname).map(|a| a.site_id.clone())
    }

    pub fn get_alias(&self, hostname: &str) -> Option<SiteAlias> {
        let hostname = normalize_hostname(hostname)?;
        self.aliases.get(&hostname).map(|a| a.clone())
    }

    pub fn list_aliases(&self, owner_did: Option<&str>) -> Vec<SiteAlias> {
        self.aliases
            .iter()
            .filter(|a| owner_did.is_none_or(|o| a.owner_did == o))
            .map(|a| a.clone())
            .collect()
    }

    /// Remove a hostname alias. `owner_did` must match the alias owner.
    pub fn remove_alias(&self, hostname: &str, owner_did: &str) -> Result<SiteAlias, SiteError> {
        let hostname = normalize_hostname(hostname)
            .ok_or_else(|| SiteError::InvalidManifest(format!("invalid hostname: {hostname}")))?;
        {
            let alias = self
                .aliases
                .get(&hostname)
                .ok_or_else(|| SiteError::NotFound(hostname.clone()))?;
            if alias.owner_did != owner_did {
                return Err(SiteError::NotOwner);
            }
        }
        if let Some(storage) = &self.storage {
            storage
                .delete(CF_METADATA, &alias_key(&hostname))
                .map_err(|e| SiteError::Storage(format!("alias delete: {e}")))?;
        }
        let (_, alias) = self
            .aliases
            .remove(&hostname)
            .ok_or(SiteError::NotFound(hostname))?;
        Ok(alias)
    }

    fn persist_domain(&self, domain: &CustomDomain) -> Result<(), SiteError> {
        if let Some(storage) = &self.storage {
            let bytes =
                serde_json::to_vec(domain).map_err(|e| SiteError::Serialization(e.to_string()))?;
            storage
                .put(CF_METADATA, &domain_key(&domain.hostname), &bytes)
                .map_err(|e| SiteError::Storage(format!("domain put: {e}")))?;
        }
        Ok(())
    }

    /// Claim `hostname` for `site_id`. The caller must own the target site. The
    /// record starts `verified = false` with a deterministic ownership token the
    /// caller publishes at `_tenzro-ownership.<hostname>`; the platform verifies
    /// it before issuing a certificate. Re-claiming an already-claimed hostname
    /// is allowed only by the DID that first claimed it (no hijack), and
    /// re-claiming resets verification so a re-point is re-proved.
    pub fn claim_domain(
        &self,
        hostname: &str,
        site_id: &str,
        owner_did: &str,
    ) -> Result<CustomDomain, SiteError> {
        let hostname = normalize_hostname(hostname)
            .ok_or_else(|| SiteError::InvalidManifest(format!("invalid hostname: {hostname}")))?;
        let manifest = self
            .sites
            .get(site_id)
            .ok_or_else(|| SiteError::NotFound(site_id.to_string()))?;
        if manifest.owner_did != owner_did {
            return Err(SiteError::NotOwner);
        }
        drop(manifest);
        if let Some(existing) = self.domains.get(&hostname)
            && existing.owner_did != owner_did
        {
            return Err(SiteError::NotOwner);
        }
        let now = now_ms();
        let created_at = self
            .domains
            .get(&hostname)
            .map(|d| d.created_at)
            .unwrap_or(now);
        let domain = CustomDomain {
            hostname: hostname.clone(),
            owner_did: owner_did.to_string(),
            site_id: site_id.to_string(),
            ownership_token: compute_ownership_token(&hostname, owner_did),
            verified: false,
            verified_at: None,
            created_at,
            updated_at: now,
        };
        self.persist_domain(&domain)?;
        self.domains.insert(hostname, domain.clone());
        Ok(domain)
    }

    /// Build the DNS records a domain owner must publish for `domain`, naming
    /// this operator's configured edge. An apex hostname (one label before the
    /// public suffix, e.g. `example.com`) gets `A`/`AAAA` records to the edge
    /// address; a subdomain gets a single `CNAME` to the operator's app domain.
    /// Both get the `_tenzro-ownership.<hostname>` `TXT` proof. When the
    /// operator configured no edge address / app domain, the corresponding
    /// record carries `value: None` and the CLI prints a placeholder — nothing
    /// hardcodes a canonical host.
    pub fn domain_onboarding(&self, domain: &CustomDomain) -> Vec<DnsRecord> {
        let mut records = Vec::new();
        // Apex = exactly one dot (`example.com`); anything deeper is a subdomain.
        // Public-suffix edge cases (e.g. `co.uk`) are the owner's DNS concern;
        // the record shape is the same either way.
        let is_apex = domain.hostname.matches('.').count() <= 1;
        if is_apex {
            records.push(DnsRecord {
                record_type: "A".to_string(),
                name: domain.hostname.clone(),
                value: self.config.edge_ipv4.clone(),
            });
            records.push(DnsRecord {
                record_type: "AAAA".to_string(),
                name: domain.hostname.clone(),
                value: self.config.edge_ipv6.clone(),
            });
        } else {
            records.push(DnsRecord {
                record_type: "CNAME".to_string(),
                name: domain.hostname.clone(),
                value: self.config.app_domain.clone(),
            });
        }
        records.push(DnsRecord {
            record_type: "TXT".to_string(),
            name: ownership_txt_name(&domain.hostname),
            value: Some(domain.ownership_token.clone()),
        });
        records
    }

    /// Mark a claimed domain verified after the DNS TXT challenge is confirmed.
    /// Idempotent; write-through so the ask endpoint sees it across restarts.
    pub fn mark_domain_verified(&self, hostname: &str) -> Result<CustomDomain, SiteError> {
        let hostname = normalize_hostname(hostname)
            .ok_or_else(|| SiteError::InvalidManifest(format!("invalid hostname: {hostname}")))?;
        let mut domain = self
            .domains
            .get(&hostname)
            .map(|d| d.clone())
            .ok_or_else(|| SiteError::NotFound(hostname.clone()))?;
        let now = now_ms();
        domain.verified = true;
        domain.verified_at = Some(now);
        domain.updated_at = now;
        self.persist_domain(&domain)?;
        self.domains.insert(hostname, domain.clone());
        Ok(domain)
    }

    /// Resolve `_tenzro-ownership.<hostname>` over DNS and confirm the claimed
    /// ownership token is present as a TXT value. On a match, flip the domain to
    /// verified (write-through) so the TLS-ask endpoint admits it. The domain
    /// must have been claimed first — the expected token is read from the stored
    /// claim, not recomputed from caller-supplied input, so a caller cannot
    /// self-assert verification for a domain it never claimed.
    pub async fn verify_domain(&self, hostname: &str) -> Result<CustomDomain, SiteError> {
        let hostname = normalize_hostname(hostname)
            .ok_or_else(|| SiteError::InvalidManifest(format!("invalid hostname: {hostname}")))?;
        let expected = self
            .domains
            .get(&hostname)
            .map(|d| d.ownership_token.clone())
            .ok_or_else(|| SiteError::NotFound(hostname.clone()))?;

        let txt_name = ownership_txt_name(&hostname);
        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(5);
        opts.attempts = 2;
        let resolver = Resolver::builder_tokio()
            .map_err(|e| SiteError::Dns(format!("resolver init: {e}")))?
            .with_options(opts)
            .build()
            .map_err(|e| SiteError::Dns(format!("resolver init: {e}")))?;

        let txt = resolver
            .txt_lookup(txt_name.as_str())
            .await
            .map_err(|e| SiteError::Dns(format!("TXT lookup {txt_name}: {e}")))?;

        let found = txt
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::TXT(t) => Some(t),
                _ => None,
            })
            .flat_map(|t| t.txt_data.iter())
            .any(|d| String::from_utf8_lossy(d).trim() == expected);

        if !found {
            return Err(SiteError::ChallengeNotFound { name: txt_name });
        }
        self.mark_domain_verified(&hostname)
    }

    /// Fast, allocation-light check for the TLS-ask endpoint: is `hostname` a
    /// verified custom domain? This runs on Caddy's on-demand-TLS ask path, once
    /// per new domain per handshake, so it must never touch the network.
    pub fn is_domain_verified(&self, hostname: &str) -> bool {
        match normalize_hostname(hostname) {
            Some(h) => self.domains.get(&h).is_some_and(|d| d.verified),
            None => false,
        }
    }

    pub fn get_domain(&self, hostname: &str) -> Option<CustomDomain> {
        let hostname = normalize_hostname(hostname)?;
        self.domains.get(&hostname).map(|d| d.clone())
    }

    pub fn list_domains(&self, owner_did: Option<&str>) -> Vec<CustomDomain> {
        self.domains
            .iter()
            .filter(|d| owner_did.is_none_or(|o| d.owner_did == o))
            .map(|d| d.clone())
            .collect()
    }

    /// Resolve a verified custom domain to its site id. Unverified domains do
    /// not resolve, so an in-flight claim never serves content.
    pub fn resolve_domain(&self, hostname: &str) -> Option<String> {
        let hostname = normalize_hostname(hostname)?;
        self.domains
            .get(&hostname)
            .filter(|d| d.verified)
            .map(|d| d.site_id.clone())
    }

    /// Remove a custom-domain claim. `owner_did` must match the claim owner.
    pub fn remove_domain(
        &self,
        hostname: &str,
        owner_did: &str,
    ) -> Result<CustomDomain, SiteError> {
        let hostname = normalize_hostname(hostname)
            .ok_or_else(|| SiteError::InvalidManifest(format!("invalid hostname: {hostname}")))?;
        {
            let domain = self
                .domains
                .get(&hostname)
                .ok_or_else(|| SiteError::NotFound(hostname.clone()))?;
            if domain.owner_did != owner_did {
                return Err(SiteError::NotOwner);
            }
        }
        if let Some(storage) = &self.storage {
            storage
                .delete(CF_METADATA, &domain_key(&hostname))
                .map_err(|e| SiteError::Storage(format!("domain delete: {e}")))?;
        }
        let (_, domain) = self
            .domains
            .remove(&hostname)
            .ok_or(SiteError::NotFound(hostname))?;
        Ok(domain)
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
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
                .publish_site("s", "did:tenzro:human:a", bad_path, None, None, false, None)
                .is_err()
        );

        let mut traversal = BTreeMap::new();
        traversal.insert("/../etc/passwd".to_string(), route(0x01));
        assert!(
            registry
                .publish_site("s", "did:tenzro:human:a", traversal, None, None, false, None)
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
                .publish_site("s", "did:tenzro:human:a", bad_hash, None, None, false, None)
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
                .publish_site("s", "did:tenzro:human:a", bad_ct, None, None, false, None)
                .is_err()
        );

        assert!(
            registry
                .publish_site("bad name!", "did:tenzro:human:a", one_page_routes(), None, None, false, None)
                .is_err()
        );
        assert!(
            registry
                .publish_site("s", "not-a-did", one_page_routes(), None, None, false, None)
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
                    false,
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
                    false,
                    None,
                )
                .is_err()
        );
    }

    #[test]
    fn republish_bumps_version_preserves_created_at() {
        let registry = SiteRegistry::new();
        let v1 = registry
            .publish_site("blog", "did:tenzro:human:a", one_page_routes(), None, None, false, None)
            .unwrap();
        assert_eq!(v1.version, 1);
        let v2 = registry
            .publish_site("blog", "did:tenzro:human:a", one_page_routes(), None, None, false, Some(5))
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
            .publish_site("blog", "did:tenzro:human:a", one_page_routes(), None, None, false, None)
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
            .publish_site("a", "did:tenzro:human:a", one_page_routes(), None, None, false, None)
            .unwrap();
        registry
            .publish_site("b", "did:tenzro:human:b", one_page_routes(), None, None, false, None)
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

    #[test]
    fn normalize_hostname_strips_port_lowercases_and_trims_dot() {
        assert_eq!(
            normalize_hostname("MyApp.Apps.Tenzro.XYZ:443"),
            Some("myapp.apps.tenzro.xyz".to_string())
        );
        assert_eq!(
            normalize_hostname("host.example."),
            Some("host.example".to_string())
        );
        assert_eq!(normalize_hostname(""), None);
        assert_eq!(normalize_hostname("bad_host"), None);
        assert_eq!(normalize_hostname("has space"), None);
        assert_eq!(normalize_hostname(&"a".repeat(254)), None);
    }

    #[test]
    fn is_asset_path_distinguishes_assets_from_routes() {
        assert!(is_asset_path("/assets/app.js"));
        assert!(is_asset_path("/main.css"));
        assert!(is_asset_path("favicon.ico"));
        assert!(!is_asset_path("/dashboard"));
        assert!(!is_asset_path("/users/42/profile"));
        assert!(!is_asset_path("/"));
        assert!(!is_asset_path("/.hidden"));
    }

    #[test]
    fn publish_records_spa_flag() {
        let registry = SiteRegistry::new();
        let m = registry
            .publish_site(
                "app",
                "did:tenzro:human:a",
                one_page_routes(),
                None,
                None,
                true,
                None,
            )
            .unwrap();
        assert!(m.spa);
        assert!(registry.get_site(&m.site_id).unwrap().spa);
    }

    #[test]
    fn set_alias_requires_manifest_ownership() {
        let registry = SiteRegistry::new();
        let m = registry
            .publish_site(
                "app",
                "did:tenzro:human:a",
                one_page_routes(),
                None,
                None,
                false,
                None,
            )
            .unwrap();
        // Non-owner cannot alias onto owner's site.
        assert!(matches!(
            registry.set_alias("app.apps.tenzro.xyz", &m.site_id, "did:tenzro:human:b"),
            Err(SiteError::NotOwner)
        ));
        // Owner can, and resolution round-trips (host normalized).
        let alias = registry
            .set_alias("App.Apps.Tenzro.XYZ", &m.site_id, "did:tenzro:human:a")
            .unwrap();
        assert_eq!(alias.hostname, "app.apps.tenzro.xyz");
        assert_eq!(
            registry.resolve_alias("app.apps.tenzro.xyz:8080"),
            Some(m.site_id.clone())
        );
    }

    #[test]
    fn set_alias_rejects_hijack_of_existing_hostname() {
        let registry = SiteRegistry::new();
        let a = registry
            .publish_site(
                "a",
                "did:tenzro:human:a",
                one_page_routes(),
                None,
                None,
                false,
                None,
            )
            .unwrap();
        let b = registry
            .publish_site(
                "b",
                "did:tenzro:human:b",
                one_page_routes(),
                None,
                None,
                false,
                None,
            )
            .unwrap();
        registry
            .set_alias("shared.apps.tenzro.xyz", &a.site_id, "did:tenzro:human:a")
            .unwrap();
        // Owner b owns site b but cannot re-point a hostname first claimed by a.
        assert!(matches!(
            registry.set_alias("shared.apps.tenzro.xyz", &b.site_id, "did:tenzro:human:b"),
            Err(SiteError::NotOwner)
        ));
        // Owner a may re-point their own hostname.
        registry
            .set_alias("shared.apps.tenzro.xyz", &a.site_id, "did:tenzro:human:a")
            .unwrap();
    }

    #[test]
    fn remove_alias_enforces_owner_and_filters_list() {
        let registry = SiteRegistry::new();
        let m = registry
            .publish_site(
                "app",
                "did:tenzro:human:a",
                one_page_routes(),
                None,
                None,
                false,
                None,
            )
            .unwrap();
        registry
            .set_alias("app.apps.tenzro.xyz", &m.site_id, "did:tenzro:human:a")
            .unwrap();
        assert_eq!(registry.list_aliases(None).len(), 1);
        assert_eq!(
            registry.list_aliases(Some("did:tenzro:human:b")).len(),
            0
        );
        assert!(matches!(
            registry.remove_alias("app.apps.tenzro.xyz", "did:tenzro:human:b"),
            Err(SiteError::NotOwner)
        ));
        assert!(
            registry
                .remove_alias("app.apps.tenzro.xyz", "did:tenzro:human:a")
                .is_ok()
        );
        assert!(registry.resolve_alias("app.apps.tenzro.xyz").is_none());
    }

    fn publish(registry: &SiteRegistry, name: &str, did: &str) -> SiteManifest {
        registry
            .publish_site(name, did, one_page_routes(), None, None, false, None)
            .unwrap()
    }

    #[test]
    fn ownership_token_is_deterministic_and_owner_scoped() {
        let a = compute_ownership_token("shop.example.com", "did:tenzro:human:a");
        let b = compute_ownership_token("shop.example.com", "did:tenzro:human:a");
        let c = compute_ownership_token("shop.example.com", "did:tenzro:human:b");
        let d = compute_ownership_token("blog.example.com", "did:tenzro:human:a");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
        assert_eq!(a.len(), 64);
        assert_eq!(
            ownership_txt_name("shop.example.com"),
            "_tenzro-ownership.shop.example.com"
        );
    }

    #[test]
    fn claim_domain_requires_site_ownership() {
        let registry = SiteRegistry::new();
        let m = publish(&registry, "shop", "did:tenzro:human:a");
        assert!(matches!(
            registry.claim_domain("shop.example.com", &m.site_id, "did:tenzro:human:b"),
            Err(SiteError::NotOwner)
        ));
        let d = registry
            .claim_domain("shop.example.com", &m.site_id, "did:tenzro:human:a")
            .unwrap();
        assert!(!d.verified);
        assert_eq!(
            d.ownership_token,
            compute_ownership_token("shop.example.com", "did:tenzro:human:a")
        );
    }

    #[test]
    fn unverified_domain_does_not_resolve() {
        let registry = SiteRegistry::new();
        let m = publish(&registry, "shop", "did:tenzro:human:a");
        registry
            .claim_domain("shop.example.com", &m.site_id, "did:tenzro:human:a")
            .unwrap();
        assert!(!registry.is_domain_verified("shop.example.com"));
        assert!(registry.resolve_domain("shop.example.com").is_none());

        registry.mark_domain_verified("shop.example.com").unwrap();
        assert!(registry.is_domain_verified("shop.example.com"));
        assert_eq!(
            registry.resolve_domain("shop.example.com").as_deref(),
            Some(m.site_id.as_str())
        );
    }

    #[test]
    fn claim_domain_no_hijack_and_reclaim_resets_verification() {
        let registry = SiteRegistry::new();
        let a = publish(&registry, "shop", "did:tenzro:human:a");
        let b = publish(&registry, "store", "did:tenzro:human:b");
        registry
            .claim_domain("shop.example.com", &a.site_id, "did:tenzro:human:a")
            .unwrap();
        registry.mark_domain_verified("shop.example.com").unwrap();
        // Another owner cannot steal the claimed hostname.
        assert!(matches!(
            registry.claim_domain("shop.example.com", &b.site_id, "did:tenzro:human:b"),
            Err(SiteError::NotOwner)
        ));
        // The original owner re-pointing resets verification so it is re-proved.
        let repointed = registry
            .claim_domain("shop.example.com", &a.site_id, "did:tenzro:human:a")
            .unwrap();
        assert!(!repointed.verified);
        assert!(registry.resolve_domain("shop.example.com").is_none());
    }

    #[test]
    fn verify_domain_requires_prior_claim() {
        let registry = SiteRegistry::new();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt.block_on(registry.verify_domain("never-claimed.example.com"));
        assert!(matches!(err, Err(SiteError::NotFound(_))));
    }

    #[test]
    fn remove_domain_enforces_owner_and_filters_list() {
        let registry = SiteRegistry::new();
        let m = publish(&registry, "shop", "did:tenzro:human:a");
        registry
            .claim_domain("shop.example.com", &m.site_id, "did:tenzro:human:a")
            .unwrap();
        assert_eq!(registry.list_domains(None).len(), 1);
        assert_eq!(registry.list_domains(Some("did:tenzro:human:b")).len(), 0);
        assert!(matches!(
            registry.remove_domain("shop.example.com", "did:tenzro:human:b"),
            Err(SiteError::NotOwner)
        ));
        assert!(
            registry
                .remove_domain("shop.example.com", "did:tenzro:human:a")
                .is_ok()
        );
        assert!(registry.get_domain("shop.example.com").is_none());
    }
}
