//! Function hosting: request-scoped `wasi:http` components deployed to a node
//! and served over the same `tenzro/http` ingress path that static sites use.
//!
//! A function deployment is a single content-addressed wasm blob (a component
//! that exports the `wasi:http/incoming-handler` proxy world) plus a capability
//! manifest describing exactly what host authority it is granted. Deployments
//! persist under `CF_METADATA` keyed `function:<id>` with write-through on
//! deploy/remove and hydrate-on-boot, matching the site registry.
//!
//! The naming layer is shared with [`crate::sites::SiteRegistry`]: the same
//! `compute_site_id(owner_did, name)` derives the id, and the same alias /
//! custom-domain tables resolve a public Host header to that id. Ingress
//! resolves a host to an id once, then checks the function registry before the
//! static site registry — a given id is either a function or a site, never both.
//!
//! # Request lifecycle (spec §9.5)
//!
//! `wasi:http` components are request-scoped: each request instantiates a fresh
//! component store from the deployment's capabilities, so no state leaks between
//! requests. A function that needs cross-request state pairs with a companion
//! long-lived component (a `machine` app) or an external store reached through a
//! declared network capability. The runtime here holds no per-deployment state
//! beyond the compiled component; every request is independent.

use std::sync::Arc;

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use tenzro_storage::{CF_METADATA, KvStore};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::sites::compute_site_id;

/// Key prefix for function deployment records within `CF_METADATA`.
const FUNCTION_PREFIX: &str = "function:";

fn function_key(id: &str) -> Vec<u8> {
    format!("{FUNCTION_PREFIX}{id}").into_bytes()
}

const MAX_NAME_LEN: usize = 64;

#[derive(Debug, Error)]
pub enum FunctionError {
    #[error("invalid deployment: {0}")]
    InvalidDeployment(String),
    #[error("function not found: {0}")]
    NotFound(String),
    #[error("not function owner")]
    NotOwner,
    #[error("storage error: {0}")]
    Storage(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Storage capabilities a function is granted. Mirrors the wasm host's
/// `StorageCapability` but lives here so the registry compiles without the
/// `wasi-skills` feature (metadata RPCs must work on any node). Each pair is
/// `(host_path, guest_path)` under the WASI preopen model.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionStorageCapability {
    #[serde(default)]
    pub read_only: Vec<(String, String)>,
    #[serde(default)]
    pub read_write: Vec<(String, String)>,
}

/// Network capabilities a function is granted.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionNetworkCapability {
    #[serde(default)]
    pub outbound_tcp: Vec<String>,
    #[serde(default)]
    pub dns_allow: Vec<String>,
    #[serde(default)]
    pub https_proxy: bool,
}

/// The capability grant attached to a function deployment. A component starts
/// with no ambient authority; only what this declares is exposed.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FunctionCapabilities {
    #[serde(default)]
    pub storage: FunctionStorageCapability,
    #[serde(default)]
    pub network: FunctionNetworkCapability,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub host_methods: Vec<String>,
}

#[cfg(feature = "wasi-skills")]
impl From<&FunctionCapabilities> for tenzro_wasm::SkillCapabilities {
    fn from(c: &FunctionCapabilities) -> Self {
        tenzro_wasm::SkillCapabilities {
            storage: tenzro_wasm::StorageCapability {
                read_only: c.storage.read_only.clone(),
                read_write: c.storage.read_write.clone(),
            },
            network: tenzro_wasm::NetworkCapability {
                outbound_tcp: c.network.outbound_tcp.clone(),
                dns_allow: c.network.dns_allow.clone(),
                https_proxy: c.network.https_proxy,
            },
            env: c.env.clone(),
            host_methods: c.host_methods.clone(),
        }
    }
}

/// A deployed function: the wasm component blob plus its capability grant.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDeployment {
    /// Deterministic id from `compute_site_id(owner_did, name)`. Shared naming
    /// space with static sites so aliases / custom domains resolve uniformly.
    pub id: String,
    pub name: String,
    pub owner_did: String,
    pub version: u64,
    /// BLAKE3 hex (64 lowercase hex chars) of the component blob in the iroh
    /// store. The blob is a `wasi:http/proxy` component.
    pub wasm_blob_hash: String,
    /// Capability grant applied to every instantiation.
    pub capabilities: FunctionCapabilities,
    /// Per-request fuel budget (deterministic metering).
    pub fuel_limit: u64,
    /// Per-request wall-clock deadline in milliseconds.
    pub deadline_ms: u64,
    /// TNZO per request; when `Some`, serving is x402-gated.
    pub price_per_request: Option<u128>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Default per-request fuel budget for a function. Sized for typical request
/// handling; a deployment may raise or lower it.
pub const DEFAULT_FUEL_LIMIT: u64 = 200_000_000;

/// Default per-request wall-clock deadline (milliseconds).
pub const DEFAULT_DEADLINE_MS: u64 = 10_000;

fn validate_name(name: &str) -> Result<(), FunctionError> {
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(FunctionError::InvalidDeployment(
            "name must be 1-64 characters".into(),
        ));
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
    {
        return Err(FunctionError::InvalidDeployment(
            "name may only contain [a-zA-Z0-9._-]".into(),
        ));
    }
    Ok(())
}

fn validate_blob_hash(hash: &str) -> Result<(), FunctionError> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(FunctionError::InvalidDeployment(
            "wasm_blob_hash must be 64 lowercase hex chars".into(),
        ));
    }
    Ok(())
}

/// Registry of deployed functions with write-through persistence. The compiled
/// component cache lives on the node ([`crate::node::TenzroNode`]) under the
/// `wasi-skills` feature; this registry holds only the durable metadata.
pub struct FunctionRegistry {
    functions: DashMap<String, FunctionDeployment>,
    storage: Option<Arc<dyn KvStore>>,
}

impl std::fmt::Debug for FunctionRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FunctionRegistry")
            .field("functions", &self.functions.len())
            .finish()
    }
}

impl FunctionRegistry {
    pub fn new() -> Self {
        Self {
            functions: DashMap::new(),
            storage: None,
        }
    }

    /// Storage-backed registry: hydrates existing deployments from `CF_METADATA`
    /// under the `function:` prefix.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Result<Self, FunctionError> {
        let registry = Self {
            functions: DashMap::new(),
            storage: Some(storage.clone()),
        };
        let keys = storage
            .get_keys_with_prefix(CF_METADATA, FUNCTION_PREFIX.as_bytes())
            .map_err(|e| FunctionError::Storage(format!("function scan: {e}")))?;
        let mut restored = 0usize;
        for key in keys {
            match storage.get(CF_METADATA, &key) {
                Ok(Some(bytes)) => match serde_json::from_slice::<FunctionDeployment>(&bytes) {
                    Ok(deployment) => {
                        registry.functions.insert(deployment.id.clone(), deployment);
                        restored += 1;
                    }
                    Err(e) => warn!("skipping undecodable function deployment: {e}"),
                },
                Ok(None) => {}
                Err(e) => return Err(FunctionError::Storage(format!("function get: {e}"))),
            }
        }
        if restored > 0 {
            info!("restored {restored} function deployment(s)");
        }
        Ok(registry)
    }

    fn persist(&self, deployment: &FunctionDeployment) -> Result<(), FunctionError> {
        if let Some(storage) = &self.storage {
            let bytes = serde_json::to_vec(deployment)
                .map_err(|e| FunctionError::Serialization(e.to_string()))?;
            storage
                .put(CF_METADATA, &function_key(&deployment.id), &bytes)
                .map_err(|e| FunctionError::Storage(format!("function put: {e}")))?;
        }
        Ok(())
    }

    /// Deploy or redeploy a function. Redeploying the same (owner, name) bumps
    /// `version` and preserves `created_at`; a different owner is rejected.
    #[allow(clippy::too_many_arguments)]
    pub fn deploy(
        &self,
        name: &str,
        owner_did: &str,
        wasm_blob_hash: &str,
        capabilities: FunctionCapabilities,
        fuel_limit: Option<u64>,
        deadline_ms: Option<u64>,
        price_per_request: Option<u128>,
    ) -> Result<FunctionDeployment, FunctionError> {
        validate_name(name)?;
        if !owner_did.starts_with("did:") {
            return Err(FunctionError::InvalidDeployment(
                "owner_did must be a DID".into(),
            ));
        }
        validate_blob_hash(wasm_blob_hash)?;

        let id = compute_site_id(owner_did, name);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let fuel_limit = fuel_limit.unwrap_or(DEFAULT_FUEL_LIMIT);
        let deadline_ms = deadline_ms.unwrap_or(DEFAULT_DEADLINE_MS);

        let deployment = match self.functions.get(&id) {
            Some(existing) => {
                if existing.owner_did != owner_did {
                    return Err(FunctionError::NotOwner);
                }
                FunctionDeployment {
                    id: id.clone(),
                    name: name.to_string(),
                    owner_did: owner_did.to_string(),
                    version: existing.version + 1,
                    wasm_blob_hash: wasm_blob_hash.to_string(),
                    capabilities,
                    fuel_limit,
                    deadline_ms,
                    price_per_request,
                    created_at: existing.created_at,
                    updated_at: now,
                }
            }
            None => FunctionDeployment {
                id: id.clone(),
                name: name.to_string(),
                owner_did: owner_did.to_string(),
                version: 1,
                wasm_blob_hash: wasm_blob_hash.to_string(),
                capabilities,
                fuel_limit,
                deadline_ms,
                price_per_request,
                created_at: now,
                updated_at: now,
            },
        };

        self.persist(&deployment)?;
        self.functions.insert(id, deployment.clone());
        Ok(deployment)
    }

    pub fn get(&self, id: &str) -> Option<FunctionDeployment> {
        self.functions.get(id).map(|d| d.clone())
    }

    pub fn list(&self, owner_did: Option<&str>) -> Vec<FunctionDeployment> {
        self.functions
            .iter()
            .filter(|d| owner_did.is_none_or(|o| d.owner_did == o))
            .map(|d| d.clone())
            .collect()
    }

    /// Remove a deployment. `owner_did` must match. Returns the removed record.
    pub fn remove(&self, id: &str, owner_did: &str) -> Result<FunctionDeployment, FunctionError> {
        {
            let deployment = self
                .functions
                .get(id)
                .ok_or_else(|| FunctionError::NotFound(id.to_string()))?;
            if deployment.owner_did != owner_did {
                return Err(FunctionError::NotOwner);
            }
        }
        if let Some(storage) = &self.storage {
            storage
                .delete(CF_METADATA, &function_key(id))
                .map_err(|e| FunctionError::Storage(format!("function delete: {e}")))?;
        }
        let (_, deployment) = self
            .functions
            .remove(id)
            .ok_or_else(|| FunctionError::NotFound(id.to_string()))?;
        debug!("removed function deployment {id}");
        Ok(deployment)
    }
}

impl Default for FunctionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Compiled `wasi:http` component cache. Compiling a component is the expensive
/// step; a deployment's blob is immutable per version, so a compiled handle is
/// cached under `(id, version)` and reused across requests. A redeploy bumps the
/// version, so the old handle is naturally superseded on the next lookup.
///
/// Present only under the `wasi-skills` feature — a node built without wasm
/// support still holds the [`FunctionRegistry`] metadata but never serves
/// function requests (ingress returns 501 for a function deployment).
#[cfg(feature = "wasi-skills")]
pub struct FunctionComponentCache {
    engine: tenzro_wasm::WasmEngine,
    compiled: DashMap<String, Arc<tenzro_wasm::HttpComponent>>,
}

#[cfg(feature = "wasi-skills")]
impl std::fmt::Debug for FunctionComponentCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FunctionComponentCache")
            .field("compiled", &self.compiled.len())
            .finish()
    }
}

#[cfg(feature = "wasi-skills")]
impl FunctionComponentCache {
    /// Build a cache over a fresh wasm engine.
    pub fn new() -> Result<Self, tenzro_wasm::WasmError> {
        Ok(Self {
            engine: tenzro_wasm::WasmEngine::new()?,
            compiled: DashMap::new(),
        })
    }

    /// The engine backing this cache. The node ticks its epoch clock so
    /// per-request deadlines trip.
    pub fn engine(&self) -> &tenzro_wasm::WasmEngine {
        &self.engine
    }

    fn cache_key(id: &str, version: u64) -> String {
        format!("{id}@{version}")
    }

    /// Compile (or reuse) the `wasi:http` component for a deployment, given the
    /// wasm blob bytes already fetched from the iroh store. The bytes must hash
    /// to `deployment.wasm_blob_hash` — the caller verifies via the resolver's
    /// content-addressed fetch, so no re-hash is done here.
    pub fn get_or_compile(
        &self,
        deployment: &FunctionDeployment,
        bytes: &[u8],
    ) -> Result<Arc<tenzro_wasm::HttpComponent>, tenzro_wasm::WasmError> {
        let key = Self::cache_key(&deployment.id, deployment.version);
        if let Some(existing) = self.compiled.get(&key) {
            return Ok(existing.clone());
        }
        let caps: tenzro_wasm::SkillCapabilities = (&deployment.capabilities).into();
        let component = tenzro_wasm::HttpComponent::compile(
            &self.engine,
            bytes,
            caps,
            deployment.fuel_limit,
            std::time::Duration::from_millis(deployment.deadline_ms.max(1)),
        )?;
        let handle = Arc::new(component);
        self.compiled.insert(key, handle.clone());
        Ok(handle)
    }

    /// Drop any cached compiled handle for a deployment (all versions). Called
    /// on remove so a redeployed-then-removed id does not leak a stale handle.
    pub fn invalidate(&self, id: &str) {
        let prefix = format!("{id}@");
        self.compiled.retain(|k, _| !k.starts_with(&prefix));
    }
}
