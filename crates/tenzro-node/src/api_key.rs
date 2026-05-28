//! Per-client API key management for proxied service access.
//!
//! Tenzro mediates access to credentials that clients should not hold
//! directly — most notably the Canton devnet JWT, which authorizes the
//! shared Splice validator party `tenzro-validator-1`. External callers
//! authenticate to the Tenzro node via an API key (presented in the
//! `X-Tenzro-Api-Key` HTTP header on REST routes, or as the `api_key`
//! parameter on the corresponding JSON-RPC methods); the node then
//! makes the upstream Canton request on the caller's behalf using its
//! own bearer token.
//!
//! The raw key material is **never** persisted — only the SHA-256 hash
//! is stored in `CF_API_KEYS`. The plaintext is returned exactly once,
//! at issuance time.
//!
//! # Key format
//!
//! Issued keys are 32-byte random tokens, base64url-encoded without
//! padding, with a `tnz_` prefix for visual identification. Example:
//! `tnz_3v8q7s2X...`.
//!
//! # Scopes
//!
//! Each key is bound to a set of `ApiKeyScope` values that gate which
//! RPC namespaces it can access. A key with no scopes is invalid.

use std::sync::Arc;

use parking_lot::RwLock;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_storage::{KvStore, CF_API_KEYS};

use crate::error::{NodeError, Result};

/// Scopes an API key can be granted.
///
/// Each scope corresponds to a logical surface the node mediates on
/// behalf of the caller. New scopes added here MUST also be threaded
/// into [`gate_rpc_method`] so the middleware actually enforces them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyScope {
    /// Canton JSON Ledger API mediated by this node's bearer token.
    /// Gates `tenzro_*Canton*` RPC methods and the Canton MCP tools.
    Canton,
}

impl ApiKeyScope {
    /// Returns the canonical string form used in JSON-RPC params and
    /// `CF_API_KEYS` records.
    pub fn as_str(&self) -> &'static str {
        match self {
            ApiKeyScope::Canton => "canton",
        }
    }
}

/// Persisted record for an issued API key.
///
/// The raw key is hashed with SHA-256 and never stored. The key id
/// (first 8 bytes of the hash, hex-encoded) is a non-secret handle
/// used for revocation and audit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyRecord {
    /// Non-secret handle for revocation (8-byte hex prefix of the hash).
    pub key_id: String,
    /// Optional subject identifier (typically a Tenzro DID).
    pub subject: Option<String>,
    /// Free-form label set at issuance.
    pub label: String,
    /// Granted scopes. Empty = invalid.
    pub scopes: Vec<ApiKeyScope>,
    /// Unix timestamp (seconds) of issuance.
    pub created_at: i64,
    /// Unix timestamp (seconds) of revocation, if any.
    pub revoked_at: Option<i64>,
}

impl ApiKeyRecord {
    /// Returns true if the record is still active.
    pub fn is_active(&self) -> bool {
        self.revoked_at.is_none() && !self.scopes.is_empty()
    }

    /// Returns true if the record carries the given scope.
    pub fn has_scope(&self, scope: ApiKeyScope) -> bool {
        self.scopes.contains(&scope)
    }
}

/// Result of issuing a new API key.
#[derive(Debug, Clone)]
pub struct IssuedApiKey {
    /// The plaintext API key. Returned exactly once.
    pub key: String,
    /// The persisted record (without the plaintext).
    pub record: ApiKeyRecord,
}

/// In-memory + persistent API-key registry.
///
/// Lookups hit an in-memory cache (`DashMap` semantics via `RwLock`-wrapped
/// `HashMap`) for the hot path; writes go through to `CF_API_KEYS`.
/// On construction, the registry hydrates from RocksDB so issued keys
/// survive node restarts.
pub struct ApiKeyManager {
    storage: Arc<dyn KvStore>,
    cache: RwLock<std::collections::HashMap<String, ApiKeyRecord>>,
}

impl std::fmt::Debug for ApiKeyManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyManager")
            .field("cached", &self.cache.read().len())
            .finish()
    }
}

impl ApiKeyManager {
    /// Constructs a manager backed by the given KV store and hydrates the
    /// in-memory cache from `CF_API_KEYS`.
    pub fn new(storage: Arc<dyn KvStore>) -> Result<Arc<Self>> {
        let mgr = Self {
            storage,
            cache: RwLock::new(std::collections::HashMap::new()),
        };
        mgr.hydrate()?;
        Ok(Arc::new(mgr))
    }

    /// Loads all existing records from `CF_API_KEYS` into the cache.
    fn hydrate(&self) -> Result<()> {
        let entries = self
            .storage
            .scan_prefix(CF_API_KEYS, b"apikey:")
            .map_err(|e| NodeError::Internal(format!("api_key hydrate scan failed: {}", e)))?;

        let mut cache = self.cache.write();
        for (key, value) in entries {
            let hash_hex = match std::str::from_utf8(&key) {
                Ok(k) => k.trim_start_matches("apikey:").to_string(),
                Err(_) => continue,
            };
            let record: ApiKeyRecord = match serde_json::from_slice(&value) {
                Ok(r) => r,
                Err(_) => continue,
            };
            cache.insert(hash_hex, record);
        }
        Ok(())
    }

    /// Generates a new key, persists its hash + record, and returns the
    /// plaintext exactly once. Scopes must be non-empty.
    pub fn issue(
        &self,
        subject: Option<String>,
        label: impl Into<String>,
        scopes: Vec<ApiKeyScope>,
    ) -> Result<IssuedApiKey> {
        if scopes.is_empty() {
            return Err(NodeError::Internal(
                "api_key issue: at least one scope required".to_string(),
            ));
        }

        // 32 bytes of CSPRNG, base64url-no-pad, tnz_ prefix.
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        use base64::Engine;
        let body = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let key = format!("tnz_{}", body);

        let hash_hex = hash_key(&key);
        let key_id = hash_hex[..16].to_string();
        let created_at = chrono::Utc::now().timestamp();

        let record = ApiKeyRecord {
            key_id,
            subject,
            label: label.into(),
            scopes,
            created_at,
            revoked_at: None,
        };

        let storage_key = format!("apikey:{}", hash_hex);
        let value = serde_json::to_vec(&record)
            .map_err(|e| NodeError::Internal(format!("api_key serialize: {}", e)))?;
        self.storage
            .put(CF_API_KEYS, storage_key.as_bytes(), &value)
            .map_err(|e| NodeError::Internal(format!("api_key put: {}", e)))?;

        self.cache.write().insert(hash_hex, record.clone());

        Ok(IssuedApiKey { key, record })
    }

    /// Looks up a key by its plaintext value. Returns `Ok(None)` if the
    /// key is unknown or revoked.
    pub fn lookup(&self, plaintext: &str) -> Option<ApiKeyRecord> {
        let hash_hex = hash_key(plaintext);
        let cache = self.cache.read();
        cache.get(&hash_hex).filter(|r| r.is_active()).cloned()
    }

    /// Revokes a key by its `key_id` (non-secret handle). Returns true if
    /// a matching active key was found and revoked.
    pub fn revoke_by_id(&self, key_id: &str) -> Result<bool> {
        let mut cache = self.cache.write();
        let (hash_hex, mut record) = match cache
            .iter()
            .find(|(_, r)| r.key_id == key_id && r.is_active())
            .map(|(k, r)| (k.clone(), r.clone()))
        {
            Some(pair) => pair,
            None => return Ok(false),
        };

        record.revoked_at = Some(chrono::Utc::now().timestamp());
        let storage_key = format!("apikey:{}", hash_hex);
        let value = serde_json::to_vec(&record)
            .map_err(|e| NodeError::Internal(format!("api_key serialize: {}", e)))?;
        self.storage
            .put(CF_API_KEYS, storage_key.as_bytes(), &value)
            .map_err(|e| NodeError::Internal(format!("api_key put: {}", e)))?;
        cache.insert(hash_hex, record);
        Ok(true)
    }

    /// Lists all known records (active and revoked). The plaintext keys
    /// are not stored and cannot be returned.
    pub fn list(&self) -> Vec<ApiKeyRecord> {
        self.cache.read().values().cloned().collect()
    }

    /// Authorizes a request for the given RPC method.
    ///
    /// When `plaintext` is `None`, the request is allowed only if the
    /// method is not gated by any scope.
    pub fn authorize(&self, plaintext: Option<&str>, method: &str) -> AuthorizeOutcome {
        let required = match required_scope_for_method(method) {
            None => return AuthorizeOutcome::Allowed,
            Some(s) => s,
        };

        let plaintext = match plaintext {
            Some(p) => p,
            None => return AuthorizeOutcome::MissingKey(required),
        };

        match self.lookup(plaintext) {
            Some(record) if record.has_scope(required) => AuthorizeOutcome::Allowed,
            Some(_) => AuthorizeOutcome::InsufficientScope(required),
            None => AuthorizeOutcome::UnknownOrRevoked,
        }
    }
}

/// Result of an authorization check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizeOutcome {
    /// Either the method requires no scope, or the key carries the
    /// required scope and is active.
    Allowed,
    /// The method requires a scope but no API key was presented.
    MissingKey(ApiKeyScope),
    /// The presented key is unknown to the registry or revoked.
    UnknownOrRevoked,
    /// The key is active but does not carry the required scope.
    InsufficientScope(ApiKeyScope),
}

/// SHA-256 hash of an API key, hex-encoded. Used as the persistence and
/// cache key. Constant-time comparison is not required because the
/// attacker cannot influence which key we look up — we hash the
/// presented plaintext first.
fn hash_key(plaintext: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(plaintext.as_bytes());
    hex::encode(hasher.finalize())
}

/// Constant-time comparison of a presented admin token against the
/// expected operator secret.
///
/// The admin token gates operator-only mutation RPCs (API-key issuance,
/// staking, provider registration). It is a single shared secret held by
/// the node operator, loaded from `TENZRO_ADMIN_TOKEN` at startup and
/// kept off-disk: it is never serialized into `NodeConfig` snapshots,
/// never written to RocksDB, and redacted in `Debug` output.
///
/// Both sides are compared as raw bytes via [`subtle::ConstantTimeEq`]
/// to avoid leaking the length-prefix of a matching token through a
/// length-dependent fast-path. Empty `expected` always returns `false`
/// — a node started without an admin token cannot be unlocked by an
/// empty presentation.
pub fn verify_admin_token(presented: &str, expected: &str) -> bool {
    use subtle::ConstantTimeEq;
    if expected.is_empty() {
        return false;
    }
    // Equal-length comparison is required for ConstantTimeEq; differing
    // lengths short-circuit to false without revealing the expected length.
    if presented.len() != expected.len() {
        return false;
    }
    presented.as_bytes().ct_eq(expected.as_bytes()).into()
}

/// Returns the scope that gates the given JSON-RPC method, if any.
///
/// New gates should be added here in lock-step with the underlying
/// handler — the gate is the only authoritative source for which
/// methods cost which scope.
pub fn required_scope_for_method(method: &str) -> Option<ApiKeyScope> {
    // Canton-mediated namespaces: the node proxies the call to the
    // shared Canton validator party using its own bearer JWT, so the
    // caller must hold a key with the `canton` scope. Both `*Canton*`
    // and `*Daml*` method names route to the same upstream — the gate
    // must catch both substrings.
    if method.starts_with("tenzro_") && (method.contains("Canton") || method.contains("Daml")) {
        return Some(ApiKeyScope::Canton);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::MemoryStore;

    fn mem_store() -> Arc<dyn KvStore> {
        Arc::new(MemoryStore::new())
    }

    #[test]
    fn issue_and_lookup_roundtrip() {
        let mgr = ApiKeyManager::new(mem_store()).unwrap();
        let issued = mgr
            .issue(
                Some("did:tenzro:human:abc".to_string()),
                "test key",
                vec![ApiKeyScope::Canton],
            )
            .unwrap();
        assert!(issued.key.starts_with("tnz_"));
        let found = mgr.lookup(&issued.key).expect("key must resolve");
        assert!(found.has_scope(ApiKeyScope::Canton));
        assert_eq!(found.key_id, issued.record.key_id);
    }

    #[test]
    fn revoke_makes_key_unusable() {
        let mgr = ApiKeyManager::new(mem_store()).unwrap();
        let issued = mgr
            .issue(None, "to revoke", vec![ApiKeyScope::Canton])
            .unwrap();
        let revoked = mgr.revoke_by_id(&issued.record.key_id).unwrap();
        assert!(revoked);
        assert!(mgr.lookup(&issued.key).is_none());
    }

    #[test]
    fn authorize_blocks_unauthenticated_canton() {
        let mgr = ApiKeyManager::new(mem_store()).unwrap();
        let outcome = mgr.authorize(None, "tenzro_listCantonDomains");
        assert_eq!(outcome, AuthorizeOutcome::MissingKey(ApiKeyScope::Canton));
    }

    #[test]
    fn authorize_blocks_unauthenticated_daml() {
        // `*Daml*` method names route to the same upstream Canton
        // participant as `*Canton*` and must share the same gate.
        let mgr = ApiKeyManager::new(mem_store()).unwrap();
        for method in [
            "tenzro_listDamlContracts",
            "tenzro_submitDamlCommand",
            "tenzro_consumeDamlEvents",
        ] {
            let outcome = mgr.authorize(None, method);
            assert_eq!(
                outcome,
                AuthorizeOutcome::MissingKey(ApiKeyScope::Canton),
                "method {} must be gated by canton scope",
                method,
            );
        }
    }

    #[test]
    fn authorize_allows_ungated_method_without_key() {
        let mgr = ApiKeyManager::new(mem_store()).unwrap();
        let outcome = mgr.authorize(None, "tenzro_blockNumber");
        assert_eq!(outcome, AuthorizeOutcome::Allowed);
    }

    #[test]
    fn authorize_rejects_revoked_key() {
        let mgr = ApiKeyManager::new(mem_store()).unwrap();
        let issued = mgr
            .issue(None, "tmp", vec![ApiKeyScope::Canton])
            .unwrap();
        mgr.revoke_by_id(&issued.record.key_id).unwrap();
        let outcome = mgr.authorize(Some(&issued.key), "tenzro_listCantonDomains");
        assert_eq!(outcome, AuthorizeOutcome::UnknownOrRevoked);
    }

    #[test]
    fn hydrate_restores_from_storage() {
        let store = mem_store();
        let mgr = ApiKeyManager::new(store.clone()).unwrap();
        let issued = mgr
            .issue(None, "persisted", vec![ApiKeyScope::Canton])
            .unwrap();
        // Drop and rebuild against the same backing store.
        drop(mgr);
        let mgr2 = ApiKeyManager::new(store).unwrap();
        let found = mgr2.lookup(&issued.key);
        assert!(found.is_some());
    }

    #[test]
    fn admin_token_accepts_exact_match() {
        assert!(verify_admin_token("s3cret-token-value", "s3cret-token-value"));
    }

    #[test]
    fn admin_token_rejects_mismatch() {
        assert!(!verify_admin_token("wrong", "s3cret-token-value"));
        // Same length, different bytes — exercises the ct_eq path rather
        // than the length-prefix short-circuit.
        assert!(!verify_admin_token("s3cret-token-valuX", "s3cret-token-value"));
    }

    #[test]
    fn admin_token_rejects_empty_expected() {
        // A node configured without TENZRO_ADMIN_TOKEN must be unreachable
        // through the gate — including by a caller presenting the empty
        // string.
        assert!(!verify_admin_token("", ""));
        assert!(!verify_admin_token("anything", ""));
    }

    #[test]
    fn admin_token_rejects_empty_presented_against_real_secret() {
        assert!(!verify_admin_token("", "s3cret-token-value"));
    }

    #[test]
    fn admin_token_rejects_prefix() {
        // Confirms that a partial prefix does not authenticate — the
        // length-prefix check short-circuits before ct_eq.
        assert!(!verify_admin_token("s3cret", "s3cret-token-value"));
        assert!(!verify_admin_token("s3cret-token-value-extra", "s3cret-token-value"));
    }
}
