//! Permissionless application registry for developer payments.
//!
//! Developers who run their own fiat rails (Stripe, Bridge, or any PSP)
//! register their application here by signing the registration with their
//! TDIP DID. The node never touches a payment-provider secret — the registry
//! only records what any node needs to verify a developer-signed settlement
//! authorization and to apply the declared margin:
//!
//! - the developer's DID and the app's TNZO wallet (the developer's own
//!   treasury for this app — funds move FROM this wallet at settlement),
//! - the Ed25519 keys authorized to sign `SettlementAuthorization`s,
//! - the declared `margin_bps` (capped by
//!   [`tenzro_types::MAX_DEVELOPER_MARGIN_BPS`] as abuse / fat-finger
//!   protection),
//! - a `min_balance` the developer commits to keeping in the app wallet so
//!   underfunding is visible before settlements start failing.
//!
//! Registration and status changes are authorized by a
//! [`TenzroDidEnvelope`] whose `params_hash` binds the exact record being
//! written, so any node can verify the write without trusting the caller.
//! Records persist to `CF_SETTLEMENTS` under the `app:` prefix and hydrate
//! on startup, so every node converges on the same registry.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tenzro_identity::{IdentityRegistry, TenzroDidEnvelope, params_hash, verify_envelope};
use tenzro_storage::{CF_SETTLEMENTS, KvStore};
use tenzro_types::MAX_DEVELOPER_MARGIN_BPS;
use tenzro_types::primitives::Address;

use crate::error::{NodeError, Result};

/// RocksDB key prefix for app records in `CF_SETTLEMENTS`.
const APP_RECORD_PREFIX: &[u8] = b"app:";

/// Envelope `method` required on registration writes.
pub const METHOD_REGISTER_APP: &str = "tenzro_registerApp";

/// Envelope `method` required on status writes.
pub const METHOD_SET_APP_STATUS: &str = "tenzro_setAppStatus";

/// Domain tag bound into the canonical registration params.
const APP_REGISTRATION_DOMAIN: &[u8] = b"tenzro/app/registration";

/// Domain tag bound into the canonical status-change params.
const APP_STATUS_DOMAIN: &[u8] = b"tenzro/app/status";

/// An Ed25519 key authorized to sign settlement authorizations for an app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppSigningKey {
    /// Developer-chosen identifier for the key (e.g. `"backend-primary"`).
    pub key_id: String,
    /// Raw 32-byte Ed25519 public key.
    pub public_key: Vec<u8>,
    /// Optional per-day settlement ceiling (smallest TNZO unit) for this
    /// key. `None` means unrestricted — appropriate for the developer's
    /// primary backend key; session-scoped keys should carry a ceiling.
    pub daily_limit_tnzo: Option<u128>,
}

/// A registered application.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppRecord {
    /// Developer-chosen application identifier. First-writer-wins: once
    /// registered, only the same `developer_did` may update it.
    pub app_id: String,
    /// The developer's TDIP DID. Signs every registry write and every
    /// settlement authorization chain of trust starts here.
    pub developer_did: String,
    /// The developer's own TNZO treasury wallet for this app. Settlements
    /// move TNZO FROM this wallet; the network never holds a float.
    pub app_wallet: Address,
    /// Keys authorized to sign `SettlementAuthorization`s for this app.
    pub signing_pubkeys: Vec<AppSigningKey>,
    /// Developer margin applied on top of network cost at settlement,
    /// in basis points. Capped by [`MAX_DEVELOPER_MARGIN_BPS`].
    pub margin_bps: u32,
    /// Balance floor (smallest TNZO unit) the developer commits to keep in
    /// `app_wallet`. Below this, the app is flagged underfunded.
    pub min_balance: u128,
    /// Unix milliseconds of first registration. Server-set; preserved
    /// across updates.
    pub created_at: u64,
    /// Whether the app accepts settlements. Toggled via a signed status
    /// write.
    pub active: bool,
}

impl AppRecord {
    /// Canonical byte encoding of the developer-signed registration fields.
    ///
    /// `created_at` is excluded (server-set). Every variable-length field is
    /// u32-BE length-prefixed; integers are fixed-width BE.
    pub fn canonical_params(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(256);
        buf.extend_from_slice(APP_REGISTRATION_DOMAIN);
        push_bytes(&mut buf, self.app_id.as_bytes());
        push_bytes(&mut buf, self.developer_did.as_bytes());
        push_bytes(&mut buf, self.app_wallet.as_bytes());
        buf.extend_from_slice(&(self.signing_pubkeys.len() as u32).to_be_bytes());
        for key in &self.signing_pubkeys {
            push_bytes(&mut buf, key.key_id.as_bytes());
            push_bytes(&mut buf, &key.public_key);
            match key.daily_limit_tnzo {
                Some(limit) => {
                    buf.push(1);
                    buf.extend_from_slice(&limit.to_be_bytes());
                }
                None => buf.push(0),
            }
        }
        buf.extend_from_slice(&self.margin_bps.to_be_bytes());
        buf.extend_from_slice(&self.min_balance.to_be_bytes());
        buf.push(self.active as u8);
        buf
    }

    /// Structural validation independent of any signature.
    pub fn validate(&self) -> Result<()> {
        if self.app_id.is_empty() || self.app_id.len() > 128 {
            return Err(NodeError::InvalidState(
                "app_id must be 1..=128 bytes".to_string(),
            ));
        }
        if self.developer_did.is_empty() {
            return Err(NodeError::InvalidState(
                "developer_did must not be empty".to_string(),
            ));
        }
        if self.signing_pubkeys.is_empty() {
            return Err(NodeError::InvalidState(
                "at least one signing key is required".to_string(),
            ));
        }
        for key in &self.signing_pubkeys {
            if key.key_id.is_empty() || key.key_id.len() > 64 {
                return Err(NodeError::InvalidState(
                    "signing key_id must be 1..=64 bytes".to_string(),
                ));
            }
            if key.public_key.len() != 32 {
                return Err(NodeError::InvalidState(format!(
                    "signing key '{}' is not a 32-byte Ed25519 public key",
                    key.key_id
                )));
            }
        }
        if self.margin_bps > MAX_DEVELOPER_MARGIN_BPS {
            return Err(NodeError::InvalidState(format!(
                "margin_bps {} exceeds protocol cap {}",
                self.margin_bps, MAX_DEVELOPER_MARGIN_BPS
            )));
        }
        Ok(())
    }
}

/// Canonical byte encoding of a signed status change.
pub fn canonical_status_params(app_id: &str, active: bool) -> Vec<u8> {
    let mut buf = Vec::with_capacity(APP_STATUS_DOMAIN.len() + 4 + app_id.len() + 1);
    buf.extend_from_slice(APP_STATUS_DOMAIN);
    push_bytes(&mut buf, app_id.as_bytes());
    buf.push(active as u8);
    buf
}

fn push_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// In-memory + persistent application registry.
///
/// Lookups hit the in-memory cache; writes go through to `CF_SETTLEMENTS`
/// under the `app:` prefix. On construction, the registry hydrates from
/// RocksDB so registered apps survive node restarts.
pub struct AppRegistry {
    storage: Arc<dyn KvStore>,
    cache: RwLock<HashMap<String, AppRecord>>,
}

impl std::fmt::Debug for AppRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppRegistry")
            .field("cached", &self.cache.read().len())
            .finish()
    }
}

impl AppRegistry {
    /// Constructs a registry backed by the given KV store and hydrates the
    /// in-memory cache from `CF_SETTLEMENTS`.
    pub fn new(storage: Arc<dyn KvStore>) -> Result<Arc<Self>> {
        let registry = Self {
            storage,
            cache: RwLock::new(HashMap::new()),
        };
        registry.hydrate()?;
        Ok(Arc::new(registry))
    }

    /// Loads all existing records from `CF_SETTLEMENTS` into the cache.
    fn hydrate(&self) -> Result<()> {
        let entries = self
            .storage
            .scan_prefix(CF_SETTLEMENTS, APP_RECORD_PREFIX)
            .map_err(|e| NodeError::Internal(format!("app registry hydrate scan failed: {}", e)))?;

        let mut cache = self.cache.write();
        for (_key, value) in entries {
            let record: AppRecord = match serde_json::from_slice(&value) {
                Ok(r) => r,
                Err(_) => continue,
            };
            cache.insert(record.app_id.clone(), record);
        }
        Ok(())
    }

    fn persist(&self, record: &AppRecord) -> Result<()> {
        let mut key = APP_RECORD_PREFIX.to_vec();
        key.extend_from_slice(record.app_id.as_bytes());
        let value = serde_json::to_vec(record)
            .map_err(|e| NodeError::Internal(format!("app record serialize failed: {}", e)))?;
        self.storage
            .put(CF_SETTLEMENTS, &key, &value)
            .map_err(|e| NodeError::Internal(format!("app record persist failed: {}", e)))?;
        Ok(())
    }

    /// Registers (or updates) an app from a developer-signed envelope.
    ///
    /// The envelope must:
    /// - carry `method == `[`METHOD_REGISTER_APP`],
    /// - be signed by `record.developer_did`,
    /// - bind `params_hash` to [`AppRecord::canonical_params`] of the exact
    ///   record being written.
    ///
    /// Registration is permissionless and first-writer-wins on `app_id`:
    /// an existing app may only be updated by the DID that registered it.
    /// `created_at` is server-set on first registration and preserved on
    /// updates regardless of the caller-supplied value.
    pub fn register_signed(
        &self,
        mut record: AppRecord,
        envelope: &TenzroDidEnvelope,
        identity_registry: &IdentityRegistry,
    ) -> Result<AppRecord> {
        if envelope.method != METHOD_REGISTER_APP {
            return Err(NodeError::InvalidState(format!(
                "envelope method '{}' does not authorize app registration",
                envelope.method
            )));
        }
        if envelope.did != record.developer_did {
            return Err(NodeError::InvalidState(
                "envelope DID does not match developer_did".to_string(),
            ));
        }
        if envelope.params_hash != params_hash(&record.canonical_params()) {
            return Err(NodeError::InvalidState(
                "envelope params_hash does not bind this app record".to_string(),
            ));
        }
        verify_envelope(envelope, identity_registry)
            .map_err(|e| NodeError::InvalidState(format!("envelope verification failed: {}", e)))?;
        record.validate()?;

        let existing_created_at = {
            let cache = self.cache.read();
            match cache.get(&record.app_id) {
                Some(existing) if existing.developer_did != record.developer_did => {
                    return Err(NodeError::InvalidState(format!(
                        "app_id '{}' is registered to a different developer",
                        record.app_id
                    )));
                }
                Some(existing) => Some(existing.created_at),
                None => None,
            }
        };
        record.created_at = existing_created_at.unwrap_or_else(now_ms);

        self.persist(&record)?;
        self.cache
            .write()
            .insert(record.app_id.clone(), record.clone());
        Ok(record)
    }

    /// Activates or deactivates an app from a developer-signed envelope.
    ///
    /// The envelope must carry `method == `[`METHOD_SET_APP_STATUS`], be
    /// signed by the registered `developer_did`, and bind `params_hash` to
    /// [`canonical_status_params`] of `(app_id, active)`.
    pub fn set_active_signed(
        &self,
        app_id: &str,
        active: bool,
        envelope: &TenzroDidEnvelope,
        identity_registry: &IdentityRegistry,
    ) -> Result<AppRecord> {
        if envelope.method != METHOD_SET_APP_STATUS {
            return Err(NodeError::InvalidState(format!(
                "envelope method '{}' does not authorize app status change",
                envelope.method
            )));
        }
        if envelope.params_hash != params_hash(&canonical_status_params(app_id, active)) {
            return Err(NodeError::InvalidState(
                "envelope params_hash does not bind this status change".to_string(),
            ));
        }

        let mut record = self
            .get(app_id)
            .ok_or_else(|| NodeError::InvalidState(format!("unknown app_id '{}'", app_id)))?;
        if envelope.did != record.developer_did {
            return Err(NodeError::InvalidState(
                "envelope DID does not match the registered developer_did".to_string(),
            ));
        }
        verify_envelope(envelope, identity_registry)
            .map_err(|e| NodeError::InvalidState(format!("envelope verification failed: {}", e)))?;

        record.active = active;
        self.persist(&record)?;
        self.cache
            .write()
            .insert(app_id.to_string(), record.clone());
        Ok(record)
    }

    /// Looks up an app by id.
    pub fn get(&self, app_id: &str) -> Option<AppRecord> {
        self.cache.read().get(app_id).cloned()
    }

    /// Lists all registered apps, sorted by `app_id`.
    pub fn list(&self) -> Vec<AppRecord> {
        let mut records: Vec<AppRecord> = self.cache.read().values().cloned().collect();
        records.sort_by(|a, b| a.app_id.cmp(&b.app_id));
        records
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::keys::{KeyPair, KeyType};
    use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
    use tenzro_identity::canonical_preimage;
    use tenzro_storage::MemoryStore;

    /// did:key DID + signer for a fresh Ed25519 keypair, so envelope
    /// verification resolves without a populated identity registry.
    fn did_key_signer() -> (String, Ed25519SignerImpl) {
        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let pk = kp.public_key().as_bytes().to_vec();
        // did:key multicodec prefix for Ed25519 is 0xed 0x01.
        let mut multicodec = vec![0xed, 0x01];
        multicodec.extend_from_slice(&pk);
        let did = format!("did:key:z{}", bs58::encode(multicodec).into_string());
        (did, Ed25519SignerImpl::new(kp).unwrap())
    }

    fn signed_envelope(
        did: &str,
        signer: &Ed25519SignerImpl,
        method: &str,
        params: &[u8],
    ) -> TenzroDidEnvelope {
        let mut env = TenzroDidEnvelope {
            did: did.to_string(),
            method: method.to_string(),
            params_hash: params_hash(params),
            timestamp: now_ms(),
            nonce: [7u8; 16],
            signature: Vec::new(),
        };
        env.signature = signer
            .sign(&canonical_preimage(&env))
            .unwrap()
            .as_bytes()
            .to_vec();
        env
    }

    fn sample_record(developer_did: &str, signing_key: Vec<u8>) -> AppRecord {
        AppRecord {
            app_id: "demo-app".to_string(),
            developer_did: developer_did.to_string(),
            app_wallet: Address::new([0xAA; 32]),
            signing_pubkeys: vec![AppSigningKey {
                key_id: "backend-primary".to_string(),
                public_key: signing_key,
                daily_limit_tnzo: None,
            }],
            margin_bps: 1000,
            min_balance: 1_000_000_000_000_000_000,
            created_at: 0,
            active: true,
        }
    }

    fn registry() -> Arc<AppRegistry> {
        AppRegistry::new(Arc::new(MemoryStore::new())).unwrap()
    }

    #[test]
    fn register_and_hydrate_roundtrip() {
        let storage: Arc<dyn KvStore> = Arc::new(MemoryStore::new());
        let registry = AppRegistry::new(storage.clone()).unwrap();
        let identities = IdentityRegistry::new();
        let (did, signer) = did_key_signer();
        let record = sample_record(&did, vec![1u8; 32]);

        let env = signed_envelope(
            &did,
            &signer,
            METHOD_REGISTER_APP,
            &record.canonical_params(),
        );
        let stored = registry
            .register_signed(record.clone(), &env, &identities)
            .unwrap();
        assert!(stored.created_at > 0);
        assert_eq!(registry.get("demo-app").unwrap().developer_did, did);

        // Fresh registry over the same storage sees the record.
        let rehydrated = AppRegistry::new(storage).unwrap();
        assert_eq!(rehydrated.get("demo-app").unwrap(), stored);
        assert_eq!(rehydrated.list().len(), 1);
    }

    #[test]
    fn rejects_margin_above_cap() {
        let registry = registry();
        let identities = IdentityRegistry::new();
        let (did, signer) = did_key_signer();
        let mut record = sample_record(&did, vec![1u8; 32]);
        record.margin_bps = MAX_DEVELOPER_MARGIN_BPS + 1;

        let env = signed_envelope(
            &did,
            &signer,
            METHOD_REGISTER_APP,
            &record.canonical_params(),
        );
        assert!(registry.register_signed(record, &env, &identities).is_err());
    }

    #[test]
    fn rejects_takeover_by_other_did() {
        let registry = registry();
        let identities = IdentityRegistry::new();
        let (did_a, signer_a) = did_key_signer();
        let record_a = sample_record(&did_a, vec![1u8; 32]);
        let env_a = signed_envelope(
            &did_a,
            &signer_a,
            METHOD_REGISTER_APP,
            &record_a.canonical_params(),
        );
        registry
            .register_signed(record_a, &env_a, &identities)
            .unwrap();

        let (did_b, signer_b) = did_key_signer();
        let record_b = sample_record(&did_b, vec![2u8; 32]);
        let env_b = signed_envelope(
            &did_b,
            &signer_b,
            METHOD_REGISTER_APP,
            &record_b.canonical_params(),
        );
        let err = registry
            .register_signed(record_b, &env_b, &identities)
            .unwrap_err();
        assert!(err.to_string().contains("different developer"));
    }

    #[test]
    fn rejects_mismatched_params_hash() {
        let registry = registry();
        let identities = IdentityRegistry::new();
        let (did, signer) = did_key_signer();
        let record = sample_record(&did, vec![1u8; 32]);

        // Envelope binds different params than the submitted record.
        let env = signed_envelope(&did, &signer, METHOD_REGISTER_APP, b"other-params");
        assert!(registry.register_signed(record, &env, &identities).is_err());
    }

    #[test]
    fn status_change_requires_developer_signature() {
        let registry = registry();
        let identities = IdentityRegistry::new();
        let (did, signer) = did_key_signer();
        let record = sample_record(&did, vec![1u8; 32]);
        let env = signed_envelope(
            &did,
            &signer,
            METHOD_REGISTER_APP,
            &record.canonical_params(),
        );
        registry.register_signed(record, &env, &identities).unwrap();

        // Developer deactivates their app.
        let status_env = signed_envelope(
            &did,
            &signer,
            METHOD_SET_APP_STATUS,
            &canonical_status_params("demo-app", false),
        );
        let updated = registry
            .set_active_signed("demo-app", false, &status_env, &identities)
            .unwrap();
        assert!(!updated.active);

        // A different DID cannot flip it back.
        let (other_did, other_signer) = did_key_signer();
        let forged = signed_envelope(
            &other_did,
            &other_signer,
            METHOD_SET_APP_STATUS,
            &canonical_status_params("demo-app", true),
        );
        assert!(
            registry
                .set_active_signed("demo-app", true, &forged, &identities)
                .is_err()
        );
    }
}
