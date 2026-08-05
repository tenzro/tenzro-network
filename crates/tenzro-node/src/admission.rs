//! Node-level admission gate: the operator's switch for "nobody uses my node
//! without this key."
//!
//! Wraps [`tenzro_auth::AdmissionPolicy`] with the two things a running node
//! adds to it — persistence and runtime mutability — and applies it at the four
//! service entry points (JSON-RPC, MCP, A2A, HTTP web API).
//!
//! # What it does not touch
//!
//! Consensus and P2P. A gated node still proposes, votes, and gossips. An
//! operator restricting who may call their inference API has said nothing about
//! whether they want to keep validating, and the two must not be coupled: a
//! staked node that quietly stopped participating because of a service-surface
//! setting would be withholding what it is bonded to provide.
//!
//! # Off by default
//!
//! A node with no keys configured admits everything, exactly as before the gate
//! existed. The network is permissionless; this is an operator's local choice,
//! not a protocol change.

use std::sync::Arc;

use axum::{
    Json,
    body::Body,
    extract::{Request, State},
    http::{StatusCode, header::HeaderMap},
    middleware::Next,
    response::{IntoResponse, Response},
};
use parking_lot::RwLock;
use tenzro_auth::{Admission, AdmissionPolicy, ServiceKeyHash, ServiceSurface, admit};
use tenzro_storage::{CF_METADATA, KvStore};
use tracing::{info, warn};

/// Wall-clock now, in Unix milliseconds.
///
/// A service-key grant may carry an expiry, so admission is time-dependent.
/// Read here rather than inside [`tenzro_auth::admit`] so that function stays
/// pure and its tests can pin a clock instead of sleeping.
fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// RocksDB key prefix for accepted service-key digests.
const ACCEPTED_PREFIX: &[u8] = b"admission_key:";
/// RocksDB key prefix for revoked service-key digests.
const REVOKED_PREFIX: &[u8] = b"admission_revoked:";

/// Environment variable carrying plaintext service keys, comma-separated.
///
/// Plaintext is accepted here because the operator has to get the key onto the
/// node somehow and a systemd `EnvironmentFile` with mode 0600 is the ordinary
/// way to do that. It is hashed on the way in and the plaintext is not retained.
const ENV_SERVICE_KEYS: &str = "TENZRO_SERVICE_KEYS";

/// The node's admission gate.
pub struct NodeAdmissionGate {
    policy: RwLock<AdmissionPolicy>,
    storage: Option<Arc<dyn KvStore>>,
}

impl NodeAdmissionGate {
    /// An open gate with no persistence — the default for a node that has not
    /// configured one.
    pub fn new() -> Self {
        Self {
            policy: RwLock::new(AdmissionPolicy::open()),
            storage: None,
        }
    }

    /// Build the gate from persisted state, the node config, and the
    /// environment.
    ///
    /// Sources are additive: a key from any of the three is accepted, and a
    /// revocation from storage beats all of them. Revocations are loaded first
    /// so a key that was revoked while the node was down cannot be re-admitted
    /// by a config file the operator forgot to edit.
    /// `admin_token` is the operator's own credential, folded in below so a
    /// gated node stays reachable by the person who gated it. Passed in rather
    /// than read from the environment here so the node reads it once, in one
    /// place.
    pub fn load(
        storage: Option<Arc<dyn KvStore>>,
        config_keys: &[String],
        admin_token: Option<&str>,
    ) -> Self {
        let mut policy = AdmissionPolicy::open();

        if let Some(store) = storage.as_ref() {
            match store.get_keys_with_prefix(CF_METADATA, REVOKED_PREFIX) {
                Ok(keys) => {
                    for key in keys {
                        if let Some(hex) = digest_from_key(&key, REVOKED_PREFIX) {
                            policy.revoke_key(ServiceKeyHash::from_hex(hex));
                        }
                    }
                }
                Err(e) => warn!("admission gate: could not read revocations: {e}"),
            }
            match store.get_keys_with_prefix(CF_METADATA, ACCEPTED_PREFIX) {
                Ok(keys) => {
                    for key in keys {
                        if let Some(hex) = digest_from_key(&key, ACCEPTED_PREFIX) {
                            policy.accept_key(ServiceKeyHash::from_hex(hex));
                        }
                    }
                }
                Err(e) => warn!("admission gate: could not read stored keys: {e}"),
            }
        }

        // Config carries digests, not plaintext — an operator's config file is
        // the wrong place for a secret, and a digest is enough to admit.
        for hex in config_keys {
            policy.accept_key(ServiceKeyHash::from_hex(hex.trim()));
        }

        if let Ok(raw) = std::env::var(ENV_SERVICE_KEYS) {
            for key in raw.split(',').map(str::trim).filter(|k| !k.is_empty()) {
                policy.accept_key(ServiceKeyHash::from_plaintext(key));
            }
        }

        // The operator's own admin token is admitted as a service key, but
        // only once some *other* key has turned the gate on — otherwise
        // merely setting `TENZRO_ADMIN_TOKEN` would silently gate a node
        // whose operator never asked for a gate.
        //
        // Without this an operator who set a service key and holds the admin
        // token is locked out of their own node's RPC, and the only remedy is
        // editing the config and restarting. The operator's credential is at
        // least as strong as any key they would have issued.
        if policy.is_enabled()
            && let Some(token) = admin_token.filter(|t| !t.is_empty())
        {
            policy.accept_key(ServiceKeyHash::from_plaintext(token));
        }

        if policy.is_enabled() {
            // The count, never the keys. A digest in a log is not a secret but
            // it is a target, and there is no operational question it answers.
            info!(
                keys = policy.accepted_len(),
                "node admission gate ENABLED — JSON-RPC, MCP, A2A and the web API require a service key"
            );
        }

        Self {
            policy: RwLock::new(policy),
            storage,
        }
    }

    /// Whether the gate is active.
    pub fn is_enabled(&self) -> bool {
        self.policy.read().is_enabled()
    }

    /// How many keys are accepted.
    pub fn accepted_len(&self) -> usize {
        self.policy.read().accepted_len()
    }

    /// Decide one request.
    pub fn admit(
        &self,
        surface: ServiceSurface,
        path: &str,
        presented_key: Option<&str>,
    ) -> Admission {
        admit(
            &self.policy.read(),
            surface,
            path,
            presented_key,
            now_unix_ms(),
        )
    }

    /// Accept a new key at runtime, persisting it so it survives a restart.
    ///
    /// Takes plaintext because the caller is an operator adding a key they
    /// just generated; only the digest is stored.
    pub fn add_key(&self, plaintext: &str) -> Result<String, String> {
        let hash = ServiceKeyHash::from_plaintext(plaintext);
        let hex = hash.as_hex().to_string();
        self.persist(ACCEPTED_PREFIX, &hex)?;
        self.policy.write().accept_key(hash);
        Ok(hex)
    }

    /// Accept a key with an explicit grant — scoped surfaces and a term.
    ///
    /// Used by the lease registry, which mints keys for rentals. Deliberately
    /// **not** persisted into the admission column family: the lease record is
    /// already durable and is the source of truth, and writing a second copy
    /// here would let a key outlive the lease that justified it — the exact
    /// failure the grant's term exists to prevent. Leases are re-registered
    /// from storage when the gate is attached.
    ///
    /// The operator issues these; see `remote_access::LeaseRegistry`, whose
    /// open/revoke RPCs are admin-token gated.
    pub fn accept_grant(&self, grant: tenzro_auth::ServiceKeyGrant) {
        self.policy.write().accept_grant(grant);
    }

    /// Revoke a key by its digest.
    ///
    /// Revocation is recorded rather than the acceptance being deleted, so a
    /// config file or environment variable that still names the key cannot
    /// re-admit it at the next start.
    pub fn revoke_key(&self, hex_digest: &str) -> Result<(), String> {
        let hash = ServiceKeyHash::from_hex(hex_digest);
        self.persist(REVOKED_PREFIX, hash.as_hex())?;
        self.policy.write().revoke_key(hash);
        Ok(())
    }

    fn persist(&self, prefix: &[u8], hex: &str) -> Result<(), String> {
        let Some(store) = self.storage.as_ref() else {
            // No storage means no durability. Say so rather than reporting a
            // success the operator would discover was a lie at the next restart.
            return Err(
                "node has no storage open; the admission gate cannot persist this change"
                    .to_string(),
            );
        };
        let mut key = prefix.to_vec();
        key.extend_from_slice(hex.as_bytes());
        store
            .put(CF_METADATA, &key, b"1")
            .map_err(|e| format!("admission gate persist failed: {e}"))
    }
}

impl Default for NodeAdmissionGate {
    fn default() -> Self {
        Self::new()
    }
}

/// Header carrying the operator's service key.
///
/// A dedicated header rather than `Authorization`, which on this node already
/// carries DPoP-bound JWTs. Overloading it would make "which credential was
/// this request refused for?" ambiguous at exactly the moment an operator is
/// trying to answer it.
pub const SERVICE_KEY_HEADER: &str = "x-tenzro-service-key";

/// Header carrying the operator admin token.
///
/// Accepted as a service key so an operator who gated their node is not
/// locked out of it by their own setting — see [`NodeAdmissionGate::load`].
const ADMIN_TOKEN_HEADER: &str = "x-tenzro-admin-token";

/// Pull the presented service key out of a request's headers.
///
/// Falls back to the admin token header so an operator's existing tooling
/// reaches a gated node without also learning a second header.
fn presented_key(headers: &HeaderMap) -> Option<&str> {
    [SERVICE_KEY_HEADER, ADMIN_TOKEN_HEADER]
        .into_iter()
        .find_map(|name| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::trim)
                .filter(|k| !k.is_empty())
        })
}

/// The one middleware, applied at each of the four service entry points.
///
/// Deliberately a single layer rather than a per-method check: the per-method
/// model means every method added later defaults to reachable and has to be
/// remembered, and that default has already produced gaps on this node.
///
/// Takes the gate rather than the whole node so the same layer mounts on all
/// four routers, whose axum states differ (`Arc<TenzroNode>` for JSON-RPC,
/// `Arc<WebState>` for the web API, `Arc<A2aState>` for A2A, an OAuth state
/// for MCP). `surface` is fixed per mount point by the caller — which is also
/// why [`ServiceSurface`] has no consensus variant: no mount point could
/// pass one.
pub async fn gate_request(
    surface: ServiceSurface,
    State(gate): State<Arc<NodeAdmissionGate>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let path = request.uri().path().to_string();
    let key = presented_key(request.headers()).map(str::to_owned);

    match gate.admit(surface, &path, key.as_deref()) {
        Admission::Allow => next.run(request).await,
        Admission::Deny(reason) => {
            // 401 rather than 403: the caller can fix this by presenting a
            // credential, which is what 401 means. The body names the header
            // because a would-be user of a gated node otherwise has no way to
            // learn how to authenticate.
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({
                    "error": reason,
                    "header": SERVICE_KEY_HEADER,
                    "surface": surface.as_str(),
                })),
            )
                .into_response()
        }
    }
}

/// Recover the hex digest from a prefixed RocksDB key.
fn digest_from_key(key: &[u8], prefix: &[u8]) -> Option<String> {
    let rest = key.strip_prefix(prefix)?;
    std::str::from_utf8(rest).ok().map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_storage::MemoryStore;

    fn store() -> Arc<dyn KvStore> {
        Arc::new(MemoryStore::new())
    }

    #[test]
    fn a_node_with_nothing_configured_admits_everything() {
        let gate = NodeAdmissionGate::load(Some(store()), &[], None);
        assert!(!gate.is_enabled());
        assert!(
            gate.admit(ServiceSurface::JsonRpc, "/", None).is_allowed(),
            "the network is permissionless by default"
        );
    }

    #[test]
    fn a_key_added_at_runtime_gates_the_node_and_survives_a_restart() {
        let store = store();
        let gate = NodeAdmissionGate::load(Some(store.clone()), &[], None);
        gate.add_key("operator-chosen-key").unwrap();

        assert!(gate.is_enabled());
        assert!(!gate.admit(ServiceSurface::Mcp, "/mcp", None).is_allowed());
        assert!(
            gate.admit(ServiceSurface::Mcp, "/mcp", Some("operator-chosen-key"))
                .is_allowed()
        );

        let restarted = NodeAdmissionGate::load(Some(store), &[], None);
        assert!(
            restarted
                .admit(ServiceSurface::Mcp, "/mcp", Some("operator-chosen-key"))
                .is_allowed(),
            "a key added at runtime must still be accepted after a restart"
        );
    }

    /// The reason revocation is stored rather than the acceptance being
    /// deleted: the operator's config file still names the key, and a restart
    /// must not undo the revocation.
    #[test]
    fn revocation_survives_a_restart_that_reloads_the_key_from_config() {
        let store = store();
        let digest = {
            let gate = NodeAdmissionGate::load(Some(store.clone()), &[], None);
            let digest = gate.add_key("leaked-key").unwrap();
            gate.revoke_key(&digest).unwrap();
            digest
        };

        let restarted = NodeAdmissionGate::load(Some(store), std::slice::from_ref(&digest), None);
        assert!(
            !restarted
                .admit(ServiceSurface::JsonRpc, "/", Some("leaked-key"))
                .is_allowed(),
            "a revoked key must stay revoked even though config still lists it"
        );
    }

    #[test]
    fn config_digests_are_accepted_without_the_plaintext_ever_being_configured() {
        let digest = ServiceKeyHash::from_plaintext("shared-with-the-renter")
            .as_hex()
            .to_string();
        let gate = NodeAdmissionGate::load(Some(store()), &[digest], None);
        assert!(
            gate.admit(
                ServiceSurface::WebApi,
                "/status",
                Some("shared-with-the-renter")
            )
            .is_allowed()
        );
    }

    #[test]
    fn liveness_probes_stay_reachable_on_a_gated_node() {
        let gate = NodeAdmissionGate::load(Some(store()), &[], None);
        gate.add_key("k").unwrap();
        for path in ["/health", "/ready", "/verify/health", "/verify/ready"] {
            assert!(gate.admit(ServiceSurface::WebApi, path, None).is_allowed());
        }
    }

    /// An operator who gates their node must not be locked out of it by
    /// their own setting. The remedy would otherwise be editing the config
    /// and restarting — at the exact moment they are trying to revoke a
    /// leaked key.
    #[test]
    fn the_admin_token_reaches_a_gated_node() {
        let store = store();
        NodeAdmissionGate::load(Some(store.clone()), &[], None)
            .add_key("renter-key")
            .unwrap();
        let gate = NodeAdmissionGate::load(Some(store), &[], Some("operator-admin-token"));

        assert!(gate.is_enabled());
        assert!(
            gate.admit(ServiceSurface::JsonRpc, "/", Some("operator-admin-token"))
                .is_allowed()
        );
        assert!(!gate.admit(ServiceSurface::JsonRpc, "/", None).is_allowed());
    }

    /// The other half of that rule: an admin token alone must not turn a gate
    /// on, or every node on the network that set `TENZRO_ADMIN_TOKEN` would
    /// silently stop serving.
    #[test]
    fn an_admin_token_alone_does_not_gate_the_node() {
        let gate = NodeAdmissionGate::load(Some(store()), &[], Some("operator-admin-token"));

        assert!(!gate.is_enabled());
        assert!(gate.admit(ServiceSurface::JsonRpc, "/", None).is_allowed());
    }

    #[test]
    fn either_header_can_carry_the_key() {
        let mut headers = HeaderMap::new();
        headers.insert(SERVICE_KEY_HEADER, "from-service-header".parse().unwrap());
        assert_eq!(presented_key(&headers), Some("from-service-header"));

        let mut headers = HeaderMap::new();
        headers.insert(ADMIN_TOKEN_HEADER, "from-admin-header".parse().unwrap());
        assert_eq!(presented_key(&headers), Some("from-admin-header"));

        let mut headers = HeaderMap::new();
        headers.insert(SERVICE_KEY_HEADER, "   ".parse().unwrap());
        assert_eq!(
            presented_key(&headers),
            None,
            "a blank header is no key, not an empty-string key"
        );
    }

    /// Reporting success for a change that was never written would be
    /// discovered only at the next restart, by which point the operator
    /// believes a key is revoked that is not.
    #[test]
    fn a_gate_with_no_storage_refuses_to_claim_it_persisted() {
        let gate = NodeAdmissionGate::new();
        assert!(gate.add_key("k").is_err());
        assert!(gate.revoke_key(&"0".repeat(64)).is_err());
    }
}
