//! DID-resolvable Visa TAP agent registry.
//!
//! Visa's reference TAP implementation uses a centralized JWKS endpoint at
//! `https://mcp.visa.com/.well-known/jwks` with `keyid` referencing the JWK
//! `kid`. RFC 9421 §2.3 leaves `keyid` as an opaque string, so Tenzro lets
//! agents present a DID-form `keyid` such as `did:tenzro:machine:<uuid>` that
//! resolves through the local TDIP identity registry to the agent's Ed25519
//! verification key.
//!
//! This adapter composes the two: when the `keyid` starts with `did:`, it
//! delegates to a [`AgentRegistryClient`] backed by `TenzroAgentRegistry` (or
//! any other DID resolver). For non-DID keyids, it falls back to a JWKS-style
//! client (e.g. [`crate::visa_tap::VisaAgentRegistryClient`]) so cross-network
//! interop with Visa's deployment continues to work.

use async_trait::async_trait;
use std::sync::Arc;
use tracing::debug;

use crate::error::{PaymentError, Result};
use crate::rfc9421::{AgentPublicKeyInfo, AgentRegistryClient};

/// Composite agent registry that prefers DID resolution for `keyid` values
/// shaped like a DID (`did:*:*`) and falls back to a JWKS-style client for
/// every other `keyid`.
///
/// Either side may be omitted: a verifier deployed inside a Tenzro-only mesh
/// can pass `jwks_fallback: None` and reject non-DID keyids; a verifier that
/// proxies for Visa-issued JWKS but happens to live next to a Tenzro identity
/// registry can pass `did_resolver: Some(_)` to opportunistically accept DID
/// keyids.
pub struct DidResolverAgentRegistry {
    did_resolver: Option<Arc<dyn AgentRegistryClient>>,
    jwks_fallback: Option<Arc<dyn AgentRegistryClient>>,
}

impl DidResolverAgentRegistry {
    /// Create a registry with both a DID resolver and a JWKS fallback wired up.
    pub fn new(
        did_resolver: Arc<dyn AgentRegistryClient>,
        jwks_fallback: Arc<dyn AgentRegistryClient>,
    ) -> Self {
        Self {
            did_resolver: Some(did_resolver),
            jwks_fallback: Some(jwks_fallback),
        }
    }

    /// DID-only registry: rejects non-DID keyids outright.
    pub fn did_only(did_resolver: Arc<dyn AgentRegistryClient>) -> Self {
        Self {
            did_resolver: Some(did_resolver),
            jwks_fallback: None,
        }
    }

    /// JWKS-only registry (mostly useful as a transparent passthrough during
    /// migration — equivalent to wrapping the underlying client directly, but
    /// keeps verifier construction shape-stable across deployments).
    pub fn jwks_only(jwks_fallback: Arc<dyn AgentRegistryClient>) -> Self {
        Self {
            did_resolver: None,
            jwks_fallback: Some(jwks_fallback),
        }
    }

    /// Returns true when this `keyid` should be routed through the DID resolver.
    fn is_did_keyid(key_id: &str) -> bool {
        // A DID always starts with the literal `did:` and carries at least one
        // method-specific segment after the method identifier. We only need a
        // cheap prefix test here — full DID syntax validation is the resolver's
        // job (e.g. `tenzro_resolveDidDocument` parses and validates the whole
        // DID string).
        key_id.starts_with("did:")
    }
}

#[async_trait]
impl AgentRegistryClient for DidResolverAgentRegistry {
    async fn get_public_key(&self, key_id: &str) -> Result<AgentPublicKeyInfo> {
        if Self::is_did_keyid(key_id) {
            if let Some(resolver) = &self.did_resolver {
                debug!("Routing DID keyid {} through DID resolver", key_id);
                return resolver.get_public_key(key_id).await;
            }
            return Err(PaymentError::AgentRegistryError(format!(
                "DID keyid {} received but no DID resolver is configured",
                key_id
            )));
        }

        if let Some(fallback) = &self.jwks_fallback {
            debug!("Routing non-DID keyid {} through JWKS fallback", key_id);
            return fallback.get_public_key(key_id).await;
        }

        Err(PaymentError::AgentRegistryError(format!(
            "non-DID keyid {} received but no JWKS fallback is configured",
            key_id
        )))
    }

    async fn verify_agent(&self, key_id: &str) -> Result<bool> {
        if Self::is_did_keyid(key_id) {
            if let Some(resolver) = &self.did_resolver {
                return resolver.verify_agent(key_id).await;
            }
            return Ok(false);
        }

        if let Some(fallback) = &self.jwks_fallback {
            return fallback.verify_agent(key_id).await;
        }

        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfc9421::SignatureAlgorithm;
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// Trivial mock that records which keyid was last queried and which
    /// "tier" (DID resolver vs JWKS fallback) it represents — lets us prove
    /// that `DidResolverAgentRegistry` routes correctly.
    struct TaggedMockRegistry {
        tier: &'static str,
        last_seen: Mutex<Option<String>>,
        keys: HashMap<String, AgentPublicKeyInfo>,
    }

    impl TaggedMockRegistry {
        fn new(tier: &'static str, keys: HashMap<String, AgentPublicKeyInfo>) -> Self {
            Self {
                tier,
                last_seen: Mutex::new(None),
                keys,
            }
        }
    }

    #[async_trait]
    impl AgentRegistryClient for TaggedMockRegistry {
        async fn get_public_key(&self, key_id: &str) -> Result<AgentPublicKeyInfo> {
            *self.last_seen.lock().unwrap() = Some(key_id.to_string());
            self.keys.get(key_id).cloned().ok_or_else(|| {
                PaymentError::AgentRegistryError(format!(
                    "{} tier: key {} not found",
                    self.tier, key_id
                ))
            })
        }

        async fn verify_agent(&self, key_id: &str) -> Result<bool> {
            *self.last_seen.lock().unwrap() = Some(key_id.to_string());
            Ok(self.keys.contains_key(key_id))
        }
    }

    fn key_info(kid: &str, did: Option<&str>) -> AgentPublicKeyInfo {
        AgentPublicKeyInfo {
            key_id: kid.to_string(),
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_bytes: vec![1u8; 32],
            agent_did: did.map(String::from),
            is_active: true,
        }
    }

    #[tokio::test]
    async fn did_keyid_routed_to_did_resolver() {
        let did = "did:tenzro:machine:abc";
        let mut did_keys = HashMap::new();
        did_keys.insert(did.to_string(), key_info(did, Some(did)));
        let did_mock = Arc::new(TaggedMockRegistry::new("did", did_keys));

        let mut jwks_keys = HashMap::new();
        jwks_keys.insert("visa-key-7".to_string(), key_info("visa-key-7", None));
        let jwks_mock = Arc::new(TaggedMockRegistry::new("jwks", jwks_keys));

        let composite = DidResolverAgentRegistry::new(did_mock.clone(), jwks_mock.clone());

        let info = composite.get_public_key(did).await.unwrap();
        assert_eq!(info.key_id, did);
        assert_eq!(info.agent_did.as_deref(), Some(did));
        assert_eq!(did_mock.last_seen.lock().unwrap().as_deref(), Some(did));
        assert!(jwks_mock.last_seen.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn non_did_keyid_routed_to_jwks_fallback() {
        let mut did_keys = HashMap::new();
        did_keys.insert(
            "did:tenzro:machine:abc".to_string(),
            key_info("did:tenzro:machine:abc", Some("did:tenzro:machine:abc")),
        );
        let did_mock = Arc::new(TaggedMockRegistry::new("did", did_keys));

        let mut jwks_keys = HashMap::new();
        jwks_keys.insert("visa-key-7".to_string(), key_info("visa-key-7", None));
        let jwks_mock = Arc::new(TaggedMockRegistry::new("jwks", jwks_keys));

        let composite = DidResolverAgentRegistry::new(did_mock.clone(), jwks_mock.clone());

        let info = composite.get_public_key("visa-key-7").await.unwrap();
        assert_eq!(info.key_id, "visa-key-7");
        assert_eq!(
            jwks_mock.last_seen.lock().unwrap().as_deref(),
            Some("visa-key-7")
        );
        assert!(did_mock.last_seen.lock().unwrap().is_none());
    }

    #[tokio::test]
    async fn did_only_rejects_non_did_keyid() {
        let mut did_keys = HashMap::new();
        did_keys.insert(
            "did:tenzro:machine:abc".to_string(),
            key_info("did:tenzro:machine:abc", Some("did:tenzro:machine:abc")),
        );
        let did_mock = Arc::new(TaggedMockRegistry::new("did", did_keys));

        let composite = DidResolverAgentRegistry::did_only(did_mock);
        let result = composite.get_public_key("visa-key-7").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no JWKS fallback"));
    }

    #[tokio::test]
    async fn jwks_only_rejects_did_keyid() {
        let mut jwks_keys = HashMap::new();
        jwks_keys.insert("visa-key-7".to_string(), key_info("visa-key-7", None));
        let jwks_mock = Arc::new(TaggedMockRegistry::new("jwks", jwks_keys));

        let composite = DidResolverAgentRegistry::jwks_only(jwks_mock);
        let result = composite.get_public_key("did:tenzro:machine:abc").await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("no DID resolver"));
    }

    #[tokio::test]
    async fn verify_agent_routes_correctly() {
        let did = "did:tenzro:machine:abc";
        let mut did_keys = HashMap::new();
        did_keys.insert(did.to_string(), key_info(did, Some(did)));
        let did_mock = Arc::new(TaggedMockRegistry::new("did", did_keys));

        let mut jwks_keys = HashMap::new();
        jwks_keys.insert("visa-key-7".to_string(), key_info("visa-key-7", None));
        let jwks_mock = Arc::new(TaggedMockRegistry::new("jwks", jwks_keys));

        let composite = DidResolverAgentRegistry::new(did_mock.clone(), jwks_mock.clone());

        assert!(composite.verify_agent(did).await.unwrap());
        assert!(composite.verify_agent("visa-key-7").await.unwrap());
        assert!(
            !composite
                .verify_agent("did:tenzro:machine:nope")
                .await
                .unwrap_or(true)
        );
    }

    #[test]
    fn detects_did_prefix() {
        assert!(DidResolverAgentRegistry::is_did_keyid(
            "did:tenzro:machine:abc"
        ));
        assert!(DidResolverAgentRegistry::is_did_keyid(
            "did:web:example.com"
        ));
        assert!(DidResolverAgentRegistry::is_did_keyid("did:key:z6Mk..."));
        assert!(!DidResolverAgentRegistry::is_did_keyid("visa-key-7"));
        assert!(!DidResolverAgentRegistry::is_did_keyid(
            "urn:tenzro:machine:abc"
        ));
        assert!(!DidResolverAgentRegistry::is_did_keyid(""));
    }
}
