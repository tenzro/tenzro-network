//! Agent registry abstraction for public key lookup
//!
//! Provides trait-based abstraction for looking up agent public keys and
//! verification status. Includes a Tenzro identity registry implementation.

use crate::error::{PaymentError, Result};
use crate::rfc9421::SignatureAlgorithm;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_identity::{IdentityRegistry, IdentityStatus};
use tracing::debug;

/// Agent public key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentPublicKeyInfo {
    /// Key identifier
    pub key_id: String,
    /// Signature algorithm for this key
    pub algorithm: SignatureAlgorithm,
    /// Raw public key bytes
    pub public_key_bytes: Vec<u8>,
    /// Optional agent DID
    pub agent_did: Option<String>,
    /// Whether the agent is currently active
    pub is_active: bool,
}

/// Trait for looking up agent public keys
///
/// This abstraction allows different implementations (Tenzro identity registry,
/// external registries, mock implementations for testing, etc.)
#[async_trait]
pub trait AgentRegistryClient: Send + Sync {
    /// Get public key information for an agent
    ///
    /// # Arguments
    ///
    /// * `key_id` - The key identifier (may be a DID, key fingerprint, etc.)
    ///
    /// # Returns
    ///
    /// Agent public key information if found
    async fn get_public_key(&self, key_id: &str) -> Result<AgentPublicKeyInfo>;

    /// Verify that an agent is active and authorized
    ///
    /// # Arguments
    ///
    /// * `key_id` - The key identifier
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the agent is active, `Ok(false)` if inactive, error if not found
    async fn verify_agent(&self, key_id: &str) -> Result<bool>;
}

/// Tenzro identity registry implementation
///
/// Resolves agent DIDs from the Tenzro identity registry and extracts
/// public keys for signature verification.
pub struct TenzroAgentRegistry {
    identity_registry: Arc<IdentityRegistry>,
}

impl TenzroAgentRegistry {
    /// Create a new Tenzro agent registry
    ///
    /// # Arguments
    ///
    /// * `identity_registry` - The Tenzro identity registry instance
    pub fn new(identity_registry: Arc<IdentityRegistry>) -> Self {
        Self { identity_registry }
    }

    /// Enumerate every RFC-9421-compatible public key across all registered
    /// identities, formatted as [`AgentPublicKeyInfo`] records. Keys whose
    /// `key_type` is not a supported signing algorithm (e.g. `Secp256k1`,
    /// `X25519`) are silently skipped — they exist for other purposes
    /// (block signing, key agreement) and must not appear in the JWKS.
    ///
    /// The `key_id` on each record is encoded as `<agent_did>#<fragment>` so
    /// downstream consumers can resolve a specific key with
    /// [`AgentRegistryClient::get_public_key`].
    pub fn list_all_agents(&self) -> Vec<AgentPublicKeyInfo> {
        let mut out = Vec::new();
        for (_did_str, identity) in self.identity_registry.list_all() {
            let did = identity.did.to_string();
            let is_active = matches!(identity.status, IdentityStatus::Active);
            for pk in &identity.public_keys {
                let Ok(algorithm) = key_type_to_algorithm(&pk.key_type) else {
                    continue;
                };
                out.push(AgentPublicKeyInfo {
                    key_id: format!("{}#{}", did, pk.key_id),
                    algorithm,
                    public_key_bytes: pk.public_key.clone(),
                    agent_did: Some(did.clone()),
                    is_active,
                });
            }
        }
        out
    }
}

/// Map a `tenzro_identity::PublicKeyInfo.key_type` string to a
/// [`SignatureAlgorithm`].
///
/// Identities currently store `"Ed25519"`, `"Secp256k1"`, `"P256"`, `"P384"`,
/// or `"Rsa"`. Returns `Err` for unrecognized values rather than silently
/// defaulting — callers must surface the unsupported algorithm to the verifier.
pub(crate) fn key_type_to_algorithm(key_type: &str) -> Result<SignatureAlgorithm> {
    match key_type {
        "Ed25519" => Ok(SignatureAlgorithm::Ed25519),
        "P256" | "EcdsaP256" | "ecdsa-p256" => Ok(SignatureAlgorithm::EcdsaP256Sha256),
        "P384" | "EcdsaP384" | "ecdsa-p384" => Ok(SignatureAlgorithm::EcdsaP384Sha384),
        "RsaPss" | "rsa-pss-sha256" => Ok(SignatureAlgorithm::RsaPssSha256),
        "RsaPssSha512" | "rsa-pss-sha512" => Ok(SignatureAlgorithm::RsaPssSha512),
        "Rsa" | "RsaPkcs1v15" | "rsa-v1_5-sha256" => Ok(SignatureAlgorithm::RsaV15Sha256),
        // Tenzro identities can carry Secp256k1 keys for chain-bound signing,
        // but RFC 9421 §3.3 has no Secp256k1 algorithm — reject explicitly.
        "Secp256k1" => Err(PaymentError::AgentRegistryError(
            "Secp256k1 keys are not RFC 9421 algorithms; use Ed25519 / ECDSA P-256/P-384"
                .to_string(),
        )),
        // X25519 is a key-exchange key, not a signing key — reject explicitly.
        "X25519" => Err(PaymentError::AgentRegistryError(
            "X25519 is a key-exchange key, not a signing algorithm".to_string(),
        )),
        other => Err(PaymentError::AgentRegistryError(format!(
            "unsupported key_type for RFC 9421: {}",
            other
        ))),
    }
}

/// Parse an RFC 9421 `keyid` parameter into `(did, optional_fragment)`.
///
/// The Tenzro convention is `did:tenzro:machine:<id>` (whole identity, first
/// matching key) or `did:tenzro:machine:<id>#<key_fragment>` (selects the
/// `PublicKeyInfo` whose `key_id` matches the fragment).
fn split_keyid(key_id: &str) -> (&str, Option<&str>) {
    match key_id.split_once('#') {
        Some((did, frag)) => (did, Some(frag)),
        None => (key_id, None),
    }
}

#[async_trait]
impl AgentRegistryClient for TenzroAgentRegistry {
    async fn get_public_key(&self, key_id: &str) -> Result<AgentPublicKeyInfo> {
        debug!("Looking up public key for key_id: {}", key_id);

        let (did, fragment) = split_keyid(key_id);

        let identity = self
            .identity_registry
            .resolve(did)
            .map_err(|_| PaymentError::AgentRegistryError(format!("agent {} not found", did)))?;

        let is_active = matches!(identity.status, IdentityStatus::Active);
        if !is_active {
            debug!("Agent {} is not active (status: {:?})", did, identity.status);
        }

        if identity.public_keys.is_empty() {
            return Err(PaymentError::AgentRegistryError(format!(
                "agent {} has no public keys",
                did
            )));
        }

        // Selection: if a fragment is provided, find the matching key. Otherwise,
        // pick the first key whose key_type maps to a supported RFC 9421 algorithm.
        let pk = if let Some(frag) = fragment {
            identity
                .public_keys
                .iter()
                .find(|k| k.key_id == frag)
                .ok_or_else(|| {
                    PaymentError::AgentRegistryError(format!(
                        "agent {} has no key with id #{}",
                        did, frag
                    ))
                })?
        } else {
            identity
                .public_keys
                .iter()
                .find(|k| key_type_to_algorithm(&k.key_type).is_ok())
                .ok_or_else(|| {
                    PaymentError::AgentRegistryError(format!(
                        "agent {} has no RFC 9421-compatible key (only {})",
                        did,
                        identity
                            .public_keys
                            .iter()
                            .map(|k| k.key_type.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                })?
        };

        let algorithm = key_type_to_algorithm(&pk.key_type)?;
        let public_key_bytes = pk.public_key.clone();

        Ok(AgentPublicKeyInfo {
            key_id: key_id.to_string(),
            algorithm,
            public_key_bytes,
            agent_did: Some(identity.did.to_string()),
            is_active,
        })
    }

    async fn verify_agent(&self, key_id: &str) -> Result<bool> {
        debug!("Verifying agent: {}", key_id);
        let (did, _fragment) = split_keyid(key_id);

        let identity = self
            .identity_registry
            .resolve(did)
            .map_err(|_| PaymentError::AgentRegistryError(format!("agent {} not found", did)))?;

        // Agent is verified if status is Active
        Ok(matches!(identity.status, IdentityStatus::Active))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_crypto::composite::InMemoryHybridSigner;
    use tenzro_crypto::pq::MlDsaSigningKey;
    use tenzro_crypto::signatures::Ed25519SignerImpl;
    use tenzro_crypto::{KeyPair, KeyType};
    use tenzro_identity::DelegationScope;
    use tenzro_types::identity::KycTier;

    /// Build a fresh hybrid signer for revocation tests in this module.
    fn revocation_test_signer() -> InMemoryHybridSigner {
        let kp = KeyPair::generate(KeyType::Ed25519).unwrap();
        let classical = Ed25519SignerImpl::new(kp).unwrap();
        InMemoryHybridSigner::new(Box::new(classical), MlDsaSigningKey::generate())
    }

    #[tokio::test]
    async fn test_get_public_key_success() {
        let registry = IdentityRegistry::new();

        // Create a human identity first (required for machine registration)
        let human_public_key = vec![1u8; 32];
        let human = registry
            .register_human_with_fee(human_public_key, "Test Human".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity;

        // Create a test machine identity with a public key
        let machine_public_key = vec![2u8; 32];
        let machine = registry
            .register_machine_with_fee(
                &human.did.to_string(),
                machine_public_key.clone(),
                vec!["test".to_string()],
                DelegationScope::unrestricted(),
            )
            .await
            .unwrap()
            .identity;

        let agent_registry = TenzroAgentRegistry::new(Arc::new(registry));

        let result = agent_registry.get_public_key(&machine.did.to_string()).await;
        assert!(result.is_ok());

        let key_info = result.unwrap();
        assert_eq!(key_info.algorithm, SignatureAlgorithm::Ed25519);
        assert_eq!(key_info.public_key_bytes, machine_public_key);
        assert_eq!(key_info.agent_did, Some(machine.did.to_string()));
        assert!(key_info.is_active);
    }

    #[tokio::test]
    async fn test_get_public_key_not_found() {
        let registry = IdentityRegistry::new();
        let agent_registry = TenzroAgentRegistry::new(Arc::new(registry));

        let result = agent_registry.get_public_key("did:tenzro:machine:nonexistent").await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), PaymentError::AgentRegistryError(_)));
    }

    #[tokio::test]
    async fn test_get_public_key_inactive_agent() {
        let registry = IdentityRegistry::new();

        // Create a human identity
        let human = registry
            .register_human_with_fee(vec![1u8; 32], "Test Human".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity;

        // Create a machine identity
        let machine = registry
            .register_machine_with_fee(
                &human.did.to_string(),
                vec![2u8; 32],
                vec!["test".to_string()],
                DelegationScope::unrestricted(),
            )
            .await
            .unwrap()
            .identity;

        // Revoke the machine identity
        let signer = revocation_test_signer();
        registry.revoke(&machine.did.to_string(), "Test revocation".to_string(), human.did.to_string(), &signer).unwrap();

        let agent_registry = TenzroAgentRegistry::new(Arc::new(registry));

        let result = agent_registry.get_public_key(&machine.did.to_string()).await;
        assert!(result.is_ok());

        let key_info = result.unwrap();
        assert!(!key_info.is_active); // Should be marked as inactive
    }

    #[tokio::test]
    async fn test_verify_agent_active() {
        let registry = IdentityRegistry::new();

        // Create a human identity
        let human = registry
            .register_human_with_fee(vec![1u8; 32], "Test Human".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity;

        // Create a machine identity
        let machine = registry
            .register_machine_with_fee(
                &human.did.to_string(),
                vec![3u8; 32],
                vec!["test".to_string()],
                DelegationScope::unrestricted(),
            )
            .await
            .unwrap()
            .identity;

        let agent_registry = TenzroAgentRegistry::new(Arc::new(registry));

        let result = agent_registry.verify_agent(&machine.did.to_string()).await;
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be active
    }

    #[tokio::test]
    async fn test_verify_agent_inactive() {
        let registry = IdentityRegistry::new();

        // Create a human identity
        let human = registry
            .register_human_with_fee(vec![1u8; 32], "Test Human".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity;

        // Create a machine identity
        let machine = registry
            .register_machine_with_fee(
                &human.did.to_string(),
                vec![4u8; 32],
                vec!["test".to_string()],
                DelegationScope::unrestricted(),
            )
            .await
            .unwrap()
            .identity;

        // Revoke the machine
        let signer = revocation_test_signer();
        registry.revoke(&machine.did.to_string(), "Test revocation".to_string(), human.did.to_string(), &signer).unwrap();

        let agent_registry = TenzroAgentRegistry::new(Arc::new(registry));

        let result = agent_registry.verify_agent(&machine.did.to_string()).await;
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should be inactive
    }

    #[tokio::test]
    async fn test_verify_agent_not_found() {
        let registry = IdentityRegistry::new();
        let agent_registry = TenzroAgentRegistry::new(Arc::new(registry));

        let result = agent_registry.verify_agent("did:tenzro:machine:nonexistent").await;
        assert!(result.is_err());
    }

    // Note: test_get_public_key_no_keys is not feasible with the current tenzro_identity API
    // because register_machine_with_fee always requires a non-empty public_key parameter.
    // The API prevents creating identities without public keys, so this edge case cannot be tested.

    #[test]
    fn test_key_type_to_algorithm_mapping() {
        assert!(matches!(
            key_type_to_algorithm("Ed25519").unwrap(),
            SignatureAlgorithm::Ed25519
        ));
        assert!(matches!(
            key_type_to_algorithm("P256").unwrap(),
            SignatureAlgorithm::EcdsaP256Sha256
        ));
        assert!(matches!(
            key_type_to_algorithm("P384").unwrap(),
            SignatureAlgorithm::EcdsaP384Sha384
        ));
        assert!(matches!(
            key_type_to_algorithm("RsaPss").unwrap(),
            SignatureAlgorithm::RsaPssSha256
        ));
        assert!(matches!(
            key_type_to_algorithm("RsaPssSha512").unwrap(),
            SignatureAlgorithm::RsaPssSha512
        ));
        assert!(matches!(
            key_type_to_algorithm("Rsa").unwrap(),
            SignatureAlgorithm::RsaV15Sha256
        ));

        // Secp256k1 explicitly rejected — not an RFC 9421 algorithm
        assert!(key_type_to_algorithm("Secp256k1").is_err());
        // X25519 is key-exchange, not signing
        assert!(key_type_to_algorithm("X25519").is_err());
        // Unknown algorithms rejected
        assert!(key_type_to_algorithm("Garbage").is_err());
    }

    #[test]
    fn test_split_keyid_with_fragment() {
        let (did, frag) = split_keyid("did:tenzro:machine:abc#key-1");
        assert_eq!(did, "did:tenzro:machine:abc");
        assert_eq!(frag, Some("key-1"));
    }

    #[test]
    fn test_split_keyid_without_fragment() {
        let (did, frag) = split_keyid("did:tenzro:machine:abc");
        assert_eq!(did, "did:tenzro:machine:abc");
        assert_eq!(frag, None);
    }
}
