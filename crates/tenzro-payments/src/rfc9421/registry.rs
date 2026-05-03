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
}

#[async_trait]
impl AgentRegistryClient for TenzroAgentRegistry {
    async fn get_public_key(&self, key_id: &str) -> Result<AgentPublicKeyInfo> {
        debug!("Looking up public key for key_id: {}", key_id);

        // Try to resolve key_id as a DID
        let identity = self
            .identity_registry
            .resolve(key_id)
            .map_err(|_| PaymentError::AgentRegistryError(format!("agent {} not found", key_id)))?;

        // Check if identity is active
        let is_active = matches!(identity.status, IdentityStatus::Active);

        if !is_active {
            debug!("Agent {} is not active (status: {:?})", key_id, identity.status);
        }

        // Extract public key bytes from the identity
        // Get the first public key from the identity's public_keys list
        let public_key_info = identity.public_keys.first().ok_or_else(|| {
            PaymentError::AgentRegistryError(format!("agent {} has no public keys", key_id))
        })?;

        let public_key_bytes = public_key_info.public_key.clone();

        Ok(AgentPublicKeyInfo {
            key_id: key_id.to_string(),
            algorithm: SignatureAlgorithm::Ed25519,
            public_key_bytes,
            agent_did: Some(identity.did.to_string()),
            is_active,
        })
    }

    async fn verify_agent(&self, key_id: &str) -> Result<bool> {
        debug!("Verifying agent: {}", key_id);

        let identity = self
            .identity_registry
            .resolve(key_id)
            .map_err(|_| PaymentError::AgentRegistryError(format!("agent {} not found", key_id)))?;

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
}
