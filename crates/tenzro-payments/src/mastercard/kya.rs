//! Know Your Agent (KYA) verification implementation
//!
//! Implements Mastercard's Know Your Agent verification framework using
//! the Tenzro Decentralized Identity Protocol (TDIP).

use crate::error::Result;
use crate::mastercard::types::{KyaLevel, KyaVerification};
use chrono::Utc;
use std::sync::Arc;
use tenzro_identity::identity::{IdentityData, IdentityStatus};
use tenzro_identity::IdentityRegistry;
use tracing::{debug, info};

/// Know Your Agent verifier using TDIP identity registry
pub struct KyaVerifier {
    /// TDIP identity registry for looking up agent identities
    identity_registry: Arc<IdentityRegistry>,
}

impl KyaVerifier {
    /// Create a new KYA verifier
    ///
    /// # Arguments
    ///
    /// * `identity_registry` - TDIP identity registry for agent lookup
    pub fn new(identity_registry: Arc<IdentityRegistry>) -> Self {
        Self { identity_registry }
    }

    /// Verify an agent's identity via Know Your Agent protocol
    ///
    /// # Arguments
    ///
    /// * `agent_did` - The agent DID to verify
    ///
    /// # Returns
    ///
    /// * `Ok(KyaVerification)` with verification level and audit trail
    /// * `Err(PaymentError)` if verification fails
    pub fn verify(&self, agent_did: &str) -> Result<KyaVerification> {
        info!("Starting KYA verification for agent: {}", agent_did);

        let mut audit_trail = Vec::new();
        audit_trail.push(format!("Verifying agent DID: {}", agent_did));

        // Step 1: Resolve the agent identity from the registry
        let identity = match self.identity_registry.resolve(agent_did) {
            Ok(id) => {
                audit_trail.push(format!("✓ Agent identity found in registry"));
                id
            }
            Err(e) => {
                audit_trail.push(format!("✗ Agent identity not found: {}", e));
                debug!("KYA verification failed for {}: not found", agent_did);
                return Ok(KyaVerification {
                    verified: false,
                    agent_did: agent_did.to_string(),
                    controller_did: None,
                    verification_level: KyaLevel::Unverified,
                    verified_at: Utc::now(),
                    audit_trail,
                });
            }
        };

        // Step 2: Check if the identity is active (not suspended or revoked)
        match identity.status {
            IdentityStatus::Active => {
                audit_trail.push(format!("✓ Agent identity is active"));
            }
            IdentityStatus::Suspended => {
                audit_trail.push(format!("✗ Agent identity is suspended"));
                debug!("KYA verification failed for {}: suspended", agent_did);
                return Ok(KyaVerification {
                    verified: false,
                    agent_did: agent_did.to_string(),
                    controller_did: None,
                    verification_level: KyaLevel::Unverified,
                    verified_at: Utc::now(),
                    audit_trail,
                });
            }
            IdentityStatus::Revoked => {
                audit_trail.push(format!("✗ Agent identity is revoked"));
                debug!("KYA verification failed for {}: revoked", agent_did);
                return Ok(KyaVerification {
                    verified: false,
                    agent_did: agent_did.to_string(),
                    controller_did: None,
                    verification_level: KyaLevel::Unverified,
                    verified_at: Utc::now(),
                    audit_trail,
                });
            }
        }

        // Step 3: Determine verification level based on identity type and configuration
        let (verification_level, controller_did) = match &identity.identity_data {
            IdentityData::Machine {
                controller_did,
                delegation_scope,
                ..
            } => {
                audit_trail.push(format!("✓ Identity is a machine agent"));

                match controller_did {
                    None => {
                        // Autonomous agent (no controller)
                        audit_trail.push(format!("ℹ Agent is autonomous (no controller)"));
                        audit_trail.push(format!("→ KYA Level: Basic"));
                        (KyaLevel::Basic, None)
                    }
                    Some(controller) => {
                        audit_trail.push(format!("✓ Agent is controlled by: {}", controller));

                        // Verify controller is active
                        match self.identity_registry.resolve(controller) {
                            Ok(controller_identity) => {
                                if controller_identity.status == IdentityStatus::Active {
                                    audit_trail.push(format!("✓ Controller identity is active"));

                                    // Check if delegation scope is configured
                                    if delegation_scope.max_transaction_value.is_some()
                                        || !delegation_scope.allowed_operations.is_empty()
                                        || !delegation_scope.allowed_payment_protocols.is_empty()
                                    {
                                        audit_trail.push(format!(
                                            "✓ Delegation scope configured (max_tx: {:?}, ops: {}, protocols: {})",
                                            delegation_scope.max_transaction_value,
                                            delegation_scope.allowed_operations.len(),
                                            delegation_scope.allowed_payment_protocols.len()
                                        ));
                                        audit_trail.push(format!("→ KYA Level: Full"));
                                        (KyaLevel::Full, Some(controller.clone()))
                                    } else {
                                        audit_trail.push(format!(
                                            "ℹ Delegation scope not configured"
                                        ));
                                        audit_trail.push(format!("→ KYA Level: Enhanced"));
                                        (KyaLevel::Enhanced, Some(controller.clone()))
                                    }
                                } else {
                                    audit_trail.push(format!(
                                        "✗ Controller identity is not active: {:?}",
                                        controller_identity.status
                                    ));
                                    audit_trail.push(format!("→ KYA Level: Basic"));
                                    (KyaLevel::Basic, Some(controller.clone()))
                                }
                            }
                            Err(e) => {
                                audit_trail
                                    .push(format!("✗ Controller identity not found: {}", e));
                                audit_trail.push(format!("→ KYA Level: Basic"));
                                (KyaLevel::Basic, Some(controller.clone()))
                            }
                        }
                    }
                }
            }
            IdentityData::Human { .. } => {
                // Human identities get Basic level (they can use Agent Pay as manual users)
                audit_trail.push(format!("ℹ Identity is a human (not an agent)"));
                audit_trail.push(format!("→ KYA Level: Basic"));
                (KyaLevel::Basic, None)
            }
        };

        let verified = verification_level > KyaLevel::Unverified;

        info!(
            "KYA verification complete for {}: level={:?} verified={}",
            agent_did, verification_level, verified
        );

        Ok(KyaVerification {
            verified,
            agent_did: agent_did.to_string(),
            controller_did,
            verification_level,
            verified_at: Utc::now(),
            audit_trail,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_identity::delegation::DelegationScope;
    use tenzro_types::identity::KycTier;

    fn make_registry() -> Arc<IdentityRegistry> {
        Arc::new(IdentityRegistry::new())
    }

    #[test]
    fn test_kya_unverified_for_unknown() {
        let registry = make_registry();
        let verifier = KyaVerifier::new(registry);

        let result = verifier.verify("did:tenzro:machine:unknown").unwrap();

        assert!(!result.verified);
        assert_eq!(result.verification_level, KyaLevel::Unverified);
        assert!(result.audit_trail.iter().any(|s| s.contains("not found")));
    }

    #[tokio::test]
    async fn test_kya_unverified_for_suspended() {
        let registry = make_registry();

        // Register an autonomous agent
        let agent_did = registry
            .register_autonomous_machine(
                vec![1; 32],
                vec!["inference".to_string()],
            )
            .await
            .unwrap()
            .did_string();

        // Suspend it
        registry.suspend(&agent_did).unwrap();

        let verifier = KyaVerifier::new(registry);
        let result = verifier.verify(&agent_did).unwrap();

        assert!(!result.verified);
        assert_eq!(result.verification_level, KyaLevel::Unverified);
        assert!(result.audit_trail.iter().any(|s| s.contains("suspended")));
    }

    #[tokio::test]
    async fn test_kya_basic_for_autonomous_agent() {
        let registry = make_registry();

        // Register an autonomous agent (no controller)
        let agent_did = registry
            .register_autonomous_machine(
                vec![2; 32],
                vec!["inference".to_string()],
            )
            .await
            .unwrap()
            .did_string();

        let verifier = KyaVerifier::new(registry);
        let result = verifier.verify(&agent_did).unwrap();

        assert!(result.verified);
        assert_eq!(result.verification_level, KyaLevel::Basic);
        assert!(result.controller_did.is_none());
        assert!(result.audit_trail.iter().any(|s| s.contains("autonomous")));
    }

    #[tokio::test]
    async fn test_kya_basic_for_human() {
        let registry = make_registry();

        // Register a human identity
        let human_did = registry
            .register_human_with_fee(vec![3; 32], "Alice".to_string(), KycTier::Unverified)
            .await
            .unwrap()
            .identity
            .did_string();

        let verifier = KyaVerifier::new(registry);
        let result = verifier.verify(&human_did).unwrap();

        assert!(result.verified);
        assert_eq!(result.verification_level, KyaLevel::Basic);
        assert!(result.audit_trail.iter().any(|s| s.contains("human")));
    }

    #[tokio::test]
    async fn test_kya_enhanced_for_controlled() {
        let registry = make_registry();

        // Register controller
        let controller_did = registry
            .register_human_with_fee(vec![4; 32], "Bob".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity
            .did_string();

        // Register controlled agent (no delegation scope configured)
        let agent_did = registry
            .register_machine_with_fee(
                &controller_did,
                vec![5; 32],
                vec!["trading".to_string()],
                DelegationScope::default(),
            )
            .await
            .unwrap()
            .identity
            .did_string();

        let verifier = KyaVerifier::new(registry);
        let result = verifier.verify(&agent_did).unwrap();

        assert!(result.verified);
        assert_eq!(result.verification_level, KyaLevel::Enhanced);
        assert_eq!(result.controller_did, Some(controller_did.clone()));
        assert!(result
            .audit_trail
            .iter()
            .any(|s| s.contains("Controller identity is active")));
    }

    #[tokio::test]
    async fn test_kya_full_for_delegated() {
        let registry = make_registry();

        // Register controller
        let controller_did = registry
            .register_human_with_fee(vec![6; 32], "Charlie".to_string(), KycTier::Enhanced)
            .await
            .unwrap()
            .identity
            .did_string();

        // Register controlled agent with delegation scope
        let mut delegation_scope = DelegationScope::default();
        delegation_scope.max_transaction_value = Some(1000);
        delegation_scope.allowed_operations = vec!["transfer".to_string()];
        delegation_scope.allowed_payment_protocols = vec!["mpp".to_string()];

        let agent_did = registry
            .register_machine_with_fee(
                &controller_did,
                vec![7; 32],
                vec!["payment".to_string()],
                delegation_scope,
            )
            .await
            .unwrap()
            .identity
            .did_string();

        let verifier = KyaVerifier::new(registry);
        let result = verifier.verify(&agent_did).unwrap();

        assert!(result.verified);
        assert_eq!(result.verification_level, KyaLevel::Full);
        assert_eq!(result.controller_did, Some(controller_did.clone()));
        assert!(result
            .audit_trail
            .iter()
            .any(|s| s.contains("Delegation scope configured")));
    }

    #[tokio::test]
    async fn test_kya_basic_when_controller_inactive() {
        let registry = make_registry();

        // Register controller
        let controller_did = registry
            .register_human_with_fee(vec![8; 32], "Dave".to_string(), KycTier::Basic)
            .await
            .unwrap()
            .identity
            .did_string();

        // Register controlled agent FIRST (while controller is active)
        let agent_did = registry
            .register_machine_with_fee(
                &controller_did,
                vec![9; 32],
                vec!["inference".to_string()],
                DelegationScope::default(),
            )
            .await
            .unwrap()
            .identity
            .did_string();

        // Suspend controller (not revoke, to avoid cascading revocation)
        registry.suspend(&controller_did).unwrap();

        let verifier = KyaVerifier::new(registry);
        let result = verifier.verify(&agent_did).unwrap();

        // Agent itself is active, but controller is suspended, so only Basic level
        assert!(result.verified);
        assert_eq!(result.verification_level, KyaLevel::Basic);
        assert!(result
            .audit_trail
            .iter()
            .any(|s| s.contains("Controller identity is not active")));
    }
}
