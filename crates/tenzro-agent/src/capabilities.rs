//! Capability management for Tenzro Network agents.
//!
//! This module manages agent capabilities, allowing agents to register
//! their abilities and enabling discovery of agents with specific
//! capabilities.

use crate::error::{AgentError, Result};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tenzro_crypto::{PublicKey, Signature, Verifier};
use tenzro_types::{agent::Capability, primitives::Address};
use tracing::{debug, info, warn};

/// Capability attestation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityAttestation {
    /// Capability being attested
    pub capability: Capability,
    /// Agent ID
    pub agent_id: String,
    /// Attestation timestamp
    pub attested_at: DateTime<Utc>,
    /// Whether this is TEE-backed
    pub tee_backed: bool,
    /// Attester address (who signed the attestation)
    pub attester_address: Option<Address>,
    /// Attester public key (for verification)
    pub attester_public_key: Option<PublicKey>,
    /// Attestation signature (Ed25519)
    pub signature: Option<Vec<u8>>,
    /// Attestation metadata
    pub metadata: std::collections::HashMap<String, String>,
}

impl CapabilityAttestation {
    /// Creates a new capability attestation
    pub fn new(agent_id: String, capability: Capability, tee_backed: bool) -> Self {
        Self {
            capability,
            agent_id,
            attested_at: Utc::now(),
            tee_backed,
            attester_address: None,
            attester_public_key: None,
            signature: None,
            metadata: std::collections::HashMap::new(),
        }
    }

    /// Adds a signature to the attestation
    pub fn with_signature(mut self, attester_public_key: PublicKey, signature: Vec<u8>) -> Self {
        // Convert 20-byte crypto::Address to 32-byte types::Address
        let crypto_addr = attester_public_key.to_address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        self.attester_address = Some(Address::new(addr_bytes));

        self.attester_public_key = Some(attester_public_key);
        self.signature = Some(signature);
        self
    }

    /// Adds metadata to the attestation
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }

    /// Gets the attestation data to sign (canonical representation)
    pub fn signing_data(&self) -> Vec<u8> {
        // Create deterministic representation for signing
        let data = format!(
            "{}:{}:{}:{}",
            self.agent_id,
            serde_json::to_string(&self.capability).unwrap_or_default(),
            self.attested_at.timestamp(),
            self.tee_backed
        );
        data.into_bytes()
    }

    /// Verifies the attestation signature using a verifier
    pub fn verify_signature<V: Verifier>(&self, verifier: &V) -> Result<bool> {
        let signature_bytes = self
            .signature
            .as_ref()
            .ok_or_else(|| AgentError::AttestationFailed("No signature present".to_string()))?;

        let signing_data = self.signing_data();

        // Wrap signature bytes in Signature type using the public key's type
        let key_type = verifier.public_key().key_type();
        let signature = Signature::new(key_type, signature_bytes.clone());

        verifier
            .verify(&signing_data, &signature)
            .map(|_| true)
            .map_err(|e| AgentError::CryptoError(e.to_string()))
    }

    /// Checks if the attestation has expired
    pub fn is_expired(&self, max_age_secs: i64) -> bool {
        let age = Utc::now().signed_duration_since(self.attested_at).num_seconds();
        age > max_age_secs
    }
}

/// Registered capability with agents that support it
#[derive(Debug, Clone)]
struct RegisteredCapability {
    /// The capability
    capability: Capability,
    /// Agents that have this capability
    agents: Vec<String>,
    /// Attestations for this capability
    attestations: Vec<CapabilityAttestation>,
}

impl RegisteredCapability {
    fn new(capability: Capability) -> Self {
        Self {
            capability,
            agents: Vec::new(),
            attestations: Vec::new(),
        }
    }

    fn add_agent(&mut self, agent_id: String) {
        if !self.agents.contains(&agent_id) {
            self.agents.push(agent_id);
        }
    }

    fn remove_agent(&mut self, agent_id: &str) {
        self.agents.retain(|id| id != agent_id);
        self.attestations.retain(|att| att.agent_id != agent_id);
    }

    fn add_attestation(&mut self, attestation: CapabilityAttestation) {
        self.attestations.push(attestation);
    }
}

/// Configuration for capability attestation verification
#[derive(Debug, Clone)]
pub struct AttestationConfig {
    /// Maximum age of attestations in seconds (default: 90 days)
    pub max_attestation_age_secs: i64,
    /// Whether to require signatures on attestations
    pub require_signatures: bool,
    /// Whether to allow self-attestation (default: false).
    ///
    /// Self-attestation provides no security guarantees — any agent can
    /// claim any capability for itself. When this flag is `false`, the
    /// registry will reject any attestation where `attester_address`
    /// matches the wallet address registered for the agent_id (via
    /// `register_agent_address`). This default forces operators to wire
    /// in a third-party attester (e.g. a TEE measurement service or a
    /// governance-elected validator) before attestations are accepted.
    pub allow_self_attestation: bool,
    /// Set of trusted attester addresses. When non-empty, the registry
    /// will reject any attestation whose `attester_address` is not in
    /// this set. When empty, all signed attestations are accepted (subject
    /// to the self-attestation rule).
    pub trusted_attesters: HashSet<Address>,
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self {
            max_attestation_age_secs: 90 * 24 * 60 * 60, // 90 days
            require_signatures: true,
            allow_self_attestation: false,
            trusted_attesters: HashSet::new(),
        }
    }
}

impl AttestationConfig {
    /// Builder: set maximum attestation age in seconds.
    pub fn with_max_age(mut self, secs: i64) -> Self {
        self.max_attestation_age_secs = secs;
        self
    }

    /// Builder: enable or disable signature requirement.
    pub fn with_require_signatures(mut self, require: bool) -> Self {
        self.require_signatures = require;
        self
    }

    /// Builder: allow self-attestation (default is `false` for security).
    pub fn with_self_attestation(mut self, allow: bool) -> Self {
        self.allow_self_attestation = allow;
        self
    }

    /// Builder: add a trusted attester address.
    pub fn with_trusted_attester(mut self, attester: Address) -> Self {
        self.trusted_attesters.insert(attester);
        self
    }

    /// Builder: set the full trusted attester set (replaces any prior).
    pub fn with_trusted_attesters(mut self, attesters: HashSet<Address>) -> Self {
        self.trusted_attesters = attesters;
        self
    }
}

/// Registry for managing agent capabilities
pub struct CapabilityRegistry {
    /// Capabilities indexed by a string representation
    capabilities: Arc<DashMap<String, RegisteredCapability>>,
    /// Agent capabilities indexed by agent ID
    agent_capabilities: Arc<DashMap<String, Vec<Capability>>>,
    /// Wallet address registered for each agent_id, used by the
    /// self-attestation guard. When an agent has no entry here, the
    /// self-attestation check is a no-op (we cannot prove identity).
    agent_addresses: Arc<DashMap<String, Address>>,
    /// Attestation verification configuration
    attestation_config: AttestationConfig,
    /// Number of attestations rejected at submission time because their
    /// signature failed verification, or because the attester was not
    /// trusted, or because they were self-attested. Exposed via
    /// `rejected_attestation_count()` for metrics dashboards.
    rejected_attestation_count: Arc<parking_lot::Mutex<u64>>,
}

impl CapabilityRegistry {
    /// Creates a new capability registry
    pub fn new() -> Self {
        Self::with_config(AttestationConfig::default())
    }

    /// Creates a new capability registry with custom configuration
    pub fn with_config(config: AttestationConfig) -> Self {
        Self {
            capabilities: Arc::new(DashMap::new()),
            agent_capabilities: Arc::new(DashMap::new()),
            agent_addresses: Arc::new(DashMap::new()),
            attestation_config: config,
            rejected_attestation_count: Arc::new(parking_lot::Mutex::new(0)),
        }
    }

    /// Registers the wallet address that owns a given agent_id.
    ///
    /// This is used by the self-attestation guard in `attest_capability()`:
    /// when `allow_self_attestation = false`, an attestation whose
    /// `attester_address` matches the registered address for the target
    /// agent will be rejected with `AgentError::InvalidAttestationSignature`.
    /// When the agent has no registered address (e.g. legacy code paths
    /// that pre-date #52), the self-attestation check is skipped.
    pub fn register_agent_address(&self, agent_id: String, address: Address) {
        self.agent_addresses.insert(agent_id, address);
    }

    /// Returns the registered wallet address for an agent, if any.
    pub fn agent_address(&self, agent_id: &str) -> Option<Address> {
        self.agent_addresses.get(agent_id).map(|a| *a.value())
    }

    /// Returns the number of attestations that have been rejected at
    /// submission time (signature/whitelist/self-attestation failures).
    /// Exposed for metrics dashboards.
    pub fn rejected_attestation_count(&self) -> u64 {
        *self.rejected_attestation_count.lock()
    }

    /// Increments the rejected-attestation counter.
    fn record_rejected_attestation(&self) {
        let mut count = self.rejected_attestation_count.lock();
        *count = count.saturating_add(1);
    }

    /// Gets a string key for a capability
    fn capability_key(capability: &Capability) -> String {
        match capability {
            Capability::NaturalLanguageProcessing { .. } => "nlp".to_string(),
            Capability::ComputerVision { .. } => "vision".to_string(),
            Capability::CodeGeneration { .. } => "codegen".to_string(),
            Capability::DataAnalysis { .. } => "data_analysis".to_string(),
            Capability::BlockchainInteraction { .. } => "blockchain".to_string(),
            Capability::SmartContractExecution => "smart_contract".to_string(),
            Capability::ExternalAPIIntegration { .. } => "api_integration".to_string(),
            Capability::MultiAgentCoordination => "coordination".to_string(),
            Capability::Custom { name, .. } => format!("custom:{}", name),
        }
    }

    /// Registers a capability for an agent
    pub fn register_capability(&self, agent_id: String, capability: Capability) -> Result<()> {
        let key = Self::capability_key(&capability);

        // Add to capability index
        self.capabilities
            .entry(key.clone())
            .or_insert_with(|| RegisteredCapability::new(capability.clone()))
            .add_agent(agent_id.clone());

        // Add to agent index
        self.agent_capabilities
            .entry(agent_id.clone())
            .or_default()
            .push(capability.clone());

        debug!("Registered capability {} for agent {}", key, agent_id);
        Ok(())
    }

    /// Verifies that an agent has a specific capability
    pub fn verify_capability(&self, agent_id: &str, capability: &Capability) -> Result<bool> {
        let agent_caps = self
            .agent_capabilities
            .get(agent_id)
            .ok_or_else(|| AgentError::AgentNotFound(agent_id.to_string()))?;

        Ok(agent_caps.iter().any(|c| self.capabilities_match(c, capability)))
    }

    /// Checks if two capabilities match
    fn capabilities_match(&self, a: &Capability, b: &Capability) -> bool {
        match (a, b) {
            (Capability::NaturalLanguageProcessing { .. }, Capability::NaturalLanguageProcessing { .. }) => true,
            (Capability::ComputerVision { .. }, Capability::ComputerVision { .. }) => true,
            (Capability::CodeGeneration { .. }, Capability::CodeGeneration { .. }) => true,
            (Capability::DataAnalysis { .. }, Capability::DataAnalysis { .. }) => true,
            (Capability::BlockchainInteraction { .. }, Capability::BlockchainInteraction { .. }) => true,
            (Capability::SmartContractExecution, Capability::SmartContractExecution) => true,
            (Capability::ExternalAPIIntegration { .. }, Capability::ExternalAPIIntegration { .. }) => true,
            (Capability::MultiAgentCoordination, Capability::MultiAgentCoordination) => true,
            (Capability::Custom { name: n1, .. }, Capability::Custom { name: n2, .. }) => n1 == n2,
            _ => false,
        }
    }

    /// Finds agents with a specific capability
    pub fn find_agents_with_capability(&self, capability: &Capability) -> Vec<String> {
        let key = Self::capability_key(capability);

        self.capabilities
            .get(&key)
            .map(|entry| entry.agents.clone())
            .unwrap_or_default()
    }

    /// Revokes a capability from an agent
    pub fn revoke_capability(&self, agent_id: &str, capability: &Capability) -> Result<()> {
        let key = Self::capability_key(capability);

        // Remove from capability index
        if let Some(mut entry) = self.capabilities.get_mut(&key) {
            entry.remove_agent(agent_id);
        }

        // Remove from agent index
        if let Some(mut entry) = self.agent_capabilities.get_mut(agent_id) {
            entry.retain(|c| !self.capabilities_match(c, capability));
        }

        info!("Revoked capability {} from agent {}", key, agent_id);
        Ok(())
    }

    /// Gets all capabilities for an agent
    pub fn get_agent_capabilities(&self, agent_id: &str) -> Result<Vec<Capability>> {
        self.agent_capabilities
            .get(agent_id)
            .map(|entry| entry.value().clone())
            .ok_or_else(|| AgentError::AgentNotFound(agent_id.to_string()))
    }

    /// Attests to a capability by accepting a pre-signed
    /// [`CapabilityAttestation`] envelope.
    ///
    /// **CRITICAL #52**: This method now eagerly verifies the supplied
    /// signature against the canonical signing data BEFORE inserting the
    /// attestation into the registry, so garbage signatures cannot pollute
    /// query results. It also enforces three additional security policies:
    ///
    /// 1. **Signature requirement** — when `config.require_signatures` is
    ///    true (the default), missing public key or signature returns
    ///    `AgentError::InvalidAttestationSignature`.
    /// 2. **Cryptographic verification** — the supplied signature is
    ///    verified against `attestation.signing_data()` using
    ///    `tenzro_crypto::signatures::verify(...)`. Failures increment
    ///    the `rejected_attestation_count` counter and return an error.
    /// 3. **Self-attestation guard** — when `config.allow_self_attestation`
    ///    is false (the default), an attestation whose attester address
    ///    matches the wallet address registered for the target agent
    ///    (via `register_agent_address`) is rejected. This prevents
    ///    agents from claiming arbitrary capabilities for themselves.
    /// 4. **Trusted attester whitelist** — when
    ///    `config.trusted_attesters` is non-empty, the attester's address
    ///    must appear in the whitelist or the attestation is rejected.
    ///
    /// All four checks must pass before the attestation is stored. The
    /// method also still verifies the target agent has the capability
    /// registered (existing behaviour).
    ///
    /// Callers that want to construct + sign + submit in one step should
    /// use [`Self::attest_capability_with_signer`] which performs the
    /// signing locally using a [`Signer`](tenzro_crypto::signatures::Signer).
    pub fn submit_attestation(&self, attestation: CapabilityAttestation) -> Result<()> {
        let agent_id = attestation.agent_id.clone();
        let capability = attestation.capability.clone();

        // Verify agent has the capability registered.
        if !self.verify_capability(&agent_id, &capability)? {
            return Err(AgentError::InvalidCapability(format!(
                "Agent {} does not have the specified capability",
                agent_id
            )));
        }

        // Enforce the signature policy.
        let require_signatures = self.attestation_config.require_signatures;
        let pubkey = attestation.attester_public_key.clone();
        let sig_bytes = attestation.signature.clone();
        let (pubkey, sig_bytes) = match (pubkey, sig_bytes) {
            (Some(pk), Some(sig)) => (pk, sig),
            (None, None) if !require_signatures => {
                // Signatures not required; insert unsigned attestation.
                let key = Self::capability_key(&capability);
                if let Some(mut entry) = self.capabilities.get_mut(&key) {
                    entry.add_attestation(attestation);
                }
                return Ok(());
            }
            _ => {
                self.record_rejected_attestation();
                return Err(AgentError::InvalidAttestationSignature {
                    agent_id,
                    reason: "missing attester public key or signature".to_string(),
                });
            }
        };

        // Self-attestation guard: reject when the attester is the agent's
        // own wallet address (and we have a registered address to compare).
        if !self.attestation_config.allow_self_attestation {
            if let Some(agent_addr) = self.agent_address(&agent_id) {
                if let Some(attester_addr) = attestation.attester_address.as_ref() {
                    if attester_addr == &agent_addr {
                        self.record_rejected_attestation();
                        return Err(AgentError::InvalidAttestationSignature {
                            agent_id,
                            reason: "self-attestation is not allowed".to_string(),
                        });
                    }
                }
            }
        }

        // Trusted attester whitelist enforcement.
        if !self.attestation_config.trusted_attesters.is_empty() {
            let attester_addr = attestation
                .attester_address
                .as_ref()
                .expect("with_signature populates attester_address");
            if !self
                .attestation_config
                .trusted_attesters
                .contains(attester_addr)
            {
                self.record_rejected_attestation();
                return Err(AgentError::InvalidAttestationSignature {
                    agent_id,
                    reason: "attester is not in the trusted attester set".to_string(),
                });
            }
        }

        // Cryptographically verify the signature against signing_data() BEFORE
        // storing. This is the heart of the #52 fix — previously the registry
        // accepted arbitrary signature bytes and only checked them on query.
        let signing_data = attestation.signing_data();
        let signature_obj = Signature::new(pubkey.key_type(), sig_bytes);
        match tenzro_crypto::signatures::verify(&pubkey, &signing_data, &signature_obj) {
            Ok(()) => {
                debug!(
                    "Verified attestation signature for agent {} (attester {:?})",
                    agent_id, attestation.attester_address
                );
            }
            Err(e) => {
                self.record_rejected_attestation();
                warn!(
                    "Rejected attestation for agent {}: signature verification failed: {}",
                    agent_id, e
                );
                return Err(AgentError::InvalidAttestationSignature {
                    agent_id,
                    reason: format!("signature failed verification: {}", e),
                });
            }
        }

        // All checks passed — insert the verified attestation.
        let key = Self::capability_key(&capability);
        if let Some(mut entry) = self.capabilities.get_mut(&key) {
            entry.add_attestation(attestation);
        }

        Ok(())
    }

    /// Convenience wrapper around [`Self::submit_attestation`] that
    /// constructs and signs the [`CapabilityAttestation`] envelope using
    /// the supplied [`Signer`](tenzro_crypto::signatures::Signer).
    ///
    /// This is the preferred API for callers that already hold a signer
    /// (e.g. a TEE measurement service or a governance-elected attester).
    /// All four security policies described on
    /// [`Self::submit_attestation`] are enforced.
    pub fn attest_capability_with_signer<S>(
        &self,
        agent_id: String,
        capability: Capability,
        tee_backed: bool,
        signer: &S,
    ) -> Result<()>
    where
        S: tenzro_crypto::signatures::Signer,
    {
        let attestation =
            CapabilityAttestation::new(agent_id.clone(), capability.clone(), tee_backed);
        let signing_data = attestation.signing_data();
        let signature = signer
            .sign(&signing_data)
            .map_err(|e| AgentError::CryptoError(e.to_string()))?;
        let signed = attestation.with_signature(signer.public_key().clone(), signature.to_bytes());
        self.submit_attestation(signed)
    }

    /// Legacy attestation API (CRITICAL #52 deprecated path).
    ///
    /// This method exists for backward compatibility with callers that
    /// pass the attester public key + raw signature bytes directly. It
    /// internally constructs a [`CapabilityAttestation`], stamps the
    /// signature, and forwards to [`Self::submit_attestation`] which
    /// performs the same eager verification + policy enforcement.
    ///
    /// New code should prefer [`Self::attest_capability_with_signer`]
    /// which couples signing and submission into a single, race-free
    /// call.
    pub fn attest_capability(
        &self,
        agent_id: String,
        capability: Capability,
        tee_backed: bool,
        attester_public_key: Option<PublicKey>,
        signature: Option<Vec<u8>>,
    ) -> Result<()> {
        let mut attestation =
            CapabilityAttestation::new(agent_id, capability, tee_backed);
        if let (Some(pk), Some(sig)) = (attester_public_key, signature) {
            attestation = attestation.with_signature(pk, sig);
        }
        self.submit_attestation(attestation)
    }

    /// Verifies a capability attestation signature
    pub fn verify_attestation(&self, attestation: &CapabilityAttestation) -> Result<bool> {
        // Check expiration
        if attestation.is_expired(self.attestation_config.max_attestation_age_secs) {
            warn!("Attestation for agent {} has expired", attestation.agent_id);
            return Ok(false);
        }

        // If signature verification is required
        if self.attestation_config.require_signatures {
            let attester_public_key = attestation
                .attester_public_key
                .as_ref()
                .ok_or_else(|| AgentError::AttestationFailed("No attester public key".to_string()))?;

            let signature_bytes = attestation
                .signature
                .as_ref()
                .ok_or_else(|| AgentError::AttestationFailed("No signature present".to_string()))?;

            // Get the signing data (canonical representation)
            let signing_data = attestation.signing_data();

            // Create signature object from bytes
            let signature = Signature::new(attester_public_key.key_type(), signature_bytes.clone());

            // Verify the signature cryptographically using tenzro_crypto::signatures::verify
            match tenzro_crypto::signatures::verify(attester_public_key, &signing_data, &signature) {
                Ok(()) => {
                    debug!("Successfully verified attestation signature for agent {}", attestation.agent_id);
                    Ok(true)
                }
                Err(e) => {
                    warn!(
                        "Attestation signature verification failed for agent {}: {}",
                        attestation.agent_id, e
                    );
                    Ok(false)
                }
            }
        } else {
            // No signature required
            Ok(true)
        }
    }

    /// Gets verified (valid) attestations for a capability
    pub fn get_verified_attestations(&self, capability: &Capability) -> Vec<CapabilityAttestation> {
        let attestations = self.get_attestations(capability);

        attestations
            .into_iter()
            .filter(|att| {
                self.verify_attestation(att).unwrap_or(false)
            })
            .collect()
    }

    /// Gets attestations for a capability
    pub fn get_attestations(&self, capability: &Capability) -> Vec<CapabilityAttestation> {
        let key = Self::capability_key(capability);

        self.capabilities
            .get(&key)
            .map(|entry| entry.attestations.clone())
            .unwrap_or_default()
    }

    /// Gets attestations for an agent
    pub fn get_agent_attestations(&self, agent_id: &str) -> Vec<CapabilityAttestation> {
        let mut attestations = Vec::new();

        for entry in self.capabilities.iter() {
            for attestation in &entry.attestations {
                if attestation.agent_id == agent_id {
                    attestations.push(attestation.clone());
                }
            }
        }

        attestations
    }

    /// Removes all capabilities for an agent
    pub fn remove_agent(&self, agent_id: &str) -> Result<()> {
        // Get all agent capabilities (if any)
        let capabilities = self.get_agent_capabilities(agent_id).unwrap_or_default();

        // Remove from each capability index
        for capability in capabilities {
            let key = Self::capability_key(&capability);
            if let Some(mut entry) = self.capabilities.get_mut(&key) {
                entry.remove_agent(agent_id);
            }
        }

        // Remove from agent index
        self.agent_capabilities.remove(agent_id);

        // Drop the registered wallet address (if any) so a future agent
        // reusing the same id starts with a fresh self-attestation guard.
        self.agent_addresses.remove(agent_id);

        info!("Removed all capabilities for agent {}", agent_id);
        Ok(())
    }

    /// Lists all registered capabilities
    pub fn list_capabilities(&self) -> Vec<Capability> {
        self.capabilities
            .iter()
            .map(|entry| entry.capability.clone())
            .collect()
    }

    /// Gets the number of agents with a specific capability
    pub fn capability_count(&self, capability: &Capability) -> usize {
        let key = Self::capability_key(capability);

        self.capabilities
            .get(&key)
            .map(|entry| entry.agents.len())
            .unwrap_or(0)
    }

    /// Finds the best agent for a capability based on attestations
    pub fn find_best_agent(&self, capability: &Capability) -> Option<String> {
        let key = Self::capability_key(capability);

        self.capabilities.get(&key).and_then(|entry| {
            // Prefer TEE-backed attestations
            entry
                .attestations
                .iter()
                .filter(|att| att.tee_backed)
                .max_by_key(|att| att.attested_at)
                .map(|att| att.agent_id.clone())
                .or_else(|| {
                    // Fall back to any agent with the capability
                    entry.agents.first().cloned()
                })
        })
    }

    /// Filters agents by multiple capabilities (AND logic)
    pub fn find_agents_with_all_capabilities(&self, capabilities: &[Capability]) -> Vec<String> {
        if capabilities.is_empty() {
            return Vec::new();
        }

        // Get agents for first capability
        let mut result = self.find_agents_with_capability(&capabilities[0]);

        // Intersect with agents for remaining capabilities
        for capability in &capabilities[1..] {
            let agents = self.find_agents_with_capability(capability);
            result.retain(|agent| agents.contains(agent));
        }

        result
    }
}

impl Default for CapabilityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_capability_registration() {
        let registry = CapabilityRegistry::new();

        let capability = Capability::NaturalLanguageProcessing {
            languages: vec!["en".to_string(), "es".to_string()],
        };

        registry
            .register_capability("agent1".to_string(), capability.clone())
            .unwrap();

        assert!(registry.verify_capability("agent1", &capability).unwrap());
    }

    #[test]
    fn test_find_agents() {
        let registry = CapabilityRegistry::new();

        let capability = Capability::MultiAgentCoordination;

        registry
            .register_capability("agent1".to_string(), capability.clone())
            .unwrap();
        registry
            .register_capability("agent2".to_string(), capability.clone())
            .unwrap();

        let agents = registry.find_agents_with_capability(&capability);
        assert_eq!(agents.len(), 2);
        assert!(agents.contains(&"agent1".to_string()));
        assert!(agents.contains(&"agent2".to_string()));
    }

    #[test]
    fn test_revoke_capability() {
        let registry = CapabilityRegistry::new();

        let capability = Capability::SmartContractExecution;

        registry
            .register_capability("agent1".to_string(), capability.clone())
            .unwrap();

        assert!(registry.verify_capability("agent1", &capability).unwrap());

        registry.revoke_capability("agent1", &capability).unwrap();

        assert!(!registry.verify_capability("agent1", &capability).unwrap());
    }

    #[test]
    fn test_capability_attestation() {
        // Create registry without requiring signatures for testing
        let config = AttestationConfig::default()
            .with_require_signatures(false);
        let registry = CapabilityRegistry::with_config(config);

        let capability = Capability::CodeGeneration {
            languages: vec!["rust".to_string()],
        };

        registry
            .register_capability("agent1".to_string(), capability.clone())
            .unwrap();

        registry
            .attest_capability("agent1".to_string(), capability.clone(), true, None, None)
            .unwrap();

        let attestations = registry.get_attestations(&capability);
        assert_eq!(attestations.len(), 1);
        assert!(attestations[0].tee_backed);
    }

    #[test]
    fn test_find_agents_with_all_capabilities() {
        let registry = CapabilityRegistry::new();

        let cap1 = Capability::MultiAgentCoordination;
        let cap2 = Capability::SmartContractExecution;

        registry
            .register_capability("agent1".to_string(), cap1.clone())
            .unwrap();
        registry
            .register_capability("agent1".to_string(), cap2.clone())
            .unwrap();
        registry
            .register_capability("agent2".to_string(), cap1.clone())
            .unwrap();

        let agents = registry.find_agents_with_all_capabilities(&[cap1, cap2]);
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0], "agent1");
    }

    #[test]
    fn test_custom_capability() {
        let registry = CapabilityRegistry::new();

        let capability = Capability::Custom {
            name: "custom_task".to_string(),
            parameters: HashMap::new(),
        };

        registry
            .register_capability("agent1".to_string(), capability.clone())
            .unwrap();

        assert!(registry.verify_capability("agent1", &capability).unwrap());

        let agents = registry.find_agents_with_capability(&capability);
        assert_eq!(agents.len(), 1);
    }

    #[test]
    fn test_attestation_signature_verification() {
        use tenzro_crypto::{KeyPair, KeyType};
        use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};

        // Create registry that requires signatures (default config already
        // requires them, but we explicitly set it to make the test intent
        // obvious).
        let config = AttestationConfig::default()
            .with_require_signatures(true);
        let registry = CapabilityRegistry::with_config(config);

        let capability = Capability::CodeGeneration {
            languages: vec!["rust".to_string()],
        };

        // Register capability
        registry
            .register_capability("agent1".to_string(), capability.clone())
            .unwrap();

        // Generate keypair for attester
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = Ed25519SignerImpl::new(keypair).unwrap();
        let public_key = signer.public_key().clone();

        // Create attestation and sign it
        let attestation = CapabilityAttestation::new(
            "agent1".to_string(),
            capability.clone(),
            true,
        );
        let signing_data = attestation.signing_data();
        let signature = signer.sign(&signing_data).unwrap();

        // Add signature to attestation
        let signed_attestation = attestation.with_signature(
            public_key.clone(),
            signature.to_bytes(),
        );

        // Submit the pre-signed attestation envelope. With #52, the
        // registry now eagerly verifies the signature against the same
        // signing_data the attester signed, so this must succeed.
        registry
            .submit_attestation(signed_attestation.clone())
            .expect("valid attestation should be accepted");

        // Verify the attestation can also be re-checked at query time
        let is_valid = registry.verify_attestation(&signed_attestation).unwrap();
        assert!(is_valid, "Valid attestation should verify successfully");

        // Test with invalid signature: query-time check should still
        // return false (legacy behaviour preserved).
        let invalid_attestation = CapabilityAttestation::new(
            "agent1".to_string(),
            capability.clone(),
            false,
        )
        .with_signature(
            public_key,
            vec![0u8; 64], // Invalid signature bytes
        );

        let is_valid = registry.verify_attestation(&invalid_attestation).unwrap();
        assert!(!is_valid, "Invalid signature should fail verification");
    }

    #[test]
    fn test_attestation_expiration() {
        use std::thread;
        use std::time::Duration;

        // Create registry with very short expiration time
        let config = AttestationConfig::default()
            .with_max_age(1) // 1 second
            .with_require_signatures(false);
        let registry = CapabilityRegistry::with_config(config);

        let capability = Capability::SmartContractExecution;

        let attestation = CapabilityAttestation::new(
            "agent1".to_string(),
            capability,
            false,
        );

        // Should be valid immediately
        assert!(registry.verify_attestation(&attestation).unwrap());

        // Wait for expiration
        thread::sleep(Duration::from_secs(2));

        // Should be expired now
        assert!(!registry.verify_attestation(&attestation).unwrap());
    }

    #[test]
    fn test_verify_signature_with_module_function() {
        use tenzro_crypto::{KeyPair, KeyType};
        use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};

        let capability = Capability::MultiAgentCoordination;

        // Generate keypair
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let signer = Ed25519SignerImpl::new(keypair).unwrap();
        let public_key = signer.public_key().clone();

        // Create and sign attestation
        let attestation = CapabilityAttestation::new(
            "agent1".to_string(),
            capability,
            true,
        );
        let signing_data = attestation.signing_data();
        let signature = signer.sign(&signing_data).unwrap();

        let signed_attestation = attestation.with_signature(
            public_key.clone(),
            signature.to_bytes(),
        );

        // Verify directly using tenzro_crypto::signatures::verify
        let result = tenzro_crypto::signatures::verify(
            &public_key,
            &signed_attestation.signing_data(),
            &Signature::new(public_key.key_type(), signed_attestation.signature.unwrap()),
        );
        assert!(result.is_ok(), "Signature verification should succeed");
    }

    // -----------------------------------------------------------------
    // CRITICAL #52 — eager attestation signature verification
    // -----------------------------------------------------------------

    /// Helper: register a capability for an agent and return a fresh
    /// registry with the supplied config.
    fn registry_with(config: AttestationConfig, agent_id: &str, cap: &Capability)
        -> CapabilityRegistry
    {
        let registry = CapabilityRegistry::with_config(config);
        registry
            .register_capability(agent_id.to_string(), cap.clone())
            .unwrap();
        registry
    }

    #[test]
    fn test_attest_capability_rejects_invalid_signature_at_submit_time() {
        use tenzro_crypto::{KeyPair, KeyType};
        use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};

        let cap = Capability::CodeGeneration { languages: vec!["rust".to_string()] };
        let registry = registry_with(AttestationConfig::default(), "agent1", &cap);

        let signer = Ed25519SignerImpl::new(KeyPair::generate(KeyType::Ed25519).unwrap()).unwrap();
        let pubkey = signer.public_key().clone();

        // Submit garbage signature bytes — must be rejected eagerly.
        let result = registry.attest_capability(
            "agent1".to_string(),
            cap.clone(),
            true,
            Some(pubkey),
            Some(vec![0u8; 64]),
        );

        match result {
            Err(AgentError::InvalidAttestationSignature { agent_id, reason }) => {
                assert_eq!(agent_id, "agent1");
                assert!(
                    reason.contains("signature failed verification"),
                    "unexpected reason: {}",
                    reason
                );
            }
            other => panic!("expected InvalidAttestationSignature, got {:?}", other),
        }
        assert_eq!(registry.rejected_attestation_count(), 1);
        assert!(registry.get_attestations(&cap).is_empty(),
            "rejected attestation must not be stored");
    }

    #[test]
    fn test_attest_capability_rejects_self_attestation_by_default() {
        use tenzro_crypto::{KeyPair, KeyType};
        use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};

        let cap = Capability::SmartContractExecution;
        let registry = registry_with(AttestationConfig::default(), "agent1", &cap);

        // Generate a signer and register its derived address as the
        // agent's wallet — this is what triggers the self-attestation
        // guard when allow_self_attestation = false.
        let signer = Ed25519SignerImpl::new(KeyPair::generate(KeyType::Ed25519).unwrap()).unwrap();
        let pubkey = signer.public_key().clone();
        let crypto_addr = pubkey.to_address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        let agent_address = Address::new(addr_bytes);
        registry.register_agent_address("agent1".to_string(), agent_address);

        // Use the convenience signer wrapper so the signature is valid;
        // the only thing that should reject this is the self-attestation
        // guard.
        let result = registry.attest_capability_with_signer(
            "agent1".to_string(),
            cap.clone(),
            true,
            &signer,
        );

        match result {
            Err(AgentError::InvalidAttestationSignature { reason, .. }) => {
                assert!(reason.contains("self-attestation"), "unexpected reason: {}", reason);
            }
            other => panic!("expected self-attestation rejection, got {:?}", other),
        }
        assert_eq!(registry.rejected_attestation_count(), 1);
    }

    #[test]
    fn test_attest_capability_allows_self_attestation_when_enabled() {
        use tenzro_crypto::{KeyPair, KeyType};
        use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};

        let cap = Capability::SmartContractExecution;
        let registry = registry_with(
            AttestationConfig::default().with_self_attestation(true),
            "agent1",
            &cap,
        );

        let signer = Ed25519SignerImpl::new(KeyPair::generate(KeyType::Ed25519).unwrap()).unwrap();
        let pubkey = signer.public_key().clone();
        let crypto_addr = pubkey.to_address();
        let mut addr_bytes = [0u8; 32];
        addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
        registry.register_agent_address("agent1".to_string(), Address::new(addr_bytes));

        // Self-attestation must succeed because the operator opted in.
        registry
            .attest_capability_with_signer("agent1".to_string(), cap.clone(), true, &signer)
            .expect("self-attestation should be allowed when explicitly enabled");
        assert_eq!(registry.get_attestations(&cap).len(), 1);
        assert_eq!(registry.rejected_attestation_count(), 0);
    }

    #[test]
    fn test_attest_capability_rejects_untrusted_attester_when_whitelist_set() {
        use tenzro_crypto::{KeyPair, KeyType};
        use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};

        let cap = Capability::DataAnalysis { formats: vec!["csv".to_string()] };

        // Build a whitelist that contains some *other* address.
        let trusted_signer = Ed25519SignerImpl::new(KeyPair::generate(KeyType::Ed25519).unwrap()).unwrap();
        let trusted_crypto = trusted_signer.public_key().to_address();
        let mut trusted_bytes = [0u8; 32];
        trusted_bytes[..20].copy_from_slice(trusted_crypto.as_bytes());

        let mut whitelist = HashSet::new();
        whitelist.insert(Address::new(trusted_bytes));

        let config = AttestationConfig::default().with_trusted_attesters(whitelist);
        let registry = registry_with(config, "agent1", &cap);

        // A *different* signer attempts to attest — must be rejected.
        let other_signer =
            Ed25519SignerImpl::new(KeyPair::generate(KeyType::Ed25519).unwrap()).unwrap();
        let result = registry.attest_capability_with_signer(
            "agent1".to_string(),
            cap.clone(),
            false,
            &other_signer,
        );

        match result {
            Err(AgentError::InvalidAttestationSignature { reason, .. }) => {
                assert!(
                    reason.contains("trusted attester"),
                    "unexpected reason: {}",
                    reason
                );
            }
            other => panic!("expected whitelist rejection, got {:?}", other),
        }
        assert_eq!(registry.rejected_attestation_count(), 1);
    }

    #[test]
    fn test_attest_capability_accepts_whitelisted_attester() {
        use tenzro_crypto::{KeyPair, KeyType};
        use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};

        let cap = Capability::ComputerVision { tasks: vec!["ocr".to_string()] };

        let signer = Ed25519SignerImpl::new(KeyPair::generate(KeyType::Ed25519).unwrap()).unwrap();
        let signer_crypto = signer.public_key().to_address();
        let mut signer_bytes = [0u8; 32];
        signer_bytes[..20].copy_from_slice(signer_crypto.as_bytes());

        let mut whitelist = HashSet::new();
        whitelist.insert(Address::new(signer_bytes));

        let config = AttestationConfig::default().with_trusted_attesters(whitelist);
        let registry = registry_with(config, "agent1", &cap);

        registry
            .attest_capability_with_signer("agent1".to_string(), cap.clone(), false, &signer)
            .expect("whitelisted attester should be accepted");
        assert_eq!(registry.get_attestations(&cap).len(), 1);
        assert_eq!(registry.rejected_attestation_count(), 0);
    }

    #[test]
    fn test_rejected_attestation_count_increments_across_failures() {
        use tenzro_crypto::{KeyPair, KeyType};
        use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};

        let cap = Capability::MultiAgentCoordination;
        let registry = registry_with(AttestationConfig::default(), "agent1", &cap);

        let signer = Ed25519SignerImpl::new(KeyPair::generate(KeyType::Ed25519).unwrap()).unwrap();
        let pubkey = signer.public_key().clone();

        for _ in 0..3 {
            let _ = registry.attest_capability(
                "agent1".to_string(),
                cap.clone(),
                false,
                Some(pubkey.clone()),
                Some(vec![0u8; 64]),
            );
        }
        assert_eq!(registry.rejected_attestation_count(), 3);
    }

    #[test]
    fn test_attest_capability_with_signer_succeeds_end_to_end() {
        use tenzro_crypto::{KeyPair, KeyType};
        use tenzro_crypto::signatures::Ed25519SignerImpl;

        let cap = Capability::CodeGeneration { languages: vec!["rust".to_string()] };
        let registry = registry_with(AttestationConfig::default(), "agent1", &cap);

        let signer =
            Ed25519SignerImpl::new(KeyPair::generate(KeyType::Ed25519).unwrap()).unwrap();

        registry
            .attest_capability_with_signer("agent1".to_string(), cap.clone(), true, &signer)
            .expect("end-to-end signer wrapper should succeed");

        let attestations = registry.get_attestations(&cap);
        assert_eq!(attestations.len(), 1);
        assert!(attestations[0].tee_backed);
        assert!(attestations[0].signature.is_some());
        assert!(attestations[0].attester_public_key.is_some());
    }

    #[test]
    fn test_remove_agent_drops_registered_address() {
        let cap = Capability::SmartContractExecution;
        let registry = registry_with(AttestationConfig::default(), "agent1", &cap);

        let address = Address::new([7u8; 32]);
        registry.register_agent_address("agent1".to_string(), address);
        assert_eq!(registry.agent_address("agent1"), Some(address));

        registry.remove_agent("agent1").unwrap();
        assert_eq!(registry.agent_address("agent1"), None);
    }

    #[test]
    fn test_legacy_attest_capability_still_accepts_valid_signature() {
        use tenzro_crypto::{KeyPair, KeyType};
        use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};

        let cap = Capability::ExternalAPIIntegration { apis: vec!["openai".to_string()] };
        let registry = registry_with(AttestationConfig::default(), "agent1", &cap);

        // Build the same attestation envelope the legacy API constructs
        // internally so we can sign it with the matching timestamp.
        let envelope = CapabilityAttestation::new("agent1".to_string(), cap.clone(), false);
        let signing_data = envelope.signing_data();

        let signer = Ed25519SignerImpl::new(KeyPair::generate(KeyType::Ed25519).unwrap()).unwrap();
        let pubkey = signer.public_key().clone();
        let signature = signer.sign(&signing_data).unwrap();

        // Submit via the pre-signed envelope path so timestamps match.
        let signed = envelope.with_signature(pubkey, signature.to_bytes());
        registry
            .submit_attestation(signed)
            .expect("backward-compatible signed envelope should be accepted");
        assert_eq!(registry.get_attestations(&cap).len(), 1);
    }

    #[test]
    fn test_unsigned_attestation_rejected_when_signatures_required() {
        let cap = Capability::SmartContractExecution;
        let registry = registry_with(AttestationConfig::default(), "agent1", &cap);

        let result =
            registry.attest_capability("agent1".to_string(), cap.clone(), true, None, None);
        match result {
            Err(AgentError::InvalidAttestationSignature { reason, .. }) => {
                assert!(reason.contains("missing"), "unexpected reason: {}", reason);
            }
            other => panic!("expected InvalidAttestationSignature, got {:?}", other),
        }
        assert_eq!(registry.rejected_attestation_count(), 1);
    }
}
