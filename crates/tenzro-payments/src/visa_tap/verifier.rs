//! Visa TAP 7-stage CDN Proxy verification pipeline

use std::sync::Arc;
use std::time::Duration;
use chrono::Utc;
use tracing::{debug, info, warn};

use crate::error::{PaymentError, Result};
use crate::rfc9421::{
    AgentRegistryClient, NonceCache, RequestParts, SignedHeaders,
};

/// Result of TAP verification pipeline
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Whether all verification stages passed
    pub verified: bool,
    /// Agent's key identifier
    pub agent_key_id: String,
    /// Agent's decentralized identifier (if available)
    pub agent_did: Option<String>,
    /// List of verification stages that passed
    pub stages_passed: Vec<String>,
}

/// Visa TAP verifier implementing 7-stage CDN Proxy verification
pub struct TapVerifier {
    agent_registry: Arc<dyn AgentRegistryClient>,
    nonce_cache: NonceCache,
    max_signature_age: Duration,
    required_domain: Option<String>,
}

impl TapVerifier {
    /// Create a new TAP verifier
    pub fn new(agent_registry: Arc<dyn AgentRegistryClient>) -> Self {
        Self {
            agent_registry,
            nonce_cache: NonceCache::new(),
            max_signature_age: Duration::from_secs(480), // 8 minutes default
            required_domain: None,
        }
    }

    /// Set maximum signature age
    pub fn with_max_age(mut self, duration: Duration) -> Self {
        self.max_signature_age = duration;
        self
    }

    /// Set required domain for @authority binding
    pub fn with_domain(mut self, domain: String) -> Self {
        self.required_domain = Some(domain);
        self
    }

    /// Verify HTTP request using 7-stage pipeline
    ///
    /// Stages:
    /// 1. Header extraction (done by caller)
    /// 2. Key retrieval from agent registry
    /// 3. Timestamp validation
    /// 4. Replay prevention via nonce cache
    /// 5. Domain binding validation
    /// 6. Cryptographic signature verification
    /// 7. Build verification result
    pub async fn verify(
        &self,
        request_parts: &RequestParts,
        signed_headers: &SignedHeaders,
    ) -> Result<VerificationResult> {
        let mut stages_passed = Vec::new();

        // Stage 1: Header extraction (assumed done by caller)
        stages_passed.push("header_extraction".to_string());
        debug!("Stage 1: Header extraction complete");

        // Stage 2: Key retrieval
        let key_id = &signed_headers.parsed.params.keyid;
        let public_key_info = self.agent_registry.get_public_key(key_id).await
            .map_err(|e| PaymentError::AgentRegistryError(format!("Key retrieval failed: {}", e)))?;

        if !public_key_info.is_active {
            warn!("Agent key {} is not active", key_id);
            return Ok(VerificationResult {
                verified: false,
                agent_key_id: key_id.clone(),
                agent_did: public_key_info.agent_did,
                stages_passed,
            });
        }

        stages_passed.push("key_retrieval".to_string());
        debug!("Stage 2: Key retrieval successful for {}", key_id);

        // Stage 3: Timestamp validation
        if let Some(created) = signed_headers.parsed.params.created {
            let created_time = chrono::DateTime::from_timestamp(created as i64, 0)
                .ok_or_else(|| PaymentError::VisaTapError("Invalid created timestamp".to_string()))?;
            let now = Utc::now();
            let age = now.signed_duration_since(created_time);

            if age.num_seconds() < 0 {
                warn!("Signature created in the future: {:?}", created_time);
                return Err(PaymentError::VisaTapError(
                    "Signature timestamp is in the future".to_string(),
                ));
            }

            if age > chrono::Duration::from_std(self.max_signature_age)
                .map_err(|e| PaymentError::VisaTapError(format!("Duration conversion error: {}", e)))? {
                warn!("Signature too old: age={:?}, max={:?}", age, self.max_signature_age);
                return Err(PaymentError::VisaTapError(
                    format!("Signature age ({:?}) exceeds maximum ({:?})", age, self.max_signature_age),
                ));
            }

            stages_passed.push("timestamp_validation".to_string());
            debug!("Stage 3: Timestamp validation passed (age: {:?})", age);
        } else {
            warn!("Signature missing 'created' timestamp");
            return Err(PaymentError::VisaTapError(
                "Signature must include 'created' timestamp".to_string(),
            ));
        }

        // Stage 4: Replay prevention
        if let Some(nonce) = &signed_headers.parsed.params.nonce {
            self.nonce_cache.check_and_store(nonce)
                .map_err(|e| PaymentError::ReplayDetected(format!("Nonce check failed: {}", e)))?;

            stages_passed.push("replay_prevention".to_string());
            debug!("Stage 4: Replay prevention passed (nonce: {})", nonce);
        } else {
            warn!("Signature missing nonce for replay prevention");
            return Err(PaymentError::VisaTapError(
                "Signature must include nonce for replay prevention".to_string(),
            ));
        }

        // Stage 5: Domain binding
        if let Some(required_domain) = &self.required_domain {
            if !signed_headers.parsed.covered_components.contains(&"@authority".to_string()) {
                warn!("Signature does not cover @authority component");
                return Err(PaymentError::VisaTapError(
                    "Signature must cover @authority component for domain binding".to_string(),
                ));
            }

            if &request_parts.authority != required_domain {
                warn!(
                    "Domain mismatch: expected {}, got {}",
                    required_domain, request_parts.authority
                );
                return Err(PaymentError::VisaTapError(
                    format!("Domain mismatch: expected {}, got {}", required_domain, request_parts.authority),
                ));
            }

            stages_passed.push("domain_binding".to_string());
            debug!("Stage 5: Domain binding validated ({})", required_domain);
        } else {
            // Domain binding not required, skip
            stages_passed.push("domain_binding_skipped".to_string());
            debug!("Stage 5: Domain binding not required");
        }

        // Stage 6: Cryptographic verification
        crate::rfc9421::signature::verify_http_signature(
            request_parts,
            signed_headers,
            &public_key_info.public_key_bytes,
            &public_key_info.algorithm,
        )
        .map_err(|e| PaymentError::Rfc9421Error(format!("Signature verification failed: {}", e)))?;

        stages_passed.push("cryptographic_verification".to_string());
        info!("Stage 6: Cryptographic verification successful for agent {}", key_id);

        // Stage 7: Build verification result
        stages_passed.push("result_construction".to_string());
        debug!("Stage 7: Verification complete");

        Ok(VerificationResult {
            verified: true,
            agent_key_id: key_id.clone(),
            agent_did: public_key_info.agent_did,
            stages_passed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfc9421::{AgentPublicKeyInfo, SignatureAlgorithm, SignatureInput, SignatureParams};
    use async_trait::async_trait;
    use std::collections::HashMap;

    struct MockAgentRegistry {
        keys: HashMap<String, AgentPublicKeyInfo>,
    }

    #[async_trait]
    impl AgentRegistryClient for MockAgentRegistry {
        async fn get_public_key(&self, key_id: &str) -> Result<AgentPublicKeyInfo> {
            self.keys.get(key_id)
                .cloned()
                .ok_or_else(|| PaymentError::AgentRegistryError("Key not found".to_string()))
        }

        async fn verify_agent(&self, key_id: &str) -> Result<bool> {
            Ok(self.keys.contains_key(key_id))
        }
    }

    fn create_mock_registry() -> Arc<MockAgentRegistry> {
        let mut keys = HashMap::new();
        keys.insert(
            "test-key-1".to_string(),
            AgentPublicKeyInfo {
                key_id: "test-key-1".to_string(),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key_bytes: vec![1; 32],
                agent_did: Some("did:tenzro:machine:test".to_string()),
                is_active: true,
            },
        );
        Arc::new(MockAgentRegistry { keys })
    }

    fn create_test_request_parts() -> RequestParts {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        RequestParts {
            method: "GET".to_string(),
            authority: "api.example.com".to_string(),
            path: "/resource".to_string(),
            headers,
        }
    }

    fn create_test_signed_headers() -> SignedHeaders {
        let now = Utc::now().timestamp() as u64;
        SignedHeaders {
            signature_input_raw: "sig1=(\"@authority\" \"@path\" \"content-type\");created=123;nonce=\"abc\"".to_string(),
            signature_bytes: vec![0; 64],
            parsed: SignatureInput {
                label: "sig1".to_string(),
                covered_components: vec![
                    "@authority".to_string(),
                    "@path".to_string(),
                    "content-type".to_string(),
                ],
                params: SignatureParams {
                    label: "sig1".to_string(),
                    created: Some(now),
                    expires: None,
                    nonce: Some("test-nonce-123".to_string()),
                    keyid: "test-key-1".to_string(),
                    alg: SignatureAlgorithm::Ed25519,
                    tag: None,
                },
            },
        }
    }

    #[tokio::test]
    async fn test_verifier_creation() {
        let registry = create_mock_registry();
        let verifier = TapVerifier::new(registry.clone());
        assert_eq!(verifier.max_signature_age, Duration::from_secs(480));
        assert!(verifier.required_domain.is_none());
    }

    #[tokio::test]
    async fn test_verifier_with_custom_settings() {
        let registry = create_mock_registry();
        let verifier = TapVerifier::new(registry.clone())
            .with_max_age(Duration::from_secs(300))
            .with_domain("api.example.com".to_string());

        assert_eq!(verifier.max_signature_age, Duration::from_secs(300));
        assert_eq!(verifier.required_domain, Some("api.example.com".to_string()));
    }

    #[tokio::test]
    async fn test_verify_missing_timestamp() {
        let registry = create_mock_registry();
        let verifier = TapVerifier::new(registry.clone());
        let request_parts = create_test_request_parts();
        let mut signed_headers = create_test_signed_headers();
        signed_headers.parsed.params.created = None;

        let result = verifier.verify(&request_parts, &signed_headers).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("created"));
    }

    #[tokio::test]
    async fn test_verify_missing_nonce() {
        let registry = create_mock_registry();
        let verifier = TapVerifier::new(registry.clone());
        let request_parts = create_test_request_parts();
        let mut signed_headers = create_test_signed_headers();
        signed_headers.parsed.params.nonce = None;

        let result = verifier.verify(&request_parts, &signed_headers).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonce"));
    }

    #[tokio::test]
    async fn test_verify_domain_mismatch() {
        let registry = create_mock_registry();
        let verifier = TapVerifier::new(registry.clone())
            .with_domain("required-domain.com".to_string());
        let request_parts = create_test_request_parts(); // uses api.example.com
        let signed_headers = create_test_signed_headers();

        let result = verifier.verify(&request_parts, &signed_headers).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Domain mismatch"));
    }

    #[tokio::test]
    async fn test_verify_inactive_key() {
        let mut keys = HashMap::new();
        keys.insert(
            "inactive-key".to_string(),
            AgentPublicKeyInfo {
                key_id: "inactive-key".to_string(),
                algorithm: SignatureAlgorithm::Ed25519,
                public_key_bytes: vec![1; 32],
                agent_did: None,
                is_active: false,
            },
        );
        let registry = Arc::new(MockAgentRegistry { keys });
        let verifier = TapVerifier::new(registry);

        let request_parts = create_test_request_parts();
        let mut signed_headers = create_test_signed_headers();
        signed_headers.parsed.params.keyid = "inactive-key".to_string();

        let result = verifier.verify(&request_parts, &signed_headers).await.unwrap();
        assert!(!result.verified);
        assert_eq!(result.agent_key_id, "inactive-key");
    }

    #[tokio::test]
    async fn test_verify_future_timestamp() {
        let registry = create_mock_registry();
        let verifier = TapVerifier::new(registry.clone());
        let request_parts = create_test_request_parts();
        let mut signed_headers = create_test_signed_headers();

        // Set timestamp to 1 hour in the future
        let future_time = (Utc::now() + chrono::Duration::hours(1)).timestamp() as u64;
        signed_headers.parsed.params.created = Some(future_time);

        let result = verifier.verify(&request_parts, &signed_headers).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("future"));
    }

    #[tokio::test]
    async fn test_verify_expired_signature() {
        let registry = create_mock_registry();
        let verifier = TapVerifier::new(registry.clone())
            .with_max_age(Duration::from_secs(60));
        let request_parts = create_test_request_parts();
        let mut signed_headers = create_test_signed_headers();

        // Set timestamp to 2 hours ago
        let old_time = (Utc::now() - chrono::Duration::hours(2)).timestamp() as u64;
        signed_headers.parsed.params.created = Some(old_time);

        let result = verifier.verify(&request_parts, &signed_headers).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("age"));
    }
}
