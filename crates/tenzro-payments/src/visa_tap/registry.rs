//! HTTP client for Visa's external agent registry

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};

use crate::error::{PaymentError, Result};
use crate::rfc9421::{AgentPublicKeyInfo, AgentRegistryClient, SignatureAlgorithm};

/// Visa Agent Registry client
pub struct VisaAgentRegistryClient {
    http_client: reqwest::Client,
    registry_url: String,
}

/// JWK Set response from a `/.well-known/jwks` endpoint.
/// Returned by `list_keys()` for bulk agent-key publication.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwkResponse {
    keys: Vec<JwkKey>,
}

/// Single JWK entry, as published either standalone (single-key fetch) or
/// inside a [`JwkResponse`] (`/.well-known/jwks` bulk fetch).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct JwkKey {
    kid: String,
    kty: String,
    alg: Option<String>,
    x: Option<String>,
    n: Option<String>,
    e: Option<String>,
    #[serde(default)]
    active: bool,
    agent_did: Option<String>,
}

impl VisaAgentRegistryClient {
    /// Create a new Visa Agent Registry client
    pub fn new(registry_url: String) -> Self {
        Self {
            http_client: reqwest::Client::new(),
            registry_url,
        }
    }

    /// Create client with default Visa MCP registry URL
    pub fn with_default_url() -> Self {
        Self::new("https://mcp.visa.com/.well-known/jwks".to_string())
    }

    /// Parse JWK key into AgentPublicKeyInfo
    fn parse_jwk_key(key: &JwkKey) -> Result<AgentPublicKeyInfo> {
        let algorithm = match key.kty.as_str() {
            "OKP" => {
                // Ed25519 key
                match key.alg.as_deref() {
                    Some("EdDSA") | Some("Ed25519") | None => SignatureAlgorithm::Ed25519,
                    Some(alg) => {
                        return Err(PaymentError::AgentRegistryError(
                            format!("Unsupported OKP algorithm: {}", alg),
                        ))
                    }
                }
            }
            "RSA" => {
                // RSA key
                match key.alg.as_deref() {
                    Some("PS256") | Some("RS256") | None => SignatureAlgorithm::RsaPssSha256,
                    Some(alg) => {
                        return Err(PaymentError::AgentRegistryError(
                            format!("Unsupported RSA algorithm: {}", alg),
                        ))
                    }
                }
            }
            kty => {
                return Err(PaymentError::AgentRegistryError(
                    format!("Unsupported key type: {}", kty),
                ))
            }
        };

        // Extract public key bytes
        let public_key_bytes = match algorithm {
            SignatureAlgorithm::Ed25519 => {
                let x = key.x.as_ref().ok_or_else(|| {
                    PaymentError::AgentRegistryError("Missing 'x' parameter for Ed25519 key".to_string())
                })?;
                URL_SAFE_NO_PAD.decode(x)
                    .map_err(|e| PaymentError::AgentRegistryError(format!("Invalid base64 in 'x': {}", e)))?
            }
            SignatureAlgorithm::RsaPssSha256 => {
                let n = key.n.as_ref().ok_or_else(|| {
                    PaymentError::AgentRegistryError("Missing 'n' parameter for RSA key".to_string())
                })?;
                let e = key.e.as_ref().ok_or_else(|| {
                    PaymentError::AgentRegistryError("Missing 'e' parameter for RSA key".to_string())
                })?;

                // Concatenate n and e for RSA public key representation
                let mut bytes = Vec::new();
                bytes.extend_from_slice(
                    &URL_SAFE_NO_PAD.decode(n)
                        .map_err(|e| PaymentError::AgentRegistryError(format!("Invalid base64 in 'n': {}", e)))?,
                );
                bytes.extend_from_slice(
                    &URL_SAFE_NO_PAD.decode(e)
                        .map_err(|e| PaymentError::AgentRegistryError(format!("Invalid base64 in 'e': {}", e)))?,
                );
                bytes
            }
            // Visa TAP §JWKS only emits OKP/Ed25519 and RSA/RS256|PS256 →
            // RsaPssSha256 from the `kty` switch above. The other RFC 9421
            // algorithms (ECDSA P-256/P-384, RSA-PSS-SHA512, RSA-v1.5,
            // HMAC) are not produced for Visa-issued JWK material, so this
            // branch is unreachable — surface as an explicit error rather
            // than panicking, in case Visa ever extends the JWKS contract.
            other => {
                return Err(PaymentError::AgentRegistryError(format!(
                    "Visa JWK parser produced unexpected algorithm {:?} — \
                     the kty→algorithm switch only emits Ed25519 / RsaPssSha256",
                    other
                )));
            }
        };

        Ok(AgentPublicKeyInfo {
            key_id: key.kid.clone(),
            algorithm,
            public_key_bytes,
            agent_did: key.agent_did.clone(),
            is_active: key.active,
        })
    }

    /// Bulk-fetch every published agent key from the registry's JWK Set
    /// endpoint (`{registry_url}` itself, since the default URL points at
    /// `/.well-known/jwks`). Skips entries that don't parse rather than
    /// failing the whole list.
    pub async fn list_keys(&self) -> Result<Vec<AgentPublicKeyInfo>> {
        debug!("Listing public keys from registry: {}", self.registry_url);

        let response = self
            .http_client
            .get(&self.registry_url)
            .send()
            .await
            .map_err(|e| PaymentError::AgentRegistryError(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            return Err(PaymentError::AgentRegistryError(format!(
                "Registry returned status: {}",
                response.status()
            )));
        }

        let jwks: JwkResponse = response
            .json()
            .await
            .map_err(|e| PaymentError::AgentRegistryError(format!("Failed to parse JWKS: {}", e)))?;

        let mut out = Vec::with_capacity(jwks.keys.len());
        for key in &jwks.keys {
            match Self::parse_jwk_key(key) {
                Ok(info) => out.push(info),
                Err(e) => warn!("Skipping malformed JWK entry kid={}: {}", key.kid, e),
            }
        }
        Ok(out)
    }
}

#[async_trait]
impl AgentRegistryClient for VisaAgentRegistryClient {
    async fn get_public_key(&self, key_id: &str) -> Result<AgentPublicKeyInfo> {
        debug!("Fetching public key from Visa registry: {}", key_id);

        let url = format!("{}/keys/{}", self.registry_url, key_id);

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .map_err(|e| PaymentError::AgentRegistryError(format!("HTTP request failed: {}", e)))?;

        if !response.status().is_success() {
            warn!("Failed to fetch key {}: status {}", key_id, response.status());
            return Err(PaymentError::AgentRegistryError(format!(
                "Registry returned status: {}",
                response.status()
            )));
        }

        let key_response: JwkKey = response
            .json()
            .await
            .map_err(|e| PaymentError::AgentRegistryError(format!("Failed to parse response: {}", e)))?;

        if key_response.kid != key_id {
            warn!("Key ID mismatch: expected {}, got {}", key_id, key_response.kid);
            return Err(PaymentError::AgentRegistryError(
                "Key ID mismatch in response".to_string(),
            ));
        }

        Self::parse_jwk_key(&key_response)
    }

    async fn verify_agent(&self, key_id: &str) -> Result<bool> {
        debug!("Verifying agent: {}", key_id);

        match self.get_public_key(key_id).await {
            Ok(info) => Ok(info.is_active),
            Err(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = VisaAgentRegistryClient::new("https://example.com/jwks".to_string());
        assert_eq!(client.registry_url, "https://example.com/jwks");
    }

    #[test]
    fn test_default_url() {
        let client = VisaAgentRegistryClient::with_default_url();
        assert_eq!(client.registry_url, "https://mcp.visa.com/.well-known/jwks");
    }

    #[test]
    fn test_parse_ed25519_jwk() {
        let key = JwkKey {
            kid: "test-key-1".to_string(),
            kty: "OKP".to_string(),
            alg: Some("EdDSA".to_string()),
            x: Some(URL_SAFE_NO_PAD.encode([1u8; 32])),
            n: None,
            e: None,
            active: true,
            agent_did: Some("did:tenzro:machine:test".to_string()),
        };

        let info = VisaAgentRegistryClient::parse_jwk_key(&key).unwrap();
        assert_eq!(info.key_id, "test-key-1");
        assert!(matches!(info.algorithm, SignatureAlgorithm::Ed25519));
        assert_eq!(info.public_key_bytes.len(), 32);
        assert!(info.is_active);
        assert_eq!(info.agent_did.as_deref(), Some("did:tenzro:machine:test"));
    }

    #[test]
    fn test_parse_rsa_jwk() {
        let key = JwkKey {
            kid: "test-rsa-key".to_string(),
            kty: "RSA".to_string(),
            alg: Some("PS256".to_string()),
            x: None,
            n: Some(URL_SAFE_NO_PAD.encode([2u8; 256])),
            e: Some(URL_SAFE_NO_PAD.encode([3u8; 3])),
            active: true,
            agent_did: None,
        };

        let info = VisaAgentRegistryClient::parse_jwk_key(&key).unwrap();
        assert_eq!(info.key_id, "test-rsa-key");
        assert!(matches!(info.algorithm, SignatureAlgorithm::RsaPssSha256));
        assert_eq!(info.public_key_bytes.len(), 256 + 3);
        assert!(info.is_active);
    }

    #[test]
    fn test_parse_unsupported_key_type() {
        let key = JwkKey {
            kid: "bad-key".to_string(),
            kty: "EC".to_string(), // Unsupported
            alg: Some("ES256".to_string()),
            x: None,
            n: None,
            e: None,
            active: true,
            agent_did: None,
        };

        let result = VisaAgentRegistryClient::parse_jwk_key(&key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Unsupported key type"));
    }

    #[test]
    fn test_parse_missing_x_parameter() {
        let key = JwkKey {
            kid: "incomplete-key".to_string(),
            kty: "OKP".to_string(),
            alg: Some("EdDSA".to_string()),
            x: None, // Missing
            n: None,
            e: None,
            active: true,
            agent_did: None,
        };

        let result = VisaAgentRegistryClient::parse_jwk_key(&key);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Missing 'x'"));
    }
}
