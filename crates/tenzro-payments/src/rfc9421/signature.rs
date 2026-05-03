//! RFC 9421 HTTP Message Signature implementation
//!
//! Provides parsing, creation, and verification of HTTP message signatures
//! as defined in RFC 9421.

use crate::error::{PaymentError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use tenzro_crypto::keys::{KeyPair, KeyType, PublicKey};
use tenzro_crypto::signatures::{Ed25519SignerImpl, Ed25519VerifierImpl, Signature, Signer, Verifier};
use tracing::debug;

/// Supported signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SignatureAlgorithm {
    /// Ed25519 signature algorithm
    Ed25519,
    /// RSA-PSS with SHA-256
    #[serde(rename = "rsa-pss-sha256")]
    RsaPssSha256,
}

impl fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl SignatureAlgorithm {
    /// Parse algorithm from string
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "ed25519" => Ok(SignatureAlgorithm::Ed25519),
            "rsa-pss-sha256" => Ok(SignatureAlgorithm::RsaPssSha256),
            _ => Err(PaymentError::Rfc9421Error(format!(
                "unsupported algorithm: {}",
                s
            ))),
        }
    }

    /// Convert algorithm to string representation
    pub fn as_str(&self) -> &str {
        match self {
            SignatureAlgorithm::Ed25519 => "ed25519",
            SignatureAlgorithm::RsaPssSha256 => "rsa-pss-sha256",
        }
    }
}

/// Signature parameters from RFC 9421
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureParams {
    /// Signature label
    pub label: String,
    /// Unix timestamp when signature was created
    pub created: Option<u64>,
    /// Unix timestamp when signature expires
    pub expires: Option<u64>,
    /// Unique nonce for replay protection
    pub nonce: Option<String>,
    /// Key identifier
    pub keyid: String,
    /// Signature algorithm
    pub alg: SignatureAlgorithm,
    /// Optional tag for additional context
    pub tag: Option<String>,
}

/// Parsed signature input from Signature-Input header
#[derive(Debug, Clone)]
pub struct SignatureInput {
    /// Signature label
    pub label: String,
    /// List of covered components (e.g., "@method", "@path", "content-type")
    pub covered_components: Vec<String>,
    /// Signature parameters
    pub params: SignatureParams,
}

/// HTTP request parts needed for signature verification
#[derive(Debug, Clone)]
pub struct RequestParts {
    /// HTTP method (e.g., "GET", "POST")
    pub method: String,
    /// Authority (host:port)
    pub authority: String,
    /// Request path
    pub path: String,
    /// HTTP headers (lowercase keys)
    pub headers: HashMap<String, String>,
}

/// Signed HTTP headers
#[derive(Debug, Clone)]
pub struct SignedHeaders {
    /// Raw Signature-Input header value
    pub signature_input_raw: String,
    /// Base64-decoded signature bytes
    pub signature_bytes: Vec<u8>,
    /// Parsed signature input
    pub parsed: SignatureInput,
}

/// Parse Signature-Input header value
///
/// Format: `sig1=("@authority" "@path" "content-type");created=1701234567;nonce="abc123";keyid="agent_key_001";alg="ed25519";tag="agent-browser-auth"`
///
/// # Arguments
///
/// * `header` - The Signature-Input header value
///
/// # Returns
///
/// Parsed `SignatureInput` structure
pub fn parse_signature_input(header: &str) -> Result<SignatureInput> {
    // Find the position of '=' to split label from the rest
    let eq_pos = header
        .find('=')
        .ok_or_else(|| PaymentError::Rfc9421Error("missing '=' in Signature-Input".to_string()))?;

    let label = header[..eq_pos].trim().to_string();
    let rest = &header[eq_pos + 1..];

    // Find the inner list (components in parentheses)
    let paren_start = rest
        .find('(')
        .ok_or_else(|| PaymentError::Rfc9421Error("missing '(' in Signature-Input".to_string()))?;
    let paren_end = rest
        .find(')')
        .ok_or_else(|| PaymentError::Rfc9421Error("missing ')' in Signature-Input".to_string()))?;

    // Extract covered components
    let components_str = &rest[paren_start + 1..paren_end];
    let covered_components: Vec<String> = components_str
        .split_whitespace()
        .map(|s| s.trim_matches('"').to_string())
        .collect();

    // Parse parameters after the closing parenthesis
    let params_str = &rest[paren_end + 1..];
    let mut created = None;
    let mut expires = None;
    let mut nonce = None;
    let mut keyid = String::new();
    let mut alg = None;
    let mut tag = None;

    for part in params_str.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if let Some((key, value)) = part.split_once('=') {
            let key = key.trim();
            let value = value.trim().trim_matches('"');

            match key {
                "created" => {
                    created = Some(value.parse::<u64>().map_err(|_| {
                        PaymentError::Rfc9421Error("invalid created timestamp".to_string())
                    })?);
                }
                "expires" => {
                    expires = Some(value.parse::<u64>().map_err(|_| {
                        PaymentError::Rfc9421Error("invalid expires timestamp".to_string())
                    })?);
                }
                "nonce" => {
                    nonce = Some(value.to_string());
                }
                "keyid" => {
                    keyid = value.to_string();
                }
                "alg" => {
                    alg = Some(SignatureAlgorithm::from_str(value)?);
                }
                "tag" => {
                    tag = Some(value.to_string());
                }
                _ => {
                    debug!("Unknown signature parameter: {}", key);
                }
            }
        }
    }

    // Validate required parameters
    if keyid.is_empty() {
        return Err(PaymentError::Rfc9421Error(
            "missing required parameter: keyid".to_string(),
        ));
    }

    let alg = alg.ok_or_else(|| {
        PaymentError::Rfc9421Error("missing required parameter: alg".to_string())
    })?;

    Ok(SignatureInput {
        label: label.clone(),
        covered_components,
        params: SignatureParams {
            label,
            created,
            expires,
            nonce,
            keyid,
            alg,
            tag,
        },
    })
}

/// Build the canonical signature base string per RFC 9421 Section 2.5
///
/// # Arguments
///
/// * `request_parts` - HTTP request parts
/// * `input` - Parsed signature input
///
/// # Returns
///
/// Canonical signature base as string
pub fn build_signature_base(request_parts: &RequestParts, input: &SignatureInput) -> Result<String> {
    let mut lines = Vec::new();

    // Process each covered component
    for component in &input.covered_components {
        let component_lower = component.to_lowercase();
        let value = match component_lower.as_str() {
            "@method" => request_parts.method.clone(),
            "@authority" => request_parts.authority.clone(),
            "@path" => request_parts.path.clone(),
            _ => {
                // Regular header lookup
                request_parts
                    .headers
                    .get(&component_lower)
                    .ok_or_else(|| PaymentError::Rfc9421Error(format!("Missing header: {}", component)))?
                    .clone()
            }
        };

        // Format: "component-name": value
        lines.push(format!("\"{}\": {}", component_lower, value));
    }

    // Build @signature-params line
    let components_list: Vec<String> = input
        .covered_components
        .iter()
        .map(|c| format!("\"{}\"", c.to_lowercase()))
        .collect();

    let mut params_parts = vec![format!("({})", components_list.join(" "))];

    if let Some(created) = input.params.created {
        params_parts.push(format!("created={}", created));
    }
    if let Some(expires) = input.params.expires {
        params_parts.push(format!("expires={}", expires));
    }
    if let Some(ref nonce) = input.params.nonce {
        params_parts.push(format!("nonce=\"{}\"", nonce));
    }
    params_parts.push(format!("keyid=\"{}\"", input.params.keyid));
    params_parts.push(format!("alg=\"{}\"", input.params.alg.as_str()));
    if let Some(ref tag) = input.params.tag {
        params_parts.push(format!("tag=\"{}\"", tag));
    }

    lines.push(format!("\"@signature-params\": {}", params_parts.join(";")));

    // Join all lines with newline
    Ok(lines.join("\n"))
}

/// Verify an HTTP message signature
///
/// # Arguments
///
/// * `request_parts` - HTTP request parts
/// * `signed_headers` - Signed headers containing signature and metadata
/// * `public_key_bytes` - Public key bytes for verification
/// * `algorithm` - Signature algorithm to use
///
/// # Returns
///
/// `Ok(())` if signature is valid, error otherwise
pub fn verify_http_signature(
    request_parts: &RequestParts,
    signed_headers: &SignedHeaders,
    public_key_bytes: &[u8],
    algorithm: &SignatureAlgorithm,
) -> Result<()> {
    // Build the signature base
    let signature_base = build_signature_base(request_parts, &signed_headers.parsed)?;

    // Verify based on algorithm
    match algorithm {
        SignatureAlgorithm::Ed25519 => {
            let pk = PublicKey::new(KeyType::Ed25519, public_key_bytes.to_vec());
            let sig = Signature::new(KeyType::Ed25519, signed_headers.signature_bytes.clone());
            let verifier = Ed25519VerifierImpl::new(pk)
                .map_err(|e| PaymentError::Rfc9421Error(format!("Invalid public key: {}", e)))?;
            verifier.verify(signature_base.as_bytes(), &sig)
                .map_err(|e| PaymentError::Rfc9421Error(format!("Signature verification failed: {}", e)))?;
            Ok(())
        }
        SignatureAlgorithm::RsaPssSha256 => {
            // RSA-PSS verification not yet implemented
            Err(PaymentError::Rfc9421Error(
                "RSA-PSS-SHA256 verification not yet implemented".to_string(),
            ))
        }
    }
}

/// Create an HTTP message signature
///
/// # Arguments
///
/// * `request_parts` - HTTP request parts
/// * `input` - Signature input with parameters
/// * `private_key_bytes` - Ed25519 private key bytes (32 or 64 bytes)
/// * `algorithm` - Signature algorithm to use
///
/// # Returns
///
/// Signature bytes
pub fn create_http_signature(
    request_parts: &RequestParts,
    input: &SignatureInput,
    private_key_bytes: &[u8],
    algorithm: &SignatureAlgorithm,
) -> Result<Vec<u8>> {
    // Build signature base
    let signature_base = build_signature_base(request_parts, input)?;

    match algorithm {
        SignatureAlgorithm::Ed25519 => {
            let keypair = KeyPair::from_bytes(KeyType::Ed25519, private_key_bytes)
                .map_err(|e| PaymentError::Rfc9421Error(format!("Invalid private key: {}", e)))?;
            let signer = Ed25519SignerImpl::new(keypair)
                .map_err(|e| PaymentError::Rfc9421Error(format!("Signer creation failed: {}", e)))?;
            let signature = signer.sign(signature_base.as_bytes())
                .map_err(|e| PaymentError::Rfc9421Error(format!("Signing failed: {}", e)))?;
            Ok(signature.to_bytes())
        }
        SignatureAlgorithm::RsaPssSha256 => {
            Err(PaymentError::Rfc9421Error("RSA-PSS-SHA256 not yet implemented".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_ed25519_input() {
        let header = r#"sig1=("@authority" "@path" "content-type");created=1701234567;nonce="abc123";keyid="agent_key_001";alg="ed25519";tag="agent-browser-auth""#;

        let result = parse_signature_input(header);
        assert!(result.is_ok());

        let input = result.unwrap();
        assert_eq!(input.label, "sig1");
        assert_eq!(input.covered_components.len(), 3);
        assert_eq!(input.covered_components[0], "@authority");
        assert_eq!(input.covered_components[1], "@path");
        assert_eq!(input.covered_components[2], "content-type");

        assert_eq!(input.params.label, "sig1");
        assert_eq!(input.params.created, Some(1701234567));
        assert_eq!(input.params.nonce, Some("abc123".to_string()));
        assert_eq!(input.params.keyid, "agent_key_001");
        assert_eq!(input.params.alg, SignatureAlgorithm::Ed25519);
        assert_eq!(input.params.tag, Some("agent-browser-auth".to_string()));
    }

    #[test]
    fn test_parse_rsa_pss_input() {
        let header = r#"sig2=("@method" "@authority");keyid="rsa_key_001";alg="rsa-pss-sha256""#;

        let result = parse_signature_input(header);
        assert!(result.is_ok());

        let input = result.unwrap();
        assert_eq!(input.label, "sig2");
        assert_eq!(input.params.alg, SignatureAlgorithm::RsaPssSha256);
    }

    #[test]
    fn test_parse_missing_required_params() {
        // Missing keyid
        let header = r#"sig1=("@authority");alg="ed25519""#;
        let result = parse_signature_input(header);
        assert!(result.is_err());

        // Missing alg
        let header = r#"sig1=("@authority");keyid="key1""#;
        let result = parse_signature_input(header);
        assert!(result.is_err());
    }

    #[test]
    fn test_build_signature_base() {
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("content-length".to_string(), "123".to_string());

        let request_parts = RequestParts {
            method: "POST".to_string(),
            authority: "api.example.com".to_string(),
            path: "/payment".to_string(),
            headers,
        };

        let input = SignatureInput {
            label: "sig1".to_string(),
            covered_components: vec![
                "@authority".to_string(),
                "@path".to_string(),
                "content-type".to_string(),
            ],
            params: SignatureParams {
                label: "sig1".to_string(),
                created: Some(1234567890),
                expires: None,
                nonce: Some("xyz".to_string()),
                keyid: "key1".to_string(),
                alg: SignatureAlgorithm::Ed25519,
                tag: None,
            },
        };

        let base = build_signature_base(&request_parts, &input).unwrap();

        assert!(base.contains("\"@authority\": api.example.com"));
        assert!(base.contains("\"@path\": /payment"));
        assert!(base.contains("\"content-type\": application/json"));
        assert!(base.contains("\"@signature-params\""));
        assert!(base.contains("created=1234567890"));
        assert!(base.contains("nonce=\"xyz\""));
        assert!(base.contains("keyid=\"key1\""));
        assert!(base.contains("alg=\"ed25519\""));
    }

    #[test]
    fn test_round_trip_sign_verify() {
        // Generate keypair
        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
        let private_key = keypair.to_bytes();
        let public_key = keypair.public_key().to_bytes();

        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        let request_parts = RequestParts {
            method: "POST".to_string(),
            authority: "api.example.com".to_string(),
            path: "/test".to_string(),
            headers,
        };

        let input = SignatureInput {
            label: "sig1".to_string(),
            covered_components: vec![
                "@method".to_string(),
                "@authority".to_string(),
                "content-type".to_string(),
            ],
            params: SignatureParams {
                label: "sig1".to_string(),
                created: Some(1234567890),
                expires: None,
                nonce: Some("test-nonce".to_string()),
                keyid: "test-key".to_string(),
                alg: SignatureAlgorithm::Ed25519,
                tag: None,
            },
        };

        // Sign
        let signature_bytes = create_http_signature(
            &request_parts,
            &input,
            &private_key,
            &SignatureAlgorithm::Ed25519,
        ).unwrap();

        // Verify
        let signed_headers = SignedHeaders {
            signature_input_raw: "test".to_string(),
            signature_bytes,
            parsed: input,
        };

        let result = verify_http_signature(
            &request_parts,
            &signed_headers,
            &public_key,
            &SignatureAlgorithm::Ed25519,
        );

        assert!(result.is_ok());
    }

    #[test]
    fn test_verify_with_wrong_key_fails() {
        // Generate two different keypairs
        let keypair1 = KeyPair::generate(KeyType::Ed25519).unwrap();
        let keypair2 = KeyPair::generate(KeyType::Ed25519).unwrap();

        let private_key1 = keypair1.to_bytes();
        let public_key2 = keypair2.public_key().to_bytes();

        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());

        let request_parts = RequestParts {
            method: "POST".to_string(),
            authority: "api.example.com".to_string(),
            path: "/test".to_string(),
            headers,
        };

        let input = SignatureInput {
            label: "sig1".to_string(),
            covered_components: vec!["@method".to_string()],
            params: SignatureParams {
                label: "sig1".to_string(),
                created: None,
                expires: None,
                nonce: None,
                keyid: "test-key".to_string(),
                alg: SignatureAlgorithm::Ed25519,
                tag: None,
            },
        };

        // Sign with keypair1
        let signature_bytes = create_http_signature(
            &request_parts,
            &input,
            &private_key1,
            &SignatureAlgorithm::Ed25519,
        ).unwrap();

        // Try to verify with public_key2
        let signed_headers = SignedHeaders {
            signature_input_raw: "test".to_string(),
            signature_bytes,
            parsed: input,
        };

        let result = verify_http_signature(
            &request_parts,
            &signed_headers,
            &public_key2,
            &SignatureAlgorithm::Ed25519,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_reject_malformed_input() {
        // Missing '='
        let header = "sig1";
        assert!(parse_signature_input(header).is_err());

        // Missing parentheses
        let header = r#"sig1=keyid="key1";alg="ed25519""#;
        assert!(parse_signature_input(header).is_err());

        // Unmatched parentheses
        let header = r#"sig1=("@authority";keyid="key1";alg="ed25519""#;
        assert!(parse_signature_input(header).is_err());
    }

    #[test]
    fn test_signature_algorithm_display() {
        assert_eq!(SignatureAlgorithm::Ed25519.to_string(), "ed25519");
        assert_eq!(SignatureAlgorithm::RsaPssSha256.to_string(), "rsa-pss-sha256");
    }

    #[test]
    fn test_signature_algorithm_from_str() {
        assert_eq!(SignatureAlgorithm::from_str("ed25519").unwrap(), SignatureAlgorithm::Ed25519);
        assert_eq!(SignatureAlgorithm::from_str("ED25519").unwrap(), SignatureAlgorithm::Ed25519);
        assert_eq!(SignatureAlgorithm::from_str("rsa-pss-sha256").unwrap(), SignatureAlgorithm::RsaPssSha256);
        assert!(SignatureAlgorithm::from_str("unknown").is_err());
    }

    #[test]
    fn test_build_signature_base_missing_header() {
        let request_parts = RequestParts {
            method: "POST".to_string(),
            authority: "api.example.com".to_string(),
            path: "/test".to_string(),
            headers: HashMap::new(),
        };

        let input = SignatureInput {
            label: "sig1".to_string(),
            covered_components: vec!["missing-header".to_string()],
            params: SignatureParams {
                label: "sig1".to_string(),
                created: None,
                expires: None,
                nonce: None,
                keyid: "key1".to_string(),
                alg: SignatureAlgorithm::Ed25519,
                tag: None,
            },
        };

        let result = build_signature_base(&request_parts, &input);
        assert!(result.is_err());
    }
}
