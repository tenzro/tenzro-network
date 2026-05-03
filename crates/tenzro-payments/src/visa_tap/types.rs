//! Visa TAP-specific types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::rfc9421::SignatureAlgorithm;

/// Agent Recognition data from RFC 9421 HTTP Message Signatures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecognition {
    /// Raw Signature-Input header value
    pub signature_input: String,
    /// Base64-encoded signature bytes
    pub signature: String,
    /// Key identifier from signature parameters
    pub key_id: String,
    /// Signature algorithm
    pub algorithm: SignatureAlgorithm,
    /// Signature creation timestamp
    pub created_at: DateTime<Utc>,
    /// Anti-replay nonce
    pub nonce: String,
}

/// Consumer Recognition via JWT ID Token
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsumerRecognition {
    /// OpenID Connect ID Token (JWT)
    pub id_token: String,
    /// Consumer's decentralized identifier
    pub consumer_did: Option<String>,
    /// Reference to delegation scope allowing agent to act on consumer's behalf
    pub delegation_scope_id: Option<String>,
}

/// Payment Container wrapping payment information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentContainer {
    /// Payment method details
    pub payment_method: PaymentMethod,
    /// Payment amount in smallest unit (e.g., wei, satoshis)
    pub amount: u128,
    /// Asset type (e.g., "TNZO", "USDC", "ETH")
    pub asset: String,
    /// Recipient address or identifier
    pub recipient: String,
    /// Blockchain or payment network identifier
    pub chain: String,
}

/// Payment method variants supported by Visa TAP
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PaymentMethod {
    /// Tenzro settlement with credential reference
    TenzroSettlement {
        /// Payment credential identifier
        credential_id: String,
    },
    /// Tokenized card payment
    CardToken {
        /// Hash of tokenized card data
        token_hash: String,
    },
    /// Direct stablecoin transfer
    StablecoinTransfer {
        /// Blockchain transaction hash
        tx_hash: String,
    },
}

/// Visa TAP-specific challenge structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VisaTapChallenge {
    /// Unique challenge identifier
    pub challenge_id: String,
    /// Protected resource URI
    pub resource: String,
    /// Required payment amount
    pub amount: u128,
    /// Payment asset type
    pub asset: String,
    /// Payment recipient
    pub recipient: String,
    /// HTTP headers that must be included in signature
    pub required_headers: Vec<String>,
    /// Maximum age of signature in seconds (default: 480 = 8 minutes)
    pub max_signature_age_secs: u64,
    /// Required domain for @authority component binding
    pub domain: String,
    /// Challenge expiration timestamp
    pub expires_at: DateTime<Utc>,
}

impl Default for VisaTapChallenge {
    fn default() -> Self {
        Self {
            challenge_id: String::new(),
            resource: String::new(),
            amount: 0,
            asset: "TNZO".to_string(),
            recipient: String::new(),
            required_headers: vec![
                "@authority".to_string(),
                "@path".to_string(),
                "content-type".to_string(),
            ],
            max_signature_age_secs: 480, // 8 minutes
            domain: String::new(),
            expires_at: Utc::now() + chrono::Duration::minutes(15),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_visa_tap_challenge_default() {
        let challenge = VisaTapChallenge::default();
        assert_eq!(challenge.max_signature_age_secs, 480);
        assert_eq!(challenge.required_headers.len(), 3);
        assert!(challenge.required_headers.contains(&"@authority".to_string()));
        assert!(challenge.required_headers.contains(&"@path".to_string()));
        assert!(challenge.required_headers.contains(&"content-type".to_string()));
    }

    #[test]
    fn test_payment_method_serialization() {
        let method = PaymentMethod::TenzroSettlement {
            credential_id: "cred_123".to_string(),
        };
        let json = serde_json::to_string(&method).unwrap();
        assert!(json.contains("tenzro_settlement"));
        assert!(json.contains("cred_123"));
    }

    #[test]
    fn test_payment_container_creation() {
        let container = PaymentContainer {
            payment_method: PaymentMethod::StablecoinTransfer {
                tx_hash: "0xabc".to_string(),
            },
            amount: 1000000,
            asset: "USDC".to_string(),
            recipient: "0x123".to_string(),
            chain: "ethereum".to_string(),
        };
        assert_eq!(container.amount, 1000000);
        assert_eq!(container.asset, "USDC");
    }

    #[test]
    fn test_agent_recognition_structure() {
        let recognition = AgentRecognition {
            signature_input: "sig1=(...)".to_string(),
            signature: "base64data".to_string(),
            key_id: "agent-key-1".to_string(),
            algorithm: SignatureAlgorithm::Ed25519,
            created_at: Utc::now(),
            nonce: "nonce123".to_string(),
        };
        assert_eq!(recognition.key_id, "agent-key-1");
        assert!(matches!(recognition.algorithm, SignatureAlgorithm::Ed25519));
    }

    #[test]
    fn test_consumer_recognition_with_did() {
        let recognition = ConsumerRecognition {
            id_token: "jwt.token.here".to_string(),
            consumer_did: Some("did:tenzro:human:abc123".to_string()),
            delegation_scope_id: Some("scope-456".to_string()),
        };
        assert!(recognition.consumer_did.is_some());
        assert!(recognition.delegation_scope_id.is_some());
    }
}
