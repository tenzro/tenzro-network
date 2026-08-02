//! W3C DID Document types
//!
//! Defines the DID Document structure following the W3C DID Core specification,
//! used as the external representation format for Tenzro identities.

use serde::{Deserialize, Serialize};

/// A W3C DID Document
///
/// See: <https://www.w3.org/TR/did-core/>
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    /// JSON-LD context
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    /// The DID subject
    pub id: String,
    /// Optional controller DID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<String>,
    /// Verification methods (public keys)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_method: Vec<VerificationMethod>,
    /// Authentication verification relationships
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<String>,
    /// Assertion method verification relationships
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_method: Vec<String>,
    /// Key agreement verification relationships
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_agreement: Vec<String>,
    /// Service endpoints
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<DidService>,
}

impl DidDocument {
    /// Creates a new DID Document with default Tenzro context
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            context: vec![
                "https://www.w3.org/ns/did/v1".to_string(),
                "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
                "https://ns.tenzro.xyz/v1".to_string(),
            ],
            id: id.into(),
            controller: None,
            verification_method: Vec::new(),
            authentication: Vec::new(),
            assertion_method: Vec::new(),
            key_agreement: Vec::new(),
            service: Vec::new(),
        }
    }

    /// Sets the controller
    pub fn with_controller(mut self, controller: impl Into<String>) -> Self {
        self.controller = Some(controller.into());
        self
    }

    /// Adds a verification method
    pub fn add_verification_method(&mut self, method: VerificationMethod) {
        let method_id = method.id.clone();
        for purpose in &method.purposes {
            match purpose {
                VerificationPurpose::Authentication => {
                    self.authentication.push(method_id.clone());
                }
                VerificationPurpose::AssertionMethod => {
                    self.assertion_method.push(method_id.clone());
                }
                VerificationPurpose::KeyAgreement => {
                    self.key_agreement.push(method_id.clone());
                }
            }
        }
        self.verification_method.push(method);
    }

    /// Adds a service endpoint
    pub fn add_service(&mut self, service: DidService) {
        self.service.push(service);
    }
}

/// A verification method in a DID Document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// Verification method ID (e.g., "did:tenzro:human:abc#key-1")
    pub id: String,
    /// The DID this method belongs to
    pub controller: String,
    /// Method type (e.g., "Ed25519VerificationKey2020")
    #[serde(rename = "type")]
    pub method_type: String,
    /// Public key in multibase encoding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_multibase: Option<String>,
    /// Public key in JWK format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_jwk: Option<serde_json::Value>,
    /// Purposes this key serves (not part of W3C spec, used internally)
    #[serde(skip)]
    pub purposes: Vec<VerificationPurpose>,
}

/// Purpose of a verification method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationPurpose {
    /// Used for authentication
    Authentication,
    /// Used for making assertions (signing credentials)
    AssertionMethod,
    /// Used for key agreement (encryption)
    KeyAgreement,
}

/// A service endpoint in a DID Document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidService {
    /// Service ID
    pub id: String,
    /// Service type
    #[serde(rename = "type")]
    pub service_type: String,
    /// Service endpoint URL
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_did_document() {
        let doc = DidDocument::new("did:tenzro:human:alice-uuid");
        assert_eq!(doc.id, "did:tenzro:human:alice-uuid");
        assert!(
            doc.context
                .contains(&"https://www.w3.org/ns/did/v1".to_string())
        );
        assert!(doc.controller.is_none());
    }

    #[test]
    fn test_did_document_with_controller() {
        let doc = DidDocument::new("did:tenzro:machine:ctrl:bot1")
            .with_controller("did:tenzro:human:ctrl");
        assert_eq!(doc.controller, Some("did:tenzro:human:ctrl".to_string()));
    }

    #[test]
    fn test_add_verification_method() {
        let mut doc = DidDocument::new("did:tenzro:human:alice");

        let method = VerificationMethod {
            id: "did:tenzro:human:alice#key-1".to_string(),
            controller: "did:tenzro:human:alice".to_string(),
            method_type: "Ed25519VerificationKey2020".to_string(),
            public_key_multibase: Some("z6Mk...".to_string()),
            public_key_jwk: None,
            purposes: vec![
                VerificationPurpose::Authentication,
                VerificationPurpose::AssertionMethod,
            ],
        };

        doc.add_verification_method(method);

        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.authentication.len(), 1);
        assert_eq!(doc.assertion_method.len(), 1);
        assert_eq!(doc.key_agreement.len(), 0);
    }

    #[test]
    fn test_add_service() {
        let mut doc = DidDocument::new("did:tenzro:human:alice");

        doc.add_service(DidService {
            id: "did:tenzro:human:alice#inference".to_string(),
            service_type: "InferenceEndpoint".to_string(),
            service_endpoint: "https://node.tenzro.com/inference".to_string(),
        });

        assert_eq!(doc.service.len(), 1);
        assert_eq!(doc.service[0].service_type, "InferenceEndpoint");
    }

    #[test]
    fn test_serialize_did_document() {
        let doc = DidDocument::new("did:tenzro:human:alice");
        let json = serde_json::to_string_pretty(&doc).unwrap();
        assert!(json.contains("@context"));
        assert!(json.contains("did:tenzro:human:alice"));
    }

    #[test]
    fn test_w3c_did_document_json_ld_compliance() {
        let mut doc = DidDocument::new("did:tenzro:human:alice-uuid");

        // Add a verification method
        doc.add_verification_method(VerificationMethod {
            id: "did:tenzro:human:alice-uuid#key-1".to_string(),
            controller: "did:tenzro:human:alice-uuid".to_string(),
            method_type: "Ed25519VerificationKey2020".to_string(),
            public_key_multibase: Some(
                "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK".to_string(),
            ),
            public_key_jwk: None,
            purposes: vec![VerificationPurpose::Authentication],
        });

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&doc).unwrap();

        // Verify W3C required fields are present
        assert!(json.contains("@context"), "Missing @context field");
        assert!(
            json.contains("https://www.w3.org/ns/did/v1"),
            "Missing W3C DID context"
        );
        assert!(json.contains("\"id\""), "Missing id field");
        assert!(
            json.contains("verificationMethod"),
            "Missing verificationMethod"
        );
        assert!(
            json.contains("authentication"),
            "Missing authentication relationship"
        );

        // Deserialize and verify
        let parsed: DidDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "did:tenzro:human:alice-uuid");
        assert_eq!(parsed.context.len(), 3);
        assert_eq!(parsed.verification_method.len(), 1);
        assert_eq!(parsed.authentication.len(), 1);
    }

    #[test]
    fn test_did_document_roundtrip_with_all_fields() {
        let mut doc = DidDocument::new("did:tenzro:machine:ctrl:bot")
            .with_controller("did:tenzro:human:ctrl");

        doc.add_verification_method(VerificationMethod {
            id: "did:tenzro:machine:ctrl:bot#key-1".to_string(),
            controller: "did:tenzro:machine:ctrl:bot".to_string(),
            method_type: "Ed25519VerificationKey2020".to_string(),
            public_key_multibase: Some("z6Mk...".to_string()),
            public_key_jwk: None,
            purposes: vec![
                VerificationPurpose::Authentication,
                VerificationPurpose::AssertionMethod,
                VerificationPurpose::KeyAgreement,
            ],
        });

        doc.add_service(DidService {
            id: "did:tenzro:machine:ctrl:bot#inference".to_string(),
            service_type: "InferenceEndpoint".to_string(),
            service_endpoint: "https://node.example.com/inference".to_string(),
        });

        // Serialize
        let json = serde_json::to_string(&doc).unwrap();

        // Deserialize
        let parsed: DidDocument = serde_json::from_str(&json).unwrap();

        // Verify all fields match
        assert_eq!(parsed.id, doc.id);
        assert_eq!(parsed.controller, doc.controller);
        assert_eq!(parsed.verification_method.len(), 1);
        assert_eq!(parsed.authentication.len(), 1);
        assert_eq!(parsed.assertion_method.len(), 1);
        assert_eq!(parsed.key_agreement.len(), 1);
        assert_eq!(parsed.service.len(), 1);
    }
}
