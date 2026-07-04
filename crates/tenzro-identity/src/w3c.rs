//! W3C DID Document conversion functions
//!
//! Converts between internal `TenzroIdentity` representations and
//! W3C DID Documents for interoperability with external systems.

use crate::document::{DidDocument, DidService, VerificationMethod, VerificationPurpose};
use crate::identity::{KeyPurpose, TenzroIdentity};

/// Converts a `TenzroIdentity` to a W3C DID Document
pub fn identity_to_did_document(identity: &TenzroIdentity) -> DidDocument {
    let did_string = identity.did_string();
    let mut doc = DidDocument::new(&did_string);

    // Set controller for machine identities
    if let Some(controller) = identity.controller_did() {
        doc = doc.with_controller(controller);
    }

    // Add verification methods from public keys
    for key_info in &identity.public_keys {
        let method_type = match key_info.key_type.as_str() {
            "Ed25519" => "Ed25519VerificationKey2020",
            "Secp256k1" => "EcdsaSecp256k1VerificationKey2019",
            "X25519" => "X25519KeyAgreementKey2020",
            other => other,
        };

        let purposes: Vec<VerificationPurpose> = key_info
            .purposes
            .iter()
            .filter_map(|p| match p {
                KeyPurpose::Authentication => Some(VerificationPurpose::Authentication),
                KeyPurpose::AssertionMethod => Some(VerificationPurpose::AssertionMethod),
                KeyPurpose::KeyAgreement => Some(VerificationPurpose::KeyAgreement),
                _ => None,
            })
            .collect();

        let method = VerificationMethod {
            id: format!("{}#{}", did_string, key_info.key_id),
            controller: did_string.clone(),
            method_type: method_type.to_string(),
            public_key_multibase: Some(format!("z{}", bs58::encode(&key_info.public_key).into_string())),
            public_key_jwk: None,
            purposes,
        };

        doc.add_verification_method(method);
    }

    // Add the post-quantum ML-DSA-65 verification method. Under the hybrid
    // migration, every TenzroIdentity carries an ML-DSA-65 verifying key
    // alongside its classical key, so the DID Document exports both. The
    // method type follows the draft "MlDsa65VerificationKey2026" suite name.
    if !identity.pq_verifying_key.is_empty() {
        let pq_method = VerificationMethod {
            id: format!("{}#pq-key-1", did_string),
            controller: did_string.clone(),
            method_type: "MlDsa65VerificationKey2026".to_string(),
            public_key_multibase: Some(format!(
                "z{}",
                bs58::encode(&identity.pq_verifying_key).into_string()
            )),
            public_key_jwk: None,
            purposes: vec![
                VerificationPurpose::Authentication,
                VerificationPurpose::AssertionMethod,
            ],
        };
        doc.add_verification_method(pq_method);
    }

    // Add service endpoints
    for svc in &identity.services {
        doc.add_service(DidService {
            id: format!("{}#{}", did_string, svc.id),
            service_type: svc.service_type.clone(),
            service_endpoint: svc.service_endpoint.clone(),
        });
    }

    doc
}

/// Attempts to extract basic identity information from a W3C DID Document
///
/// This performs a best-effort import; not all DID Document fields map
/// to TenzroIdentity fields.
pub fn extract_public_keys_from_document(
    doc: &DidDocument,
) -> Vec<(String, String, Vec<u8>)> {
    doc.verification_method
        .iter()
        .filter_map(|method| {
            let key_type = match method.method_type.as_str() {
                "Ed25519VerificationKey2020" => "Ed25519",
                "EcdsaSecp256k1VerificationKey2019" => "Secp256k1",
                "X25519KeyAgreementKey2020" => "X25519",
                other => other,
            };

            let public_key = method.public_key_multibase.as_ref().and_then(|mb| {
                mb.strip_prefix('z')
                    .and_then(|b58| bs58::decode(b58).into_vec().ok())
            })?;

            Some((
                method.id.clone(),
                key_type.to_string(),
                public_key,
            ))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::DelegationScope;
    use crate::did::TenzroDid;
    use crate::identity::*;
    use chrono::Utc;
    use std::collections::HashMap;
    use tenzro_types::identity::KycTier;
    use tenzro_types::primitives::Address;

    fn test_pq_vk() -> Vec<u8> {
        tenzro_crypto::pq::MlDsaSigningKey::generate()
            .verifying_key_bytes()
            .to_vec()
    }

    fn test_bls_vk() -> Vec<u8> {
        tenzro_crypto::bls::BlsKeyPair::generate()
            .unwrap()
            .public_key()
            .to_bytes()
            .to_vec()
    }

    fn make_test_identity() -> TenzroIdentity {
        TenzroIdentity {
            did: TenzroDid::parse("did:tenzro:human:test-id").unwrap(),
            public_keys: vec![
                PublicKeyInfo {
                    key_id: "key-1".to_string(),
                    key_type: "Ed25519".to_string(),
                    public_key: vec![1; 32],
                    purposes: vec![KeyPurpose::Authentication, KeyPurpose::AssertionMethod],
                },
                PublicKeyInfo {
                    key_id: "key-2".to_string(),
                    key_type: "X25519".to_string(),
                    public_key: vec![2; 32],
                    purposes: vec![KeyPurpose::KeyAgreement],
                },
            ],
            identity_data: IdentityData::Human {
                display_name: "Alice".to_string(),
                kyc_tier: KycTier::Enhanced,
                controlled_machines: Vec::new(),
            },
            status: IdentityStatus::Active,
            wallet_address: Address::new([0u8; 32]),
            wallet_id: "wallet-1".to_string(),
            pq_verifying_key: test_pq_vk(),
            bls_verifying_key: test_bls_vk(),
            credentials: Vec::new(),
            services: vec![ServiceEndpoint {
                id: "inference".to_string(),
                service_type: "InferenceEndpoint".to_string(),
                service_endpoint: "https://node.example.com/inference".to_string(),
            }],
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
            username: None,
        }
    }

    #[test]
    fn test_identity_to_did_document() {
        let identity = make_test_identity();
        let doc = identity_to_did_document(&identity);

        assert_eq!(doc.id, "did:tenzro:human:test-id");
        assert!(doc.controller.is_none());
        // 2 classical methods (Ed25519 + X25519) + 1 PQ method (ML-DSA-65)
        assert_eq!(doc.verification_method.len(), 3);
        // Ed25519 auth + ML-DSA-65 auth
        assert_eq!(doc.authentication.len(), 2);
        // Ed25519 assertion + ML-DSA-65 assertion
        assert_eq!(doc.assertion_method.len(), 2);
        assert_eq!(doc.key_agreement.len(), 1);
        assert_eq!(doc.service.len(), 1);

        // Confirm the PQ entry is present and correctly typed
        let pq_method = doc
            .verification_method
            .iter()
            .find(|m| m.method_type == "MlDsa65VerificationKey2026")
            .expect("missing ML-DSA-65 verification method");
        assert!(pq_method.id.ends_with("#pq-key-1"));
    }

    #[test]
    fn test_machine_identity_document_has_controller() {
        let identity = TenzroIdentity {
            did: TenzroDid::parse("did:tenzro:machine:ctrl:bot1").unwrap(),
            public_keys: vec![PublicKeyInfo {
                key_id: "key-1".to_string(),
                key_type: "Ed25519".to_string(),
                public_key: vec![1; 32],
                purposes: vec![KeyPurpose::Authentication],
            }],
            identity_data: IdentityData::Machine {
                capabilities: vec![],
                delegation_scope: DelegationScope::default(),
                controller_did: Some("did:tenzro:human:ctrl".to_string()),
                reputation: 0,
                tenzro_agent_id: None,
                erc8004_agent_id: None,
                is_seed_agent: false,
            },
            status: IdentityStatus::Active,
            wallet_address: Address::new([0u8; 32]),
            wallet_id: "wallet-2".to_string(),
            pq_verifying_key: test_pq_vk(),
            bls_verifying_key: test_bls_vk(),
            credentials: Vec::new(),
            services: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
            username: None,
        };

        let doc = identity_to_did_document(&identity);
        assert_eq!(
            doc.controller,
            Some("did:tenzro:human:ctrl".to_string())
        );
    }

    #[test]
    fn test_extract_public_keys() {
        let identity = make_test_identity();
        let doc = identity_to_did_document(&identity);
        let keys = extract_public_keys_from_document(&doc);

        // Ed25519 + X25519 + MlDsa65VerificationKey2026 (passed through unmapped)
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].1, "Ed25519");
        assert_eq!(keys[0].2, vec![1; 32]);
        assert_eq!(keys[1].1, "X25519");
        assert_eq!(keys[2].1, "MlDsa65VerificationKey2026");
    }

    #[test]
    fn test_roundtrip_serialization() {
        let identity = make_test_identity();
        let doc = identity_to_did_document(&identity);
        let json = serde_json::to_string(&doc).unwrap();
        let parsed: DidDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, doc.id);
        assert_eq!(parsed.verification_method.len(), doc.verification_method.len());
    }
}
