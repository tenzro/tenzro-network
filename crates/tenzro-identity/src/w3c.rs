//! W3C DID Document conversion functions
//!
//! Converts between internal `TenzroIdentity` representations and
//! W3C DID Documents for interoperability with external systems.

use crate::document::{
    DidDocument, ML_DSA_65_METHOD_TYPE, VerificationMethod, VerificationPurpose,
};
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
            "P-256" => "EcdsaSecp256r1VerificationKey2019",
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
            public_key_multibase: Some(format!(
                "z{}",
                bs58::encode(&key_info.public_key).into_string()
            )),
            public_key_jwk: None,
            purposes,
        };

        doc.add_verification_method(method);
    }

    // The ML-DSA-65 verification method, when the identity has its key. The
    // document lists it ahead of the classical methods, in
    // `verificationMethod` and in the authentication and assertion
    // relationships, so a verifier takes the post-quantum method first.
    if !identity.pq_verifying_key.is_empty() {
        doc.add_verification_method(VerificationMethod::ml_dsa_65(
            format!("{}#pq-key-1", did_string),
            did_string.clone(),
            &identity.pq_verifying_key,
            vec![
                VerificationPurpose::Authentication,
                VerificationPurpose::AssertionMethod,
            ],
        ));
    }

    doc
}

/// Attempts to extract basic identity information from a W3C DID Document
///
/// This performs a best-effort import; not all DID Document fields map
/// to TenzroIdentity fields.
pub fn extract_public_keys_from_document(doc: &DidDocument) -> Vec<(String, String, Vec<u8>)> {
    doc.verification_method
        .iter()
        .filter_map(|method| {
            let key_type = match method.method_type.as_str() {
                "Ed25519VerificationKey2020" => "Ed25519",
                "EcdsaSecp256k1VerificationKey2019" => "Secp256k1",
                "EcdsaSecp256r1VerificationKey2019" => "P-256",
                "X25519KeyAgreementKey2020" => "X25519",
                ML_DSA_65_METHOD_TYPE => "ML-DSA-65",
                other => other,
            };

            let public_key = method.public_key_multibase.as_ref().and_then(|mb| {
                mb.strip_prefix('z')
                    .and_then(|b58| bs58::decode(b58).into_vec().ok())
            })?;

            Some((method.id.clone(), key_type.to_string(), public_key))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::TenzroDid;
    use crate::identity::*;
    use chrono::Utc;
    use std::collections::HashMap;
    use tenzro_types::primitives::Address;

    fn test_pq_vk() -> Vec<u8> {
        tenzro_crypto::pq::MlDsaSigningKey::generate()
            .verifying_key_bytes()
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
                controlled_machines: Vec::new(),
            },
            status: IdentityStatus::Active,
            wallet_address: Address::new([0u8; 32]),
            wallet_id: "wallet-1".to_string(),
            pq_verifying_key: test_pq_vk(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
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
        // The ML-DSA-65 method comes first, and is the one authentication
        // takes.
        assert_eq!(
            doc.verification_method[0].method_type,
            "MlDsa65VerificationKey2026"
        );
        assert!(doc.authentication[0].ends_with("#pq-key-1"));
        assert!(
            doc.preferred_authentication_method()
                .unwrap()
                .is_post_quantum()
        );
        let extracted = extract_public_keys_from_document(&doc);
        assert_eq!(extracted[0].1, "ML-DSA-65");
        assert_eq!(extracted[0].2, identity.pq_verifying_key);
        // Ed25519 auth + ML-DSA-65 auth
        assert_eq!(doc.authentication.len(), 2);
        // Ed25519 assertion + ML-DSA-65 assertion
        assert_eq!(doc.assertion_method.len(), 2);
        assert_eq!(doc.key_agreement.len(), 1);
        assert!(
            doc.service.is_empty(),
            "service entries come from consensus state, not the identity"
        );

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
                controller_did: Some("did:tenzro:human:ctrl".to_string()),
                reputation: 0,
                tenzro_agent_id: None,
                erc8004_agent_id: None,
            },
            status: IdentityStatus::Active,
            wallet_address: Address::new([0u8; 32]),
            wallet_id: "wallet-2".to_string(),
            pq_verifying_key: test_pq_vk(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
        };

        let doc = identity_to_did_document(&identity);
        assert_eq!(doc.controller, Some("did:tenzro:human:ctrl".to_string()));
    }

    #[test]
    fn test_extract_public_keys() {
        let identity = make_test_identity();
        let doc = identity_to_did_document(&identity);
        let keys = extract_public_keys_from_document(&doc);

        // ML-DSA-65 first, then Ed25519 and X25519
        assert_eq!(keys.len(), 3);
        assert_eq!(keys[0].1, "ML-DSA-65");
        assert_eq!(keys[1].1, "Ed25519");
        assert_eq!(keys[1].2, vec![1; 32]);
        assert_eq!(keys[2].1, "X25519");
    }

    #[test]
    fn test_roundtrip_serialization() {
        let identity = make_test_identity();
        let doc = identity_to_did_document(&identity);
        let json = serde_json::to_string(&doc).unwrap();
        let parsed: DidDocument = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, doc.id);
        assert_eq!(
            parsed.verification_method.len(),
            doc.verification_method.len()
        );
    }
}
