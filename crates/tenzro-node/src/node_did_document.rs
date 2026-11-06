//! The node's self-published DID Document — one entry point to every way of
//! reaching it.
//!
//! A node is addressed by five different identifiers, and until now a caller
//! holding one had no documented path to the others:
//!
//! | Identifier | What it is | Derives from |
//! |---|---|---|
//! | TDIP DID | `did:tenzro:machine:<device-key-id>` — the on-chain identity | provisioned identity |
//! | Ed25519 public key | the node's signing key | its keystore |
//! | iroh `EndpointId` | QUIC/NAT-traversing transport identity | **byte-identical** to the Ed25519 key |
//! | Relays | where the iroh endpoint is reachable, by relay URL | the signed endpoint record |
//!
//! Resolving the DID yields all of them plus any RPC/MCP URL the operator
//! published for their own edge, so DID resolution is the single entry point rather than one of five
//! things a caller has to already know.
//!
//! # How a resolver knows the document is the node's
//!
//! The published document carries a Data Integrity proof
//! ([`crate::data_integrity`], `ecdsa-jcs-2019`) by the machine's identity
//! key, the P-256 key in its TPM or Secure Enclave that its machine DID and
//! its endpoint records derive from, listed in the document as
//! `#hardware-key`. A relay or cache that edits any field breaks the proof,
//! and [`verify_node_did_document`] also checks that the DID derives from the
//! key that signed. A machine with no TPM or Secure Enclave has no machine
//! identity and publishes no document.
//!
//! The document lists the node's ML-DSA-65 key as `#pq-key-1`, ahead of the
//! classical methods in `verificationMethod` and in the authentication and
//! assertion relationships, so a verifier takes the post-quantum method
//! first. The proof covers that entry like every other field.
//!
//! # What it deliberately omits
//!
//! Bind addresses that are not routable. A document advertising
//! `0.0.0.0:8545` tells a caller nothing and costs them a timeout, so an
//! endpoint is published only when the operator configured an external
//! address or the bind address is actually dialable.

use serde_json::Value;
use tenzro_device_key::HardwareSigner;
use tenzro_identity::document::{DidDocument, DidService, VerificationMethod, VerificationPurpose};

use crate::data_integrity;

/// Fragment of the verification method naming that key.
const HARDWARE_KEY_FRAGMENT: &str = "#hardware-key";

/// Service type for the JSON-RPC surface.
pub const SERVICE_TYPE_RPC: &str = "TenzroJsonRpc";
/// Service type for the Model Context Protocol surface.
pub const SERVICE_TYPE_MCP: &str = "TenzroMcp";
/// Service type for the iroh QUIC endpoint.
pub const SERVICE_TYPE_IROH: &str = "TenzroIrohEndpoint";
/// Service type for a relay this node is reachable through.
pub const SERVICE_TYPE_RELAY: &str = "TenzroRelay";

/// Everything a node knows about how to reach itself.
///
/// Assembled by the node from its live state; `None` for anything it does not
/// have, so a document never advertises a surface that is not running.
#[derive(Debug, Clone, Default)]
pub struct NodeAddressing {
    /// The node's TDIP DID. Without one there is nothing to publish.
    pub did: Option<String>,
    /// Ed25519 public key, lowercase hex. Also the iroh `EndpointId`.
    pub ed25519_public_key_hex: Option<String>,
    /// The node's ML-DSA-65 verifying key. Listed as the document's preferred
    /// verification method.
    pub ml_dsa_65_public_key: Option<Vec<u8>>,
    /// iroh `EndpointId`, as the transport renders it.
    pub iroh_endpoint_id: Option<String>,
    /// ALPNs registered on that endpoint.
    pub iroh_alpns: Vec<String>,
    /// URLs of the relays this node is reachable through.
    pub relays: Vec<String>,
    /// JSON-RPC URL the operator published for their own edge, if any.
    pub rpc_url: Option<String>,
    /// MCP URL the operator published for their own edge, if any.
    pub mcp_url: Option<String>,
}

/// Build the node's DID Document.
///
/// Returns `None` when the node has no DID — a node that has not been
/// provisioned has no identity to publish a document *for*, and inventing one
/// would produce a document nothing could resolve.
pub fn build_node_did_document(addressing: &NodeAddressing) -> Option<DidDocument> {
    let did = addressing.did.as_ref()?;
    let mut doc = DidDocument::new(did.clone());

    // Listed ahead of the classical method: a verifier takes the
    // post-quantum method first.
    if let Some(ml_dsa) = addressing.ml_dsa_65_public_key.as_ref() {
        doc.add_verification_method(VerificationMethod::ml_dsa_65(
            format!("{did}#pq-key-1"),
            did.clone(),
            ml_dsa,
            vec![
                VerificationPurpose::Authentication,
                VerificationPurpose::AssertionMethod,
            ],
        ));
    }

    if let Some(key_hex) = addressing.ed25519_public_key_hex.as_ref() {
        doc.add_verification_method(VerificationMethod {
            id: format!("{did}#node-key"),
            controller: did.clone(),
            method_type: "Ed25519VerificationKey2020".to_string(),
            // Multibase `z` + base58btc is what the Ed25519-2020 suite
            // expects; the hex form travels as the iroh service endpoint
            // below, where it is what a dialer actually needs.
            public_key_multibase: Some(format!("z{key_hex}")),
            public_key_jwk: None,
            // Authentication and assertion, not key agreement: this is a
            // signing key, and listing it for encryption would invite a
            // caller to use an Ed25519 key for X25519.
            purposes: vec![
                VerificationPurpose::Authentication,
                VerificationPurpose::AssertionMethod,
            ],
        });
    }

    // The transport identities first: these are what make the document worth
    // resolving, since a caller who has one of the service URLs already knows
    // how to reach the node.
    if let Some(endpoint) = addressing.iroh_endpoint_id.as_ref() {
        doc.add_service(DidService {
            id: format!("{did}#iroh"),
            service_type: SERVICE_TYPE_IROH.to_string(),
            // The ALPNs ride in the endpoint string so one service entry
            // answers both "where" and "what can I speak to it".
            service_endpoint: if addressing.iroh_alpns.is_empty() {
                format!("tenzro://node/{endpoint}")
            } else {
                format!(
                    "tenzro://node/{endpoint}?alpn={}",
                    addressing.iroh_alpns.join(",")
                )
            },
        });
    }

    for (i, relay) in addressing.relays.iter().enumerate() {
        doc.add_service(DidService {
            id: format!("{did}#relay-{i}"),
            service_type: SERVICE_TYPE_RELAY.to_string(),
            service_endpoint: relay.clone(),
        });
    }

    for (suffix, kind, url) in [
        ("rpc", SERVICE_TYPE_RPC, &addressing.rpc_url),
        ("mcp", SERVICE_TYPE_MCP, &addressing.mcp_url),
    ] {
        if let Some(url) = url.as_ref() {
            doc.add_service(DidService {
                id: format!("{did}#{suffix}"),
                service_type: kind.to_string(),
                service_endpoint: url.clone(),
            });
        }
    }

    Some(doc)
}

/// The node's DID Document as published: built from `addressing` and signed
/// by this machine's identity key, the one its machine DID and its endpoint
/// records derive from, when it has one.
pub fn publish(addressing: &NodeAddressing) -> Option<Value> {
    build_node_did_document(addressing)
        .map(|doc| sign_node_did_document(doc, crate::identity_bootstrap::machine_signer()))
}

/// Add `signer`'s key to `doc` as `#hardware-key` and sign the result.
///
/// The document is signed only when its DID derives from `signer`'s key.
/// Otherwise the proof would say no more than "somebody with a P-256 key
/// signed this", which any relay that re-signed a modified copy could also
/// say — the key is listed in the document it authenticates, so a verifier
/// with nothing tying it to the DID learns nothing. Without that binding the
/// document is returned unsigned, which is honest, rather than carrying a
/// proof that proves nothing.
pub fn sign_node_did_document(mut doc: DidDocument, signer: Option<&dyn HardwareSigner>) -> Value {
    let Some((signer, public_key)) =
        signer.and_then(|s| s.public_key_sec1().ok().map(|pk| (s, pk)))
    else {
        return serde_json::to_value(&doc).unwrap_or(Value::Null);
    };
    if !tenzro_types::did_derivation::did_derives_from_key(&doc.id, &public_key) {
        return serde_json::to_value(&doc).unwrap_or(Value::Null);
    }
    let method_id = format!("{}{HARDWARE_KEY_FRAGMENT}", doc.id);
    doc.add_verification_method(VerificationMethod {
        id: method_id.clone(),
        controller: doc.id.clone(),
        method_type: "JsonWebKey".to_string(),
        public_key_multibase: None,
        public_key_jwk: Some(data_integrity::p256_jwk(&public_key)),
        purposes: vec![VerificationPurpose::AssertionMethod],
    });
    let unsigned = serde_json::to_value(&doc).unwrap_or(Value::Null);
    let created = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    data_integrity::sign(
        unsigned.clone(),
        signer,
        &method_id,
        "assertionMethod",
        &created,
    )
    .unwrap_or(unsigned)
}

/// What a verified node document proves.
#[derive(Debug, PartialEq, Eq)]
pub struct VerifiedNodeDocument {
    /// The key that signed, uncompressed SEC1. The document's DID derives
    /// from it, so the document is self-certifying.
    pub signing_key: Vec<u8>,
}

/// Verify a published node DID Document's proof.
///
/// The signing key is the one the document lists under the proof's
/// verification method, and the document's DID must derive from that key.
/// Checking only the signature would accept any document a relay re-signed
/// with a key of its own, since the relay lists its own key in the copy it
/// serves; the derivation is what makes the proof about this DID.
pub fn verify_node_did_document(
    document: &Value,
) -> Result<VerifiedNodeDocument, data_integrity::ProofError> {
    use data_integrity::ProofError;
    let method_id = document
        .pointer("/proof/verificationMethod")
        .and_then(Value::as_str)
        .ok_or(ProofError::Missing)?;
    let did = document
        .get("id")
        .and_then(Value::as_str)
        .ok_or(ProofError::Malformed)?;
    if method_id != format!("{did}{HARDWARE_KEY_FRAGMENT}") {
        return Err(ProofError::Malformed);
    }
    let signing_key = document
        .get("verificationMethod")
        .and_then(Value::as_array)
        .and_then(|methods| {
            methods
                .iter()
                .find(|m| m.get("id").and_then(Value::as_str) == Some(method_id))
        })
        .and_then(|m| m.get("publicKeyJwk"))
        .and_then(data_integrity::p256_from_jwk)
        .ok_or(ProofError::Malformed)?;
    data_integrity::verify(document, &signing_key)?;
    if !tenzro_types::did_derivation::did_derives_from_key(did, &signing_key) {
        return Err(ProofError::NotTheSubjectsKey);
    }
    Ok(VerifiedNodeDocument {
        signing_key: signing_key.to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full() -> NodeAddressing {
        NodeAddressing {
            did: Some("did:tenzro:machine:abc".to_string()),
            ed25519_public_key_hex: Some("ab".repeat(32)),
            ml_dsa_65_public_key: None,
            iroh_endpoint_id: Some("endpoint123".to_string()),
            iroh_alpns: vec!["tenzro/a2a".to_string(), "tenzro/mcp".to_string()],
            relays: vec!["https://relay.example.com/".to_string()],
            rpc_url: Some("https://rpc.example.com".to_string()),
            mcp_url: Some("https://mcp.example.com/mcp".to_string()),
        }
    }

    fn service<'a>(doc: &'a DidDocument, kind: &str) -> Option<&'a DidService> {
        doc.service.iter().find(|s| s.service_type == kind)
    }

    /// The whole point: resolving the DID answers every addressing question at
    /// once, instead of being one of five things a caller must already know.
    #[test]
    fn one_document_carries_every_way_to_reach_the_node() {
        let doc = build_node_did_document(&full()).unwrap();
        for kind in [
            SERVICE_TYPE_IROH,
            SERVICE_TYPE_RELAY,
            SERVICE_TYPE_RPC,
            SERVICE_TYPE_MCP,
        ] {
            assert!(service(&doc, kind).is_some(), "{kind} missing");
        }
    }

    /// A node with no DID has no identity to publish a document *for*.
    /// Inventing one would produce something nothing could resolve.
    #[test]
    fn a_node_with_no_did_publishes_nothing() {
        assert!(build_node_did_document(&NodeAddressing::default()).is_none());
    }

    /// The Ed25519 key and the iroh EndpointId are the same key material, so a
    /// verified signature over this document is also a verification that the
    /// endpoint belongs to the DID.
    #[test]
    fn the_signing_key_is_published_for_authentication_and_assertion() {
        let doc = build_node_did_document(&full()).unwrap();
        assert_eq!(doc.verification_method.len(), 1);
        assert_eq!(doc.authentication, vec!["did:tenzro:machine:abc#node-key"]);
        assert_eq!(
            doc.assertion_method,
            vec!["did:tenzro:machine:abc#node-key"]
        );
        assert!(
            doc.key_agreement.is_empty(),
            "an Ed25519 signing key must not be advertised for key agreement"
        );
    }

    /// The node's ML-DSA-65 key is a verification method of its document,
    /// preferred for authentication over the classical ones, and the proof
    /// covers it.
    #[test]
    fn the_ml_dsa_key_is_the_preferred_method() {
        let signer = crate::data_integrity::tests::test_signer(9);
        let pq = tenzro_crypto::pq::MlDsaSigningKey::from_seed(&[5u8; 32]).unwrap();
        let addressing = NodeAddressing {
            ml_dsa_65_public_key: Some(pq.verifying_key_bytes().to_vec()),
            ..owned_addressing(&signer)
        };
        let doc = build_node_did_document(&addressing).unwrap();
        assert!(doc.has_post_quantum_method());
        let preferred = doc.preferred_authentication_method().unwrap();
        assert_eq!(preferred.id, format!("{}#pq-key-1", doc.id));
        assert!(preferred.is_post_quantum());
        assert_eq!(doc.verification_method[0].id, preferred.id);

        let signed = sign_node_did_document(doc, Some(&signer));
        verify_node_did_document(&signed).unwrap();
        let mut swapped = signed.clone();
        swapped["verificationMethod"][0]["publicKeyMultibase"] = "zattacker".into();
        assert!(verify_node_did_document(&swapped).is_err());
    }

    /// One service entry answers both "where" and "what can I speak to it",
    /// so a caller does not have to probe.
    #[test]
    fn the_iroh_entry_carries_its_alpns() {
        let doc = build_node_did_document(&full()).unwrap();
        assert_eq!(
            service(&doc, SERVICE_TYPE_IROH).unwrap().service_endpoint,
            "tenzro://node/endpoint123?alpn=tenzro/a2a,tenzro/mcp"
        );
    }

    #[test]
    fn an_endpoint_with_no_alpns_is_still_addressable() {
        let addressing = NodeAddressing {
            iroh_alpns: Vec::new(),
            ..full()
        };
        let doc = build_node_did_document(&addressing).unwrap();
        assert_eq!(
            service(&doc, SERVICE_TYPE_IROH).unwrap().service_endpoint,
            "tenzro://node/endpoint123"
        );
    }

    /// A node that runs no iroh endpoint and no mesh still publishes whatever
    /// it does have, rather than an empty document or none at all.
    #[test]
    fn a_partial_node_publishes_what_it_has() {
        let addressing = NodeAddressing {
            did: Some("did:tenzro:machine:abc".to_string()),
            rpc_url: Some("https://rpc.example.com".to_string()),
            ..NodeAddressing::default()
        };
        let doc = build_node_did_document(&addressing).unwrap();
        assert_eq!(doc.service.len(), 1);
        assert_eq!(doc.service[0].service_type, SERVICE_TYPE_RPC);
        assert!(doc.verification_method.is_empty());
    }

    /// A node whose DID derives from its own key: the proof is the DID's.
    fn owned_addressing(signer: &dyn HardwareSigner) -> NodeAddressing {
        let pk = signer.public_key_sec1().unwrap();
        let did = format!(
            "did:tenzro:machine:{}",
            tenzro_types::did_derivation::machine_device_id(&pk)
        );
        NodeAddressing {
            did: Some(did),
            ..full()
        }
    }

    #[test]
    fn a_published_document_is_signed_by_the_hardware_key() {
        let signer = crate::data_integrity::tests::test_signer(9);
        let doc = build_node_did_document(&owned_addressing(&signer)).unwrap();
        let signed = sign_node_did_document(doc, Some(&signer));
        let verified = verify_node_did_document(&signed).unwrap();
        assert_eq!(
            verified.signing_key,
            signer.public_key_sec1().unwrap().to_vec()
        );
        assert!(
            signed["assertionMethod"]
                .as_array()
                .unwrap()
                .iter()
                .any(|m| m.as_str().unwrap().ends_with("#hardware-key"))
        );
    }

    #[test]
    fn a_relay_that_rewrites_an_endpoint_is_caught() {
        let signer = crate::data_integrity::tests::test_signer(9);
        let mut signed = sign_node_did_document(
            build_node_did_document(&owned_addressing(&signer)).unwrap(),
            Some(&signer),
        );
        signed["service"][0]["serviceEndpoint"] = "tenzro://node/attacker".into();
        assert!(verify_node_did_document(&signed).is_err());
    }

    /// The point of the proof: a relay can re-sign a modified copy with its
    /// own key and list that key in the copy it serves, so a signature that is
    /// only checked against the document's own key proves nothing. The DID
    /// must derive from the key that signed.
    #[test]
    fn a_relay_that_swaps_in_its_own_key_is_refused() {
        let owner = crate::data_integrity::tests::test_signer(9);
        let addressing = owned_addressing(&owner);
        verify_node_did_document(&sign_node_did_document(
            build_node_did_document(&addressing).unwrap(),
            Some(&owner),
        ))
        .expect("the subject's own key certifies its document");

        // A relay re-signs the same document with a key of its own.
        let relay = crate::data_integrity::tests::test_signer(10);
        let mut doc = build_node_did_document(&addressing).unwrap();
        let relay_pk = relay.public_key_sec1().unwrap();
        let method_id = format!("{}{HARDWARE_KEY_FRAGMENT}", doc.id);
        doc.add_verification_method(VerificationMethod {
            id: method_id.clone(),
            controller: doc.id.clone(),
            method_type: "JsonWebKey".to_string(),
            public_key_multibase: None,
            public_key_jwk: Some(data_integrity::p256_jwk(&relay_pk)),
            purposes: vec![VerificationPurpose::AssertionMethod],
        });
        let unsigned = serde_json::to_value(&doc).unwrap();
        let created = "2026-01-01T00:00:00Z";
        let forged =
            data_integrity::sign(unsigned, &relay, &method_id, "assertionMethod", created).unwrap();
        assert_eq!(
            verify_node_did_document(&forged).unwrap_err(),
            data_integrity::ProofError::NotTheSubjectsKey,
            "a relay's own key must not certify someone else's DID"
        );
    }

    /// A DID that derives from no key cannot be certified at all, so the
    /// document goes out unsigned rather than carrying an empty promise.
    #[test]
    fn a_did_that_derives_from_nothing_is_published_unsigned() {
        let signer = crate::data_integrity::tests::test_signer(9);
        let signed =
            sign_node_did_document(build_node_did_document(&full()).unwrap(), Some(&signer));
        assert!(signed.get("proof").is_none());
        assert_eq!(
            verify_node_did_document(&signed).unwrap_err(),
            data_integrity::ProofError::Missing
        );
    }

    #[test]
    fn without_hardware_the_document_is_unsigned() {
        let v = sign_node_did_document(build_node_did_document(&full()).unwrap(), None);
        assert!(v.get("proof").is_none());
        assert!(verify_node_did_document(&v).is_err());
    }
}
