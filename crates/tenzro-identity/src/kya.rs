//! Know Your Agent (KYA): DID-anchored federation primitives.
//!
//! Card networks and other registries run closed know-your-agent
//! directories, each discovered per issuer at
//! `/.well-known/http-message-signatures-directory`, with RFC 9421 over hosted
//! keys and no shared resolver or chain anchor.
//!
//! Tenzro adds the missing pieces:
//!
//! - `did:tenzro:machine:*`, a DID for any agent
//! - ERC-8004 Identity precompile `0x101a`, an on-chain registry mirror,
//!   written through on machine registration via [`OnChainAgentRegistry`].
//! - RFC 9421 agent signatures in the Web Bot Auth profile, whose key
//!   directory every node derives from the agent's terms in consensus state.
//!
//! This module exposes the federation surface:
//!
//! Service-type constants: canonical strings for the W3C DID Document
//!    `service[].type` field, so a DID Document can carry pointers into
//!    external registries and the agent's settlement endpoints on other
//!    rails from one place.
//!
//! # Example
//!
//! Add a registry pointer to a machine identity: an `IdentityServices`
//! transaction, approved by the machine's identity key, publishes it in the
//! DID's document from consensus state:
//!
//! ```text
//! tenzro identity service --did did:tenzro:machine:abc --id mastercard-kya \
//!     --service-type MastercardKYA --endpoint https://registry.example/agents/abc
//! ```
//!
//! The agent's DID Document then carries the pointer, and the same agent
//! identity is portable between that registry and Tenzro's open one.

/// Canonical W3C DID Document `service[].type` value advertising a Mastercard
/// KYA federation pointer.
pub const SERVICE_TYPE_MASTERCARD_KYA: &str = "MastercardKYA";

/// Canonical W3C DID Document `service[].type` value advertising a Visa TAP
/// federation pointer.
pub const SERVICE_TYPE_VISA_TAP: &str = "VisaTAP";

/// Canonical W3C DID Document `service[].type` value advertising a Stripe
/// SharedPaymentToken (SPT) federation pointer. The endpoint resolves to the
/// Stripe Issuing account that issues `SharedPaymentIssuedToken` /
/// `SharedPaymentGrantedToken` resources for the agent.
pub const SERVICE_TYPE_STRIPE_SPT: &str = "StripeSPT";

/// Canonical W3C DID Document `service[].type` value advertising a Tempo L1
/// account pointer. The endpoint resolves to the agent's Tempo address (the
/// EIP-55 checksummed Secp256k1-derived address used for TIP-20 settlement).
pub const SERVICE_TYPE_TEMPO_ACCOUNT: &str = "TempoAccount";

/// Returns true if `service_type` is a recognized KYA federation service type.
pub fn is_kya_service_type(service_type: &str) -> bool {
    matches!(
        service_type,
        SERVICE_TYPE_MASTERCARD_KYA
            | SERVICE_TYPE_VISA_TAP
            | SERVICE_TYPE_STRIPE_SPT
            | SERVICE_TYPE_TEMPO_ACCOUNT
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_kya_service_type_constants() {
        assert_eq!(SERVICE_TYPE_MASTERCARD_KYA, "MastercardKYA");
        assert_eq!(SERVICE_TYPE_VISA_TAP, "VisaTAP");
        assert_eq!(SERVICE_TYPE_STRIPE_SPT, "StripeSPT");
        assert_eq!(SERVICE_TYPE_TEMPO_ACCOUNT, "TempoAccount");
        assert!(is_kya_service_type(SERVICE_TYPE_MASTERCARD_KYA));
        assert!(is_kya_service_type(SERVICE_TYPE_VISA_TAP));
        assert!(is_kya_service_type(SERVICE_TYPE_STRIPE_SPT));
        assert!(is_kya_service_type(SERVICE_TYPE_TEMPO_ACCOUNT));
        assert!(!is_kya_service_type("InferenceEndpoint"));
        assert!(!is_kya_service_type(""));
    }

    #[test]
    fn test_did_document_can_carry_kya_service_type() {
        // Ensure the constants work as DidDocument service-type strings
        // — i.e. they make a valid service entry of a DID's document.
        let svc = tenzro_types::did_services::DidServiceEntry {
            id: "mastercard-kya".to_string(),
            service_type: SERVICE_TYPE_MASTERCARD_KYA.to_string(),
            endpoint: "https://kya.mastercard.com/agents/abc".to_string(),
        };
        assert!(svc.check().is_ok());
        let json = serde_json::to_string(&svc).unwrap();
        assert!(json.contains("MastercardKYA"));
        assert!(json.contains("kya.mastercard.com"));
    }
}
