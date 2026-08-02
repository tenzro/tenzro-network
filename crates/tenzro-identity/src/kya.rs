//! Know Your Agent (KYA) — DID-anchored federation primitives.
//!
//! Mastercard and Visa each operate **closed** Know-Your-Agent directories
//! (Cloudflare/Visa/Mastercard joint write-up: *"Visa and Mastercard will be
//! hosting their own directories for Visa-registered and Mastercard-registered
//! agents, respectively"*). Discovery is per-issuer
//! `/.well-known/http-message-signatures-directory`; there is no cross-network
//! resolver and no on-chain anchor. Authentication is RFC 9421 over hosted JWKS
//! — no DIDs, no VCs, no chain anchor.
//!
//! Tenzro adds the missing pieces:
//!
//! - `did:tenzro:machine:*` — DID for any agent
//! - ERC-8004 Identity precompile `0x101a` — on-chain registry mirror, written
//!   through automatically on machine registration via [`OnChainAgentRegistry`].
//! - [`DelegationScope`] with `enforce_operation()` — programmatic spend limits
//! - RFC 9421 signing already aligned with Web Bot Auth
//!
//! This module exposes the federation surface:
//!
//! 1. [`KyaRecord`] — a structured projection of a TDIP machine identity into
//!    the three KYA axes (controller / authenticator / delegation_scope) so a
//!    Mastercard or Visa directory can ingest the record without re-encoding it.
//! 2. Service-type constants ([`SERVICE_TYPE_MASTERCARD_KYA`],
//!    [`SERVICE_TYPE_VISA_TAP`], [`SERVICE_TYPE_STRIPE_SPT`],
//!    [`SERVICE_TYPE_TEMPO_ACCOUNT`]) — canonical strings for the W3C DID
//!    Document `service[].type` field, so federated directories can advertise
//!    cross-registry pointers (Mastercard KYA / Visa TAP) and the agent's
//!    settlement endpoints (Stripe SPT issuer account / Tempo L1 address) can
//!    be discovered from a single DID Document. SPT is a token primitive (not
//!    a directory) and TempoAccount is a chain address (not authentication),
//!    but co-locating the constants keeps the DID-Document service-type
//!    registry in one place.
//!
//! # Example
//!
//! Add a Mastercard KYA service entry to a TDIP machine identity:
//!
//! ```text
//! POST /  { "method": "tenzro_addService",
//!           "params": { "did": "did:tenzro:machine:abc",
//!                       "type": "MastercardKYA",
//!                       "endpoint": "https://kya.mastercard.com/agents/abc" } }
//! ```
//!
//! The agent's DID Document then carries the federation pointer, and the same
//! agent identity is portable between Mastercard's closed registry and
//! Tenzro's open one.

use serde::{Deserialize, Serialize};

use crate::delegation::DelegationScope;
use crate::identity::{IdentityData, IdentityStatus, KeyPurpose, PublicKeyInfo, TenzroIdentity};

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

/// Authenticator binding — the public key the agent signs RFC 9421 requests
/// with, plus a flag indicating whether the key resides in TEE hardware.
///
/// Mastercard's KYA framework treats the authenticator binding as one of the
/// three axes a directory must verify before issuing agentic tokens. Tenzro
/// already records the agent's verification keys on the TDIP identity; this
/// is a typed projection so the directory ingest path doesn't have to walk
/// the full `TenzroIdentity` shape.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuthenticatorBinding {
    /// Key identifier (e.g., "key-1")
    pub key_id: String,
    /// Key type (e.g., "Ed25519", "Secp256k1")
    pub key_type: String,
    /// The public key bytes
    pub public_key: Vec<u8>,
    /// True if the underlying signing key is bound to TEE hardware.
    ///
    /// Currently derived from `is_seed_agent` as a coarse proxy
    /// (seed agents always run inside the operator-attested TEE pool).
    /// A future revision introduces a dedicated `tee_provider` field on
    /// `IdentityData::Machine` and sources this flag directly.
    pub tee_attested: bool,
}

impl AuthenticatorBinding {
    /// Build an authenticator binding from a TDIP `PublicKeyInfo`.
    ///
    /// `tee_attested` is the caller's responsibility — it is filled from
    /// the machine's `is_seed_agent` flag.
    pub fn from_public_key(key: &PublicKeyInfo, tee_attested: bool) -> Self {
        Self {
            key_id: key.key_id.clone(),
            key_type: key.key_type.clone(),
            public_key: key.public_key.clone(),
            tee_attested,
        }
    }
}

/// KYA verification level ladder.
///
/// Mirrors the four-tier scale used by the Mastercard payment-side
/// `KyaVerifier` (`crates/tenzro-payments/src/mastercard/kya.rs`) so a
/// `KyaRecord` produced here can be scored against the same ladder by the
/// payments crate without re-importing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum KyaLevel {
    /// Identity not verified (not found, suspended, or revoked).
    Unverified = 0,
    /// Identity exists and is active.
    Basic = 1,
    /// Controlled by an active controller.
    Enhanced = 2,
    /// Controlled and has a non-default delegation scope.
    Full = 3,
}

impl std::fmt::Display for KyaLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KyaLevel::Unverified => write!(f, "unverified"),
            KyaLevel::Basic => write!(f, "basic"),
            KyaLevel::Enhanced => write!(f, "enhanced"),
            KyaLevel::Full => write!(f, "full"),
        }
    }
}

/// DID-anchored KYA record — the wire-shaped projection of a TDIP machine
/// identity that a Mastercard or Visa directory can ingest as a federated
/// counterparty.
///
/// Three axes per Mastercard KYA spec:
///
/// 1. **Controller identity** — the human or organization operating the agent.
/// 2. **Authenticator binding** — the public key + TEE-residency flag.
/// 3. **Delegation scope** — programmatic per-session, per-merchant spend
///    limits.
///
/// Plus four Tenzro-extension fields surfaced for cross-network discovery:
///
/// - `agent_did` — the resolvable `did:tenzro:machine:*` identifier
/// - `status` — TDIP lifecycle state (Active / Suspended / Revoked)
/// - `is_seed_agent` — protocol-owned bootstrap agent flag (for organic-vs-seed
///   metrics in receiving directories)
/// - `kya_level` — pre-computed level on the four-tier ladder
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KyaRecord {
    /// The machine agent's resolvable DID.
    pub agent_did: String,
    /// Controller (human or organization) DID, if any.
    pub controller_did: Option<String>,
    /// Public-key authenticator binding (Authentication-purpose key only).
    pub authenticator: Option<AuthenticatorBinding>,
    /// Programmatic spend limits.
    pub delegation_scope: DelegationScope,
    /// TDIP lifecycle status.
    pub status: IdentityStatus,
    /// Protocol-owned bootstrap agent flag.
    pub is_seed_agent: bool,
    /// Pre-computed KYA level from `(status, controller_did, delegation_scope)`.
    ///
    /// Note: this score reflects only the agent-record axes. The payment-side
    /// `KyaVerifier` independently re-resolves the controller identity to
    /// confirm it is also active before promoting a controlled agent above
    /// `Basic`. A `KyaRecord` produced here always reports the *upper bound*
    /// of the ladder; the payments-side check may downgrade.
    pub kya_level: KyaLevel,
}

impl KyaRecord {
    /// Build a `KyaRecord` from a TDIP machine identity.
    ///
    /// Returns `None` if `identity` is a human — KYA records are only
    /// meaningful for machine agents.
    ///
    /// # Authenticator selection
    ///
    /// The first public key carrying [`KeyPurpose::Authentication`] is used.
    /// If no Authentication-purpose key exists, `authenticator` is `None`
    /// and the record can still be ingested (e.g., for human-controlled
    /// agents whose authenticator is bound off-record via `cnf` claims).
    ///
    /// # KYA level computation
    ///
    /// Mirrors the payments-side `KyaVerifier::verify` ladder, but without
    /// resolving the controller — that is the payments crate's job. The
    /// level here is the upper bound:
    ///
    /// | status | controller | delegation_scope | level |
    /// |---|---|---|---|
    /// | Active | None | any | Basic |
    /// | Active | Some(_) | default | Enhanced |
    /// | Active | Some(_) | non-default | Full |
    /// | Suspended / Revoked | * | * | Unverified |
    pub fn from_identity(identity: &TenzroIdentity) -> Option<Self> {
        let IdentityData::Machine {
            delegation_scope,
            controller_did,
            is_seed_agent,
            ..
        } = &identity.identity_data
        else {
            return None;
        };

        let tee_attested = *is_seed_agent;
        let authenticator = identity
            .public_keys
            .iter()
            .find(|k| k.purposes.contains(&KeyPurpose::Authentication))
            .map(|k| AuthenticatorBinding::from_public_key(k, tee_attested));

        let kya_level = compute_kya_level(identity.status, controller_did, delegation_scope);

        Some(Self {
            agent_did: identity.did_string(),
            controller_did: controller_did.clone(),
            authenticator,
            delegation_scope: delegation_scope.clone(),
            status: identity.status,
            is_seed_agent: *is_seed_agent,
            kya_level,
        })
    }
}

/// Compute the KYA level upper bound from the three machine-record axes.
///
/// Lifted out of `KyaRecord::from_identity` so the payments crate's
/// `KyaVerifier` can call it after re-resolving the controller status.
pub fn compute_kya_level(
    status: IdentityStatus,
    controller_did: &Option<String>,
    delegation_scope: &DelegationScope,
) -> KyaLevel {
    if status != IdentityStatus::Active {
        return KyaLevel::Unverified;
    }
    let Some(_) = controller_did else {
        return KyaLevel::Basic;
    };
    if delegation_scope.max_transaction_value.is_some()
        || !delegation_scope.allowed_operations.is_empty()
        || !delegation_scope.allowed_payment_protocols.is_empty()
    {
        KyaLevel::Full
    } else {
        KyaLevel::Enhanced
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::TenzroDid;
    use crate::identity::{KeyPurpose, PublicKeyInfo, ServiceEndpoint};
    use chrono::Utc;
    use std::collections::HashMap;
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

    fn machine_identity_with_scope(
        controller: Option<&str>,
        scope: DelegationScope,
        is_seed_agent: bool,
        status: IdentityStatus,
    ) -> TenzroIdentity {
        TenzroIdentity {
            did: TenzroDid::parse("did:tenzro:machine:ctrl:bot1").unwrap(),
            public_keys: vec![PublicKeyInfo {
                key_id: "key-1".to_string(),
                key_type: "Ed25519".to_string(),
                public_key: vec![1; 32],
                purposes: vec![KeyPurpose::Authentication, KeyPurpose::AssertionMethod],
            }],
            identity_data: IdentityData::Machine {
                capabilities: vec!["inference".to_string()],
                delegation_scope: scope,
                controller_did: controller.map(String::from),
                reputation: 0,
                tenzro_agent_id: None,
                erc8004_agent_id: None,
                is_seed_agent,
            },
            status,
            wallet_address: Address::new([0u8; 32]),
            wallet_id: "wallet-1".to_string(),
            pq_verifying_key: test_pq_vk(),
            bls_verifying_key: test_bls_vk(),
            credentials: Vec::new(),
            services: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
            username: None,
        }
    }

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
    fn test_kya_record_returns_none_for_human() {
        let human = TenzroIdentity {
            did: TenzroDid::parse("did:tenzro:human:alice").unwrap(),
            public_keys: vec![],
            identity_data: IdentityData::Human {
                display_name: "Alice".to_string(),
                kyc_tier: tenzro_types::identity::KycTier::Unverified,
                controlled_machines: Vec::new(),
            },
            status: IdentityStatus::Active,
            wallet_address: Address::new([0u8; 32]),
            wallet_id: "wallet-1".to_string(),
            pq_verifying_key: test_pq_vk(),
            bls_verifying_key: test_bls_vk(),
            credentials: Vec::new(),
            services: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            metadata: HashMap::new(),
            username: None,
        };
        assert!(KyaRecord::from_identity(&human).is_none());
    }

    #[test]
    fn test_kya_record_autonomous_basic() {
        let id = machine_identity_with_scope(
            None,
            DelegationScope::default(),
            false,
            IdentityStatus::Active,
        );
        let rec = KyaRecord::from_identity(&id).expect("machine record");
        assert_eq!(rec.kya_level, KyaLevel::Basic);
        assert!(rec.controller_did.is_none());
        assert!(rec.authenticator.is_some());
        assert!(!rec.authenticator.as_ref().unwrap().tee_attested);
    }

    #[test]
    fn test_kya_record_controlled_default_scope_enhanced() {
        let id = machine_identity_with_scope(
            Some("did:tenzro:human:ctrl"),
            DelegationScope::default(),
            false,
            IdentityStatus::Active,
        );
        let rec = KyaRecord::from_identity(&id).unwrap();
        assert_eq!(rec.kya_level, KyaLevel::Enhanced);
        assert_eq!(rec.controller_did.as_deref(), Some("did:tenzro:human:ctrl"));
    }

    #[test]
    fn test_kya_record_controlled_with_scope_full() {
        let scope = DelegationScope {
            max_transaction_value: Some(1000),
            allowed_operations: vec!["transfer".to_string()],
            ..Default::default()
        };
        let id = machine_identity_with_scope(
            Some("did:tenzro:human:ctrl"),
            scope,
            false,
            IdentityStatus::Active,
        );
        let rec = KyaRecord::from_identity(&id).unwrap();
        assert_eq!(rec.kya_level, KyaLevel::Full);
    }

    #[test]
    fn test_kya_record_suspended_unverified() {
        let id = machine_identity_with_scope(
            Some("did:tenzro:human:ctrl"),
            DelegationScope::default(),
            false,
            IdentityStatus::Suspended,
        );
        let rec = KyaRecord::from_identity(&id).unwrap();
        assert_eq!(rec.kya_level, KyaLevel::Unverified);
    }

    #[test]
    fn test_kya_record_revoked_unverified() {
        let id = machine_identity_with_scope(
            None,
            DelegationScope::default(),
            false,
            IdentityStatus::Revoked,
        );
        let rec = KyaRecord::from_identity(&id).unwrap();
        assert_eq!(rec.kya_level, KyaLevel::Unverified);
    }

    #[test]
    fn test_kya_record_seed_agent_marks_tee_attested() {
        let id = machine_identity_with_scope(
            None,
            DelegationScope::default(),
            true,
            IdentityStatus::Active,
        );
        let rec = KyaRecord::from_identity(&id).unwrap();
        assert!(rec.is_seed_agent);
        assert!(rec.authenticator.unwrap().tee_attested);
    }

    #[test]
    fn test_kya_record_no_auth_key_no_authenticator() {
        let mut id = machine_identity_with_scope(
            None,
            DelegationScope::default(),
            false,
            IdentityStatus::Active,
        );
        // Replace the only key with an assertion-only key (no Authentication purpose).
        id.public_keys = vec![PublicKeyInfo {
            key_id: "key-1".to_string(),
            key_type: "Ed25519".to_string(),
            public_key: vec![1; 32],
            purposes: vec![KeyPurpose::AssertionMethod],
        }];
        let rec = KyaRecord::from_identity(&id).unwrap();
        assert!(rec.authenticator.is_none());
    }

    #[test]
    fn test_kya_record_serde_round_trip() {
        let id = machine_identity_with_scope(
            Some("did:tenzro:human:ctrl"),
            DelegationScope::default(),
            true,
            IdentityStatus::Active,
        );
        let rec = KyaRecord::from_identity(&id).unwrap();
        let json = serde_json::to_string(&rec).unwrap();
        let parsed: KyaRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.agent_did, rec.agent_did);
        assert_eq!(parsed.kya_level, rec.kya_level);
        assert_eq!(parsed.is_seed_agent, rec.is_seed_agent);
        assert_eq!(
            parsed.authenticator.as_ref().unwrap().tee_attested,
            rec.authenticator.as_ref().unwrap().tee_attested
        );
    }

    #[test]
    fn test_compute_kya_level_pure_function() {
        let scope = DelegationScope::default();
        assert_eq!(
            compute_kya_level(IdentityStatus::Active, &None, &scope),
            KyaLevel::Basic
        );
        assert_eq!(
            compute_kya_level(IdentityStatus::Active, &Some("x".to_string()), &scope),
            KyaLevel::Enhanced
        );
        assert_eq!(
            compute_kya_level(IdentityStatus::Suspended, &None, &scope),
            KyaLevel::Unverified
        );
    }

    #[test]
    fn test_kya_level_ord() {
        assert!(KyaLevel::Unverified < KyaLevel::Basic);
        assert!(KyaLevel::Basic < KyaLevel::Enhanced);
        assert!(KyaLevel::Enhanced < KyaLevel::Full);
    }

    #[test]
    fn test_did_document_can_carry_kya_service_type() {
        // Ensure the constants work as DidDocument service-type strings
        // — i.e. they compose with ServiceEndpoint cleanly.
        let svc = ServiceEndpoint {
            id: "did:tenzro:machine:abc#mastercard-kya".to_string(),
            service_type: SERVICE_TYPE_MASTERCARD_KYA.to_string(),
            service_endpoint: "https://kya.mastercard.com/agents/abc".to_string(),
        };
        let json = serde_json::to_string(&svc).unwrap();
        assert!(json.contains("MastercardKYA"));
        assert!(json.contains("kya.mastercard.com"));
    }
}
