//! Tenzro Decentralized Identity Protocol (TDIP)
//!
//! A unified identity protocol for humans and machines on the Tenzro Network.
//! TDIP provides W3C DID-compatible decentralized identifiers with verifiable
//! credentials, delegation scopes, and automatic wallet provisioning.
//!
//! # Overview
//!
//! TDIP is the identity standard for the Tenzro Network. It recognises
//! three identity classes:
//!
//! - **Human** (`did:tenzro:human:{uuid}`) — KYC-tiered, credential-holding
//! - **Delegated agent** (`did:tenzro:machine:{controller}:{uuid}`) — machine
//!   under a human controller, scoped by `DelegationScope`
//! - **Autonomous agent** (`did:tenzro:machine:{uuid}`) — self-sovereign machine,
//!   no controller
//!
//! # Key Features
//!
//! - **Unified identity type** — `TenzroIdentity` covers both humans and machines
//! - **W3C DID Documents** — Export/import identities as standard DID Documents
//! - **Verifiable Credentials** — Issue, inherit, and verify W3C VC-compatible credentials
//! - **Delegation Scopes** — Fine-grained control over machine permissions including
//!   payment protocol restrictions and chain allowlists
//! - **Auto-provisioned wallets** — Every identity gets an MPC wallet automatically
//! - **Cascading revocation** — Revoking a human revokes all controlled machines
//!
//! # Examples
//!
//! ```no_run
//! use tenzro_identity::registry::IdentityRegistry;
//! use tenzro_identity::delegation::DelegationScope;
//! use tenzro_types::identity::KycTier;
//!
//! # async fn example() -> tenzro_identity::error::Result<()> {
//! let registry = IdentityRegistry::new();
//!
//! // Register a human identity
//! let human = registry.register_human_with_fee(
//!     vec![1; 32],
//!     "Alice".to_string(),
//!     KycTier::Enhanced,
//! ).await?.identity;
//!
//! // Register a machine under the human
//! let machine = registry.register_machine_with_fee(
//!     &human.did_string(),
//!     vec![2; 32],
//!     vec!["inference".to_string()],
//!     DelegationScope::unrestricted()
//!         .with_max_transaction_value(10_000)
//!         .with_allowed_payment_protocols(vec!["mpp".to_string()]),
//! ).await?.identity;
//!
//! println!("Human DID: {}", human.did_string());
//! println!("Machine DID: {}", machine.did_string());
//! # Ok(())
//! # }
//! ```

pub mod car;
pub mod credential;
pub mod delegation;
pub mod derivation;
pub mod did;
pub mod document;
pub mod envelope;
pub mod erc7683;
pub mod erc8004;
pub mod erc8004_daml;
pub mod erc8004_svm;
pub mod error;
pub mod gossip;
pub mod identity;
pub mod iso20022;
pub mod ivms101;
pub mod keri;
pub mod kya;
pub mod registry;
pub mod verification;
pub mod w3c;
pub mod wallet_binding;

// Re-export commonly used types
pub use car::IdentityCarBundle;
pub use credential::{
    CredentialProof, TenzroCredentialType, VerifiableCredential, sign_credential_hybrid,
};
pub use delegation::{DelegationEntry, DelegationScope, TimeBound};
pub use derivation::{
    ChainDerivation, DerivationError, TargetChain, TargetCurve, evm_address, stellar_strkey,
    xrpl_classic_address,
};
pub use did::{DidType, TenzroDid};
pub use document::{DidDocument, DidService, VerificationMethod};
pub use envelope::{
    EnvelopeError, TenzroDidEnvelope, canonical_preimage, params_hash, verify_envelope,
};
pub use erc8004::{
    AgentRecord, Erc8004Adapter, Erc8004Addresses, Erc8004Transport, EthAddress, FeedbackEntry,
    MetadataEntry, OnChainAgentRegistry, ValidationRequest, ValidationResult,
    agent_id_from_uint256_be, agent_id_to_uint256_be,
};
pub use erc8004_daml::{
    DamlAgentRecord, DamlPackageIds, Erc8004DamlTransport, OnChainAgentDamlRegistry, PackageId,
    PartyId,
};
pub use erc8004_svm::{Erc8004SvmTransport, OnChainAgentSvmRegistry, SolPubkey, SvmAgentRecord};
pub use error::{IdentityError, Result};
pub use gossip::{
    IDENTITY_TOPIC, IdentityGossipMessage, decode_identity_for_topic, encode_revocation_broadcast,
};
pub use identity::{
    IdentityData, IdentityStatus, KeyPurpose, MachineAnchor, OwnershipTransfer, PublicKeyInfo,
    RevocationEntry, ServiceEndpoint, TenzroIdentity, TransferAuthority, TransferError,
    validate_username,
};
pub use iso20022::{
    DecimalAmount, Iso20022Error, Ivms101Mapping, PACS008_NAMESPACE, Pacs008Document,
    TransferDetails,
};
pub use kya::{
    AuthenticatorBinding, KyaLevel, KyaRecord, SERVICE_TYPE_MASTERCARD_KYA,
    SERVICE_TYPE_STRIPE_SPT, SERVICE_TYPE_TEMPO_ACCOUNT, SERVICE_TYPE_VISA_TAP, compute_kya_level,
    is_kya_service_type,
};
pub use registry::{
    DelegationPolicy, DidResolutionBackend, IdentityRegistry, RegistrationResult,
    RevocationBroadcaster, SignedRevocationEntry,
};
pub use verification::{IdentityVerifier, TrustChainResult};
pub use w3c::{extract_public_keys_from_document, identity_to_did_document};
pub use wallet_binding::{WalletBinder, WalletBinding};
