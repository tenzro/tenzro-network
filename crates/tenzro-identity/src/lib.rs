//! Tenzro Decentralized Identity Protocol (TDIP)
//!
//! A unified identity protocol for humans and machines on the Tenzro Network.
//! TDIP provides W3C DID-compatible decentralized identifiers with delegation
//! scopes and automatic wallet provisioning. Credentials about an identity
//! (certifications, KYC) are trust records in `tenzro-trust`, not part of
//! the identity.
//!
//! # Overview
//!
//! TDIP is the identity standard for the Tenzro Network. It recognises
//! three identity classes:
//!
//! - **Human** (`did:tenzro:human:{uuid}`) — rooted in a passkey
//! - **Delegated agent** (`did:tenzro:machine:{controller}:{uuid}`) — machine
//!   under a human controller; its authority is only its consensus Terms
//! - **Autonomous agent** (`did:tenzro:machine:{uuid}`) — self-sovereign machine,
//!   no controller
//!
//! # Key Features
//!
//! - **Unified identity type** — `TenzroIdentity` covers both humans and machines
//! - **W3C DID Documents** — Export/import identities as standard DID Documents
//! - **Derived KYC tiers** — a [`KycResolver`] supplies each identity's tier; none is stored
//! - **Machine-access grants** — `DelegationScope` names the machine
//!   resources and operation bounds an owner-signed machine-access grant
//!   allows; agent authority is not stored here (consensus Terms)
//! - **Auto-provisioned wallets** — Every identity gets a wallet automatically, bound to that identity
//! - **Cascading revocation** — Revoking a human revokes all controlled machines
//!
//! # Examples
//!
//! ```no_run
//! use tenzro_identity::registry::IdentityRegistry;
//!
//! # async fn example() -> tenzro_identity::error::Result<()> {
//! let registry = IdentityRegistry::new();
//!
//! // Register a human identity
//! // The first argument is the passkey credential id that owns this identity;
//! // the second is the passkey's public half. The registry never sees a secret.
//! let human = registry.register_human_via_binder(
//!     b"passkey-credential-id".to_vec(),
//!     vec![1; 32],
//!     "Alice".to_string(),
//! ).await?.identity;
//!
//! // Register a machine under the human
//! let machine = registry.register_machine_with_fee(
//!     &human.did_string(),
//!     vec![2; 32],
//!     vec!["inference".to_string()],
//! ).await?.identity;
//!
//! println!("Human DID: {}", human.did_string());
//! println!("Machine DID: {}", machine.did_string());
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]

pub mod delegation;
pub mod did;
pub mod document;
pub mod envelope;
pub mod erc8004;
pub mod error;
pub mod identity;
pub mod ivms101;
pub mod keri;
pub mod kya;
pub mod pq_rotation;
pub mod registry;
pub mod w3c;
pub mod wallet_binding;

// Re-export commonly used types
pub use delegation::{
    DelegationEntry, DelegationScope, MachineResource, OperationBound, TimeBound,
};
pub use did::{DidType, TenzroDid};
pub use document::{DidDocument, DidService, VerificationMethod};
pub use envelope::{
    EnvelopeError, TenzroDidEnvelope, canonical_preimage, identity_key, params_hash,
    verify_envelope,
};
pub use erc8004::{
    AgentRecord, Erc8004Adapter, Erc8004Addresses, Erc8004Transport, EthAddress, FeedbackEntry,
    MetadataEntry, OnChainAgentRegistry, ValidationRequest, ValidationResult,
    agent_id_from_uint256_be, agent_id_to_uint256_be,
};
pub use error::{IdentityError, Result};
pub use identity::{
    IdentityData, IdentityStatus, KeyPurpose, MachineAnchor, OwnershipTransfer, PublicKeyInfo,
    RevocationEntry, TenzroIdentity, TransferAuthority, TransferError,
};
pub use kya::{
    SERVICE_TYPE_MASTERCARD_KYA, SERVICE_TYPE_STRIPE_SPT, SERVICE_TYPE_TEMPO_ACCOUNT,
    SERVICE_TYPE_VISA_TAP, is_kya_service_type,
};
pub use registry::{
    AgentTermsLookup, DelegationPolicy, IdentityRegistry, KycResolver, PendingRegistration,
    RegistrationResult,
};
pub use w3c::{extract_public_keys_from_document, identity_to_did_document};
pub use wallet_binding::{WalletBinder, WalletBinding};
