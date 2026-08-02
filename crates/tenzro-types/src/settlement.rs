//! Settlement types for Tenzro Network
//!
//! This module defines types for payment settlement, service billing,
//! and transaction finalization on the network.

use crate::primitives::{Address, Hash, Timestamp};
use crate::principal_chain::PrincipalChain;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A request for settlement on Tenzro Network
///
/// Settlement requests represent claims for payment for services rendered.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementRequest {
    /// Request ID
    pub request_id: String,
    /// Service provider requesting settlement
    pub provider: Address,
    /// Customer being billed
    pub customer: Address,
    /// Service type
    pub service_type: ServiceType,
    /// Payment intent details
    pub payment_intent: PaymentIntent,
    /// Amount to settle (in smallest TNZO unit)
    pub amount: u64,
    /// Service details and proof
    pub service_proof: ServiceProof,
    /// Request timestamp
    pub timestamp: Timestamp,
    /// Settlement deadline
    pub deadline: Option<Timestamp>,
}

impl SettlementRequest {
    /// Creates a new settlement request
    pub fn new(
        provider: Address,
        customer: Address,
        service_type: ServiceType,
        amount: u64,
        service_proof: ServiceProof,
    ) -> Self {
        Self {
            request_id: uuid::Uuid::new_v4().to_string(),
            provider,
            customer,
            service_type,
            payment_intent: PaymentIntent::Immediate,
            amount,
            service_proof,
            timestamp: Timestamp::now(),
            deadline: None,
        }
    }

    /// Sets the payment intent
    pub fn with_payment_intent(mut self, intent: PaymentIntent) -> Self {
        self.payment_intent = intent;
        self
    }

    /// Sets a settlement deadline
    pub fn with_deadline(mut self, deadline: Timestamp) -> Self {
        self.deadline = Some(deadline);
        self
    }

    /// Checks if the settlement has expired
    pub fn is_expired(&self) -> bool {
        if let Some(deadline) = self.deadline {
            Timestamp::now() > deadline
        } else {
            false
        }
    }
}

/// Receipt for a completed settlement
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementReceipt {
    /// Receipt ID
    pub receipt_id: String,
    /// Settlement request this receipt is for
    pub request_id: String,
    /// Transaction hash
    pub transaction_hash: Hash,
    /// Provider
    pub provider: Address,
    /// Customer
    pub customer: Address,
    /// Service type
    pub service_type: ServiceType,
    /// Amount settled (in smallest TNZO unit)
    pub amount: u64,
    /// Settlement status
    pub status: SettlementStatus,
    /// Settlement timestamp
    pub settled_at: Timestamp,
    /// Frozen principal chain for the customer (payer) — see Agent-Swarm
    /// Spec 5. Captures the controller, KYC tier, and bond at the time of
    /// settlement so liability is identifiable from the receipt without
    /// recursive identity-registry walks. Resolved by the settlement
    /// engine via a `PrincipalChainResolver`; falls back to a synthetic
    /// anonymous chain when the customer address has no bound DID.
    pub principal_chain: PrincipalChain,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl SettlementReceipt {
    /// Creates a new settlement receipt with an explicit principal chain.
    ///
    /// Callers must resolve the chain via a `PrincipalChainResolver`
    /// (typically `IdentityRegistry::resolve_principal_chain`) and pass
    /// it in. There is no implicit fallback inside the type — callers
    /// that genuinely have no chain context should use
    /// `principal_chain::anonymous_chain_for_address`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        request_id: String,
        transaction_hash: Hash,
        provider: Address,
        customer: Address,
        service_type: ServiceType,
        amount: u64,
        status: SettlementStatus,
        principal_chain: PrincipalChain,
    ) -> Self {
        Self {
            receipt_id: uuid::Uuid::new_v4().to_string(),
            request_id,
            transaction_hash,
            provider,
            customer,
            service_type,
            amount,
            status,
            settled_at: Timestamp::now(),
            principal_chain,
            metadata: HashMap::new(),
        }
    }

    /// Adds metadata to the receipt
    pub fn add_metadata(&mut self, key: String, value: String) {
        self.metadata.insert(key, value);
    }
}

/// Settlement status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SettlementStatus {
    /// Settlement is pending
    Pending,
    /// Settlement completed successfully
    Completed,
    /// Settlement failed
    Failed,
    /// Settlement disputed
    Disputed,
    /// Settlement refunded
    Refunded,
}

/// Types of services that can be settled
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "details")]
pub enum ServiceType {
    /// Model inference service
    ModelInference {
        /// Model ID
        model_id: String,
        /// Number of tokens processed
        tokens: u32,
    },
    /// TEE computation service
    TeeComputation {
        /// Computation ID
        computation_id: String,
        /// Compute units used
        compute_units: u64,
    },
    /// Storage service
    Storage {
        /// Data size (bytes)
        data_size: u64,
        /// Duration (seconds)
        duration: u64,
    },
    /// Agent execution service
    AgentExecution {
        /// Agent ID
        agent_id: String,
        /// Task ID
        task_id: String,
    },
    /// Data service
    DataService {
        /// Service ID
        service_id: String,
        /// Data volume
        volume: u64,
    },
    /// Bridge service
    Bridge {
        /// Transfer ID
        transfer_id: String,
        /// Amount bridged
        amount: u64,
    },
    /// HTTP 402 payment protocol service (MPP, x402)
    HttpPayment {
        /// Protocol used (e.g., "mpp", "x402")
        protocol: String,
        /// Resource URL that was paid for
        resource: String,
    },
    /// Custom service
    Custom {
        /// Service name
        name: String,
        /// Service parameters
        parameters: HashMap<String, String>,
    },
}

impl ServiceType {
    /// Returns the service type name
    pub fn type_name(&self) -> &str {
        match self {
            Self::ModelInference { .. } => "ModelInference",
            Self::TeeComputation { .. } => "TeeComputation",
            Self::Storage { .. } => "Storage",
            Self::AgentExecution { .. } => "AgentExecution",
            Self::DataService { .. } => "DataService",
            Self::Bridge { .. } => "Bridge",
            Self::HttpPayment { .. } => "HttpPayment",
            Self::Custom { .. } => "Custom",
        }
    }
}

/// Payment intent for settlement
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaymentIntent {
    /// Immediate payment required
    Immediate,
    /// Payment can be deferred
    Deferred,
    /// Payment on delivery/completion
    OnDelivery,
    /// Escrow-based payment
    Escrow,
    /// Subscription-based payment
    Subscription,
}

/// Proof of service for settlement verification
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceProof {
    /// Proof type
    pub proof_type: ProofType,
    /// Proof data
    pub proof_data: Vec<u8>,
    /// Signatures from relevant parties
    pub signatures: Vec<ProofSignature>,
    /// Attestation (if service was performed in TEE)
    pub attestation: Option<Vec<u8>>,
}

impl ServiceProof {
    /// Creates a new service proof
    pub fn new(proof_type: ProofType, proof_data: Vec<u8>) -> Self {
        Self {
            proof_type,
            proof_data,
            signatures: Vec::new(),
            attestation: None,
        }
    }

    /// Adds a signature to the proof
    pub fn add_signature(&mut self, signature: ProofSignature) {
        self.signatures.push(signature);
    }

    /// Adds an attestation
    pub fn with_attestation(mut self, attestation: Vec<u8>) -> Self {
        self.attestation = Some(attestation);
        self
    }
}

/// Types of service proofs
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofType {
    /// Cryptographic proof
    Cryptographic,
    /// TEE attestation proof
    TeeAttestation,
    /// Multi-party signature proof
    MultiParty,
    /// Merkle proof
    Merkle,
    /// ZK proof
    ZeroKnowledge,
    /// Oracle verification
    Oracle,
}

/// A signature in a service proof
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofSignature {
    /// Signer address
    pub signer: Address,
    /// Signature bytes
    pub signature: Vec<u8>,
    /// Signer role
    pub role: SignerRole,
}

/// Role of a signer in a proof
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignerRole {
    /// Service provider
    Provider,
    /// Service consumer
    Consumer,
    /// Third-party verifier
    Verifier,
    /// Oracle
    Oracle,
}

/// Escrow configuration for settlements
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowConfig {
    /// Escrow address
    pub escrow_address: Address,
    /// Amount held in escrow (in smallest TNZO unit)
    pub amount: u64,
    /// Release conditions
    pub release_conditions: ReleaseConditions,
    /// Timeout (if conditions not met)
    pub timeout: Timestamp,
}

/// Conditions for escrow release
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ReleaseConditions {
    /// Release on provider signature
    ProviderSignature,
    /// Release on consumer signature
    ConsumerSignature,
    /// Release on both signatures
    BothSignatures,
    /// Release on verifier signature
    VerifierSignature,
    /// Release on timeout
    Timeout,
    /// Custom condition
    Custom { condition: String },
}

/// Domain separation tag for [`SettlementAuthorization`] signing preimages.
pub const SETTLEMENT_AUTHORIZATION_DOMAIN: &[u8] = b"tenzro/settlement/authorization";

/// A developer-signed authorization to settle TNZO from an app wallet to a
/// payer after an off-network fiat payment cleared on the developer's own
/// payment provider.
///
/// The developer backend charges the end user through its own provider
/// account (the network never holds provider credentials or fiat float),
/// then signs this authorization with a key registered in the app's
/// on-chain record. Any node can verify and execute it: the TNZO moves
/// from the developer's app wallet to the payer's wallet, minus the
/// network settlement commission.
///
/// `signature` is an Ed25519 signature over [`Self::signing_hash`], which
/// binds every field except the signature itself — including `key_id`, so
/// a signature cannot be re-attributed to a different registered key with
/// a different spending ceiling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementAuthorization {
    /// App identifier in the on-chain app registry
    pub app_id: String,
    /// Chain id the authorization is valid on (prevents cross-chain replay)
    pub chain_id: u64,
    /// Payer's DID — resolved to a wallet address at execution time
    pub payer_did: String,
    /// TNZO amount, fixed and quoted at charge time (never fiat-denominated)
    pub amount_tnzo: u128,
    /// Developer's payment-provider reference (idempotency key per app)
    pub external_ref: String,
    /// Random 32 bytes chosen by the signer
    pub nonce: [u8; 32],
    /// Expiry in unix milliseconds — a short quote-lock window
    pub expiry: u64,
    /// Which registered signing key produced `signature`
    pub key_id: String,
    /// Ed25519 signature over [`Self::signing_hash`]
    pub signature: Vec<u8>,
}

impl SettlementAuthorization {
    /// Canonical signing preimage: domain tag, then each field with
    /// variable-length fields prefixed by their u32 big-endian byte length
    /// and integers in fixed-width big-endian. The signature is excluded.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            SETTLEMENT_AUTHORIZATION_DOMAIN.len()
                + self.app_id.len()
                + self.payer_did.len()
                + self.external_ref.len()
                + self.key_id.len()
                + 96,
        );
        out.extend_from_slice(SETTLEMENT_AUTHORIZATION_DOMAIN);
        let write_str = |out: &mut Vec<u8>, s: &str| {
            out.extend_from_slice(&(s.len() as u32).to_be_bytes());
            out.extend_from_slice(s.as_bytes());
        };
        write_str(&mut out, &self.app_id);
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        write_str(&mut out, &self.payer_did);
        out.extend_from_slice(&self.amount_tnzo.to_be_bytes());
        write_str(&mut out, &self.external_ref);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.expiry.to_be_bytes());
        write_str(&mut out, &self.key_id);
        out
    }

    /// SHA-256 of [`Self::signing_preimage`] — the exact 32 bytes the
    /// developer key signs.
    pub fn signing_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.signing_preimage());
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod settlement_authorization_tests {
    use super::*;

    fn sample() -> SettlementAuthorization {
        SettlementAuthorization {
            app_id: "demo-app".into(),
            chain_id: 1337,
            payer_did: "did:tenzro:human:abc".into(),
            amount_tnzo: 1_000_000_000_000_000_000,
            external_ref: "pi_3Nqw8s".into(),
            nonce: [7u8; 32],
            expiry: 1_800_000_000_000,
            key_id: "backend-1".into(),
            signature: vec![],
        }
    }

    #[test]
    fn preimage_is_deterministic() {
        assert_eq!(sample().signing_hash(), sample().signing_hash());
    }

    #[test]
    fn preimage_starts_with_domain() {
        assert!(
            sample()
                .signing_preimage()
                .starts_with(SETTLEMENT_AUTHORIZATION_DOMAIN)
        );
    }

    #[test]
    fn every_field_changes_hash() {
        let base = sample().signing_hash();
        let mut a = sample();
        a.app_id = "other-app".into();
        assert_ne!(a.signing_hash(), base);
        let mut c = sample();
        c.chain_id = 1;
        assert_ne!(c.signing_hash(), base);
        let mut p = sample();
        p.payer_did = "did:tenzro:human:xyz".into();
        assert_ne!(p.signing_hash(), base);
        let mut m = sample();
        m.amount_tnzo += 1;
        assert_ne!(m.signing_hash(), base);
        let mut r = sample();
        r.external_ref = "pi_other".into();
        assert_ne!(r.signing_hash(), base);
        let mut n = sample();
        n.nonce = [8u8; 32];
        assert_ne!(n.signing_hash(), base);
        let mut e = sample();
        e.expiry += 1;
        assert_ne!(e.signing_hash(), base);
        let mut k = sample();
        k.key_id = "backend-2".into();
        assert_ne!(k.signing_hash(), base);
    }

    #[test]
    fn signature_not_in_preimage() {
        let mut s = sample();
        let before = s.signing_hash();
        s.signature = vec![1, 2, 3];
        assert_eq!(s.signing_hash(), before);
    }

    #[test]
    fn length_prefix_prevents_field_boundary_shift() {
        let mut a = sample();
        a.app_id = "ab".into();
        a.payer_did = "cdid:tenzro:human:abc".into();
        let mut b = sample();
        b.app_id = "abc".into();
        b.payer_did = "did:tenzro:human:abc".into();
        assert_ne!(a.signing_hash(), b.signing_hash());
    }
}
