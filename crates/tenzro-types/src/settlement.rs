//! Settlement types for Tenzro Network
//!
//! This module defines types for payment settlement, service billing,
//! and transaction finalization on the network.

use crate::primitives::{Address, Hash, Timestamp};
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
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl SettlementReceipt {
    /// Creates a new settlement receipt
    pub fn new(
        request_id: String,
        transaction_hash: Hash,
        provider: Address,
        customer: Address,
        service_type: ServiceType,
        amount: u64,
        status: SettlementStatus,
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
