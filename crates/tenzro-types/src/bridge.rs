//! Cross-chain bridge types for Tenzro Network
//!
//! This module defines types for bridging assets between Tenzro Network
//! and other blockchains.

use crate::primitives::{Address, Hash, Timestamp};
use serde::{Deserialize, Serialize};

/// A message sent through the bridge
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeMessage {
    /// Message ID
    pub message_id: String,
    /// Source chain
    pub source_chain: String,
    /// Destination chain
    pub destination_chain: String,
    /// Sender address on source chain
    pub sender: String,
    /// Recipient address on destination chain
    pub recipient: String,
    /// Message payload
    pub payload: Vec<u8>,
    /// Message nonce
    pub nonce: u64,
    /// Message timestamp
    pub timestamp: Timestamp,
    /// Bridge protocol used
    pub protocol: BridgeProtocol,
    /// Message status
    pub status: BridgeMessageStatus,
}

impl BridgeMessage {
    /// Creates a new bridge message
    pub fn new(
        source_chain: String,
        destination_chain: String,
        sender: String,
        recipient: String,
        payload: Vec<u8>,
        nonce: u64,
        protocol: BridgeProtocol,
    ) -> Self {
        Self {
            message_id: uuid::Uuid::new_v4().to_string(),
            source_chain,
            destination_chain,
            sender,
            recipient,
            payload,
            nonce,
            timestamp: Timestamp::now(),
            protocol,
            status: BridgeMessageStatus::Pending,
        }
    }

    /// Computes the message hash
    pub fn hash(&self) -> Hash {
        // In production, this would use a proper hashing algorithm
        let json = serde_json::to_string(self).unwrap_or_default();
        let mut hasher = [0u8; 32];
        let bytes = json.as_bytes();
        for (i, byte) in bytes.iter().enumerate().take(32) {
            hasher[i % 32] ^= byte;
        }
        Hash::new(hasher)
    }
}

/// Status of a bridge message
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeMessageStatus {
    /// Message is pending
    Pending,
    /// Message is being processed
    Processing,
    /// Message has been confirmed on source chain
    SourceConfirmed,
    /// Message is being relayed
    Relaying,
    /// Message has been delivered to destination
    Delivered,
    /// Message failed
    Failed,
    /// Message was refunded
    Refunded,
}

/// Bridge protocol types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeProtocol {
    /// Lock and mint protocol
    LockAndMint,
    /// Burn and mint protocol
    BurnAndMint,
    /// Liquidity pool protocol
    LiquidityPool,
    /// Atomic swap protocol
    AtomicSwap,
    /// Optimistic bridge protocol
    Optimistic,
    /// ZK proof bridge protocol
    ZeroKnowledge,
}

impl BridgeProtocol {
    /// Returns the protocol name
    pub fn as_str(&self) -> &str {
        match self {
            Self::LockAndMint => "Lock and Mint",
            Self::BurnAndMint => "Burn and Mint",
            Self::LiquidityPool => "Liquidity Pool",
            Self::AtomicSwap => "Atomic Swap",
            Self::Optimistic => "Optimistic",
            Self::ZeroKnowledge => "Zero Knowledge",
        }
    }
}

/// A cross-chain transfer via bridge
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeTransfer {
    /// Transfer ID
    pub transfer_id: String,
    /// Bridge message
    pub message: BridgeMessage,
    /// Asset being transferred
    pub asset_id: String,
    /// Amount being transferred
    pub amount: u64,
    /// Bridge fee (in source chain units)
    pub bridge_fee: u64,
    /// Relayer fee (in destination chain units)
    pub relayer_fee: u64,
    /// Source transaction hash
    pub source_tx_hash: Option<Hash>,
    /// Destination transaction hash
    pub destination_tx_hash: Option<Hash>,
    /// Transfer proof
    pub proof: Option<BridgeProof>,
    /// Transfer metadata
    pub metadata: BridgeTransferMetadata,
}

impl BridgeTransfer {
    /// Creates a new bridge transfer
    pub fn new(message: BridgeMessage, asset_id: String, amount: u64, bridge_fee: u64) -> Self {
        Self {
            transfer_id: uuid::Uuid::new_v4().to_string(),
            message,
            asset_id,
            amount,
            bridge_fee,
            relayer_fee: 0,
            source_tx_hash: None,
            destination_tx_hash: None,
            proof: None,
            metadata: BridgeTransferMetadata::default(),
        }
    }

    /// Sets the source transaction hash
    pub fn with_source_tx(mut self, tx_hash: Hash) -> Self {
        self.source_tx_hash = Some(tx_hash);
        self
    }

    /// Sets the destination transaction hash
    pub fn with_destination_tx(mut self, tx_hash: Hash) -> Self {
        self.destination_tx_hash = Some(tx_hash);
        self
    }

    /// Sets the transfer proof
    pub fn with_proof(mut self, proof: BridgeProof) -> Self {
        self.proof = Some(proof);
        self
    }
}

/// Metadata for bridge transfers
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct BridgeTransferMetadata {
    /// Number of confirmations on source chain
    pub source_confirmations: u32,
    /// Required confirmations
    pub required_confirmations: u32,
    /// Relayer address
    pub relayer: Option<String>,
    /// Challenge period end (for optimistic bridges)
    pub challenge_period_end: Option<Timestamp>,
    /// Additional metadata
    pub extra: Option<Vec<u8>>,
}

/// Proof for a bridge transfer
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeProof {
    /// Proof type
    pub proof_type: BridgeProofType,
    /// Proof data
    pub proof_data: Vec<u8>,
    /// Validator signatures (if applicable)
    pub signatures: Vec<ValidatorSignature>,
}

impl BridgeProof {
    /// Creates a new bridge proof
    pub fn new(proof_type: BridgeProofType, proof_data: Vec<u8>) -> Self {
        Self {
            proof_type,
            proof_data,
            signatures: Vec::new(),
        }
    }

    /// Adds a validator signature
    pub fn add_signature(&mut self, signature: ValidatorSignature) {
        self.signatures.push(signature);
    }
}

/// Type of bridge proof
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BridgeProofType {
    /// Merkle proof
    Merkle,
    /// Multi-signature proof
    MultiSig,
    /// ZK proof
    ZeroKnowledge,
    /// Light client proof
    LightClient,
    /// Optimistic proof (challenge-based)
    Optimistic,
}

/// A validator signature for bridge operations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSignature {
    /// Validator address
    pub validator: Address,
    /// Signature bytes
    pub signature: Vec<u8>,
    /// Validator's voting power
    #[serde(with = "crate::primitives::u128_serde")]
    pub voting_power: u128,
    /// Signature timestamp
    pub signed_at: Timestamp,
}

/// Bridge relay configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeRelayConfig {
    /// Relayer address
    pub relayer: Address,
    /// Supported source chains
    pub supported_source_chains: Vec<String>,
    /// Supported destination chains
    pub supported_destination_chains: Vec<String>,
    /// Relayer fee (basis points)
    pub relayer_fee_bps: u32,
    /// Minimum transfer amount
    pub min_transfer_amount: u64,
    /// Maximum transfer amount
    pub max_transfer_amount: u64,
    /// Relayer status
    pub status: RelayerStatus,
}

impl BridgeRelayConfig {
    /// Creates a new bridge relay configuration
    pub fn new(relayer: Address) -> Self {
        Self {
            relayer,
            supported_source_chains: Vec::new(),
            supported_destination_chains: Vec::new(),
            relayer_fee_bps: 10, // 0.1%
            min_transfer_amount: 1000,
            max_transfer_amount: u64::MAX,
            status: RelayerStatus::Active,
        }
    }

    /// Adds a supported source chain
    pub fn add_source_chain(&mut self, chain: String) {
        if !self.supported_source_chains.contains(&chain) {
            self.supported_source_chains.push(chain);
        }
    }

    /// Adds a supported destination chain
    pub fn add_destination_chain(&mut self, chain: String) {
        if !self.supported_destination_chains.contains(&chain) {
            self.supported_destination_chains.push(chain);
        }
    }

    /// Checks if a route is supported
    pub fn supports_route(&self, source: &str, destination: &str) -> bool {
        self.supported_source_chains.iter().any(|c| c == source)
            && self
                .supported_destination_chains
                .iter()
                .any(|c| c == destination)
    }
}

/// Relayer operational status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayerStatus {
    /// Relayer is active
    Active,
    /// Relayer is paused
    Paused,
    /// Relayer is suspended
    Suspended,
}
