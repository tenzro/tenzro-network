//! Standardized message format for cross-chain communication
//!
//! This module defines a universal message format that can be used across all bridge
//! protocols for consistent cross-chain communication in the Tenzro Network.
//!
//! # Post-Quantum Migration: EXTERNAL_LOCKED
//!
//! `TenzroMessage` is the wire format spoken to **external** chains
//! (LayerZero V2, Chainlink CCIP, Wormhole, deBridge, Canton). Those
//! counterparties have no ML-DSA-65 verifier on their execution layer, so
//! the Tenzro-side signing leg here is intentionally classical-only
//! (Ed25519 / Secp256k1). Adding a hybrid composite signature would not
//! make outbound messages safer — relying chains would simply discard the
//! PQ leg.
//!
//! Internal Tenzro-to-Tenzro authentication (consensus votes, agent A2A,
//! payment server credentials, identity revocations) MUST use the hybrid
//! signing path in `tenzro_crypto::composite` — never this format.

use crate::error::{BridgeError, Result};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tenzro_crypto::keys::{KeyType, PublicKey};
use tenzro_crypto::signatures::Signature as CryptoSignature;
use tenzro_types::primitives::{Hash, Timestamp};
use tracing;

/// Standardized cross-chain message format for Tenzro Network
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenzroMessage {
    /// Message format version for compatibility
    pub version: u8,
    /// Type of message
    pub message_type: MessageType,
    /// Source chain identifier for replay protection
    pub source_chain_id: u64,
    /// Destination chain identifier for replay protection
    pub dest_chain_id: u64,
    /// Sender address (source chain format)
    pub sender: String,
    /// Receiver address (destination chain format)
    pub receiver: String,
    /// Message payload
    pub payload: Vec<u8>,
    /// Message nonce for ordering and replay protection (per-sender monotonic)
    pub nonce: u64,
    /// Message timestamp
    pub timestamp: Timestamp,
    /// SHA-256 hash of (source_chain_id + dest_chain_id + nonce + payload) for integrity
    pub message_hash: [u8; 32],
    /// Optional Ed25519/Secp256k1 signature over message_hash for verification
    pub signature: Option<Vec<u8>>,
    /// Public key of the signer (required when signature is present)
    #[serde(default)]
    pub signer_public_key: Option<Vec<u8>>,
    /// Key type of the signer (Ed25519 or Secp256k1)
    #[serde(default)]
    pub signer_key_type: Option<String>,
}

impl TenzroMessage {
    /// Creates a new Tenzro message with replay protection
    pub fn new(
        message_type: MessageType,
        source_chain_id: u64,
        dest_chain_id: u64,
        sender: impl Into<String>,
        receiver: impl Into<String>,
        payload: Vec<u8>,
        nonce: u64,
    ) -> Self {
        let sender_str = sender.into();
        let receiver_str = receiver.into();

        // Compute message hash for integrity verification
        let message_hash = Self::compute_hash(source_chain_id, dest_chain_id, nonce, &payload);

        Self {
            version: 1,
            message_type,
            source_chain_id,
            dest_chain_id,
            sender: sender_str,
            receiver: receiver_str,
            payload,
            nonce,
            timestamp: Timestamp::now(),
            message_hash,
            signature: None,
            signer_public_key: None,
            signer_key_type: None,
        }
    }

    /// Computes the SHA-256 hash of the message for integrity verification
    fn compute_hash(
        source_chain_id: u64,
        dest_chain_id: u64,
        nonce: u64,
        payload: &[u8],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(source_chain_id.to_le_bytes());
        hasher.update(dest_chain_id.to_le_bytes());
        hasher.update(nonce.to_le_bytes());
        hasher.update(payload);

        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result[..32]);
        hash
    }

    /// Adds a raw signature to the message (for backwards compatibility)
    pub fn with_signature(mut self, signature: Vec<u8>) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Returns the message hash as a typed [`Hash`].
    ///
    /// The raw `message_hash: [u8; 32]` field is kept on the wire format for
    /// cross-chain compatibility (external chains see raw bytes), but Tenzro
    /// callers should use this accessor when comparing against other
    /// Tenzro-typed hashes (block hashes, settlement hashes, etc.) so the
    /// type system catches confusion across hash domains.
    pub fn typed_hash(&self) -> Hash {
        Hash::new(self.message_hash)
    }

    /// Signs the message using a tenzro-crypto keypair.
    ///
    /// Creates an Ed25519 or Secp256k1 signature over the `message_hash` field
    /// and stores the signature, public key, and key type for later verification.
    ///
    /// Takes ownership of the keypair because `KeyPair` contains zeroize-on-drop
    /// secret key material and cannot be cloned.
    pub fn sign(&mut self, keypair: tenzro_crypto::KeyPair) -> Result<()> {
        use tenzro_crypto::signatures::{Ed25519SignerImpl, Secp256k1SignerImpl, Signer};

        let key_type = keypair.key_type();
        let public_key_bytes = keypair.public_key().as_bytes().to_vec();

        let signature = match key_type {
            KeyType::Ed25519 => {
                let signer = Ed25519SignerImpl::new(keypair).map_err(|e| {
                    BridgeError::AdapterError(format!("Ed25519 signer creation failed: {}", e))
                })?;
                signer.sign(&self.message_hash).map_err(|e| {
                    BridgeError::AdapterError(format!("Ed25519 signing failed: {}", e))
                })?
            }
            KeyType::Secp256k1 => {
                let signer = Secp256k1SignerImpl::new(keypair).map_err(|e| {
                    BridgeError::AdapterError(format!("Secp256k1 signer creation failed: {}", e))
                })?;
                signer.sign(&self.message_hash).map_err(|e| {
                    BridgeError::AdapterError(format!("Secp256k1 signing failed: {}", e))
                })?
            }
        };

        self.signature = Some(signature.as_bytes().to_vec());
        self.signer_public_key = Some(public_key_bytes);
        self.signer_key_type = Some(match key_type {
            KeyType::Ed25519 => "ed25519".to_string(),
            KeyType::Secp256k1 => "secp256k1".to_string(),
        });
        Ok(())
    }

    /// Encodes the message to bytes
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| BridgeError::SerializationError(e.to_string()))
    }

    /// Decodes a message from bytes
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| BridgeError::SerializationError(e.to_string()))
    }

    /// Verifies the message hash integrity
    pub fn verify_hash(&self) -> bool {
        let expected = Self::compute_hash(
            self.source_chain_id,
            self.dest_chain_id,
            self.nonce,
            &self.payload,
        );
        expected == self.message_hash
    }

    /// Validates the message format
    pub fn validate(&self) -> Result<()> {
        // Check version
        if self.version == 0 || self.version > 1 {
            return Err(BridgeError::AdapterError(format!(
                "Unsupported message version: {}",
                self.version
            )));
        }

        // Check addresses are not empty
        if self.sender.is_empty() {
            return Err(BridgeError::AdapterError(
                "Sender cannot be empty".to_string(),
            ));
        }
        if self.receiver.is_empty() {
            return Err(BridgeError::AdapterError(
                "Receiver cannot be empty".to_string(),
            ));
        }

        // Check timestamp is reasonable
        let now = Timestamp::now().as_millis();
        let msg_time = self.timestamp.as_millis();
        let max_drift = 300_000; // 5 minutes

        if msg_time > now + max_drift {
            return Err(BridgeError::AdapterError(
                "Message timestamp is too far in the future".to_string(),
            ));
        }

        Ok(())
    }

    /// Verifies the message signature using tenzro-crypto.
    ///
    /// Checks that the signature over the `message_hash` is valid for
    /// the stored `signer_public_key` using Ed25519 or Secp256k1 verification.
    pub fn verify_signature(&self) -> Result<bool> {
        let sig_bytes = match &self.signature {
            Some(bytes) if !bytes.is_empty() => bytes,
            _ => return Ok(false),
        };

        let pubkey_bytes = match &self.signer_public_key {
            Some(bytes) if !bytes.is_empty() => bytes,
            _ => {
                // Legacy messages without signer_public_key: can't verify
                tracing::warn!("Message has signature but no signer_public_key — cannot verify");
                return Ok(false);
            }
        };

        // Determine key type
        let key_type = match self.signer_key_type.as_deref() {
            Some("ed25519") => KeyType::Ed25519,
            Some("secp256k1") => KeyType::Secp256k1,
            _ => {
                // Infer from key length: 32 bytes = Ed25519, 33/65 = Secp256k1
                match pubkey_bytes.len() {
                    32 => KeyType::Ed25519,
                    33 | 65 => KeyType::Secp256k1,
                    _ => {
                        return Err(BridgeError::AdapterError(format!(
                            "Cannot determine key type from public key length: {}",
                            pubkey_bytes.len()
                        )));
                    }
                }
            }
        };

        let pubkey = PublicKey::new(key_type, pubkey_bytes.clone());
        let signature = CryptoSignature::new(key_type, sig_bytes.clone());

        match tenzro_crypto::signatures::verify(&pubkey, &self.message_hash, &signature) {
            Ok(()) => Ok(true),
            Err(e) => {
                tracing::debug!("Signature verification failed: {}", e);
                Ok(false)
            }
        }
    }
}

/// Nonce tracker for replay protection
///
/// Tracks used nonces per sender to prevent replay attacks. Each sender must use
/// monotonically increasing nonces, and each (sender, nonce) pair can only be used once.
pub struct NonceTracker {
    /// Map of sender address to their last used nonce
    nonces: Arc<DashMap<String, u64>>,
    /// Optional persistence backend. When set, every check_and_update
    /// writes through to `CF_SETTLEMENTS / bridge_nonce:<scope>:<sender>`
    /// so replay protection survives node restart. Without this,
    /// every cross-chain message processed before the restart becomes
    /// replayable — double-mint on token bridging, double-execute on
    /// arbitrary GMP.
    storage: Option<Arc<dyn tenzro_storage::KvStore>>,
    /// Scope prefix so multiple adapters can share the column family
    /// without collisions (e.g. "wormhole", "hyperlane", "ccip").
    scope: String,
}

impl NonceTracker {
    /// Creates a new nonce tracker (in-memory only — test/dev path).
    pub fn new() -> Self {
        Self {
            nonces: Arc::new(DashMap::new()),
            storage: None,
            scope: String::new(),
        }
    }

    /// Production constructor: write-through to `CF_SETTLEMENTS` with
    /// `scope` prefix. Hydrates on construction.
    pub fn with_storage(
        scope: impl Into<String>,
        storage: Arc<dyn tenzro_storage::KvStore>,
    ) -> Self {
        let t = Self {
            nonces: Arc::new(DashMap::new()),
            storage: Some(storage),
            scope: scope.into(),
        };
        t.hydrate();
        t
    }

    fn key(&self, sender: &str) -> Vec<u8> {
        let mut k = b"bridge_nonce:".to_vec();
        k.extend_from_slice(self.scope.as_bytes());
        k.push(b':');
        k.extend_from_slice(sender.as_bytes());
        k
    }

    fn hydrate(&self) {
        let Some(ref storage) = self.storage else {
            return;
        };
        let mut prefix = b"bridge_nonce:".to_vec();
        prefix.extend_from_slice(self.scope.as_bytes());
        prefix.push(b':');
        let entries = match storage.scan_prefix(tenzro_storage::CF_SETTLEMENTS, &prefix) {
            Ok(e) => e,
            Err(_) => return,
        };
        let prefix_len = prefix.len();
        for (key, value) in entries {
            if key.len() <= prefix_len || value.len() != 8 {
                continue;
            }
            let sender = match std::str::from_utf8(&key[prefix_len..]) {
                Ok(s) => s.to_string(),
                Err(_) => continue,
            };
            let mut buf = [0u8; 8];
            buf.copy_from_slice(&value);
            let last = u64::from_le_bytes(buf);
            self.nonces.insert(sender, last);
        }
    }

    fn persist(&self, sender: &str, nonce: u64) {
        if let Some(ref storage) = self.storage {
            let _ = storage.put(
                tenzro_storage::CF_SETTLEMENTS,
                &self.key(sender),
                &nonce.to_le_bytes(),
            );
        }
    }

    /// Checks if a nonce is valid for a sender and marks it as used
    ///
    /// Returns Ok(()) if the nonce is valid and marks it as used.
    /// Returns Err if the nonce has already been used or is not monotonically increasing.
    pub fn check_and_update(&self, sender: &str, nonce: u64) -> Result<()> {
        let mut entry = self.nonces.entry(sender.to_string()).or_insert(0);

        // Nonce must be strictly greater than the last used nonce
        if nonce <= *entry {
            return Err(BridgeError::AdapterError(format!(
                "Replay attack detected: nonce {} already used by sender {} (last: {})",
                nonce, sender, *entry
            )));
        }

        // Update the last used nonce
        *entry = nonce;
        drop(entry);
        self.persist(sender, nonce);
        Ok(())
    }

    /// Gets the last used nonce for a sender
    pub fn get_last_nonce(&self, sender: &str) -> Option<u64> {
        self.nonces.get(sender).map(|entry| *entry.value())
    }

    /// Clears all tracked nonces (for testing)
    #[cfg(test)]
    pub fn clear(&self) {
        self.nonces.clear();
    }
}

impl Default for NonceTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Load all persisted replay-protection dedup keys for `scope` from
/// `CF_SETTLEMENTS / bridge_seen:<scope>:<key>`. Used by adapters to
/// hydrate their in-memory seen-message maps on construction so replay
/// protection survives node restart.
pub fn load_seen_keys(storage: &Arc<dyn tenzro_storage::KvStore>, scope: &str) -> Vec<String> {
    let mut prefix = b"bridge_seen:".to_vec();
    prefix.extend_from_slice(scope.as_bytes());
    prefix.push(b':');
    let entries = match storage.scan_prefix(tenzro_storage::CF_SETTLEMENTS, &prefix) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let prefix_len = prefix.len();
    entries
        .into_iter()
        .filter_map(|(key, _)| {
            if key.len() <= prefix_len {
                return None;
            }
            std::str::from_utf8(&key[prefix_len..])
                .ok()
                .map(|s| s.to_string())
        })
        .collect()
}

/// Write-through a single replay-protection dedup key to
/// `CF_SETTLEMENTS / bridge_seen:<scope>:<key>`.
pub fn persist_seen_key(storage: &Arc<dyn tenzro_storage::KvStore>, scope: &str, key: &str) {
    let mut k = b"bridge_seen:".to_vec();
    k.extend_from_slice(scope.as_bytes());
    k.push(b':');
    k.extend_from_slice(key.as_bytes());
    let _ = storage.put(tenzro_storage::CF_SETTLEMENTS, &k, b"");
}

/// Runs the standard inner-message verification discipline on a
/// quorum-verified outer body: decode → validate → verify_hash →
/// verify_signature → optional per-sender nonce check.
///
/// Returns `Ok(None)` when the body does not carry a [`TenzroMessage`]
/// (plain provider-native payloads such as Token-Bridge transfers or
/// commit reports), `Ok(Some(message))` when it does and every check
/// passes, and `Err` when the body decodes as a `TenzroMessage` but
/// fails validation.
pub fn verify_inner_message(
    body: &[u8],
    nonce_tracker: Option<&NonceTracker>,
) -> Result<Option<TenzroMessage>> {
    let message = match TenzroMessage::decode(body) {
        Ok(m) => m,
        Err(_) => return Ok(None),
    };
    message.validate()?;
    if !message.verify_hash() {
        return Err(BridgeError::InvalidParameter(
            "inbound TenzroMessage hash mismatch".into(),
        ));
    }
    if message.signature.is_some() && !message.verify_signature().unwrap_or(false) {
        return Err(BridgeError::InvalidParameter(
            "inbound TenzroMessage signature verification failed".into(),
        ));
    }
    if let Some(tracker) = nonce_tracker {
        tracker
            .check_and_update(&message.sender, message.nonce)
            .map_err(|e| BridgeError::ReplayAttack(format!("nonce: {e}")))?;
    }
    Ok(Some(message))
}

/// Type of cross-chain message
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// Token transfer message
    TokenTransfer,
    /// Generic data message
    DataMessage,
    /// Governance action
    GovernanceAction,
    /// AI model registration
    ModelRegistration,
    /// AI agent message
    AgentMessage,
    /// Custom message type
    Custom(u8),
}

impl MessageType {
    /// Returns the message type as a byte
    pub fn as_byte(&self) -> u8 {
        match self {
            Self::TokenTransfer => 0x01,
            Self::DataMessage => 0x02,
            Self::GovernanceAction => 0x03,
            Self::ModelRegistration => 0x04,
            Self::AgentMessage => 0x05,
            Self::Custom(b) => *b,
        }
    }

    /// Creates a message type from a byte
    pub fn from_byte(byte: u8) -> Self {
        match byte {
            0x01 => Self::TokenTransfer,
            0x02 => Self::DataMessage,
            0x03 => Self::GovernanceAction,
            0x04 => Self::ModelRegistration,
            0x05 => Self::AgentMessage,
            b => Self::Custom(b),
        }
    }
}

/// Message envelope with routing metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageEnvelope {
    /// The inner Tenzro message
    pub message: TenzroMessage,
    /// Source chain identifier
    pub source_chain: String,
    /// Destination chain identifier
    pub dest_chain: String,
    /// Bridge protocol used
    pub bridge_protocol: String,
    /// Fee paid for bridging
    pub fee_paid: u128,
    /// Additional routing metadata
    pub metadata: MessageMetadata,
}

impl MessageEnvelope {
    /// Creates a new message envelope
    pub fn new(
        message: TenzroMessage,
        source_chain: impl Into<String>,
        dest_chain: impl Into<String>,
        bridge_protocol: impl Into<String>,
        fee_paid: u128,
    ) -> Self {
        Self {
            message,
            source_chain: source_chain.into(),
            dest_chain: dest_chain.into(),
            bridge_protocol: bridge_protocol.into(),
            fee_paid,
            metadata: MessageMetadata::default(),
        }
    }

    /// Adds metadata to the envelope
    pub fn with_metadata(mut self, metadata: MessageMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Encodes the envelope to bytes
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| BridgeError::SerializationError(e.to_string()))
    }

    /// Decodes an envelope from bytes
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| BridgeError::SerializationError(e.to_string()))
    }

    /// Validates the envelope
    pub fn validate(&self) -> Result<()> {
        // Validate inner message
        self.message.validate()?;

        // Validate routing info
        if self.source_chain.is_empty() {
            return Err(BridgeError::AdapterError(
                "Source chain cannot be empty".to_string(),
            ));
        }
        if self.dest_chain.is_empty() {
            return Err(BridgeError::AdapterError(
                "Destination chain cannot be empty".to_string(),
            ));
        }
        if self.bridge_protocol.is_empty() {
            return Err(BridgeError::AdapterError(
                "Bridge protocol cannot be empty".to_string(),
            ));
        }

        Ok(())
    }
}

/// Additional metadata for message routing
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MessageMetadata {
    /// Gas limit for destination execution
    pub gas_limit: Option<u64>,
    /// Priority level (0 = normal, higher = higher priority)
    pub priority: u8,
    /// Whether delivery proof is required
    pub require_proof: bool,
    /// Custom key-value metadata
    pub custom: Option<serde_json::Value>,
}

impl MessageMetadata {
    /// Creates new message metadata
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the gas limit
    pub fn with_gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = Some(gas_limit);
        self
    }

    /// Sets the priority
    pub fn with_priority(mut self, priority: u8) -> Self {
        self.priority = priority;
        self
    }

    /// Sets whether proof is required
    pub fn with_require_proof(mut self, require_proof: bool) -> Self {
        self.require_proof = require_proof;
        self
    }
}

/// Token transfer payload for TokenTransfer message type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenTransferPayload {
    /// Asset identifier
    pub asset_id: String,
    /// Amount to transfer
    pub amount: u128,
    /// Optional memo
    pub memo: Option<String>,
}

impl TokenTransferPayload {
    /// Creates a new token transfer payload
    pub fn new(asset_id: impl Into<String>, amount: u128) -> Self {
        Self {
            asset_id: asset_id.into(),
            amount,
            memo: None,
        }
    }

    /// Adds a memo
    pub fn with_memo(mut self, memo: impl Into<String>) -> Self {
        self.memo = Some(memo.into());
        self
    }

    /// Encodes the payload to bytes
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| BridgeError::SerializationError(e.to_string()))
    }

    /// Decodes a payload from bytes
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| BridgeError::SerializationError(e.to_string()))
    }
}

/// Agent message payload for AgentMessage type
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentMessagePayload {
    /// Agent ID
    pub agent_id: String,
    /// Action to perform
    pub action: String,
    /// Action parameters
    pub params: serde_json::Value,
}

impl AgentMessagePayload {
    /// Creates a new agent message payload
    pub fn new(
        agent_id: impl Into<String>,
        action: impl Into<String>,
        params: serde_json::Value,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            action: action.into(),
            params,
        }
    }

    /// Encodes the payload to bytes
    pub fn encode(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|e| BridgeError::SerializationError(e.to_string()))
    }

    /// Decodes a payload from bytes
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(|e| BridgeError::SerializationError(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_creation_and_encoding() {
        let payload = TokenTransferPayload::new("TNZO", 1000000).encode().unwrap();

        let message = TenzroMessage::new(
            MessageType::TokenTransfer,
            1,     // source_chain_id
            42161, // dest_chain_id (Arbitrum)
            "sender123",
            "receiver456",
            payload,
            1,
        );

        assert_eq!(message.version, 1);
        assert_eq!(message.nonce, 1);
        assert_eq!(message.source_chain_id, 1);
        assert_eq!(message.dest_chain_id, 42161);

        // Verify hash integrity
        assert!(message.verify_hash());

        let encoded = message.encode().unwrap();
        let decoded = TenzroMessage::decode(&encoded).unwrap();

        assert_eq!(message, decoded);
    }

    #[test]
    fn test_message_validation() {
        let message = TenzroMessage::new(
            MessageType::DataMessage,
            1,
            2,
            "sender",
            "receiver",
            vec![1, 2, 3],
            1,
        );

        assert!(message.validate().is_ok());
    }

    #[test]
    fn test_message_hash_integrity() {
        let message = TenzroMessage::new(
            MessageType::TokenTransfer,
            1,
            2,
            "sender",
            "receiver",
            vec![1, 2, 3, 4, 5],
            100,
        );

        // Hash should be valid
        assert!(message.verify_hash());

        // Modify message and verify hash becomes invalid
        let mut modified = message.clone();
        modified.payload.push(6);
        assert!(!modified.verify_hash());
    }

    #[test]
    fn test_nonce_tracker() {
        let tracker = NonceTracker::new();

        // First nonce should succeed
        assert!(tracker.check_and_update("alice", 1).is_ok());

        // Reusing same nonce should fail
        assert!(tracker.check_and_update("alice", 1).is_err());

        // Lower nonce should fail
        assert!(tracker.check_and_update("alice", 0).is_err());

        // Higher nonce should succeed
        assert!(tracker.check_and_update("alice", 2).is_ok());

        // Different sender should have independent nonce
        assert!(tracker.check_and_update("bob", 1).is_ok());

        // Verify last nonces
        assert_eq!(tracker.get_last_nonce("alice"), Some(2));
        assert_eq!(tracker.get_last_nonce("bob"), Some(1));
        assert_eq!(tracker.get_last_nonce("charlie"), None);
    }

    #[test]
    fn test_sign_and_verify_ed25519() {
        use tenzro_crypto::{KeyPair, KeyType};

        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

        let mut message = TenzroMessage::new(
            MessageType::TokenTransfer,
            1,
            42161,
            "sender",
            "receiver",
            vec![1, 2, 3],
            1,
        );

        // Sign the message
        message.sign(keypair).unwrap();
        assert!(message.signature.is_some());
        assert!(message.signer_public_key.is_some());
        assert_eq!(message.signer_key_type.as_deref(), Some("ed25519"));

        // Verify — should succeed
        assert!(message.verify_signature().unwrap());

        // Tamper with the message hash and verify — should fail
        let mut tampered = message.clone();
        tampered.message_hash[0] ^= 0xFF;
        assert!(!tampered.verify_signature().unwrap());
    }

    #[test]
    fn test_sign_and_verify_secp256k1() {
        use tenzro_crypto::{KeyPair, KeyType};

        let keypair = KeyPair::generate(KeyType::Secp256k1).unwrap();

        let mut message = TenzroMessage::new(
            MessageType::DataMessage,
            1,
            10,
            "sender",
            "receiver",
            vec![4, 5, 6],
            2,
        );

        // Sign the message
        message.sign(keypair).unwrap();
        assert!(message.signature.is_some());
        assert_eq!(message.signer_key_type.as_deref(), Some("secp256k1"));

        // Verify — should succeed
        assert!(message.verify_signature().unwrap());
    }

    #[test]
    fn test_verify_unsigned_message() {
        let message = TenzroMessage::new(
            MessageType::DataMessage,
            1,
            2,
            "sender",
            "receiver",
            vec![1],
            1,
        );

        // No signature → false
        assert!(!message.verify_signature().unwrap());
    }

    #[test]
    fn test_verify_forged_signature() {
        let message = TenzroMessage::new(
            MessageType::TokenTransfer,
            1,
            2,
            "sender",
            "receiver",
            vec![1, 2, 3],
            1,
        );

        // Forge a signature (random bytes)
        let mut forged = message.with_signature(vec![0xDE; 64]);
        forged.signer_public_key = Some(vec![0xAB; 32]);
        forged.signer_key_type = Some("ed25519".to_string());

        // Should fail — random bytes aren't valid Ed25519 key/signature
        // verify_signature returns false on invalid keys/signatures
        let result = forged.verify_signature();
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test]
    fn test_sign_verify_roundtrip_through_serialization() {
        use tenzro_crypto::{KeyPair, KeyType};

        let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();

        let mut message = TenzroMessage::new(
            MessageType::AgentMessage,
            1337,
            1,
            "agent1",
            "agent2",
            vec![10, 20, 30],
            42,
        );

        message.sign(keypair).unwrap();

        // Serialize and deserialize
        let encoded = message.encode().unwrap();
        let decoded = TenzroMessage::decode(&encoded).unwrap();

        // Verify on deserialized message — should still work
        assert!(decoded.verify_signature().unwrap());
        assert!(decoded.verify_hash());
    }

    #[test]
    fn test_envelope_creation() {
        let message = TenzroMessage::new(
            MessageType::TokenTransfer,
            1,
            42161,
            "sender",
            "receiver",
            vec![],
            1,
        );

        let envelope = MessageEnvelope::new(message, "ethereum", "arbitrum", "LayerZero", 100000);

        assert_eq!(envelope.source_chain, "ethereum");
        assert_eq!(envelope.dest_chain, "arbitrum");
        assert!(envelope.validate().is_ok());
    }
}
