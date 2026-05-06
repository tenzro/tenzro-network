//! Network message types for Tenzro Network

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tenzro_types::{
    Block, SignedTransaction, Hash,
    ModelClass, ArtifactCompleteness, ArtifactMetadata, ModelTopology, ExecutionSupport,
    RuntimeSupport, NodeNetworkProfile, TrustProfile, WorkerRole,
};

/// Network message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMessage {
    /// Message type and payload
    pub payload: MessagePayload,
    /// Message ID for deduplication
    pub message_id: String,
    /// Timestamp when message was created
    pub timestamp: i64,
}

impl NetworkMessage {
    /// Creates a new network message
    pub fn new(payload: MessagePayload) -> Self {
        Self {
            payload,
            message_id: uuid::Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now().timestamp_millis(),
        }
    }

    /// Serializes the message to bytes using bincode.
    ///
    /// Wire format: bincode (length-prefixed varint sequences). Bincode is used
    /// rather than `serde_json` because consensus payloads embed `Block` and
    /// `Transaction` types that carry `u128` fields (token amounts, gas), and
    /// `serde_json` does not support `u128` without `arbitrary_precision`.
    /// Mismatched encoders/decoders previously caused honest peers to silently
    /// drop each other's votes, stalling consensus.
    pub fn to_bytes(&self) -> Result<Bytes, bincode::Error> {
        let buf = bincode::serialize(self)?;
        Ok(Bytes::from(buf))
    }

    /// Deserializes a message from bincode bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Returns the message topic
    pub fn topic(&self) -> &str {
        self.payload.topic()
    }
}

/// Message payload types.
///
/// Uses serde's default externally-tagged enum representation
/// (`{"Variant": payload}` in JSON, `u32` discriminant + payload in bincode).
/// Adjacently/internally tagged forms (`#[serde(tag = "...", content = "...")]`)
/// route through `serialize_struct`/`deserialize_identifier`, which bincode 1.x
/// does not support — receivers reject every gossip message with
/// "Bincode does not support Deserializer::deserialize_identifier", stalling
/// consensus. See bincode-org/bincode#272 and #548.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessagePayload {
    /// New block announcement
    Block(Block),

    /// Block request by hash
    BlockRequest(Hash),

    /// Block response
    BlockResponse(Option<Block>),

    /// Transaction broadcast
    Transaction(SignedTransaction),

    /// Transaction request
    TransactionRequest(Hash),

    /// Transaction response
    TransactionResponse(Option<SignedTransaction>),

    /// Consensus message (votes, proposals)
    Consensus(ConsensusMessage),

    /// TEE attestation
    Attestation(AttestationMessage),

    /// Model inference request
    InferenceRequest(InferenceRequestMessage),

    /// Model inference response
    InferenceResponse(InferenceResponseMessage),

    /// Model registration
    ModelRegistration(ModelRegistrationMessage),

    /// Agent announcement — broadcast by nodes that have registered agents
    /// so all peers can populate their network_agents cache.
    AgentAnnouncement(AgentAnnouncementMessage),

    /// Provider announcement — broadcast by nodes serving models/TEE so all
    /// peers can populate their network_providers cache.
    ProviderAnnouncement(ProviderAnnouncementMessage),

    /// Peer status update
    Status(StatusMessage),

    /// Ping message
    Ping,

    /// Pong response
    Pong,

    /// Custom application message
    Custom { topic: String, data: Vec<u8> },
}

impl MessagePayload {
    /// Returns the topic for this message type
    pub fn topic(&self) -> &str {
        match self {
            Self::Block(_) | Self::BlockRequest(_) | Self::BlockResponse(_) => "tenzro/blocks",
            Self::Transaction(_) | Self::TransactionRequest(_) | Self::TransactionResponse(_) => {
                "tenzro/transactions"
            }
            Self::Consensus(_) => "tenzro/consensus",
            Self::Attestation(_) => "tenzro/attestations",
            Self::InferenceRequest(_) | Self::InferenceResponse(_) => "tenzro/inference",
            Self::ModelRegistration(_) => "tenzro/models",
            Self::AgentAnnouncement(_) => "tenzro/agents",
            Self::ProviderAnnouncement(_) => "tenzro/providers",
            Self::Status(_) | Self::Ping | Self::Pong => "tenzro/status",
            Self::Custom { topic, .. } => topic,
        }
    }
}

/// Consensus message types.
///
/// Uses serde's default externally-tagged enum representation. See
/// `MessagePayload` above for the rationale — `#[serde(tag = "...")]` is
/// internally-tagged and incompatible with bincode 1.x.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusMessage {
    /// Block proposal.
    ///
    /// `timeout_certificate` is `Some(_)` only when the leader is recovering
    /// from a view timeout — it carries the bincode-serialized
    /// `tenzro_consensus::timeout::TimeoutCertificate` (2f+1 timeout signatures
    /// from the previous view) so peers can verify the new view was
    /// legitimately abandoned (Jolteon `safe_to_extend`, DiemBFT v4 §3.5).
    ///
    /// `high_qc_view` is the proposer's local highest-Prepare-QC view at the
    /// moment of proposing (#171, Aptos SyncInfo pattern). Receivers adopt it
    /// if higher than their own to fast-forward the lagging-replica case.
    /// Must satisfy `high_qc_view < block.header.view`.
    Proposal {
        block: Box<Block>,
        proposer: String,
        round: u64,
        high_qc_view: u64,
        /// bincode-serialized `tenzro_consensus::timeout::TimeoutCertificate`,
        /// or `None` for the steady-state happy path.
        timeout_certificate: Option<Vec<u8>>,
        /// bincode-serialized
        /// `tenzro_consensus::timeout::NoEndorsementCertificate`. Carries f+1
        /// no-endorsement signatures attesting that no Prepare-QC formed at
        /// the timed-out view (MonadBFT, arXiv:2502.20692). `Some(_)` is
        /// required when the leader is proposing a fresh block after a TC
        /// — receivers reject an unaccompanied fresh block. `None` for the
        /// steady-state happy path AND when the leader is reproposing the
        /// existing high-tip block (the parent-hash match suffices).
        no_endorsement_certificate: Option<Vec<u8>>,
    },
    /// Vote on a proposal
    ///
    /// Carries a hybrid (Ed25519 + ML-DSA-65) signature and the voter's
    /// composite public key so peers can verify both legs without an
    /// out-of-band registry lookup. The two opaque blobs are bincode-
    /// serialized `CompositeSignature` / `CompositePublicKey` from
    /// `tenzro_crypto::composite`.
    ///
    /// `high_qc_view` is the voter's local highest-Prepare-QC view at the
    /// moment of voting (#171, Aptos SyncInfo). Bound into the vote's signing
    /// payload — must match the bound on the inner `Vote` or signature
    /// verification fails.
    Vote {
        block_hash: Hash,
        voter: String,
        vote_type: VoteType,
        round: u64,
        height: u64,
        high_qc_view: u64,
        /// bincode-serialized `tenzro_crypto::composite::CompositeSignature`
        signature: Vec<u8>,
        /// bincode-serialized `tenzro_crypto::composite::CompositePublicKey`
        public_key: Vec<u8>,
    },
    /// Commit message
    Commit {
        block_hash: Hash,
        signatures: Vec<Vec<u8>>,
    },
    /// Pacemaker timeout broadcast (DiemBFT v4 §3.5).
    ///
    /// Sent on local view-timer expiry. Receivers at a strictly lower view
    /// adopt `view` (subject to `MAX_VIEW_JUMP` cap in the consensus engine).
    /// This is the backward-sync channel that prevents two honest replicas
    /// from drifting apart by N views under partial synchrony.
    ///
    /// The two opaque blobs are bincode-serialized `CompositeSignature` /
    /// `CompositePublicKey` from `tenzro_crypto::composite`, mirroring the
    /// Vote variant. Format version is pinned by
    /// `tenzro_consensus::TIMEOUT_MSG_FORMAT_VERSION`.
    Timeout {
        format_version: u8,
        view: u64,
        /// Highest Prepare-QC view this voter has observed (≤ `view - 1`).
        /// Aggregated by the receiver into the TC's `max_high_qc_view()` so
        /// the next leader can compute the Jolteon `safe_to_extend` predicate.
        high_qc_view: u64,
        voter: tenzro_types::primitives::Address,
        /// bincode-serialized `tenzro_crypto::composite::CompositeSignature`
        signature: Vec<u8>,
        /// bincode-serialized `tenzro_crypto::composite::CompositePublicKey`
        public_key: Vec<u8>,
    },
    /// MonadBFT no-endorsement attestation broadcast (arXiv:2502.20692).
    ///
    /// Sent on local view-timer expiry alongside the Timeout broadcast.
    /// Aggregated by the receiver into a `NoEndorsementCertificate` (f+1
    /// signatures) which the next leader attaches to a fresh block proposal
    /// after the timed-out view. The f+1 threshold is the smallest set that
    /// guarantees at least one honest signer — and any honest signer would
    /// refuse to sign if it had observed a Prepare-QC at the timed-out view,
    /// so the NEC is unforgeable evidence that no QC formed.
    ///
    /// The two opaque blobs mirror the Vote / Timeout variants — bincode-
    /// serialized `CompositeSignature` / `CompositePublicKey`. Format version
    /// is pinned by `tenzro_consensus::NO_ENDORSEMENT_MSG_FORMAT_VERSION`.
    NoEndorsement {
        format_version: u8,
        view: u64,
        voter: tenzro_types::primitives::Address,
        /// bincode-serialized `tenzro_crypto::composite::CompositeSignature`
        signature: Vec<u8>,
        /// bincode-serialized `tenzro_crypto::composite::CompositePublicKey`
        public_key: Vec<u8>,
    },
}

/// Vote types for consensus
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum VoteType {
    /// Prevote
    Prevote,
    /// Precommit
    Precommit,
}

/// TEE attestation message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationMessage {
    /// Provider identifier
    pub provider_id: String,
    /// Attestation report (vendor-specific)
    pub report: Vec<u8>,
    /// Report signature
    pub signature: Vec<u8>,
    /// Timestamp
    pub timestamp: i64,
}

/// Inference request message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRequestMessage {
    /// Request ID
    pub request_id: String,
    /// Model identifier
    pub model_id: String,
    /// Input data
    pub input: Vec<u8>,
    /// Requester address
    pub requester: String,
    /// Payment details
    pub payment: PaymentDetails,
}

/// Inference response message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceResponseMessage {
    /// Request ID this responds to
    pub request_id: String,
    /// Provider identifier
    pub provider_id: String,
    /// Output data
    pub output: Vec<u8>,
    /// Computation proof (optional)
    pub proof: Option<Vec<u8>>,
}

/// Model registration message — broadcast over gossipsub when a provider
/// starts serving a model to the network.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ModelRegistrationMessage {
    /// Model identifier
    pub model_id: String,
    /// Model name
    pub name: String,
    /// Model description
    pub description: String,
    /// Model modality
    pub modality: String,
    /// Model category (e.g. "chat", "completion", "embedding")
    #[serde(default)]
    pub category: String,
    /// Model parameters (e.g. "3B", "0.8B")
    #[serde(default)]
    pub parameters: String,
    /// Model context length
    #[serde(default)]
    pub context_length: u32,
    /// Provider address
    pub provider: String,
    /// Provider's libp2p peer ID (for direct routing)
    #[serde(default)]
    pub peer_id: String,
    /// Pricing information
    pub pricing: PricingInfo,
    /// Serving schedule (when this model is available)
    #[serde(default)]
    pub schedule: Option<ModelSchedule>,
    /// Visibility: "network" (gossipsub-discoverable) or "local" (this node only)
    #[serde(default = "default_visibility")]
    pub visibility: String,
    /// TTL in seconds — entries expire if not refreshed (default 120s)
    #[serde(default = "default_ttl")]
    pub ttl_secs: u64,
    /// Whether this is a withdrawal (model stopped serving)
    #[serde(default)]
    pub withdrawn: bool,
    /// RPC endpoint for inference requests (e.g. "http://10.128.0.3:8545")
    #[serde(default)]
    pub rpc_endpoint: String,
    /// RFC-0007: High-level model class classification
    #[serde(default)]
    pub model_class: ModelClass,
    /// RFC-0007: Which artifact types are present, determining supported execution modes
    #[serde(default)]
    pub artifact_completeness: ArtifactCompleteness,
    /// RFC-0007: Downloadable artifact descriptors (weights, shards, tokenizers)
    #[serde(default)]
    pub artifacts: Vec<ArtifactMetadata>,
    /// RFC-0007: Internal topology metadata for MoE and large-scale models
    #[serde(default)]
    pub topology: ModelTopology,
    /// RFC-0007: Execution modes this provider can serve for this model
    #[serde(default)]
    pub execution_support: ExecutionSupport,
}

fn default_visibility() -> String {
    "network".to_string()
}

fn default_ttl() -> u64 {
    120
}

fn default_agent_ttl() -> u64 {
    180
}

fn default_provider_ttl() -> u64 {
    120
}

/// Agent announcement message — broadcast over gossipsub topic "tenzro/agents"
/// every 60s by nodes that have registered agents. All peers merge incoming
/// announcements into their `network_agents` DashMap so any node can discover
/// every agent in the network without a central registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentAnnouncementMessage {
    /// Agent identifier
    pub agent_id: String,
    /// Human-readable agent name
    pub name: String,
    /// Agent type (e.g. "tenzroclaw", "custom")
    #[serde(default)]
    pub agent_type: String,
    /// Capability names this agent exposes
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Lifecycle status (e.g. "active", "suspended")
    #[serde(default)]
    pub status: String,
    /// libp2p peer ID of the originating node
    #[serde(default)]
    pub origin_peer_id: String,
    /// RPC endpoint of the originating node (for direct routing)
    #[serde(default)]
    pub rpc_endpoint: String,
    /// Unix timestamp (ms) when this announcement was created
    pub timestamp: i64,
    /// TTL in seconds — entries expire if not refreshed (default 180s)
    #[serde(default = "default_agent_ttl")]
    pub ttl_secs: u64,
}

/// Provider announcement message — broadcast over gossipsub topic "tenzro/providers"
/// every 60s by nodes serving models or TEE services. All peers merge incoming
/// announcements into their `network_providers` DashMap so any node can discover
/// every provider in the network without a central registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderAnnouncementMessage {
    /// libp2p peer ID of the announcing node
    pub peer_id: String,
    /// Wallet/account address of the provider
    pub provider_address: String,
    /// Provider type (e.g. "llm", "tee", "general")
    #[serde(default)]
    pub provider_type: String,
    /// Model IDs currently being served by this node
    #[serde(default)]
    pub served_models: Vec<String>,
    /// Capability labels (e.g. "inference", "tee-attestation")
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// HTTP RPC endpoint for direct inference routing (e.g. "http://10.128.0.5:8545")
    #[serde(default)]
    pub rpc_endpoint: String,
    /// Lifecycle status (e.g. "active", "draining")
    #[serde(default)]
    pub status: String,
    /// Unix timestamp (ms) when this announcement was created
    pub timestamp: i64,
    /// TTL in seconds — entries expire if not refreshed (default 120s)
    #[serde(default = "default_provider_ttl")]
    pub ttl_secs: u64,
    /// RFC-0007: Runtime capabilities of this provider node
    #[serde(default)]
    pub runtime_support: RuntimeSupport,
    /// RFC-0007: Network topology profile of this node
    #[serde(default)]
    pub network_profile: NodeNetworkProfile,
    /// RFC-0007: TEE trust provenance for this provider
    #[serde(default)]
    pub trust_profile: TrustProfile,
    /// RFC-0007: Worker roles this node can fulfil in distributed inference
    #[serde(default)]
    pub worker_roles: Vec<WorkerRole>,
}

/// Schedule for when a model is available for serving
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelSchedule {
    /// Whether scheduling is enabled (if false, model is always available)
    pub enabled: bool,
    /// Start hour (0-23) in the provider's timezone
    #[serde(default)]
    pub start_hour: u8,
    /// End hour (0-23) in the provider's timezone
    #[serde(default = "default_end_hour")]
    pub end_hour: u8,
    /// Timezone (e.g. "UTC", "America/New_York")
    #[serde(default = "default_timezone")]
    pub timezone: String,
    /// Days of the week the model is available (0=Sun, 1=Mon, ..., 6=Sat)
    #[serde(default = "default_days")]
    pub days_of_week: Vec<u8>,
}

fn default_end_hour() -> u8 {
    23
}

fn default_timezone() -> String {
    "UTC".to_string()
}

fn default_days() -> Vec<u8> {
    vec![0, 1, 2, 3, 4, 5, 6]
}

/// Payment details for inference requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentDetails {
    /// Amount in TNZO
    pub amount: u64,
    /// Payment transaction hash
    pub tx_hash: Option<Hash>,
}

/// Pricing information for models
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PricingInfo {
    /// Price per request in TNZO
    pub per_request: u64,
    /// Price per token (for LLMs)
    pub per_token: Option<u64>,
}

/// Status message for peer synchronization.
///
/// Broadcast on `tenzro/status` every 10s by every node and consumed
/// by `PeerStatusTracker` to compute a network-tip estimate for `eth_syncing`.
/// `peer_id` is embedded so subscribers can attribute the message to a sender —
/// gossipsub does not surface the originating PeerId to topic subscribers,
/// only to the swarm event handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusMessage {
    /// libp2p PeerId of the sender, base58-encoded. Subscribers parse this
    /// back into a `PeerId` via `PeerId::from_str`. Required so the
    /// `PeerStatusTracker` can key entries by peer.
    pub peer_id: String,
    /// Current best block hash
    pub best_block: Hash,
    /// Current block height
    pub height: u64,
    /// Chain ID
    pub chain_id: u64,
    /// Protocol version
    pub protocol_version: String,
}

/// Message validation
pub fn validate_message(msg: &NetworkMessage) -> crate::error::Result<()> {
    // Check timestamp is not too far in the future (allow 5 minute clock skew)
    let now = chrono::Utc::now().timestamp_millis();
    if msg.timestamp > now + 300_000 {
        return Err(crate::error::NetworkError::InvalidMessage("Message timestamp is too far in the future".to_string()));
    }

    // Check message is not too old (reject messages older than 1 hour)
    if now - msg.timestamp > 3_600_000 {
        return Err(crate::error::NetworkError::InvalidMessage("Message is too old".to_string()));
    }

    // Additional payload-specific validation
    match &msg.payload {
        MessagePayload::Block(block) => {
            if block.header.height.0 == 0 && block.header.prev_hash != Hash::zero() {
                return Err(crate::error::NetworkError::InvalidMessage("Genesis block must have zero prev_hash".to_string()));
            }
        }
        MessagePayload::InferenceRequest(req) => {
            if req.request_id.is_empty() {
                return Err(crate::error::NetworkError::InvalidMessage("Inference request must have a request ID".to_string()));
            }
            if req.model_id.is_empty() {
                return Err(crate::error::NetworkError::InvalidMessage("Inference request must specify a model ID".to_string()));
            }
        }
        _ => {}
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let msg = NetworkMessage::new(MessagePayload::Ping);
        let bytes = msg.to_bytes().unwrap();
        let decoded = NetworkMessage::from_bytes(&bytes).unwrap();

        assert_eq!(msg.message_id, decoded.message_id);
        assert_eq!(msg.timestamp, decoded.timestamp);
    }

    #[test]
    fn test_message_topics() {
        assert_eq!(MessagePayload::Ping.topic(), "tenzro/status");
        assert_eq!(
            MessagePayload::Custom {
                topic: "test/topic".to_string(),
                data: vec![]
            }
            .topic(),
            "test/topic"
        );
    }
}
