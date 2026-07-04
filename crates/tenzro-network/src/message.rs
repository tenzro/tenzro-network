//! Network message types for Tenzro Network

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tenzro_types::{
    Block, SignedTransaction, Hash,
    ModelClass, ArtifactCompleteness, ArtifactMetadata, ModelTopology, ExecutionSupport,
    RuntimeSupport, NodeNetworkProfile, TrustProfile, WorkerRole,
    HardwareCapabilities,
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

    /// Blob availability announcement — broadcast by nodes whose iroh blob
    /// store holds content so peers can populate their blob-provider hint
    /// caches and fetch `tenzro://blob/...` URIs without an explicit
    /// provider hint.
    BlobAnnouncement(BlobAnnouncementMessage),

    /// Shard replication request — broadcast by the origin node after it
    /// erasure-encodes and stores an object, listing every shard's blob hash
    /// and commitment. Storage-capable peers run rendezvous (HRW)
    /// self-selection per shard and pin the shards they rank for, spreading
    /// the object across independent providers.
    ShardReplication(ShardReplicationMessage),

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
            Self::Attestation(_) => "tenzro/attestations",
            Self::InferenceRequest(_) | Self::InferenceResponse(_) => "tenzro/inference",
            Self::ModelRegistration(_) => "tenzro/models",
            Self::AgentAnnouncement(_) => "tenzro/agents",
            Self::ProviderAnnouncement(_) => "tenzro/providers",
            Self::BlobAnnouncement(_) | Self::ShardReplication(_) => "tenzro/blobs",
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
        /// bincode-serialized `tenzro_crypto::composite::CompositeSignature`
        /// — the leader's hybrid (Ed25519 + ML-DSA-65) signature over the
        /// canonical proposal payload (`view || height || block_hash ||
        /// high_qc_view`). Receivers verify it against the proposer's
        /// REGISTERED composite key before acting on the proposal, making
        /// proposals attributable (proposal-equivocation slashing) and
        /// authenticating the `high_qc_view` SyncInfo hint.
        proposer_signature: Vec<u8>,
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
        /// Raw 96-byte BLS12-381 G2 signature over the canonical QC payload
        /// (`TENZRO_QC_BLS:` || vote_format_version || view || height || block_hash
        /// || vote_type`). Aggregated by `VoteCollector` into the QC's
        /// `bls_aggregate`.
        bls_signature: Vec<u8>,
    },
    /// Commit message
    Commit {
        block_hash: Hash,
        signatures: Vec<Vec<u8>>,
    },
    /// Pacemaker timeout broadcast (DiemBFT v4 §3.5).
    ///
    /// Sent on local view-timer expiry. Receivers at a strictly lower view
    /// adopt `view` after verifying the sender's hybrid signature — the
    /// signature is the cryptographic gate (DiemBFT v4 §3.5
    /// `process_remote_timeout`); no numeric jump cap is applied, since
    /// stuck replicas may legitimately need to sync forward by many
    /// thousands of views. This is the backward-sync channel that
    /// prevents two honest replicas from drifting apart under partial
    /// synchrony.
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
        /// The sender's highest finalized block height. Part of the signed
        /// payload. Receivers behind this height engage block-sync — the heal
        /// path for single-block finalization skew (one replica finalized via
        /// a Commit QC the others never received).
        finalized_height: u64,
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
    /// Unix timestamp (ms) when this announcement was created. Covered by
    /// the signature; consumers reject announcements older than `ttl_secs`
    /// or dated in the future, so a captured announcement can't be replayed
    /// after the provider stops serving or changes its endpoint.
    pub timestamp: i64,
    /// Whether this is a withdrawal (model stopped serving)
    #[serde(default)]
    pub withdrawn: bool,
    /// RPC endpoint for inference requests (e.g. "http://10.128.0.3:8545")
    #[serde(default)]
    pub rpc_endpoint: String,
    /// Provider's iroh `EndpointId` (hex) for peer-identity-addressed
    /// inference dispatch over the `tenzro/infer` ALPN. Empty when the
    /// provider has no iroh endpoint bound. Consumers prefer this over
    /// `rpc_endpoint` because it works across NAT without a reachable
    /// public HTTP address; `rpc_endpoint` stays as an opportunistic
    /// fallback for nodes that do expose a dialable endpoint.
    #[serde(default)]
    pub iroh_endpoint_id: String,
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
    /// SHA-256 (hex) of the served GGUF weights, computed by the provider at
    /// load time. Lets any peer that serves the same `model_id` — or a
    /// verifier — detect a provider serving substituted/poisoned weights by
    /// comparing hashes across announcements. Empty when the provider did not
    /// compute it (e.g. clustered load spanning multiple files).
    #[serde(default)]
    pub weights_sha256: String,
    /// Ed25519 public key (raw 32B) of the announcing provider. Empty on
    /// legacy/unsigned announcements, which consumers reject.
    #[serde(default)]
    pub pubkey: Vec<u8>,
    /// Ed25519 signature over the canonical preimage. Empty on unsigned
    /// announcements, which consumers reject.
    #[serde(default)]
    pub signature: Vec<u8>,
}

/// Domain-separation tags for announcement signatures. Each announcement
/// type signs `tag || serde_json(message with signature cleared)`, so a
/// signature over one announcement type can never be replayed as another
/// even though all three are signed by the same node key.
const MODEL_ANNOUNCE_DOMAIN: &[u8] = b"tenzro/announce/model";
const AGENT_ANNOUNCE_DOMAIN: &[u8] = b"tenzro/announce/agent";
const PROVIDER_ANNOUNCE_DOMAIN: &[u8] = b"tenzro/announce/provider";
const BLOB_ANNOUNCE_DOMAIN: &[u8] = b"tenzro/announce/blobs";
const SHARD_REPLICATION_DOMAIN: &[u8] = b"tenzro/announce/shard-replication";

/// Builds the canonical signing preimage for an announcement: the domain
/// tag followed by the JSON serialization of the message. The message must
/// already have `pubkey` populated and `signature` cleared, so the entire
/// announcement — every routable, priceable, or freshness-relevant field —
/// is covered by the signature. Fields added later are covered
/// automatically instead of silently becoming replay-mutable.
fn announce_preimage<T: Serialize>(domain: &[u8], msg: &T) -> Result<Vec<u8>, String> {
    let body = serde_json::to_vec(msg).map_err(|e| e.to_string())?;
    let mut preimage = Vec::with_capacity(domain.len() + body.len());
    preimage.extend_from_slice(domain);
    preimage.extend_from_slice(&body);
    Ok(preimage)
}

fn verify_announce_signature<T: Serialize>(
    domain: &[u8],
    unsigned: &T,
    pubkey: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    use tenzro_crypto::{
        keys::{KeyType, PublicKey},
        signatures::{verify, Signature},
    };
    let preimage = announce_preimage(domain, unsigned)?;
    let pk = PublicKey::new(KeyType::Ed25519, pubkey.to_vec());
    let sig = Signature::new(KeyType::Ed25519, signature.to_vec());
    verify(&pk, &preimage, &sig).map_err(|e| e.to_string())
}

impl ModelRegistrationMessage {
    /// Sign this announcement with the provider's Ed25519 key, populating
    /// `pubkey` + `signature`. Call after all fields are set.
    pub fn sign(
        &mut self,
        signer: &dyn tenzro_crypto::signatures::Signer,
    ) -> Result<(), String> {
        self.pubkey = signer.public_key().as_bytes().to_vec();
        self.signature = Vec::new();
        let preimage = announce_preimage(MODEL_ANNOUNCE_DOMAIN, self)?;
        let sig = signer.sign(&preimage).map_err(|e| e.to_string())?;
        self.signature = sig.as_bytes().to_vec();
        Ok(())
    }

    /// Verify the embedded signature over the full announcement. Returns an
    /// error for unsigned (empty `pubkey`/`signature`) or tampered messages.
    pub fn verify(&self) -> Result<(), String> {
        if self.pubkey.is_empty() || self.signature.is_empty() {
            return Err("unsigned model announcement".to_string());
        }
        let mut unsigned = self.clone();
        unsigned.signature = Vec::new();
        verify_announce_signature(
            MODEL_ANNOUNCE_DOMAIN,
            &unsigned,
            &self.pubkey,
            &self.signature,
        )
    }
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
    /// Ed25519 public key (raw 32B) of the announcing node. Empty on
    /// unsigned announcements, which consumers reject.
    #[serde(default)]
    pub pubkey: Vec<u8>,
    /// Ed25519 signature over the canonical preimage. Empty on unsigned
    /// announcements, which consumers reject.
    #[serde(default)]
    pub signature: Vec<u8>,
}

impl AgentAnnouncementMessage {
    /// Sign this announcement with the node's Ed25519 announce key,
    /// populating `pubkey` + `signature`. Call after all fields are set —
    /// the signature covers the entire struct.
    pub fn sign(&mut self, signer: &dyn tenzro_crypto::signatures::Signer) -> Result<(), String> {
        self.pubkey = signer.public_key().as_bytes().to_vec();
        self.signature = Vec::new();
        let preimage = announce_preimage(AGENT_ANNOUNCE_DOMAIN, self)?;
        let sig = signer.sign(&preimage).map_err(|e| e.to_string())?;
        self.signature = sig.as_bytes().to_vec();
        Ok(())
    }

    /// Verify the embedded signature over the whole-struct preimage. Returns
    /// an error for unsigned (empty `pubkey`/`signature`) or tampered messages.
    pub fn verify(&self) -> Result<(), String> {
        if self.pubkey.is_empty() || self.signature.is_empty() {
            return Err("unsigned agent announcement".to_string());
        }
        let mut unsigned = self.clone();
        unsigned.signature = Vec::new();
        verify_announce_signature(
            AGENT_ANNOUNCE_DOMAIN,
            &unsigned,
            &self.pubkey,
            &self.signature,
        )
    }
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
    /// Hardware envelope of this provider node — RAM, VRAM, disk, CPU, TEE
    /// availability. Populated at announcement-build time from the local
    /// `HardwareCapabilities::detect()` result so consumers can route by
    /// memory / GPU / TEE class without an extra RPC round-trip.
    #[serde(default)]
    pub hardware: HardwareCapabilities,
    /// Geographic locality declared by the operator (free-form identifier
    /// such as `us-central1-a`, `eu-west`, `ap-southeast-1`). `None` means
    /// the provider declined to declare a region; consumers must treat
    /// `None` as "unknown geography", not as a wildcard match.
    #[serde(default)]
    pub geography: Option<String>,
    /// iroh `EndpointId` of this node (lowercase hex) — the dialable
    /// identity on the iroh data plane. Consumers use it as the candidate
    /// identity for rendezvous shard placement and for peer-first blob
    /// fetches. Empty when the node has no iroh resolver bound.
    #[serde(default)]
    pub iroh_endpoint_id: String,
    /// LAN-cluster serving profile, present only when this node is willing
    /// to join LAN pipeline clusters. Carries the llama.cpp commit, serving
    /// backend / capability key, and ggml `rpc-server` socket a head needs
    /// to admit this node as a pipeline member. `None` means single-box
    /// serving only — the node will not be auto-clustered.
    #[serde(default)]
    pub cluster_profile: Option<tenzro_types::ClusterProfile>,
    /// Ed25519 public key (raw 32B) of the announcing provider. Empty on
    /// legacy/unsigned announcements, which consumers reject.
    #[serde(default)]
    pub pubkey: Vec<u8>,
    /// Ed25519 signature over the canonical preimage. Empty on unsigned
    /// announcements, which consumers reject.
    #[serde(default)]
    pub signature: Vec<u8>,
}

impl ProviderAnnouncementMessage {
    /// Sign this announcement with the provider's Ed25519 announce key,
    /// populating `pubkey` + `signature`. Call after all fields are set —
    /// the signature covers the entire struct (endpoint, served models,
    /// hardware, status, timestamp, ttl), so no field can be mutated
    /// post-signing without invalidating the signature.
    pub fn sign(&mut self, signer: &dyn tenzro_crypto::signatures::Signer) -> Result<(), String> {
        self.pubkey = signer.public_key().as_bytes().to_vec();
        self.signature = Vec::new();
        let preimage = announce_preimage(PROVIDER_ANNOUNCE_DOMAIN, self)?;
        let sig = signer.sign(&preimage).map_err(|e| e.to_string())?;
        self.signature = sig.as_bytes().to_vec();
        Ok(())
    }

    /// Verify the embedded signature over the whole-struct preimage. Returns
    /// an error for unsigned (empty `pubkey`/`signature`) or tampered messages.
    pub fn verify(&self) -> Result<(), String> {
        if self.pubkey.is_empty() || self.signature.is_empty() {
            return Err("unsigned provider announcement".to_string());
        }
        let mut unsigned = self.clone();
        unsigned.signature = Vec::new();
        verify_announce_signature(
            PROVIDER_ANNOUNCE_DOMAIN,
            &unsigned,
            &self.pubkey,
            &self.signature,
        )
    }
}

fn default_blob_ttl() -> u64 {
    180
}

/// Blob availability announcement — broadcast over gossipsub topic
/// "tenzro/blobs" by nodes whose iroh blob store holds content. Peers
/// verify the signature and record `endpoint_id` as a provider for each
/// listed hash in the resolver's hint cache, so hint-less
/// `tenzro://blob/...` fetches can dial announced holders.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobAnnouncementMessage {
    /// iroh `EndpointId` of the announcing node, lowercase hex — the
    /// dialable identity on the iroh data plane (distinct from the libp2p
    /// peer id on the control plane).
    pub endpoint_id: String,
    /// BLAKE3 hex hashes of blobs held in the announcer's store. Producers
    /// chunk large stores across multiple announcements.
    pub blob_hashes: Vec<String>,
    /// libp2p peer ID of the originating node
    #[serde(default)]
    pub origin_peer_id: String,
    /// Unix timestamp (ms) when this announcement was created
    pub timestamp: i64,
    /// TTL in seconds — consumers reject announcements older than this
    /// (default 180s)
    #[serde(default = "default_blob_ttl")]
    pub ttl_secs: u64,
    /// Ed25519 public key (raw 32B) of the announcing node. Empty on
    /// unsigned announcements, which consumers reject.
    #[serde(default)]
    pub pubkey: Vec<u8>,
    /// Ed25519 signature over the canonical preimage. Empty on unsigned
    /// announcements, which consumers reject.
    #[serde(default)]
    pub signature: Vec<u8>,
}

impl BlobAnnouncementMessage {
    /// Sign this announcement with the node's Ed25519 announce key,
    /// populating `pubkey` + `signature`. Call after all fields are set —
    /// the signature covers the entire struct.
    pub fn sign(&mut self, signer: &dyn tenzro_crypto::signatures::Signer) -> Result<(), String> {
        self.pubkey = signer.public_key().as_bytes().to_vec();
        self.signature = Vec::new();
        let preimage = announce_preimage(BLOB_ANNOUNCE_DOMAIN, self)?;
        let sig = signer.sign(&preimage).map_err(|e| e.to_string())?;
        self.signature = sig.as_bytes().to_vec();
        Ok(())
    }

    /// Verify the embedded signature over the whole-struct preimage. Returns
    /// an error for unsigned (empty `pubkey`/`signature`) or tampered messages.
    pub fn verify(&self) -> Result<(), String> {
        if self.pubkey.is_empty() || self.signature.is_empty() {
            return Err("unsigned blob announcement".to_string());
        }
        let mut unsigned = self.clone();
        unsigned.signature = Vec::new();
        verify_announce_signature(
            BLOB_ANNOUNCE_DOMAIN,
            &unsigned,
            &self.pubkey,
            &self.signature,
        )
    }
}

/// One shard entry inside a [`ShardReplicationMessage`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardReplicationEntry {
    /// Shard index within the erasure-coded object (0-based; indices below
    /// `k` are data shards, the rest parity).
    pub index: usize,
    /// BLAKE3 hex hash of the shard bytes — the iroh blob identity peers
    /// fetch and pin.
    pub blob_hash: String,
    /// SHA-256 hex commitment of the shard bytes — the placement key and
    /// retrievability-challenge identity.
    pub commitment: String,
}

/// Shard replication request — broadcast over gossipsub topic "tenzro/blobs"
/// by the origin node right after it erasure-encodes and stores an object.
/// Storage-capable peers verify the signature, run rendezvous (HRW)
/// self-selection per shard against their local membership view, and pin
/// (fetch + publish) the shards they rank for. The blob heartbeat then
/// re-announces the pinned shards, closing the discovery loop.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardReplicationMessage {
    /// Object identifier the shards belong to.
    pub object_id: String,
    /// iroh `EndpointId` of the origin node (lowercase hex) — where peers
    /// fetch the shard bytes from.
    pub origin_endpoint_id: String,
    /// libp2p peer ID of the originating node.
    #[serde(default)]
    pub origin_peer_id: String,
    /// Every shard of the object (data + parity).
    pub shards: Vec<ShardReplicationEntry>,
    /// Desired holder count per shard (including the origin).
    pub replicas: usize,
    /// Unix timestamp (ms) when this request was created.
    pub timestamp: i64,
    /// TTL in seconds — consumers reject requests older than this
    /// (default 180s).
    #[serde(default = "default_blob_ttl")]
    pub ttl_secs: u64,
    /// Ed25519 public key (raw 32B) of the origin node. Empty on unsigned
    /// requests, which consumers reject.
    #[serde(default)]
    pub pubkey: Vec<u8>,
    /// Ed25519 signature over the canonical preimage. Empty on unsigned
    /// requests, which consumers reject.
    #[serde(default)]
    pub signature: Vec<u8>,
}

impl ShardReplicationMessage {
    /// Sign this request with the node's Ed25519 announce key, populating
    /// `pubkey` + `signature`. Call after all fields are set — the signature
    /// covers the entire struct.
    pub fn sign(&mut self, signer: &dyn tenzro_crypto::signatures::Signer) -> Result<(), String> {
        self.pubkey = signer.public_key().as_bytes().to_vec();
        self.signature = Vec::new();
        let preimage = announce_preimage(SHARD_REPLICATION_DOMAIN, self)?;
        let sig = signer.sign(&preimage).map_err(|e| e.to_string())?;
        self.signature = sig.as_bytes().to_vec();
        Ok(())
    }

    /// Verify the embedded signature over the whole-struct preimage. Returns
    /// an error for unsigned (empty `pubkey`/`signature`) or tampered messages.
    pub fn verify(&self) -> Result<(), String> {
        if self.pubkey.is_empty() || self.signature.is_empty() {
            return Err("unsigned shard replication request".to_string());
        }
        let mut unsigned = self.clone();
        unsigned.signature = Vec::new();
        verify_announce_signature(
            SHARD_REPLICATION_DOMAIN,
            &unsigned,
            &self.pubkey,
            &self.signature,
        )
    }
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
/// by `PeerStatusTracker` to compute a network-tip estimate for `eth_syncing`
/// and to discover TEE-capable peers for confidential-compute routing.
/// `peer_id` is embedded so subscribers can attribute the message to a sender —
/// gossipsub does not surface the originating PeerId to topic subscribers,
/// only to the swarm event handler.
///
/// # TEE capability advertisement
///
/// Every node advertises its TEE capability here so peers can route
/// confidential-compute and custodial-key workloads to TEE-equipped nodes
/// without requiring out-of-band discovery. All nodes participate in
/// consensus regardless of `tee_capable`; the field is purely a routing
/// hint for TEE-gated workloads (confidential AI inference, custodial
/// key management, attestation issuance).
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
    /// Whether this node has a TEE provider available and can serve
    /// confidential-compute / custodial workloads on behalf of peers.
    pub tee_capable: bool,
    /// TEE vendor for this node, if any (`None` on commodity hardware).
    /// Peers consult this when selecting a TEE provider for a specific
    /// vendor requirement (e.g. SEV-SNP-only workloads).
    pub tee_vendor: Option<tenzro_types::tee::TeeVendor>,
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

    use tenzro_crypto::signatures::Signer;

    fn test_signer() -> tenzro_crypto::signatures::Ed25519SignerImpl {
        tenzro_crypto::signatures::Ed25519SignerImpl::generate().expect("keypair generation")
    }

    fn sample_model_announcement() -> ModelRegistrationMessage {
        ModelRegistrationMessage {
            model_id: "qwen3-0.6b".to_string(),
            name: "Qwen 3 0.6B".to_string(),
            provider: "0xabc".to_string(),
            peer_id: "12D3KooWTest".to_string(),
            rpc_endpoint: "http://10.0.0.1:8545".to_string(),
            timestamp: 1_700_000_000_000,
            ttl_secs: 120,
            ..Default::default()
        }
    }

    fn sample_provider_announcement() -> ProviderAnnouncementMessage {
        ProviderAnnouncementMessage {
            peer_id: "12D3KooWTest".to_string(),
            provider_address: "0xabc".to_string(),
            provider_type: "llm".to_string(),
            served_models: vec!["qwen3-0.6b".to_string()],
            capabilities: vec!["inference".to_string()],
            rpc_endpoint: "http://10.0.0.1:8545".to_string(),
            iroh_endpoint_id: String::new(),
            status: "active".to_string(),
            timestamp: 1_700_000_000_000,
            ttl_secs: 120,
            runtime_support: RuntimeSupport::default(),
            network_profile: NodeNetworkProfile::default(),
            trust_profile: TrustProfile::default(),
            worker_roles: Vec::new(),
            hardware: HardwareCapabilities::default(),
            geography: None,
            cluster_profile: None,
            pubkey: Vec::new(),
            signature: Vec::new(),
        }
    }

    fn sample_agent_announcement() -> AgentAnnouncementMessage {
        AgentAnnouncementMessage {
            agent_id: "agent-1".to_string(),
            name: "Test Agent".to_string(),
            agent_type: "custom".to_string(),
            capabilities: vec!["chat".to_string()],
            status: "active".to_string(),
            origin_peer_id: "12D3KooWTest".to_string(),
            rpc_endpoint: "http://10.0.0.1:8545".to_string(),
            timestamp: 1_700_000_000_000,
            ttl_secs: 180,
            pubkey: Vec::new(),
            signature: Vec::new(),
        }
    }

    #[test]
    fn test_model_announcement_sign_verify_roundtrip() {
        let signer = test_signer();
        let mut msg = sample_model_announcement();
        msg.sign(&signer).unwrap();
        assert!(!msg.pubkey.is_empty());
        assert!(!msg.signature.is_empty());
        msg.verify().unwrap();
    }

    #[test]
    fn test_model_announcement_tamper_rejected() {
        let signer = test_signer();
        let mut msg = sample_model_announcement();
        msg.sign(&signer).unwrap();

        let mut tampered = msg.clone();
        tampered.rpc_endpoint = "http://evil:8545".to_string();
        assert!(tampered.verify().is_err());

        let mut tampered = msg.clone();
        tampered.timestamp += 1;
        assert!(tampered.verify().is_err());

        let mut tampered = msg.clone();
        tampered.withdrawn = true;
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn test_unsigned_announcements_rejected() {
        assert!(sample_model_announcement().verify().is_err());
        assert!(sample_provider_announcement().verify().is_err());
        assert!(sample_agent_announcement().verify().is_err());
    }

    #[test]
    fn test_provider_announcement_sign_verify_roundtrip() {
        let signer = test_signer();
        let mut msg = sample_provider_announcement();
        msg.sign(&signer).unwrap();
        msg.verify().unwrap();

        let mut tampered = msg.clone();
        tampered.served_models.push("other-model".to_string());
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn test_agent_announcement_sign_verify_roundtrip() {
        let signer = test_signer();
        let mut msg = sample_agent_announcement();
        msg.sign(&signer).unwrap();
        msg.verify().unwrap();

        let mut tampered = msg.clone();
        tampered.origin_peer_id = "12D3KooWEvil".to_string();
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn test_announcement_key_substitution_rejected() {
        // An attacker re-signing someone else's announcement with their own
        // key produces a self-consistent message; consumers detect this via
        // first-seen pubkey pinning, but the raw signature must also fail
        // when only the pubkey is swapped without re-signing.
        let signer = test_signer();
        let other = test_signer();
        let mut msg = sample_provider_announcement();
        msg.sign(&signer).unwrap();
        let mut swapped = msg.clone();
        swapped.pubkey = other.public_key().as_bytes().to_vec();
        assert!(swapped.verify().is_err());
    }
}
