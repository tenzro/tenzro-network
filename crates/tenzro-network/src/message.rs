//! Network message types for Tenzro Network

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tenzro_types::{
    ArtifactCompleteness, ArtifactMetadata, Block, ExecutionSupport, HardwareCapabilities, Hash,
    ModelClass, ModelTopology, NodeNetworkProfile, RuntimeSupport, SignedTransaction, TrustProfile,
    WorkerRole,
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
        let buf = match self.payload.wire_form() {
            Some(payload) => bincode::serialize(&NetworkMessage {
                payload,
                message_id: self.message_id.clone(),
                timestamp: self.timestamp,
            })?,
            None => bincode::serialize(self)?,
        };
        Ok(Bytes::from(buf))
    }

    /// Deserializes a message from bincode bytes.
    ///
    /// Input longer than one gossip message is refused before decoding,
    /// decoding reads no more than that many bytes, and trailing bytes are
    /// refused, so one message decodes in time linear in its length and
    /// cannot be padded into distinct encodings.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bincode::Error> {
        use bincode::Options;
        let limit = tenzro_iroh::gossip::MAX_GOSSIP_MESSAGE;
        if bytes.len() > limit {
            return Err(Box::new(bincode::ErrorKind::SizeLimit));
        }
        let mut msg: NetworkMessage = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_limit(limit as u64)
            .reject_trailing_bytes()
            .deserialize(bytes)?;
        msg.payload = msg.payload.into_native().map_err(|e| {
            Box::new(bincode::ErrorKind::Custom(format!("batched announcement: {e}")))
        })?;
        Ok(msg)
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
// Boxing the large `Block` variant would alter every cross-crate
// construction/match site of this wire type; the size disparity is inherent.
#[allow(clippy::large_enum_variant)]
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

    /// Model registration
    ModelRegistration(ModelRegistrationMessage),

    /// Provider announcement — broadcast by nodes serving models/TEE so all
    /// peers can populate their network_providers cache.
    ProviderAnnouncement(ProviderAnnouncementMessage),

    /// Provider heartbeat — a serving node's signed proof of life, sent every
    /// few seconds so peers stop routing to it within seconds of it failing.
    ProviderHeartbeat(ProviderHeartbeatMessage),

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

    /// A checkpoint certificate, published by validators so followers can
    /// import the blocks it covers. Carries the bincode-encoded
    /// `tenzro_consensus::PublishedCertificate` (the certificate and the
    /// session certificates of its epoch's bundle) as opaque bytes (the
    /// network crate does not depend on the consensus crate); followers
    /// verify it against the committee of its epoch before acting on it.
    Certificate(Vec<u8>),

    /// A compact checkpoint certificate: the bincode-encoded
    /// `tenzro_consensus::compact::CompactCertificate`, which one STARK
    /// proves the quorum's ML-DSA-65 signatures in. Opaque here for the same
    /// reason as `Certificate`; light clients and followers verify it against
    /// the committee and session-certificate bundle of its epoch.
    CompactCertificate(Vec<u8>),

    /// Where to reach a validator this boot: the bincode-encoded
    /// `tenzro_consensus::announce::EndpointAnnouncement`, signed by the
    /// validator's consensus key. Opaque here for the same reason as
    /// `Certificate`; receivers verify it against the validator's registered
    /// key before dialling the endpoint it names.
    ValidatorEndpoint(Vec<u8>),

    /// Peer status update
    Status(StatusMessage),

    /// Ping message
    Ping,

    /// Pong response
    Pong,

    /// Custom application message
    Custom { topic: String, data: Vec<u8> },

    /// A gossip announcement signed in a hardware batch. Appended last so
    /// every earlier variant keeps its encoding; a node that predates it
    /// cannot decode the message and drops it. Decoding turns it back into
    /// the announcement it carries, with the batched signature in the
    /// message's `signature` field, so consumers see one form.
    BatchedAnnouncement(BatchedAnnouncementMessage),
}

/// Which announcement a [`BatchedAnnouncementMessage`] carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnnouncementKind {
    Model,
    Provider,
    Heartbeat,
    Blob,
    Shard,
}

/// A batch-signed announcement on the wire: the announcement's JSON with
/// both signature slots empty (the bytes the signature covers, after the
/// domain tag), and the batched signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchedAnnouncementMessage {
    pub kind: AnnouncementKind,
    pub body: Vec<u8>,
    pub signature: tenzro_crypto::batch::RecordSignature,
}

fn to_batched<T: SignedAnnouncement>(
    kind: AnnouncementKind,
    m: &T,
) -> Option<MessagePayload> {
    let record = m.signature()?.clone();
    let mut unsigned = m.clone();
    *unsigned.signer_fields().1 = None;
    let body = serde_json::to_vec(&unsigned).ok()?;
    Some(MessagePayload::BatchedAnnouncement(BatchedAnnouncementMessage {
        kind,
        body,
        signature: record,
    }))
}

fn from_batched<T: SignedAnnouncement + serde::de::DeserializeOwned>(
    m: &BatchedAnnouncementMessage,
) -> Result<T, String> {
    let mut msg: T = serde_json::from_slice(&m.body).map_err(|e| e.to_string())?;
    *msg.signer_fields().1 = Some(m.signature.clone());
    Ok(msg)
}

impl MessagePayload {
    /// The wire form of a payload whose announcement is batch-signed, or
    /// `None` when the payload goes out as it is.
    fn wire_form(&self) -> Option<MessagePayload> {
        match self {
            Self::ModelRegistration(m) => to_batched(AnnouncementKind::Model, m),
            Self::ProviderAnnouncement(m) => to_batched(AnnouncementKind::Provider, m),
            Self::ProviderHeartbeat(m) => to_batched(AnnouncementKind::Heartbeat, m),
            Self::BlobAnnouncement(m) => to_batched(AnnouncementKind::Blob, m),
            Self::ShardReplication(m) => to_batched(AnnouncementKind::Shard, m),
            _ => None,
        }
    }

    /// Turns a received batched announcement back into the announcement it
    /// carries.
    fn into_native(self) -> Result<MessagePayload, String> {
        match self {
            Self::BatchedAnnouncement(b) => Ok(match b.kind {
                AnnouncementKind::Model => Self::ModelRegistration(from_batched(&b)?),
                AnnouncementKind::Provider => Self::ProviderAnnouncement(from_batched(&b)?),
                AnnouncementKind::Heartbeat => Self::ProviderHeartbeat(from_batched(&b)?),
                AnnouncementKind::Blob => Self::BlobAnnouncement(from_batched(&b)?),
                AnnouncementKind::Shard => Self::ShardReplication(from_batched(&b)?),
            }),
            other => Ok(other),
        }
    }

    /// Returns the topic for this message type
    pub fn topic(&self) -> &str {
        match self {
            Self::Block(_) | Self::BlockRequest(_) | Self::BlockResponse(_) => "tenzro/blocks",
            Self::Transaction(_) | Self::TransactionRequest(_) | Self::TransactionResponse(_) => {
                "tenzro/transactions"
            }
            Self::ModelRegistration(_) => "tenzro/models",
            Self::ProviderAnnouncement(_) | Self::ProviderHeartbeat(_) => "tenzro/providers",
            Self::BlobAnnouncement(_) | Self::ShardReplication(_) => "tenzro/blobs",
            Self::Certificate(_) | Self::CompactCertificate(_) => "tenzro/certificates",
            Self::ValidatorEndpoint(_) => "tenzro/validators",
            Self::Status(_) | Self::Ping | Self::Pong => "tenzro/status",
            Self::Custom { topic, .. } => topic,
            Self::BatchedAnnouncement(b) => match b.kind {
                AnnouncementKind::Model => "tenzro/models",
                AnnouncementKind::Provider | AnnouncementKind::Heartbeat => "tenzro/providers",
                AnnouncementKind::Blob | AnnouncementKind::Shard => "tenzro/blobs",
            },
        }
    }
}

/// Model registration message — broadcast over gossip when a provider
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
    /// The provider's rate card for this model: per input and output token,
    /// per request, per compute-millisecond and every other billable unit,
    /// under the pricing scheme it declares. Anyone can quote a request
    /// against it.
    pub pricing: tenzro_types::price_card::RateCard,
    /// Serving schedule (when this model is available)
    #[serde(default)]
    pub schedule: Option<ModelSchedule>,
    /// Visibility of the model: "public" (anyone may call it by paying the
    /// provider's price) or "gated" (callers need an access token the operator's
    /// access policy admits for it). Private models
    /// are never announced.
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
    /// Provider's iroh `EndpointId` (hex): the only address a provider is
    /// reached by. Inference is dispatched over the `tenzro/infer` ALPN and
    /// the id resolves through the signed endpoint records. Empty when the
    /// provider has no iroh endpoint bound.
    #[serde(default)]
    pub iroh_endpoint_id: String,
    /// High-level model class classification
    #[serde(default)]
    pub model_class: ModelClass,
    /// Which artifact types are present, determining supported execution modes
    #[serde(default)]
    pub artifact_completeness: ArtifactCompleteness,
    /// Downloadable artifact descriptors (weights, shards, tokenizers)
    #[serde(default)]
    pub artifacts: Vec<ArtifactMetadata>,
    /// Internal topology metadata for MoE and large-scale models
    #[serde(default)]
    pub topology: ModelTopology,
    /// Execution modes this provider can serve for this model
    #[serde(default)]
    pub execution_support: ExecutionSupport,
    /// SHA-256 (hex) of the served GGUF weights, computed by the provider at
    /// load time. Lets any peer that serves the same `model_id` — or a
    /// verifier — detect a provider serving substituted/poisoned weights by
    /// comparing hashes across announcements. Empty when the provider did not
    /// compute it (e.g. clustered load spanning multiple files).
    #[serde(default)]
    pub weights_sha256: String,
    /// Machine identity of the announcing node, `did:tenzro:machine:...`.
    /// Receivers verify `signature` against the hardware identity key
    /// registered for it.
    #[serde(default)]
    pub machine_did: String,
    /// The hardware-batch signature; `None` on unsigned announcements, which
    /// consumers reject. Never part of the body or of the signed preimage: on
    /// the wire it travels in `MessagePayload::BatchedAnnouncement`, and
    /// decoding fills it here.
    #[serde(skip)]
    pub signature: Option<tenzro_crypto::batch::RecordSignature>,
}

/// Domain-separation tags for announcement signatures. Each announcement
/// type signs `tag || serde_json(message with signature cleared)`, so a
/// signature over one announcement type can never be replayed as another
/// even though every type is signed by the same machine identity.
const MODEL_ANNOUNCE_DOMAIN: &[u8] = b"tenzro/announce/model";
const PROVIDER_ANNOUNCE_DOMAIN: &[u8] = b"tenzro/announce/provider";
const PROVIDER_HEARTBEAT_DOMAIN: &[u8] = b"tenzro/announce/provider-heartbeat";
/// Canonical provider-class string for a node that serves models.
///
/// Generalised on purpose: a provider may serve text, multimodal, image,
/// video, audio or embedding models, and frequently several at once. The
/// class says *what kind of provider this is*, not what shape its models take.
pub const PROVIDER_TYPE_AI: &str = "ai";

/// Whether a declared provider class satisfies a requested one.
///
/// Case-insensitive equality. There is no alias table: this network runs one
/// binary, so a declared class means the same thing on every node that can
/// announce it.
pub fn provider_type_matches(declared: &str, requested: &str) -> bool {
    declared.eq_ignore_ascii_case(requested)
}

/// Domain of the endpoint binding: the iroh endpoint key signs a machine DID
/// under it to vouch that the identity speaks for the endpoint. A dedicated
/// domain keeps a signature made for this purpose from being replayed as any
/// other.
const ANNOUNCE_KEY_BINDING_DOMAIN: &[u8] = b"tenzro/announce/endpoint-binding";

const BLOB_ANNOUNCE_DOMAIN: &[u8] = b"tenzro/announce/blobs";
const SHARD_REPLICATION_DOMAIN: &[u8] = b"tenzro/announce/shard-replication";

/// Builds the canonical signing preimage for an announcement: the domain
/// tag followed by the JSON serialization of the message. The message must
/// already have `machine_did` populated and `signature` cleared, so the entire
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

/// A gossip announcement signed by its node's hardware identity.
///
/// The node's hardware identity key (P-256, plus ML-DSA-65 where the chip
/// holds one) signs `DOMAIN || serde_json(message with signature cleared)`
/// in a hardware batch. The announcement
/// names the signing machine by DID only: a receiver resolves the key
/// registered for that DID and verifies against it, so no announcement can
/// carry its own key and nothing is trusted on first sight. The domain tag
/// keeps a signature over one announcement type from being replayed as
/// another.
pub trait SignedAnnouncement: Clone + Serialize {
    /// Domain tag of this announcement type.
    const DOMAIN: &'static [u8];
    /// The signing machine's DID.
    fn machine_did(&self) -> &str;
    /// The signer DID and signature slots.
    fn signer_fields(
        &mut self,
    ) -> (
        &mut String,
        &mut Option<tenzro_crypto::batch::RecordSignature>,
    );
    /// The signature, when signed.
    fn signature(&self) -> Option<&tenzro_crypto::batch::RecordSignature>;
    /// The announcement's creation time (ms).
    fn made_at_ms(&self) -> u64;

    /// Sign as `machine_did` with `signer`. Call after every other field is
    /// set: the signature covers the whole message.
    fn sign(
        &mut self,
        machine_did: &str,
        signer: &dyn tenzro_crypto::batch::RecordSigner,
    ) -> Result<(), String> {
        {
            let (did, sig) = self.signer_fields();
            *did = machine_did.to_string();
            *sig = None;
        }
        let preimage = announce_preimage(Self::DOMAIN, self)?;
        let signature = signer.sign_record(&preimage).map_err(|e| e.to_string())?;
        *self.signer_fields().1 = Some(signature);
        Ok(())
    }

    /// Verify against `identity`, the key registered for
    /// [`SignedAnnouncement::machine_did`]. Errors on unsigned or tampered
    /// messages and on a signature certified by any other key.
    fn verify(
        &self,
        identity: &tenzro_crypto::composite::CompositePublicKey,
    ) -> Result<(), String> {
        if self.machine_did().is_empty() {
            return Err("announcement names no machine identity".to_string());
        }
        let signature = self
            .signature()
            .ok_or_else(|| "unsigned announcement".to_string())?;
        let mut unsigned = self.clone();
        *unsigned.signer_fields().1 = None;
            let preimage = announce_preimage(Self::DOMAIN, &unsigned)?;
        signature
            .verify_record_at(identity, &preimage, self.made_at_ms())
            .map_err(|e| e.to_string())
    }
}

/// Provider heartbeat — broadcast over "tenzro/providers" every few seconds
/// by a serving node, signed by the same machine identity as its provider
/// announcement, so a receiver ties it to the provider whose key it pinned.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderHeartbeatMessage {
    /// Wallet/account address of the provider.
    pub provider_address: String,
    /// The provider's iroh endpoint, the key its announcements are pinned under.
    pub iroh_endpoint_id: String,
    /// Unix timestamp (ms) when the heartbeat was created.
    pub timestamp: i64,
    /// The provider's own forecaster flagged its serving latency or queue
    /// outside the forecast band.
    pub degraded: bool,
    /// Live load of each model it serves, read when the heartbeat was built.
    pub model_load: Vec<tenzro_types::provider_listing::ModelLoad>,
    /// Machine identity of the announcing node, `did:tenzro:machine:...`.
    /// Receivers verify `signature` against the hardware identity key
    /// registered for it.
    pub machine_did: String,
    /// The hardware-batch signature; `None` on unsigned announcements, which
    /// consumers reject. Never part of the body or of the signed preimage: on
    /// the wire it travels in `MessagePayload::BatchedAnnouncement`, and
    /// decoding fills it here.
    #[serde(skip)]
    pub signature: Option<tenzro_crypto::batch::RecordSignature>,
}

impl SignedAnnouncement for ProviderHeartbeatMessage {
    const DOMAIN: &'static [u8] = PROVIDER_HEARTBEAT_DOMAIN;
    fn machine_did(&self) -> &str {
        &self.machine_did
    }
    fn signer_fields(
        &mut self,
    ) -> (
        &mut String,
        &mut Option<tenzro_crypto::batch::RecordSignature>,
    ) {
        (&mut self.machine_did, &mut self.signature)
    }
    fn signature(&self) -> Option<&tenzro_crypto::batch::RecordSignature> {
        self.signature.as_ref()
    }
    fn made_at_ms(&self) -> u64 {
        self.timestamp.max(0) as u64
    }
}

impl SignedAnnouncement for ModelRegistrationMessage {
    const DOMAIN: &'static [u8] = MODEL_ANNOUNCE_DOMAIN;
    fn machine_did(&self) -> &str {
        &self.machine_did
    }
    fn signer_fields(
        &mut self,
    ) -> (
        &mut String,
        &mut Option<tenzro_crypto::batch::RecordSignature>,
    ) {
        (&mut self.machine_did, &mut self.signature)
    }
    fn signature(&self) -> Option<&tenzro_crypto::batch::RecordSignature> {
        self.signature.as_ref()
    }
    fn made_at_ms(&self) -> u64 {
        self.timestamp.max(0) as u64
    }
}

fn default_ttl() -> u64 {
    120
}

fn default_provider_ttl() -> u64 {
    120
}

/// Provider announcement message — broadcast over gossip topic "tenzro/providers"
/// every 60s by nodes serving models or TEE services. All peers merge incoming
/// announcements into their `network_providers` DashMap so any node can discover
/// every provider in the network without a central registry.
/// `Default` exists so the wire-format tests can round-trip the *empty* case,
/// which is the one that breaks: `skip_serializing_if` only omits bytes when a
/// field is unset, so a fixture with everything populated proves nothing.
///
/// Note `ttl_secs` defaults to 0 here, not to [`default_provider_ttl`] — a
/// constructed announcement must set it explicitly or it is born expired.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderAnnouncementMessage {
    /// Wallet/account address of the provider
    pub provider_address: String,
    /// Provider class: `"ai"`, `"tee"`, `"storage"`, `"compute"`, `"database"`,
    /// `"cloud"`, `"general"`.
    ///
    /// `"ai"` covers every model class a node can serve — text, multimodal,
    /// image, video, audio, embeddings. `"llm"` is not an alias:
    /// it would mislabel any node serving something other than a text model.
    /// Compare with
    /// [`provider_type_matches`], which is case-insensitive equality.
    #[serde(default)]
    pub provider_type: String,
    /// Model IDs currently being served by this node
    #[serde(default)]
    pub served_models: Vec<String>,
    /// The subset of `served_models` that is gated: callers need an access
    /// token the operator's access policy admits, and there is no pay-per-use
    /// path. The rest are public.
    #[serde(default)]
    pub key_required_models: Vec<String>,
    /// Capability labels (e.g. "inference", "tee-attestation")
    #[serde(default)]
    pub capabilities: Vec<String>,
    /// Lifecycle status (e.g. "active", "draining")
    #[serde(default)]
    pub status: String,
    /// Unix timestamp (ms) when this announcement was created
    pub timestamp: i64,
    /// TTL in seconds — entries expire if not refreshed (default 120s)
    #[serde(default = "default_provider_ttl")]
    pub ttl_secs: u64,
    /// Runtime capabilities of this provider node
    #[serde(default)]
    pub runtime_support: RuntimeSupport,
    /// Network topology profile of this node
    #[serde(default)]
    pub network_profile: NodeNetworkProfile,
    /// TEE trust provenance for this provider
    #[serde(default)]
    pub trust_profile: TrustProfile,
    /// Worker roles this node can fulfil in distributed inference
    #[serde(default)]
    pub worker_roles: Vec<WorkerRole>,
    /// Hardware envelope of this provider node — RAM, VRAM, disk, CPU, TEE
    /// availability. Populated at announcement-build time from the local
    /// `HardwareCapabilities::detect()` result so consumers can route by
    /// memory / GPU / TEE class without an extra RPC round-trip.
    #[serde(default)]
    pub hardware: HardwareCapabilities,
    /// Advertised serving throughput/concurrency envelope — max concurrent
    /// requests, declared requests-per-second ceiling, batch size, and MTP
    /// availability. Populated at announcement-build time from the provider's
    /// `ProviderCapacity`. Consumers rank by this declared capacity but gate
    /// every number on observed serving metrics (measured throughput +
    /// latency) before trusting it. Covered by the announcement signature.
    #[serde(default)]
    pub capacity: tenzro_types::AdvertisedCapacity,
    /// Coarse region declared by the operator: a country code or a wide
    /// region (see [`tenzro_types::provider_listing::coarse_region`]), never
    /// anything finer. `None` means the provider declined to declare one;
    /// consumers must treat it as unknown, not as a wildcard match.
    #[serde(default)]
    pub region: Option<String>,
    /// iroh `EndpointId` of this node (lowercase hex) — the dialable
    /// identity on the iroh data plane. Consumers use it as the candidate
    /// identity for rendezvous shard placement and for peer-first blob
    /// fetches. Empty when the node has no iroh resolver bound.
    #[serde(default)]
    pub iroh_endpoint_id: String,
    /// LAN-cluster profile, present only when this node is a member of at
    /// least one cluster. Carries the signed memberships, the llama.cpp
    /// commit and the serving backend / capability key. `None` means
    /// single-box serving only.
    #[serde(default)]
    pub cluster_profile: Option<tenzro_types::ClusterProfile>,
    /// Identity operating that node. Present only alongside the
    /// `agent_serving` capability.
    #[serde(default)]
    pub operator_did: Option<String>,
    /// Machine identity of the announcing node, `did:tenzro:machine:...`.
    /// Receivers verify `signature` against the hardware identity key
    /// registered for it.
    #[serde(default)]
    pub machine_did: String,
    /// The hardware-batch signature; `None` on unsigned announcements, which
    /// consumers reject. Never part of the body or of the signed preimage: on
    /// the wire it travels in `MessagePayload::BatchedAnnouncement`, and
    /// decoding fills it here.
    #[serde(skip)]
    pub signature: Option<tenzro_crypto::batch::RecordSignature>,
    /// Signature by the iroh endpoint key named in `iroh_endpoint_id` over
    /// `ANNOUNCE_KEY_BINDING_DOMAIN || machine_did`: the holder of the
    /// endpoint vouches that this machine identity speaks for it. Without it
    /// a peer could publish another node's endpoint under its own identity
    /// and inherit the capability that node had advertised.
    #[serde(default)]
    pub endpoint_binding_sig: Vec<u8>,
}

/// What a node signs with its iroh endpoint key to vouch for the machine
/// identity announcing it.
fn endpoint_binding_payload(machine_did: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(ANNOUNCE_KEY_BINDING_DOMAIN.len() + machine_did.len());
    payload.extend_from_slice(ANNOUNCE_KEY_BINDING_DOMAIN);
    payload.extend_from_slice(machine_did.as_bytes());
    payload
}

impl SignedAnnouncement for ProviderAnnouncementMessage {
    const DOMAIN: &'static [u8] = PROVIDER_ANNOUNCE_DOMAIN;
    fn machine_did(&self) -> &str {
        &self.machine_did
    }
    fn signer_fields(
        &mut self,
    ) -> (
        &mut String,
        &mut Option<tenzro_crypto::batch::RecordSignature>,
    ) {
        (&mut self.machine_did, &mut self.signature)
    }
    fn signature(&self) -> Option<&tenzro_crypto::batch::RecordSignature> {
        self.signature.as_ref()
    }
    fn made_at_ms(&self) -> u64 {
        self.timestamp.max(0) as u64
    }
}

impl ProviderAnnouncementMessage {
    /// Bind `machine_did` to this node's iroh endpoint, then sign.
    ///
    /// The binding is written first so the signature covers it; otherwise it
    /// could be stripped or swapped in flight and the announcement would
    /// still verify. Only the holder of the endpoint key can produce it, so a
    /// peer cannot publish another node's endpoint under its own identity.
    pub fn sign_bound(
        &mut self,
        machine_did: &str,
        signer: &dyn tenzro_crypto::batch::RecordSigner,
        endpoint_key: &iroh::SecretKey,
    ) -> Result<(), String> {
        self.iroh_endpoint_id = endpoint_key.public().to_string();
        self.endpoint_binding_sig = endpoint_key
            .sign(&endpoint_binding_payload(machine_did))
            .to_bytes()
            .to_vec();
        SignedAnnouncement::sign(self, machine_did, signer)
    }

    /// Whether this announcement proves its machine identity may speak for
    /// its `iroh_endpoint_id`.
    ///
    /// Separate from [`SignedAnnouncement::verify`] so a consumer can decide
    /// what an unbound announcement is worth. An announcement with no binding
    /// returns `Ok(false)`: not forged, merely unproven.
    pub fn verify_endpoint_binding(&self) -> Result<bool, String> {
        if self.endpoint_binding_sig.is_empty() {
            return Ok(false);
        }
        // The endpoint id is the Ed25519 public key itself, so the binding
        // verifies against exactly the identity the announcement claims.
        let endpoint: iroh::EndpointId = self
            .iroh_endpoint_id
            .parse()
            .map_err(|e| format!("unparseable iroh_endpoint_id: {e}"))?;
        let sig_bytes: [u8; 64] = self
            .endpoint_binding_sig
            .as_slice()
            .try_into()
            .map_err(|_| "endpoint binding is not a 64-byte signature".to_string())?;
        endpoint
            .verify(
                &endpoint_binding_payload(&self.machine_did),
                &iroh::Signature::from_bytes(&sig_bytes),
            )
            .map_err(|_| "endpoint binding does not cover this machine identity".to_string())?;
        Ok(true)
    }
}

fn default_blob_ttl() -> u64 {
    180
}

/// Blob availability announcement — broadcast over gossip topic
/// "tenzro/blobs" by nodes whose iroh blob store holds content. Peers
/// verify the signature and record `endpoint_id` as a provider for each
/// listed hash in the resolver's hint cache, so hint-less
/// `tenzro://blob/...` fetches can dial announced holders.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobAnnouncementMessage {
    /// iroh `EndpointId` of the announcing node, lowercase hex — the
    /// dialable identity of the node holding the blobs.
    pub endpoint_id: String,
    /// BLAKE3 hex hashes of blobs held in the announcer's store. Producers
    /// chunk large stores across multiple announcements.
    pub blob_hashes: Vec<String>,
    /// Unix timestamp (ms) when this announcement was created
    pub timestamp: i64,
    /// TTL in seconds — consumers reject announcements older than this
    /// (default 180s)
    #[serde(default = "default_blob_ttl")]
    pub ttl_secs: u64,
    /// Machine identity of the announcing node, `did:tenzro:machine:...`.
    /// Receivers verify `signature` against the hardware identity key
    /// registered for it.
    #[serde(default)]
    pub machine_did: String,
    /// The hardware-batch signature; `None` on unsigned announcements, which
    /// consumers reject. Never part of the body or of the signed preimage: on
    /// the wire it travels in `MessagePayload::BatchedAnnouncement`, and
    /// decoding fills it here.
    #[serde(skip)]
    pub signature: Option<tenzro_crypto::batch::RecordSignature>,
}

impl SignedAnnouncement for BlobAnnouncementMessage {
    const DOMAIN: &'static [u8] = BLOB_ANNOUNCE_DOMAIN;
    fn machine_did(&self) -> &str {
        &self.machine_did
    }
    fn signer_fields(
        &mut self,
    ) -> (
        &mut String,
        &mut Option<tenzro_crypto::batch::RecordSignature>,
    ) {
        (&mut self.machine_did, &mut self.signature)
    }
    fn signature(&self) -> Option<&tenzro_crypto::batch::RecordSignature> {
        self.signature.as_ref()
    }
    fn made_at_ms(&self) -> u64 {
        self.timestamp.max(0) as u64
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

/// Shard replication request — broadcast over gossip topic "tenzro/blobs"
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
    /// Machine identity of the announcing node, `did:tenzro:machine:...`.
    /// Receivers verify `signature` against the hardware identity key
    /// registered for it.
    #[serde(default)]
    pub machine_did: String,
    /// The hardware-batch signature; `None` on unsigned announcements, which
    /// consumers reject. Never part of the body or of the signed preimage: on
    /// the wire it travels in `MessagePayload::BatchedAnnouncement`, and
    /// decoding fills it here.
    #[serde(skip)]
    pub signature: Option<tenzro_crypto::batch::RecordSignature>,
}

impl SignedAnnouncement for ShardReplicationMessage {
    const DOMAIN: &'static [u8] = SHARD_REPLICATION_DOMAIN;
    fn machine_did(&self) -> &str {
        &self.machine_did
    }
    fn signer_fields(
        &mut self,
    ) -> (
        &mut String,
        &mut Option<tenzro_crypto::batch::RecordSignature>,
    ) {
        (&mut self.machine_did, &mut self.signature)
    }
    fn signature(&self) -> Option<&tenzro_crypto::batch::RecordSignature> {
        self.signature.as_ref()
    }
    fn made_at_ms(&self) -> u64 {
        self.timestamp.max(0) as u64
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

/// Status message for peer synchronization.
///
/// Broadcast on `tenzro/status` every 10s by every node and consumed
/// by `PeerStatusTracker` to compute a network-tip estimate for `eth_syncing`
/// and to discover TEE-capable peers for confidential-compute routing.
/// `endpoint_id` is embedded so subscribers can attribute the message to a sender —
/// gossip does not surface the originating node to topic subscribers.
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
    /// iroh `EndpointId` of the sender, lowercase hex. Subscribers parse this
    /// back into an `EndpointId`. Required so the `PeerStatusTracker` can key
    /// entries by peer.
    pub endpoint_id: String,
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
    if msg.timestamp > now.saturating_add(300_000) {
        return Err(crate::error::NetworkError::InvalidMessage(
            "Message timestamp is too far in the future".to_string(),
        ));
    }

    // Check message is not too old (reject messages older than 1 hour). A
    // timestamp so far back that the age does not fit is too old as well.
    if now
        .checked_sub(msg.timestamp)
        .is_none_or(|age| age > 3_600_000)
    {
        return Err(crate::error::NetworkError::InvalidMessage(
            "Message is too old".to_string(),
        ));
    }

    // Additional payload-specific validation
    if let MessagePayload::Block(block) = &msg.payload
        && block.header.height.0 == 0
        && block.header.prev_hash != Hash::zero()
    {
        return Err(crate::error::NetworkError::InvalidMessage(
            "Genesis block must have zero prev_hash".to_string(),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One encoding per message: trailing bytes and input longer than a
    /// gossip message are refused.
    #[test]
    fn trailing_bytes_and_oversized_input_are_refused() {
        let msg = NetworkMessage::new(MessagePayload::Certificate(vec![1, 2, 3]));
        let mut bytes = msg.to_bytes().unwrap().to_vec();
        assert!(NetworkMessage::from_bytes(&bytes).is_ok());
        bytes.push(0);
        assert!(NetworkMessage::from_bytes(&bytes).is_err());
        let big = NetworkMessage::new(MessagePayload::Certificate(vec![
            7;
            tenzro_iroh::gossip::MAX_GOSSIP_MESSAGE
        ]));
        assert!(NetworkMessage::from_bytes(&big.to_bytes().unwrap()).is_err());
    }

    /// Length prefixes claiming far more than the input holds end decoding
    /// at the end of the input.
    #[test]
    fn a_length_prefix_past_the_input_is_refused() {
        let bytes = include_bytes!(
            "../../../fuzz/regressions/gossip_decode/transaction-response-claiming-unbounded-lengths"
        );
        assert!(NetworkMessage::from_bytes(bytes).is_err());
        let mut claim = 11u32.to_le_bytes().to_vec();
        claim.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(NetworkMessage::from_bytes(&claim).is_err());
    }

    /// Timestamps at the ends of the range are refused, not wrapped into
    /// the accepted window.
    #[test]
    fn extreme_timestamps_are_refused() {
        let mut msg = NetworkMessage::new(MessagePayload::Certificate(vec![1]));
        assert!(validate_message(&msg).is_ok());
        for t in [i64::MIN, i64::MIN + 1, -1, 0, i64::MAX, i64::MAX - 1] {
            msg.timestamp = t;
            assert!(
                validate_message(&msg).is_err(),
                "timestamp {t} was accepted"
            );
        }
    }

    /// A node announcing the new value must still satisfy a client written
    /// against the old one, and the reverse — both sides of a rollout.
    #[test]
    fn ai_and_llm_name_the_same_provider_class() {
        assert!(provider_type_matches("ai", "ai"));
        assert!(provider_type_matches("ai", "AI"));
        // "llm" is no longer an alias for "ai" -- it is just another string.
        assert!(!provider_type_matches("ai", "llm"));
        assert!(!provider_type_matches("llm", "ai"));
    }

    /// The alias must not swallow other classes. A storage node is not an AI
    /// node, and a filter for one must never return the other.
    #[test]
    fn the_alias_does_not_leak_into_other_classes() {
        for other in ["tee", "storage", "compute", "database", "cloud", "general"] {
            assert!(!provider_type_matches("ai", other), "ai vs {other}");
            assert!(!provider_type_matches(other, "ai"), "{other} vs ai");
        }
        assert!(provider_type_matches("storage", "storage"));
    }

    /// Case is not meaningful in a class name; a client sending "AI" and a
    /// node announcing "ai" are naming the same class.
    ///
    /// Case folding is all that happens — "llm" is a different class name
    /// since the alias was removed, not a spelling of "ai".
    #[test]
    fn provider_class_matching_ignores_case() {
        assert!(provider_type_matches("AI", "ai"));
        assert!(provider_type_matches("ai", "AI"));
        assert!(provider_type_matches("Storage", "storage"));
        assert!(!provider_type_matches("AI", "llm"));
        assert!(!provider_type_matches("LLM", "ai"));
    }

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

    fn sample_model_announcement() -> ModelRegistrationMessage {
        ModelRegistrationMessage {
            model_id: "qwen3-0.6b".to_string(),
            name: "Qwen 3 0.6B".to_string(),
            provider: "0xabc".to_string(),
            iroh_endpoint_id: "provider-endpoint".to_string(),
            timestamp: 1_700_000_000_000,
            ttl_secs: 120,
            ..Default::default()
        }
    }

    fn sample_provider_announcement() -> ProviderAnnouncementMessage {
        ProviderAnnouncementMessage {
            provider_address: "0xabc".to_string(),
            provider_type: PROVIDER_TYPE_AI.to_string(),
            served_models: vec!["qwen3-0.6b".to_string()],
            key_required_models: Vec::new(),
            capabilities: vec!["inference".to_string()],
            iroh_endpoint_id: String::new(),
            status: "active".to_string(),
            timestamp: 1_700_000_000_000,
            ttl_secs: 120,
            runtime_support: RuntimeSupport::default(),
            network_profile: NodeNetworkProfile::default(),
            trust_profile: TrustProfile::default(),
            worker_roles: Vec::new(),
            hardware: HardwareCapabilities::default(),
            capacity: tenzro_types::AdvertisedCapacity::default(),
            region: None,
            cluster_profile: None,
            operator_did: None,
            machine_did: String::new(),
            signature: None,
            endpoint_binding_sig: Vec::new(),
        }
    }

    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_crypto::batch::ImmediateRecordSigner;

    const DID: &str = "did:tenzro:machine:test";

    /// A fresh iroh endpoint key.
    fn endpoint_key(seed: u8) -> iroh::SecretKey {
        iroh::SecretKey::from_bytes(&[seed; 32])
    }

    /// A record signer over a stand-in hardware identity, and the
    /// identity key a receiver resolves for the machine.
    fn identity(
        seed: u8,
        hybrid: bool,
    ) -> (ImmediateRecordSigner, tenzro_crypto::composite::CompositePublicKey) {
        let hw = if hybrid {
            TestHybridSigner::hybrid(seed)
        } else {
            TestHybridSigner::p256_only(seed)
        };
        let signer = ImmediateRecordSigner::new(std::sync::Arc::new(hw));
        let key = signer.identity().clone();
        (signer, key)
    }

    #[test]
    fn every_announcement_type_verifies_against_the_registered_identity() {
        for hybrid in [false, true] {
            let (signer, key) = identity(1, hybrid);
            let mut model = sample_model_announcement();
            model.sign(DID, &signer).unwrap();
            model.verify(&key).unwrap();
            assert_eq!(model.machine_did, DID);

            let mut provider = sample_provider_announcement();
            provider.sign_bound(DID, &signer, &endpoint_key(1)).unwrap();
            provider.verify(&key).unwrap();
            assert_eq!(provider.verify_endpoint_binding(), Ok(true));

            let mut hb = ProviderHeartbeatMessage {
                provider_address: "0xabc".into(),
                timestamp: 1,
                ..Default::default()
            };
            hb.sign(DID, &signer).unwrap();
            hb.verify(&key).unwrap();

            let mut blob = BlobAnnouncementMessage {
                endpoint_id: "e".into(),
                blob_hashes: vec!["h".into()],
                timestamp: 1,
                ttl_secs: 180,
                machine_did: String::new(),
                signature: None,
            };
            blob.sign(DID, &signer).unwrap();
            blob.verify(&key).unwrap();

            let mut shard = ShardReplicationMessage {
                object_id: "o".into(),
                origin_endpoint_id: "e".into(),
                shards: Vec::new(),
                replicas: 2,
                timestamp: 1,
                ttl_secs: 180,
                machine_did: String::new(),
                signature: None,
            };
            shard.sign(DID, &signer).unwrap();
            shard.verify(&key).unwrap();
        }
    }

    /// A signature certified by any identity other than the one registered
    /// for the machine DID is refused, even though it is self-consistent.
    #[test]
    fn a_signature_by_another_identity_is_refused() {
        let (signer, _) = identity(1, true);
        let (_, other) = identity(2, true);
        let mut msg = sample_provider_announcement();
        msg.sign(DID, &signer).unwrap();
        assert!(msg.verify(&other).is_err());

        // The registered key with its ML-DSA leg dropped is another key too.
        let (signer, key) = identity(3, true);
        let mut msg = sample_model_announcement();
        msg.sign(DID, &signer).unwrap();
        let stripped =
            tenzro_crypto::composite::CompositePublicKey::new(key.p256.clone(), None).unwrap();
        assert!(msg.verify(&stripped).is_err());
    }

    #[test]
    fn unsigned_and_tampered_announcements_are_refused() {
        let (signer, key) = identity(4, false);
        assert!(sample_model_announcement().verify(&key).is_err());
        assert!(sample_provider_announcement().verify(&key).is_err());

        let mut msg = sample_model_announcement();
        msg.sign(DID, &signer).unwrap();
        let tampers: [fn(&mut ModelRegistrationMessage); 4] = [
            |m: &mut ModelRegistrationMessage| m.iroh_endpoint_id = "evil".into(),
            |m: &mut ModelRegistrationMessage| m.timestamp += 1,
            |m: &mut ModelRegistrationMessage| m.withdrawn = true,
            |m: &mut ModelRegistrationMessage| m.machine_did = "did:tenzro:machine:other".into(),
        ];
        for tamper in tampers {
            let mut t = msg.clone();
            tamper(&mut t);
            assert!(t.verify(&key).is_err());
        }

        let mut ann = sample_provider_announcement();
        ann.sign(DID, &signer).unwrap();
        let mut t = ann.clone();
        t.served_models.push("other-model".into());
        assert!(t.verify(&key).is_err());
    }

    /// The advertised trust tier is inside the signed struct, so an
    /// intermediary cannot promote a delegated node to the TPM tier in flight.
    #[test]
    fn the_identity_root_cannot_be_upgraded_in_flight() {
        let (signer, key) = identity(5, false);
        let mut ann = sample_provider_announcement();
        ann.trust_profile.identity_root = "passkey-delegated".to_string();
        ann.sign_bound(DID, &signer, &endpoint_key(2)).unwrap();
        ann.verify(&key).unwrap();
        ann.trust_profile.identity_root = "tpm".to_string();
        assert!(ann.verify(&key).is_err());
    }

    /// A machine that publishes another node's endpoint under its own
    /// identity signs a valid announcement; only the binding catches it.
    #[test]
    fn a_spoofer_cannot_claim_another_nodes_endpoint() {
        let victim = endpoint_key(8);
        let (signer, key) = identity(6, false);
        let mut ann = sample_provider_announcement();
        ann.sign_bound(DID, &signer, &endpoint_key(9)).unwrap();
        ann.iroh_endpoint_id = victim.public().to_string();
        ann.sign(DID, &signer).unwrap();
        ann.verify(&key).unwrap();
        assert!(ann.verify_endpoint_binding().is_err());
    }

    /// Stripping the binding breaks the signature; a malformed binding is an
    /// error; an absent one is unproven, not forged.
    #[test]
    fn the_endpoint_binding_is_covered_and_checked() {
        let key = endpoint_key(10);
        let (signer, id) = identity(7, false);
        let mut ann = sample_provider_announcement();
        ann.sign_bound(DID, &signer, &key).unwrap();
        let mut stripped = ann.clone();
        stripped.endpoint_binding_sig.clear();
        assert!(stripped.verify(&id).is_err());

        let mut half = sample_provider_announcement();
        half.iroh_endpoint_id = key.public().to_string();
        half.endpoint_binding_sig = vec![0u8; 12];
        assert!(half.verify_endpoint_binding().is_err());

        let mut unbound = sample_provider_announcement();
        unbound.sign(DID, &signer).unwrap();
        unbound.verify(&id).unwrap();
        assert_eq!(unbound.verify_endpoint_binding(), Ok(false));

        // A binding made for one machine identity does not cover another.
        let mut moved = ann.clone();
        moved.sign("did:tenzro:machine:other", &signer).unwrap();
        assert!(moved.verify_endpoint_binding().is_err());
    }
}
