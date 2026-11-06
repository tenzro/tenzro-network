//! Node-layer transport for the committee-DA surface.
//!
//! Binds the storage-side [`DaCommitteeSurface`](crate::da_committee::DaCommitteeSurface)
//! to the `tenzro/da-committee` ALPN on the node's endpoint. A request is one
//! bincode-encoded [`DaCommitteeRequest`], answered by one
//! [`DaCommitteeResponse`].
//!
//! ## Index → address → endpoint
//!
//! The surface addresses a member by its committee index. The mapping is
//! committee-index → validator `Address` (from the
//! [`CommitteeView`](crate::da_committee::CommitteeView)) → the endpoint that
//! validator announced ([`MemberEndpoints`]). In a running node the endpoint
//! comes from the validator's endpoint announcement, verified against its
//! committee key by consensus ([`announced_member_endpoints`]). A member with
//! no current announcement is treated as unreachable — the writer only needs
//! `2f+1`, so a minority of unresolved members does not fail a submit.
//!
//! ## Inbound serving
//!
//! A validator both writes blobs (outbound) and holds slivers for blobs other
//! validators wrote (inbound). [`DaCommitteeServer`] is the inbound side,
//! installed behind the ALPN: a `StoreSliver` decodes the sliver, persists it
//! to the local [`DaCommitteeStore`](crate::da_committee::DaCommitteeStore),
//! signs an attestation, and replies; a `FetchSliver` returns the held sliver
//! (or `None`). The server owns the local signing key and store so it can
//! serve without a round-trip to the backend.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use tenzro_consensus::EpochManager;
use tenzro_crypto::batch::{RecordSignature, RecordSigner};
use tenzro_iroh::{
    ALPN_DA_COMMITTEE, Endpoint, EndpointId, MAX_STORE_REQUEST, Reply, RequestHandler,
};
use tenzro_storage::kv::KvStore;
use tenzro_storage::redstuff::{CommitteeShape, SliverPair};
use tenzro_types::primitives::{Address, Hash};

use crate::da_committee::{
    CommitteeMember, CommitteeView, DaCommitteeError, DaCommitteeStore, DaCommitteeSurface,
    MemberAttestation, PossessionProof, StoredSliver, attestation_message, challenge_message,
};

type Result<T> = std::result::Result<T, DaCommitteeError>;

/// Longest a writer, reader or challenger waits on one member.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Committee DA request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaCommitteeRequest {
    /// Writer asks this member to durably store `sliver` for the blob whose
    /// 32-byte commitment is `commitment`. On success the member replies
    /// [`DaCommitteeResponse::Attestation`].
    StoreSliver {
        /// 32-byte blob commitment.
        commitment: [u8; 32],
        /// bincode-encoded `redstuff::CommitteeShape`.
        shape_blob: Vec<u8>,
        /// True byte length of the blob.
        blob_len: u64,
        /// Symbol length of the encoding.
        symbol_len: u64,
        /// bincode-encoded `redstuff::SliverPair`.
        sliver: Vec<u8>,
    },

    /// Reader asks this member for the sliver it holds for `commitment`. The
    /// member replies [`DaCommitteeResponse::Sliver`] — `Some(bytes)` if held,
    /// `None` otherwise.
    FetchSliver {
        /// 32-byte blob commitment.
        commitment: [u8; 32],
    },

    /// Challenger asks this member to prove *current* possession of its sliver
    /// for `commitment`. The member must reply
    /// [`DaCommitteeResponse::PossessionProof`] carrying the sliver itself plus
    /// a signature binding the challenger-chosen `nonce` — a cached Merkle path
    /// alone proves nothing about possession, so the proof is the full sliver
    /// re-verified against the commitment on the challenger side.
    ChallengeSliver {
        /// 32-byte blob commitment.
        commitment: [u8; 32],
        /// Challenger-chosen random nonce bound into the signed response.
        nonce: [u8; 32],
    },

    /// A node outside the committee asks where this member put the history
    /// segment starting at checkpoint `first_index`. The member replies
    /// [`DaCommitteeResponse::HistorySegment`]; the asker verifies the
    /// segment's bytes against certified checkpoints before relying on it.
    HistorySegment {
        /// First checkpoint index the segment covers.
        first_index: u64,
    },
}

/// Committee DA response.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DaCommitteeResponse {
    /// Response to `StoreSliver`: the member stored its sliver and signed for
    /// custody.
    Attestation(WireMemberAttestation),

    /// Response to `FetchSliver`: `Some` bincode-encoded `redstuff::SliverPair`
    /// if the member holds it, `None` otherwise.
    Sliver(Option<Vec<u8>>),

    /// Response to `ChallengeSliver`: `Some` proof if the member holds the
    /// sliver, `None` if it does not (an honest "not held" answer — the
    /// challenger records the failure against the member's availability score).
    PossessionProof(Option<WirePossessionProof>),

    /// Response to `HistorySegment`: `Some` bincode-encoded
    /// [`ArchivedSegment`] if this member recorded one starting there.
    HistorySegment(Option<Vec<u8>>),

    /// The member could not verify or persist the sliver (bad proof, wrong
    /// commitment binding, storage failure). The requester treats this the
    /// same as a missing attestation / missing sliver and moves on.
    Error(String),
}

/// One committee member's signed acknowledgment that it stored its sliver, as
/// carried on the wire. Maps to [`MemberAttestation`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireMemberAttestation {
    /// Committee index of the attesting member.
    pub index: u64,
    /// The member's on-chain address (bound into the signed message).
    pub address: Address,
    /// Signature over the canonical attestation message by the member's
    /// committee key, made in a hardware batch.
    pub signature: RecordSignature,
}

/// One committee member's nonce-bound proof that it currently holds its
/// sliver, as carried on the wire. Maps to [`PossessionProof`]. The `sliver`
/// bytes are the bincode-encoded `redstuff::SliverPair` — the challenger
/// re-runs full sliver verification against the blob commitment, so a member
/// cannot pass with stale metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WirePossessionProof {
    /// Committee index of the responding member.
    pub index: u64,
    /// The member's on-chain address (bound into the signed message).
    pub address: Address,
    /// Signature over the canonical challenge message
    /// (commitment ‖ nonce ‖ address under the challenge domain tag) by the
    /// member's committee key, made in a hardware batch.
    pub signature: RecordSignature,
    /// bincode-encoded `redstuff::SliverPair`.
    pub sliver: Vec<u8>,
}

/// Resolves a committee member's validator address to the endpoint it can be
/// dialed at, if one is currently known.
pub type MemberEndpoints = Arc<dyn Fn(&Address) -> Option<EndpointId> + Send + Sync>;

/// Member endpoints from consensus: the validator at an address in the
/// current epoch set, and the endpoint its verified endpoint announcement
/// names while that announcement is current.
pub fn announced_member_endpoints(
    consensus: Arc<crate::consensus_driver::ConsensusHandle>,
) -> MemberEndpoints {
    Arc::new(move |address: &Address| {
        let set = consensus.epoch_manager().current_validator_set();
        let validator = set
            .active_validators()
            .iter()
            .find(|v| &v.address == address)?;
        let endpoint = consensus.announced_endpoint(&validator.public_key)?;
        EndpointId::from_bytes(&endpoint).ok()
    })
}

/// A [`CommitteeView`] over the live epoch validator set. Each member's key
/// is the one registered for its machine identity, which derives from the
/// P-256 leg of its consensus key.
pub struct EpochManagerCommitteeView {
    epoch_manager: Arc<EpochManager>,
    registry: crate::identity_bootstrap::RegistrySlot,
}

impl EpochManagerCommitteeView {
    /// Construct the view over a shared epoch manager (`consensus.epoch_manager()`)
    /// and the node's identity registry.
    pub fn new(
        epoch_manager: Arc<EpochManager>,
        registry: crate::identity_bootstrap::RegistrySlot,
    ) -> Self {
        Self {
            epoch_manager,
            registry,
        }
    }
}

impl CommitteeView for EpochManagerCommitteeView {
    fn members(&self) -> Vec<CommitteeMember> {
        self.epoch_manager
            .current_validator_set()
            .active_validators()
            .iter()
            .enumerate()
            .map(|(index, v)| CommitteeMember {
                index,
                address: v.address,
                public_key: crate::identity_bootstrap::registered_machine_key(
                    &self.registry,
                    &v.public_key.p256,
                ),
            })
            .collect()
    }
}

/// `DaCommitteeSurface` over the `tenzro/da-committee` ALPN.
///
/// One instance per running node. Resolves committee index → member address
/// (via the [`CommitteeView`]) → endpoint (via [`MemberEndpoints`]), then
/// sends the request and reads the member's answer.
pub struct IrohDaCommitteeSurface {
    endpoint: Endpoint,
    committee: Arc<dyn CommitteeView>,
    endpoints: MemberEndpoints,
    local_address: Address,
}

impl IrohDaCommitteeSurface {
    /// Construct the surface. `local_address` is the running node's own
    /// validator address; requests targeting it are short-circuited by the
    /// backend before reaching the surface, so this is only used to reject a
    /// self-directed wire request defensively.
    pub fn new(
        endpoint: Endpoint,
        committee: Arc<dyn CommitteeView>,
        endpoints: MemberEndpoints,
        local_address: Address,
    ) -> Self {
        Self {
            endpoint,
            committee,
            endpoints,
            local_address,
        }
    }

    /// Resolve a committee index to the endpoint to dial.
    fn resolve(&self, to_index: usize) -> Result<EndpointId> {
        let member = self
            .committee
            .members()
            .into_iter()
            .find(|m| m.index == to_index)
            .ok_or_else(|| {
                DaCommitteeError::Transport(format!("no committee member at index {to_index}"))
            })?;
        if member.address == self.local_address {
            return Err(DaCommitteeError::Transport(
                "refusing to dial self over the wire".into(),
            ));
        }
        (self.endpoints)(&member.address).ok_or_else(|| {
            DaCommitteeError::Transport(format!(
                "no endpoint known for committee member {to_index} ({})",
                member.address
            ))
        })
    }

    /// Send `request` to member `to_index` and decode its answer.
    async fn call(
        &self,
        to_index: usize,
        request: &DaCommitteeRequest,
    ) -> Result<DaCommitteeResponse> {
        let member = self.resolve(to_index)?;
        let bytes =
            bincode::serialize(request).map_err(|e| DaCommitteeError::Core(e.to_string()))?;
        let exchange = async {
            let response = tenzro_iroh::request(&self.endpoint, member, ALPN_DA_COMMITTEE, &bytes)
                .await
                .map_err(|e| e.to_string())?;
            let status = response.status;
            let body = response
                .bytes(MAX_STORE_REQUEST)
                .await
                .map_err(|e| e.to_string())?;
            if !(200..300).contains(&status) {
                return Err(format!(
                    "member answered {status}: {}",
                    String::from_utf8_lossy(&body)
                ));
            }
            Ok(body)
        };
        let body = tokio::time::timeout(REQUEST_TIMEOUT, exchange)
            .await
            .map_err(|_| DaCommitteeError::Transport(format!("member {to_index} timed out")))?
            .map_err(DaCommitteeError::Transport)?;
        bincode::deserialize(&body)
            .map_err(|e| DaCommitteeError::Transport(format!("undecodable member answer: {e}")))
    }
}

#[async_trait::async_trait]
impl DaCommitteeSurface for IrohDaCommitteeSurface {
    async fn store_sliver(
        &self,
        to_index: usize,
        commitment: &Hash,
        shape: CommitteeShape,
        blob_len: u64,
        symbol_len: usize,
        sliver: &SliverPair,
    ) -> Result<MemberAttestation> {
        let request = DaCommitteeRequest::StoreSliver {
            commitment: commitment.0,
            shape_blob: encode_shape(&shape)?,
            blob_len,
            symbol_len: symbol_len as u64,
            sliver: encode_sliver(sliver)?,
        };
        match self.call(to_index, &request).await? {
            DaCommitteeResponse::Attestation(wire) => Ok(wire_to_attestation(wire)),
            DaCommitteeResponse::Error(e) => Err(member_error(e)),
            other => Err(DaCommitteeError::Transport(format!(
                "member answered StoreSliver with an unexpected {} response",
                response_kind(&other)
            ))),
        }
    }

    async fn fetch_sliver(&self, to_index: usize, commitment: &Hash) -> Result<Option<SliverPair>> {
        let request = DaCommitteeRequest::FetchSliver {
            commitment: commitment.0,
        };
        match self.call(to_index, &request).await? {
            DaCommitteeResponse::Sliver(None) => Ok(None),
            DaCommitteeResponse::Sliver(Some(bytes)) => Ok(Some(decode_sliver(&bytes)?)),
            DaCommitteeResponse::Error(e) => Err(member_error(e)),
            other => Err(DaCommitteeError::Transport(format!(
                "member answered FetchSliver with an unexpected {} response",
                response_kind(&other)
            ))),
        }
    }

    async fn challenge_sliver(
        &self,
        to_index: usize,
        commitment: &Hash,
        nonce: &[u8; 32],
    ) -> Result<Option<PossessionProof>> {
        let request = DaCommitteeRequest::ChallengeSliver {
            commitment: commitment.0,
            nonce: *nonce,
        };
        match self.call(to_index, &request).await? {
            DaCommitteeResponse::PossessionProof(None) => Ok(None),
            DaCommitteeResponse::PossessionProof(Some(wire)) => {
                Ok(Some(wire_to_possession_proof(wire)?))
            }
            DaCommitteeResponse::Error(e) => Err(member_error(e)),
            other => Err(DaCommitteeError::Transport(format!(
                "member answered ChallengeSliver with an unexpected {} response",
                response_kind(&other)
            ))),
        }
    }
}

#[async_trait::async_trait]
impl crate::history_archive::SegmentLocator for IrohDaCommitteeSurface {
    /// Asks every committee member; distinct answers are returned for the
    /// archive to verify, so one member's wrong answer cannot hide another's.
    async fn locate(&self, first_index: u64) -> Vec<crate::history_archive::ArchivedSegment> {
        let mut found: Vec<crate::history_archive::ArchivedSegment> = Vec::new();
        for member in self.committee.members() {
            if member.address == self.local_address {
                continue;
            }
            let request = DaCommitteeRequest::HistorySegment { first_index };
            if let Ok(DaCommitteeResponse::HistorySegment(Some(bytes))) =
                self.call(member.index, &request).await
                && let Ok(seg) =
                    bincode::deserialize::<crate::history_archive::ArchivedSegment>(&bytes)
                && seg.first_index == first_index
                && !found.contains(&seg)
            {
                found.push(seg);
            }
        }
        found
    }
}

/// A committee DA reader for a node outside the committee: fetches blobs
/// from the members and locates history segments they archived. `signer` is
/// the node's own session signer; it is never a committee member, so it
/// never attests.
pub fn follower_reader(
    endpoint: Endpoint,
    consensus: Arc<crate::consensus_driver::ConsensusHandle>,
    registry: crate::identity_bootstrap::RegistrySlot,
    signer: Arc<dyn RecordSigner>,
) -> Result<(
    Arc<crate::da_committee::DaCommitteeBackend>,
    Arc<IrohDaCommitteeSurface>,
)> {
    let committee: Arc<dyn CommitteeView> = Arc::new(EpochManagerCommitteeView::new(
        consensus.epoch_manager().clone(),
        registry,
    ));
    let local_address = crate::da_committee::committee_address(signer.identity());
    let surface = Arc::new(IrohDaCommitteeSurface::new(
        endpoint,
        committee.clone(),
        announced_member_endpoints(consensus),
        local_address,
    ));
    let backend = crate::da_committee::DaCommitteeBackend::new(
        signer,
        committee,
        surface.clone(),
        Arc::new(DaCommitteeStore::new()),
    )?;
    Ok((Arc::new(backend), surface))
}

/// The inbound serving half: answers each `StoreSliver` / `FetchSliver` /
/// `ChallengeSliver` from the local custody store, signing attestations with
/// the local validator key.
///
/// Owns the pieces needed to serve without touching the backend: the local
/// session signer + address (to attest) and the shared [`DaCommitteeStore`]
/// (to persist / look up slivers).
pub struct DaCommitteeServer {
    store: Arc<DaCommitteeStore>,
    signer: Arc<dyn RecordSigner>,
    local_index: LocalIndexResolver,
    local_address: Address,
    /// The node store holding this member's history segment records.
    history: Option<Arc<dyn KvStore>>,
}

impl std::fmt::Debug for DaCommitteeServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DaCommitteeServer")
            .field("local_address", &self.local_address)
            .finish_non_exhaustive()
    }
}

/// Resolves the local node's committee index at serve time. The index a member
/// signs into its attestation must match the writer's view, and the validator
/// set can change across epochs, so we re-read the committee on each request
/// rather than caching a stale index.
struct LocalIndexResolver {
    committee: Arc<dyn CommitteeView>,
    local_address: Address,
}

impl LocalIndexResolver {
    fn index(&self) -> Option<usize> {
        self.committee
            .members()
            .into_iter()
            .find(|m| m.address == self.local_address)
            .map(|m| m.index)
    }
}

impl DaCommitteeServer {
    /// Construct the inbound server. `signer` is the validator's session
    /// signer (the same one the backend attests with); `store` is the shared local
    /// custody store the writer-side backend also uses, so a sliver this node
    /// receives over the wire is visible to a later local fetch.
    pub fn new(
        committee: Arc<dyn CommitteeView>,
        store: Arc<DaCommitteeStore>,
        signer: Arc<dyn RecordSigner>,
    ) -> Self {
        let local_address = crate::da_committee::committee_address(signer.identity());
        Self {
            store,
            signer,
            local_index: LocalIndexResolver {
                committee,
                local_address,
            },
            local_address,
            history: None,
        }
    }

    /// Answer `HistorySegment` requests from the segment records in `storage`.
    pub fn with_history(mut self, storage: Arc<dyn KvStore>) -> Self {
        self.history = Some(storage);
        self
    }

    fn handle_history_segment(&self, first_index: u64) -> DaCommitteeResponse {
        let Some(storage) = &self.history else {
            return DaCommitteeResponse::HistorySegment(None);
        };
        match crate::history_archive::recorded_segment(&**storage, first_index) {
            Ok(Some(seg)) => match bincode::serialize(&seg) {
                Ok(bytes) => DaCommitteeResponse::HistorySegment(Some(bytes)),
                Err(e) => DaCommitteeResponse::Error(format!("encode segment record: {e}")),
            },
            Ok(None) => DaCommitteeResponse::HistorySegment(None),
            Err(e) => DaCommitteeResponse::Error(e.to_string()),
        }
    }

    /// Answer one request. Never panics — every decode / persist / sign
    /// failure is folded into a `DaCommitteeResponse::Error` the requester can
    /// treat as a missing attestation / missing sliver.
    fn answer(&self, request: DaCommitteeRequest) -> DaCommitteeResponse {
        match request {
            DaCommitteeRequest::StoreSliver {
                commitment,
                shape_blob,
                blob_len,
                symbol_len,
                sliver,
            } => self.handle_store(commitment, shape_blob, blob_len, symbol_len, sliver),
            DaCommitteeRequest::FetchSliver { commitment } => self.handle_fetch(commitment),
            DaCommitteeRequest::ChallengeSliver { commitment, nonce } => {
                self.handle_challenge(commitment, nonce)
            }
            DaCommitteeRequest::HistorySegment { first_index } => {
                self.handle_history_segment(first_index)
            }
        }
    }

    fn handle_store(
        &self,
        commitment: [u8; 32],
        shape_blob: Vec<u8>,
        blob_len: u64,
        symbol_len: u64,
        sliver_blob: Vec<u8>,
    ) -> DaCommitteeResponse {
        let commitment = Hash::new(commitment);
        let shape = match decode_shape(&shape_blob) {
            Ok(s) => s,
            Err(e) => return DaCommitteeResponse::Error(e.to_string()),
        };
        let sliver = match decode_sliver(&sliver_blob) {
            Ok(s) => s,
            Err(e) => return DaCommitteeResponse::Error(e.to_string()),
        };
        // Bind the sliver to the claimed commitment/shape/length before storing
        // — a member must not attest to a sliver that does not verify.
        if !tenzro_storage::redstuff::verify_sliver(
            &sliver,
            shape,
            blob_len,
            symbol_len as usize,
            &commitment,
        ) {
            return DaCommitteeResponse::Error("sliver does not verify against commitment".into());
        }
        if let Err(e) = self.store.put_sliver(StoredSliver {
            shape,
            blob_len,
            symbol_len: symbol_len as usize,
            commitment,
            sliver,
        }) {
            return DaCommitteeResponse::Error(e.to_string());
        }
        let Some(index) = self.local_index.index() else {
            // We are not in the current committee — we stored the sliver as a
            // courtesy but cannot produce a positioned attestation the writer
            // will accept.
            return DaCommitteeResponse::Error("local node is not in the current committee".into());
        };
        let msg = attestation_message(&commitment, &self.local_address);
        let signature = match self.signer.sign_record(&msg) {
            Ok(sig) => sig,
            Err(e) => return DaCommitteeResponse::Error(e.to_string()),
        };
        DaCommitteeResponse::Attestation(WireMemberAttestation {
            index: index as u64,
            address: self.local_address,
            signature,
        })
    }

    fn handle_fetch(&self, commitment: [u8; 32]) -> DaCommitteeResponse {
        let commitment = Hash::new(commitment);
        match self.store.get_sliver(&commitment) {
            Some(stored) => match encode_sliver(&stored.sliver) {
                Ok(bytes) => DaCommitteeResponse::Sliver(Some(bytes)),
                Err(e) => DaCommitteeResponse::Error(e.to_string()),
            },
            None => DaCommitteeResponse::Sliver(None),
        }
    }

    /// Answer a possession challenge: return the held sliver plus a signature
    /// binding the challenger's nonce, or an honest `None` when the sliver is
    /// not held. The challenger re-verifies the sliver against the commitment
    /// on its side, so there is nothing to be gained by answering with stale
    /// or borrowed data.
    fn handle_challenge(&self, commitment: [u8; 32], nonce: [u8; 32]) -> DaCommitteeResponse {
        let commitment = Hash::new(commitment);
        let Some(stored) = self.store.get_sliver(&commitment) else {
            return DaCommitteeResponse::PossessionProof(None);
        };
        let Some(index) = self.local_index.index() else {
            return DaCommitteeResponse::Error("local node is not in the current committee".into());
        };
        let sliver_bytes = match encode_sliver(&stored.sliver) {
            Ok(bytes) => bytes,
            Err(e) => return DaCommitteeResponse::Error(e.to_string()),
        };
        let msg = challenge_message(&commitment, &nonce, &self.local_address);
        let signature = match self.signer.sign_record(&msg) {
            Ok(sig) => sig,
            Err(e) => return DaCommitteeResponse::Error(e.to_string()),
        };
        DaCommitteeResponse::PossessionProof(Some(WirePossessionProof {
            index: index as u64,
            address: self.local_address,
            signature,
            sliver: sliver_bytes,
        }))
    }
}

#[async_trait::async_trait]
impl RequestHandler for DaCommitteeServer {
    async fn handle(&self, _remote: EndpointId, request: Bytes) -> Reply {
        let response = match bincode::deserialize::<DaCommitteeRequest>(&request) {
            Ok(request) => self.answer(request),
            Err(e) => DaCommitteeResponse::Error(format!("undecodable request: {e}")),
        };
        match bincode::serialize(&response) {
            Ok(body) => Reply::full(200, body),
            Err(e) => Reply::full(500, format!("encode response: {e}")),
        }
    }
}

fn encode_sliver(sliver: &SliverPair) -> Result<Vec<u8>> {
    bincode::serialize(sliver).map_err(|e| DaCommitteeError::Core(e.to_string()))
}

fn decode_sliver(bytes: &[u8]) -> Result<SliverPair> {
    bincode::deserialize(bytes).map_err(|e| DaCommitteeError::Core(e.to_string()))
}

fn encode_shape(shape: &CommitteeShape) -> Result<Vec<u8>> {
    bincode::serialize(shape).map_err(|e| DaCommitteeError::Core(e.to_string()))
}

fn decode_shape(bytes: &[u8]) -> Result<CommitteeShape> {
    bincode::deserialize(bytes).map_err(|e| DaCommitteeError::Core(e.to_string()))
}

fn wire_to_attestation(wire: WireMemberAttestation) -> MemberAttestation {
    MemberAttestation {
        index: wire.index as usize,
        address: wire.address,
        signature: wire.signature,
    }
}

fn wire_to_possession_proof(wire: WirePossessionProof) -> Result<PossessionProof> {
    Ok(PossessionProof {
        index: wire.index as usize,
        address: wire.address,
        signature: wire.signature,
        sliver: decode_sliver(&wire.sliver)?,
    })
}

/// Human-readable variant name for a mismatched response, used in transport
/// error messages.
fn response_kind(response: &DaCommitteeResponse) -> &'static str {
    match response {
        DaCommitteeResponse::Attestation(_) => "Attestation",
        DaCommitteeResponse::Sliver(_) => "Sliver",
        DaCommitteeResponse::PossessionProof(_) => "PossessionProof",
        DaCommitteeResponse::HistorySegment(_) => "HistorySegment",
        DaCommitteeResponse::Error(_) => "Error",
    }
}

fn member_error(e: String) -> DaCommitteeError {
    DaCommitteeError::Transport(format!("member storage error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::batch_signing::test_support::Immediate;

    fn index(r: &DaCommitteeResponse) -> u32 {
        let bytes = bincode::serialize(r).unwrap();
        u32::from_le_bytes(bytes[..4].try_into().unwrap())
    }

    #[test]
    fn the_responses_keep_their_variant_positions_and_round_trip() {
        let signer = Immediate::new(41);
        let batched = signer.sign_record(b"m").unwrap();
        let wire = WireMemberAttestation {
            index: 1,
            address: Address::new([1; 32]),
            signature: batched.clone(),
        };
        let new = DaCommitteeResponse::Attestation(wire.clone());
        let proof = DaCommitteeResponse::PossessionProof(Some(WirePossessionProof {
            index: 1,
            address: Address::new([1; 32]),
            signature: batched,
            sliver: vec![1, 2, 3],
        }));
        assert_eq!(index(&new), 0);
        assert_eq!(index(&DaCommitteeResponse::Sliver(None)), 1);
        assert_eq!(index(&proof), 2);
        assert_eq!(index(&DaCommitteeResponse::Error(String::new())), 4);
        for r in [&new, &proof] {
            let bytes = bincode::serialize(r).unwrap();
            let back: DaCommitteeResponse = bincode::deserialize(&bytes).unwrap();
            assert_eq!(&back, r);
        }
        let att = wire_to_attestation(wire);
        assert_eq!(att.index, 1);
    }
}
