//! Node-layer libp2p adapter for the committee-DA surface.
//!
//! Binds the storage-side [`DaCommitteeSurface`](crate::da_committee::DaCommitteeSurface)
//! to the network-side `/tenzro/da/committee` request_response protocol
//! (`NetworkService::da_committee_request` /
//! `subscribe_da_committee_requests` / `send_da_committee_response`).
//!
//! ## Why this file exists
//!
//! `tenzro-network` depends on `tenzro-types` + `tenzro-crypto` but NOT
//! `tenzro-storage`, so it cannot name `redstuff::SliverPair` /
//! `redstuff::CommitteeShape`. The node crate is the only crate that depends on
//! both, so this is where the typed committee-DA types are encoded into the
//! opaque `Vec<u8>` blobs the wire protocol carries (`DaCommitteeRequest` /
//! `DaCommitteeResponse` in `tenzro_network::da_committee_relay`) and decoded
//! back. This mirrors [`crate::mpc_libp2p_adapter::NetworkMpcSurface`], which
//! does the same for the MPC relay.
//!
//! ## Index → address → PeerId
//!
//! The surface addresses a member by its committee index; the wire protocol
//! addresses a peer by `PeerId`. The mapping is committee-index →
//! validator-`Address` (from the [`CommitteeView`](crate::da_committee::CommitteeView))
//! → `PeerId` (from [`AddressPeerRegistry`]). The registry is populated at the
//! same admission point the network layer uses to grant validator-topic rights:
//! when a peer's signed PeerId↔validator-identity binding verifies, the
//! validator Ed25519 pubkey's address is bound to that PeerId. A member whose
//! address has no registered PeerId is treated as unreachable — the writer only
//! needs `2f+1`, so a minority of unresolved members does not fail a submit.
//!
//! ## Inbound serving
//!
//! A validator both writes blobs (outbound) and holds slivers for blobs other
//! validators wrote (inbound). [`spawn_inbound_handler`] drives the inbound
//! side: it consumes `subscribe_da_committee_requests()` and answers each
//! request itself — a `StoreSliver` decodes the sliver, persists it to the
//! local [`DaCommitteeStore`](crate::da_committee::DaCommitteeStore), signs an
//! attestation, and replies; a `FetchSliver` returns the held sliver (or
//! `None`). The handler owns the local signing key and store so it can serve
//! without a round-trip to the backend.

use std::sync::Arc;

use dashmap::DashMap;
use libp2p::PeerId;

use tenzro_consensus::EpochManager;
use tenzro_crypto::keys::{KeyPair, PublicKey};
use tenzro_crypto::signatures::{Ed25519SignerImpl, Signer};
use tenzro_network::da_committee_relay::{
    DaCommitteeError as WireError, DaCommitteeRequest, DaCommitteeResponse, WireMemberAttestation,
};
use tenzro_network::NetworkService;
use tenzro_storage::redstuff::{CommitteeShape, SliverPair};
use tenzro_types::primitives::{Address, Hash};

use crate::da_committee::{
    attestation_message, committee_address, committee_address_from_pubkey, CommitteeMember,
    CommitteeView, DaCommitteeError, DaCommitteeStore, DaCommitteeSurface, MemberAttestation,
    StoredSliver,
};

type Result<T> = std::result::Result<T, DaCommitteeError>;

/// In-process registry binding validator on-chain `Address`es to their libp2p
/// `PeerId`s.
///
/// Populated from the network layer's validator-admission path: when a peer's
/// signed PeerId↔validator-identity binding verifies, the node records
/// `(validator_address, peer_id)` here. The committee-DA surface reads it to
/// resolve a committee member's address to the `PeerId` to dial.
///
/// This is intentionally separate from the DID↔PeerId registry the MPC relay
/// uses: MPC committees are addressed by TDIP DID, DA committees by the
/// consensus validator address. Both derive from the same libp2p transport
/// identity but key on different things.
#[derive(Default)]
pub struct AddressPeerRegistry {
    address_to_peer: DashMap<Address, PeerId>,
}

impl AddressPeerRegistry {
    /// Construct an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a `(validator_address, peer_id)` binding. Overwrites any prior
    /// binding for the same address — a validator that re-keys its transport
    /// identity gets its new PeerId here on the next verified binding.
    pub fn insert(&self, address: Address, peer_id: PeerId) {
        self.address_to_peer.insert(address, peer_id);
    }

    /// Resolve a validator address to its PeerId, if a binding is known.
    pub fn peer_id_for_address(&self, address: &Address) -> Option<PeerId> {
        self.address_to_peer.get(address).map(|v| *v.value())
    }

    /// Current number of bindings.
    pub fn len(&self) -> usize {
        self.address_to_peer.len()
    }

    /// Whether the registry currently has no bindings.
    pub fn is_empty(&self) -> bool {
        self.address_to_peer.is_empty()
    }
}

/// [`CommitteeView`] backed by the consensus [`EpochManager`]'s active
/// validator set.
///
/// The committee the DA backend encodes for is exactly the active HotStuff-2
/// validator set of the current epoch. `members()` snapshots
/// `EpochManager::current_validator_set().active_validators()` on each call so
/// encoding always tracks the current epoch — an epoch transition changes the
/// committee shape on the next operation without any explicit refresh. The
/// canonical index is the position in `active_validators()`, matching the order
/// every validator computes deterministically.
pub struct EpochManagerCommitteeView {
    epoch_manager: Arc<EpochManager>,
}

impl EpochManagerCommitteeView {
    /// Construct the view over a shared epoch manager (`consensus.epoch_manager()`).
    pub fn new(epoch_manager: Arc<EpochManager>) -> Self {
        Self { epoch_manager }
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
                public_key: v.public_key.clone(),
            })
            .collect()
    }
}

/// `DaCommitteeSurface` implementation that drives the libp2p
/// `/tenzro/da/committee` request_response protocol via a `NetworkService`.
///
/// One instance per running node. Resolves committee index → member address
/// (via the [`CommitteeView`]) → `PeerId` (via the [`AddressPeerRegistry`]),
/// then dispatches the reply-carrying request over the network layer.
pub struct NetworkDaCommitteeSurface {
    network: Arc<dyn NetworkService>,
    committee: Arc<dyn CommitteeView>,
    peers: Arc<AddressPeerRegistry>,
    local_address: Address,
}

impl NetworkDaCommitteeSurface {
    /// Construct the surface. `local_address` is the running node's own
    /// validator address; requests targeting it are short-circuited by the
    /// backend before reaching the surface, so this is only used to reject a
    /// self-directed wire request defensively.
    pub fn new(
        network: Arc<dyn NetworkService>,
        committee: Arc<dyn CommitteeView>,
        peers: Arc<AddressPeerRegistry>,
        local_address: Address,
    ) -> Self {
        Self {
            network,
            committee,
            peers,
            local_address,
        }
    }

    /// Resolve a committee index to the `PeerId` to dial.
    fn resolve_peer(&self, to_index: usize) -> Result<PeerId> {
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
        self.peers
            .peer_id_for_address(&member.address)
            .ok_or_else(|| {
                DaCommitteeError::Transport(format!(
                    "no PeerId bound for committee member {to_index} ({})",
                    member.address
                ))
            })
    }
}

#[async_trait::async_trait]
impl DaCommitteeSurface for NetworkDaCommitteeSurface {
    async fn store_sliver(
        &self,
        to_index: usize,
        commitment: &Hash,
        shape: CommitteeShape,
        blob_len: u64,
        symbol_len: usize,
        sliver: &SliverPair,
    ) -> Result<MemberAttestation> {
        let peer = self.resolve_peer(to_index)?;
        let request = DaCommitteeRequest::StoreSliver {
            commitment: commitment.0,
            shape_blob: encode_shape(&shape)?,
            blob_len,
            symbol_len: symbol_len as u64,
            sliver: encode_sliver(sliver)?,
        };
        let response = self
            .network
            .da_committee_request(peer, request)
            .await
            .map_err(|e| DaCommitteeError::Transport(e.to_string()))?;
        match response {
            DaCommitteeResponse::Attestation(wire) => Ok(wire_to_attestation(wire)),
            DaCommitteeResponse::Error(e) => Err(wire_error(e)),
            DaCommitteeResponse::Sliver(_) => Err(DaCommitteeError::Transport(
                "member answered StoreSliver with a Sliver response".into(),
            )),
        }
    }

    async fn fetch_sliver(
        &self,
        to_index: usize,
        commitment: &Hash,
    ) -> Result<Option<SliverPair>> {
        let peer = self.resolve_peer(to_index)?;
        let request = DaCommitteeRequest::FetchSliver {
            commitment: commitment.0,
        };
        let response = self
            .network
            .da_committee_request(peer, request)
            .await
            .map_err(|e| DaCommitteeError::Transport(e.to_string()))?;
        match response {
            DaCommitteeResponse::Sliver(None) => Ok(None),
            DaCommitteeResponse::Sliver(Some(bytes)) => Ok(Some(decode_sliver(&bytes)?)),
            DaCommitteeResponse::Error(e) => Err(wire_error(e)),
            DaCommitteeResponse::Attestation(_) => Err(DaCommitteeError::Transport(
                "member answered FetchSliver with an Attestation response".into(),
            )),
        }
    }
}

/// The inbound serving half: consumes `subscribe_da_committee_requests()` and
/// answers each `StoreSliver` / `FetchSliver` from the local custody store,
/// signing attestations with the local validator key.
///
/// Owns the pieces needed to serve without touching the backend: the local
/// Ed25519 signer + address (to attest), the shared [`DaCommitteeStore`] (to
/// persist / look up slivers), and the [`NetworkService`] handle (to send the
/// reply keyed by the inbound request id). One task per node.
pub struct DaCommitteeServer {
    network: Arc<dyn NetworkService>,
    store: Arc<DaCommitteeStore>,
    signer: Arc<Ed25519SignerImpl>,
    local_index: LocalIndexResolver,
    local_address: Address,
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
    /// Construct the inbound server. `local_keypair` is the validator's Ed25519
    /// key (the same one the backend attests with); `store` is the shared local
    /// custody store the writer-side backend also uses, so a sliver this node
    /// receives over the wire is visible to a later local fetch.
    pub fn new(
        network: Arc<dyn NetworkService>,
        committee: Arc<dyn CommitteeView>,
        store: Arc<DaCommitteeStore>,
        local_keypair: KeyPair,
    ) -> Result<Self> {
        let local_address = committee_address(&local_keypair)?;
        let signer = Arc::new(
            Ed25519SignerImpl::new(local_keypair)
                .map_err(|e| DaCommitteeError::Signing(e.to_string()))?,
        );
        Ok(Self {
            network,
            store,
            signer,
            local_index: LocalIndexResolver {
                committee,
                local_address,
            },
            local_address,
        })
    }

    /// Subscribe to inbound requests and spawn the serving loop. Returns the
    /// task handle; the caller keeps it alive for the node's lifetime.
    pub async fn spawn(self) -> tenzro_network::Result<tokio::task::JoinHandle<()>> {
        let mut rx = self.network.subscribe_da_committee_requests().await?;
        let handle = tokio::spawn(async move {
            while let Some(inbound) = rx.recv().await {
                let response = self.handle(inbound.request);
                if let Err(e) = self
                    .network
                    .send_da_committee_response(inbound.request_id, response)
                    .await
                {
                    tracing::debug!(
                        error = %e,
                        "committee-DA reply channel closed before response was sent"
                    );
                }
            }
            tracing::info!("committee-DA inbound handler stream ended");
        });
        Ok(handle)
    }

    /// Answer one inbound request. Never panics — every decode / persist / sign
    /// failure is folded into a `DaCommitteeResponse::Error` the requester can
    /// treat as a missing attestation / missing sliver.
    fn handle(&self, request: DaCommitteeRequest) -> DaCommitteeResponse {
        match request {
            DaCommitteeRequest::StoreSliver {
                commitment,
                shape_blob,
                blob_len,
                symbol_len,
                sliver,
            } => self.handle_store(commitment, shape_blob, blob_len, symbol_len, sliver),
            DaCommitteeRequest::FetchSliver { commitment } => self.handle_fetch(commitment),
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
            Err(e) => return DaCommitteeResponse::Error(WireError::Storage(e.to_string())),
        };
        let sliver = match decode_sliver(&sliver_blob) {
            Ok(s) => s,
            Err(e) => return DaCommitteeResponse::Error(WireError::Storage(e.to_string())),
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
            return DaCommitteeResponse::Error(WireError::Storage(
                "sliver does not verify against commitment".into(),
            ));
        }
        if let Err(e) = self.store.put_sliver(StoredSliver {
            shape,
            blob_len,
            symbol_len: symbol_len as usize,
            commitment,
            sliver,
        }) {
            return DaCommitteeResponse::Error(WireError::Storage(e.to_string()));
        }
        let Some(index) = self.local_index.index() else {
            // We are not in the current committee — we stored the sliver as a
            // courtesy but cannot produce a positioned attestation the writer
            // will accept.
            return DaCommitteeResponse::Error(WireError::Storage(
                "local node is not in the current committee".into(),
            ));
        };
        let msg = attestation_message(&commitment, &self.local_address);
        let signature = match self.signer.sign(&msg) {
            Ok(sig) => sig,
            Err(e) => return DaCommitteeResponse::Error(WireError::Storage(e.to_string())),
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
                Err(e) => DaCommitteeResponse::Error(WireError::Storage(e.to_string())),
            },
            None => DaCommitteeResponse::Sliver(None),
        }
    }
}

/// Build the address-registry seed for the local node so a self-directed
/// operation (e.g. a single-validator dev network) resolves. The backend
/// short-circuits local custody before the surface is called, so this is
/// primarily for symmetry / tests.
pub fn register_local(peers: &AddressPeerRegistry, local_key: &PublicKey, local_peer: PeerId) {
    peers.insert(committee_address_from_pubkey(local_key), local_peer);
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

fn wire_error(e: WireError) -> DaCommitteeError {
    match e {
        WireError::ServerBusy { limit } => {
            DaCommitteeError::Transport(format!("member busy (>{limit} inflight streams)"))
        }
        WireError::NoHandler => {
            DaCommitteeError::Transport("member has no committee-DA handler attached".into())
        }
        WireError::Storage(s) => DaCommitteeError::Transport(format!("member storage error: {s}")),
    }
}
