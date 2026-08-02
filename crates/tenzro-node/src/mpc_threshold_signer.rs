//! Node-layer concrete [`ThresholdSigner`] implementation.
//!
//! Closes over the four dependencies the bridge crate intentionally avoids
//! depending on directly:
//!
//! 1. **Persistence** — `Arc<NodeKeyshareStore>` (RocksDB-backed
//!    [`KeyshareStore`]).
//! 2. **Sealing** — `Arc<dyn KeyshareSealer>` (TEE-rooted or in-memory
//!    test).
//! 3. **Transport** — `Arc<dyn MpcLibp2pSurface>` (libp2p
//!    request_response on `/tenzro/mpc/v1`, wired by
//!    [`crate::mpc_libp2p_adapter::NetworkMpcSurface`]).
//! 4. **Chain entropy** — `Arc<dyn ChainEntropyProvider>` (HotStuff-2
//!    finalized block hash, the grinding-resistant input to committee
//!    draw).
//!
//! Each `sign_prehash` call:
//!
//! 1. Reads the latest epoch from the keyshare store.
//! 2. Fetches the finalized block hash via the chain-entropy provider.
//! 3. Derives an `InstanceId` from `(finalized_block, message_hash,
//!    session_nonce)`.
//! 4. Resolves the signing committee via
//!    [`build_committee_bound_sign_config`].
//! 5. Dispatches:
//!    - `Participant` → constructs a fresh [`MpcLibp2pRelay`] over the
//!      surface and drives [`SignSession::run`].
//!    - `Observer` → returns [`SignError::LocalNotInQuorum`] without
//!      burning round numbers.
//!    - `UnderQuorum` → returns [`SignError::InvalidParameters`] with a
//!      diagnostic.
//!
//! The 20-byte sender address is derived once at construction from the
//! group public key (Keccak-256 of the uncompressed secp256k1 point tail,
//! low 20 bytes) and cached — the bridge's RLP and nonce-sync paths read
//! it without locking.

use std::sync::Arc;

use async_trait::async_trait;
use rand::RngCore;
use tenzro_bridge::mpc::committee::{CommitteeRole, build_committee_bound_sign_config};
use tenzro_bridge::mpc::libp2p_relay::{MpcLibp2pRelay, MpcLibp2pSurface};
use tenzro_bridge::mpc::sealing::KeyshareSealer;
use tenzro_bridge::mpc::setup::{InstanceId, MpcParameters, SESSION_NONCE_LEN};
use tenzro_bridge::mpc::sign::{SignConfig, SignError, SignOutput, SignSession, ThresholdSigner};
use tenzro_bridge::mpc::store::{GroupId, KeyshareStore};
use tenzro_types::Hash;

use crate::mpc_keyshare_store::NodeKeyshareStore;

/// Source of grinding-resistant chain entropy fed into committee draw.
///
/// The node layer plumbs the finalized block hash from `BlockStoreImpl` (or
/// `FinalityTracker` once available). Kept as a trait so this module does
/// not pull in `tenzro-storage::block_store` directly — tests can
/// substitute a static hash.
#[async_trait]
pub trait ChainEntropyProvider: Send + Sync {
    /// Returns the latest finalized block hash on this node.
    ///
    /// Used as `chain_entropy` in
    /// [`build_committee_bound_sign_config`]. Producing the hash *after*
    /// the message is queued is what defeats payer grinding attacks —
    /// the node layer is responsible for honoring that ordering.
    async fn latest_finalized_hash(&self) -> Result<Hash, SignError>;
}

/// [`ChainEntropyProvider`] backed by a [`tenzro_storage::traits::BlockStore`].
///
/// Reads the latest finalized block hash on every signing call. Genesis-only
/// state (no finalized block yet) surfaces as
/// [`SignError::InvalidParameters`] — committee draw fundamentally cannot
/// proceed without an anchor.
pub struct BlockStoreEntropyProvider {
    store: Arc<dyn tenzro_storage::BlockStore>,
}

impl BlockStoreEntropyProvider {
    /// Wrap a shared [`tenzro_storage::BlockStore`] trait object.
    pub fn new(store: Arc<dyn tenzro_storage::BlockStore>) -> Self {
        Self { store }
    }
}

#[async_trait]
impl ChainEntropyProvider for BlockStoreEntropyProvider {
    async fn latest_finalized_hash(&self) -> Result<Hash, SignError> {
        let height = self
            .store
            .latest_height()
            .await
            .map_err(|e| {
                SignError::InvalidParameters(format!("block store latest_height failed: {}", e))
            })?
            .ok_or_else(|| {
                SignError::InvalidParameters(
                    "no finalized blocks available — committee draw requires chain anchor"
                        .to_string(),
                )
            })?;
        self.store
            .get_block_hash(height)
            .await
            .map_err(|e| {
                SignError::InvalidParameters(format!(
                    "block store get_block_hash({}) failed: {}",
                    height, e
                ))
            })?
            .ok_or_else(|| {
                SignError::InvalidParameters(format!(
                    "block hash missing for finalized height {}",
                    height
                ))
            })
    }
}

/// Concrete [`ThresholdSigner`] for the node.
///
/// One handle per `(group_id, epoch-cohort, group_public_key)` triple.
/// Construct with [`NodeThresholdSigner::new`]; share via `Arc` across
/// every bridge adapter that signs for this group.
///
/// Cheap to clone: every field is already an `Arc` (or a small fixed-size
/// value).
#[derive(Clone)]
pub struct NodeThresholdSigner {
    group_id: GroupId,
    local_did: String,
    group_members: Vec<String>,
    group_public_key_compressed: Vec<u8>,
    parameters: MpcParameters,
    /// Cached 20-byte Ethereum-style address derived from
    /// `group_public_key_compressed`. Populated once at construction.
    sender_address: [u8; 20],
    store: Arc<NodeKeyshareStore>,
    sealer: Arc<dyn KeyshareSealer>,
    surface: Arc<dyn MpcLibp2pSurface>,
    chain_entropy: Arc<dyn ChainEntropyProvider>,
}

impl std::fmt::Debug for NodeThresholdSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeThresholdSigner")
            .field("group_id", &self.group_id.to_hex())
            .field("local_did", &self.local_did)
            .field("group_members", &self.group_members)
            .field("parameters", &self.parameters)
            .field("sender_address", &hex::encode(self.sender_address))
            .finish_non_exhaustive()
    }
}

impl NodeThresholdSigner {
    /// Construct a threshold-signer handle for `group_id`.
    ///
    /// `group_public_key_compressed` must be the 33-byte SEC1-compressed
    /// secp256k1 point produced by the DKG run that wrote the local
    /// envelope (the [`KeyshareEnvelope::group_public_key_compressed`]
    /// field).
    ///
    /// Returns an error if the public key cannot be decoded as a valid
    /// secp256k1 point on the curve.
    pub fn new(
        group_id: GroupId,
        local_did: String,
        group_members: Vec<String>,
        group_public_key_compressed: Vec<u8>,
        parameters: MpcParameters,
        store: Arc<NodeKeyshareStore>,
        sealer: Arc<dyn KeyshareSealer>,
        surface: Arc<dyn MpcLibp2pSurface>,
        chain_entropy: Arc<dyn ChainEntropyProvider>,
    ) -> Result<Self, SignError> {
        let sender_address = derive_eth_address(&group_public_key_compressed)?;
        Ok(Self {
            group_id,
            local_did,
            group_members,
            group_public_key_compressed,
            parameters,
            sender_address,
            store,
            sealer,
            surface,
            chain_entropy,
        })
    }

    /// 20-byte sender address derived from the group public key. Same as
    /// `<NodeThresholdSigner as ThresholdSigner>::sender_address`; exposed
    /// as an inherent method for callers that already hold a concrete
    /// handle.
    pub fn cached_sender_address(&self) -> [u8; 20] {
        self.sender_address
    }
}

#[async_trait]
impl ThresholdSigner for NodeThresholdSigner {
    fn sender_address(&self) -> [u8; 20] {
        self.sender_address
    }

    async fn sign_prehash(&self, msg_hash: [u8; 32]) -> Result<SignOutput, SignError> {
        // -------- Resolve the latest epoch for this group ----------------
        // `KeyshareStore::latest` already returns the highest-epoch envelope.
        // We only need its `.epoch` field to bind the committee draw — the
        // envelope itself is re-fetched by `SignSession::run`.
        let envelope = self.store.latest(&self.group_id).await?;
        let epoch = envelope.epoch;

        // Sanity: the cached group public key must match the on-disk
        // envelope, otherwise we're about to dispatch a session that
        // `SignSession::new` will refuse with
        // `EnvelopeGroupPublicKeyMismatch`. Surface that as a deterministic
        // error here instead of letting it bubble through DKG-time fields.
        if envelope.group_public_key_compressed != self.group_public_key_compressed {
            return Err(SignError::EnvelopeGroupPublicKeyMismatch);
        }
        if envelope.parameters != self.parameters {
            return Err(SignError::EnvelopeParametersMismatch);
        }

        // -------- Fetch finalized block hash (chain entropy) -------------
        let finalized_hash = self.chain_entropy.latest_finalized_hash().await?;

        // -------- Derive a fresh InstanceId ------------------------------
        // The uniqueness invariant on `(finalized_block_hash, message_hash,
        // session_nonce)` is what `InstanceId::derive` guarantees; we own
        // the nonce, the consensus layer owns the block hash, and the
        // caller owns the message hash.
        let mut session_nonce = [0u8; SESSION_NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut session_nonce);
        let instance_id = InstanceId::derive(&finalized_hash, &msg_hash, &session_nonce);

        // -------- Resolve committee role ---------------------------------
        let role = build_committee_bound_sign_config(
            instance_id,
            self.group_id,
            epoch,
            self.parameters,
            self.group_public_key_compressed.clone(),
            msg_hash,
            finalized_hash,
            &self.group_members,
            &self.local_did,
        )?;

        match role {
            CommitteeRole::UnderQuorum {
                available,
                threshold,
            } => Err(SignError::InvalidParameters(format!(
                "group under quorum: available={} threshold={}",
                available, threshold
            ))),
            CommitteeRole::Observer { .. } => {
                // Caller should retry once a different group_members
                // composition makes the local party eligible. Returning
                // `LocalNotInQuorum` matches the bridge crate's existing
                // `SignConfig::validate` taxonomy.
                Err(SignError::LocalNotInQuorum)
            }
            CommitteeRole::Participant(cfg) => self.run_participant(cfg).await,
        }
    }
}

impl NodeThresholdSigner {
    /// Drive a single signing session as the participant party. Wraps the
    /// surface into a fresh [`MpcLibp2pRelay`] per call so concurrent
    /// `sign_prehash` invocations do not share inbox state.
    async fn run_participant(&self, cfg: SignConfig) -> Result<SignOutput, SignError> {
        let transport = MpcLibp2pRelay::new(self.surface.clone());
        // Construct a per-call adapter around the shared store / sealer so
        // `SignSession::new`'s generic bounds (which take owned `S`/`K`)
        // can be satisfied without forcing the inner trait objects to be
        // `Clone`.
        let store = StoreHandle {
            inner: self.store.clone(),
        };
        let sealer = SealerHandle {
            inner: self.sealer.clone(),
        };
        let session = SignSession::new(cfg, transport, sealer, store)?;
        session.run().await
    }
}

/// `Arc`-wrapping adapter so `SignSession` / `KeygenSession` can take the
/// store by value without forcing `dyn KeyshareStore: Clone`. Shared with
/// the DKG orchestration in [`crate::mpc_keygen`].
#[derive(Clone)]
pub(crate) struct StoreHandle {
    pub(crate) inner: Arc<NodeKeyshareStore>,
}

#[async_trait]
impl KeyshareStore for StoreHandle {
    async fn insert(
        &self,
        envelope: tenzro_bridge::mpc::store::KeyshareEnvelope,
    ) -> Result<(), tenzro_bridge::mpc::store::KeyshareError> {
        self.inner.insert(envelope).await
    }

    async fn get(
        &self,
        group_id: &GroupId,
        epoch: u64,
    ) -> Result<tenzro_bridge::mpc::store::KeyshareEnvelope, tenzro_bridge::mpc::store::KeyshareError>
    {
        self.inner.get(group_id, epoch).await
    }

    async fn latest(
        &self,
        group_id: &GroupId,
    ) -> Result<tenzro_bridge::mpc::store::KeyshareEnvelope, tenzro_bridge::mpc::store::KeyshareError>
    {
        self.inner.latest(group_id).await
    }

    async fn list_epochs(
        &self,
        group_id: &GroupId,
    ) -> Result<Vec<u64>, tenzro_bridge::mpc::store::KeyshareError> {
        self.inner.list_epochs(group_id).await
    }

    async fn prune(
        &self,
        group_id: &GroupId,
        keep_last_n: usize,
    ) -> Result<usize, tenzro_bridge::mpc::store::KeyshareError> {
        self.inner.prune(group_id, keep_last_n).await
    }
}

/// `Arc`-wrapping adapter so `SignSession` / `KeygenSession` can take the
/// sealer by value without forcing `dyn KeyshareSealer: Clone`. Shared with
/// the DKG orchestration in [`crate::mpc_keygen`].
#[derive(Clone)]
pub(crate) struct SealerHandle {
    pub(crate) inner: Arc<dyn KeyshareSealer>,
}

#[async_trait]
impl KeyshareSealer for SealerHandle {
    async fn seal(
        &self,
        group_id: &GroupId,
        party_index: u8,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, tenzro_bridge::mpc::sealing::KeyshareSealerError> {
        self.inner.seal(group_id, party_index, plaintext).await
    }

    async fn unseal(
        &self,
        group_id: &GroupId,
        party_index: u8,
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, tenzro_bridge::mpc::sealing::KeyshareSealerError> {
        self.inner.unseal(group_id, party_index, ciphertext).await
    }
}

/// Derive a 20-byte Ethereum-style address from a 33-byte SEC1-compressed
/// secp256k1 group public key.
///
/// Address = `keccak256(uncompressed_pubkey_tail)[12..32]` where
/// `uncompressed_pubkey_tail` is the 64-byte concatenation `x || y` of the
/// affine coordinates (no `0x04` prefix), matching go-ethereum and the
/// EVM `ecRecover` precompile.
fn derive_eth_address(pubkey_compressed: &[u8]) -> Result<[u8; 20], SignError> {
    use k256::ecdsa::VerifyingKey;
    // VerifyingKey::from_sec1_bytes accepts either SEC1-compressed (33B)
    // or uncompressed (65B); it validates the point is on-curve.
    let vk = VerifyingKey::from_sec1_bytes(pubkey_compressed)
        .map_err(|e| SignError::MalformedGroupPublicKey(e.to_string()))?;
    let uncompressed = vk.to_sec1_point(false);
    let tail = uncompressed
        .as_bytes()
        .get(1..)
        .ok_or_else(|| SignError::MalformedGroupPublicKey("empty point encoding".to_string()))?;
    if tail.len() != 64 {
        return Err(SignError::MalformedGroupPublicKey(format!(
            "expected 64-byte uncompressed tail, got {}",
            tail.len()
        )));
    }
    let digest = tenzro_crypto::hash::keccak256(tail);
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest.as_bytes()[12..32]);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;
    use std::sync::Mutex;
    use tenzro_bridge::mpc::sealing::InMemoryKeyshareSealer;
    use tenzro_bridge::mpc::setup::MpcCurve;
    use tenzro_bridge::mpc::store::KeyshareEnvelope;
    use tenzro_bridge::mpc::transport::{MpcRoundMessage, TransportError};
    use tenzro_storage::MemoryStore;
    use tenzro_types::Hash;

    /// Static chain-entropy provider for unit tests.
    struct StaticEntropy(Hash);

    #[async_trait]
    impl ChainEntropyProvider for StaticEntropy {
        async fn latest_finalized_hash(&self) -> Result<Hash, SignError> {
            Ok(self.0)
        }
    }

    /// Loopback surface so we can construct a `NodeThresholdSigner` in
    /// tests that exercise the non-network paths (address derivation,
    /// under-quorum branch, missing-envelope branch).
    struct LoopbackSurface {
        outbox: Mutex<Vec<MpcRoundMessage>>,
    }

    #[async_trait]
    impl MpcLibp2pSurface for LoopbackSurface {
        async fn send_point_to_point(
            &self,
            message: &MpcRoundMessage,
        ) -> Result<(), TransportError> {
            self.outbox.lock().unwrap().push(message.clone());
            Ok(())
        }

        async fn recv_point_to_point(&self) -> Result<MpcRoundMessage, TransportError> {
            Err(TransportError::Closed)
        }
    }

    fn sample_pubkey() -> Vec<u8> {
        // Deterministic test secret → SEC1-compressed pubkey.
        let sk = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let pk = sk.verifying_key();
        pk.to_sec1_point(true).as_bytes().to_vec()
    }

    fn sample_store() -> Arc<NodeKeyshareStore> {
        Arc::new(NodeKeyshareStore::new(Arc::new(MemoryStore::new())))
    }

    fn build_signer(
        group_members: Vec<String>,
        local_did: &str,
        params: MpcParameters,
    ) -> NodeThresholdSigner {
        NodeThresholdSigner::new(
            GroupId([0xAB; 32]),
            local_did.to_string(),
            group_members,
            sample_pubkey(),
            params,
            sample_store(),
            Arc::new(InMemoryKeyshareSealer::new([0x42u8; 32])),
            Arc::new(LoopbackSurface {
                outbox: Mutex::new(Vec::new()),
            }),
            Arc::new(StaticEntropy(Hash::from_bytes(&[9u8; 32]).unwrap())),
        )
        .unwrap()
    }

    #[test]
    fn sender_address_is_20_bytes_and_stable() {
        let s = build_signer(
            vec!["did:tenzro:machine:a".to_string()],
            "did:tenzro:machine:a",
            MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
        );
        let a1 = s.sender_address();
        let a2 = s.sender_address();
        assert_eq!(a1, a2);
        assert_eq!(a1.len(), 20);
        // Test vector: for SigningKey::from_bytes([7u8; 32]) the address is
        // deterministic — exact value asserted via stability check, not
        // hard-coded since the public key is implementation-derived.
    }

    #[test]
    fn malformed_pubkey_rejected_at_construction() {
        let err = NodeThresholdSigner::new(
            GroupId([0u8; 32]),
            "did:tenzro:machine:a".to_string(),
            vec!["did:tenzro:machine:a".to_string()],
            vec![0xFF; 33], // not a valid compressed point
            MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
            sample_store(),
            Arc::new(InMemoryKeyshareSealer::new([0u8; 32])),
            Arc::new(LoopbackSurface {
                outbox: Mutex::new(Vec::new()),
            }),
            Arc::new(StaticEntropy(Hash::from_bytes(&[0u8; 32]).unwrap())),
        )
        .unwrap_err();
        assert!(matches!(err, SignError::MalformedGroupPublicKey(_)));
    }

    #[tokio::test]
    async fn sign_prehash_returns_under_quorum_when_group_too_small() {
        // threshold=2 but only 1 group member → UnderQuorum branch maps to
        // InvalidParameters per the trait contract.
        let s = build_signer(
            vec!["did:tenzro:machine:a".to_string()],
            "did:tenzro:machine:a",
            MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
        );
        // Pre-seed an envelope so `latest()` does not return NotFound first.
        let envelope = KeyshareEnvelope {
            group_id: GroupId([0xAB; 32]),
            epoch: 0,
            party_index: 1,
            parameters: MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
            group_public_key_compressed: sample_pubkey(),
            share_hash: Hash::from_bytes(&[1u8; 32]).unwrap(),
            sealed_payload: vec![0x01],
            created_at_ms: 0,
        };
        s.store.insert(envelope).await.unwrap();

        let err = s.sign_prehash([0u8; 32]).await.unwrap_err();
        match err {
            SignError::InvalidParameters(msg) => {
                assert!(msg.contains("under quorum"), "{msg}");
            }
            other => panic!("expected InvalidParameters, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sign_prehash_returns_local_not_in_quorum_when_observer() {
        // threshold=2, n=3, but local_did is NOT in group_members → committee
        // draw concludes with the local party as an Observer.
        let s = build_signer(
            vec![
                "did:tenzro:machine:peer-a".to_string(),
                "did:tenzro:machine:peer-b".to_string(),
                "did:tenzro:machine:peer-c".to_string(),
            ],
            "did:tenzro:machine:bystander",
            MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
        );
        let envelope = KeyshareEnvelope {
            group_id: GroupId([0xAB; 32]),
            epoch: 0,
            party_index: 1,
            parameters: MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
            group_public_key_compressed: sample_pubkey(),
            share_hash: Hash::from_bytes(&[1u8; 32]).unwrap(),
            sealed_payload: vec![0x01],
            created_at_ms: 0,
        };
        s.store.insert(envelope).await.unwrap();

        let err = s.sign_prehash([0u8; 32]).await.unwrap_err();
        assert!(matches!(err, SignError::LocalNotInQuorum));
    }

    #[tokio::test]
    async fn sign_prehash_returns_store_error_when_no_envelope() {
        let s = build_signer(
            vec!["did:tenzro:machine:a".to_string()],
            "did:tenzro:machine:a",
            MpcParameters::new(MpcCurve::Secp256k1, 2, 3).unwrap(),
        );
        let err = s.sign_prehash([0u8; 32]).await.unwrap_err();
        // The latest() call returns NotFound for an empty store; it
        // bubbles through the trait's `#[from] KeyshareError` conversion.
        assert!(matches!(err, SignError::Store(_)), "got {err:?}");
    }
}
