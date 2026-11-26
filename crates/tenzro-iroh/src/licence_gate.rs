//! Blobs served only to machines whose operator accepted their licence.
//!
//! Some model weights are published under a licence their origin makes each
//! user accept before fetching them. A node whose operator accepted it holds
//! the weights and serves them to other nodes by content hash, but only to a
//! machine whose current endpoint record (signed by its hardware key, see
//! [`crate::identity_record`]) states that its operator accepted the same
//! licence. Every other request for the blob is refused before a byte moves.
//!
//! A blob is bound to a licence by a tag in the blob store, so the binding
//! persists with the bytes and is in force from the first request after a
//! restart. A node binds the hash before the bytes enter its store, so they
//! are never served unbound.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use futures_util::StreamExt;
use iroh::EndpointId;
use iroh_blobs::{
    Hash,
    api::Store as BlobStore,
    provider::events::{
        AbortReason, ConnectMode, EventMask, EventSender, ProviderMessage, RequestMode,
        ThrottleMode,
    },
};
use parking_lot::{Mutex, RwLock};

use crate::discovery::DiscoveryStore;
use crate::error::{IrohError, IrohResult};
use crate::identity_record::is_licence_id;

/// Prefix of the store tags that bind a blob to a licence:
/// `tenzro/licence/<blake3 hex>/<licence id>`.
pub const LICENCE_TAG_PREFIX: &str = "tenzro/licence/";

fn hash_prefix(hash: &Hash) -> String {
    format!("{LICENCE_TAG_PREFIX}{}/", hash.to_hex())
}

/// Binds `hash` to `licence` in `store`.
pub async fn bind(store: &BlobStore, hash: Hash, licence: &str) -> IrohResult<()> {
    if !is_licence_id(licence) {
        return Err(IrohError::Backend(format!(
            "licence id {licence:?} is not in the record form"
        )));
    }
    store
        .tags()
        .set(format!("{}{licence}", hash_prefix(&hash)), hash)
        .await
        .map_err(|e| IrohError::Backend(format!("binding {hash} to {licence}: {e}")))
}

/// The licences `hash` is bound to in `store`.
pub async fn licences_of(store: &BlobStore, hash: Hash) -> IrohResult<Vec<String>> {
    let prefix = hash_prefix(&hash);
    let mut tags = store
        .tags()
        .list_prefix(prefix.as_bytes())
        .await
        .map_err(|e| IrohError::Backend(format!("reading the licences of {hash}: {e}")))?;
    let mut out = Vec::new();
    while let Some(tag) = tags.next().await {
        let tag =
            tag.map_err(|e| IrohError::Backend(format!("reading the licences of {hash}: {e}")))?;
        let name = String::from_utf8_lossy(tag.name.0.as_ref()).into_owned();
        if let Some(id) = name.strip_prefix(&prefix) {
            out.push(id.to_string());
        }
    }
    Ok(out)
}

/// The blobs a peer without a registered identity may fetch: the files of
/// the state snapshots this node retains. A node joining by snapshot is not
/// registered yet; everything else in the store stays closed to it.
#[derive(Clone, Default)]
pub struct SnapshotBlobs(Arc<RwLock<HashSet<Hash>>>);

impl SnapshotBlobs {
    /// Replaces the set with the files of the snapshots retained now.
    pub fn set(&self, hashes: impl IntoIterator<Item = [u8; 32]>) {
        *self.0.write() = hashes.into_iter().map(Hash::from_bytes).collect();
    }

    fn holds(&self, hash: &Hash) -> bool {
        self.0.read().contains(hash)
    }
}

/// Whether `peer` may fetch every one of `hashes` from `store`. A peer
/// without full access gets only snapshot files. A hash bound to licences
/// goes only to a peer whose current record accepts each of them. A store
/// that cannot be read refuses.
async fn may_fetch(
    store: &BlobStore,
    discovery: Option<&DiscoveryStore>,
    peer: Option<EndpointId>,
    full_access: bool,
    snapshots: &SnapshotBlobs,
    hashes: &[Hash],
) -> bool {
    if !full_access && !hashes.iter().all(|h| snapshots.holds(h)) {
        tracing::debug!(
            ?peer,
            "blob refused to a peer with no registered identity: not a snapshot file"
        );
        return false;
    }
    for hash in hashes {
        let licences = match licences_of(store, *hash).await {
            Ok(l) => l,
            Err(e) => {
                tracing::warn!(error = %e, "blob request refused: its licences could not be read");
                return false;
            }
        };
        if licences.is_empty() {
            continue;
        }
        let accepted = match (discovery, peer) {
            (Some(d), Some(p)) => licences.iter().all(|l| d.accepts_licence(p, l)),
            _ => false,
        };
        if !accepted {
            tracing::debug!(%hash, ?peer, ?licences, "licence-bound blob refused to a peer that did not accept its licence");
            return false;
        }
    }
    true
}

/// The provider event hook that enforces licence bindings on every get
/// request served from `store`. A request for a hash sequence's children is
/// refused: the network fetches single blobs, and a sequence would name
/// children no per-hash check saw.
///
/// `gate` says whether the requesting peer is a registered identity; one
/// that is not is served only the files in `snapshots`. With a `pacer`,
/// every chunk sent waits for the peer's upload rate
/// ([`crate::bulk_pacer`]).
pub fn events(
    store: BlobStore,
    discovery: Option<Arc<DiscoveryStore>>,
    gate: crate::identity_gate::IdentityGate,
    snapshots: SnapshotBlobs,
    pacer: Option<Arc<crate::bulk_pacer::BulkPacer>>,
) -> EventSender {
    let mask = EventMask {
        connected: ConnectMode::Intercept,
        get: RequestMode::Intercept,
        get_many: RequestMode::Intercept,
        throttle: if pacer.is_some() {
            ThrottleMode::Intercept
        } else {
            ThrottleMode::None
        },
        ..EventMask::DEFAULT
    };
    let (tx, mut rx) = EventSender::channel(64, mask);
    tokio::spawn(async move {
        let peers: Arc<Mutex<HashMap<u64, Option<EndpointId>>>> = Arc::default();
        while let Some(msg) = rx.recv().await {
            match msg {
                ProviderMessage::ClientConnected(msg) => {
                    peers.lock().insert(msg.connection_id, msg.endpoint_id);
                    msg.tx.send(Ok(())).await.ok();
                }
                ProviderMessage::ConnectionClosed(msg) => {
                    peers.lock().remove(&msg.connection_id);
                }
                ProviderMessage::GetRequestReceived(msg) => {
                    let peer = peers.lock().get(&msg.connection_id).copied().flatten();
                    if !msg.request.ranges.is_blob() {
                        msg.tx.send(Err(AbortReason::Permission)).await.ok();
                        continue;
                    }
                    let (store, discovery, hash) =
                        (store.clone(), discovery.clone(), msg.request.hash);
                    let (full, snapshots) = (gate.holds_full_access(peer), snapshots.clone());
                    tokio::spawn(async move {
                        let ok = may_fetch(
                            &store,
                            discovery.as_deref(),
                            peer,
                            full,
                            &snapshots,
                            &[hash],
                        )
                        .await;
                        msg.tx
                            .send(if ok {
                                Ok(())
                            } else {
                                Err(AbortReason::Permission)
                            })
                            .await
                            .ok();
                    });
                }
                ProviderMessage::GetManyRequestReceived(msg) => {
                    let peer = peers.lock().get(&msg.connection_id).copied().flatten();
                    let (store, discovery, hashes) =
                        (store.clone(), discovery.clone(), msg.request.hashes.clone());
                    let (full, snapshots) = (gate.holds_full_access(peer), snapshots.clone());
                    tokio::spawn(async move {
                        let ok = may_fetch(
                            &store,
                            discovery.as_deref(),
                            peer,
                            full,
                            &snapshots,
                            &hashes,
                        )
                        .await;
                        msg.tx
                            .send(if ok {
                                Ok(())
                            } else {
                                Err(AbortReason::Permission)
                            })
                            .await
                            .ok();
                    });
                }
                ProviderMessage::Throttle(msg) => {
                    let peer = peers.lock().get(&msg.connection_id).copied().flatten();
                    match (peer, pacer.clone()) {
                        (Some(peer), Some(pacer)) => {
                            let size = msg.size;
                            tokio::spawn(async move {
                                pacer.pace(peer, size).await;
                                msg.tx.send(Ok(())).await.ok();
                            });
                        }
                        _ => {
                            msg.tx.send(Ok(())).await.ok();
                        }
                    }
                }
                _ => {}
            }
        }
    });
    tx
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use iroh::address_lookup::memory::MemoryLookup;
    use tenzro_types::tenzro_uri::TenzroUri;

    use super::*;
    use crate::identity_record::tests::TestMachineKey;
    use crate::identity_record::{EndpointRecord, RecordScope};
    use crate::identity_transport::iroh_endpoint_key;
    use crate::relay::now_ms;
    use crate::resolver::{IrohBackedResolver, IrohResolver};

    async fn node(lookup: &MemoryLookup) -> (Arc<IrohBackedResolver>, Arc<DiscoveryStore>) {
        let discovery = Arc::new(DiscoveryStore::new());
        (
            IrohBackedResolver::bind_for_test(lookup, discovery.clone())
                .await
                .unwrap(),
            discovery,
        )
    }

    /// `key`'s record for `node`'s endpoint, number `sequence`, accepting `licences`.
    fn record(
        key: &TestMachineKey,
        node: &IrohBackedResolver,
        sequence: u64,
        licences: &[&str],
    ) -> EndpointRecord {
        EndpointRecord::sign(
            key,
            iroh_endpoint_key(node.endpoint().id()),
            vec![],
            Vec::new(),
            None,
            RecordScope::Network,
            licences.iter().map(|l| l.to_string()).collect(),
            sequence,
            now_ms(),
        )
        .unwrap()
    }

    fn from(provider: &IrohBackedResolver, hash: &str) -> TenzroUri {
        TenzroUri::Blob {
            hash: hash.to_string(),
            provider_hint: Some(provider.endpoint().id().to_string()),
        }
    }

    /// A registry in which nobody is registered.
    struct NobodyRegistered;
    impl crate::identity_gate::RegistryView for NobodyRegistered {
        fn standing(&self, _: &str) -> tenzro_onboarding_types::onboarding::Standing {
            tenzro_onboarding_types::onboarding::Standing::Unregistered
        }
    }

    /// A blob served to a peer whose path shows a queue goes at the pacer's
    /// floor; the same blob to a peer with no queue goes at once.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_upload_to_a_peer_behind_a_queue_is_paced() {
        let lookup = MemoryLookup::new();
        let paths = crate::paths::Paths::new();
        let provider = IrohBackedResolver::bind_for_test_with_paths(
            &lookup,
            Arc::new(DiscoveryStore::new()),
            Some(paths.clone()),
        )
        .await
        .unwrap();
        let (queued, _) = node(&lookup).await;
        let (clear, _) = node(&lookup).await;
        let blob = Bytes::from(vec![7u8; 768 * 1024]);
        let hash = match provider.publish_bytes(blob.clone()).await.unwrap() {
            TenzroUri::Blob { hash, .. } => hash,
            other => panic!("{other}"),
        };
        let addr = iroh::TransportAddr::Ip("192.0.2.1:1".parse().unwrap());
        let t = std::time::Instant::now();
        for (peer, queue_ms) in [(queued.endpoint().id(), 100), (clear.endpoint().id(), 0)] {
            let latency = paths.latency_source();
            latency.record_sample(peer, addr.clone(), std::time::Duration::from_millis(10), t);
            latency.record_sample(
                peer,
                addr.clone(),
                std::time::Duration::from_millis(10 + queue_ms),
                t,
            );
        }

        let started = std::time::Instant::now();
        assert_eq!(
            clear.fetch_bytes(&from(&provider, &hash)).await.unwrap(),
            blob
        );
        let unpaced = started.elapsed();
        let started = std::time::Instant::now();
        assert_eq!(
            queued.fetch_bytes(&from(&provider, &hash)).await.unwrap(),
            blob
        );
        let paced = started.elapsed();
        // 768 KiB at the 256 KiB/s floor, the first chunk free: about 3 s.
        assert!(
            paced >= std::time::Duration::from_secs(2),
            "the upload behind a queue took {paced:?}"
        );
        assert!(
            unpaced < std::time::Duration::from_secs(1),
            "the upload with no queue took {unpaced:?}"
        );
    }

    #[tokio::test]
    async fn a_peer_with_no_registered_identity_fetches_snapshot_files_and_nothing_else() {
        use tenzro_onboarding_types::onboarding::{GateMode, OnboardingPolicy};

        let lookup = MemoryLookup::new();
        let (provider, _) = node(&lookup).await;
        let (joiner, _) = node(&lookup).await;
        let snapshot = Bytes::from_static(b"a bucket of a retained snapshot");
        let weights = Bytes::from_static(b"model weights");
        let hash_of = |uri: TenzroUri| match uri {
            TenzroUri::Blob { hash, .. } => hash,
            other => panic!("{other}"),
        };
        let snapshot_hash = hash_of(provider.publish_bytes(snapshot.clone()).await.unwrap());
        let weights_hash = hash_of(provider.publish_bytes(weights.clone()).await.unwrap());

        // The provider's gate is in force and knows the joiner as nobody.
        provider.identity_gate().set_policy(OnboardingPolicy {
            mode: GateMode::Enforce,
            ..OnboardingPolicy::default()
        });
        provider
            .identity_gate()
            .install_registry(Arc::new(NobodyRegistered));
        provider
            .snapshot_blobs()
            .set([*Hash::new(&snapshot).as_bytes()]);

        assert_eq!(
            joiner
                .fetch_bytes(&from(&provider, &snapshot_hash))
                .await
                .unwrap(),
            snapshot
        );
        assert!(
            joiner
                .fetch_bytes(&from(&provider, &weights_hash))
                .await
                .is_err(),
            "a blob that is no snapshot file went to a peer with no registered identity"
        );
    }

    #[tokio::test]
    async fn a_licence_bound_blob_goes_only_to_a_machine_that_accepted_its_licence() {
        let lookup = MemoryLookup::new();
        let (provider, _) = node(&lookup).await;
        let (requester, requester_book) = node(&lookup).await;
        let key = TestMachineKey::from_seed(81);

        // An unbound blob goes to anyone.
        let open = provider
            .publish_bytes(Bytes::from_static(b"open weights"))
            .await
            .unwrap();
        let TenzroUri::Blob {
            hash: open_hash, ..
        } = &open
        else {
            panic!("{open}")
        };
        assert_eq!(
            requester
                .fetch_bytes(&from(&provider, open_hash))
                .await
                .unwrap(),
            Bytes::from_static(b"open weights")
        );

        // Bound before it is published, it is never served unbound.
        let gated_bytes = Bytes::from_static(b"gated weights");
        let gated_hash = Hash::new(&gated_bytes).to_string();
        provider
            .bind_licence(&gated_hash, "custom-terms")
            .await
            .unwrap();
        provider.publish_bytes(gated_bytes.clone()).await.unwrap();
        assert_eq!(
            licences_of(&provider.store().clone(), Hash::new(&gated_bytes))
                .await
                .unwrap(),
            vec!["custom-terms"]
        );

        // A machine with no record is refused.
        assert!(
            requester
                .fetch_bytes(&from(&provider, &gated_hash))
                .await
                .is_err()
        );

        // A machine whose record accepts another licence is refused.
        requester
            .bind_licence(&gated_hash, "custom-terms")
            .await
            .unwrap();
        requester_book
            .offer(record(&key, &requester, 1, &["other-terms"]))
            .unwrap();
        assert!(
            requester
                .fetch_bytes(&from(&provider, &gated_hash))
                .await
                .is_err()
        );

        // Once its record states the licence, the provider serves it.
        requester_book
            .offer(record(
                &key,
                &requester,
                2,
                &["custom-terms", "other-terms"],
            ))
            .unwrap();
        assert_eq!(
            requester
                .fetch_bytes(&from(&provider, &gated_hash))
                .await
                .unwrap(),
            gated_bytes
        );
    }

    #[tokio::test]
    async fn a_licence_id_outside_the_record_form_is_not_bound() {
        let lookup = MemoryLookup::new();
        let (provider, _) = node(&lookup).await;
        let hash = Hash::new(b"x").to_string();
        assert!(provider.bind_licence(&hash, "Not A Licence").await.is_err());
        assert!(provider.bind_licence(&hash, "").await.is_err());
    }
}
