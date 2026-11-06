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

use std::collections::HashMap;
use std::sync::Arc;

use futures_util::StreamExt;
use iroh::EndpointId;
use iroh_blobs::{
    Hash,
    api::Store as BlobStore,
    provider::events::{
        AbortReason, ConnectMode, EventMask, EventSender, ProviderMessage, RequestMode,
    },
};
use parking_lot::Mutex;

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

/// Whether `peer` may fetch every one of `hashes` from `store`: a hash bound
/// to licences goes only to a peer whose current record accepts each of
/// them. A store that cannot be read refuses.
async fn may_fetch(
    store: &BlobStore,
    discovery: Option<&DiscoveryStore>,
    peer: Option<EndpointId>,
    hashes: &[Hash],
) -> bool {
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
pub fn events(store: BlobStore, discovery: Option<Arc<DiscoveryStore>>) -> EventSender {
    let mask = EventMask {
        connected: ConnectMode::Intercept,
        get: RequestMode::Intercept,
        get_many: RequestMode::Intercept,
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
                    tokio::spawn(async move {
                        let ok = may_fetch(&store, discovery.as_deref(), peer, &[hash]).await;
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
                    tokio::spawn(async move {
                        let ok = may_fetch(&store, discovery.as_deref(), peer, &hashes).await;
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
