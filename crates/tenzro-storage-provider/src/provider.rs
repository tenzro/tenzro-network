//! Storage provider daemon (D1): accept objects, persist erasure shards over
//! the iroh content-addressed transport, and serve objects back on request.
//!
//! # Flow
//!
//! - **Store.** A renter submits an object's bytes plus a [`RedundancyScheme`].
//!   The provider erasure-encodes it (`redundancy::encode`), publishes each
//!   shard through the [`IrohResolver`] (which returns a content-addressed
//!   `tenzro://blob/<blake3>` URI per shard), and records an
//!   [`ObjectDescriptor`] binding the object id to its shard URIs, per-shard
//!   commitments, byte length, and scheme. The descriptor is the durable
//!   manifest; the bytes live in iroh-blobs.
//! - **Serve.** Given an object id, the provider fetches each shard URI back
//!   through the resolver, rebuilds [`Shard`]s (verifying each against its
//!   recorded commitment), and reconstructs the object — tolerating up to
//!   `parity_shards` missing or corrupt shards.
//!
//! # Source of truth
//!
//! Like the iroh stores it wraps, [`StorageProvider`] is a node-local actor.
//! The on-chain settlement state (per-byte metering, payment) is owned by
//! [`crate::metering`]; durable cross-node placement is owned by
//! [`crate::redundancy`] descriptors anchored on-chain. This type only handles
//! the local accept/serve loop and an in-memory descriptor index.

use crate::error::{Result, StorageProviderError};
use crate::redundancy::{self, RedundancyScheme, Shard};
use bytes::Bytes;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tenzro_iroh::{IrohResolver, TenzroUri};
use tenzro_storage::{KvStore, CF_SETTLEMENTS};
use tenzro_types::access_policy::{AccessPolicy, ConfidentialSeal};
use tracing::{debug, info, warn};

/// RocksDB key prefix (in `CF_SETTLEMENTS`) for persisted object descriptors.
const STORAGE_OBJECT_PREFIX: &[u8] = b"storage_object:";

/// Durable manifest for a stored object: enough to fetch every shard back and
/// reconstruct, plus the integrity commitments to detect tampering.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectDescriptor {
    /// Application-level object identifier (caller-assigned, unique per owner).
    pub object_id: String,
    /// Owner address bytes (hex) — the renter who pays for this object.
    pub owner_hex: String,
    /// True original byte length, used to strip erasure padding on rebuild.
    pub size_bytes: u64,
    /// Redundancy scheme the shards were encoded under.
    pub scheme: RedundancyScheme,
    /// One entry per shard, in shard-index order (`0..n`).
    pub shards: Vec<ShardRef>,
    /// Who may retrieve and administer this object — the same policy the
    /// database tier gates on, enforced identically across local, LAN-cluster,
    /// and network placement. A node layer that links `tenzro-auth` adjudicates
    /// the caller's capability against this before serving shards back.
    pub access_policy: AccessPolicy,
    /// Opt-in encryption-at-rest for network-tier objects: when set, the stored
    /// shards are ciphertext and the data key is wrapped once per authorized
    /// DID. Absent for plaintext objects.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidential: Option<ConfidentialSeal>,
}

impl ObjectDescriptor {
    /// Number of distinct shards this object was split into (`n = k + m`).
    pub fn shard_count(&self) -> usize {
        self.shards.len()
    }
}

/// A reference to one stored shard: where to fetch it and how to verify it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardRef {
    /// Index in `0..n` (matches [`Shard::index`]).
    pub index: usize,
    /// Content-addressed URI the shard bytes were published under.
    pub uri: String,
    /// Hex SHA-256 commitment of the shard bytes.
    pub commitment: String,
}

/// Node-local storage provider over an iroh transport.
pub struct StorageProvider {
    /// Content-addressed transport used to publish + fetch shard bytes.
    resolver: Arc<dyn IrohResolver>,
    /// Object descriptors by object id.
    objects: DashMap<String, ObjectDescriptor>,
    /// Durable store for object descriptors, so held objects survive restart.
    storage: Option<Arc<dyn KvStore>>,
}

impl std::fmt::Debug for StorageProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageProvider")
            .field("objects", &self.objects.len())
            .finish()
    }
}

impl StorageProvider {
    /// Creates a provider over the given content-addressed transport.
    pub fn new(resolver: Arc<dyn IrohResolver>) -> Self {
        Self {
            resolver,
            objects: DashMap::new(),
            storage: None,
        }
    }

    /// Creates a provider whose descriptor index is durable: persisted object
    /// descriptors are hydrated from `CF_SETTLEMENTS` on construction and
    /// written through on every `store_object`.
    pub fn with_storage(resolver: Arc<dyn IrohResolver>, storage: Arc<dyn KvStore>) -> Self {
        let objects = DashMap::new();
        match storage.get_keys_with_prefix(CF_SETTLEMENTS, STORAGE_OBJECT_PREFIX) {
            Ok(keys) => {
                for key in keys {
                    let value = match storage.get(CF_SETTLEMENTS, &key) {
                        Ok(Some(v)) => v,
                        Ok(None) => continue,
                        Err(e) => {
                            warn!("Failed to read persisted object descriptor: {}", e);
                            continue;
                        }
                    };
                    match serde_json::from_slice::<ObjectDescriptor>(&value) {
                        Ok(desc) => {
                            objects.insert(desc.object_id.clone(), desc);
                        }
                        Err(e) => warn!("Skipping unparseable persisted object descriptor: {}", e),
                    }
                }
            }
            Err(e) => warn!("Failed to hydrate object descriptors: {}", e),
        }
        info!("Hydrated {} storage object descriptor(s)", objects.len());
        Self {
            resolver,
            objects,
            storage: Some(storage),
        }
    }

    /// Best-effort write-through of an object descriptor to durable storage.
    fn persist_object(&self, descriptor: &ObjectDescriptor) {
        let Some(storage) = self.storage.as_ref() else {
            return;
        };
        let mut key = STORAGE_OBJECT_PREFIX.to_vec();
        key.extend_from_slice(descriptor.object_id.as_bytes());
        match serde_json::to_vec(descriptor) {
            Ok(bytes) => {
                if let Err(e) = storage.put(CF_SETTLEMENTS, &key, &bytes) {
                    warn!("Failed to persist object descriptor {}: {}", descriptor.object_id, e);
                }
            }
            Err(e) => warn!("Failed to serialize object descriptor {}: {}", descriptor.object_id, e),
        }
    }

    /// Accepts an object: erasure-encodes it, publishes every shard through the
    /// transport, and records its descriptor under `access_policy`. Returns the
    /// durable descriptor. Pass `confidential` to record encryption-at-rest
    /// envelopes for a network-tier object (the caller encrypts the bytes before
    /// submitting; this layer only records who holds a wrapped data key).
    pub async fn store_object(
        &self,
        object_id: impl Into<String>,
        owner_hex: impl Into<String>,
        data: &[u8],
        scheme: RedundancyScheme,
        access_policy: AccessPolicy,
        confidential: Option<ConfidentialSeal>,
    ) -> Result<ObjectDescriptor> {
        let object_id = object_id.into();
        let owner_hex = owner_hex.into();

        let shards = redundancy::encode(data, scheme)?;

        let mut shard_refs = Vec::with_capacity(shards.len());
        for shard in &shards {
            let uri = self
                .resolver
                .publish_bytes(Bytes::from(shard.bytes.clone()))
                .await?;
            shard_refs.push(ShardRef {
                index: shard.index,
                uri: uri.to_string(),
                commitment: shard.commitment.clone(),
            });
        }

        let descriptor = ObjectDescriptor {
            object_id: object_id.clone(),
            owner_hex,
            size_bytes: data.len() as u64,
            scheme,
            shards: shard_refs,
            access_policy,
            confidential,
        };

        self.objects.insert(object_id.clone(), descriptor.clone());
        self.persist_object(&descriptor);
        info!(
            "Stored object {} ({} bytes) as {} shards (k={} m={})",
            object_id,
            data.len(),
            descriptor.shard_count(),
            scheme.data_shards,
            scheme.parity_shards
        );
        Ok(descriptor)
    }

    /// Serves an object back by fetching its shards and reconstructing.
    ///
    /// Tolerates up to `parity_shards` shards that fail to fetch or fail their
    /// commitment check; only the data-shard count `k` valid shards are needed.
    pub async fn retrieve_object(&self, object_id: &str) -> Result<Vec<u8>> {
        let descriptor = self
            .objects
            .get(object_id)
            .map(|e| e.value().clone())
            .ok_or_else(|| StorageProviderError::ObjectNotFound(object_id.to_string()))?;

        let present = self.fetch_shards(&descriptor).await;
        if present.len() < descriptor.scheme.data_shards {
            return Err(StorageProviderError::InsufficientShards {
                object_id: object_id.to_string(),
                have: present.len(),
                need: descriptor.scheme.data_shards,
            });
        }

        let data = redundancy::reconstruct(
            &present,
            descriptor.scheme,
            descriptor.size_bytes as usize,
            object_id,
        )?;
        debug!("Reconstructed object {} from {} shards", object_id, present.len());
        Ok(data)
    }

    /// Fetches as many of an object's shards as are currently retrievable,
    /// verifying each against its commitment. Unretrievable or corrupt shards
    /// are skipped (the caller decides whether enough survived).
    async fn fetch_shards(&self, descriptor: &ObjectDescriptor) -> Vec<Shard> {
        let mut present = Vec::with_capacity(descriptor.shards.len());
        for sref in &descriptor.shards {
            let uri: TenzroUri = match sref.uri.parse() {
                Ok(u) => u,
                Err(e) => {
                    warn!("Object {} shard {} has unparseable URI: {}", descriptor.object_id, sref.index, e);
                    continue;
                }
            };
            match self.resolver.fetch_bytes(&uri).await {
                Ok(bytes) => {
                    let shard = Shard {
                        index: sref.index,
                        bytes: bytes.to_vec(),
                        commitment: sref.commitment.clone(),
                    };
                    if shard.verify() {
                        present.push(shard);
                    } else {
                        warn!(
                            "Object {} shard {} failed commitment check on fetch",
                            descriptor.object_id, sref.index
                        );
                    }
                }
                Err(e) => debug!(
                    "Object {} shard {} not retrievable: {}",
                    descriptor.object_id, sref.index, e
                ),
            }
        }
        present
    }

    /// Looks up an object's descriptor.
    pub fn descriptor(&self, object_id: &str) -> Result<ObjectDescriptor> {
        self.objects
            .get(object_id)
            .map(|e| e.value().clone())
            .ok_or_else(|| StorageProviderError::ObjectNotFound(object_id.to_string()))
    }

    /// Number of objects this provider is tracking.
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_iroh::IrohBackedResolver;

    async fn provider() -> StorageProvider {
        let resolver = IrohBackedResolver::bind_in_memory().await.unwrap();
        StorageProvider::new(resolver)
    }

    #[tokio::test]
    async fn store_and_retrieve_round_trips() {
        let p = provider().await;
        let scheme = RedundancyScheme::erasure(3, 2).unwrap();
        let data = b"storage provider object payload that spans several shards".to_vec();
        let desc = p
            .store_object(
                "obj-1",
                "deadbeef",
                &data,
                scheme,
                AccessPolicy::public("did:tenzro:human:test"),
                None,
            )
            .await
            .unwrap();
        assert_eq!(desc.shard_count(), 5);
        assert_eq!(desc.size_bytes, data.len() as u64);

        let back = p.retrieve_object("obj-1").await.unwrap();
        assert_eq!(back, data);
        assert_eq!(p.object_count(), 1);
    }

    #[tokio::test]
    async fn retrieve_unknown_object_errors() {
        let p = provider().await;
        let err = p.retrieve_object("missing").await.unwrap_err();
        assert!(matches!(err, StorageProviderError::ObjectNotFound(_)));
    }

    #[tokio::test]
    async fn descriptor_is_recorded() {
        let p = provider().await;
        let scheme = RedundancyScheme::replicated(3).unwrap();
        p.store_object(
            "obj-2",
            "cafe",
            b"small",
            scheme,
            AccessPolicy::public("did:tenzro:human:test"),
            None,
        )
        .await
        .unwrap();
        let d = p.descriptor("obj-2").unwrap();
        assert_eq!(d.owner_hex, "cafe");
        assert_eq!(d.scheme.total_shards(), 3);
        assert_eq!(d.shards.len(), 3);
    }
}
