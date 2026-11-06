//! Verified state sync: snapshots of the committed state, served as
//! BLAKE3-verified blobs over iroh and checked, bucket by bucket, against a
//! state root carried by a block the joining node already trusts.
//!
//! # What a snapshot is
//!
//! The committed state at height `S` (the state-trie version `S`), cut into
//! the trie's buckets (see [`tenzro_storage::state_trie::snapshot`]). Each
//! non-empty bucket is one blob holding its entries in tree-key order. A
//! manifest blob lists every bucket's summary and blob hash, plus one more
//! blob holding the blocks `S ..= S + STATE_ROOT_LAG`.
//!
//! Snapshots are taken only at the first block of an epoch, because that is
//! where the node commits the epoch's validator set and the validator
//! registry (see [`crate::state_commitment`]); a node restoring from the
//! snapshot restores both, verified, and can check every later certificate.
//!
//! # Trust
//!
//! A joining node starts from a weak-subjectivity checkpoint: a block hash
//! at height `A` it trusts. The snapshot it asks for is at `S = A -
//! STATE_ROOT_LAG`, because block `A` commits the state root of height `S`.
//! Then:
//!
//! 1. The anchor chain is checked: consecutive heights `S ..= A`, linked by
//!    `prev_hash`, ending in the trusted block. Its last header's state root
//!    is now trusted.
//! 2. The manifest's bucket summaries must fold to that root.
//! 3. Each bucket, as it arrives, must rebuild its manifest summary. Only
//!    then is it written.
//! 4. After the last bucket, the node's own trie must reproduce the root.
//!
//! Nothing a peer says is used before it has been checked against the
//! trusted block, so where the bytes came from does not matter: every blob
//! is fetched from whichever peer has it, verified by its BLAKE3 hash on the
//! way in. Buckets are fetched and written one at a time, so the joiner never
//! holds more than one bucket in memory, and a sync that stops resumes by
//! skipping the buckets it already committed.

use crate::error::{NodeError, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::Arc;
use tenzro_consensus::STATE_ROOT_LAG;
use tenzro_storage::state_trie::capture::Writes;
use tenzro_storage::state_trie::snapshot::{BucketSummary, root_from_buckets, verify_bucket};
use tenzro_storage::state_trie::{NS_EPOCH, NS_VALIDATOR_REGISTRY, StateTrie, is_committed_cf};
use tenzro_storage::traits::BlockStore;
use tenzro_storage::{
    BlockStoreImpl, CF_METADATA, CF_STATE_TRIE, KvStore, RocksDbStore, StateEntry, WriteOp,
};
use tenzro_types::block::Block;
use tenzro_types::hash_scheme::HashScheme;
use tenzro_types::primitives::{BlockHeight, Hash};

/// Default spacing between snapshots, in blocks. A snapshot is taken at the
/// first epoch start at least this far past the previous one.
pub const DEFAULT_SNAPSHOT_INTERVAL_BLOCKS: u64 = 100_000;

/// Default number of snapshots kept.
pub const DEFAULT_SNAPSHOT_RETAIN_COUNT: usize = 2;

/// Metadata key prefix of the local snapshot index: height → manifest hash.
const INDEX_PREFIX: &[u8] = b"state_snapshot:";

/// Metadata key prefix recording a bucket a joining node has committed.
const PROGRESS_PREFIX: &[u8] = b"state_sync_bucket:";

/// Producer policy. Joining nodes are unaffected by it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotConfig {
    /// Master switch for producing snapshots.
    #[serde(default)]
    pub enabled: bool,
    /// Minimum spacing between snapshots, in blocks.
    #[serde(default = "default_snapshot_interval_blocks")]
    pub interval_blocks: u64,
    /// Snapshots kept; older ones are dropped from the index and their blobs
    /// released.
    #[serde(default = "default_snapshot_retain_count")]
    pub retain_count: usize,
}

fn default_snapshot_interval_blocks() -> u64 {
    DEFAULT_SNAPSHOT_INTERVAL_BLOCKS
}

fn default_snapshot_retain_count() -> usize {
    DEFAULT_SNAPSHOT_RETAIN_COUNT
}

impl Default for SnapshotConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_blocks: DEFAULT_SNAPSHOT_INTERVAL_BLOCKS,
            retain_count: DEFAULT_SNAPSHOT_RETAIN_COUNT,
        }
    }
}

/// One bucket of a snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestBucket {
    /// The bucket's index and summary.
    pub summary: BucketSummary,
    /// BLAKE3 hash of the blob holding the bucket's entries.
    pub blob: [u8; 32],
    /// Number of entries in the bucket.
    pub entries: u64,
}

/// A snapshot manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotManifest {
    /// Height of the committed state.
    pub height: u64,
    /// The state root at `height`.
    pub state_root: Hash,
    /// BLAKE3 hash of the blob holding blocks `height ..= height + STATE_ROOT_LAG`.
    pub anchor_chain: [u8; 32],
    /// Every non-empty bucket, in index order.
    pub buckets: Vec<ManifestBucket>,
}

impl SnapshotManifest {
    /// Checks that the bucket summaries fold to `state_root` under the node
    /// hash `scheme` of the snapshot's height.
    pub fn check_root(&self, scheme: HashScheme) -> Result<()> {
        let summaries: Vec<BucketSummary> = self.buckets.iter().map(|b| b.summary).collect();
        let folded = root_from_buckets(scheme, &summaries).map_err(NodeError::Storage)?;
        if folded != self.state_root {
            return Err(NodeError::Other(format!(
                "snapshot manifest buckets fold to {folded}, not the declared root {}",
                self.state_root
            )));
        }
        Ok(())
    }
}

/// Checks the anchor chain of a snapshot at `height` against the trusted
/// block hash, and returns the state root it commits for `height`.
pub fn check_anchor_chain(height: u64, chain: &[Block], trusted: &Hash) -> Result<Hash> {
    if chain.len() as u64 != STATE_ROOT_LAG + 1 {
        return Err(NodeError::Other(format!(
            "anchor chain holds {} blocks, expected {}",
            chain.len(),
            STATE_ROOT_LAG + 1
        )));
    }
    for (i, block) in chain.iter().enumerate() {
        if block.height().0 != height + i as u64 {
            return Err(NodeError::Other(format!(
                "anchor chain block {i} is at height {}, expected {}",
                block.height(),
                height + i as u64
            )));
        }
        if i > 0 && block.header.prev_hash != chain[i - 1].hash() {
            return Err(NodeError::Other(format!(
                "anchor chain block at height {} does not link to its predecessor",
                block.height()
            )));
        }
        // The header hash does not cover the body, so a peer could pair a
        // genuine header with other transactions; the joiner stores and serves
        // these blocks, so each body must match its header's tx_root.
        block
            .verify_body()
            .map_err(|e| NodeError::Other(format!("anchor chain block: {e}")))?;
    }
    let last = chain.last().expect("length checked above");
    if last.hash() != *trusted {
        return Err(NodeError::Other(format!(
            "anchor chain ends in block {}, the trusted checkpoint is {trusted}",
            last.hash()
        )));
    }
    Ok(last.header.state_root)
}

/// Where snapshot blobs are published and fetched: the node's iroh blob
/// store, which verifies every blob against its BLAKE3 hash.
#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Publishes `bytes`, returning their BLAKE3 hash.
    async fn publish(&self, bytes: Vec<u8>) -> Result<[u8; 32]>;
    /// Fetches the blob with hash `hash`, from the local store or any peer
    /// that has it, verified against the hash.
    async fn fetch(&self, hash: &[u8; 32]) -> Result<Vec<u8>>;
}

/// A peer to sync from: answers which manifest it holds for a height.
#[async_trait]
pub trait ManifestSource: Send + Sync {
    /// The manifest blob hash for the snapshot at `height`, if any.
    async fn manifest_for(&self, height: u64) -> Result<Option<[u8; 32]>>;
}

/// The iroh-backed [`BlobStore`] and [`ManifestSource`].
pub struct IrohSnapshotTransport {
    resolver: Arc<tenzro_iroh::IrohBackedResolver>,
    /// The peer asked for manifests, and tried first for blobs.
    peer: Option<tenzro_iroh::EndpointId>,
}

impl IrohSnapshotTransport {
    /// A transport over `resolver`, syncing from `peer` when set.
    pub fn new(
        resolver: Arc<tenzro_iroh::IrohBackedResolver>,
        peer: Option<tenzro_iroh::EndpointId>,
    ) -> Self {
        Self { resolver, peer }
    }
}

#[async_trait]
impl BlobStore for IrohSnapshotTransport {
    async fn publish(&self, bytes: Vec<u8>) -> Result<[u8; 32]> {
        use tenzro_iroh::IrohResolver as _;
        let uri = self
            .resolver
            .publish_bytes(bytes.into())
            .await
            .map_err(|e| NodeError::Other(format!("publish snapshot blob: {e}")))?;
        let tenzro_iroh::TenzroUri::Blob { hash, .. } = uri else {
            return Err(NodeError::Other("publish returned a non-blob URI".into()));
        };
        let mut out = [0u8; 32];
        hex::decode_to_slice(&hash, &mut out)
            .map_err(|e| NodeError::Other(format!("blob hash {hash}: {e}")))?;
        Ok(out)
    }

    async fn fetch(&self, hash: &[u8; 32]) -> Result<Vec<u8>> {
        use tenzro_iroh::IrohResolver as _;
        let uri = tenzro_iroh::TenzroUri::Blob {
            hash: hex::encode(hash),
            provider_hint: self.peer.map(|p| p.to_string()),
        };
        self.resolver
            .fetch_bytes(&uri)
            .await
            .map(|b| b.to_vec())
            .map_err(|e| {
                NodeError::Other(format!("fetch snapshot blob {}: {e}", hex::encode(hash)))
            })
    }
}

#[async_trait]
impl ManifestSource for IrohSnapshotTransport {
    async fn manifest_for(&self, height: u64) -> Result<Option<[u8; 32]>> {
        let peer = self
            .peer
            .ok_or_else(|| NodeError::Other("no state-sync peer configured".into()))?;
        self.resolver
            .request_snapshot_manifest(peer, height)
            .await
            .map_err(|e| NodeError::Other(format!("manifest lookup at {peer}: {e}")))
    }
}

/// A snapshot this node holds, as listed over RPC.
#[derive(Debug, Clone, Serialize)]
pub struct SnapshotSummary {
    /// Height of the committed state.
    pub height: u64,
    /// State root at that height.
    pub state_root: String,
    /// BLAKE3 hash of the manifest blob.
    pub manifest_blob: String,
    /// Number of buckets.
    pub buckets: usize,
}

/// Producer and index of this node's snapshots.
pub struct SnapshotStore {
    store: Arc<RocksDbStore>,
    trie: Arc<StateTrie>,
    blobs: Arc<dyn BlobStore>,
    config: SnapshotConfig,
}

impl SnapshotStore {
    /// A store over the node's database and blob store.
    pub fn new(
        store: Arc<RocksDbStore>,
        blobs: Arc<dyn BlobStore>,
        config: SnapshotConfig,
    ) -> Self {
        let trie = Arc::new(StateTrie::new(store.clone() as Arc<dyn KvStore>));
        Self {
            store,
            trie,
            blobs,
            config,
        }
    }

    fn index(&self) -> Result<BTreeMap<u64, [u8; 32]>> {
        let mut out = BTreeMap::new();
        for (k, v) in self
            .store
            .scan_prefix(CF_METADATA, INDEX_PREFIX)
            .map_err(NodeError::Storage)?
        {
            let height = u64::from_be_bytes(
                k[INDEX_PREFIX.len()..]
                    .try_into()
                    .map_err(|_| NodeError::Other("bad snapshot index key".into()))?,
            );
            let hash: [u8; 32] = v
                .as_slice()
                .try_into()
                .map_err(|_| NodeError::Other("bad snapshot index value".into()))?;
            out.insert(height, hash);
        }
        Ok(out)
    }

    fn index_key(height: u64) -> Vec<u8> {
        let mut k = INDEX_PREFIX.to_vec();
        k.extend_from_slice(&height.to_be_bytes());
        k
    }

    /// The manifest blob hash of the snapshot at `height`, if held.
    pub fn manifest_hash(&self, height: u64) -> Result<Option<[u8; 32]>> {
        Ok(self.index()?.get(&height).copied())
    }

    /// The manifest of the snapshot at `height`, if held.
    pub async fn manifest(&self, height: u64) -> Result<Option<SnapshotManifest>> {
        let Some(hash) = self.manifest_hash(height)? else {
            return Ok(None);
        };
        let bytes = self.blobs.fetch(&hash).await?;
        Ok(Some(bincode::deserialize(&bytes).map_err(|e| {
            NodeError::Other(format!("decode manifest: {e}"))
        })?))
    }

    /// Every snapshot this node holds, newest first.
    pub async fn list(&self) -> Result<Vec<SnapshotSummary>> {
        let mut out = Vec::new();
        for (height, hash) in self.index()?.into_iter().rev() {
            if let Some(m) = self.manifest(height).await? {
                out.push(SnapshotSummary {
                    height,
                    state_root: m.state_root.to_string(),
                    manifest_blob: hex::encode(hash),
                    buckets: m.buckets.len(),
                });
            }
        }
        Ok(out)
    }

    /// Whether a snapshot of height `state_height` is due: producing is
    /// enabled, `state_height` starts an epoch, and the newest snapshot is at
    /// least the configured interval older.
    pub fn due(&self, state_height: u64, starts_epoch: bool) -> Result<bool> {
        if !self.config.enabled || !starts_epoch || state_height == 0 {
            return Ok(false);
        }
        let newest = self.index()?.keys().next_back().copied();
        Ok(newest.is_none_or(|n| state_height >= n + self.config.interval_blocks.max(1)))
    }

    /// Produces the snapshot of the committed state at `state_height`. The
    /// blocks `state_height ..= state_height + STATE_ROOT_LAG` must be
    /// stored. Reads an immutable trie version, so blocks committing while
    /// this runs cannot tear it.
    pub async fn produce(&self, state_height: u64) -> Result<SnapshotManifest> {
        let root = self
            .trie
            .root_at(state_height)
            .map_err(NodeError::Storage)?
            .ok_or_else(|| {
                NodeError::Other(format!("no committed state at height {state_height}"))
            })?;
        let block_store = BlockStoreImpl::new(self.store.clone()).map_err(NodeError::Storage)?;
        let mut chain = Vec::new();
        for h in state_height..=state_height + STATE_ROOT_LAG {
            chain.push(
                block_store
                    .get_block_by_height(BlockHeight(h))
                    .await
                    .map_err(NodeError::Storage)?
                    .ok_or_else(|| NodeError::Other(format!("block {h} is not stored")))?,
            );
        }
        let chain_bytes =
            bincode::serialize(&chain).map_err(|e| NodeError::Other(e.to_string()))?;
        let anchor_chain = self.blobs.publish(chain_bytes).await?;

        let mut buckets = Vec::new();
        for summary in self
            .trie
            .bucket_summaries(state_height)
            .map_err(NodeError::Storage)?
        {
            let entries = self
                .trie
                .bucket_entries(state_height, summary.index)
                .map_err(NodeError::Storage)?;
            let count = entries.len() as u64;
            let bytes =
                bincode::serialize(&entries).map_err(|e| NodeError::Other(e.to_string()))?;
            let blob = self.blobs.publish(bytes).await?;
            buckets.push(ManifestBucket {
                summary,
                blob,
                entries: count,
            });
        }
        let manifest = SnapshotManifest {
            height: state_height,
            state_root: root,
            anchor_chain,
            buckets,
        };
        manifest.check_root(
            self.trie
                .scheme_at(state_height)
                .map_err(NodeError::Storage)?,
        )?;
        let manifest_bytes =
            bincode::serialize(&manifest).map_err(|e| NodeError::Other(e.to_string()))?;
        let manifest_hash = self.blobs.publish(manifest_bytes).await?;
        self.store
            .put(CF_METADATA, &Self::index_key(state_height), &manifest_hash)
            .map_err(NodeError::Storage)?;
        self.prune()?;
        Ok(manifest)
    }

    /// Drops the oldest snapshots from the index beyond the retain count.
    fn prune(&self) -> Result<()> {
        let index = self.index()?;
        let keep = self.config.retain_count.max(1);
        if index.len() <= keep {
            return Ok(());
        }
        let ops = index
            .keys()
            .take(index.len() - keep)
            .map(|h| WriteOp::Delete {
                cf: CF_METADATA.to_string(),
                key: Self::index_key(*h),
            })
            .collect();
        self.store.write_batch(ops).map_err(NodeError::Storage)
    }
}

impl std::fmt::Debug for SnapshotStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotStore")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl tenzro_iroh::SnapshotDirectory for SnapshotStore {
    async fn manifest_for(&self, height: u64) -> Option<[u8; 32]> {
        self.manifest_hash(height).ok().flatten()
    }
}

/// Outcome of a completed state sync.
#[derive(Debug, Clone)]
pub struct SyncedState {
    /// Height of the restored state.
    pub height: u64,
    /// Its state root, reproduced by this node's trie.
    pub state_root: Hash,
    /// Buckets fetched in this run (fewer than the manifest's when resumed).
    pub buckets_fetched: usize,
}

fn progress_key(root: &Hash, index: u32) -> Vec<u8> {
    let mut k = PROGRESS_PREFIX.to_vec();
    k.extend_from_slice(root.as_bytes());
    k.extend_from_slice(&index.to_be_bytes());
    k
}

/// Restores the committed state from a peer's snapshot, anchored to the
/// trusted block `(anchor_height, anchor_hash)`.
///
/// Refuses unless this node holds at most genesis: a node with chain state
/// of its own has nothing to restore. Genesis state is replaced by the
/// snapshot, not merged with it.
pub async fn state_sync(
    store: &Arc<RocksDbStore>,
    source: &dyn ManifestSource,
    blobs: &dyn BlobStore,
    anchor_height: u64,
    anchor_hash: Hash,
    epoch_duration: u64,
) -> Result<SyncedState> {
    let height = anchor_height.checked_sub(STATE_ROOT_LAG).ok_or_else(|| {
        NodeError::Other(format!(
            "checkpoint height {anchor_height} is below the state-root lag"
        ))
    })?;
    let kv = store.clone() as Arc<dyn KvStore>;
    let trie = StateTrie::new(kv.clone());
    match trie.latest_version().map_err(NodeError::Storage)? {
        Some(v) if v != 0 && v != height => {
            return Err(NodeError::Other(format!(
                "this node already holds committed state up to height {v}; state sync restores only a fresh node"
            )));
        }
        _ => {}
    }

    let manifest_hash = source.manifest_for(height).await?.ok_or_else(|| {
        NodeError::Other(format!("the peer holds no snapshot at height {height}"))
    })?;
    let manifest: SnapshotManifest = bincode::deserialize(&blobs.fetch(&manifest_hash).await?)
        .map_err(|e| NodeError::Other(format!("decode manifest: {e}")))?;
    if manifest.height != height {
        return Err(NodeError::Other(format!(
            "the peer answered a manifest for height {}, asked for {height}",
            manifest.height
        )));
    }
    let chain: Vec<Block> = bincode::deserialize(&blobs.fetch(&manifest.anchor_chain).await?)
        .map_err(|e| NodeError::Other(format!("decode anchor chain: {e}")))?;
    let trusted_root = check_anchor_chain(height, &chain, &anchor_hash)?;
    // The state at `height` is hashed under the scheme its block's protocol
    // version names, as the node that committed it hashed it.
    let scheme = tenzro_types::hash_scheme::block_hash_scheme(
        chain
            .first()
            .ok_or_else(|| NodeError::Other("the anchor chain is empty".into()))?
            .header
            .metadata
            .protocol_version,
        tenzro_types::hash_scheme::STATE_TRIE_HASH_SCHEMES,
    );
    if manifest.state_root != trusted_root {
        return Err(NodeError::Other(format!(
            "manifest declares root {}, the trusted block commits {trusted_root}",
            manifest.state_root
        )));
    }
    manifest.check_root(scheme)?;

    // A fresh node holds genesis at version 0. Its entries are removed from
    // the column families and the trie is cleared, so the restored state is
    // exactly the snapshot's.
    if trie.latest_version().map_err(NodeError::Storage)? == Some(0) {
        clear_genesis_state(&kv, &trie)?;
    }
    trie.adopt_scheme(height, scheme)
        .map_err(NodeError::Storage)?;

    let mut fetched = 0usize;
    for bucket in &manifest.buckets {
        let done_key = progress_key(&trusted_root, bucket.summary.index);
        if kv
            .get(CF_METADATA, &done_key)
            .map_err(NodeError::Storage)?
            .is_some()
        {
            continue;
        }
        let entries: Vec<StateEntry> = bincode::deserialize(&blobs.fetch(&bucket.blob).await?)
            .map_err(|e| {
                NodeError::Other(format!("decode bucket {}: {e}", bucket.summary.index))
            })?;
        verify_bucket(
            scheme,
            bucket.summary.index,
            &entries,
            &bucket.summary.subtree,
        )
        .map_err(NodeError::Storage)?;

        let mut writes = Writes::new();
        let mut ops = Vec::with_capacity(entries.len() + 1);
        for e in entries {
            if is_committed_cf(&e.namespace) {
                ops.push(WriteOp::Put {
                    cf: e.namespace.clone(),
                    key: e.key.clone(),
                    value: e.value.clone(),
                });
            }
            writes.insert((e.namespace, e.key), Some(e.value));
        }
        trie.commit(height, &writes).map_err(NodeError::Storage)?;
        ops.push(WriteOp::Put {
            cf: CF_METADATA.to_string(),
            key: done_key,
            value: vec![1],
        });
        kv.write_batch_sync(ops).map_err(NodeError::Storage)?;
        fetched += 1;
    }
    // A snapshot of an empty state has no buckets; the trie still needs its
    // version.
    if manifest.buckets.is_empty() {
        trie.commit(height, &Writes::new())
            .map_err(NodeError::Storage)?;
    }

    let reproduced = trie
        .root_at(height)
        .map_err(NodeError::Storage)?
        .ok_or_else(|| NodeError::Other("restored state has no root".into()))?;
    if reproduced != trusted_root {
        return Err(NodeError::Other(format!(
            "restored state reproduces root {reproduced}, the trusted block commits {trusted_root}"
        )));
    }

    restore_consensus_records(&kv, &trie, height, epoch_duration)?;

    // The restored height's block becomes the local tip; block-sync imports
    // from the next height on, checking every certificate.
    let mut block_store = BlockStoreImpl::new(store.clone()).map_err(NodeError::Storage)?;
    block_store
        .put_block(&chain[0])
        .await
        .map_err(NodeError::Storage)?;

    Ok(SyncedState {
        height,
        state_root: trusted_root,
        buckets_fetched: fetched,
    })
}

/// Removes genesis-written entries from the column families and clears the
/// trie, on a node that holds nothing but genesis.
fn clear_genesis_state(kv: &Arc<dyn KvStore>, trie: &StateTrie) -> Result<()> {
    let mut ops = Vec::new();
    for bucket in trie.bucket_summaries(0).map_err(NodeError::Storage)? {
        for e in trie
            .bucket_entries(0, bucket.index)
            .map_err(NodeError::Storage)?
        {
            if is_committed_cf(&e.namespace) {
                ops.push(WriteOp::Delete {
                    cf: e.namespace,
                    key: e.key,
                });
            }
        }
    }
    for key in kv
        .get_keys_with_prefix(CF_STATE_TRIE, b"")
        .map_err(NodeError::Storage)?
    {
        ops.push(WriteOp::Delete {
            cf: CF_STATE_TRIE.to_string(),
            key,
        });
    }
    kv.write_batch_sync(ops).map_err(NodeError::Storage)
}

/// Writes the committed epoch record and validator registry of `height`
/// into the stores the consensus engine and the registry hydrate from.
fn restore_consensus_records(
    kv: &Arc<dyn KvStore>,
    trie: &StateTrie,
    height: u64,
    epoch_duration: u64,
) -> Result<()> {
    use crate::state_commitment::{EpochRecord, REGISTRY_INDEX_KEY};
    let mut records: Vec<EpochRecord> = Vec::new();
    let mut registry = Vec::new();
    let mut index: Option<Vec<tenzro_types::primitives::Address>> = None;
    for bucket in trie.bucket_summaries(height).map_err(NodeError::Storage)? {
        for e in trie
            .bucket_entries(height, bucket.index)
            .map_err(NodeError::Storage)?
        {
            if e.namespace == NS_EPOCH {
                records.push(
                    bincode::deserialize(&e.value)
                        .map_err(|err| NodeError::Other(format!("decode epoch record: {err}")))?,
                );
            } else if e.namespace == NS_VALIDATOR_REGISTRY {
                if e.key == REGISTRY_INDEX_KEY {
                    index = Some(bincode::deserialize(&e.value).map_err(|err| {
                        NodeError::Other(format!("decode registry index: {err}"))
                    })?);
                } else {
                    registry.push(e.value);
                }
            }
        }
    }
    let epoch = records
        .into_iter()
        .max_by_key(|r| r.number)
        .ok_or_else(|| NodeError::Other("the snapshot commits no epoch record".into()))?;
    if epoch.start_height > height {
        return Err(NodeError::Other(
            "the snapshot's newest epoch starts after its own height".into(),
        ));
    }

    let mut ops = Vec::new();
    let validators = epoch
        .validators
        .iter()
        .map(|v| {
            let key = tenzro_consensus::ValidatorPublicKey::new(
                v.ml_dsa_public_key.clone(),
                v.p256_public_key.clone(),
            )
            .map_err(|e| NodeError::Other(format!("restored validator key: {e}")))?;
            Ok(tenzro_consensus::ValidatorInfo::new(
                v.address, key, v.node_key, v.stake,
            ))
        })
        .collect::<std::result::Result<Vec<_>, NodeError>>()?;
    let set = tenzro_consensus::ValidatorSet::new(epoch.number, validators)
        .map_err(|e| NodeError::Other(format!("restored validator set: {e}")))?;
    let restored = tenzro_consensus::Epoch::new(
        epoch.number,
        BlockHeight(epoch.start_height),
        BlockHeight(epoch.start_height + epoch_duration.max(1)),
        set,
    );
    ops.push(WriteOp::Put {
        cf: CF_METADATA.to_string(),
        key: crate::epoch_state_store::epoch_key(epoch.number),
        value: bincode::serialize(&restored).map_err(|e| NodeError::Other(e.to_string()))?,
    });

    let registry_cf = tenzro_storage::CF_TOKENS;
    for value in registry {
        let entry: tenzro_token::validator_registry::ValidatorRegistryEntry =
            bincode::deserialize(&value)
                .map_err(|e| NodeError::Other(format!("decode registry entry: {e}")))?;
        ops.push(WriteOp::Put {
            cf: registry_cf.to_string(),
            key: format!(
                "{}{}",
                tenzro_token::validator_registry::VALIDATOR_PREFIX,
                hex::encode(entry.address.as_bytes())
            )
            .into_bytes(),
            value,
        });
    }
    if let Some(index) = index {
        let hexes: Vec<String> = index.iter().map(|a| hex::encode(a.as_bytes())).collect();
        ops.push(WriteOp::Put {
            cf: registry_cf.to_string(),
            key: tenzro_token::validator_registry::VALIDATOR_INDEX_KEY
                .as_bytes()
                .to_vec(),
            value: bincode::serialize(&hexes).map_err(|e| NodeError::Other(e.to_string()))?,
        });
    }
    kv.write_batch_sync(ops).map_err(NodeError::Storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_commitment::{EpochRecord, EpochValidator, epoch_key};
    use parking_lot::Mutex;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tenzro_storage::CF_ACCOUNTS;
    use tenzro_types::block::BlockHeader;
    use tenzro_types::primitives::Address;

    /// A content-addressed blob store in memory. `tamper` rewrites the blob
    /// served for one hash, as a peer that lies about its contents would.
    #[derive(Default)]
    struct MemBlobs {
        blobs: Mutex<HashMap<[u8; 32], Vec<u8>>>,
        tamper: Mutex<Option<([u8; 32], Vec<u8>)>>,
        fetches: AtomicUsize,
        fail_after: Mutex<Option<usize>>,
    }

    #[async_trait]
    impl BlobStore for MemBlobs {
        async fn publish(&self, bytes: Vec<u8>) -> Result<[u8; 32]> {
            let hash: [u8; 32] = Sha256::digest(&bytes).into();
            self.blobs.lock().insert(hash, bytes);
            Ok(hash)
        }

        async fn fetch(&self, hash: &[u8; 32]) -> Result<Vec<u8>> {
            let n = self.fetches.fetch_add(1, Ordering::SeqCst);
            if let Some(limit) = *self.fail_after.lock()
                && n >= limit
            {
                return Err(NodeError::Other("peer went away".into()));
            }
            if let Some((h, bytes)) = self.tamper.lock().as_ref()
                && h == hash
            {
                return Ok(bytes.clone());
            }
            self.blobs
                .lock()
                .get(hash)
                .cloned()
                .ok_or_else(|| NodeError::Other("no such blob".into()))
        }
    }

    struct Directory(Arc<SnapshotStore>);

    #[async_trait]
    impl ManifestSource for Directory {
        async fn manifest_for(&self, height: u64) -> Result<Option<[u8; 32]>> {
            self.0.manifest_hash(height)
        }
    }

    const HEIGHT: u64 = 10;

    fn open(dir: &tempfile::TempDir) -> Arc<RocksDbStore> {
        Arc::new(RocksDbStore::open_default(dir.path()).unwrap())
    }

    fn account(i: u32) -> (String, Vec<u8>) {
        (CF_ACCOUNTS.to_string(), format!("account-{i}").into_bytes())
    }

    /// A producer holding committed state at [`HEIGHT`] (a few hundred
    /// accounts and an epoch record) and blocks `HEIGHT ..= HEIGHT + LAG`,
    /// the last of which commits the state root. Returns the store and the
    /// trusted anchor hash.
    async fn producer(dir: &tempfile::TempDir) -> (Arc<RocksDbStore>, Hash) {
        let store = open(dir);
        let trie = StateTrie::new(store.clone() as Arc<dyn KvStore>);
        let mut writes = Writes::new();
        let mut ops = Vec::new();
        for i in 0..300u32 {
            let (ns, key) = account(i);
            let value = (i as u64 * 7).to_le_bytes().to_vec();
            ops.push(WriteOp::Put {
                cf: ns.clone(),
                key: key.clone(),
                value: value.clone(),
            });
            writes.insert((ns, key), Some(value));
        }
        let record = EpochRecord {
            number: 1,
            start_height: HEIGHT,
            validators: vec![EpochValidator {
                address: Address::new([3u8; 32]),
                ml_dsa_public_key: tenzro_crypto::pq::MlDsaSigningKey::generate()
                    .verifying_key_bytes()
                    .to_vec(),
                p256_public_key: tenzro_crypto::P256KeyPair::generate()
                    .public_key_sec1()
                    .to_vec(),
                node_key: [4u8; 32],
                stake: 1000,
            }],
        };
        writes.insert(
            (NS_EPOCH.to_string(), epoch_key(1)),
            Some(bincode::serialize(&record).unwrap()),
        );
        store.write_batch(ops).unwrap();
        let root = trie.commit(HEIGHT, &writes).unwrap();

        let mut blocks = BlockStoreImpl::new(store.clone()).unwrap();
        let mut prev = Hash::new([1u8; 32]);
        let mut last = Hash::zero();
        for h in HEIGHT..=HEIGHT + STATE_ROOT_LAG {
            let state_root = if h == HEIGHT + STATE_ROOT_LAG {
                root
            } else {
                Hash::new([h as u8; 32])
            };
            let block = Block::new(
                BlockHeader::new(
                    BlockHeight(h),
                    prev,
                    Hash::zero(),
                    state_root,
                    Address::new([2u8; 32]),
                ),
                vec![],
            );
            prev = block.hash();
            last = prev;
            blocks.put_block(&block).await.unwrap();
        }
        (store, last)
    }

    fn snapshot_store(store: &Arc<RocksDbStore>, blobs: Arc<MemBlobs>) -> Arc<SnapshotStore> {
        Arc::new(SnapshotStore::new(
            store.clone(),
            blobs,
            SnapshotConfig {
                enabled: true,
                interval_blocks: 1,
                retain_count: 2,
            },
        ))
    }

    #[tokio::test]
    async fn a_fresh_node_restores_the_trusted_state() {
        let pdir = tempfile::tempdir().unwrap();
        let (pstore, anchor) = producer(&pdir).await;
        let blobs = Arc::new(MemBlobs::default());
        let snapshots = snapshot_store(&pstore, blobs.clone());
        let manifest = snapshots.produce(HEIGHT).await.unwrap();
        assert!(
            manifest.buckets.len() > 1,
            "the state spans several buckets"
        );

        let jdir = tempfile::tempdir().unwrap();
        let joiner = open(&jdir);
        let synced = state_sync(
            &joiner,
            &Directory(snapshots),
            blobs.as_ref(),
            HEIGHT + STATE_ROOT_LAG,
            anchor,
            100,
        )
        .await
        .unwrap();
        assert_eq!(synced.state_root, manifest.state_root);
        assert_eq!(synced.buckets_fetched, manifest.buckets.len());
        let (ns, key) = account(42);
        assert_eq!(
            joiner.get(&ns, &key).unwrap(),
            Some((42u64 * 7).to_le_bytes().to_vec())
        );
        assert!(
            joiner
                .get(CF_METADATA, &crate::epoch_state_store::epoch_key(1))
                .unwrap()
                .is_some(),
            "the committed epoch record is restored for the consensus engine"
        );
    }

    #[tokio::test]
    async fn a_tampered_bucket_is_refused_and_not_written() {
        let pdir = tempfile::tempdir().unwrap();
        let (pstore, anchor) = producer(&pdir).await;
        let blobs = Arc::new(MemBlobs::default());
        let snapshots = snapshot_store(&pstore, blobs.clone());
        let manifest = snapshots.produce(HEIGHT).await.unwrap();

        // The peer serves one bucket with a value changed.
        let target = &manifest.buckets[0];
        let mut entries: Vec<StateEntry> =
            bincode::deserialize(&blobs.blobs.lock()[&target.blob]).unwrap();
        entries[0].value = b"forged".to_vec();
        *blobs.tamper.lock() = Some((target.blob, bincode::serialize(&entries).unwrap()));

        let jdir = tempfile::tempdir().unwrap();
        let joiner = open(&jdir);
        let result = state_sync(
            &joiner,
            &Directory(snapshots),
            blobs.as_ref(),
            HEIGHT + STATE_ROOT_LAG,
            anchor,
            100,
        )
        .await;
        assert!(
            result.is_err(),
            "a bucket that does not rebuild its summary is refused"
        );
        let forged = &entries[0];
        assert_ne!(
            joiner.get(&forged.namespace, &forged.key).unwrap(),
            Some(b"forged".to_vec())
        );
    }

    #[tokio::test]
    async fn a_snapshot_for_another_checkpoint_is_refused() {
        let pdir = tempfile::tempdir().unwrap();
        let (pstore, _anchor) = producer(&pdir).await;
        let blobs = Arc::new(MemBlobs::default());
        let snapshots = snapshot_store(&pstore, blobs.clone());
        snapshots.produce(HEIGHT).await.unwrap();

        let jdir = tempfile::tempdir().unwrap();
        let joiner = open(&jdir);
        let result = state_sync(
            &joiner,
            &Directory(snapshots),
            blobs.as_ref(),
            HEIGHT + STATE_ROOT_LAG,
            Hash::new([0xEE; 32]),
            100,
        )
        .await;
        assert!(
            result.is_err(),
            "the anchor chain must end in the trusted block"
        );
    }

    #[tokio::test]
    async fn an_anchor_chain_with_a_swapped_body_is_refused() {
        let pdir = tempfile::tempdir().unwrap();
        let (pstore, anchor) = producer(&pdir).await;
        let blobs = Arc::new(MemBlobs::default());
        let snapshots = snapshot_store(&pstore, blobs.clone());
        let manifest = snapshots.produce(HEIGHT).await.unwrap();

        // The peer serves the genuine headers, but the first block carries a
        // transaction its header never committed to.
        let mut chain: Vec<Block> =
            bincode::deserialize(&blobs.blobs.lock()[&manifest.anchor_chain]).unwrap();
        use tenzro_types::primitives::{ChainId, Nonce};
        use tenzro_types::transaction::{SignedTransaction, Transaction, TransactionType};
        let tx = SignedTransaction::new(
            Transaction::new(
                ChainId::from(1u64),
                Address::new([1u8; 32]),
                Address::new([2u8; 32]),
                Nonce::from(0u64),
                TransactionType::Transfer { amount: 5 },
                21_000,
                1,
            ),
            vec![3u8; 32],
            tenzro_types::account_signature::CompositeSignature::hybrid(
                tenzro_types::account_signature::ClassicalProof::Raw {
                    signature: vec![1u8; 64],
                },
                vec![1u8; 3309],
            ),
        );
        chain[0].transactions.push(tx);
        *blobs.tamper.lock() = Some((manifest.anchor_chain, bincode::serialize(&chain).unwrap()));

        let jdir = tempfile::tempdir().unwrap();
        let joiner = open(&jdir);
        let result = state_sync(
            &joiner,
            &Directory(snapshots),
            blobs.as_ref(),
            HEIGHT + STATE_ROOT_LAG,
            anchor,
            100,
        )
        .await;
        assert!(
            result.is_err(),
            "a body that does not match its header is refused"
        );
        let blocks = BlockStoreImpl::new(joiner.clone()).unwrap();
        assert!(
            blocks
                .get_block_by_height(BlockHeight(HEIGHT))
                .await
                .unwrap()
                .is_none(),
            "nothing from the refused chain is stored"
        );
    }

    #[tokio::test]
    async fn an_interrupted_sync_resumes_without_refetching_committed_buckets() {
        let pdir = tempfile::tempdir().unwrap();
        let (pstore, anchor) = producer(&pdir).await;
        let blobs = Arc::new(MemBlobs::default());
        let snapshots = snapshot_store(&pstore, blobs.clone());
        let manifest = snapshots.produce(HEIGHT).await.unwrap();
        let total = manifest.buckets.len();
        assert!(total > 2);

        let jdir = tempfile::tempdir().unwrap();
        let joiner = open(&jdir);
        // Manifest + anchor chain + two buckets, then the peer goes away.
        blobs.fetches.store(0, Ordering::SeqCst);
        *blobs.fail_after.lock() = Some(4);
        let first = state_sync(
            &joiner,
            &Directory(snapshots.clone()),
            blobs.as_ref(),
            HEIGHT + STATE_ROOT_LAG,
            anchor,
            100,
        )
        .await;
        assert!(first.is_err());

        *blobs.fail_after.lock() = None;
        let resumed = state_sync(
            &joiner,
            &Directory(snapshots),
            blobs.as_ref(),
            HEIGHT + STATE_ROOT_LAG,
            anchor,
            100,
        )
        .await
        .unwrap();
        assert_eq!(resumed.buckets_fetched, total - 2);
        assert_eq!(resumed.state_root, manifest.state_root);
    }

    #[tokio::test]
    async fn a_node_with_chain_state_of_its_own_refuses_to_restore() {
        let pdir = tempfile::tempdir().unwrap();
        let (pstore, anchor) = producer(&pdir).await;
        let blobs = Arc::new(MemBlobs::default());
        let snapshots = snapshot_store(&pstore, blobs.clone());
        snapshots.produce(HEIGHT).await.unwrap();

        let jdir = tempfile::tempdir().unwrap();
        let joiner = open(&jdir);
        let trie = StateTrie::new(joiner.clone() as Arc<dyn KvStore>);
        trie.commit(3, &Writes::new()).unwrap();
        let result = state_sync(
            &joiner,
            &Directory(snapshots),
            blobs.as_ref(),
            HEIGHT + STATE_ROOT_LAG,
            anchor,
            100,
        )
        .await;
        assert!(result.is_err());
    }
}
