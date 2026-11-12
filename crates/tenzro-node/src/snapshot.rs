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
use tracing::{info, warn};

/// Default spacing between snapshots, in blocks. A snapshot is taken at the
/// first epoch start at least this far past the previous one.
pub const DEFAULT_SNAPSHOT_INTERVAL_BLOCKS: u64 = 100_000;

/// Default number of snapshots kept.
pub const DEFAULT_SNAPSHOT_RETAIN_COUNT: usize = 2;

/// Metadata key prefix of the local snapshot index: height → manifest hash.
const INDEX_PREFIX: &[u8] = b"state_snapshot:";

/// Metadata key recording the height a node restored its state at.
pub const RESTORED_HEIGHT_KEY: &[u8] = b"state_sync_restored_height";

/// Whether the block at `height` opens its epoch, read from the stored
/// headers: it is the first block after genesis, or its header names a later
/// epoch than its parent's. Snapshots are taken at such heights, where the
/// epoch's record and the registry are committed, so a node restored from one
/// continues the registry and learns every later epoch from the blocks it
/// imports. `false` when either block is no longer stored.
pub async fn opens_epoch_at(store: &Arc<RocksDbStore>, height: u64) -> Result<bool> {
    Ok(epoch_open_shape(store, height).await?.is_some())
}

/// Whether a snapshot can be cut at `height`: it opens an epoch
/// ([`opens_epoch_at`]) and the epoch holds a second block, so the closing
/// checkpoint a restored node adopts the next committee from exists.
pub async fn can_snapshot_at(store: &Arc<RocksDbStore>, height: u64) -> Result<bool> {
    Ok(epoch_open_shape(store, height).await?.unwrap_or(false))
}

/// `None` when `height` opens no epoch; otherwise whether the next block
/// carries the same epoch.
async fn epoch_open_shape(store: &Arc<RocksDbStore>, height: u64) -> Result<Option<bool>> {
    let blocks = BlockStoreImpl::new(store.clone()).map_err(NodeError::Storage)?;
    let Some(block) = blocks
        .get_block_by_height(BlockHeight(height))
        .await
        .map_err(NodeError::Storage)?
    else {
        return Ok(None);
    };
    let parent_epoch = if height <= 1 {
        0
    } else {
        match blocks
            .get_block_by_height(BlockHeight(height - 1))
            .await
            .map_err(NodeError::Storage)?
        {
            Some(parent) => parent.header.epoch,
            None => return Ok(None),
        }
    };
    if !crate::state_commitment::opens_epoch(BlockHeight(height), block.header.epoch, parent_epoch)
    {
        return Ok(None);
    }
    let next_epoch = blocks
        .get_block_by_height(BlockHeight(height + 1))
        .await
        .map_err(NodeError::Storage)?
        .map(|b| b.header.epoch);
    Ok(Some(next_epoch == Some(block.header.epoch)))
}

/// The newest height at or below `up_to` that opens an epoch ([`opens_epoch_at`]).
pub async fn latest_epoch_open(store: &Arc<RocksDbStore>, up_to: u64) -> Result<Option<u64>> {
    /// Blocks looked back over; an epoch is far shorter.
    const LOOKBACK: u64 = 200_000;
    let trie = StateTrie::new(store.clone() as Arc<dyn KvStore>);
    let mut h = up_to;
    let floor = up_to.saturating_sub(LOOKBACK);
    while h > floor && h > 0 {
        if can_snapshot_at(store, h).await?
            && trie.root_at(h).map_err(NodeError::Storage)?.is_some()
        {
            return Ok(Some(h));
        }
        h -= 1;
    }
    Ok(None)
}

/// Metadata key prefix recording a bucket a joining node has committed.
const PROGRESS_PREFIX: &[u8] = b"state_sync_bucket:";

/// Default cap on the bytes of the snapshot blobs a node keeps, 16 GiB. It
/// bounds what the retained snapshots hold, not what was ever published:
/// snapshots beyond the retain count, and the oldest ones when the cap or the
/// volume share is reached, are removed together with their blobs.
pub const DEFAULT_SNAPSHOT_MAX_PUBLISHED_BYTES: u64 = 16 << 30;

/// Default share of the data volume the retained snapshot blobs may take,
/// percent. The effective cap is the lower of this share and
/// `max_published_bytes`, so a small disk cannot be filled by snapshots.
pub const DEFAULT_SNAPSHOT_MAX_VOLUME_PCT: u8 = 15;

/// How long a snapshot stays in place after a peer last asked for its
/// manifest. A joining node fetches the buckets one by one after that call.
pub const SERVE_LEASE: std::time::Duration = std::time::Duration::from_secs(3600);

/// Metadata key prefix of the blob bytes each retained snapshot added.
const BYTES_PREFIX: &[u8] = b"state_snapshot_bytes:";

/// Writes one node-local metadata record.
fn put_metadata(kv: &dyn KvStore, key: &[u8], value: &[u8]) -> Result<()> {
    kv.put(CF_METADATA, key, value).map_err(NodeError::Storage)
}

/// Producer policy. Joining nodes are unaffected by it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotConfig {
    /// Master switch for producing snapshots. Unset, a validator produces
    /// them (it holds the complete history and is the node joiners ask) and
    /// every other role does not; `Some(false)` turns a validator's off and
    /// `Some(true)` turns another role's on.
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Minimum spacing between snapshots, in blocks.
    #[serde(default = "default_snapshot_interval_blocks")]
    pub interval_blocks: u64,
    /// Snapshots kept (and offered to joiners); older ones are removed from
    /// the index and their blobs are released, except while a peer is
    /// fetching them. The newest snapshot is never removed.
    #[serde(default = "default_snapshot_retain_count")]
    pub retain_count: usize,
    /// Cap on the blob bytes of the snapshots kept. When it is reached the
    /// oldest snapshots are removed to make room; the newest stays.
    #[serde(default = "default_snapshot_max_published_bytes")]
    pub max_published_bytes: u64,
    /// Share of the data volume the snapshot blobs may take, percent; the
    /// lower of this and `max_published_bytes` applies.
    #[serde(default = "default_snapshot_max_volume_pct")]
    pub max_volume_pct: u8,
}

impl SnapshotConfig {
    /// Whether a node with (`is_validator`) or without the validator role
    /// produces snapshots under this policy.
    pub fn produces(&self, is_validator: bool) -> bool {
        self.enabled.unwrap_or(is_validator)
    }

    /// This policy with the role default applied, so that `enabled` is set.
    pub fn resolved(mut self, is_validator: bool) -> Self {
        self.enabled = Some(self.produces(is_validator));
        self
    }
}

fn default_snapshot_max_published_bytes() -> u64 {
    DEFAULT_SNAPSHOT_MAX_PUBLISHED_BYTES
}

fn default_snapshot_max_volume_pct() -> u8 {
    DEFAULT_SNAPSHOT_MAX_VOLUME_PCT
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
            enabled: None,
            interval_blocks: DEFAULT_SNAPSHOT_INTERVAL_BLOCKS,
            retain_count: DEFAULT_SNAPSHOT_RETAIN_COUNT,
            max_published_bytes: DEFAULT_SNAPSHOT_MAX_PUBLISHED_BYTES,
            max_volume_pct: DEFAULT_SNAPSHOT_MAX_VOLUME_PCT,
        }
    }
}

impl SnapshotConfig {
    /// The most blob bytes the kept snapshots may hold on a volume of
    /// `volume_bytes`.
    pub fn cap_for_volume(&self, volume_bytes: u64) -> u64 {
        let share = (volume_bytes as u128 * self.max_volume_pct.min(100) as u128 / 100) as u64;
        self.max_published_bytes.min(share)
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
    /// BLAKE3 hash of the blob holding blocks `height - 1 ..= height + STATE_ROOT_LAG`.
    /// The block before `height` lets a joiner see that `height` opens its epoch.
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
    if height == 0 || chain.len() as u64 != STATE_ROOT_LAG + 2 {
        return Err(NodeError::Other(format!(
            "anchor chain holds {} blocks, expected {}",
            chain.len(),
            STATE_ROOT_LAG + 2
        )));
    }
    // The chain starts at the block before `height`.
    let first = height - 1;
    for (i, block) in chain.iter().enumerate() {
        if block.height().0 != first + i as u64 {
            return Err(NodeError::Other(format!(
                "anchor chain block {i} is at height {}, expected {}",
                block.height(),
                first + i as u64
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
    // A snapshot is cut where an epoch opens: its block carries a later epoch
    // than the block before it. Anything else holds a registry that is not
    // the epoch's, and a node restored from it would stall at the next
    // boundary.
    if !crate::state_commitment::opens_epoch(
        BlockHeight(height),
        chain[1].header.epoch,
        chain[0].header.epoch,
    ) {
        return Err(NodeError::Other(format!(
            "the snapshot at height {height} is not at the start of an epoch"
        )));
    }
    // The epoch must hold more than that one block: a node restored at an
    // epoch's only block has no closing checkpoint to adopt the next
    // committee from. On a quiet network every epoch can be a single block,
    // and then no snapshot is taken; a node joins by full sync, which is
    // cheap on a chain with so few blocks.
    if chain[2].header.epoch != chain[1].header.epoch {
        return Err(NodeError::Other(format!(
            "the snapshot at height {height} is the only block of its epoch"
        )));
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
    /// Lets go of published blobs so the store can free their bytes. A store
    /// that keeps everything may leave this as it is.
    async fn release(&self, _hashes: &[[u8; 32]]) -> Result<()> {
        Ok(())
    }
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

    async fn release(&self, hashes: &[[u8; 32]]) -> Result<()> {
        self.resolver
            .release_blobs(hashes)
            .await
            .map(|_| ())
            .map_err(|e| NodeError::Other(format!("release snapshot blobs: {e}")))
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
    /// The node's data directory, whose volume a snapshot's blobs are
    /// written to; when set, production checks the free space first.
    data_dir: Option<std::path::PathBuf>,
    /// When a peer last asked for the manifest at each height.
    leases: parking_lot::Mutex<std::collections::HashMap<u64, std::time::Instant>>,
    /// Held while a snapshot is produced or snapshots are removed.
    work: tokio::sync::Mutex<()>,
}

impl SnapshotStore {
    /// Checks the free space of the volume holding `dir` before every
    /// snapshot, and refuses to start one it cannot finish.
    pub fn with_data_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.data_dir = Some(dir);
        self
    }

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
            data_dir: None,
            leases: Default::default(),
            work: Default::default(),
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
        // `enabled` is resolved from the node's roles before the store is
        // built (see `SnapshotConfig::resolved`); unresolved it is off.
        if !self.config.produces(false) || !starts_epoch || state_height == 0 {
            return Ok(false);
        }
        let newest = self.index()?.keys().next_back().copied();
        Ok(newest.is_none_or(|n| state_height >= n + self.config.interval_blocks.max(1)))
    }

    /// Produces the snapshot of the committed state at `state_height`. The
    /// blocks `state_height ..= state_height + STATE_ROOT_LAG` must be
    /// stored. Reads an immutable trie version, so blocks committing while
    /// this runs cannot tear it.
    ///
    /// Buckets are published one at a time, so memory holds one bucket. The
    /// disk needed is what the new blobs add (a bucket unchanged since the
    /// last snapshot is the same blob), estimated from the last snapshot;
    /// the oldest snapshots are removed first when the cap would be passed.
    pub async fn produce(&self, state_height: u64) -> Result<SnapshotManifest> {
        let _work = self.work.lock().await;
        let estimate = self.estimate_bytes()?;
        let cap = self.cap()?;
        if let Some(dir) = &self.data_dir {
            let volume = tenzro_storage::resources::volume_of(dir)
                .map_err(|e| NodeError::Other(format!("free space of the data volume: {e}")))?;
            tenzro_storage::resources::headroom(
                &volume,
                estimate,
                &tenzro_storage::resources::LadderConfig::default(),
            )
            .map_err(|short| NodeError::Other(format!("state snapshot not started: {short}")))?;
        }
        // Make room before writing: an old snapshot nobody is fetching goes
        // first, so the transient is one snapshot, not two.
        self.retain_locked(cap, estimate).await?;

        let mut added = 0u64;
        let mut published: Vec<[u8; 32]> = Vec::new();
        let made = self
            .publish_snapshot(state_height, &mut added, &mut published)
            .await;
        let manifest = match made {
            Ok(m) => m,
            Err(e) => {
                // Blobs of a snapshot that never completed would stay for
                // good: let go of those no kept snapshot also uses.
                if let Ok(keep) = self.referenced(&self.index()?).await {
                    let orphans: Vec<[u8; 32]> = published
                        .into_iter()
                        .filter(|h| !keep.contains(h))
                        .collect();
                    let _ = self.blobs.release(&orphans).await;
                }
                return Err(e);
            }
        };
        let manifest_hash = *published.last().expect("the manifest is published last");
        put_metadata(
            &*self.store,
            &Self::bytes_key(state_height),
            &added.to_be_bytes(),
        )?;
        put_metadata(&*self.store, &Self::index_key(state_height), &manifest_hash)?;
        self.retain_locked(cap, 0).await?;
        Ok(manifest)
    }

    async fn publish_snapshot(
        &self,
        state_height: u64,
        added: &mut u64,
        published: &mut Vec<[u8; 32]>,
    ) -> Result<SnapshotManifest> {
        let root = self
            .trie
            .root_at(state_height)
            .map_err(NodeError::Storage)?
            .ok_or_else(|| {
                NodeError::Other(format!("no committed state at height {state_height}"))
            })?;
        let block_store = BlockStoreImpl::new(self.store.clone()).map_err(NodeError::Storage)?;
        let mut chain = Vec::new();
        for h in state_height.saturating_sub(1)..=state_height + STATE_ROOT_LAG {
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
        *added += chain_bytes.len() as u64;
        let anchor_chain = self.blobs.publish(chain_bytes).await?;
        published.push(anchor_chain);

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
            *added += bytes.len() as u64;
            let blob = self.blobs.publish(bytes).await?;
            published.push(blob);
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
        *added += manifest_bytes.len() as u64;
        published.push(self.blobs.publish(manifest_bytes).await?);
        Ok(manifest)
    }

    fn bytes_key(height: u64) -> Vec<u8> {
        let mut k = BYTES_PREFIX.to_vec();
        k.extend_from_slice(&height.to_be_bytes());
        k
    }

    fn bytes_of(&self, height: u64) -> u64 {
        self.store
            .get(CF_METADATA, &Self::bytes_key(height))
            .ok()
            .flatten()
            .and_then(|v| v.as_slice().try_into().ok().map(u64::from_be_bytes))
            .unwrap_or(0)
    }

    /// Blob bytes the snapshots kept hold (blobs shared between snapshots are
    /// counted once per snapshot that added them, so this is an upper bound).
    pub fn published_bytes(&self) -> Result<u64> {
        Ok(self.index()?.keys().map(|h| self.bytes_of(*h)).sum())
    }

    /// What the next snapshot may add, as far as can be known: the size of
    /// the largest kept one, else the live state, never more than the cap.
    fn estimate_bytes(&self) -> Result<u64> {
        let last = self
            .index()?
            .keys()
            .map(|h| self.bytes_of(*h))
            .max()
            .unwrap_or(0);
        if last > 0 {
            return Ok(last);
        }
        let live = self
            .store
            .cf_sizes()
            .iter()
            .find(|c| c.name == CF_STATE_TRIE)
            .map_or(0, |c| c.live_data);
        Ok(live.min(self.cap()?))
    }

    /// The cap on kept snapshot bytes: the configured one, lowered to the
    /// share of the data volume when the volume is known.
    fn cap(&self) -> Result<u64> {
        let Some(dir) = &self.data_dir else {
            return Ok(self.config.max_published_bytes);
        };
        let volume = tenzro_storage::resources::volume_of(dir)
            .map_err(|e| NodeError::Other(format!("size of the data volume: {e}")))?;
        Ok(self.config.cap_for_volume(volume.total_bytes))
    }

    fn leased(&self, height: u64) -> bool {
        self.leases
            .lock()
            .get(&height)
            .is_some_and(|t| t.elapsed() < SERVE_LEASE)
    }

    /// Notes that a peer asked for the manifest at `height`.
    fn lease(&self, height: u64) {
        let mut leases = self.leases.lock();
        leases.retain(|_, t| t.elapsed() < SERVE_LEASE);
        leases.insert(height, std::time::Instant::now());
    }

    /// Every blob hash the snapshots in `index` use: manifest, anchor chain
    /// and buckets.
    async fn referenced(
        &self,
        index: &BTreeMap<u64, [u8; 32]>,
    ) -> Result<std::collections::HashSet<[u8; 32]>> {
        let mut out = std::collections::HashSet::new();
        for hash in index.values() {
            out.extend(self.blob_hashes(hash).await?);
        }
        Ok(out)
    }

    async fn blob_hashes(&self, manifest_hash: &[u8; 32]) -> Result<Vec<[u8; 32]>> {
        let bytes = self.blobs.fetch(manifest_hash).await?;
        let m: SnapshotManifest = bincode::deserialize(&bytes)
            .map_err(|e| NodeError::Other(format!("decode manifest: {e}")))?;
        let mut out = vec![*manifest_hash, m.anchor_chain];
        out.extend(m.buckets.iter().map(|b| b.blob));
        Ok(out)
    }

    /// Removes snapshots beyond the retain count, oldest first, and then the
    /// oldest more while the kept bytes (plus `incoming`) pass the cap. The
    /// newest snapshot and any a peer asked for within [`SERVE_LEASE`] stay.
    /// Their blobs are released unless a snapshot that stays also uses them.
    async fn retain_locked(&self, cap: u64, incoming: u64) -> Result<()> {
        let index = self.index()?;
        let keep = self.config.retain_count.max(1);
        let newest = index.keys().next_back().copied();
        let mut held: u64 = index.keys().map(|h| self.bytes_of(*h)).sum();
        let mut count = index.len();
        let mut drop = Vec::new();
        for h in index.keys().copied() {
            if Some(h) == newest || self.leased(h) {
                continue;
            }
            if count > keep || held.saturating_add(incoming) > cap {
                drop.push(h);
                count -= 1;
                held = held.saturating_sub(self.bytes_of(h));
            }
        }
        if drop.is_empty() {
            return Ok(());
        }
        let mut stays = index.clone();
        let mut candidates = Vec::new();
        for h in &drop {
            if let Some(hash) = stays.remove(h)
                && let Ok(hashes) = self.blob_hashes(&hash).await
            {
                candidates.extend(hashes);
            }
        }
        // Without the manifests that stay, what they share cannot be told:
        // keep every blob and try again on the next pass.
        let keep_hashes = match self.referenced(&stays).await {
            Ok(k) => k,
            Err(e) => {
                warn!(error = %e, "snapshot blobs kept: a retained manifest could not be read");
                return Ok(());
            }
        };
        let ops = drop
            .iter()
            .flat_map(|h| {
                [
                    WriteOp::Delete {
                        cf: CF_METADATA.to_string(),
                        key: Self::index_key(*h),
                    },
                    WriteOp::Delete {
                        cf: CF_METADATA.to_string(),
                        key: Self::bytes_key(*h),
                    },
                ]
            })
            .collect();
        self.store.write_batch(ops).map_err(NodeError::Storage)?;
        candidates.sort_unstable();
        candidates.dedup();
        candidates.retain(|h| !keep_hashes.contains(h));
        let released = candidates.len();
        self.blobs.release(&candidates).await?;
        info!(
            snapshots = drop.len(),
            blobs = released,
            "old state snapshots removed"
        );
        Ok(())
    }

    /// Applies the retention to the snapshots held now: those beyond the
    /// retain count or the cap whose lease has run out are removed with their
    /// blobs. Run periodically; `produce` does the same before and after it
    /// writes.
    pub async fn maintain(&self) -> Result<()> {
        let _work = self.work.lock().await;
        let cap = self.cap()?;
        self.retain_locked(cap, 0).await
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
        let hash = self.manifest_hash(height).ok().flatten();
        if hash.is_some() {
            self.lease(height);
        }
        hash
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
            .get(1)
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

    restore_consensus_records(&kv, &trie, height, epoch_duration, chain[1].header.epoch)?;
    info!(
        height,
        epoch = chain[1].header.epoch,
        "State restored at the first block of an epoch; this node takes part in consensus from the handover into the next epoch, after it has imported this one"
    );

    // The restored height's block becomes the local tip; block-sync imports
    // from the next height on, checking every certificate.
    put_metadata(&*kv, RESTORED_HEIGHT_KEY, &height.to_be_bytes())?;
    let mut block_store = BlockStoreImpl::new(store.clone()).map_err(NodeError::Storage)?;
    block_store
        .put_block(&chain[1])
        .await
        .map_err(NodeError::Storage)?;

    Ok(SyncedState {
        height,
        state_root: trusted_root,
        buckets_fetched: fetched,
    })
}

/// Whether a state sync began on this store and did not finish: buckets
/// are recorded as written but the restored height's block, which the sync
/// stores last, is not there. Such a store holds neither genesis state nor
/// the snapshot's.
pub async fn restore_interrupted(store: &Arc<RocksDbStore>) -> Result<bool> {
    let begun = !store
        .scan_prefix(CF_METADATA, PROGRESS_PREFIX)
        .map_err(NodeError::Storage)?
        .is_empty();
    if !begun {
        return Ok(false);
    }
    let tip = BlockStoreImpl::new(store.clone()).map_err(NodeError::Storage)?;
    let finished = tip
        .latest_height()
        .await
        .map_err(NodeError::Storage)?
        .is_some_and(|h| h.0 > 0);
    Ok(!finished)
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
    expected_epoch: u64,
) -> Result<()> {
    use crate::state_commitment::{EpochRecord, EpochSide, REGISTRY_INDEX_KEY};
    let mut records: Vec<EpochRecord> = Vec::new();
    let mut registry = Vec::new();
    let mut index: Option<Vec<tenzro_types::primitives::Address>> = None;
    let mut side: Option<EpochSide> = None;
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
                if e.key == crate::state_commitment::REGISTRY_SIDE_KEY {
                    side = Some(bincode::deserialize(&e.value).map_err(|err| {
                        NodeError::Other(format!("decode registry side state: {err}"))
                    })?);
                } else if e.key == REGISTRY_INDEX_KEY {
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
    if epoch.number != expected_epoch || epoch.start_height != height {
        return Err(NodeError::Other(format!(
            "the snapshot's newest epoch record is epoch {} from height {}, not epoch {expected_epoch} from {height}",
            epoch.number, epoch.start_height
        )));
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
    if let Some(registry_side) = side.and_then(|s| s.registry) {
        for (key, value) in registry_side.storage_rows() {
            ops.push(WriteOp::Put {
                cf: registry_cf.to_string(),
                key,
                value,
            });
        }
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

        async fn release(&self, hashes: &[[u8; 32]]) -> Result<()> {
            let mut blobs = self.blobs.lock();
            for h in hashes {
                blobs.remove(h);
            }
            Ok(())
        }
    }

    impl MemBlobs {
        fn bytes(&self) -> u64 {
            self.blobs.lock().values().map(|b| b.len() as u64).sum()
        }

        fn holds(&self, hash: &[u8; 32]) -> bool {
            self.blobs.lock().contains_key(hash)
        }
    }

    /// Commits another state version at `height` with a few accounts changed
    /// and stores the blocks a snapshot at `height` needs.
    async fn extend(store: &Arc<RocksDbStore>, height: u64, changed: u32) {
        let trie = StateTrie::new(store.clone() as Arc<dyn KvStore>);
        let mut writes = Writes::new();
        for i in 0..changed {
            let (ns, key) = account(i);
            writes.insert(
                (ns, key),
                Some((height * 1000 + i as u64).to_le_bytes().to_vec()),
            );
        }
        trie.commit(height, &writes).unwrap();
        let mut blocks = BlockStoreImpl::new(store.clone()).unwrap();
        let mut prev = Hash::new([1u8; 32]);
        for h in height - 1..=height + STATE_ROOT_LAG {
            let mut header = BlockHeader::new(
                BlockHeight(h),
                prev,
                Hash::zero(),
                Hash::new([h as u8; 32]),
                Address::new([2u8; 32]),
            );
            header.epoch = if h >= height { 2 } else { 1 };
            let block = Block::new(header, vec![]);
            prev = block.hash();
            blocks.put_block(&block).await.unwrap();
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
        producer_with(dir, 7).await
    }

    /// [`producer`] with `factor` deciding the account balances, so two
    /// producers can hold different, equally well-formed histories.
    async fn producer_with(dir: &tempfile::TempDir, factor: u64) -> (Arc<RocksDbStore>, Hash) {
        let store = open(dir);
        let trie = StateTrie::new(store.clone() as Arc<dyn KvStore>);
        let mut writes = Writes::new();
        let mut ops = Vec::new();
        for i in 0..300u32 {
            let (ns, key) = account(i);
            let value = (i as u64 * factor).to_le_bytes().to_vec();
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
        for h in HEIGHT - 1..=HEIGHT + STATE_ROOT_LAG {
            let state_root = if h == HEIGHT + STATE_ROOT_LAG {
                root
            } else {
                Hash::new([h as u8; 32])
            };
            let mut header = BlockHeader::new(
                BlockHeight(h),
                prev,
                Hash::zero(),
                state_root,
                Address::new([2u8; 32]),
            );
            header.epoch = if h >= HEIGHT { 1 } else { 0 };
            let block = Block::new(header, vec![]);
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
                enabled: Some(true),
                interval_blocks: 1,
                retain_count: 2,
                max_published_bytes: DEFAULT_SNAPSHOT_MAX_PUBLISHED_BYTES,
                max_volume_pct: DEFAULT_SNAPSHOT_MAX_VOLUME_PCT,
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

    /// An attacker who runs its own chain can serve a snapshot that is valid
    /// in every internal respect: the state folds to its own roots, its own
    /// blocks link and end in a header that commits the state root. A joiner
    /// that trusts only the honest chain's block hash must still refuse it.
    #[tokio::test]
    async fn a_self_consistent_snapshot_of_another_chain_is_refused() {
        let honest_dir = tempfile::tempdir().unwrap();
        let (_honest_store, honest_anchor) = producer_with(&honest_dir, 7).await;

        let evil_dir = tempfile::tempdir().unwrap();
        let (evil_store, evil_anchor) = producer_with(&evil_dir, 9).await;
        assert_ne!(evil_anchor, honest_anchor, "the two histories differ");
        let blobs = Arc::new(MemBlobs::default());
        let evil = snapshot_store(&evil_store, blobs.clone());
        evil.produce(HEIGHT).await.unwrap();

        // The joiner trusts the honest block; the attacker's own anchor
        // would have passed every internal check.
        let jdir = tempfile::tempdir().unwrap();
        let joiner = open(&jdir);
        let refused = state_sync(
            &joiner,
            &Directory(evil.clone()),
            blobs.as_ref(),
            HEIGHT + STATE_ROOT_LAG,
            honest_anchor,
            100,
        )
        .await;
        let err = refused
            .expect_err("a snapshot of another chain is refused")
            .to_string();
        assert!(err.contains("trusted checkpoint"), "{err}");
        assert!(
            !restore_interrupted(&joiner).await.unwrap(),
            "refused before anything was written"
        );
        let (ns, key) = account(42);
        assert_eq!(joiner.get(&ns, &key).unwrap(), None, "nothing was restored");

        // Control: the same snapshot is accepted by a joiner that trusts the
        // attacker's block, so the refusal above is the anchor's doing.
        let cdir = tempfile::tempdir().unwrap();
        let control = open(&cdir);
        state_sync(
            &control,
            &Directory(evil),
            blobs.as_ref(),
            HEIGHT + STATE_ROOT_LAG,
            evil_anchor,
            100,
        )
        .await
        .expect("the control accepts what it anchors to");
    }

    /// A peer that kept only an older snapshot cannot be used for a newer
    /// checkpoint: the joiner asks for exactly the height its checkpoint
    /// commits, and a stale manifest under that height is refused.
    #[tokio::test]
    async fn a_stale_snapshot_is_refused() {
        let pdir = tempfile::tempdir().unwrap();
        let (pstore, anchor) = producer(&pdir).await;
        let blobs = Arc::new(MemBlobs::default());
        let snapshots = snapshot_store(&pstore, blobs.clone());
        snapshots.produce(HEIGHT).await.unwrap();

        // The checkpoint is one epoch later than any snapshot the peer holds.
        let jdir = tempfile::tempdir().unwrap();
        let joiner = open(&jdir);
        let err = state_sync(
            &joiner,
            &Directory(snapshots),
            blobs.as_ref(),
            HEIGHT + 1000 + STATE_ROOT_LAG,
            anchor,
            100,
        )
        .await
        .expect_err("no snapshot at the checkpoint's height")
        .to_string();
        assert!(err.contains("holds no snapshot"), "{err}");
    }

    /// A sync that stops after it began writing leaves a store that neither
    /// replay nor the next boot may treat as fresh; one that completes, or
    /// never began, is not reported as interrupted.
    #[tokio::test]
    async fn an_interrupted_restore_is_told_from_a_finished_one() {
        let pdir = tempfile::tempdir().unwrap();
        let (pstore, anchor) = producer(&pdir).await;
        let blobs = Arc::new(MemBlobs::default());
        let snapshots = snapshot_store(&pstore, blobs.clone());
        snapshots.produce(HEIGHT).await.unwrap();

        let jdir = tempfile::tempdir().unwrap();
        let joiner = open(&jdir);
        assert!(!restore_interrupted(&joiner).await.unwrap(), "fresh store");

        // The peer drops out after the manifest, the anchor chain and a few
        // buckets.
        *blobs.fail_after.lock() = Some(5);
        state_sync(
            &joiner,
            &Directory(snapshots.clone()),
            blobs.as_ref(),
            HEIGHT + STATE_ROOT_LAG,
            anchor,
            100,
        )
        .await
        .expect_err("the peer went away");
        assert!(
            restore_interrupted(&joiner).await.unwrap(),
            "buckets were written, the restored block was not"
        );

        // Resuming finishes it.
        *blobs.fail_after.lock() = None;
        state_sync(
            &joiner,
            &Directory(snapshots),
            blobs.as_ref(),
            HEIGHT + STATE_ROOT_LAG,
            anchor,
            100,
        )
        .await
        .unwrap();
        assert!(!restore_interrupted(&joiner).await.unwrap(), "finished");
    }

    fn store_with(
        store: &Arc<RocksDbStore>,
        blobs: Arc<MemBlobs>,
        retain_count: usize,
        max_published_bytes: u64,
    ) -> Arc<SnapshotStore> {
        Arc::new(SnapshotStore::new(
            store.clone(),
            blobs,
            SnapshotConfig {
                enabled: Some(true),
                interval_blocks: 1,
                retain_count,
                max_published_bytes,
                max_volume_pct: DEFAULT_SNAPSHOT_MAX_VOLUME_PCT,
            },
        ))
    }

    /// Old snapshots and the blobs only they use are removed; blobs a kept
    /// snapshot shares stay.
    #[tokio::test]
    async fn old_snapshots_and_their_blobs_are_removed() {
        let pdir = tempfile::tempdir().unwrap();
        let (pstore, _anchor) = producer(&pdir).await;
        let blobs = Arc::new(MemBlobs::default());
        let snapshots = store_with(&pstore, blobs.clone(), 1, u64::MAX);
        let first = snapshots.produce(HEIGHT).await.unwrap();
        let first_manifest = snapshots.manifest_hash(HEIGHT).unwrap().unwrap();
        extend(&pstore, 20, 3).await;
        let second = snapshots.produce(20).await.unwrap();
        let second_manifest = snapshots.manifest_hash(20).unwrap().unwrap();

        assert_eq!(
            snapshots.manifest_hash(HEIGHT).unwrap(),
            None,
            "the old one is gone"
        );
        assert!(
            !blobs.holds(&first_manifest),
            "its manifest blob is released"
        );
        assert!(
            !blobs.holds(&first.anchor_chain),
            "its anchor blob is released"
        );
        assert!(blobs.holds(&second_manifest));
        for b in &second.buckets {
            assert!(blobs.holds(&b.blob), "the kept snapshot is whole");
        }
        let shared = first
            .buckets
            .iter()
            .filter(|b| second.buckets.iter().any(|c| c.blob == b.blob))
            .count();
        assert!(
            shared > 0,
            "unchanged buckets are one blob, kept for the new snapshot"
        );
        let alone = first
            .buckets
            .iter()
            .filter(|b| !second.buckets.iter().any(|c| c.blob == b.blob));
        for b in alone {
            assert!(
                !blobs.holds(&b.blob),
                "a bucket only the old snapshot used is released"
            );
        }
        assert_eq!(snapshots.published_bytes().unwrap(), snapshots.bytes_of(20));
    }

    /// The newest snapshot is never removed, whatever the cap, and neither is
    /// one a peer asked for within the lease; it goes on the next pass after.
    #[tokio::test]
    async fn the_snapshot_being_served_is_never_removed() {
        let pdir = tempfile::tempdir().unwrap();
        let (pstore, _anchor) = producer(&pdir).await;
        let blobs = Arc::new(MemBlobs::default());
        // A cap of one byte: every snapshot passes it.
        let snapshots = store_with(&pstore, blobs.clone(), 1, 1);
        snapshots.produce(HEIGHT).await.unwrap();
        assert!(
            snapshots.manifest_hash(HEIGHT).unwrap().is_some(),
            "the newest stays under any cap"
        );

        // A peer asks for the manifest at HEIGHT, then a newer snapshot lands.
        let served = tenzro_iroh::SnapshotDirectory::manifest_for(&*snapshots, HEIGHT)
            .await
            .expect("served");
        let manifest = snapshots.manifest(HEIGHT).await.unwrap().unwrap();
        extend(&pstore, 20, 3).await;
        snapshots.produce(20).await.unwrap();
        assert!(
            snapshots.manifest_hash(HEIGHT).unwrap().is_some(),
            "leased: still indexed"
        );
        assert!(blobs.holds(&served), "leased: manifest blob kept");
        for b in &manifest.buckets {
            assert!(blobs.holds(&b.blob), "leased: a peer can finish fetching");
        }
        assert!(snapshots.manifest_hash(20).unwrap().is_some());

        // The lease runs out: the next pass removes it.
        snapshots.leases.lock().insert(
            HEIGHT,
            std::time::Instant::now() - SERVE_LEASE - std::time::Duration::from_secs(1),
        );
        snapshots.maintain().await.unwrap();
        assert_eq!(snapshots.manifest_hash(HEIGHT).unwrap(), None);
        assert!(
            snapshots.manifest_hash(20).unwrap().is_some(),
            "the newest stays"
        );
    }

    /// The bytes kept stay under the cap by removing the oldest, and no
    /// lifetime counter stops production: many snapshots in a row all land.
    #[tokio::test]
    async fn production_continues_past_the_cap_by_removing_the_oldest() {
        let pdir = tempfile::tempdir().unwrap();
        let (pstore, _anchor) = producer(&pdir).await;
        let blobs = Arc::new(MemBlobs::default());
        let snapshots = store_with(&pstore, blobs.clone(), 3, u64::MAX);
        snapshots.produce(HEIGHT).await.unwrap();
        let one = snapshots.published_bytes().unwrap();
        assert!(one > 0);
        // Room for two snapshots of this size and a little more.
        let snapshots = store_with(&pstore, blobs.clone(), 3, one * 2 + one / 2);
        for (i, h) in [20u64, 30, 40, 50].into_iter().enumerate() {
            extend(&pstore, h, 40 + i as u32).await;
            snapshots
                .produce(h)
                .await
                .expect("production never stops for good");
            assert!(
                snapshots.published_bytes().unwrap() <= one * 3,
                "kept bytes stay near the cap"
            );
        }
        let kept = snapshots.index().unwrap();
        assert!(kept.len() <= 3);
        assert!(kept.contains_key(&50), "the newest is there");
        assert!(blobs.bytes() < one * 5, "released blobs left the store");
    }

    /// A small disk cannot be filled by snapshots: the cap is the lower of
    /// the byte cap and the volume share.
    #[test]
    fn the_cap_follows_the_size_of_the_volume() {
        let c = SnapshotConfig::default();
        assert_eq!(c.cap_for_volume(100 << 30), 15 << 30);
        assert_eq!(c.cap_for_volume(50 << 30), (50u64 << 30) * 15 / 100);
        assert_eq!(c.cap_for_volume(1 << 40), c.max_published_bytes);
        let wide = SnapshotConfig {
            max_published_bytes: 1 << 30,
            ..SnapshotConfig::default()
        };
        assert_eq!(wide.cap_for_volume(1 << 40), 1 << 30);
    }

    /// A snapshot whose publishing fails leaves no blob behind that a kept
    /// snapshot does not use.
    #[tokio::test]
    async fn an_unfinished_snapshot_leaves_no_blobs() {
        let pdir = tempfile::tempdir().unwrap();
        let (pstore, _anchor) = producer(&pdir).await;
        let blobs = Arc::new(MemBlobs::default());
        let snapshots = store_with(&pstore, blobs.clone(), 2, u64::MAX);
        // No blocks at this height: the anchor chain cannot be built, after
        // the state version exists.
        let trie = StateTrie::new(pstore.clone() as Arc<dyn KvStore>);
        trie.commit(20, &Writes::new()).unwrap();
        let before = blobs.bytes();
        snapshots
            .produce(20)
            .await
            .expect_err("block 20 is not stored");
        assert_eq!(blobs.bytes(), before);
    }

    /// A snapshot is cut where an epoch opens. One cut anywhere else carries a
    /// registry that is not its epoch's, and is refused whatever its root.
    #[test]
    fn a_snapshot_not_at_an_epoch_start_is_refused() {
        let build = |first_epoch: u64| {
            let mut prev = Hash::new([1u8; 32]);
            let mut chain = Vec::new();
            for h in HEIGHT - 1..=HEIGHT + STATE_ROOT_LAG {
                let mut header = BlockHeader::new(
                    BlockHeight(h),
                    prev,
                    Hash::zero(),
                    Hash::new([h as u8; 32]),
                    Address::new([2u8; 32]),
                );
                header.epoch = if h < HEIGHT { first_epoch } else { 1 };
                let block = Block::new(header, vec![]);
                prev = block.hash();
                chain.push(block);
            }
            chain
        };
        let opens = build(0);
        let trusted = opens.last().unwrap().hash();
        assert!(check_anchor_chain(HEIGHT, &opens, &trusted).is_ok());
        let mid_epoch = build(1);
        let trusted = mid_epoch.last().unwrap().hash();
        let err = check_anchor_chain(HEIGHT, &mid_epoch, &trusted)
            .unwrap_err()
            .to_string();
        assert!(err.contains("start of an epoch"), "{err}");
    }

    /// An epoch of one block gives a restored node no closing checkpoint to
    /// adopt the next committee from, so a snapshot there is refused.
    #[test]
    fn a_snapshot_at_the_only_block_of_its_epoch_is_refused() {
        let mut prev = Hash::new([1u8; 32]);
        let mut chain = Vec::new();
        for h in HEIGHT - 1..=HEIGHT + STATE_ROOT_LAG {
            let mut header = BlockHeader::new(
                BlockHeight(h),
                prev,
                Hash::zero(),
                Hash::new([h as u8; 32]),
                Address::new([2u8; 32]),
            );
            // Epoch 1 holds only block HEIGHT; epoch 2 starts right after.
            header.epoch = if h < HEIGHT {
                0
            } else if h == HEIGHT {
                1
            } else {
                2
            };
            let block = Block::new(header, vec![]);
            prev = block.hash();
            chain.push(block);
        }
        let trusted = chain.last().unwrap().hash();
        let err = check_anchor_chain(HEIGHT, &chain, &trusted)
            .unwrap_err()
            .to_string();
        assert!(err.contains("only block of its epoch"), "{err}");
    }
}
