//! The committed state of the chain: an incremental, height-versioned binary
//! trie over every entry block execution writes.
//!
//! # What is committed
//!
//! Every write block execution makes to a committed column family (see
//! [`COMMITTED_CFS`]), recorded through [`capture`], plus records the node
//! derives deterministically from finalized blocks under the reserved
//! namespaces [`NS_EPOCH`] and [`NS_VALIDATOR_REGISTRY`]. Writes that node-local
//! code makes to the same column families are not committed: they are not the
//! same on every node.
//!
//! # Structure
//!
//! A binary trie keyed by 31-byte stems, each holding 256 value slots (see
//! [`hashing`] for the hash rules). Updates are incremental: applying a block's
//! writes rewrites only the nodes on the paths to the changed stems. Nodes are
//! stored under `(version, depth, path)`, so every version stays readable until
//! pruned, which is what makes roots and proofs height-indexed. A node replaced
//! at version `v` is logged as stale at `v` and deleted once no retained
//! version can reach it.
//!
//! # Storage layout (column family [`CF_STATE_TRIE`])
//!
//! | Key | Value |
//! |---|---|
//! | `N` ‖ version ‖ depth ‖ path | node |
//! | `V` ‖ tree key ‖ version | `(namespace, key, value)` |
//! | `R` ‖ version | root reference |
//! | `S` ‖ version ‖ stale key | empty |
//! | `L` | latest version |
//!
//! Integers are big-endian so keys sort by version.

pub mod capture;
pub mod hashing;
pub mod proof;
pub mod snapshot;

use crate::error::{Result, StorageError};
use crate::kv::{KvStore, WriteOp};
use crate::{
    CF_ACCOUNTS, CF_AGENTS, CF_CHALLENGES, CF_CHANNELS, CF_CREDENTIALS, CF_DA_COMMITTEE,
    CF_DELEGATIONS, CF_IDENTITIES, CF_MODEL_SERVICES, CF_MODELS, CF_PROVIDERS, CF_SETTLEMENTS,
    CF_STATE, CF_TOKENS, CF_VALIDATOR_MODULES,
};
use hashing::{
    EMPTY, STEM_BITS, STEM_LEN, Stem, Subtree, internal_hash, leaf_hash, slot_siblings, slots_root,
    split_tree_key, stem_bit, stem_hash, tree_key,
};
use proof::{ProofTerminal, StateProof};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tenzro_types::hash_scheme::HashScheme;
use tenzro_types::primitives::Hash;

/// Column family holding the trie.
pub const CF_STATE_TRIE: &str = "state_trie";

/// Column families whose writes during block execution are committed.
///
/// Excluded are the column families that are node-local by construction:
/// blocks and the transaction index (committed through block hashes instead),
/// node metadata, snapshots, events, webhooks, the audit log, API keys, key
/// shares and analytics.
pub const COMMITTED_CFS: &[&str] = &[
    CF_STATE,
    CF_ACCOUNTS,
    CF_IDENTITIES,
    CF_DELEGATIONS,
    CF_CREDENTIALS,
    CF_CHANNELS,
    CF_AGENTS,
    CF_MODELS,
    CF_PROVIDERS,
    CF_TOKENS,
    CF_SETTLEMENTS,
    CF_MODEL_SERVICES,
    CF_VALIDATOR_MODULES,
    CF_DA_COMMITTEE,
    CF_CHALLENGES,
];

/// Namespace of the per-epoch record: the epoch's number, first height and
/// validator set, written when the epoch's first block is executed.
pub const NS_EPOCH: &str = "epoch";

/// Namespace of the validator registry as of an epoch's first block: the input
/// every later epoch transition is computed from.
pub const NS_VALIDATOR_REGISTRY: &str = "validator_registry";

/// Whether writes to `cf` during execution are committed.
pub fn is_committed_cf(cf: &str) -> bool {
    COMMITTED_CFS.contains(&cf)
}

/// Whether `namespace` may appear in the trie at all.
pub fn is_committed_namespace(namespace: &str) -> bool {
    is_committed_cf(namespace) || namespace == NS_EPOCH || namespace == NS_VALIDATOR_REGISTRY
}

/// Reference from a parent to a child node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct NodeRef {
    version: u64,
    hash: [u8; 32],
    is_stem: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum Node {
    Internal {
        left: Option<NodeRef>,
        right: Option<NodeRef>,
    },
    Stem {
        stem: Stem,
        /// Occupied slots: slot hash and the version its value was written at.
        slots: BTreeMap<u8, ([u8; 32], u64)>,
    },
}

impl Node {
    fn hash(&self, scheme: HashScheme) -> [u8; 32] {
        match self {
            Node::Internal { left, right } => internal_hash(
                scheme,
                &left.map(|r| r.hash).unwrap_or(EMPTY),
                &right.map(|r| r.hash).unwrap_or(EMPTY),
            ),
            Node::Stem { stem, slots } => stem_hash(
                scheme,
                stem,
                &slots_root(scheme, slots.iter().map(|(i, (h, _))| (*i, h))),
            ),
        }
    }
}

/// One committed entry, as stored and as exported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Column family or reserved namespace.
    pub namespace: String,
    /// Key within the namespace.
    pub key: Vec<u8>,
    /// Value.
    pub value: Vec<u8>,
}

impl Entry {
    /// The entry's tree key.
    pub fn tree_key(&self) -> [u8; 32] {
        tree_key(&self.namespace, &self.key)
    }
}

fn path_key(version: u64, depth: usize, path: &Stem) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 8 + 1 + depth.div_ceil(8));
    k.push(b'N');
    k.extend_from_slice(&version.to_be_bytes());
    k.push(depth as u8);
    let bytes = depth.div_ceil(8);
    let mut prefix = path[..bytes].to_vec();
    if !depth.is_multiple_of(8) {
        let keep = depth % 8;
        prefix[bytes - 1] &= 0xFFu8 << (8 - keep);
    }
    k.extend_from_slice(&prefix);
    k
}

fn value_key(tree_key: &[u8; 32], version: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + 32 + 8);
    k.push(b'V');
    k.extend_from_slice(tree_key);
    k.extend_from_slice(&version.to_be_bytes());
    k
}

fn root_key(version: u64) -> Vec<u8> {
    let mut k = Vec::with_capacity(9);
    k.push(b'R');
    k.extend_from_slice(&version.to_be_bytes());
    k
}

fn stale_key(version: u64, target: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(9 + target.len());
    k.push(b'S');
    k.extend_from_slice(&version.to_be_bytes());
    k.extend_from_slice(target);
    k
}

const LATEST_KEY: &[u8] = b"L";
/// The node hash scheme from each version on: bincode `(version, scheme
/// id)` pairs in version order. Absent, every version is SHA-256.
const SCHEMES_KEY: &[u8] = b"X";

fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    bincode::serialize(v).map_err(|e| StorageError::SerializationError(e.to_string()))
}

fn decode<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T> {
    bincode::deserialize(bytes).map_err(|e| StorageError::DeserializationError(e.to_string()))
}

/// Sets bit `depth` of a path.
fn with_bit(path: &Stem, depth: usize, bit: u8) -> Stem {
    let mut out = *path;
    let mask = 1u8 << (7 - (depth % 8));
    if bit == 1 {
        out[depth / 8] |= mask;
    } else {
        out[depth / 8] &= !mask;
    }
    out
}

/// The incremental state trie over a key-value store.
pub struct StateTrie {
    store: Arc<dyn KvStore>,
    /// Serializes updates; reads need no lock because every version they can
    /// see is immutable.
    write_lock: parking_lot::Mutex<()>,
}

/// Pending writes of one update, visible to the update's own reads.
struct Batch<'a> {
    store: &'a dyn KvStore,
    version: u64,
    /// The node hash scheme of `version`.
    scheme: HashScheme,
    overlay: HashMap<Vec<u8>, Option<Vec<u8>>>,
}

impl<'a> Batch<'a> {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        match self.overlay.get(key) {
            Some(v) => Ok(v.clone()),
            None => self.store.get(CF_STATE_TRIE, key),
        }
    }

    fn put(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.overlay.insert(key, Some(value));
    }

    /// Retires a node or value record written at `written_at`. One written
    /// by this same version is deleted outright, since no retained version
    /// can reach it; an older one is logged stale and kept for the versions
    /// that still reference it.
    fn retire(&mut self, key: Vec<u8>, written_at: u64) {
        if written_at == self.version {
            self.overlay.insert(key, None);
        } else {
            self.overlay
                .insert(stale_key(self.version, &key), Some(Vec::new()));
        }
    }

    fn load(&self, r: &NodeRef, depth: usize, path: &Stem) -> Result<Node> {
        let bytes = self
            .get(&path_key(r.version, depth, path))?
            .ok_or_else(|| {
                StorageError::DatabaseError(format!(
                    "state trie node missing at version {} depth {}",
                    r.version, depth
                ))
            })?;
        decode(&bytes)
    }

    fn write_node(&mut self, node: &Node, depth: usize, path: &Stem) -> Result<NodeRef> {
        let r = NodeRef {
            version: self.version,
            hash: node.hash(self.scheme),
            is_stem: matches!(node, Node::Stem { .. }),
        };
        let bytes = encode(node)?;
        self.put(path_key(self.version, depth, path), bytes);
        Ok(r)
    }

    fn into_ops(self) -> Vec<WriteOp> {
        self.overlay
            .into_iter()
            .map(|(key, value)| match value {
                Some(value) => WriteOp::Put {
                    cf: CF_STATE_TRIE.to_string(),
                    key,
                    value,
                },
                None => WriteOp::Delete {
                    cf: CF_STATE_TRIE.to_string(),
                    key,
                },
            })
            .collect()
    }
}

/// Changes to one stem: slot → new entry, or `None` to clear the slot.
type StemUpdate = BTreeMap<u8, Option<Entry>>;

impl StateTrie {
    /// A trie over `store`.
    pub fn new(store: Arc<dyn KvStore>) -> Self {
        Self {
            store,
            write_lock: parking_lot::Mutex::new(()),
        }
    }

    /// The latest committed version, if any.
    pub fn latest_version(&self) -> Result<Option<u64>> {
        match self.store.get(CF_STATE_TRIE, LATEST_KEY)? {
            Some(b) => {
                let arr: [u8; 8] = b.as_slice().try_into().map_err(|_| {
                    StorageError::DeserializationError("state trie latest version".into())
                })?;
                Ok(Some(u64::from_be_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    fn root_ref(&self, version: u64) -> Result<Option<Option<NodeRef>>> {
        match self.store.get(CF_STATE_TRIE, &root_key(version))? {
            Some(b) => Ok(Some(decode(&b)?)),
            None => Ok(None),
        }
    }

    /// The state root at `version`, or `None` if that version was never
    /// committed or has been pruned.
    pub fn root_at(&self, version: u64) -> Result<Option<Hash>> {
        Ok(self
            .root_ref(version)?
            .map(|r| Hash::new(r.map(|r| r.hash).unwrap_or(EMPTY))))
    }

    /// Commits `writes` as `version` and returns the new root.
    ///
    /// Versions must be committed in increasing order, each extending the one
    /// before it. Committing the same version again applies the writes on top
    /// of it, which is how a snapshot is imported bucket by bucket.
    pub fn commit(&self, version: u64, writes: &capture::Writes) -> Result<Hash> {
        let scheme = self.scheme_at(version)?;
        self.commit_on(scheme, version, writes, None)
    }

    /// The node hash scheme of `version`.
    pub fn scheme_at(&self, version: u64) -> Result<HashScheme> {
        use tenzro_types::hash_scheme::scheme_from;
        Ok(scheme_from(
            version,
            self.schemes()?
                .into_iter()
                .filter_map(|(v, id)| HashScheme::from_id(id).map(|s| (v, s))),
        ))
    }

    fn schemes(&self) -> Result<Vec<(u64, u8)>> {
        match self.store.get(CF_STATE_TRIE, SCHEMES_KEY)? {
            Some(b) => decode(&b),
            None => Ok(Vec::new()),
        }
    }

    /// Re-commits the whole state as `version` under `scheme`, which every
    /// later version keeps until another switch. The state is the latest
    /// version's; the trie is built afresh under the new node hashes, so its
    /// root depends on the state alone. Every earlier node and value record
    /// is logged stale at `version`, so pruning reclaims the old trie once
    /// no retained version reaches it; until then earlier versions keep
    /// their roots and proofs under their own scheme. `version` must follow
    /// the latest; the block's own writes are then committed on top of it.
    pub fn recommit_under(&self, version: u64, scheme: HashScheme) -> Result<Hash> {
        let latest = self
            .latest_version()?
            .ok_or_else(|| StorageError::DatabaseError("no committed state to re-commit".into()))?;
        if version <= latest {
            return Err(StorageError::DatabaseError(format!(
                "a re-commit at {version} must follow the latest version {latest}"
            )));
        }
        let mut writes = capture::Writes::new();
        self.for_each_entry(latest, 0, &[0u8; STEM_LEN], &mut |e| {
            writes.insert((e.namespace, e.key), Some(e.value));
            Ok(())
        })?;
        {
            let _guard = self.write_lock.lock();
            let mut ops = Vec::new();
            for prefix in [b"N".as_slice(), b"V".as_slice()] {
                self.store
                    .scan_prefix_for_each(CF_STATE_TRIE, prefix, &mut |k, _| {
                        ops.push(WriteOp::Put {
                            cf: CF_STATE_TRIE.to_string(),
                            key: stale_key(version, k),
                            value: Vec::new(),
                        });
                        Ok(())
                    })?;
            }
            let mut schemes = self.schemes()?;
            schemes.push((version, scheme.id()));
            ops.push(WriteOp::Put {
                cf: CF_STATE_TRIE.to_string(),
                key: SCHEMES_KEY.to_vec(),
                value: encode(&schemes)?,
            });
            self.store.write_batch_sync(ops)?;
        }
        self.commit_on(scheme, version, &writes, Some(None))
    }

    /// Records that `version` and every later version hash under `scheme`,
    /// on a trie holding no version past `version`: a node restoring a
    /// snapshot taken after a switch commits it under the scheme it was
    /// taken under. A trie already holding `scheme` at `version` is left as
    /// it is.
    pub fn adopt_scheme(&self, version: u64, scheme: HashScheme) -> Result<()> {
        let _guard = self.write_lock.lock();
        if self.scheme_at(version)? == scheme {
            return Ok(());
        }
        if let Some(latest) = self.latest_version()?
            && latest > version
        {
            return Err(StorageError::DatabaseError(format!(
                "a scheme adopted at {version} must not precede the latest version {latest}"
            )));
        }
        let mut schemes = self.schemes()?;
        schemes.push((version, scheme.id()));
        self.store.write_batch_sync(vec![WriteOp::Put {
            cf: CF_STATE_TRIE.to_string(),
            key: SCHEMES_KEY.to_vec(),
            value: encode(&schemes)?,
        }])
    }

    /// [`Self::commit`] on the latest version's root, or on `base` when
    /// given (`Some(None)` is an empty trie).
    fn commit_on(
        &self,
        scheme: HashScheme,
        version: u64,
        writes: &capture::Writes,
        base: Option<Option<NodeRef>>,
    ) -> Result<Hash> {
        let _guard = self.write_lock.lock();
        let latest_base = match self.latest_version()? {
            Some(latest) if latest > version => {
                return Err(StorageError::DatabaseError(format!(
                    "state trie version {version} is behind the latest version {latest}"
                )));
            }
            Some(latest) => self.root_ref(latest)?.ok_or_else(|| {
                StorageError::DatabaseError(format!("state trie root missing at {latest}"))
            })?,
            None => None,
        };
        let base = base.unwrap_or(latest_base);

        let mut by_stem: BTreeMap<Stem, StemUpdate> = BTreeMap::new();
        for ((namespace, key), value) in writes {
            if !is_committed_namespace(namespace) {
                return Err(StorageError::DatabaseError(format!(
                    "namespace {namespace} is not committed"
                )));
            }
            let (stem, slot) = split_tree_key(&tree_key(namespace, key));
            by_stem.entry(stem).or_default().insert(
                slot,
                value.as_ref().map(|v| Entry {
                    namespace: namespace.clone(),
                    key: key.clone(),
                    value: v.clone(),
                }),
            );
        }

        let mut batch = Batch {
            store: self.store.as_ref(),
            version,
            scheme,
            overlay: HashMap::new(),
        };
        let mut root = base;
        for (stem, update) in &by_stem {
            root = self.put_stem(&mut batch, root, 0, &[0u8; STEM_LEN], stem, update)?;
        }
        batch.put(root_key(version), encode(&root)?);
        batch.put(LATEST_KEY.to_vec(), version.to_be_bytes().to_vec());
        self.store.write_batch_sync(batch.into_ops())?;
        Ok(Hash::new(root.map(|r| r.hash).unwrap_or(EMPTY)))
    }

    fn apply_slots(
        batch: &mut Batch<'_>,
        stem: &Stem,
        slots: &mut BTreeMap<u8, ([u8; 32], u64)>,
        update: &StemUpdate,
    ) -> Result<()> {
        for (slot, entry) in update {
            let tk = hashing::join_tree_key(stem, *slot);
            if let Some((_, old_version)) = slots.remove(slot) {
                batch.retire(value_key(&tk, old_version), old_version);
            }
            if let Some(entry) = entry {
                slots.insert(
                    *slot,
                    (leaf_hash(batch.scheme, &entry.value), batch.version),
                );
                let bytes = encode(entry)?;
                batch.put(value_key(&tk, batch.version), bytes);
            }
        }
        Ok(())
    }

    fn put_stem(
        &self,
        batch: &mut Batch<'_>,
        node: Option<NodeRef>,
        depth: usize,
        path: &Stem,
        stem: &Stem,
        update: &StemUpdate,
    ) -> Result<Option<NodeRef>> {
        let Some(r) = node else {
            let mut slots = BTreeMap::new();
            Self::apply_slots(batch, stem, &mut slots, update)?;
            if slots.is_empty() {
                return Ok(None);
            }
            let node = Node::Stem { stem: *stem, slots };
            return Ok(Some(batch.write_node(&node, depth, path)?));
        };

        match batch.load(&r, depth, path)? {
            Node::Stem {
                stem: existing,
                mut slots,
            } => {
                if existing == *stem {
                    batch.retire(path_key(r.version, depth, path), r.version);
                    Self::apply_slots(batch, stem, &mut slots, update)?;
                    if slots.is_empty() {
                        return Ok(None);
                    }
                    let node = Node::Stem { stem: *stem, slots };
                    return Ok(Some(batch.write_node(&node, depth, path)?));
                }
                // A different stem holds this position. Clearing slots of an
                // absent stem changes nothing.
                if update.values().all(Option::is_none) {
                    return Ok(Some(r));
                }
                batch.retire(path_key(r.version, depth, path), r.version);
                let mut new_slots = BTreeMap::new();
                Self::apply_slots(batch, stem, &mut new_slots, update)?;
                let moved = Node::Stem {
                    stem: existing,
                    slots,
                };
                let added = Node::Stem {
                    stem: *stem,
                    slots: new_slots,
                };
                Ok(Some(self.split(batch, depth, path, moved, added)?))
            }
            Node::Internal { left, right } => {
                batch.retire(path_key(r.version, depth, path), r.version);
                let bit = stem_bit(stem, depth);
                let child_path = with_bit(path, depth, bit);
                let (target, other) = if bit == 0 {
                    (left, right)
                } else {
                    (right, left)
                };
                let new_child =
                    self.put_stem(batch, target, depth + 1, &child_path, stem, update)?;
                let other_path = with_bit(path, depth, 1 - bit);
                match (new_child, other) {
                    (None, None) => Ok(None),
                    (Some(only), None) if only.is_stem => Ok(Some(self.lift_stem(
                        batch,
                        only,
                        depth,
                        path,
                        &child_path,
                    )?)),
                    (None, Some(only)) if only.is_stem => Ok(Some(self.lift_stem(
                        batch,
                        only,
                        depth,
                        path,
                        &other_path,
                    )?)),
                    (new_child, other) => {
                        let (left, right) = if bit == 0 {
                            (new_child, other)
                        } else {
                            (other, new_child)
                        };
                        let node = Node::Internal { left, right };
                        Ok(Some(batch.write_node(&node, depth, path)?))
                    }
                }
            }
        }
    }

    /// Moves a stem node from `depth + 1` up to `depth`, where it is now alone.
    fn lift_stem(
        &self,
        batch: &mut Batch<'_>,
        r: NodeRef,
        depth: usize,
        path: &Stem,
        from_path: &Stem,
    ) -> Result<NodeRef> {
        let node = batch.load(&r, depth + 1, from_path)?;
        batch.retire(path_key(r.version, depth + 1, from_path), r.version);
        batch.write_node(&node, depth, path)
    }

    /// Places two stem nodes under a fresh subtree at `depth`.
    fn split(
        &self,
        batch: &mut Batch<'_>,
        depth: usize,
        path: &Stem,
        a: Node,
        b: Node,
    ) -> Result<NodeRef> {
        let (sa, sb) = match (&a, &b) {
            (Node::Stem { stem: sa, .. }, Node::Stem { stem: sb, .. }) => (*sa, *sb),
            _ => unreachable!("split places stem nodes"),
        };
        if depth >= STEM_BITS {
            return Err(StorageError::DatabaseError(
                "state trie split past the stem length".into(),
            ));
        }
        let bit_a = stem_bit(&sa, depth);
        let bit_b = stem_bit(&sb, depth);
        let node = if bit_a == bit_b {
            let child_path = with_bit(path, depth, bit_a);
            let child = self.split(batch, depth + 1, &child_path, a, b)?;
            if bit_a == 0 {
                Node::Internal {
                    left: Some(child),
                    right: None,
                }
            } else {
                Node::Internal {
                    left: None,
                    right: Some(child),
                }
            }
        } else {
            let ra = batch.write_node(&a, depth + 1, &with_bit(path, depth, bit_a))?;
            let rb = batch.write_node(&b, depth + 1, &with_bit(path, depth, bit_b))?;
            if bit_a == 0 {
                Node::Internal {
                    left: Some(ra),
                    right: Some(rb),
                }
            } else {
                Node::Internal {
                    left: Some(rb),
                    right: Some(ra),
                }
            }
        };
        batch.write_node(&node, depth, path)
    }

    fn read_node(&self, r: &NodeRef, depth: usize, path: &Stem) -> Result<Node> {
        let bytes = self
            .store
            .get(CF_STATE_TRIE, &path_key(r.version, depth, path))?
            .ok_or_else(|| {
                StorageError::DatabaseError(format!(
                    "state trie node missing at version {} depth {}",
                    r.version, depth
                ))
            })?;
        decode(&bytes)
    }

    fn read_value(&self, tree_key: &[u8; 32], version: u64) -> Result<Entry> {
        let bytes = self
            .store
            .get(CF_STATE_TRIE, &value_key(tree_key, version))?
            .ok_or_else(|| StorageError::DatabaseError("state trie value missing".into()))?;
        decode(&bytes)
    }

    /// The value of `(namespace, key)` at `version` together with a proof of
    /// it (or of its absence) under that version's root.
    pub fn prove(
        &self,
        version: u64,
        namespace: &str,
        key: &[u8],
    ) -> Result<(Option<Vec<u8>>, StateProof)> {
        let scheme = self.scheme_at(version)?;
        self.prove_under(scheme, version, namespace, key)
    }

    fn prove_under(
        &self,
        scheme: HashScheme,
        version: u64,
        namespace: &str,
        key: &[u8],
    ) -> Result<(Option<Vec<u8>>, StateProof)> {
        let root = self.root_ref(version)?.ok_or_else(|| {
            StorageError::DatabaseError(format!("no state root at version {version}"))
        })?;
        let (stem, slot) = split_tree_key(&tree_key(namespace, key));
        let mut siblings = Vec::new();
        let mut path = [0u8; STEM_LEN];
        let mut node = root;
        let mut depth = 0usize;
        loop {
            let Some(r) = node else {
                return Ok((
                    None,
                    StateProof {
                        siblings,
                        terminal: ProofTerminal::Empty,
                    },
                ));
            };
            match self.read_node(&r, depth, &path)? {
                Node::Stem { stem: found, slots } => {
                    if found != stem {
                        let slots_root =
                            slots_root(scheme, slots.iter().map(|(i, (h, _))| (*i, h)));
                        return Ok((
                            None,
                            StateProof {
                                siblings,
                                terminal: ProofTerminal::OtherStem {
                                    stem: found,
                                    slots_root,
                                },
                            },
                        ));
                    }
                    let value = match slots.get(&slot) {
                        Some((_, written_at)) => Some(
                            self.read_value(&hashing::join_tree_key(&stem, slot), *written_at)?
                                .value,
                        ),
                        None => None,
                    };
                    let slot_siblings =
                        slot_siblings(scheme, slots.iter().map(|(i, (h, _))| (*i, h)), slot);
                    return Ok((
                        value,
                        StateProof {
                            siblings,
                            terminal: ProofTerminal::Stem { slot_siblings },
                        },
                    ));
                }
                Node::Internal { left, right } => {
                    let bit = stem_bit(&stem, depth);
                    let (next, other) = if bit == 0 {
                        (left, right)
                    } else {
                        (right, left)
                    };
                    siblings.push(other.map(|o| o.hash).unwrap_or(EMPTY));
                    path = with_bit(&path, depth, bit);
                    node = next;
                    depth += 1;
                }
            }
        }
    }

    /// The value of `(namespace, key)` at `version`.
    pub fn get(&self, version: u64, namespace: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self.prove(version, namespace, key)?.0)
    }

    /// Deletes every node, value and root no version at or after `keep_from`
    /// can reach. Returns how many records were removed.
    pub fn prune(&self, keep_from: u64) -> Result<usize> {
        let _guard = self.write_lock.lock();
        let mut ops = Vec::new();
        let mut stop = false;
        self.store
            .scan_prefix_for_each(CF_STATE_TRIE, b"S", &mut |k, _| {
                if stop {
                    return Ok(());
                }
                let version = u64::from_be_bytes(k[1..9].try_into().expect("stale key version"));
                if version > keep_from {
                    stop = true;
                    return Ok(());
                }
                ops.push(WriteOp::Delete {
                    cf: CF_STATE_TRIE.to_string(),
                    key: k[9..].to_vec(),
                });
                ops.push(WriteOp::Delete {
                    cf: CF_STATE_TRIE.to_string(),
                    key: k.to_vec(),
                });
                Ok(())
            })?;
        self.store
            .scan_prefix_for_each(CF_STATE_TRIE, b"R", &mut |k, _| {
                let version = u64::from_be_bytes(k[1..9].try_into().expect("root key version"));
                if version < keep_from {
                    ops.push(WriteOp::Delete {
                        cf: CF_STATE_TRIE.to_string(),
                        key: k.to_vec(),
                    });
                }
                Ok(())
            })?;
        let removed = ops.len();
        if !ops.is_empty() {
            self.store.write_batch_sync(ops)?;
        }
        Ok(removed)
    }

    /// Summary of the subtree at `depth` along `prefix` at `version`, as it
    /// combines into the root.
    pub fn subtree(&self, version: u64, depth: usize, prefix: &Stem) -> Result<Subtree> {
        let root = self.root_ref(version)?.ok_or_else(|| {
            StorageError::DatabaseError(format!("no state root at version {version}"))
        })?;
        let mut node = root;
        let mut d = 0usize;
        let mut path = [0u8; STEM_LEN];
        loop {
            let Some(r) = node else {
                return Ok(Subtree::Empty);
            };
            if r.is_stem {
                let Node::Stem { stem, .. } = self.read_node(&r, d, &path)? else {
                    unreachable!("reference marks a stem");
                };
                return Ok(if hashing::shares_prefix(&stem, prefix, depth) {
                    Subtree::Single(r.hash)
                } else {
                    Subtree::Empty
                });
            }
            if d == depth {
                return Ok(Subtree::Multi(r.hash));
            }
            let Node::Internal { left, right } = self.read_node(&r, d, &path)? else {
                unreachable!("reference marks an interior node");
            };
            let bit = stem_bit(prefix, d);
            node = if bit == 0 { left } else { right };
            path = with_bit(&path, d, bit);
            d += 1;
        }
    }

    /// Every entry under `prefix` at `depth`, at `version`, in tree-key order,
    /// passed to `f` one at a time.
    pub fn for_each_entry(
        &self,
        version: u64,
        depth: usize,
        prefix: &Stem,
        f: &mut dyn FnMut(Entry) -> Result<()>,
    ) -> Result<()> {
        let root = self.root_ref(version)?.ok_or_else(|| {
            StorageError::DatabaseError(format!("no state root at version {version}"))
        })?;
        self.walk(root, 0, [0u8; STEM_LEN], depth, prefix, f)
    }

    fn walk(
        &self,
        node: Option<NodeRef>,
        d: usize,
        path: Stem,
        depth: usize,
        prefix: &Stem,
        f: &mut dyn FnMut(Entry) -> Result<()>,
    ) -> Result<()> {
        let Some(r) = node else {
            return Ok(());
        };
        match self.read_node(&r, d, &path)? {
            Node::Stem { stem, slots } => {
                if !hashing::shares_prefix(&stem, prefix, depth) {
                    return Ok(());
                }
                for (slot, (_, written_at)) in slots {
                    f(self.read_value(&hashing::join_tree_key(&stem, slot), written_at)?)?;
                }
                Ok(())
            }
            Node::Internal { left, right } => {
                if d < depth {
                    let bit = stem_bit(prefix, d);
                    let next = if bit == 0 { left } else { right };
                    self.walk(next, d + 1, with_bit(&path, d, bit), depth, prefix, f)
                } else {
                    self.walk(left, d + 1, with_bit(&path, d, 0), depth, prefix, f)?;
                    self.walk(right, d + 1, with_bit(&path, d, 1), depth, prefix, f)
                }
            }
        }
    }
}

/// Recomputes, from scratch, the root under `scheme` of a trie holding
/// exactly `entries`. Independent of [`StateTrie`]'s incremental update, so
/// each can check the other.
pub fn root_of_entries<'a>(
    scheme: HashScheme,
    entries: impl IntoIterator<Item = &'a Entry>,
) -> Hash {
    let mut stems: BTreeMap<Stem, BTreeMap<u8, [u8; 32]>> = BTreeMap::new();
    for e in entries {
        let (stem, slot) = split_tree_key(&e.tree_key());
        stems
            .entry(stem)
            .or_default()
            .insert(slot, leaf_hash(scheme, &e.value));
    }
    let list: Vec<(Stem, [u8; 32])> = stems
        .into_iter()
        .map(|(stem, slots)| (stem, slots_root(scheme, slots.iter().map(|(i, h)| (*i, h)))))
        .collect();
    Hash::new(hashing::build_subtree(scheme, 0, &list).hash())
}

#[cfg(test)]
mod tests;
