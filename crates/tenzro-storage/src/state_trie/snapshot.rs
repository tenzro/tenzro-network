//! Splitting the committed state into independently verifiable buckets.
//!
//! The trie is cut at depth [`BUCKET_DEPTH`] into `2^BUCKET_DEPTH` buckets,
//! each the set of entries whose stem begins with the bucket's index. A
//! manifest lists the summary ([`Subtree`]) of every non-empty bucket. Two
//! checks then make a snapshot trustworthy given only a trusted state root:
//!
//! 1. [`root_from_buckets`] folds the manifest's summaries into a root, which
//!    must equal the trusted root. This authenticates every summary.
//! 2. [`verify_bucket`] rebuilds one bucket's summary from its entries, which
//!    must equal the manifest's. This authenticates the bucket's contents.
//!
//! Each bucket is checked on its own as it arrives, so a joining node never
//! holds more than one bucket, fetches buckets from any peer in any order,
//! and resumes by skipping the buckets it already committed.

use super::hashing::{self, STEM_LEN, Stem, Subtree, combine, leaf_hash, slots_root};
use super::{Entry, NodeRef, StateTrie};
use crate::error::{Result, StorageError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tenzro_types::hash_scheme::HashScheme;
use tenzro_types::primitives::Hash;

/// Depth, in stem bits, at which the trie is cut into buckets.
pub const BUCKET_DEPTH: usize = 12;

/// Number of buckets.
pub const BUCKET_COUNT: u32 = 1 << BUCKET_DEPTH;

/// One non-empty bucket in a manifest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BucketSummary {
    /// Bucket index: the first [`BUCKET_DEPTH`] bits of every stem in it.
    pub index: u32,
    /// How the bucket's subtree combines into the root.
    pub subtree: Subtree,
}

/// The stem prefix of bucket `index`.
pub fn bucket_prefix(index: u32) -> Stem {
    let mut out = [0u8; STEM_LEN];
    let shifted = (index as u64) << (64 - BUCKET_DEPTH);
    out[..8].copy_from_slice(&shifted.to_be_bytes());
    out
}

/// The bucket a stem falls in.
pub fn bucket_of(stem: &Stem) -> u32 {
    let mut head = [0u8; 8];
    head.copy_from_slice(&stem[..8]);
    (u64::from_be_bytes(head) >> (64 - BUCKET_DEPTH)) as u32
}

/// Folds bucket summaries into the state root under the node hash `scheme`
/// of the snapshot's version. Buckets must be listed in strictly increasing
/// index order; unlisted buckets are empty.
pub fn root_from_buckets(scheme: HashScheme, buckets: &[BucketSummary]) -> Result<Hash> {
    let mut level = vec![Subtree::Empty; BUCKET_COUNT as usize];
    let mut last: Option<u32> = None;
    for b in buckets {
        if b.index >= BUCKET_COUNT {
            return Err(StorageError::InvalidSnapshot(format!(
                "bucket index {} out of range",
                b.index
            )));
        }
        if last.is_some_and(|l| l >= b.index) {
            return Err(StorageError::InvalidSnapshot(
                "bucket indexes are not strictly increasing".into(),
            ));
        }
        if b.subtree == Subtree::Empty {
            return Err(StorageError::InvalidSnapshot(format!(
                "bucket {} is listed but empty",
                b.index
            )));
        }
        last = Some(b.index);
        level[b.index as usize] = b.subtree;
    }
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|p| combine(scheme, p[0], p[1]))
            .collect();
    }
    Ok(Hash::new(level[0].hash()))
}

/// Checks that `entries` are exactly the contents of bucket `index` whose
/// summary is `expected`: every entry falls in the bucket, entries are in
/// strictly increasing tree-key order, and they rebuild `expected` under the
/// node hash `scheme` of the snapshot's version.
pub fn verify_bucket(
    scheme: HashScheme,
    index: u32,
    entries: &[Entry],
    expected: &Subtree,
) -> Result<()> {
    let mut stems: BTreeMap<Stem, BTreeMap<u8, [u8; 32]>> = BTreeMap::new();
    let mut last: Option<[u8; 32]> = None;
    for e in entries {
        if !super::is_committed_namespace(&e.namespace) {
            return Err(StorageError::InvalidSnapshot(format!(
                "bucket {index} holds an entry in namespace {} which is not committed",
                e.namespace
            )));
        }
        let tk = e.tree_key();
        if last.is_some_and(|l| l >= tk) {
            return Err(StorageError::InvalidSnapshot(format!(
                "bucket {index} entries are not in strictly increasing tree-key order"
            )));
        }
        last = Some(tk);
        let (stem, slot) = hashing::split_tree_key(&tk);
        if bucket_of(&stem) != index {
            return Err(StorageError::InvalidSnapshot(format!(
                "bucket {index} holds an entry belonging to bucket {}",
                bucket_of(&stem)
            )));
        }
        stems
            .entry(stem)
            .or_default()
            .insert(slot, leaf_hash(scheme, &e.value));
    }
    let list: Vec<(Stem, [u8; 32])> = stems
        .into_iter()
        .map(|(stem, slots)| (stem, slots_root(scheme, slots.iter().map(|(i, h)| (*i, h)))))
        .collect();
    let rebuilt = hashing::build_subtree(scheme, BUCKET_DEPTH, &list);
    if rebuilt != *expected {
        return Err(StorageError::InvalidSnapshot(format!(
            "bucket {index} contents do not match the manifest"
        )));
    }
    Ok(())
}

impl StateTrie {
    /// Summaries of every non-empty bucket at `version`, in index order.
    pub fn bucket_summaries(&self, version: u64) -> Result<Vec<BucketSummary>> {
        let root = self.root_ref(version)?.ok_or_else(|| {
            StorageError::DatabaseError(format!("no state root at version {version}"))
        })?;
        let mut out = Vec::new();
        self.collect_buckets(root, 0, [0u8; STEM_LEN], &mut out)?;
        Ok(out)
    }

    fn collect_buckets(
        &self,
        node: Option<NodeRef>,
        d: usize,
        path: Stem,
        out: &mut Vec<BucketSummary>,
    ) -> Result<()> {
        let Some(r) = node else {
            return Ok(());
        };
        if r.is_stem {
            let super::Node::Stem { stem, .. } = self.read_node(&r, d, &path)? else {
                unreachable!("reference marks a stem");
            };
            out.push(BucketSummary {
                index: bucket_of(&stem),
                subtree: Subtree::Single(r.hash),
            });
            return Ok(());
        }
        if d == BUCKET_DEPTH {
            out.push(BucketSummary {
                index: bucket_of(&path),
                subtree: Subtree::Multi(r.hash),
            });
            return Ok(());
        }
        let super::Node::Internal { left, right } = self.read_node(&r, d, &path)? else {
            unreachable!("reference marks an interior node");
        };
        self.collect_buckets(left, d + 1, super::with_bit(&path, d, 0), out)?;
        self.collect_buckets(right, d + 1, super::with_bit(&path, d, 1), out)
    }

    /// Every entry of bucket `index` at `version`, in tree-key order.
    pub fn bucket_entries(&self, version: u64, index: u32) -> Result<Vec<Entry>> {
        let mut out = Vec::new();
        self.for_each_entry(version, BUCKET_DEPTH, &bucket_prefix(index), &mut |e| {
            out.push(e);
            Ok(())
        })?;
        Ok(out)
    }
}
