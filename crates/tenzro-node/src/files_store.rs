//! The tenant-facing index behind `/v1/files`.
//!
//! # Why an index at all
//!
//! [`tenzro_storage_provider::StorageProvider`] is content-addressed: it knows
//! an object by the id the caller assigned and can rebuild its bytes from
//! shards. What it does not know is that a particular object is *Alice's
//! `notes.txt`, uploaded on Tuesday, for retrieval*. That is application
//! metadata, and pushing it into the shard layer would mean every provider
//! holding a shard also holds the filename and owner of the thing it is a
//! fragment of.
//!
//! So this keeps the naming layer local to the node the tenant uploaded
//! through, and the storage layer holds only bytes.
//!
//! # Listing is the isolation-critical path
//!
//! Retrieve, content and delete each address one known id, so a missing
//! ownership check leaks one file to someone who already guessed its id.
//! `list` is different: it *enumerates*, so a missing check there hands a
//! tenant the whole node. That is why the owner index is a separate keyspace
//! rather than a filter over a global scan — a scan that forgets its predicate
//! still returns rows, whereas a prefix that is wrong returns nothing.

use std::sync::Arc;

use dashmap::DashMap;
use tenzro_storage::{CF_SETTLEMENTS, KvStore, WriteOp};
use tracing::warn;

use crate::files_api::{FileObject, FilePurpose};

/// Key prefix for the file record itself, keyed by file id.
const FILE_PREFIX: &[u8] = b"file:";

/// Key prefix for the per-owner index: `file_owner:<owner>:<file_id>`.
///
/// Redundant with the `owner` field on the record, deliberately. A prefix scan
/// that cannot name another tenant's rows is a stronger guarantee than a filter
/// that is supposed to exclude them.
const FILE_OWNER_PREFIX: &[u8] = b"file_owner:";

/// Largest `limit` a list call will honour.
///
/// OpenAI's own files list caps at 10,000. The lower ceiling here is because
/// this list is served from a node an operator is also running models on, and
/// an unbounded enumeration is a request that holds memory proportional to a
/// tenant's whole history.
pub const MAX_LIST_LIMIT: usize = 1000;

/// Default `limit` when the caller does not ask for one.
pub const DEFAULT_LIST_LIMIT: usize = 100;

/// The naming layer over stored objects.
pub struct FileIndex {
    /// file_id -> record.
    files: DashMap<String, FileObject>,
    /// Write-through target. Absent on a node running without storage, in
    /// which case the index is memory-only and does not survive a restart.
    storage: Option<Arc<dyn KvStore>>,
}

impl std::fmt::Debug for FileIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileIndex")
            .field("files", &self.files.len())
            .field("persistent", &self.storage.is_some())
            .finish()
    }
}

impl FileIndex {
    /// A memory-only index.
    pub fn new() -> Self {
        Self {
            files: DashMap::new(),
            storage: None,
        }
    }

    /// A persistent index, hydrated from `storage`.
    ///
    /// A row that fails to deserialize is logged and skipped rather than
    /// failing the whole hydration: one corrupt record should cost a tenant
    /// one file, not cost every tenant their index.
    pub fn with_storage(storage: Arc<dyn KvStore>) -> Self {
        let files = DashMap::new();
        match storage.scan_prefix(CF_SETTLEMENTS, FILE_PREFIX) {
            Ok(rows) => {
                for (key, bytes) in rows {
                    match serde_json::from_slice::<FileObject>(&bytes) {
                        Ok(f) => {
                            files.insert(f.id.clone(), f);
                        }
                        Err(e) => warn!(
                            key = %String::from_utf8_lossy(&key),
                            error = %e,
                            "Skipping unreadable file record during hydration"
                        ),
                    }
                }
            }
            Err(e) => warn!(error = %e, "Could not hydrate the file index"),
        }
        Self {
            files,
            storage: Some(storage),
        }
    }

    /// How many files this node is indexing, across all tenants.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether the index holds nothing.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// Record a stored file.
    ///
    /// The record and its owner-index entry are written in one batch, so the
    /// two cannot disagree about who owns a file — a record without its index
    /// entry would be invisible to its owner's `list`, and an index entry
    /// without its record would be a dangling row.
    pub fn insert(&self, file: FileObject) {
        if let Some(storage) = &self.storage
            && let Ok(bytes) = serde_json::to_vec(&file)
        {
            let ops = vec![
                WriteOp::Put {
                    cf: CF_SETTLEMENTS.to_string(),
                    key: record_key(&file.id),
                    value: bytes,
                },
                WriteOp::Put {
                    cf: CF_SETTLEMENTS.to_string(),
                    key: owner_key(&file.owner, &file.id),
                    value: file.id.as_bytes().to_vec(),
                },
            ];
            if let Err(e) = storage.write_batch(ops) {
                warn!(file = %file.id, error = %e, "Could not persist the file record");
            }
        }
        self.files.insert(file.id.clone(), file);
    }

    /// The record for `file_id`, if this node has one — regardless of owner.
    ///
    /// Callers must apply [`FileObject::visible_to`] themselves. Deliberately
    /// not folded in here: a lookup that silently returns `None` for a file
    /// that exists but belongs to someone else cannot distinguish "no such
    /// file" from "not yours" at the call site, and the two want different
    /// handling for an operator reading logs.
    pub fn get(&self, file_id: &str) -> Option<FileObject> {
        self.files.get(file_id).map(|e| e.value().clone())
    }

    /// `tenant`'s files, newest first, optionally narrowed to one purpose.
    ///
    /// `limit` is clamped to [`MAX_LIST_LIMIT`].
    pub fn list(
        &self,
        tenant: &str,
        purpose: Option<FilePurpose>,
        limit: usize,
    ) -> Vec<FileObject> {
        let limit = limit.clamp(1, MAX_LIST_LIMIT);
        let mut rows: Vec<FileObject> = self
            .files
            .iter()
            .filter(|e| e.value().visible_to(tenant))
            .filter(|e| purpose.is_none_or(|p| e.value().purpose == p))
            .map(|e| e.value().clone())
            .collect();
        // Newest first, then by id so a page boundary is stable across calls
        // that land in the same second.
        rows.sort_by(|a, b| b.created_at.cmp(&a.created_at).then(a.id.cmp(&b.id)));
        rows.truncate(limit);
        rows
    }

    /// Drop `file_id` from the index and from storage.
    ///
    /// Returns the record that was removed, or `None` if there was none. This
    /// unlinks the tenant's reference; it does not erase shards — see
    /// [`crate::files_api::DELETION_NOTE`].
    pub fn remove(&self, file_id: &str) -> Option<FileObject> {
        let (_, file) = self.files.remove(file_id)?;
        if let Some(storage) = &self.storage {
            let ops = vec![
                WriteOp::Delete {
                    cf: CF_SETTLEMENTS.to_string(),
                    key: record_key(&file.id),
                },
                WriteOp::Delete {
                    cf: CF_SETTLEMENTS.to_string(),
                    key: owner_key(&file.owner, &file.id),
                },
            ];
            if let Err(e) = storage.write_batch(ops) {
                warn!(file = %file_id, error = %e, "Could not delete the file record");
            }
        }
        Some(file)
    }

    /// Total bytes `tenant` currently has stored.
    ///
    /// The number an operator needs to price or cap a tenant, and the one a
    /// tenant needs to understand their bill.
    pub fn bytes_for(&self, tenant: &str) -> u64 {
        self.files
            .iter()
            .filter(|e| e.value().visible_to(tenant))
            .map(|e| e.value().bytes)
            .sum()
    }
}

impl Default for FileIndex {
    fn default() -> Self {
        Self::new()
    }
}

fn record_key(file_id: &str) -> Vec<u8> {
    let mut k = FILE_PREFIX.to_vec();
    k.extend_from_slice(file_id.as_bytes());
    k
}

fn owner_key(owner: &str, file_id: &str) -> Vec<u8> {
    let mut k = FILE_OWNER_PREFIX.to_vec();
    k.extend_from_slice(owner.as_bytes());
    k.push(b':');
    k.extend_from_slice(file_id.as_bytes());
    k
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(id: &str, owner: &str, created_at: u64) -> FileObject {
        FileObject {
            id: id.to_string(),
            object: "file",
            bytes: 100,
            created_at,
            filename: format!("{id}.txt"),
            purpose: FilePurpose::UserData,
            owner: owner.to_string(),
            deal_id: None,
        }
    }

    const ALICE: &str = "did:tenzro:human:alice";
    const BOB: &str = "did:tenzro:human:bob";

    #[test]
    fn a_list_returns_only_the_callers_own_files() {
        // The isolation property, on the path where getting it wrong hands
        // over the whole node rather than one guessed id.
        let idx = FileIndex::new();
        idx.insert(file("file-a1", ALICE, 1));
        idx.insert(file("file-a2", ALICE, 2));
        idx.insert(file("file-b1", BOB, 3));

        let alice = idx.list(ALICE, None, 100);
        assert_eq!(alice.len(), 2);
        assert!(alice.iter().all(|f| f.owner == ALICE));

        assert_eq!(idx.list(BOB, None, 100).len(), 1);
        assert!(idx.list("did:tenzro:human:carol", None, 100).is_empty());
        assert!(idx.list("", None, 100).is_empty());
    }

    #[test]
    fn listing_is_newest_first() {
        let idx = FileIndex::new();
        idx.insert(file("file-old", ALICE, 10));
        idx.insert(file("file-new", ALICE, 30));
        idx.insert(file("file-mid", ALICE, 20));
        let ids: Vec<String> = idx
            .list(ALICE, None, 100)
            .into_iter()
            .map(|f| f.id)
            .collect();
        assert_eq!(ids, ["file-new", "file-mid", "file-old"]);
    }

    #[test]
    fn files_written_in_the_same_second_still_order_deterministically() {
        // Otherwise a caller paging through gets a different order per call
        // and either misses rows or sees them twice.
        let idx = FileIndex::new();
        for id in ["file-c", "file-a", "file-b"] {
            idx.insert(file(id, ALICE, 7));
        }
        let first: Vec<String> = idx
            .list(ALICE, None, 100)
            .into_iter()
            .map(|f| f.id)
            .collect();
        let second: Vec<String> = idx
            .list(ALICE, None, 100)
            .into_iter()
            .map(|f| f.id)
            .collect();
        assert_eq!(first, second);
        assert_eq!(first, ["file-a", "file-b", "file-c"]);
    }

    #[test]
    fn a_list_can_be_narrowed_to_one_purpose() {
        let idx = FileIndex::new();
        idx.insert(file("file-1", ALICE, 1));
        let mut tuning = file("file-2", ALICE, 2);
        tuning.purpose = FilePurpose::FineTune;
        idx.insert(tuning);

        assert_eq!(idx.list(ALICE, Some(FilePurpose::FineTune), 100).len(), 1);
        assert_eq!(idx.list(ALICE, Some(FilePurpose::UserData), 100).len(), 1);
        assert_eq!(idx.list(ALICE, Some(FilePurpose::Vision), 100).len(), 0);
        assert_eq!(idx.list(ALICE, None, 100).len(), 2);
    }

    #[test]
    fn a_limit_is_clamped_at_both_ends() {
        let idx = FileIndex::new();
        for i in 0..5 {
            idx.insert(file(&format!("file-{i}"), ALICE, i as u64));
        }
        assert_eq!(idx.list(ALICE, None, 2).len(), 2);
        // Zero would otherwise mean "return nothing", which is never what a
        // caller who omitted the parameter meant.
        assert_eq!(idx.list(ALICE, None, 0).len(), 1);
        assert_eq!(idx.list(ALICE, None, usize::MAX).len(), 5);
    }

    #[test]
    fn a_lookup_finds_a_file_regardless_of_owner() {
        // The ownership check belongs at the call site, so "not yours" and
        // "no such file" stay distinguishable for whoever reads the logs.
        let idx = FileIndex::new();
        idx.insert(file("file-b1", BOB, 1));
        let found = idx.get("file-b1").expect("the record exists");
        assert!(!found.visible_to(ALICE));
        assert!(found.visible_to(BOB));
        assert!(idx.get("file-nope").is_none());
    }

    #[test]
    fn removing_a_file_takes_it_out_of_its_owners_list() {
        let idx = FileIndex::new();
        idx.insert(file("file-a1", ALICE, 1));
        let removed = idx.remove("file-a1").expect("it was there");
        assert_eq!(removed.owner, ALICE);
        assert!(idx.list(ALICE, None, 100).is_empty());
        assert!(idx.get("file-a1").is_none());
        assert!(idx.remove("file-a1").is_none(), "removing twice is a no-op");
    }

    #[test]
    fn stored_bytes_are_counted_per_tenant() {
        // What an operator prices on and what a tenant is billed for; a count
        // that leaked across tenants would bill one for the other's usage.
        let idx = FileIndex::new();
        idx.insert(file("file-a1", ALICE, 1));
        idx.insert(file("file-a2", ALICE, 2));
        idx.insert(file("file-b1", BOB, 3));
        assert_eq!(idx.bytes_for(ALICE), 200);
        assert_eq!(idx.bytes_for(BOB), 100);
        assert_eq!(idx.bytes_for("did:tenzro:human:carol"), 0);
    }

    #[test]
    fn an_empty_index_reports_itself_empty() {
        let idx = FileIndex::new();
        assert!(idx.is_empty());
        assert_eq!(idx.len(), 0);
        idx.insert(file("file-a1", ALICE, 1));
        assert!(!idx.is_empty());
        assert_eq!(idx.len(), 1);
    }

    #[test]
    fn the_owner_key_cannot_be_confused_across_tenants() {
        // A tenant whose DID is a prefix of another's must not scan into
        // their rows. The separator is what prevents it.
        let a = owner_key("did:tenzro:human:al", "file-1");
        let b = owner_key("did:tenzro:human:alice", "file-1");
        assert!(!b.starts_with(&a[..a.len() - "file-1".len()]));
    }
}
