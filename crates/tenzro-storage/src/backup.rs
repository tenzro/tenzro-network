//! Point-in-time snapshots of the store, and incremental copies of them.
//!
//! A snapshot is a RocksDB checkpoint: a directory holding the store's
//! manifest and hardlinks to its immutable SST files, taken at a moment the
//! caller chooses. It costs almost nothing on disk while the live store still
//! holds the same files, and the caller keeps only the newest few.
//!
//! An incremental backup copies one snapshot to a destination the operator
//! chooses. SST files are immutable and never renamed, so a file already
//! present in an earlier backup at the destination, by name and size, is
//! hardlinked from there instead of copied: each backup directory is a
//! complete store on its own, and only new files cost I/O. The copy is paced
//! to a byte rate so it never competes with the node's own writes.

use crate::error::{Result, StorageError};
use crate::kv::RocksDbStore;
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// File in a snapshot holding the caller's description of it (for the node,
/// the certificate of the checkpoint the snapshot was taken at).
pub const SNAPSHOT_META: &str = "SNAPSHOT_META";

/// Suffix of a directory still being written. Never listed as a snapshot.
const PARTIAL_SUFFIX: &str = ".partial";

fn io_err(what: &str, path: &Path, e: std::io::Error) -> StorageError {
    StorageError::DatabaseError(format!("{what} {}: {e}", path.display()))
}

/// The snapshots kept under one directory, newest last by name.
#[derive(Debug, Clone)]
pub struct SnapshotDir {
    root: PathBuf,
    keep: usize,
}

impl SnapshotDir {
    /// Snapshots under `root`, keeping the newest `keep` (at least one).
    pub fn new(root: impl Into<PathBuf>, keep: usize) -> Self {
        Self {
            root: root.into(),
            keep: keep.max(1),
        }
    }

    /// Takes a snapshot of `store` named `name`, with `meta` written beside
    /// it, then removes the oldest snapshots beyond the number kept. Names
    /// must sort in the order snapshots are taken. A snapshot that already
    /// exists is left as it is.
    pub fn take(&self, store: &RocksDbStore, name: &str, meta: &[u8]) -> Result<PathBuf> {
        self.take_with(store, name, &mut |out| out.write_all(meta))
    }

    /// As [`Self::take`], with the meta written by `write_meta` straight to
    /// its file, so a large one is never held in memory whole.
    pub fn take_with(
        &self,
        store: &RocksDbStore,
        name: &str,
        write_meta: &mut dyn FnMut(&mut dyn std::io::Write) -> std::io::Result<()>,
    ) -> Result<PathBuf> {
        fs::create_dir_all(&self.root).map_err(|e| io_err("create", &self.root, e))?;
        let dir = self.root.join(name);
        if dir.exists() {
            return Ok(dir);
        }
        let partial = self.root.join(format!("{name}{PARTIAL_SUFFIX}"));
        if partial.exists() {
            fs::remove_dir_all(&partial).map_err(|e| io_err("remove", &partial, e))?;
        }
        store.create_checkpoint(&partial)?;
        let meta_path = partial.join(SNAPSHOT_META);
        let mut file = std::io::BufWriter::new(
            fs::File::create(&meta_path).map_err(|e| io_err("create", &meta_path, e))?,
        );
        write_meta(&mut file)
            .and_then(|()| std::io::Write::flush(&mut file))
            .map_err(|e| io_err("write", &meta_path, e))?;
        // Windows refuses to rename a directory that holds an open file.
        drop(file);
        fs::rename(&partial, &dir).map_err(|e| io_err("rename", &partial, e))?;
        self.trim(self.keep)?;
        Ok(dir)
    }

    /// Every complete snapshot, oldest first.
    pub fn list(&self) -> Result<Vec<PathBuf>> {
        let entries = match fs::read_dir(&self.root) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io_err("read", &self.root, e)),
        };
        let mut out: Vec<PathBuf> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir() && p.join(SNAPSHOT_META).is_file())
            .filter(|p| !p.to_string_lossy().ends_with(PARTIAL_SUFFIX))
            .collect();
        out.sort();
        Ok(out)
    }

    /// The newest complete snapshot.
    pub fn latest(&self) -> Result<Option<PathBuf>> {
        Ok(self.list()?.pop())
    }

    /// Removes every snapshot directory an earlier run left unfinished and
    /// returns the bytes freed.
    pub fn clean_partials(&self) -> Result<u64> {
        let entries = match fs::read_dir(&self.root) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(io_err("read", &self.root, e)),
        };
        let mut freed = 0u64;
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() && path.to_string_lossy().ends_with(PARTIAL_SUFFIX) {
                freed += dir_bytes(&path);
                fs::remove_dir_all(&path).map_err(|e| io_err("remove", &path, e))?;
            }
        }
        Ok(freed)
    }

    /// Removes all but the newest `keep` snapshots (at least one is kept).
    pub fn trim(&self, keep: usize) -> Result<()> {
        let all = self.list()?;
        let excess = all.len().saturating_sub(keep.max(1));
        for old in &all[..excess] {
            fs::remove_dir_all(old).map_err(|e| io_err("remove", old, e))?;
        }
        Ok(())
    }
}

/// The bytes of the files under `dir`, counted without following links.
fn dir_bytes(dir: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(entries) = fs::read_dir(&d) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                stack.push(entry.path());
            } else if let Ok(m) = entry.metadata() {
                total += m.len();
            }
        }
    }
    total
}

/// Reads the description written beside a snapshot.
pub fn read_meta(snapshot: &Path) -> Result<Vec<u8>> {
    let path = snapshot.join(SNAPSHOT_META);
    fs::read(&path).map_err(|e| io_err("read", &path, e))
}

/// What one incremental backup did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BackupReport {
    /// The directory the backup was written to.
    pub dest: PathBuf,
    /// Files copied, because no earlier backup held them.
    pub copied_files: u64,
    /// Bytes copied.
    pub copied_bytes: u64,
    /// SST files hardlinked from an earlier backup instead of copied.
    pub linked_files: u64,
    /// Whether this snapshot was already backed up, so nothing was written.
    pub already_present: bool,
}

/// Copies `snapshot` into `dest_root/<snapshot name>`, hardlinking every SST
/// file an earlier backup under `dest_root` already holds and copying the
/// rest at no more than `bytes_per_sec` (0 for unpaced). The backup appears
/// under its final name only once complete.
pub fn incremental_backup(
    snapshot: &Path,
    dest_root: &Path,
    bytes_per_sec: u64,
) -> Result<BackupReport> {
    let name = snapshot.file_name().ok_or_else(|| {
        StorageError::InvalidValue(format!("{} names no snapshot", snapshot.display()))
    })?;
    if !snapshot.join(SNAPSHOT_META).is_file() {
        return Err(StorageError::InvalidValue(format!(
            "{} is not a complete snapshot",
            snapshot.display()
        )));
    }
    fs::create_dir_all(dest_root).map_err(|e| io_err("create", dest_root, e))?;
    let dest = dest_root.join(name);
    let mut report = BackupReport {
        dest: dest.clone(),
        ..Default::default()
    };
    if dest.join(SNAPSHOT_META).is_file() {
        report.already_present = true;
        return Ok(report);
    }

    // SST files already at the destination, by name, with their size.
    let mut held: HashMap<String, (PathBuf, u64)> = HashMap::new();
    for earlier in SnapshotDir::new(dest_root, usize::MAX).list()? {
        for entry in fs::read_dir(&earlier)
            .map_err(|e| io_err("read", &earlier, e))?
            .flatten()
        {
            let file = entry.file_name().to_string_lossy().into_owned();
            if file.ends_with(".sst")
                && let Ok(m) = entry.metadata()
            {
                held.entry(file).or_insert((entry.path(), m.len()));
            }
        }
    }

    let partial = dest_root.join(format!("{}{PARTIAL_SUFFIX}", name.to_string_lossy()));
    if partial.exists() {
        fs::remove_dir_all(&partial).map_err(|e| io_err("remove", &partial, e))?;
    }
    fs::create_dir_all(&partial).map_err(|e| io_err("create", &partial, e))?;
    let mut pacer = Pacer::new(bytes_per_sec);
    let mut files: Vec<PathBuf> = fs::read_dir(snapshot)
        .map_err(|e| io_err("read", snapshot, e))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    // The description goes last: a backup is complete when it is present.
    files.sort_by_key(|p| p.file_name().is_some_and(|n| n == SNAPSHOT_META));
    for src in files {
        let file = src
            .file_name()
            .expect("listed files have names")
            .to_string_lossy()
            .into_owned();
        let len = fs::metadata(&src)
            .map_err(|e| io_err("stat", &src, e))?
            .len();
        let to = partial.join(&file);
        match held.get(&file) {
            Some((earlier, earlier_len)) if *earlier_len == len && file.ends_with(".sst") => {
                fs::hard_link(earlier, &to).map_err(|e| io_err("link", earlier, e))?;
                report.linked_files += 1;
            }
            _ => {
                copy_paced(&src, &to, &mut pacer)?;
                report.copied_files += 1;
                report.copied_bytes += len;
            }
        }
    }
    fs::rename(&partial, &dest).map_err(|e| io_err("rename", &partial, e))?;
    Ok(report)
}

/// Copies every file of `snapshot` into `db_path`, which must not exist or
/// be empty, so the store can be opened there.
pub fn restore_files(snapshot: &Path, db_path: &Path) -> Result<()> {
    if db_path.exists()
        && fs::read_dir(db_path)
            .map_err(|e| io_err("read", db_path, e))?
            .next()
            .is_some()
    {
        return Err(StorageError::InvalidValue(format!(
            "{} is not empty; restore only into an empty directory",
            db_path.display()
        )));
    }
    fs::create_dir_all(db_path).map_err(|e| io_err("create", db_path, e))?;
    let mut pacer = Pacer::new(0);
    for entry in fs::read_dir(snapshot)
        .map_err(|e| io_err("read", snapshot, e))?
        .flatten()
    {
        let src = entry.path();
        if src.is_file() && entry.file_name() != SNAPSHOT_META {
            copy_paced(&src, &db_path.join(entry.file_name()), &mut pacer)?;
        }
    }
    Ok(())
}

/// Holds a copy to a byte rate.
struct Pacer {
    bytes_per_sec: u64,
    started: Instant,
    sent: u64,
}

impl Pacer {
    fn new(bytes_per_sec: u64) -> Self {
        Self {
            bytes_per_sec,
            started: Instant::now(),
            sent: 0,
        }
    }

    fn account(&mut self, bytes: u64) {
        if self.bytes_per_sec == 0 {
            return;
        }
        self.sent += bytes;
        let due = Duration::from_secs_f64(self.sent as f64 / self.bytes_per_sec as f64);
        if let Some(wait) = due.checked_sub(self.started.elapsed()) {
            std::thread::sleep(wait);
        }
    }
}

fn copy_paced(src: &Path, dst: &Path, pacer: &mut Pacer) -> Result<()> {
    let mut from = fs::File::open(src).map_err(|e| io_err("open", src, e))?;
    let mut to = fs::File::create(dst).map_err(|e| io_err("create", dst, e))?;
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = from.read(&mut buf).map_err(|e| io_err("read", src, e))?;
        if n == 0 {
            break;
        }
        to.write_all(&buf[..n])
            .map_err(|e| io_err("write", dst, e))?;
        pacer.account(n as u64);
    }
    to.sync_all().map_err(|e| io_err("sync", dst, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StorageConfig;
    use crate::kv::{CF_STATE, KvStore};

    fn store(dir: &Path) -> RocksDbStore {
        RocksDbStore::open(&StorageConfig::new(dir.join("db")).with_memory_bytes(8 << 20)).unwrap()
    }

    #[test]
    fn snapshots_rotate_to_the_number_kept() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let snaps = SnapshotDir::new(tmp.path().join("snapshots"), 2);
        for i in 0..4u64 {
            s.put(CF_STATE, &i.to_be_bytes(), b"v").unwrap();
            snaps.take(&s, &format!("epoch-{i:020}"), b"meta").unwrap();
        }
        let kept = snaps.list().unwrap();
        assert_eq!(kept.len(), 2);
        assert!(kept[1].ends_with(format!("epoch-{:020}", 3)));
        assert_eq!(read_meta(&kept[1]).unwrap(), b"meta");
    }

    #[test]
    fn a_backup_copies_only_new_sst_files_and_restores_whole() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let snaps = SnapshotDir::new(tmp.path().join("snapshots"), 4);
        let dest = tmp.path().join("backup");

        s.put(CF_STATE, b"a", &[1u8; 4096]).unwrap();
        s.db()
            .flush_cf(s.db().cf_handle(CF_STATE).unwrap())
            .unwrap();
        let first = snaps.take(&s, "epoch-1", b"one").unwrap();
        let r1 = incremental_backup(&first, &dest, 0).unwrap();
        assert_eq!(r1.linked_files, 0);
        assert!(r1.copied_files > 0);

        s.put(CF_STATE, b"b", &[2u8; 4096]).unwrap();
        s.db()
            .flush_cf(s.db().cf_handle(CF_STATE).unwrap())
            .unwrap();
        let second = snaps.take(&s, "epoch-2", b"two").unwrap();
        let r2 = incremental_backup(&second, &dest, 0).unwrap();
        assert!(
            r2.linked_files >= 1,
            "the first flush's SST is already at the destination"
        );
        let sst_in = |d: &Path| {
            fs::read_dir(d)
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().ends_with(".sst"))
                .count() as u64
        };
        assert_eq!(
            r2.linked_files + 1,
            sst_in(&second),
            "only the new flush's SST is copied"
        );

        assert!(
            incremental_backup(&second, &dest, 0)
                .unwrap()
                .already_present
        );

        let restored = tmp.path().join("restored");
        restore_files(&r2.dest, &restored).unwrap();
        let r = RocksDbStore::open(&StorageConfig::new(restored)).unwrap();
        assert_eq!(r.get(CF_STATE, b"a").unwrap().unwrap(), vec![1u8; 4096]);
        assert_eq!(r.get(CF_STATE, b"b").unwrap().unwrap(), vec![2u8; 4096]);
        assert!(
            restore_files(&r2.dest, &tmp.path().join("snapshots")).is_err(),
            "a non-empty target is refused"
        );
    }
}
