//! A verified backup of the device-key directory.
//!
//! The directory holds the key blobs this machine's TPM or Secure Enclave
//! wrapped. A blob opens only inside the chip that made it, so a copy is
//! ciphertext to everyone else and can be kept anywhere; but without the
//! blobs the chip cannot load its keys again, and every key delegated from
//! them is orphaned. A backup therefore protects against losing the disk
//! while the hardware survives. It does not move a key to other hardware and
//! does not help when the chip itself is lost.
//!
//! A [`Backup`] is one file: every regular file under the directory with its
//! SHA-256, and a digest over all of them that is checked on reading.
//! [`Backup::restore_into`] writes them back, never over a different file,
//! and [`Backup::differences`] says how a directory differs from a backup,
//! so a backup can be checked right after it is made and before it is
//! needed.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const MAGIC: &[u8; 8] = b"TZDKBAK1";
const DIGEST_DOMAIN: &[u8] = b"tenzro/device-key-backup/v1";
/// Largest file a backup takes: a key blob is a few kilobytes.
const MAX_FILE_LEN: u64 = 1 << 20;

/// Why a backup could not be made, read or restored.
#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("{0}: {1}")]
    Io(PathBuf, std::io::Error),
    #[error("{0} is {1} bytes; a device-key directory holds no file that large")]
    TooLarge(PathBuf, u64),
    #[error("the backup is not a device-key backup, or is damaged: {0}")]
    Malformed(&'static str),
    #[error("{0} already exists with other content; a restore never replaces a file")]
    Conflict(PathBuf),
}

type Result<T> = std::result::Result<T, BackupError>;

/// The files of a device-key directory, by path relative to it with `/`
/// between components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backup {
    /// When it was made, in milliseconds since the Unix epoch.
    pub created_at_ms: u64,
    files: BTreeMap<String, Vec<u8>>,
}

/// How a directory differs from a backup.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Differences {
    /// In the backup, absent from the directory.
    pub missing: Vec<String>,
    /// In both, with other content.
    pub changed: Vec<String>,
    /// In the directory, absent from the backup.
    pub extra: Vec<String>,
}

impl Differences {
    /// Whether the directory holds exactly the backup's files.
    pub fn none(&self) -> bool {
        self.missing.is_empty() && self.changed.is_empty() && self.extra.is_empty()
    }
}

/// A file a writer has not finished: `write_new` leaves `*.partial.<pid>.<n>`
/// while it writes, and those are never part of the directory's state.
fn unfinished(name: &str) -> bool {
    name.contains(".partial.") || name.ends_with(".tmp")
}

fn collect(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) -> Result<()> {
    let io = |e| BackupError::Io(dir.to_path_buf(), e);
    for entry in std::fs::read_dir(dir).map_err(io)? {
        let entry = entry.map_err(io)?;
        let path = entry.path();
        let kind = entry
            .file_type()
            .map_err(|e| BackupError::Io(path.clone(), e))?;
        if kind.is_dir() {
            collect(root, &path, out)?;
        } else if kind.is_file() {
            if unfinished(&entry.file_name().to_string_lossy()) {
                continue;
            }
            let len = entry
                .metadata()
                .map_err(|e| BackupError::Io(path.clone(), e))?
                .len();
            if len > MAX_FILE_LEN {
                return Err(BackupError::TooLarge(path, len));
            }
            let relative = path
                .strip_prefix(root)
                .expect("walked from root")
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            let bytes = std::fs::read(&path).map_err(|e| BackupError::Io(path.clone(), e))?;
            out.insert(relative, bytes);
        }
    }
    Ok(())
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

impl Backup {
    /// Read every key file under `dir`. A directory that does not exist
    /// holds no keys.
    pub fn of_dir(dir: &Path, created_at_ms: u64) -> Result<Self> {
        let mut files = BTreeMap::new();
        if dir.exists() {
            collect(dir, dir, &mut files)?;
        }
        Ok(Self {
            created_at_ms,
            files,
        })
    }

    /// The paths in the backup, in order.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.files.keys().map(String::as_str)
    }

    /// How many files it holds.
    pub fn len(&self) -> usize {
        self.files.len()
    }

    /// Whether it holds no file.
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    fn body(&self) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        out.extend_from_slice(&self.created_at_ms.to_be_bytes());
        out.extend_from_slice(&(self.files.len() as u32).to_be_bytes());
        for (path, bytes) in &self.files {
            put(&mut out, path.as_bytes());
            put(&mut out, bytes);
        }
        out
    }

    /// SHA-256 over the backup's whole content; what [`Self::to_bytes`] ends
    /// with and what an operator notes down beside the file.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DIGEST_DOMAIN);
        h.update(self.body());
        h.finalize().into()
    }

    /// The backup as one file's bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.body();
        out.extend_from_slice(&self.digest());
        out
    }

    /// Read a backup back, refusing one whose digest does not match its
    /// content or whose paths could leave the directory it is restored into.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let malformed = BackupError::Malformed;
        if bytes.len() < MAGIC.len() + 12 + 32 || &bytes[..MAGIC.len()] != MAGIC {
            return Err(malformed("not a device-key backup"));
        }
        let (body, digest) = bytes.split_at(bytes.len() - 32);
        let mut at = MAGIC.len();
        let mut take = |n: usize| -> Result<&[u8]> {
            let end = at
                .checked_add(n)
                .filter(|e| *e <= body.len())
                .ok_or(malformed("it ends early"))?;
            let slice = &body[at..end];
            at = end;
            Ok(slice)
        };
        let created_at_ms = u64::from_be_bytes(take(8)?.try_into().expect("8 bytes"));
        let count = u32::from_be_bytes(take(4)?.try_into().expect("4 bytes"));
        let mut files = BTreeMap::new();
        for _ in 0..count {
            let len = u32::from_be_bytes(take(4)?.try_into().expect("4 bytes")) as usize;
            let path = String::from_utf8(take(len)?.to_vec())
                .map_err(|_| malformed("a path is not text"))?;
            let len = u32::from_be_bytes(take(4)?.try_into().expect("4 bytes")) as usize;
            let content = take(len)?.to_vec();
            let stays_inside = !path.is_empty()
                && path.split('/').all(|part| {
                    !part.is_empty() && part != "." && part != ".." && !part.contains('\\')
                })
                && !path.contains(':');
            if !stays_inside {
                return Err(malformed("a path would leave the directory"));
            }
            if files.insert(path, content).is_some() {
                return Err(malformed("a path appears twice"));
            }
        }
        if at != body.len() {
            return Err(malformed("it carries bytes after its last file"));
        }
        let backup = Self {
            created_at_ms,
            files,
        };
        if backup.digest().as_slice() != digest {
            return Err(malformed("its digest does not match its content"));
        }
        Ok(backup)
    }

    /// How `dir` differs from this backup.
    pub fn differences(&self, dir: &Path) -> Result<Differences> {
        let present = Self::of_dir(dir, 0)?.files;
        let mut d = Differences::default();
        for (path, bytes) in &self.files {
            match present.get(path) {
                None => d.missing.push(path.clone()),
                Some(found) if found != bytes => d.changed.push(path.clone()),
                Some(_) => {}
            }
        }
        d.extra = present
            .keys()
            .filter(|p| !self.files.contains_key(*p))
            .cloned()
            .collect();
        Ok(d)
    }

    /// Write the backup's files into `dir`, readable by this user only.
    /// A file already there with the same content is left; one with other
    /// content stops the restore before anything is written. Returns how
    /// many files were written.
    pub fn restore_into(&self, dir: &Path) -> Result<usize> {
        let differences = self.differences(dir)?;
        if let Some(path) = differences.changed.first() {
            return Err(BackupError::Conflict(dir.join(path)));
        }
        let mut written = 0;
        for path in &differences.missing {
            let target = path
                .split('/')
                .fold(dir.to_path_buf(), |p, part| p.join(part));
            let parent = target.parent().unwrap_or(dir);
            let mut builder = std::fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
            builder
                .create(parent)
                .map_err(|e| BackupError::Io(parent.to_path_buf(), e))?;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
            let io = |e| BackupError::Io(target.clone(), e);
            let mut file = options.open(&target).map_err(io)?;
            file.write_all(&self.files[path]).map_err(io)?;
            file.sync_all().map_err(io)?;
            written += 1;
        }
        Ok(written)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh directory under the system's temporary one, removed when
    /// dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch() -> Scratch {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "tenzro-dir-backup-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    /// A directory like the one a key holder keeps: one blob per key, some
    /// under a per-label directory, and a file a writer has not finished.
    fn key_dir() -> Scratch {
        let dir = scratch();
        std::fs::write(dir.path().join("aa11.sign.tpmkey"), b"blob one").unwrap();
        std::fs::write(dir.path().join("bb22.agree.tpmkey"), b"blob two").unwrap();
        std::fs::create_dir(dir.path().join("cc33")).unwrap();
        std::fs::write(dir.path().join("cc33").join("signing.blob"), b"blob three").unwrap();
        std::fs::write(dir.path().join("dd44.partial.77.0"), b"half").unwrap();
        dir
    }

    /// The directory is lost; a backup made earlier puts back every key
    /// file, byte for byte, and a second restore changes nothing.
    #[test]
    fn a_lost_directory_comes_back_whole_from_its_backup() {
        let dir = key_dir();
        let backup = Backup::of_dir(dir.path(), 7).unwrap();
        assert_eq!(
            backup.paths().collect::<Vec<_>>(),
            ["aa11.sign.tpmkey", "bb22.agree.tpmkey", "cc33/signing.blob"]
        );
        assert!(backup.differences(dir.path()).unwrap().none());
        let stored = backup.to_bytes();

        let restored_to = scratch();
        let target = restored_to.path().join("device-keys");
        let read = Backup::from_bytes(&stored).unwrap();
        assert_eq!(read, backup);
        assert_eq!(
            read.differences(&target).unwrap().missing.len(),
            3,
            "a lost directory misses every file"
        );
        assert_eq!(read.restore_into(&target).unwrap(), 3);
        assert!(read.differences(&target).unwrap().none());
        assert_eq!(
            std::fs::read(target.join("cc33").join("signing.blob")).unwrap(),
            b"blob three"
        );
        assert_eq!(read.restore_into(&target).unwrap(), 0);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode(&target.join("aa11.sign.tpmkey")), 0o600);
            assert_eq!(mode(&target.join("cc33")), 0o700);
        }
    }

    #[test]
    fn a_restore_never_replaces_a_key_file_that_differs() {
        let dir = key_dir();
        let backup = Backup::of_dir(dir.path(), 7).unwrap();
        // The key was made again since: the directory holds another blob.
        std::fs::write(dir.path().join("aa11.sign.tpmkey"), b"a newer blob").unwrap();
        std::fs::remove_file(dir.path().join("bb22.agree.tpmkey")).unwrap();
        std::fs::write(dir.path().join("ee55.sign.tpmkey"), b"made later").unwrap();
        let d = backup.differences(dir.path()).unwrap();
        assert_eq!(d.changed, ["aa11.sign.tpmkey"]);
        assert_eq!(d.missing, ["bb22.agree.tpmkey"]);
        assert_eq!(d.extra, ["ee55.sign.tpmkey"]);
        assert!(matches!(
            backup.restore_into(dir.path()),
            Err(BackupError::Conflict(_))
        ));
        assert!(
            !dir.path().join("bb22.agree.tpmkey").exists(),
            "nothing is written when the restore stops"
        );
        assert_eq!(
            std::fs::read(dir.path().join("aa11.sign.tpmkey")).unwrap(),
            b"a newer blob"
        );
    }

    #[test]
    fn a_damaged_or_hostile_backup_is_refused() {
        let backup = Backup::of_dir(key_dir().path(), 7).unwrap();
        let good = backup.to_bytes();
        assert!(Backup::from_bytes(&good).is_ok());

        let mut flipped = good.clone();
        flipped[MAGIC.len() + 20] ^= 1;
        assert!(Backup::from_bytes(&flipped).is_err());
        assert!(Backup::from_bytes(&good[..good.len() - 1]).is_err());
        assert!(Backup::from_bytes(b"not a backup").is_err());

        // A path that climbs out of the directory, under a digest that
        // matches it.
        for path in ["../escape", "/abs", "a//b", "a/./b", "c:\\x", ""] {
            let hostile = Backup {
                created_at_ms: 7,
                files: BTreeMap::from([(path.to_string(), b"x".to_vec())]),
            };
            assert!(
                Backup::from_bytes(&hostile.to_bytes()).is_err(),
                "{path:?} was accepted"
            );
        }
    }

    #[test]
    fn a_directory_that_does_not_exist_holds_no_keys() {
        let dir = scratch();
        let backup = Backup::of_dir(&dir.path().join("absent"), 1).unwrap();
        assert!(backup.is_empty());
        assert_eq!(Backup::from_bytes(&backup.to_bytes()).unwrap().len(), 0);
    }
}
