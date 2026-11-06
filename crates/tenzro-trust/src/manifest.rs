//! Content-addressed model manifests.
//!
//! A manifest lists every file of a model (weights, every shard of a split
//! file, tokenizer, chat template, configuration) with its size, SHA-256 and
//! BLAKE3. Its root is a BLAKE3 Merkle tree over those entries, so the model's
//! name on the network, `tenzro:model:<root>`, commits to every byte.
//!
//! The SHA-256 is what the Hugging Face Hub reports per file (the Git LFS
//! object id), so a Hub observation can be compared file by file. The BLAKE3
//! is the blob hash of the storage layer, so the same bytes are fetched from
//! any peer or storage provider and checked chunk by chunk as they stream.

use std::collections::BTreeSet;
use std::io::Read;
use std::path::{Component, Path};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::credential::MODEL_SUBJECT_PREFIX;
use crate::{Result, TrustError, has_type, invalid};

pub const MANIFEST_TYPE: &str = "TenzroModelManifest";
const MAX_FILES: usize = 4096;
const LEAF_TAG: u8 = 0x00;
const NODE_TAG: u8 = 0x01;

/// One file of a model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileEntry {
    /// Relative path with `/` separators.
    pub path: String,
    pub size: u64,
    /// Hex SHA-256.
    pub sha256: String,
    /// Hex BLAKE3.
    pub blake3: String,
}

fn hex32(s: &str) -> Option<[u8; 32]> {
    let v = hex::decode(s).ok()?;
    v.try_into().ok()
}

/// A path is relative, uses `/`, and never climbs out of the model directory.
pub fn normalise_path(path: &str) -> Result<String> {
    if path.is_empty() || path.len() > 512 || path.contains('\\') || path.contains('\0') {
        return Err(invalid(format!("bad path {path:?}")));
    }
    let p = Path::new(path);
    let mut parts = Vec::new();
    for c in p.components() {
        match c {
            Component::Normal(s) => parts.push(
                s.to_str()
                    .ok_or_else(|| invalid("path is not UTF-8"))?
                    .to_string(),
            ),
            _ => {
                return Err(invalid(format!(
                    "path {path:?} must be relative with no . or .. segments"
                )));
            }
        }
    }
    if parts.is_empty() {
        return Err(invalid("empty path"));
    }
    Ok(parts.join("/"))
}

impl FileEntry {
    fn validate(&self) -> Result<()> {
        if normalise_path(&self.path)? != self.path {
            return Err(invalid(format!(
                "path {:?} is not in normal form",
                self.path
            )));
        }
        if hex32(&self.sha256).is_none()
            || hex32(&self.blake3).is_none()
            || self.sha256 != self.sha256.to_lowercase()
            || self.blake3 != self.blake3.to_lowercase()
        {
            return Err(invalid(format!(
                "{}: hashes must be 64-digit lowercase hex",
                self.path
            )));
        }
        Ok(())
    }

    /// Leaf hash: `BLAKE3(0x00 || len(path) || path || size || sha256 || blake3)`.
    pub fn leaf(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(&[LEAF_TAG]);
        h.update(&(self.path.len() as u64).to_le_bytes());
        h.update(self.path.as_bytes());
        h.update(&self.size.to_le_bytes());
        h.update(&hex32(&self.sha256).unwrap_or_default());
        h.update(&hex32(&self.blake3).unwrap_or_default());
        *h.finalize().as_bytes()
    }

    /// The storage address of this file's bytes.
    pub fn blob_uri(&self) -> String {
        format!("tenzro://blob/{}", self.blake3)
    }
}

fn node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&[NODE_TAG]);
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

/// Every level of the tree over `leaves`, bottom first. An odd node at the
/// end of a level is promoted unchanged.
fn levels(leaves: Vec<[u8; 32]>) -> Vec<Vec<[u8; 32]>> {
    let mut out = vec![leaves];
    while out.last().is_some_and(|l| l.len() > 1) {
        let prev = out.last().cloned().unwrap_or_default();
        let next = prev
            .chunks(2)
            .map(|pair| {
                if pair.len() == 2 {
                    node(&pair[0], &pair[1])
                } else {
                    pair[0]
                }
            })
            .collect();
        out.push(next);
    }
    out
}

/// Proof that one file is in a manifest with a given root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub index: usize,
    pub leaf_count: usize,
    /// Hex sibling hashes, bottom first; a level where the node was promoted
    /// contributes none.
    pub siblings: Vec<String>,
}

/// Check that `entry` sits at `proof.index` under `root`.
pub fn verify_inclusion(root_hex: &str, entry: &FileEntry, proof: &InclusionProof) -> bool {
    let Some(root) = hex32(root_hex) else {
        return false;
    };
    if proof.index >= proof.leaf_count {
        return false;
    }
    let mut hash = entry.leaf();
    let (mut idx, mut width) = (proof.index, proof.leaf_count);
    let mut siblings = proof.siblings.iter();
    while width > 1 {
        let sibling = idx ^ 1;
        if sibling < width {
            let Some(s) = siblings.next().and_then(|s| hex32(s)) else {
                return false;
            };
            hash = if idx % 2 == 0 {
                node(&hash, &s)
            } else {
                node(&s, &hash)
            };
        }
        idx /= 2;
        width = width.div_ceil(2);
    }
    siblings.next().is_none() && hash == root
}

/// A model's files, sorted by path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModelManifest {
    /// The name the model is published under (a catalog id or a Hub repo).
    pub name: String,
    pub files: Vec<FileEntry>,
}

impl ModelManifest {
    pub fn new(name: &str, mut files: Vec<FileEntry>) -> Result<Self> {
        if name.is_empty() || name.len() > 256 {
            return Err(invalid("a manifest needs a name of 1-256 characters"));
        }
        if files.is_empty() || files.len() > MAX_FILES {
            return Err(invalid(format!("a manifest lists 1-{MAX_FILES} files")));
        }
        for f in &mut files {
            f.path = normalise_path(&f.path)?;
            f.sha256 = f.sha256.to_lowercase();
            f.blake3 = f.blake3.to_lowercase();
            f.validate()?;
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        let mut seen = BTreeSet::new();
        for f in &files {
            if !seen.insert(f.path.clone()) {
                return Err(invalid(format!("{} is listed twice", f.path)));
            }
        }
        Ok(ModelManifest {
            name: name.to_string(),
            files,
        })
    }

    pub fn root(&self) -> [u8; 32] {
        let lv = levels(self.files.iter().map(FileEntry::leaf).collect());
        lv.last()
            .and_then(|l| l.first().copied())
            .unwrap_or_default()
    }

    pub fn root_hex(&self) -> String {
        hex::encode(self.root())
    }

    /// The credential subject naming this model.
    pub fn subject_id(&self) -> String {
        format!("{MODEL_SUBJECT_PREFIX}{}", self.root_hex())
    }

    pub fn file(&self, path: &str) -> Option<&FileEntry> {
        self.files.iter().find(|f| f.path == path)
    }

    pub fn total_size(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum()
    }

    pub fn inclusion_proof(&self, path: &str) -> Option<InclusionProof> {
        let index = self.files.iter().position(|f| f.path == path)?;
        let lv = levels(self.files.iter().map(FileEntry::leaf).collect());
        let mut siblings = Vec::new();
        let mut idx = index;
        for level in &lv[..lv.len() - 1] {
            let sibling = idx ^ 1;
            if sibling < level.len() {
                siblings.push(hex::encode(level[sibling]));
            }
            idx /= 2;
        }
        Some(InclusionProof {
            index,
            leaf_count: self.files.len(),
            siblings,
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "type": [MANIFEST_TYPE],
            "name": self.name,
            "files": self.files,
            "root": self.root_hex(),
        })
    }

    /// Parse a manifest document. A `root` in the document must match the
    /// files: the root is recomputed, never trusted.
    pub fn from_json(doc: &Value) -> Result<Self> {
        if !has_type(doc, MANIFEST_TYPE) {
            return Err(invalid(format!("not a {MANIFEST_TYPE}")));
        }
        let name = doc.get("name").and_then(Value::as_str).unwrap_or_default();
        let files: Vec<FileEntry> =
            serde_json::from_value(doc.get("files").cloned().unwrap_or(Value::Null))
                .map_err(|e| invalid(format!("files: {e}")))?;
        let m = ModelManifest::new(name, files)?;
        if let Some(claimed) = doc.get("root").and_then(Value::as_str)
            && claimed != m.root_hex()
        {
            return Err(invalid("the stated root does not match the files"));
        }
        Ok(m)
    }
}

/// Size, hex SHA-256 and hex BLAKE3 of a file, read as a stream.
pub fn hash_file(path: &Path) -> Result<(u64, String, String)> {
    let mut f = std::fs::File::open(path)?;
    let mut sha = Sha256::new();
    let mut b3 = blake3::Hasher::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut size = 0u64;
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        sha.update(&buf[..n]);
        b3.update(&buf[..n]);
        size += n as u64;
    }
    Ok((
        size,
        hex::encode(sha.finalize()),
        b3.finalize().to_hex().to_string(),
    ))
}

fn walk(dir: &Path, base: &Path, out: &mut Vec<std::path::PathBuf>) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        let path = entry.path();
        if ft.is_symlink() {
            return Err(invalid(format!(
                "{} is a symlink; a manifest lists real files only",
                path.display()
            )));
        }
        if ft.is_dir() {
            walk(&path, base, out)?;
        } else if ft.is_file() {
            out.push(path);
        }
        if out.len() > MAX_FILES {
            return Err(invalid(format!(
                "more than {MAX_FILES} files under {}",
                base.display()
            )));
        }
    }
    Ok(())
}

fn relative(base: &Path, path: &Path) -> Result<String> {
    let rel = path
        .strip_prefix(base)
        .map_err(|_| invalid("file outside the model directory"))?;
    let parts: Vec<String> = rel
        .components()
        .map(|c| {
            c.as_os_str()
                .to_str()
                .map(str::to_string)
                .ok_or_else(|| invalid("path is not UTF-8"))
        })
        .collect::<Result<_>>()?;
    normalise_path(&parts.join("/"))
}

/// Hash every regular file under `dir` into a manifest named `name`.
pub fn build_from_dir(name: &str, dir: &Path) -> Result<ModelManifest> {
    let mut paths = Vec::new();
    walk(dir, dir, &mut paths)?;
    let mut files = Vec::with_capacity(paths.len());
    for p in paths {
        let (size, sha256, blake3) = hash_file(&p)?;
        files.push(FileEntry {
            path: relative(dir, &p)?,
            size,
            sha256,
            blake3,
        });
    }
    ModelManifest::new(name, files)
}

/// Check one local file against its manifest entry.
pub fn verify_file(entry: &FileEntry, path: &Path) -> Result<()> {
    let mismatch = |reason: String| TrustError::FileMismatch {
        path: entry.path.clone(),
        reason,
    };
    let meta = std::fs::metadata(path).map_err(|e| mismatch(e.to_string()))?;
    if meta.len() != entry.size {
        return Err(mismatch(format!("size {} != {}", meta.len(), entry.size)));
    }
    let (_, sha256, blake3) = hash_file(path)?;
    if sha256 != entry.sha256 {
        return Err(mismatch("SHA-256 differs".into()));
    }
    if blake3 != entry.blake3 {
        return Err(mismatch("BLAKE3 differs".into()));
    }
    Ok(())
}

/// Check every file of `manifest` under `dir`. Extra files are not part of
/// the model and are ignored; a missing or altered file fails.
pub fn verify_dir(manifest: &ModelManifest, dir: &Path) -> Result<()> {
    for entry in &manifest.files {
        verify_file(entry, &dir.join(&entry.path))?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn entry(path: &str, bytes: &[u8]) -> FileEntry {
        FileEntry {
            path: path.into(),
            size: bytes.len() as u64,
            sha256: hex::encode(Sha256::digest(bytes)),
            blake3: blake3::hash(bytes).to_hex().to_string(),
        }
    }

    pub(crate) fn sample(name: &str) -> ModelManifest {
        ModelManifest::new(
            name,
            vec![
                entry("model-00002-of-00002.safetensors", b"shard two"),
                entry("model-00001-of-00002.safetensors", b"shard one"),
                entry("tokenizer.json", b"{}"),
                entry("config.json", b"{\"a\":1}"),
                entry("chat_template.jinja", b"{{ messages }}"),
            ],
        )
        .unwrap()
    }

    #[test]
    fn the_root_does_not_depend_on_listing_order() {
        let a = sample("m");
        let mut files = a.files.clone();
        files.reverse();
        assert_eq!(ModelManifest::new("m", files).unwrap().root(), a.root());
    }

    #[test]
    fn changing_any_byte_of_any_file_changes_the_root() {
        let a = sample("m");
        let mut files = a.files.clone();
        files[4] = entry(&files[4].path.clone(), b"shard twO");
        assert_ne!(ModelManifest::new("m", files).unwrap().root(), a.root());
    }

    #[test]
    fn every_file_has_an_inclusion_proof_and_a_wrong_file_fails_it() {
        for n in 1..=9 {
            let files: Vec<FileEntry> = (0..n)
                .map(|i| entry(&format!("f{i}"), format!("bytes {i}").as_bytes()))
                .collect();
            let m = ModelManifest::new("m", files).unwrap();
            for f in &m.files {
                let p = m.inclusion_proof(&f.path).unwrap();
                assert!(verify_inclusion(&m.root_hex(), f, &p), "n={n} {}", f.path);
                let forged = entry(&f.path, b"tampered");
                assert!(!verify_inclusion(&m.root_hex(), &forged, &p));
            }
        }
    }

    #[test]
    fn paths_that_escape_or_repeat_are_refused() {
        assert!(ModelManifest::new("m", vec![entry("../etc/passwd", b"x")]).is_err());
        assert!(ModelManifest::new("m", vec![entry("/abs", b"x")]).is_err());
        assert!(ModelManifest::new("m", vec![entry("a", b"x"), entry("./a", b"y")]).is_err());
    }

    #[test]
    fn the_stated_root_is_recomputed_not_trusted() {
        let m = sample("m");
        let mut doc = m.to_json();
        assert_eq!(ModelManifest::from_json(&doc).unwrap(), m);
        doc["root"] = hex::encode([0u8; 32]).into();
        assert!(ModelManifest::from_json(&doc).is_err());
    }

    #[test]
    fn a_tampered_shard_on_disk_is_found() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("a.safetensors"), b"weights A").unwrap();
        std::fs::write(dir.path().join("sub/b.gguf"), b"weights B").unwrap();
        let m = build_from_dir("m", dir.path()).unwrap();
        assert_eq!(
            m.files.iter().map(|f| f.path.as_str()).collect::<Vec<_>>(),
            vec!["a.safetensors", "sub/b.gguf"]
        );
        verify_dir(&m, dir.path()).unwrap();

        std::fs::write(dir.path().join("sub/b.gguf"), b"weights b").unwrap();
        match verify_dir(&m, dir.path()) {
            Err(TrustError::FileMismatch { path, .. }) => assert_eq!(path, "sub/b.gguf"),
            other => panic!("expected a mismatch, got {other:?}"),
        }
        std::fs::remove_file(dir.path().join("a.safetensors")).unwrap();
        assert!(verify_dir(&m, dir.path()).is_err());
    }
}
