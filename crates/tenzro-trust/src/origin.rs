//! Origin attestations and multi-origin agreement.
//!
//! An observer (anyone with a hardware-derived DID) states what it saw at one
//! origin for a model name: the creator's own release, a Hugging Face Hub
//! commit, a mirror, or a storage provider that holds the bytes. The
//! statement is signed, so an origin that serves different bytes than
//! everyone else is caught in a signed, attributable contradiction.
//!
//! A manifest is corroborated file by file: each file needs enough
//! independent observers across enough distinct origins, and no signed
//! observation may contradict it. The Hub, for example, only reports a
//! SHA-256 for files stored in Git LFS, so small configuration files are
//! corroborated by observers that hashed the bytes themselves.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::manifest::{ModelManifest, normalise_path};
use crate::requirements::ProvenanceRule;
use crate::{Result, has_type, invalid, str_field, time_field, verify_signed_by};

pub const ORIGIN_TYPE: &str = "TenzroOriginAttestation";
const MAX_FILES: usize = 4096;

/// Where the bytes were observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OriginKind {
    /// The model's creator publishing its own release; the locator is the
    /// creator's DID, which must also be the observer.
    Creator,
    /// A Hugging Face Hub commit: `hf:<owner>/<repo>@<40-hex commit>`.
    Huggingface,
    /// Any other download location: an `https://` URL.
    Mirror,
    /// A node or storage provider holding the bytes: `tenzro:<DID>`.
    Storage,
}

/// One file as the observer saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedFile {
    pub path: String,
    pub size: u64,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blake3: Option<String>,
}

/// A signed observation of one origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginAttestation {
    pub digest: String,
    pub observer: String,
    pub kind: OriginKind,
    pub locator: String,
    pub name: String,
    pub files: Vec<ObservedFile>,
    pub observed_at: chrono::DateTime<chrono::Utc>,
    pub document: Value,
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn check_locator(kind: OriginKind, locator: &str, observer: &str) -> Result<()> {
    let ok = match kind {
        OriginKind::Creator => locator == observer,
        OriginKind::Huggingface => locator
            .strip_prefix("hf:")
            .and_then(|rest| rest.rsplit_once('@'))
            .is_some_and(|(repo, commit)| {
                repo.split('/').count() == 2 && !repo.contains("..") && is_hex(commit, 40)
            }),
        OriginKind::Mirror => locator.starts_with("https://") && locator.len() <= 512,
        OriginKind::Storage => locator
            .strip_prefix("tenzro:")
            .is_some_and(|d| d.starts_with("did:tenzro:")),
    };
    if ok {
        Ok(())
    } else {
        Err(invalid(format!(
            "locator {locator:?} is not a valid {kind:?} origin"
        )))
    }
}

impl OriginAttestation {
    pub fn unsigned(
        observer: &str,
        kind: OriginKind,
        locator: &str,
        name: &str,
        files: &[ObservedFile],
        observed_at: chrono::DateTime<chrono::Utc>,
    ) -> Value {
        json!({
            "type": [ORIGIN_TYPE],
            "observer": observer,
            "origin": { "kind": kind, "locator": locator },
            "name": name,
            "files": files,
            "observedAt": observed_at.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        })
    }

    pub fn parse(document: &Value) -> Result<Self> {
        if !has_type(document, ORIGIN_TYPE) {
            return Err(invalid(format!("not a {ORIGIN_TYPE}")));
        }
        let observer = str_field(document, "/observer")?.to_string();
        verify_signed_by(document, &observer)?;
        let kind: OriginKind = serde_json::from_value(
            document
                .pointer("/origin/kind")
                .cloned()
                .unwrap_or(Value::Null),
        )
        .map_err(|e| invalid(format!("origin.kind: {e}")))?;
        let locator = str_field(document, "/origin/locator")?.to_string();
        check_locator(kind, &locator, &observer)?;
        let name = str_field(document, "/name")?.to_string();
        let mut files: Vec<ObservedFile> =
            serde_json::from_value(document.get("files").cloned().unwrap_or(Value::Null))
                .map_err(|e| invalid(format!("files: {e}")))?;
        if files.is_empty() || files.len() > MAX_FILES {
            return Err(invalid(format!("an attestation lists 1-{MAX_FILES} files")));
        }
        let mut seen = BTreeSet::new();
        for f in &mut files {
            f.path = normalise_path(&f.path)?;
            if !is_hex(&f.sha256, 64) || f.blake3.as_ref().is_some_and(|b| !is_hex(b, 64)) {
                return Err(invalid(format!(
                    "{}: hashes must be 64-digit lowercase hex",
                    f.path
                )));
            }
            if !seen.insert(f.path.clone()) {
                return Err(invalid(format!("{} is listed twice", f.path)));
            }
        }
        Ok(OriginAttestation {
            digest: crate::record_digest(document),
            observer,
            kind,
            locator,
            name,
            files,
            observed_at: time_field(document, "/observedAt")?,
            document: document.clone(),
        })
    }
}

/// A signed observation that contradicts a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Conflict {
    pub observer: String,
    pub locator: String,
    pub attestation: String,
    pub paths: Vec<String>,
}

/// How well a manifest is corroborated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProvenanceStatus {
    pub root: String,
    /// Per file: the observers and origin locators that agree with it.
    pub files: BTreeMap<String, FileSupport>,
    pub conflicts: Vec<Conflict>,
    /// Whether an observation of kind `creator` agrees with every file it lists.
    pub creator_signed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct FileSupport {
    pub observers: BTreeSet<String>,
    pub origins: BTreeSet<String>,
}

impl ProvenanceStatus {
    /// Compare every observation of `manifest.name` against the manifest.
    pub fn compute<'a>(
        manifest: &ModelManifest,
        attestations: impl IntoIterator<Item = &'a OriginAttestation>,
    ) -> Self {
        let mut files: BTreeMap<String, FileSupport> = manifest
            .files
            .iter()
            .map(|f| (f.path.clone(), FileSupport::default()))
            .collect();
        let mut conflicts = Vec::new();
        let mut creator_signed = false;
        for att in attestations.into_iter().filter(|a| a.name == manifest.name) {
            let mut wrong = Vec::new();
            let mut agreeing = Vec::new();
            for obs in &att.files {
                let Some(entry) = manifest.file(&obs.path) else {
                    continue;
                };
                let same = obs.size == entry.size
                    && obs.sha256 == entry.sha256
                    && obs.blake3.as_ref().is_none_or(|b| *b == entry.blake3);
                if same {
                    agreeing.push(obs.path.clone());
                } else {
                    wrong.push(obs.path.clone());
                }
            }
            if wrong.is_empty() {
                for p in &agreeing {
                    if let Some(s) = files.get_mut(p) {
                        s.observers.insert(att.observer.clone());
                        s.origins.insert(att.locator.clone());
                    }
                }
                if att.kind == OriginKind::Creator && !agreeing.is_empty() {
                    creator_signed = true;
                }
            } else {
                conflicts.push(Conflict {
                    observer: att.observer.clone(),
                    locator: att.locator.clone(),
                    attestation: att.digest.clone(),
                    paths: wrong,
                });
            }
        }
        ProvenanceStatus {
            root: manifest.root_hex(),
            files,
            conflicts,
            creator_signed,
        }
    }

    /// The files that do not meet `rule`, counting only observers accepted
    /// by `observer_ok`.
    pub fn unmet(&self, rule: &ProvenanceRule, observer_ok: impl Fn(&str) -> bool) -> Vec<String> {
        let mut out = Vec::new();
        if !rule.allow_conflicts && !self.conflicts.is_empty() {
            out.push(format!(
                "{} contradicting observation(s)",
                self.conflicts.len()
            ));
        }
        for (path, support) in &self.files {
            let observers = support.observers.iter().filter(|o| observer_ok(o)).count() as u32;
            if observers < rule.min_observers || (support.origins.len() as u32) < rule.min_origins {
                out.push(format!(
                    "{path}: {observers} observer(s) across {} origin(s)",
                    support.origins.len()
                ));
            }
        }
        out
    }

    /// Verified under the network default rule.
    pub fn verified(&self) -> bool {
        self.unmet(&ProvenanceRule::DEFAULT, |_| true).is_empty()
    }
}

/// Read a Hugging Face Hub revision listing
/// (`/api/models/<repo>/revision/<rev>?blobs=true`) into an origin locator
/// and the files it states a SHA-256 for (the Git LFS objects). Files kept
/// in plain Git carry only a Git blob id, which is not a content hash of the
/// same kind, and are left for observers that hash the bytes.
pub fn observe_hub_listing(repo: &str, listing: &Value) -> Result<(String, Vec<ObservedFile>)> {
    let commit = listing
        .get("sha")
        .and_then(Value::as_str)
        .filter(|c| is_hex(c, 40))
        .ok_or_else(|| invalid("the listing has no 40-digit commit sha"))?;
    let siblings = listing
        .get("siblings")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("the listing has no siblings"))?;
    let mut files = Vec::new();
    for s in siblings {
        let Some(path) = s.get("rfilename").and_then(Value::as_str) else {
            continue;
        };
        let (Some(sha256), Some(size)) = (
            s.pointer("/lfs/sha256").and_then(Value::as_str),
            s.pointer("/lfs/size").and_then(Value::as_u64),
        ) else {
            continue;
        };
        files.push(ObservedFile {
            path: normalise_path(path)?,
            size,
            sha256: sha256.to_lowercase(),
            blake3: None,
        });
    }
    if files.is_empty() {
        return Err(invalid("the listing names no LFS file"));
    }
    let locator = format!("hf:{repo}@{commit}");
    check_locator(OriginKind::Huggingface, &locator, "")?;
    Ok((locator, files))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::tests::sample;
    use crate::proof::testkit::TestKey;

    fn observe(
        k: &TestKey,
        kind: OriginKind,
        locator: &str,
        m: &ModelManifest,
        with_blake3: bool,
    ) -> OriginAttestation {
        let files: Vec<ObservedFile> = m
            .files
            .iter()
            .map(|f| ObservedFile {
                path: f.path.clone(),
                size: f.size,
                sha256: f.sha256.clone(),
                blake3: with_blake3.then(|| f.blake3.clone()),
            })
            .collect();
        OriginAttestation::parse(&k.sign(OriginAttestation::unsigned(
            &k.did(),
            kind,
            locator,
            &m.name,
            &files,
            chrono::Utc::now(),
        )))
        .unwrap()
    }

    const HF: &str = "hf:org/model@0123456789abcdef0123456789abcdef01234567";

    #[test]
    fn two_independent_origins_verify_a_manifest() {
        let m = sample("org/model");
        let a = observe(&TestKey::new(1), OriginKind::Huggingface, HF, &m, false);
        let b = observe(
            &TestKey::new(2),
            OriginKind::Mirror,
            "https://mirror.example/org/model",
            &m,
            true,
        );
        let s = ProvenanceStatus::compute(&m, [&a]);
        assert!(!s.verified(), "one origin is not enough");
        let s = ProvenanceStatus::compute(&m, [&a, &b]);
        assert!(
            s.verified(),
            "{:?}",
            s.unmet(&ProvenanceRule::DEFAULT, |_| true)
        );
    }

    #[test]
    fn a_lying_mirror_is_recorded_as_a_conflict_and_blocks_verification() {
        let m = sample("org/model");
        let a = observe(&TestKey::new(1), OriginKind::Huggingface, HF, &m, false);
        let b = observe(
            &TestKey::new(2),
            OriginKind::Mirror,
            "https://good.example/m",
            &m,
            true,
        );
        let liar_key = TestKey::new(3);
        let mut lied = m.clone();
        lied.files[2].sha256 = hex::encode([0xee; 32]);
        let liar = observe(
            &liar_key,
            OriginKind::Mirror,
            "https://evil.example/m",
            &lied,
            false,
        );
        let s = ProvenanceStatus::compute(&m, [&a, &b, &liar]);
        assert_eq!(s.conflicts.len(), 1);
        assert_eq!(s.conflicts[0].observer, liar_key.did());
        assert_eq!(s.conflicts[0].paths, vec![m.files[2].path.clone()]);
        assert!(!s.verified());
        let tolerant = ProvenanceRule {
            allow_conflicts: true,
            ..ProvenanceRule::DEFAULT
        };
        assert!(s.unmet(&tolerant, |_| true).is_empty());
    }

    #[test]
    fn the_same_observer_twice_is_one_observer() {
        let m = sample("org/model");
        let k = TestKey::new(1);
        let a = observe(&k, OriginKind::Huggingface, HF, &m, false);
        let b = observe(&k, OriginKind::Mirror, "https://mirror.example/m", &m, true);
        assert!(!ProvenanceStatus::compute(&m, [&a, &b]).verified());
    }

    #[test]
    fn an_observation_of_another_name_does_not_count() {
        let m = sample("org/model");
        let other = sample("org/other");
        let a = observe(&TestKey::new(1), OriginKind::Huggingface, HF, &other, false);
        let b = observe(
            &TestKey::new(2),
            OriginKind::Mirror,
            "https://m.example/x",
            &other,
            false,
        );
        assert!(!ProvenanceStatus::compute(&m, [&a, &b]).verified());
    }

    #[test]
    fn a_creator_origin_must_be_its_own_observer() {
        let k = TestKey::new(1);
        let m = sample("org/model");
        let bad = k.sign(OriginAttestation::unsigned(
            &k.did(),
            OriginKind::Creator,
            "did:tenzro:human:someone-else",
            &m.name,
            &[],
            chrono::Utc::now(),
        ));
        assert!(OriginAttestation::parse(&bad).is_err());
        let a = observe(&k, OriginKind::Creator, &k.did(), &m, true);
        assert!(ProvenanceStatus::compute(&m, [&a]).creator_signed);
    }

    #[test]
    fn a_hub_listing_yields_the_lfs_files_at_the_commit() {
        let listing = serde_json::json!({
            "sha": "0123456789abcdef0123456789abcdef01234567",
            "siblings": [
                {"rfilename": "config.json", "blobId": "abc"},
                {"rfilename": "model.safetensors", "size": 9, "lfs": {"sha256": "AB".repeat(32), "size": 9, "pointerSize": 132}},
            ]
        });
        let (locator, files) = observe_hub_listing("org/model", &listing).unwrap();
        assert_eq!(locator, HF);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].sha256, "ab".repeat(32));
        assert!(
            observe_hub_listing(
                "org/model",
                &serde_json::json!({"sha": "main", "siblings": []})
            )
            .is_err()
        );
    }
}
