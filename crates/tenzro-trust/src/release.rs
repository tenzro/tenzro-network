//! Engine releases: a publisher's signed statement of a node build.
//!
//! A release names a version and, per platform, the size, SHA-256 and BLAKE3
//! of the binary. It travels like every other trust record, so the network
//! learns that a release exists; a node never installs one. Its operator
//! checks which releases from the publishers it names
//! in its configuration are newer than the running build, verifies a downloaded
//! artifact against the signed hashes, and installs it. A release changes the
//! software a node runs, never the chain.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{Result, has_type, invalid, str_field, verify_signed_by};

pub const ENGINE_RELEASE_TYPE: &str = "TenzroEngineRelease";
const MAX_ARTIFACTS: usize = 64;

/// One platform's binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Artifact {
    /// The platform the binary runs on, as a node reports its own
    /// (`<arch>-<os>`, optionally followed by an accelerator, e.g.
    /// `x86_64-linux-cuda`).
    pub platform: String,
    pub size: u64,
    /// Lowercase hex SHA-256 of the binary.
    pub sha256: String,
    /// Lowercase hex BLAKE3 of the binary: its blob address, so peers can
    /// serve it with chunk-by-chunk verification.
    pub blake3: String,
}

/// A verified release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineRelease {
    pub digest: String,
    pub publisher: String,
    /// `MAJOR.MINOR.PATCH`.
    pub version: String,
    pub artifacts: Vec<Artifact>,
    pub document: Value,
}

/// `MAJOR.MINOR.PATCH` as a comparable triple.
pub fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    let mut parts = v.split('.').map(|p| p.parse::<u64>().ok());
    let triple = (parts.next()??, parts.next()??, parts.next()??);
    parts.next().is_none().then_some(triple)
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl EngineRelease {
    pub fn unsigned(publisher: &str, version: &str, artifacts: &[Artifact]) -> Value {
        json!({
            "type": [ENGINE_RELEASE_TYPE],
            "publisher": publisher,
            "version": version,
            "artifacts": artifacts,
        })
    }

    pub fn parse(document: &Value) -> Result<Self> {
        if !has_type(document, ENGINE_RELEASE_TYPE) {
            return Err(invalid(format!("not a {ENGINE_RELEASE_TYPE}")));
        }
        let publisher = str_field(document, "/publisher")?.to_string();
        verify_signed_by(document, &publisher)?;
        let version = str_field(document, "/version")?.to_string();
        if parse_version(&version).is_none() {
            return Err(invalid("the version must be MAJOR.MINOR.PATCH"));
        }
        let artifacts: Vec<Artifact> =
            serde_json::from_value(document.get("artifacts").cloned().unwrap_or(Value::Null))
                .map_err(|e| invalid(format!("artifacts: {e}")))?;
        if artifacts.is_empty() || artifacts.len() > MAX_ARTIFACTS {
            return Err(invalid(format!(
                "a release lists 1-{MAX_ARTIFACTS} artifacts"
            )));
        }
        let mut platforms = std::collections::BTreeSet::new();
        for a in &artifacts {
            let platform_ok = !a.platform.is_empty()
                && a.platform.len() <= 64
                && a.platform
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_".contains(&b));
            if !platform_ok || !platforms.insert(a.platform.as_str()) {
                return Err(invalid(format!(
                    "artifact platform {:?} is malformed or repeated",
                    a.platform
                )));
            }
            if a.size == 0 || !is_hex(&a.sha256, 64) || !is_hex(&a.blake3, 64) {
                return Err(invalid(format!(
                    "artifact {} needs a size and lowercase hex SHA-256 and BLAKE3",
                    a.platform
                )));
            }
        }
        Ok(EngineRelease {
            digest: crate::record_digest(document),
            publisher,
            version,
            artifacts,
            document: document.clone(),
        })
    }

    pub fn artifact(&self, platform: &str) -> Option<&Artifact> {
        self.artifacts.iter().find(|a| a.platform == platform)
    }

    /// Whether this release is newer than `running`.
    pub fn newer_than(&self, running: &str) -> bool {
        match (parse_version(&self.version), parse_version(running)) {
            (Some(a), Some(b)) => a > b,
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::testkit::TestKey;

    fn artifact(platform: &str) -> Artifact {
        Artifact {
            platform: platform.into(),
            size: 10,
            sha256: "a".repeat(64),
            blake3: "b".repeat(64),
        }
    }

    #[test]
    fn a_signed_release_verifies_and_compares_by_version() {
        let k = TestKey::new(9);
        let doc = k.sign(EngineRelease::unsigned(
            &k.did(),
            "1.4.0",
            &[artifact("x86_64-linux")],
        ));
        let r = EngineRelease::parse(&doc).unwrap();
        assert!(r.newer_than("1.3.9") && !r.newer_than("1.4.0") && !r.newer_than("1.10.0"));
        assert!(r.artifact("x86_64-linux").is_some() && r.artifact("aarch64-linux").is_none());
    }

    #[test]
    fn a_forged_or_malformed_release_is_refused() {
        let (k, other) = (TestKey::new(9), TestKey::new(10));
        let forged = other.sign(EngineRelease::unsigned(
            &k.did(),
            "1.4.0",
            &[artifact("x86_64-linux")],
        ));
        assert!(EngineRelease::parse(&forged).is_err());
        let mut edited = k.sign(EngineRelease::unsigned(
            &k.did(),
            "1.4.0",
            &[artifact("x86_64-linux")],
        ));
        edited["artifacts"][0]["sha256"] = json!("c".repeat(64));
        assert!(EngineRelease::parse(&edited).is_err());
        for bad in [
            EngineRelease::unsigned(&k.did(), "1.4", &[artifact("x86_64-linux")]),
            EngineRelease::unsigned(&k.did(), "1.4.0", &[]),
            EngineRelease::unsigned(
                &k.did(),
                "1.4.0",
                &[artifact("x86_64-linux"), artifact("x86_64-linux")],
            ),
        ] {
            assert!(EngineRelease::parse(&k.sign(bad)).is_err());
        }
    }
}
